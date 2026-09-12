//! G02-b: per-turn isolated input directory + terminal output snapshot manifest.
//!
//! Every turn gets a run directory under
//! `{workspace_root}/conversation-runs/{conversation_id}/{label}-run-{turn_id}/`
//! (the leaf mirrors the auto-provisioned workspace's `{label}-temp-{conversation_id}`
//! convention — same label source). Attachments resolved at the send boundary are
//! copied into `input/` before the turn is dispatched, preserving their relative
//! path structure, so each turn owns a frozen, isolated snapshot of its inputs.
//!
//! Lifecycle:
//! 1. `mint_run_dir` — called at `run_user_turn` entry, before dispatch. The run
//!    boundary is the TURN (`turn_id`), not the attempt: the orchestrator's
//!    auto-replay (attempt 2) reuses the same run dir. Mint/copy failure fails
//!    the turn closed.
//! 2. `collect_run_manifest` — called once the turn reaches its terminal state.
//!    Walks the whole run dir and writes `manifest.json` (relative path + sha256
//!    hex + byte size per entry, plus ids, terminal status and a unix-ms
//!    timestamp; format follows the `aionui-runtime` managed_resources_contract
//!    schema pattern). The manifest does not list itself (no self-digest yet —
//!    a later card owns that). Collection is best-effort by contract: a failure
//!    is recorded as `collectionError` plus the partial listing; it never panics
//!    and never affects the conversation.
//! 3. `remove_collected_run_dir` — retention helper, NOT wired to any timer yet
//!    (the service-side entry is `ConversationService::cleanup_collected_run_dir`).
//!    Gated: only a run whose `manifest.json` exists AND parses as a collected
//!    manifest (known schema version + terminal status) may be removed. A run
//!    that was never collected still holds the only copy of the turn's input
//!    snapshot; deleting it would destroy evidence.
//!
//! ## Terminal status is a conversation-side heuristic
//!
//! `RunTerminalStatus` is derived in the turn orchestrator as:
//! - `final_failed == false` → [`RunTerminalStatus::Completed`]
//! - `final_failed == true && runtime_state.is_cancelling(&conv_id)` → [`RunTerminalStatus::Cancelled`]
//! - otherwise → [`RunTerminalStatus::Failed`]
//!
//! This is a conversation-side heuristic, not a rich terminal signal. The relay's
//! terminal type (`RelayTerminal`, `stream_relay.rs:120-135`) has no `Cancelled`
//! variant — `Finish | Error | ChannelClosed` only — so cancellation is detected
//! indirectly via the runtime state's conversation-scoped cancelling flag
//! (`is_cancelling`, lifecycle in `runtime_state.rs:169-241`). The flag is
//! snapshotted BEFORE the turn claim is released because releasing it clears the
//! flag (a released turn stops being "cancelling"), after which `Cancelled` and
//! `Failed` are indistinguishable. Enriching the upstream relay terminal is a
//! later card; this card deliberately does not touch `stream_relay.rs`.
//!
//! Known limits of the heuristic under replay/boundary timing:
//! - A cancel that arrived while the agent was still building (the
//!   `take_deferred_cancel` path) ends the turn as `Completed` at the
//!   orchestrator level, so its manifest says `completed` although the user
//!   withdrew the turn.
//! - The cancelling flag is conversation-scoped, not turn-scoped: a cancel raced
//!   with the NEXT turn's start can, in principle, mislabel that turn.
//! - A turn that failed on attempt 1 and was auto-replayed only reports the
//!   FINAL attempt's outcome; attempt-1 failures are not separately recorded.

use std::collections::HashSet;
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

use aionui_common::AgentType;
use aionui_db::models::ConversationRow;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};
use walkdir::WalkDir;

use crate::convert::string_to_enum;

/// Name of the snapshot manifest inside every run directory. Mirrors the
/// `managed_resources_contract.rs` naming (`manifest.json`).
pub(crate) const RUN_MANIFEST_FILE: &str = "manifest.json";
const RUN_MANIFEST_SCHEMA_VERSION: u8 = 1;
const RUNS_BUCKET_DIR: &str = "conversation-runs";
const INPUT_DIR: &str = "input";

#[derive(Debug, thiserror::Error)]
pub(crate) enum RunDirError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("conversation row unusable for run dir: {0}")]
    Row(String),
    #[error("attachment source missing or not a regular file: {0}")]
    MissingSource(String),
    #[error("attachment relative path collision: {0}")]
    Collision(String),
    #[error("attachment path escapes the input snapshot boundary: {0}")]
    Escape(String),
}

/// Conversation-side terminal classification for a run — see the module docs
/// for why this is a heuristic rather than a relay-enriched signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RunTerminalStatus {
    Completed,
    Cancelled,
    Failed,
}

/// The three-state mapping the orchestrator applies at turn terminal. Kept as a
/// pure function so the boundary behavior is directly unit-testable.
pub(crate) fn map_terminal_status(final_failed: bool, is_cancelling: bool) -> RunTerminalStatus {
    if !final_failed {
        RunTerminalStatus::Completed
    } else if is_cancelling {
        RunTerminalStatus::Cancelled
    } else {
        RunTerminalStatus::Failed
    }
}

/// A minted per-turn run directory. Handed back by [`mint_run_dir`] and consumed
/// by [`collect_run_manifest`] at the turn's terminal.
#[derive(Debug, Clone)]
pub(crate) struct TurnRunDir {
    pub path: PathBuf,
    pub turn_id: String,
    pub conversation_id: String,
}

/// Absolute run directory for `turn_id` of the conversation in `row`.
pub(crate) fn run_dir_path(
    workspace_root: &Path,
    row: &ConversationRow,
    turn_id: &str,
) -> Result<PathBuf, RunDirError> {
    let label = run_label(row)?;
    Ok(workspace_root
        .join(RUNS_BUCKET_DIR)
        .join(&row.id)
        .join(format!("{label}-run-{turn_id}")))
}

/// Label source for the run leaf name. Uses the SAME convention as the
/// auto-provisioned workspace leaf (`{label}-temp-{conversation_id}`): for ACP
/// conversations the `extra.backend` vendor string, otherwise the agent type's
/// serde name. Delegates to `ConversationService`'s `conversation_label` so the
/// two leaf-naming conventions cannot drift apart.
fn run_label(row: &ConversationRow) -> Result<String, RunDirError> {
    let agent_type: AgentType =
        string_to_enum(&row.r#type).map_err(|err| RunDirError::Row(format!("agent type {}: {err}", row.r#type)))?;
    // The label only needs the OPTIONAL `backend` field. A corrupt `extra`
    // must not permanently brick every send for this conversation, so fall
    // back to the agent type's serde name instead of failing the mint.
    let extra: Option<serde_json::Value> = match serde_json::from_str(&row.extra) {
        Ok(value) => Some(value),
        Err(err) => {
            warn!(
                conversation_id = %row.id,
                error = %err,
                "Run dir label: unreadable conversation extra; using agent type label"
            );
            None
        }
    };
    Ok(crate::service::conversation_label(
        &agent_type,
        extra.as_ref().and_then(|value| value.get("backend")),
    ))
}

/// Mint the run directory for this turn and copy the message attachments into
/// `input/`, preserving their relative path structure (relative to the
/// attachments' common parent directory). Attachments with no common parent
/// fall back to their leaf names; a leaf collision is an error. With no
/// attachments the empty `input/` dir is still minted.
///
/// Failure of any step is returned — the caller fails the turn closed. A run
/// dir this call created is removed again on failure (best-effort, never
/// masking the original error): the caller neither collects nor cleans up a
/// failed mint, so a partial run dir would otherwise linger forever.
pub(crate) async fn mint_run_dir(
    workspace_root: &Path,
    row: &ConversationRow,
    turn_id: &str,
    files: &[String],
) -> Result<TurnRunDir, RunDirError> {
    let run_path = run_dir_path(workspace_root, row, turn_id)?;
    let input_dir = run_path.join(INPUT_DIR);
    let created = !run_path.exists();
    tokio::fs::create_dir_all(&input_dir).await?;

    let sources: Vec<PathBuf> = files.iter().map(PathBuf::from).collect();
    if let Err(err) = copy_attachments(&input_dir, &sources).await {
        if created && let Err(cleanup_err) = tokio::fs::remove_dir_all(&run_path).await {
            warn!(
                conversation_id = %row.id,
                turn_id,
                run_dir = %run_path.display(),
                error = %cleanup_err,
                "Failed to clean up partially minted run dir"
            );
        }
        return Err(err);
    }

    info!(
        conversation_id = %row.id,
        turn_id,
        run_dir = %run_path.display(),
        attachments = files.len(),
        "Per-turn run dir minted"
    );
    Ok(TurnRunDir {
        path: run_path,
        turn_id: turn_id.to_owned(),
        conversation_id: row.id.clone(),
    })
}

/// Copy each attachment into `input_dir` at its planned relative destination.
async fn copy_attachments(input_dir: &Path, sources: &[PathBuf]) -> Result<(), RunDirError> {
    for (src, relative) in plan_input_layout(sources)? {
        if !src.is_file() {
            return Err(RunDirError::MissingSource(src.display().to_string()));
        }
        let target = input_dir.join(&relative);
        // Defense in depth behind plan_input_layout: the joined target must
        // stay inside the snapshot directory.
        if !target.starts_with(input_dir) {
            return Err(RunDirError::Escape(src.display().to_string()));
        }
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(&src, &target).await?;
    }
    Ok(())
}

/// Map each attachment source to its `input/`-relative destination. Sources
/// under a shared common parent keep their relative structure; sources with no
/// common parent (mixed relative/absolute input, or unrelated relative trees)
/// fall back to their leaf names. Any planned relative path carrying `..` or
/// `.` components would escape the snapshot boundary and fails closed.
fn plan_input_layout(sources: &[PathBuf]) -> Result<Vec<(PathBuf, PathBuf)>, RunDirError> {
    let mut unique = sources.to_vec();
    unique.sort();
    unique.dedup();

    let common = common_parent(&unique);
    let has_common = !common.as_os_str().is_empty();
    let mut seen: HashSet<String> = HashSet::new();
    let mut layout = Vec::with_capacity(unique.len());
    for src in &unique {
        let relative = if has_common {
            match src.strip_prefix(&common) {
                Ok(rel) if !rel.as_os_str().is_empty() => rel.to_path_buf(),
                _ => leaf_name(src)?,
            }
        } else {
            leaf_name(src)?
        };
        for component in relative.components() {
            if matches!(component, Component::ParentDir | Component::CurDir) {
                return Err(RunDirError::Escape(src.display().to_string()));
            }
        }
        let key = relative.to_string_lossy().into_owned();
        if !seen.insert(key) {
            return Err(RunDirError::Collision(src.display().to_string()));
        }
        layout.push((src.clone(), relative));
    }
    Ok(layout)
}

/// Leaf fallback destination for a source with no usable common parent.
fn leaf_name(src: &Path) -> Result<PathBuf, RunDirError> {
    src.file_name()
        .map(PathBuf::from)
        .ok_or_else(|| RunDirError::Row(format!("attachment path has no file name: {}", src.display())))
}

/// Longest directory shared by every source's parent (empty when the sources
/// live under unrelated trees).
fn common_parent(files: &[PathBuf]) -> PathBuf {
    let parents: Vec<Vec<Component>> = files
        .iter()
        .map(|file| file.parent().unwrap_or(file).components().collect())
        .collect();
    // The lexicographic min and max share exactly the longest common prefix.
    let min = parents.iter().min().cloned().unwrap_or_default();
    let max = parents.iter().max().cloned().unwrap_or_default();
    let mut common = PathBuf::new();
    for (a, b) in min.iter().zip(max.iter()) {
        if a != b {
            break;
        }
        common.push(a.as_os_str());
    }
    common
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunManifest {
    schema_version: u8,
    turn_id: String,
    conversation_id: String,
    status: RunTerminalStatus,
    collected_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    collection_error: Option<String>,
    entries: Vec<RunManifestEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunManifestEntry {
    path: String,
    sha256: String,
    size_bytes: u64,
}

/// Write the terminal `manifest.json` for `run`. Best-effort by contract: a
/// walk/hash failure is recorded as `collectionError` alongside the partial
/// listing; a manifest write failure is only logged. Never panics, never
/// affects the conversation.
pub(crate) async fn collect_run_manifest(run: &TurnRunDir, status: RunTerminalStatus) {
    let run_root = run.path.clone();
    let (entries, collection_error) = tokio::task::spawn_blocking(move || collect_entries(&run_root))
        .await
        .unwrap_or_else(|err| (Vec::new(), Some(format!("manifest collect task failed to join: {err}"))));

    let manifest = RunManifest {
        schema_version: RUN_MANIFEST_SCHEMA_VERSION,
        turn_id: run.turn_id.clone(),
        conversation_id: run.conversation_id.clone(),
        status,
        // `now_ms` is i64 (unix ms, monotonic-safe across the codebase); the
        // manifest field is u64 because a negative collection time is meaningless.
        collected_at_ms: aionui_common::now_ms().max(0) as u64,
        collection_error: collection_error.clone(),
        entries,
    };
    let json = match serde_json::to_string_pretty(&manifest) {
        Ok(json) => json,
        Err(err) => {
            error!(
                conversation_id = %run.conversation_id,
                turn_id = %run.turn_id,
                error = %err,
                "Failed to serialize run dir manifest"
            );
            return;
        }
    };
    // Atomic write (temp + rename): a torn manifest.json must never look like
    // a collected run to the cleanup gate.
    let manifest_path = run.path.join(RUN_MANIFEST_FILE);
    let tmp_path = run.path.join(format!("{RUN_MANIFEST_FILE}.tmp"));
    match std::fs::write(&tmp_path, json).and_then(|()| std::fs::rename(&tmp_path, &manifest_path)) {
        Ok(()) => info!(
            conversation_id = %run.conversation_id,
            turn_id = %run.turn_id,
            status = ?status,
            collection_error,
            "Run dir manifest collected"
        ),
        Err(err) => {
            let _ = std::fs::remove_file(&tmp_path);
            error!(
                conversation_id = %run.conversation_id,
                turn_id = %run.turn_id,
                error = %err,
                "Failed to write run dir manifest"
            )
        }
    }
}

/// Walk the run dir and hash every regular file. The manifest itself is
/// excluded (it is written after the walk and carries no self-digest yet).
fn collect_entries(run_root: &Path) -> (Vec<RunManifestEntry>, Option<String>) {
    let mut entries = Vec::new();
    let mut collection_error: Option<String> = None;
    for entry in WalkDir::new(run_root).min_depth(1) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                collection_error = Some(format!("run dir walk failed: {err}"));
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.depth() == 1 && entry.file_name() == RUN_MANIFEST_FILE {
            continue;
        }
        let relative = match entry.path().strip_prefix(run_root) {
            Ok(relative) => relative.to_string_lossy().into_owned(),
            Err(err) => {
                collection_error = Some(format!("run dir entry outside root: {err}"));
                continue;
            }
        };
        match hash_file(entry.path()) {
            Ok((sha256, size_bytes)) => entries.push(RunManifestEntry {
                path: relative,
                sha256,
                size_bytes,
            }),
            Err(err) => {
                warn!(
                    entry = %relative,
                    error = %err,
                    "Run dir manifest entry hash failed; recording partial collection"
                );
                collection_error = Some(format!("hash failed for {relative}: {err}"));
            }
        }
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    (entries, collection_error)
}

/// Stream the file in chunks so arbitrarily large inputs never load fully
/// into memory; returns the hex sha256 and the byte count.
fn hash_file(path: &Path) -> std::io::Result<(String, u64)> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total += read as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// Remove a run directory — but ONLY if its manifest was collected AND
/// validates (see the module docs for the gate's rationale). After removing
/// the run dir, the conversation's run bucket is pruned when empty (same
/// parent-pruning pattern as `cleanup_empty_date_workspace_parents` in
/// service.rs). Returns whether the run dir was actually removed.
pub(crate) async fn remove_collected_run_dir(run_dir: &Path) -> std::io::Result<bool> {
    if !is_collected_manifest(&run_dir.join(RUN_MANIFEST_FILE)) {
        return Ok(false);
    }
    tokio::fs::remove_dir_all(run_dir).await?;
    if let Some(bucket) = run_dir.parent() {
        // Expected failures (still occupied / already gone) are not errors.
        let _ = tokio::fs::remove_dir(bucket).await;
    }
    Ok(true)
}

/// The subset of the manifest schema the cleanup gate insists on. Anything
/// that does not parse into this — a corrupt, truncated, or foreign
/// `manifest.json` — keeps the run dir alive: the gate must never authorize
/// deleting a run on mere existence of a same-named file.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectedManifestGate {
    schema_version: u8,
    /// Deserializing into [`RunTerminalStatus`] IS the status validation —
    /// an unknown status string fails the whole parse; the parsed value is
    /// intentionally not read further.
    #[expect(dead_code)]
    status: RunTerminalStatus,
}

fn is_collected_manifest(manifest_path: &Path) -> bool {
    std::fs::read_to_string(manifest_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<CollectedManifestGate>(&raw).ok())
        .is_some_and(|gate| gate.schema_version == RUN_MANIFEST_SCHEMA_VERSION)
}
