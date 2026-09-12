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
//!    Gated: only a run whose `manifest.json` exists may be removed. A run that
//!    was never collected still holds the only copy of the turn's input snapshot;
//!    deleting it would destroy evidence.
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
use std::path::{Component, Path, PathBuf};

use aionui_common::AgentType;
use aionui_db::models::ConversationRow;
use serde::Serialize;
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
}

/// Conversation-side terminal classification for a run — see the module docs
/// for why this is a heuristic rather than a relay-enriched signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
    let extra: serde_json::Value =
        serde_json::from_str(&row.extra).map_err(|err| RunDirError::Row(format!("invalid extra JSON: {err}")))?;
    Ok(crate::service::conversation_label(&agent_type, extra.get("backend")))
}

/// Mint the run directory for this turn and copy the message attachments into
/// `input/`, preserving their relative path structure (relative to the
/// attachments' common parent directory). Attachments with no common parent
/// fall back to their leaf names; a leaf collision is an error. With no
/// attachments the empty `input/` dir is still minted.
///
/// Failure of any step is returned — the caller fails the turn closed.
pub(crate) async fn mint_run_dir(
    workspace_root: &Path,
    row: &ConversationRow,
    turn_id: &str,
    files: &[String],
) -> Result<TurnRunDir, RunDirError> {
    let run_path = run_dir_path(workspace_root, row, turn_id)?;
    let input_dir = run_path.join(INPUT_DIR);
    tokio::fs::create_dir_all(&input_dir).await?;

    let sources: Vec<PathBuf> = files.iter().map(PathBuf::from).collect();
    for (src, relative) in plan_input_layout(&sources)? {
        if !src.is_file() {
            return Err(RunDirError::MissingSource(src.display().to_string()));
        }
        let target = input_dir.join(&relative);
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(&src, &target).await?;
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

/// Map each attachment source to its `input/`-relative destination.
fn plan_input_layout(sources: &[PathBuf]) -> Result<Vec<(PathBuf, PathBuf)>, RunDirError> {
    let mut unique = sources.to_vec();
    unique.sort();
    unique.dedup();

    let common = common_parent(&unique);
    let mut seen: HashSet<String> = HashSet::new();
    let mut layout = Vec::with_capacity(unique.len());
    for src in &unique {
        let relative = match src.strip_prefix(&common) {
            Ok(rel) if !rel.as_os_str().is_empty() => rel.to_path_buf(),
            _ => src
                .file_name()
                .map(PathBuf::from)
                .ok_or_else(|| RunDirError::Row(format!("attachment path has no file name: {}", src.display())))?,
        };
        let key = relative.to_string_lossy().into_owned();
        if !seen.insert(key) {
            return Err(RunDirError::Collision(src.display().to_string()));
        }
        layout.push((src.clone(), relative));
    }
    Ok(layout)
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
    match std::fs::write(run.path.join(RUN_MANIFEST_FILE), json) {
        Ok(()) => info!(
            conversation_id = %run.conversation_id,
            turn_id = %run.turn_id,
            status = ?status,
            collection_error,
            "Run dir manifest collected"
        ),
        Err(err) => error!(
            conversation_id = %run.conversation_id,
            turn_id = %run.turn_id,
            error = %err,
            "Failed to write run dir manifest"
        ),
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

fn hash_file(path: &Path) -> std::io::Result<(String, u64)> {
    let bytes = std::fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    Ok((hex::encode(digest), bytes.len() as u64))
}

/// Remove a run directory — but ONLY if its manifest was collected (see the
/// module docs for the gate's rationale). After removing the run dir, the
/// conversation's run bucket is pruned when empty (same parent-pruning pattern
/// as `cleanup_empty_date_workspace_parents` in service.rs). Returns whether
/// the run dir was actually removed.
pub(crate) async fn remove_collected_run_dir(run_dir: &Path) -> std::io::Result<bool> {
    if !run_dir.join(RUN_MANIFEST_FILE).is_file() {
        return Ok(false);
    }
    tokio::fs::remove_dir_all(run_dir).await?;
    if let Some(bucket) = run_dir.parent() {
        // Expected failures (still occupied / already gone) are not errors.
        let _ = tokio::fs::remove_dir(bucket).await;
    }
    Ok(true)
}
