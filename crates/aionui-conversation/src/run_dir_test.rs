//! G02-b: tests for the per-turn run dir (mint/copy, terminal manifest,
//! cleanup gate). Unit-level: pure fs + runtime-state seeding, no service
//! harness needed — the service-side cleanup wrapper is thin glue over
//! `run_dir_path` + `remove_collected_run_dir`, both covered here.

use std::path::Path;
use std::sync::Arc;

use aionui_db::models::ConversationRow;
use serde_json::Value;

use crate::run_dir::{
    RUN_MANIFEST_FILE, RunDirError, RunTerminalStatus, collect_run_manifest, map_terminal_status, mint_run_dir,
    remove_collected_run_dir, run_dir_path,
};
use crate::runtime_state::ConversationRuntimeStateService;

/// Well-known NIST SHA-256 test vector, used as an independent digest ground
/// truth so the manifest assertions don't just re-run the code under test.
const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn row(agent_type: &str, extra: Value) -> ConversationRow {
    ConversationRow {
        id: "conv-1".into(),
        user_id: "user-1".into(),
        name: "test".into(),
        r#type: agent_type.into(),
        model: None,
        extra: extra.to_string(),
        status: None,
        source: Some("chat".into()),
        channel_chat_id: None,
        pinned: false,
        pinned_at: None,
        created_at: 0,
        updated_at: 0,
        project_id: None,
        folder_id: None,
        name_source: None,
    }
}

fn read_manifest(run_path: &Path) -> Value {
    let raw = std::fs::read_to_string(run_path.join(RUN_MANIFEST_FILE)).expect("manifest.json exists");
    serde_json::from_str(&raw).expect("manifest.json is valid JSON")
}

fn entry_for<'a>(manifest: &'a Value, path: &str) -> &'a Value {
    manifest["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .find(|entry| entry["path"] == path)
        .unwrap_or_else(|| panic!("no manifest entry for {path}"))
}

#[tokio::test]
async fn mints_run_dir_and_copies_attachments_with_relative_structure() {
    let root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let nested = src.path().join("docs/2024");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("report.pdf"), b"report-bytes").unwrap();
    std::fs::write(src.path().join("notes.txt"), b"notes-bytes").unwrap();

    let files = vec![
        nested.join("report.pdf").to_string_lossy().to_string(),
        src.path().join("notes.txt").to_string_lossy().to_string(),
    ];
    let run = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &files)
        .await
        .unwrap();

    // Leaf mirrors the auto-workspace convention with the SAME label source.
    assert_eq!(run.path.file_name().unwrap(), "aionrs-run-turn_t1");

    let copied_report = run.path.join("input/docs/2024/report.pdf");
    assert!(copied_report.is_file(), "relative structure preserved");
    assert_eq!(std::fs::read(&copied_report).unwrap(), b"report-bytes");
    assert_eq!(std::fs::read(run.path.join("input/notes.txt")).unwrap(), b"notes-bytes");
}

#[tokio::test]
async fn acp_row_label_uses_extra_backend() {
    let root = tempfile::tempdir().unwrap();
    let run = mint_run_dir(
        root.path(),
        &row("acp", serde_json::json!({ "backend": "claude" })),
        "turn_t1",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(run.path.file_name().unwrap(), "claude-run-turn_t1");
}

#[tokio::test]
async fn mints_empty_input_dir_when_no_attachments() {
    let root = tempfile::tempdir().unwrap();
    let run = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &[])
        .await
        .unwrap();
    let input = run.path.join("input");
    assert!(input.is_dir());
    assert_eq!(std::fs::read_dir(&input).unwrap().count(), 0);
}

#[tokio::test]
async fn same_named_inputs_across_turns_are_isolated() {
    let root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let file_a = src.path().join("input.txt");
    std::fs::write(&file_a, b"turn-one-payload").unwrap();

    let files = vec![file_a.to_string_lossy().to_string()];
    let run_a = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_a", &files)
        .await
        .unwrap();

    // Same-named file, different content, next turn.
    std::fs::write(&file_a, b"turn-two-payload").unwrap();
    let run_b = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_b", &files)
        .await
        .unwrap();

    assert_ne!(run_a.path, run_b.path);
    assert_eq!(
        std::fs::read(run_a.path.join("input/input.txt")).unwrap(),
        b"turn-one-payload",
        "turn A's snapshot must not see turn B's content"
    );
    assert_eq!(
        std::fs::read(run_b.path.join("input/input.txt")).unwrap(),
        b"turn-two-payload"
    );
}

#[tokio::test]
async fn mint_fails_when_source_is_missing() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("does-not-exist.txt");
    let files = vec![missing.to_string_lossy().to_string()];

    let err = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &files)
        .await
        .unwrap_err();

    assert!(matches!(err, RunDirError::MissingSource(_)), "got: {err:?}");
}

#[test]
fn run_dir_path_fails_on_unknown_agent_type() {
    let root = Path::new("/tmp");
    let err = run_dir_path(root, &row("bogus-type", serde_json::json!({})), "turn_t1").unwrap_err();
    assert!(matches!(err, RunDirError::Row(_)), "got: {err:?}");
}

// ── Three-state mapping ─────────────────────────────────────────────

#[test]
fn non_failed_turn_maps_completed() {
    assert_eq!(map_terminal_status(false, false), RunTerminalStatus::Completed);
}

#[tokio::test]
async fn cancelling_conversation_maps_failed_turn_to_cancelled() {
    // Seeded per the service_test.rs runtime-state pattern: claim, then mark.
    let state = Arc::new(ConversationRuntimeStateService::default());
    let _claim = state.try_claim_turn("conv-1", "turn-1").expect("claim created");
    state.mark_cancelling("conv-1");
    assert!(state.is_cancelling("conv-1"));

    assert_eq!(
        map_terminal_status(true, state.is_cancelling("conv-1")),
        RunTerminalStatus::Cancelled
    );
}

#[test]
fn plain_failure_maps_failed() {
    assert_eq!(map_terminal_status(true, false), RunTerminalStatus::Failed);
}

// ── Manifest collection ─────────────────────────────────────────────

#[tokio::test]
async fn collect_writes_manifest_with_status_and_hash() {
    let root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("payload.txt");
    std::fs::write(&file, b"abc").unwrap();
    let files = vec![file.to_string_lossy().to_string()];

    let run = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &files)
        .await
        .unwrap();
    collect_run_manifest(&run, RunTerminalStatus::Completed).await;

    let manifest = read_manifest(&run.path);
    assert_eq!(manifest["schemaVersion"], 1);
    assert_eq!(manifest["turnId"], "turn_t1");
    assert_eq!(manifest["conversationId"], "conv-1");
    assert_eq!(manifest["status"], "completed");
    assert!(manifest["collectedAtMs"].as_u64().unwrap() > 0);
    assert!(manifest.get("collectionError").is_none());

    let entry = entry_for(&manifest, "input/payload.txt");
    assert_eq!(entry["sha256"], ABC_SHA256, "digest must match the NIST vector");
    assert_eq!(entry["sizeBytes"], 3);
    // The manifest does not list itself (no self-digest yet).
    assert_eq!(manifest["entries"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn collect_records_failed_status_and_cancellation() {
    let root = tempfile::tempdir().unwrap();
    let run = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &[])
        .await
        .unwrap();

    collect_run_manifest(&run, RunTerminalStatus::Failed).await;
    assert_eq!(read_manifest(&run.path)["status"], "failed");

    collect_run_manifest(&run, RunTerminalStatus::Cancelled).await;
    assert_eq!(read_manifest(&run.path)["status"], "cancelled");
}

#[tokio::test]
async fn collect_records_collection_error_for_unreadable_entry() {
    let root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("locked.txt");
    std::fs::write(&file, b"secret").unwrap();
    let files = vec![file.to_string_lossy().to_string()];
    let run = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &files)
        .await
        .unwrap();

    let locked = run.path.join("input/locked.txt");
    std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
    collect_run_manifest(&run, RunTerminalStatus::Failed).await;
    let _ = std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o644));

    let manifest = read_manifest(&run.path);
    let error = manifest["collectionError"].as_str().expect("collection error recorded");
    assert!(error.contains("locked.txt"), "error names the offending entry: {error}");
}

// ── Cleanup gate ────────────────────────────────────────────────────

#[tokio::test]
async fn cleanup_only_deletes_collected_runs() {
    let root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("data.txt");
    std::fs::write(&file, b"abc").unwrap();
    let files = vec![file.to_string_lossy().to_string()];

    let run = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &files)
        .await
        .unwrap();

    // Gate: not collected yet → never deleted.
    assert!(!remove_collected_run_dir(&run.path).await.unwrap());
    assert!(run.path.is_dir(), "uncollected run dir must survive");

    // Collected → removed, and the empty conversation bucket pruned with it.
    collect_run_manifest(&run, RunTerminalStatus::Completed).await;
    assert!(remove_collected_run_dir(&run.path).await.unwrap());
    assert!(!run.path.exists());
    assert!(!run.path.parent().unwrap().exists(), "empty bucket pruned");
}

#[tokio::test]
async fn cleanup_keeps_bucket_while_sibling_runs_remain() {
    let root = tempfile::tempdir().unwrap();
    let run_a = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_a", &[])
        .await
        .unwrap();
    let run_b = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_b", &[])
        .await
        .unwrap();

    collect_run_manifest(&run_a, RunTerminalStatus::Completed).await;
    assert!(remove_collected_run_dir(&run_a.path).await.unwrap());

    assert!(!run_a.path.exists());
    assert!(run_b.path.is_dir(), "sibling run untouched");
    assert!(run_b.path.parent().unwrap().is_dir(), "bucket kept while non-empty");
}
