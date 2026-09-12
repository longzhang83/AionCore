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

// ── Snapshot boundary (P1-1 / P1-2) ─────────────────────────────────

#[tokio::test]
async fn mint_rejects_parent_dir_escape_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("inside.txt"), b"inside").unwrap();
    // Lexically carries `..` past the common parent `src/`; the real file sits
    // OUTSIDE the would-be snapshot (at the workspace root).
    std::fs::write(root.path().join("escaped.txt"), b"victim").unwrap();
    let escape = src.join("..").join("escaped.txt");

    let files = vec![
        src.join("inside.txt").to_string_lossy().to_string(),
        escape.to_string_lossy().to_string(),
    ];
    let err = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &files)
        .await
        .unwrap_err();

    assert!(matches!(err, RunDirError::Escape(_)), "got: {err:?}");
    let run_path = root
        .path()
        .join("conversation-runs")
        .join("conv-1")
        .join("aionrs-run-turn_t1");
    assert!(
        !run_path.join("input").join("escaped.txt").exists() && !run_path.join("escaped.txt").exists(),
        "no copy may land outside input/"
    );
    assert!(!run_path.exists(), "failed mint leaves no run dir behind");
    assert_eq!(
        std::fs::read(root.path().join("escaped.txt")).unwrap(),
        b"victim",
        "source file bytes untouched"
    );
}

#[tokio::test]
async fn mixed_relative_and_absolute_inputs_fall_back_to_leaf_names() {
    let root = tempfile::tempdir().unwrap();
    let abs_dir = tempfile::tempdir().unwrap();
    let abs_file = abs_dir.path().join("absolute.txt");
    std::fs::write(&abs_file, b"abs-bytes").unwrap();
    // A cwd-relative source: its parent ([]) shares no components with the
    // absolute parent ([RootDir, ...]) → no common parent → leaf fallback.
    let rel_dir = std::path::Path::new("run-dir-test-mixed");
    std::fs::create_dir_all(rel_dir).unwrap();
    let rel_file = rel_dir.join("relative.txt");
    std::fs::write(&rel_file, b"rel-bytes").unwrap();

    let files = vec![
        abs_file.to_string_lossy().to_string(),
        rel_file.to_string_lossy().to_string(),
    ];
    let run = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &files)
        .await
        .unwrap();

    assert_eq!(
        std::fs::read(run.path.join("input/absolute.txt")).unwrap(),
        b"abs-bytes",
        "absolute source lands at its leaf name"
    );
    assert_eq!(
        std::fs::read(run.path.join("input/relative.txt")).unwrap(),
        b"rel-bytes",
        "relative source lands at its leaf name"
    );
    assert!(
        !run.path.join("input").join("run-dir-test-mixed").exists(),
        "no nested structure from the mixed pair"
    );
    std::fs::remove_dir_all(rel_dir).unwrap();
}

#[tokio::test]
async fn disjoint_relative_trees_fall_back_to_leaf_names() {
    let root = tempfile::tempdir().unwrap();
    let dir_a = std::path::Path::new("run-dir-test-disjoint-a");
    let dir_b = std::path::Path::new("run-dir-test-disjoint-b");
    std::fs::create_dir_all(dir_a).unwrap();
    std::fs::create_dir_all(dir_b).unwrap();
    std::fs::write(dir_a.join("one.txt"), b"one").unwrap();
    std::fs::write(dir_b.join("two.txt"), b"two").unwrap();

    let files = vec![
        dir_a.join("one.txt").to_string_lossy().to_string(),
        dir_b.join("two.txt").to_string_lossy().to_string(),
    ];
    let run = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &files)
        .await
        .unwrap();

    assert_eq!(std::fs::read(run.path.join("input/one.txt")).unwrap(), b"one");
    assert_eq!(std::fs::read(run.path.join("input/two.txt")).unwrap(), b"two");

    std::fs::remove_dir_all(dir_a).unwrap();
    std::fs::remove_dir_all(dir_b).unwrap();
}

#[tokio::test]
async fn leaf_name_collision_without_common_parent_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let dir_a = std::path::Path::new("run-dir-test-collide-a");
    let dir_b = std::path::Path::new("run-dir-test-collide-b");
    std::fs::create_dir_all(dir_a).unwrap();
    std::fs::create_dir_all(dir_b).unwrap();
    std::fs::write(dir_a.join("dup.txt"), b"a").unwrap();
    std::fs::write(dir_b.join("dup.txt"), b"b").unwrap();

    let files = vec![
        dir_a.join("dup.txt").to_string_lossy().to_string(),
        dir_b.join("dup.txt").to_string_lossy().to_string(),
    ];
    let err = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &files)
        .await
        .unwrap_err();

    assert!(matches!(err, RunDirError::Collision(_)), "got: {err:?}");
    std::fs::remove_dir_all(dir_a).unwrap();
    std::fs::remove_dir_all(dir_b).unwrap();
}

// ── Label resilience (P2-3) ─────────────────────────────────────────

#[tokio::test]
async fn corrupt_extra_json_still_mints_with_agent_type_label() {
    let root = tempfile::tempdir().unwrap();
    let mut broken = row("aionrs", serde_json::json!({}));
    broken.extra = "{not valid json".to_string();

    let run = mint_run_dir(root.path(), &broken, "turn_t1", &[]).await.unwrap();

    assert_eq!(
        run.path.file_name().unwrap(),
        "aionrs-run-turn_t1",
        "label falls back to the agent serde name"
    );
}

#[test]
fn run_dir_path_falls_back_to_serde_name_on_corrupt_extra() {
    // Acp rows read `extra.backend`; a corrupt extra yields the agent serde
    // name instead of failing the run dir path computation.
    let mut broken = row("acp", serde_json::json!({ "backend": "claude" }));
    broken.extra = "]]]".to_string();
    let path = run_dir_path(Path::new("/tmp"), &broken, "turn_t1").unwrap();
    assert_eq!(path.file_name().unwrap(), "acp-run-turn_t1");
}

// ── Orphan cleanup on partial mint (P2-5) ───────────────────────────

#[tokio::test]
async fn failed_mint_after_partial_copy_leaves_no_orphan_run_dir() {
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("good.txt"), b"good").unwrap();
    // Named so the good source sorts (and copies) first.
    let missing = root.path().join("z-missing.txt");

    let files = vec![
        src.join("good.txt").to_string_lossy().to_string(),
        missing.to_string_lossy().to_string(),
    ];
    let err = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &files)
        .await
        .unwrap_err();

    assert!(matches!(err, RunDirError::MissingSource(_)), "got: {err:?}");
    let run_path = root
        .path()
        .join("conversation-runs")
        .join("conv-1")
        .join("aionrs-run-turn_t1");
    assert!(!run_path.exists(), "partially minted run dir must be removed");
    assert_eq!(std::fs::read(src.join("good.txt")).unwrap(), b"good");
}

// ── Cleanup gate validation (P2-4) ──────────────────────────────────

#[tokio::test]
async fn cleanup_rejects_corrupt_manifest_and_keeps_dir() {
    let root = tempfile::tempdir().unwrap();
    let run = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &[])
        .await
        .unwrap();
    std::fs::write(run.path.join(RUN_MANIFEST_FILE), "{ corrupt json").unwrap();

    assert!(!remove_collected_run_dir(&run.path).await.unwrap());
    assert!(run.path.is_dir(), "corrupt manifest must not authorize removal");
    assert!(run.path.join("input").is_dir());
}

#[tokio::test]
async fn cleanup_rejects_foreign_manifest_fields_and_keeps_dir() {
    let root = tempfile::tempdir().unwrap();
    let run = mint_run_dir(root.path(), &row("aionrs", serde_json::json!({})), "turn_t1", &[])
        .await
        .unwrap();

    for foreign in [
        r#"{"schemaVersion": 99, "status": "completed"}"#,
        r#"{"schemaVersion": 1, "status": "purged"}"#,
        r#"{"schemaVersion": 1}"#,
    ] {
        std::fs::write(run.path.join(RUN_MANIFEST_FILE), foreign).unwrap();
        assert!(
            !remove_collected_run_dir(&run.path).await.unwrap(),
            "foreign manifest must not authorize removal: {foreign}"
        );
        assert!(run.path.is_dir());
    }
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
