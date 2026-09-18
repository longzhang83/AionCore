//! Run consumer orchestration (T0-RUN-CONSUMER Slice R2): the pipeline that
//! turns a held admission into a submitted output manifest.
//!
//! Stage chain per admission, journaled after every completed stage:
//!
//! ```text
//! fetch input manifest → materialize (E1) → execute (R3 port)
//!   → capture (R1) → assemble (E2) → register snapshot (S-card port)
//!   → submit manifest (E3 uplink)
//! ```
//!
//! ## Durable state: the run-dir journal
//!
//! Each consumed admission owns `{runs_root}/{run_admission_id}/` with a
//! `workspace/` subtree (materialized input state + the agent's changes —
//! the capture root) and `consumer-state.json`, an append-by-stage journal.
//! Re-entry after a crash resumes from the deepest journaled stage, so the
//! externally visible identities stay stable across restarts:
//!
//! - `InputMaterialized` — the workspace is the frozen admitted base;
//!   materialization never re-runs. The pinned manifest is re-fetched and
//!   re-verified against the journal (drift fails closed).
//! - `Captured` — the captured member list (with its content_ids) is
//!   journaled; a re-entry re-captures only to VERIFY the workspace is
//!   unchanged (content_id is minted per capture, so the journaled list is
//!   the identity), and drift fails closed.
//! - `Assembled` — the full output manifest is journaled; `output_manifest_id`
//!   must not change between restarts or ACP would see two identities.
//! - `Registered` / `Submitted` — terminal boundaries; a re-entry after
//!   `Submitted` returns the journaled manifest without touching ACP.
//!
//! A crash between an ACP-side success and its journal write re-sends the
//! request on resume; idempotency of registration (409 semantics) is frozen
//! with the S card. Like the G02-b manifest, the journal does not
//! self-digest (a later card owns tamper evidence).
//!
//! ## Honest gaps: ports without production implementations
//!
//! - `RunExecutor` (R3): no production implementation exists yet, so the app
//!   cannot activate the consumer — nothing pretends a run happened.
//! - `CapturedSnapshotRegistrar` (S card): the ACP route does not exist yet.
//!   Deps without a registrar surface a typed
//!   [`RunConsumerError::RegistrationUnavailable`] at the registration
//!   stage — the PreconditionFailed posture frozen in the coordination doc.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aionui_db::IRunAdmissionRepository;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::run_admission_receive::RunAdmissionRecord;
use crate::run_capture::capture_workspace_state;
use crate::run_input_downlink::{RunInputDownlink, RunInputManifest, RunInputManifestMember};
use crate::run_input_materialization::materialize_run_input;
use crate::run_manifest_digest::workspace_manifest_digest;
use crate::run_output_assembly::assemble_run_output;
use crate::run_output_uplink::{RunOutputManifest, RunOutputUplink};

/// Name of the consumer journal inside every admission run directory.
pub const CONSUMER_STATE_FILE: &str = "consumer-state.json";
/// Name of the run workspace subtree (materialized input + agent changes).
pub const WORKSPACE_DIR: &str = "workspace";

const JOURNAL_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum RunConsumerError {
    #[error("run consumer journal is not well-formed: {0}")]
    InvalidJournal(String),
    #[error("stored admission record is not well-formed: {0}")]
    StoredRecordInvalid(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("journal serialization failed: {0}")]
    JournalSerde(#[from] serde_json::Error),
    #[error("run input downlink failed: {0}")]
    Downlink(#[from] crate::run_input_downlink::RunInputDownlinkError),
    #[error("input materialization failed: {0}")]
    Materialize(#[from] crate::run_input_materialization::RunInputMaterializeError),
    #[error("pinned input manifest drifted since materialization")]
    PinnedManifestDrift,
    #[error("run execution failed: {0}")]
    Execute(#[from] RunExecuteError),
    #[error("workspace capture failed: {0}")]
    Capture(#[from] crate::run_capture::RunCaptureError),
    #[error("workspace drifted since capture")]
    WorkspaceDriftedSinceCapture,
    #[error("output assembly failed: {0}")]
    Assemble(#[from] crate::run_output_assembly::RunOutputAssemblyError),
    #[error(
        "captured-snapshot registration is not wired (T0-ACP-CAPTURED-SNAPSHOT-REGISTRATION has no production transport yet)"
    )]
    RegistrationUnavailable,
    #[error("captured-snapshot registration failed: {0}")]
    Register(#[from] RegisterSnapshotError),
    #[error("output submission failed: {0}")]
    Submit(#[from] crate::run_output_uplink::RunOutputUplinkError),
}

/// The run execution port (T0-RUN-CONSUMER Slice R3 owns the production
/// implementation): drives the agent run against the materialized workspace.
/// The consumer calls it exactly once per consumption between input
/// materialization and capture; a failure stops the pipeline with the journal
/// parked at the last completed stage, so a resume re-runs the executor.
#[async_trait]
pub trait RunExecutor: Send + Sync {
    async fn execute(&self, context: &RunExecuteContext) -> Result<(), RunExecuteError>;
}

#[derive(Debug, thiserror::Error)]
pub enum RunExecuteError {
    #[error("{0}")]
    Failed(String),
}

/// Everything the executor needs to drive one admitted run.
pub struct RunExecuteContext {
    pub admission: RunAdmissionRecord,
    /// The pinned input manifest (digest verified against the admission).
    pub input_manifest: RunInputManifest,
    /// The run workspace: materialized input state plus the agent's changes.
    pub workspace: PathBuf,
}

/// The captured-snapshot registration port. The S card
/// (T0-ACP-CAPTURED-SNAPSHOT-REGISTRATION) owns the production transport:
/// captured-object upload plus snapshot manifest registration. Until it
/// lands, no production implementation exists and the consumer treats the
/// port's absence as a typed precondition failure.
#[async_trait]
pub trait CapturedSnapshotRegistrar: Send + Sync {
    async fn register_captured_snapshot(&self, context: &RegisterSnapshotContext) -> Result<(), RegisterSnapshotError>;
}

#[derive(Debug, thiserror::Error)]
pub enum RegisterSnapshotError {
    #[error("snapshot registration rejected: status {status} code {code}")]
    Rejected { status: u16, code: String },
    #[error("snapshot registration transport failed")]
    Unavailable,
}

/// Everything the registrar needs to upload and register one snapshot.
pub struct RegisterSnapshotContext {
    pub admission: RunAdmissionRecord,
    /// The assembled snapshot manifest (format + digest-bound members) — the
    /// artifact the ACP registration route will accept.
    pub snapshot: RunInputManifest,
    /// The workspace the snapshot members resolve against (upload bytes).
    pub workspace: PathBuf,
}

/// The consumer's collaborators. The registrar is `Option` on purpose: a
/// deployment without the S-card transport stays constructible and fails
/// typed at the registration stage instead of pretending completion.
pub struct RunConsumerDeps {
    pub downlink: Arc<dyn RunInputDownlink>,
    pub executor: Arc<dyn RunExecutor>,
    pub registrar: Option<Arc<dyn CapturedSnapshotRegistrar>>,
    pub uplink: Arc<dyn RunOutputUplink>,
    /// Clock for `captured_at_ms` (injected so tests are deterministic).
    pub now_unix_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
}

/// The result of a completed consumption: the manifest ACP accepted (the
/// persisted echo's identity equals the submitted one) and its digest.
#[derive(Debug)]
pub struct RunConsumptionReceipt {
    pub run_admission_id: String,
    pub submitted_manifest: RunOutputManifest,
}

/// One journaled completed stage. The `completed` list is append-by-stage;
/// the deepest entry is the resume point.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
enum CompletedStage {
    InputMaterialized { input_manifest_sha256: String },
    Executed,
    Captured { members: Vec<RunInputManifestMember> },
    Assembled { manifest: Box<RunOutputManifest> },
    Registered,
    Submitted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunConsumerJournal {
    schema_version: u8,
    run_admission_id: String,
    completed: Vec<CompletedStage>,
}

impl RunConsumerJournal {
    fn deepest<F: Fn(&CompletedStage) -> bool>(&self, matches: F) -> Option<&CompletedStage> {
        self.completed.iter().rev().find(|stage| matches(stage))
    }
}

/// Loads the journal for `record`, failing closed on version, identity, or
/// shape mismatches. A missing file is a fresh consumption.
fn load_journal(runs_root: &Path, record: &RunAdmissionRecord) -> Result<RunConsumerJournal, RunConsumerError> {
    let journal_path = runs_root.join(&record.run_admission_id).join(CONSUMER_STATE_FILE);
    let raw = match std::fs::read_to_string(&journal_path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RunConsumerJournal {
                schema_version: JOURNAL_SCHEMA_VERSION,
                run_admission_id: record.run_admission_id.clone(),
                completed: Vec::new(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    let journal: RunConsumerJournal =
        serde_json::from_str(&raw).map_err(|error| RunConsumerError::InvalidJournal(error.to_string()))?;
    if journal.schema_version != JOURNAL_SCHEMA_VERSION {
        return Err(RunConsumerError::InvalidJournal(format!(
            "unsupported schema version {}",
            journal.schema_version
        )));
    }
    if journal.run_admission_id != record.run_admission_id {
        return Err(RunConsumerError::InvalidJournal(format!(
            "journal belongs to admission {} not {}",
            journal.run_admission_id, record.run_admission_id
        )));
    }
    Ok(journal)
}

/// Atomically persists the journal (write to a `.part` sibling, rename over).
fn persist_journal(runs_root: &Path, journal: &RunConsumerJournal) -> Result<(), RunConsumerError> {
    let run_dir = runs_root.join(&journal.run_admission_id);
    let journal_path = run_dir.join(CONSUMER_STATE_FILE);
    let part_path = run_dir.join(format!("{CONSUMER_STATE_FILE}.part"));
    let raw = serde_json::to_vec_pretty(journal)?;
    std::fs::write(&part_path, raw)?;
    std::fs::rename(&part_path, &journal_path)?;
    Ok(())
}

/// Drives one admission through the full stage chain, resuming from the run
/// directory's journal when a previous attempt got part-way.
pub async fn consume_run_admission(
    deps: &RunConsumerDeps,
    record: &RunAdmissionRecord,
    runs_root: &Path,
) -> Result<RunConsumptionReceipt, RunConsumerError> {
    let run_dir = runs_root.join(&record.run_admission_id);
    let workspace = run_dir.join(WORKSPACE_DIR);
    std::fs::create_dir_all(&workspace)?;

    let mut journal = load_journal(runs_root, record)?;

    // Stage 1: pin the input manifest. Always re-fetched (it is the
    // immutable authority); on resume, re-verified against the journal.
    let input_manifest = deps.downlink.fetch_input_manifest(&record.run_admission_id).await?;
    let input_manifest_sha256 = workspace_manifest_digest(&input_manifest.manifest_format, &input_manifest.members);
    if input_manifest_sha256 != input_manifest.manifest_sha256 || input_manifest_sha256 != record.base.manifest_sha256 {
        return Err(RunConsumerError::PinnedManifestDrift);
    }
    if let Some(CompletedStage::InputMaterialized {
        input_manifest_sha256: journaled,
    }) = journal.deepest(|stage| matches!(stage, CompletedStage::InputMaterialized { .. }))
    {
        if *journaled != input_manifest_sha256 {
            return Err(RunConsumerError::PinnedManifestDrift);
        }
    } else {
        materialize_run_input(
            deps.downlink.as_ref(),
            &record.run_admission_id,
            &input_manifest,
            Some(&record.base.manifest_sha256),
            &workspace,
        )
        .await?;
        journal.completed.push(CompletedStage::InputMaterialized {
            input_manifest_sha256: input_manifest_sha256.clone(),
        });
        persist_journal(runs_root, &journal)?;
    }

    // Stage 2: execute. Re-runs on resume (the journal records completion,
    // not progress inside the stage — at-most-once execution semantics are
    // R3's contract).
    if !journal
        .completed
        .iter()
        .any(|stage| matches!(stage, CompletedStage::Executed))
    {
        deps.executor
            .execute(&RunExecuteContext {
                admission: record.clone(),
                input_manifest: input_manifest.clone(),
                workspace: workspace.clone(),
            })
            .await?;
        journal.completed.push(CompletedStage::Executed);
        persist_journal(runs_root, &journal)?;
    }

    // Stage 3: capture. The journaled list is the capture identity; re-capture
    // only verifies the workspace has not drifted since. The pinned input
    // members drive the unchanged-content id reuse the delta depends on.
    let captured: Vec<RunInputManifestMember> = if let Some(CompletedStage::Captured { members }) =
        journal.deepest(|stage| matches!(stage, CompletedStage::Captured { .. }))
    {
        let recaptured = capture_workspace_state(&workspace, &input_manifest.members)?;
        if !captured_state_unchanged(&recaptured, members) {
            return Err(RunConsumerError::WorkspaceDriftedSinceCapture);
        }
        members.clone()
    } else {
        let members = capture_workspace_state(&workspace, &input_manifest.members)?;
        journal.completed.push(CompletedStage::Captured {
            members: members.clone(),
        });
        persist_journal(runs_root, &journal)?;
        members
    };

    // Stage 4: assemble. The journaled manifest keeps `output_manifest_id`
    // stable across restarts.
    let output_manifest: RunOutputManifest = if let Some(CompletedStage::Assembled { manifest }) =
        journal.deepest(|stage| matches!(stage, CompletedStage::Assembled { .. }))
    {
        manifest.clone()
    } else {
        let assembled = assemble_run_output(record, &input_manifest, &captured, (deps.now_unix_ms)())?;
        journal.completed.push(CompletedStage::Assembled {
            manifest: assembled.manifest.clone(),
        });
        persist_journal(runs_root, &journal)?;
        assembled.manifest
    };

    // Stage 5: register the captured snapshot with ACP (S card port).
    if !journal
        .completed
        .iter()
        .any(|stage| matches!(stage, CompletedStage::Registered))
    {
        match &deps.registrar {
            Some(registrar) => {
                registrar
                    .register_captured_snapshot(&RegisterSnapshotContext {
                        admission: record.clone(),
                        snapshot: crate::run_input_downlink::RunInputManifest {
                            // The registered artifact is a workspace content
                            // manifest (E2's `captured_snapshot`), never the
                            // output-manifest format.
                            manifest_format: crate::run_manifest_digest::WORKSPACE_MANIFEST_FORMAT_V1.to_owned(),
                            members: captured.clone(),
                            manifest_sha256: output_manifest.captured_output_snapshot_sha256.clone(),
                        },
                        workspace: workspace.clone(),
                    })
                    .await?;
                journal.completed.push(CompletedStage::Registered);
                persist_journal(runs_root, &journal)?;
            }
            None => return Err(RunConsumerError::RegistrationUnavailable),
        }
    }

    // Stage 6: submit the output manifest (E3 uplink).
    if !journal
        .completed
        .iter()
        .any(|stage| matches!(stage, CompletedStage::Submitted))
    {
        deps.uplink.submit_output_manifest(&output_manifest).await?;
        journal.completed.push(CompletedStage::Submitted);
        persist_journal(runs_root, &journal)?;
    }

    Ok(RunConsumptionReceipt {
        run_admission_id: record.run_admission_id.clone(),
        submitted_manifest: output_manifest,
    })
}

/// Compares a fresh capture against the journaled one. content_id is
/// content-addressed (R1 amendment), so full member equality is the honest
/// drift check — any byte, path, or size difference fails the resume.
fn captured_state_unchanged(fresh: &[RunInputManifestMember], journaled: &[RunInputManifestMember]) -> bool {
    fresh == journaled
}

/// One admission's outcome in a pending-consumption sweep — per-admission
/// errors never abort the sweep.
pub struct PendingConsumptionOutcome {
    pub run_admission_id: String,
    pub result: Result<RunConsumptionReceipt, RunConsumerError>,
}

/// Discovers held admissions and consumes every one whose journal has not
/// reached `Submitted`. Malformed stored records are surfaced as per-admission
/// outcomes, not sweep failures. Trigger wiring (who calls this and when)
/// is the R4 env-assembly card's.
pub async fn consume_pending_run_admissions(
    deps: &RunConsumerDeps,
    repository: &dyn IRunAdmissionRepository,
    runs_root: &Path,
) -> Result<Vec<PendingConsumptionOutcome>, aionui_db::DbError> {
    let stored = repository.list().await?;
    let mut outcomes = Vec::with_capacity(stored.len());
    for row in stored {
        let outcome = match serde_json::from_str::<RunAdmissionRecord>(&row.record_json) {
            Ok(record) => {
                let already_submitted = load_journal(runs_root, &record)
                    .map(|journal| {
                        journal
                            .completed
                            .iter()
                            .any(|stage| matches!(stage, CompletedStage::Submitted))
                    })
                    .unwrap_or(false);
                if already_submitted {
                    continue;
                }
                consume_run_admission(deps, &record, runs_root).await
            }
            Err(error) => Err(RunConsumerError::StoredRecordInvalid(error.to_string())),
        };
        outcomes.push(PendingConsumptionOutcome {
            run_admission_id: row.run_admission_id,
            result: outcome,
        });
    }
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_admission_receive::{
        RunAdmissionCorePrincipal, RunAdmissionEditScope, RunAdmissionEnvironmentAuthority, RunAdmissionExpectedBase,
    };
    use crate::run_input_downlink::RunInputDownlinkError;
    use crate::run_manifest_digest::WORKSPACE_MANIFEST_FORMAT_V1;
    use crate::run_output_uplink::RunOutputUplinkError;
    use sha2::{Digest as _, Sha256};
    use tokio::io::AsyncWriteExt as _;

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn hex_digest(body: &[u8]) -> String {
        hex::encode(Sha256::digest(body))
    }

    // ---- fakes -----------------------------------------------------------

    struct FakeDownlink {
        manifest: RunInputManifest,
        objects: HashMap<String, Vec<u8>>,
    }

    #[async_trait]
    impl RunInputDownlink for FakeDownlink {
        async fn fetch_input_manifest(
            &self,
            _run_admission_id: &str,
        ) -> Result<RunInputManifest, RunInputDownlinkError> {
            Ok(self.manifest.clone())
        }

        async fn fetch_input_object(
            &self,
            _run_admission_id: &str,
            member: &RunInputManifestMember,
            destination: &Path,
        ) -> Result<crate::run_input_downlink::RunInputObjectReceipt, RunInputDownlinkError> {
            let bytes = self
                .objects
                .get(&member.content.content_id)
                .ok_or(RunInputDownlinkError::Rejected {
                    status: 404,
                    code: "object_not_in_input_manifest".to_owned(),
                })?;
            if let Some(parent) = destination.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|_| RunInputDownlinkError::Unavailable)?;
            }
            let mut file = tokio::fs::File::create(destination)
                .await
                .map_err(|_| RunInputDownlinkError::Unavailable)?;
            file.write_all(bytes)
                .await
                .map_err(|_| RunInputDownlinkError::Unavailable)?;
            Ok(crate::run_input_downlink::RunInputObjectReceipt {
                bytes_written: bytes.len() as u64,
                plaintext_sha256: hex_digest(bytes),
            })
        }
    }

    struct RecordingExecutor {
        calls: std::sync::Mutex<Vec<PathBuf>>,
        output: Option<Vec<u8>>,
    }

    #[async_trait]
    impl RunExecutor for RecordingExecutor {
        async fn execute(&self, context: &RunExecuteContext) -> Result<(), RunExecuteError> {
            self.calls.lock().unwrap().push(context.workspace.clone());
            if let Some(output) = &self.output {
                let out = context.workspace.join("out/result.txt");
                tokio::fs::create_dir_all(out.parent().unwrap()).await.unwrap();
                tokio::fs::write(out, output).await.unwrap();
            }
            Ok(())
        }
    }

    struct RecordingRegistrar {
        calls: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl CapturedSnapshotRegistrar for RecordingRegistrar {
        async fn register_captured_snapshot(
            &self,
            context: &RegisterSnapshotContext,
        ) -> Result<(), RegisterSnapshotError> {
            self.calls
                .lock()
                .unwrap()
                .push(context.snapshot.manifest_sha256.clone());
            Ok(())
        }
    }

    struct RecordingUplink {
        calls: std::sync::Mutex<Vec<RunOutputManifest>>,
    }

    #[async_trait]
    impl RunOutputUplink for RecordingUplink {
        async fn submit_output_manifest(
            &self,
            manifest: &RunOutputManifest,
        ) -> Result<RunOutputManifest, RunOutputUplinkError> {
            self.calls.lock().unwrap().push(manifest.clone());
            Ok(manifest.clone())
        }
    }

    // ---- fixtures --------------------------------------------------------

    fn ws_member(resource_path: &str, content_id: &str, digest: &str, size: i64) -> RunInputManifestMember {
        RunInputManifestMember {
            resource_path: resource_path.to_owned(),
            content: crate::run_input_downlink::RunContentIdentity {
                content_id: content_id.to_owned(),
                plaintext_sha256: digest.to_owned(),
                plaintext_size: size,
            },
        }
    }

    fn admission(input_manifest: &RunInputManifest) -> RunAdmissionRecord {
        RunAdmissionRecord {
            run_admission_id: "adm-1".to_owned(),
            admission_version: 1,
            actor_delegation_id: "del-1".to_owned(),
            actor_delegation_consumption_id: "con-1".to_owned(),
            admission_request_sha256: SHA_A.to_owned(),
            tenant_id: "tenant-1".to_owned(),
            resource_organization_id: "org-1".to_owned(),
            workspace_id: "ws-1".to_owned(),
            edit_session_id: "session-1".to_owned(),
            base: RunAdmissionExpectedBase {
                kind: "workspace_manifest".to_owned(),
                revision_id: String::new(),
                manifest_sha256: input_manifest.manifest_sha256.clone(),
            },
            scope: RunAdmissionEditScope {
                kind: "workspace".to_owned(),
                resource_paths: Vec::new(),
            },
            subject_id: "user-1".to_owned(),
            device_id: "device-1".to_owned(),
            run_id: "run-1".to_owned(),
            attempt_id: "attempt-1".to_owned(),
            owner_epoch: 1,
            core_principal: RunAdmissionCorePrincipal {
                service_id: "core-1".to_owned(),
                service_role: "core".to_owned(),
                workload_instance_id: "wi-1".to_owned(),
                credential_key_id: "ck-1".to_owned(),
                certificate_thumbprint_s256: "a".repeat(43),
                service_authority_epoch: 1,
            },
            isolation_profile_sha256: SHA_B.to_owned(),
            command_sha256: SHA_C.to_owned(),
            execution_authority_epoch: 1,
            data_classification: "synthetic".to_owned(),
            environment: RunAdmissionEnvironmentAuthority {
                environment_authority_id: "env-1".to_owned(),
                environment_kind: "non-production".to_owned(),
                environment_authority_epoch: 1,
            },
            issued_at_ms: 1_760_000_000_000,
            authorization_ttl_seconds: 30,
            expires_at_ms: 1_760_000_003_000,
            state: "active".to_owned(),
        }
    }

    fn fixture() -> (RunAdmissionRecord, RunInputManifest, FakeDownlink) {
        let mut objects = HashMap::new();
        objects.insert("obj-a".to_owned(), b"alpha".to_vec());
        let members = vec![ws_member(
            "docs/a.txt",
            "obj-a",
            &hex_digest(b"alpha"),
            b"alpha".len() as i64,
        )];
        let manifest = RunInputManifest {
            manifest_format: WORKSPACE_MANIFEST_FORMAT_V1.to_owned(),
            manifest_sha256: workspace_manifest_digest(WORKSPACE_MANIFEST_FORMAT_V1, &members),
            members,
        };
        let record = admission(&manifest);
        (record, manifest.clone(), FakeDownlink { manifest, objects })
    }

    fn deps(
        downlink: FakeDownlink,
        executor: Arc<RecordingExecutor>,
        registrar: Option<Arc<RecordingRegistrar>>,
        uplink: Arc<RecordingUplink>,
    ) -> RunConsumerDeps {
        RunConsumerDeps {
            downlink: Arc::new(downlink),
            executor,
            registrar: registrar.map(|recorder| recorder as Arc<dyn CapturedSnapshotRegistrar>),
            uplink,
            now_unix_ms: Arc::new(|| 1_760_000_010_000),
        }
    }

    // ---- tests -----------------------------------------------------------

    #[tokio::test]
    async fn happy_path_drives_every_stage_and_produces_a_submission() {
        let (record, _manifest, downlink) = fixture();
        let executor = Arc::new(RecordingExecutor {
            calls: std::sync::Mutex::new(Vec::new()),
            output: Some(b"result".to_vec()),
        });
        let registrar = Arc::new(RecordingRegistrar {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let uplink = Arc::new(RecordingUplink {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let deps = deps(downlink, executor.clone(), Some(registrar.clone()), uplink.clone());
        let runs = tempfile::tempdir().unwrap();

        let receipt = consume_run_admission(&deps, &record, runs.path())
            .await
            .expect("consumption should complete");

        assert_eq!(receipt.run_admission_id, "adm-1");
        // The executor saw the materialized workspace; the uplink saw exactly
        // one submission whose delta is the agent's output file.
        assert_eq!(executor.calls.lock().unwrap().len(), 1);
        assert_eq!(uplink.calls.lock().unwrap().len(), 1);
        let submitted = &uplink.calls.lock().unwrap()[0];
        assert_eq!(submitted, &receipt.submitted_manifest);
        assert_eq!(submitted.members.len(), 1);
        assert_eq!(submitted.members[0].resource_path, "out/result.txt");
        assert_eq!(submitted.members[0].change.change_kind, "add");
        assert_eq!(
            submitted.members[0]
                .change
                .output_content
                .content
                .as_ref()
                .unwrap()
                .plaintext_sha256,
            hex_digest(b"result")
        );
        // The registrar received the assembled snapshot digest.
        assert_eq!(registrar.calls.lock().unwrap().len(), 1);
        // The journal ends at Submitted.
        let journal: RunConsumerJournal = serde_json::from_str(
            &std::fs::read_to_string(runs.path().join("adm-1").join(CONSUMER_STATE_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(journal.completed.len(), 6);
        assert!(matches!(journal.completed.last(), Some(CompletedStage::Submitted)));
    }

    #[tokio::test]
    async fn resume_after_completion_returns_the_journaled_manifest_without_side_effects() {
        let (record, _manifest, downlink) = fixture();
        let executor = Arc::new(RecordingExecutor {
            calls: std::sync::Mutex::new(Vec::new()),
            output: Some(b"result".to_vec()),
        });
        let registrar = Arc::new(RecordingRegistrar {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let uplink = Arc::new(RecordingUplink {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let deps = deps(downlink, executor.clone(), Some(registrar.clone()), uplink.clone());
        let runs = tempfile::tempdir().unwrap();

        let first = consume_run_admission(&deps, &record, runs.path()).await.unwrap();
        let second = consume_run_admission(&deps, &record, runs.path()).await.unwrap();

        // Re-entry replays nothing: identities stable, side-effect ports idle.
        assert_eq!(
            first.submitted_manifest.output_manifest_id,
            second.submitted_manifest.output_manifest_id
        );
        assert_eq!(executor.calls.lock().unwrap().len(), 1);
        assert_eq!(registrar.calls.lock().unwrap().len(), 1);
        assert_eq!(uplink.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn registration_without_the_s_card_transport_fails_typed() {
        let (record, _manifest, downlink) = fixture();
        let executor = Arc::new(RecordingExecutor {
            calls: std::sync::Mutex::new(Vec::new()),
            output: Some(b"result".to_vec()),
        });
        let uplink = Arc::new(RecordingUplink {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let deps = deps(downlink, executor, None, uplink);
        let runs = tempfile::tempdir().unwrap();

        let error = consume_run_admission(&deps, &record, runs.path()).await.unwrap_err();

        assert!(matches!(error, RunConsumerError::RegistrationUnavailable));
        // The journal stops after Assembled — nothing pretends registration
        // happened, and a later resume with a real registrar continues.
        let journal: RunConsumerJournal = serde_json::from_str(
            &std::fs::read_to_string(runs.path().join("adm-1").join(CONSUMER_STATE_FILE)).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            journal.completed.last(),
            Some(CompletedStage::Assembled { .. })
        ));
    }

    #[tokio::test]
    async fn corrupted_journal_manifest_digest_fails_closed_on_resume() {
        let (record, _manifest, downlink) = fixture();
        let executor = Arc::new(RecordingExecutor {
            calls: std::sync::Mutex::new(Vec::new()),
            output: None,
        });
        let registrar = Arc::new(RecordingRegistrar {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let uplink = Arc::new(RecordingUplink {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let deps = deps(downlink, executor, Some(registrar), uplink);
        let runs = tempfile::tempdir().unwrap();

        // Seed a journal that claims materialization from a digest that is
        // neither the pinned manifest's nor the admission base's — journal
        // corruption must stop the resume, never proceed on stale state.
        let run_dir = runs.path().join("adm-1");
        std::fs::create_dir_all(&run_dir).unwrap();
        let journal = RunConsumerJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            run_admission_id: "adm-1".to_owned(),
            completed: vec![CompletedStage::InputMaterialized {
                input_manifest_sha256: "0".repeat(64),
            }],
        };
        std::fs::write(
            run_dir.join(CONSUMER_STATE_FILE),
            serde_json::to_vec_pretty(&journal).unwrap(),
        )
        .unwrap();

        let error = consume_run_admission(&deps, &record, runs.path()).await.unwrap_err();

        assert!(matches!(error, RunConsumerError::PinnedManifestDrift));
        // The executor never ran on top of the unverified state.
        let journal: RunConsumerJournal =
            serde_json::from_str(&std::fs::read_to_string(run_dir.join(CONSUMER_STATE_FILE)).unwrap()).unwrap();
        assert_eq!(journal.completed.len(), 1);
    }

    #[tokio::test]
    async fn materialization_failure_leaves_no_input_materialized_stage() {
        let (record, _manifest, mut downlink) = fixture();
        downlink.objects.remove("obj-a");
        let executor = Arc::new(RecordingExecutor {
            calls: std::sync::Mutex::new(Vec::new()),
            output: None,
        });
        let registrar = Arc::new(RecordingRegistrar {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let uplink = Arc::new(RecordingUplink {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let deps = deps(downlink, executor, Some(registrar), uplink);
        let runs = tempfile::tempdir().unwrap();

        let error = consume_run_admission(&deps, &record, runs.path()).await.unwrap_err();

        assert!(matches!(error, RunConsumerError::Materialize(_)));
        let journal_path = runs.path().join("adm-1").join(CONSUMER_STATE_FILE);
        assert!(
            !journal_path.exists(),
            "no stage may be journaled before materialization completes"
        );
    }
}
