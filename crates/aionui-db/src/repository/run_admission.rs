use crate::error::DbError;

/// A new run admission to persist (`POST /internal/run-authority/v1/admissions`,
/// T0-ACP-ADMISSION-DELIVERY Slice B2).
///
/// `record_json` is the canonical JSON projection of the accepted
/// `RunAdmissionRecord` (frozen ACP Go json tags). It is stored verbatim and
/// echoed on 200 — the Agent Control Plane strict-decodes the echo and
/// validates the identity triple, so the stored bytes are the wire truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRunAdmission {
    /// Immutable admission identity; the table's primary key. A repeat
    /// delivery of the same admission is a duplicate, never a re-adjudication.
    pub run_admission_id: String,
    /// The caller's canonical UUIDv4 `Idempotency-Key` header, recorded for
    /// delivery traceability. Duplicate detection keys on
    /// `run_admission_id` only.
    pub idempotency_key: String,
    /// Canonical JSON of the admitted record, echoed verbatim on 200.
    pub record_json: String,
}

/// Outcome of an admission attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunAdmissionOutcome {
    /// The admission was persisted; the caller answers 200 with the record
    /// echo.
    Admitted,
    /// This `run_admission_id` is already held (an earlier delivery attempt
    /// was received but its response was lost). The caller answers
    /// 409 `run_admission_duplicate` and the delivery counts as delivered.
    Duplicate,
}

/// A stored admission row exposed to read paths (run-consumer discovery,
/// T0-RUN-CONSUMER Slice R2). `record_json` is the verbatim canonical
/// projection persisted at admit time — the wire truth, re-parsed by readers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRunAdmission {
    pub run_admission_id: String,
    pub idempotency_key: String,
    pub record_json: String,
}

/// Run admission persistence for the Core receive face of the ACP
/// admission push (T0-ACP-ADMISSION-DELIVERY).
///
/// Admissions are immutable authority records: a repeated `run_admission_id`
/// is a duplicate outcome, not an update, and stored records never change.
#[async_trait::async_trait]
pub trait IRunAdmissionRepository: Send + Sync {
    /// Attempts to persist the admission atomically.
    async fn admit(&self, admission: &NewRunAdmission) -> Result<RunAdmissionOutcome, DbError>;

    /// Lists all stored admissions in delivery order (insertion order).
    /// Consumers filter by their own progress state — the store records
    /// delivery, not consumption.
    async fn list(&self) -> Result<Vec<StoredRunAdmission>, DbError>;
}
