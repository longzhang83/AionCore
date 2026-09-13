-- Run admission receive face (T0-ACP-ADMISSION-DELIVERY Slice B2).
--
-- Immutable, write-once store of RunAdmissionRecords pushed by the Agent
-- Control Plane. The admission identity is the primary key: a repeat
-- delivery of the same run_admission_id is a duplicate outcome (409
-- run_admission_duplicate), never a re-adjudication. record_json is the
-- canonical JSON projection echoed verbatim on 200.
CREATE TABLE IF NOT EXISTS acp_run_admissions (
    run_admission_id TEXT PRIMARY KEY NOT NULL,
    idempotency_key TEXT NOT NULL,
    record_json TEXT NOT NULL,
    admitted_at_ms INTEGER NOT NULL
);
