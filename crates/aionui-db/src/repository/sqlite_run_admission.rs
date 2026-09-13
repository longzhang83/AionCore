use sqlx::SqlitePool;

use crate::error::DbError;
use crate::repository::run_admission::{IRunAdmissionRepository, NewRunAdmission, RunAdmissionOutcome};

/// SQLite-backed implementation of [`IRunAdmissionRepository`].
#[derive(Clone, Debug)]
pub struct SqliteRunAdmissionRepository {
    pool: SqlitePool,
}

impl SqliteRunAdmissionRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl IRunAdmissionRepository for SqliteRunAdmissionRepository {
    async fn admit(&self, admission: &NewRunAdmission) -> Result<RunAdmissionOutcome, DbError> {
        let result = sqlx::query(
            "INSERT INTO acp_run_admissions (run_admission_id, idempotency_key, record_json, admitted_at_ms) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&admission.run_admission_id)
        .bind(&admission.idempotency_key)
        .bind(&admission.record_json)
        .bind(aionui_common::now_ms())
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(RunAdmissionOutcome::Admitted),
            Err(sqlx::Error::Database(database_error)) => {
                // Only a collision on the admission identity itself is a
                // duplicate delivery; any other constraint violation is a
                // storage fault that must surface as an error (503 upstream),
                // never as a fake duplicate.
                let message = database_error.message();
                if crate::error::message_indicates_unique_violation(message)
                    && message
                        .to_ascii_lowercase()
                        .contains("acp_run_admissions.run_admission_id")
                {
                    Ok(RunAdmissionOutcome::Duplicate)
                } else {
                    Err(sqlx::Error::Database(database_error).into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }
}
