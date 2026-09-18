//! Black-box integration tests for IRunAdmissionRepository.
//!
//! Tests exercise the public trait interface against an in-memory SQLite
//! database with migration 040 applied (T0-ACP-ADMISSION-DELIVERY Slice B2a).

use std::sync::Arc;

use aionui_db::{
    IRunAdmissionRepository, NewRunAdmission, RunAdmissionOutcome, SqliteRunAdmissionRepository, init_database_memory,
};

async fn repo() -> Arc<dyn IRunAdmissionRepository> {
    let db = init_database_memory().await.unwrap();
    Arc::new(SqliteRunAdmissionRepository::new(db.pool().clone()))
}

fn admission(id: &str) -> NewRunAdmission {
    NewRunAdmission {
        run_admission_id: id.to_string(),
        idempotency_key: "3b241101-e2bb-4255-8caf-4136c566a962".to_string(),
        record_json: format!(r#"{{"run_admission_id":"{id}"}}"#),
    }
}

#[tokio::test]
async fn first_admit_is_admitted() {
    let r = repo().await;
    assert_eq!(
        r.admit(&admission("adm-1")).await.unwrap(),
        RunAdmissionOutcome::Admitted
    );
}

#[tokio::test]
async fn repeat_admit_same_identity_is_duplicate() {
    let r = repo().await;
    assert_eq!(
        r.admit(&admission("adm-1")).await.unwrap(),
        RunAdmissionOutcome::Admitted
    );
    // A repeat delivery of the same run_admission_id is a duplicate outcome,
    // never a re-adjudication — even with a different idempotency key or body.
    let mut replay = admission("adm-1");
    replay.idempotency_key = "4b241101-e2bb-4255-8caf-4136c566a963".to_string();
    replay.record_json = r#"{"run_admission_id":"adm-1","tampered":true}"#.to_string();
    assert_eq!(r.admit(&replay).await.unwrap(), RunAdmissionOutcome::Duplicate);
}

#[tokio::test]
async fn distinct_identities_are_independent() {
    let r = repo().await;
    assert_eq!(
        r.admit(&admission("adm-1")).await.unwrap(),
        RunAdmissionOutcome::Admitted
    );
    assert_eq!(
        r.admit(&admission("adm-2")).await.unwrap(),
        RunAdmissionOutcome::Admitted
    );
    assert_eq!(
        r.admit(&admission("adm-1")).await.unwrap(),
        RunAdmissionOutcome::Duplicate
    );
    assert_eq!(
        r.admit(&admission("adm-2")).await.unwrap(),
        RunAdmissionOutcome::Duplicate
    );
}

#[tokio::test]
async fn list_returns_stored_admissions_in_delivery_order() {
    let r = repo().await;
    assert!(r.list().await.unwrap().is_empty());

    r.admit(&admission("adm-2")).await.unwrap();
    r.admit(&admission("adm-1")).await.unwrap();

    let rows = r.list().await.unwrap();
    let ids: Vec<&str> = rows.iter().map(|row| row.run_admission_id.as_str()).collect();
    assert_eq!(ids, vec!["adm-2", "adm-1"]);
    // The stored projection is the verbatim wire truth, not a re-rendering.
    assert_eq!(rows[0].record_json, r#"{"run_admission_id":"adm-2"}"#);
}
