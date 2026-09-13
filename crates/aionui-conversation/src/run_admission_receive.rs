//! Run admission receive face (T0-ACP-ADMISSION-DELIVERY Slice B2a).
//!
//! Core's receiving side of the ACP admission push: `POST
//! /internal/run-authority/v1/admissions`, mirroring the Auth Center internal
//! device-admission endpoint's discipline (auth precedes all request parsing,
//! strict single-JSON decoding, idempotency-key and content-type checks,
//! 64KB body cap) under the frozen Slice A wire contract:
//!
//! - **200** with the persisted `RunAdmissionRecord` echo verbatim — the ACP
//!   strict-decodes it and validates the identity triple;
//! - **409** only with code `run_admission_duplicate`, only when the same
//!   `run_admission_id` is already held (an earlier delivery attempt was
//!   received but its response was lost);
//! - **401** for any authentication failure (never a decoder oracle);
//! - **400** `invalid_request` for malformed requests (headers, body shape,
//!   size, incomplete admission identity);
//! - **503** `run_admission_unavailable` when the admission cannot be
//!   persisted — definitive on the ACP side, never retried.
//!
//! Authentication is the B1 [`AcpServiceTokenVerifier`]: the caller presents
//! its certificate-bound ACP machine service token, and the verified TLS leaf
//! must be inserted into the request extensions by the dedicated internal
//! mTLS listener (Slice B2b). A request without a verified leaf is a 401.

use std::sync::Arc;

use aionui_auth::{AcpServiceTokenVerifier, VerifiedClientLeaf};
use aionui_db::{IRunAdmissionRepository, NewRunAdmission, RunAdmissionOutcome};
use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use http_body_util::{BodyExt, Limited};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Frozen Core run-admission receive path (mirrors the Auth Center
/// `/internal/device-authority/v1/admissions` shape).
pub const RUN_ADMISSION_RECEIVE_PATH: &str = "/internal/run-authority/v1/admissions";
/// Error code for an already-held admission (the only legal 409).
pub const RUN_ADMISSION_DUPLICATE_CODE: &str = "run_admission_duplicate";
/// Error code for a persistence failure (definitive, never retried by ACP).
pub const RUN_ADMISSION_UNAVAILABLE_CODE: &str = "run_admission_unavailable";
/// Body cap, mirroring the Auth Center internal admission limit.
pub const RUN_ADMISSION_BODY_LIMIT: usize = 64 << 10;

/// `run_authority.ExpectedBase` — the exact approved input selected for the
/// run. Strict decode mirrors Go's recursive `DisallowUnknownFields`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunAdmissionExpectedBase {
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub revision_id: String,
    pub manifest_sha256: String,
}

/// `run_authority.EditScope` — the server-derived write scope carried by an
/// admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunAdmissionEditScope {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_paths: Vec<String>,
}

/// `run_authority.CoreServicePrincipal` — the certificate-bound Core identity
/// the admission was issued for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunAdmissionCorePrincipal {
    pub service_id: String,
    pub service_role: String,
    pub workload_instance_id: String,
    pub credential_key_id: String,
    pub certificate_thumbprint_s256: String,
    pub service_authority_epoch: i64,
}

/// `run_authority.EnvironmentAuthority` — binds synthetic data to one
/// non-production authority generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunAdmissionEnvironmentAuthority {
    pub environment_authority_id: String,
    pub environment_kind: String,
    pub environment_authority_epoch: i64,
}

/// `run_authority.RunAdmissionRecord` — the immutable authority projection,
/// frozen ACP Go json tags verbatim. Decoding is strict: unknown fields at
/// any nesting level and any value after the single JSON object are
/// rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunAdmissionRecord {
    pub run_admission_id: String,
    pub admission_version: i64,
    pub actor_delegation_id: String,
    pub actor_delegation_consumption_id: String,
    pub admission_request_sha256: String,
    pub tenant_id: String,
    pub resource_organization_id: String,
    pub workspace_id: String,
    pub edit_session_id: String,
    pub base: RunAdmissionExpectedBase,
    pub scope: RunAdmissionEditScope,
    pub subject_id: String,
    pub device_id: String,
    pub run_id: String,
    pub attempt_id: String,
    pub owner_epoch: i64,
    pub core_principal: RunAdmissionCorePrincipal,
    pub isolation_profile_sha256: String,
    pub command_sha256: String,
    pub execution_authority_epoch: i64,
    pub data_classification: String,
    pub environment: RunAdmissionEnvironmentAuthority,
    pub issued_at_ms: i64,
    pub authorization_ttl_seconds: i64,
    pub expires_at_ms: i64,
    pub state: String,
}

impl RunAdmissionRecord {
    /// The delivery identity floor mirrored from the ACP deliverer: a record
    /// missing any of these cannot be a legitimate issued admission and is
    /// rejected before persistence.
    pub fn has_delivery_identity_floor(&self) -> bool {
        let fields = [
            (&self.run_admission_id, "run_admission_id"),
            (&self.tenant_id, "tenant_id"),
            (&self.resource_organization_id, "resource_organization_id"),
            (&self.workspace_id, "workspace_id"),
            (&self.run_id, "run_id"),
            (&self.attempt_id, "attempt_id"),
        ];
        fields.iter().all(|(value, _)| !value.trim().is_empty())
    }
}

/// Shared state of the receive face.
pub struct RunAdmissionReceiveState {
    /// B1 verifier: certificate-bound ACP machine service tokens with
    /// audience `core:run-admission-receive`.
    pub verifier: AcpServiceTokenVerifier,
    /// Write-once admission persistence.
    pub repository: Arc<dyn IRunAdmissionRepository>,
}

/// Builds the receive-face router. Mount it ONLY on the dedicated internal
/// mTLS listener (Slice B2b) whose accept loop inserts the verified
/// [`VerifiedClientLeaf`] into every request's extensions — a request without
/// one is answered 401, so mounting on a plaintext listener fails closed.
pub fn run_admission_receive_router(state: RunAdmissionReceiveState) -> Router {
    Router::new()
        .route(RUN_ADMISSION_RECEIVE_PATH, post(admit_run_admission))
        .with_state(Arc::new(state))
}

/// The receive-face error envelope. The ACP deliverer reads
/// `error.code`; `description` is operational context only.
#[derive(Serialize)]
struct AdmissionErrorResponse<'a> {
    error: AdmissionErrorBody<'a>,
}

#[derive(Serialize)]
struct AdmissionErrorBody<'a> {
    code: &'a str,
    description: &'a str,
}

fn admission_error(status: StatusCode, code: &'static str, description: &'static str) -> Response {
    let body = Json(AdmissionErrorResponse {
        error: AdmissionErrorBody { code, description },
    });
    (status, body).into_response()
}

fn unauthorized() -> Response {
    admission_error(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "Internal service authentication failed.",
    )
}

fn invalid_request() -> Response {
    admission_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Invalid run admission request.",
    )
}

async fn admit_run_admission(
    State(state): State<Arc<RunAdmissionReceiveState>>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    // Authentication intentionally precedes all request parsing so an
    // unauthenticated caller cannot use the decoder as an input oracle
    // (Auth Center internal admission discipline).
    let leaf = match request.extensions().get::<VerifiedClientLeaf>() {
        Some(leaf) => leaf.clone(),
        None => {
            tracing::debug!("run admission receive: no verified client leaf on request");
            return unauthorized();
        }
    };
    let token = match bearer_token(&headers) {
        Ok(token) => token,
        Err(reason) => {
            tracing::debug!(reason, "run admission receive: bearer credential rejected");
            return unauthorized();
        }
    };
    if let Err(error) = state.verifier.verify(&token, &leaf).await {
        tracing::debug!(error = %error, "run admission receive: service token rejected");
        return unauthorized();
    }

    let (idempotency_key, content_type_ok) = match admission_headers(&headers) {
        Ok(parsed) => parsed,
        Err(reason) => {
            tracing::debug!(reason, "run admission receive: invalid admission headers");
            return invalid_request();
        }
    };
    if !content_type_ok {
        tracing::debug!("run admission receive: content type is not application/json");
        return invalid_request();
    }

    let payload = match read_capped_body(request).await {
        Ok(payload) => payload,
        Err(reason) => {
            tracing::debug!(reason, "run admission receive: invalid request body");
            return invalid_request();
        }
    };
    let record: RunAdmissionRecord = match serde_json::from_slice(&payload) {
        Ok(record) => record,
        Err(error) => {
            tracing::debug!(error = %error, "run admission receive: record decode failed");
            return invalid_request();
        }
    };
    if !record.has_delivery_identity_floor() {
        tracing::debug!("run admission receive: record fails the delivery identity floor");
        return invalid_request();
    }

    // Echo the canonical projection of what was decoded and floor-checked,
    // never the raw bytes: the persisted record is the decoded value.
    let record_json = match serde_json::to_string(&record) {
        Ok(record_json) => record_json,
        Err(error) => {
            tracing::error!(error = %error, "run admission receive: record re-encode failed");
            return admission_error(
                StatusCode::SERVICE_UNAVAILABLE,
                RUN_ADMISSION_UNAVAILABLE_CODE,
                "Run admission is unavailable.",
            );
        }
    };
    let admission = NewRunAdmission {
        run_admission_id: record.run_admission_id.clone(),
        idempotency_key,
        record_json,
    };
    match state.repository.admit(&admission).await {
        Ok(RunAdmissionOutcome::Admitted) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            admission.record_json,
        )
            .into_response(),
        Ok(RunAdmissionOutcome::Duplicate) => admission_error(
            StatusCode::CONFLICT,
            RUN_ADMISSION_DUPLICATE_CODE,
            "Run admission already held.",
        ),
        Err(error) => {
            tracing::error!(error = %error, "run admission receive: persist failed");
            admission_error(
                StatusCode::SERVICE_UNAVAILABLE,
                RUN_ADMISSION_UNAVAILABLE_CODE,
                "Run admission is unavailable.",
            )
        }
    }
}

/// Parses the Bearer credential: exactly one `Authorization` header carrying
/// a non-blank `Bearer` scheme token.
fn bearer_token(headers: &HeaderMap) -> Result<String, &'static str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = match (values.next(), values.next()) {
        (Some(value), None) => value,
        _ => return Err("authorization header must appear exactly once"),
    };
    let value = value.to_str().map_err(|_| "authorization header is not ASCII")?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or("authorization scheme must be Bearer")?;
    if token.trim().is_empty() {
        return Err("bearer credential is blank");
    }
    Ok(token.to_string())
}

/// Validates the admission request headers: exactly one canonical UUIDv4
/// `Idempotency-Key` and exactly one `application/json` `Content-Type`.
fn admission_headers(headers: &HeaderMap) -> Result<(String, bool), &'static str> {
    let mut keys = headers.get_all("Idempotency-Key").iter();
    let key = match (keys.next(), keys.next()) {
        (Some(key), None) => key,
        _ => return Err("idempotency key must appear exactly once"),
    };
    let key = key.to_str().map_err(|_| "idempotency key is not ASCII")?;
    if !canonical_uuid_v4(key) {
        return Err("idempotency key is not a canonical UUIDv4");
    }

    let mut types = headers.get_all(header::CONTENT_TYPE).iter();
    let content_type = match (types.next(), types.next()) {
        (Some(value), None) => value,
        _ => return Err("content type must appear exactly once"),
    };
    let content_type = content_type.to_str().map_err(|_| "content type is not ASCII")?;
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    let is_json = media_type.eq_ignore_ascii_case("application/json");
    Ok((key.to_string(), is_json))
}

/// Canonical UUIDv4: parses, is version 4, and round-trips through the
/// canonical hyphenated lowercase form (mirrors the Auth Center check).
fn canonical_uuid_v4(value: &str) -> bool {
    match Uuid::parse_str(value) {
        Ok(parsed) => parsed.get_version_num() == 4 && parsed.to_string() == value,
        Err(_) => false,
    }
}

/// Reads the request body with the 64KB cap: one byte past the limit is a
/// rejection (400), never a truncation, mirroring the Auth Center
/// `MaxBytesReader` discipline instead of a framework-level 413.
async fn read_capped_body(request: Request) -> Result<Bytes, &'static str> {
    let limited = Limited::new(request.into_body(), RUN_ADMISSION_BODY_LIMIT + 1);
    let collected = limited.collect().await.map_err(|_| "body read failed")?;
    let payload = collected.to_bytes();
    if payload.len() > RUN_ADMISSION_BODY_LIMIT {
        return Err("body exceeds the admission size limit");
    }
    Ok(payload)
}
