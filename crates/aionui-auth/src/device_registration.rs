//! Client for the Auth Center device-registration endpoint.
//!
//! After the OIDC token exchange succeeds, AionCore registers the login's
//! DPoP session key (device key == session key, same `IDpopKeyStore` handle)
//! as a device with the Auth Center, then stores the receipt in the token
//! vault bundle. The wire contract is dictated by the server handler
//! (verified: rsm_project/auth-center/internal/httpapi/device_registration.go):
//!
//! * `POST {base}/api/auth-center/v1/devices` with `Authorization: Bearer`
//!   (the registration proof does not bind the access token, so the DPoP
//!   scheme is not used), exactly one `Content-Type: application/json`, an
//!   `Idempotency-Key` (canonical lowercase UUIDv4), and a `DPoP` proof on
//!   the `unbound_management` profile (`htm`/`htu`/`iat`/`jti`, NO `ath`;
//!   verified: oauthdpop/proof.go:124-126, 177-180).
//! * Body is exactly `{}` so a retry with the same key has an identical
//!   request digest and the server can replay the original receipt.
//! * `htu` is `{base without trailing /}/api/auth-center/v1/devices`,
//!   exact match, no query. The server enforces https on its canonical
//!   endpoint; the client does not re-enforce the scheme — it sends the
//!   configured base verbatim.
//!
//! ## Error semantics (fail-closed)
//!
//! A registration failure fails the whole login: the caller must not store
//! the vault bundle or make any upstream call with an unenrolled session.
//! `400 invalid_request` / `400 invalid_dpop_proof`, `401 unauthorized`,
//! `409` conflict and `503 device_admission_unavailable` are terminal.
//! `400 use_dpop_nonce` with a `DPoP-Nonce` response header retries ONCE
//! with a fresh proof carrying that nonce (same idempotency key). Network
//! errors and timeouts retry up to [`MAX_NETWORK_RETRIES`] times with the
//! SAME idempotency key and exponential backoff, because the server replays
//! the original receipt for a repeated key.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dpop::{DpopSigningHandle, build_dpop_proof, generate_dpop_jti};
use crate::error::AuthCenterError;

/// Path of the device registration endpoint on the Auth Center
/// (verified: rsm_project/auth-center/internal/httpapi/device_registration.go:29).
pub const DEVICE_REGISTRATION_PATH: &str = "/api/auth-center/v1/devices";

/// Maximum network-level retries (connection errors / timeouts) before the
/// login fails. Two retries means at most three attempts per registration.
const MAX_NETWORK_RETRIES: u32 = 2;

/// Base delay for the exponential network-retry backoff (200 ms, 400 ms).
const NETWORK_RETRY_BASE_DELAY: Duration = Duration::from_millis(200);

/// Receipt returned by the Auth Center on a `201` device registration
/// (verified: device_registration.go:64-71, 165-168). `registered_at` /
/// `updated_at` are RFC3339Nano strings; `binding_version` /
/// `authority_epoch` are always 1 for a fresh registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRegistrationReceipt {
    pub device_id: String,
    pub status: String,
    pub binding_version: i64,
    pub authority_epoch: i64,
    pub registered_at: String,
    pub updated_at: String,
}

/// Errors raised while registering the login's DPoP key as a device.
/// Every variant is a fail-closed signal: the login must abort.
#[derive(Debug, thiserror::Error)]
pub enum DeviceRegistrationError {
    #[error("Device registration failed: DPoP proof generation error: {0}")]
    Proof(String),
    #[error("Device registration failed: rejected by Auth Center (HTTP {status}, error \"{code}\")")]
    Rejected { status: u16, code: String },
    #[error("Device registration failed: device admission unavailable")]
    Unavailable,
    #[error("Device registration failed: network error after {MAX_NETWORK_RETRIES} retries: {0}")]
    Network(String),
    #[error("Device registration failed: Auth Center returned an invalid registration receipt")]
    InvalidReceipt,
}

impl From<DeviceRegistrationError> for AuthCenterError {
    fn from(error: DeviceRegistrationError) -> Self {
        match error {
            DeviceRegistrationError::Proof(message) => AuthCenterError::Internal(message),
            DeviceRegistrationError::Rejected { status: 401, code } => AuthCenterError::Unauthorized(format!(
                "Device registration failed: rejected by Auth Center (HTTP 401, error \"{code}\")"
            )),
            DeviceRegistrationError::Rejected { status, code } => AuthCenterError::BadRequest(format!(
                "Device registration failed: rejected by Auth Center (HTTP {status}, error \"{code}\")"
            )),
            DeviceRegistrationError::Unavailable => {
                AuthCenterError::BadGateway("Device registration failed: device admission unavailable".into())
            }
            DeviceRegistrationError::Network(message) => AuthCenterError::BadGateway(format!(
                "Device registration failed: network error after retries: {message}"
            )),
            DeviceRegistrationError::InvalidReceipt => AuthCenterError::BadGateway(
                "Device registration failed: Auth Center returned an invalid registration receipt".into(),
            ),
        }
    }
}

/// Fixed custom namespace UUID for the deterministic `Idempotency-Key`
/// derivation (`6e1f4a7c-9b2d-4e3f-8a5c-1d0b9f2e4a6c`). Contract: the key is
/// derived UUIDv5-style from `namespace_bytes || name_bytes` where name is
/// the login key's RFC 7638 thumbprint, so every retry of the same login key
/// produces the identical key and the server replays the original receipt.
const IDEMPOTENCY_NAMESPACE_BYTES: [u8; 16] = [
    0x6e, 0x1f, 0x4a, 0x7c, 0x9b, 0x2d, 0x4e, 0x3f, 0x8a, 0x5c, 0x1d, 0x0b, 0x9f, 0x2e, 0x4a, 0x6c,
];

/// Derive the deterministic `Idempotency-Key` for one DPoP login key.
///
/// SHA-256 over `namespace_bytes || jkt_bytes`, truncated to 16 bytes, with
/// the RFC 4122 version and variant bits set. The version nibble is pinned
/// to 4 (not 5): the receiver only accepts canonical UUIDv4 strings
/// (verified: device_registration.go:178-184, 339-342), so "v5" here refers
/// to the name-based derivation scheme, not the version bits.
pub fn derive_device_idempotency_key(jkt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(IDEMPOTENCY_NAMESPACE_BYTES);
    hasher.update(jkt.as_bytes());
    let digest = hasher.finalize();

    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant

    let hex = |slice: &[u8]| -> String {
        slice
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("")
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&bytes[0..4]),
        hex(&bytes[4..6]),
        hex(&bytes[6..8]),
        hex(&bytes[8..10]),
        hex(&bytes[10..16])
    )
}

#[derive(Debug, Deserialize)]
struct DeviceRegistrationErrorBody {
    #[serde(default)]
    error: Option<String>,
}

/// Register the login's ES256 session key as a device with the Auth Center.
///
/// * `auth_center_base_url` — scheme + host (+ optional prefix), no trailing
///   slash required; the endpoint is `{base}/api/auth-center/v1/devices`.
/// * `access_token` — the token obtained by this login's OIDC exchange,
///   presented as `Authorization: Bearer <token>`.
/// * `dpop_handle` — the same session key the access token is bound to; the
///   device key therefore equals the session key.
///
/// Fail-closed: any error return means the caller must abort the login and
/// must not store the vault bundle.
pub async fn register_device(
    http_client: &reqwest::Client,
    auth_center_base_url: &str,
    access_token: &str,
    dpop_handle: &DpopSigningHandle,
) -> Result<DeviceRegistrationReceipt, DeviceRegistrationError> {
    let endpoint = format!(
        "{}{}",
        auth_center_base_url.trim_end_matches('/'),
        DEVICE_REGISTRATION_PATH
    );
    // One deterministic key per login key: every retry (network and nonce)
    // reuses it so the server can replay the original receipt.
    let idempotency_key = derive_device_idempotency_key(dpop_handle.jkt());

    let result = register_device_inner(http_client, &endpoint, access_token, dpop_handle, &idempotency_key).await;
    match &result {
        Ok(receipt) => {
            tracing::info!(device_id = %receipt.device_id, "device registration succeeded");
        }
        Err(error) => {
            tracing::warn!(error = %error, "device registration failed; failing the login closed");
        }
    }
    result
}

async fn register_device_inner(
    http_client: &reqwest::Client,
    endpoint: &str,
    access_token: &str,
    dpop_handle: &DpopSigningHandle,
    idempotency_key: &str,
) -> Result<DeviceRegistrationReceipt, DeviceRegistrationError> {
    let mut nonce: Option<String> = None;
    let mut nonce_retry_used = false;
    let mut network_failures = 0_u32;

    loop {
        let proof = build_dpop_proof(
            dpop_handle,
            "POST",
            endpoint,
            chrono::Utc::now().timestamp(),
            &generate_dpop_jti(),
            None,
            nonce.as_deref(),
        )
        .map_err(|error| DeviceRegistrationError::Proof(error.to_string()))?;

        let response = http_client
            .post(endpoint)
            .bearer_auth(access_token)
            .header("Idempotency-Key", idempotency_key)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("DPoP", &proof)
            .body("{}")
            .send()
            .await;

        let response = match response {
            Ok(response) => {
                // A completed exchange resets the network-retry budget: the
                // budget guards consecutive transport failures only.
                network_failures = 0;
                response
            }
            Err(error) => {
                // Network error / timeout: same key, exponential backoff; the
                // server replays the original receipt for a repeated key.
                if network_failures < MAX_NETWORK_RETRIES {
                    network_failures += 1;
                    tokio::time::sleep(NETWORK_RETRY_BASE_DELAY * 2_u32.pow(network_failures - 1)).await;
                    continue;
                }
                return Err(DeviceRegistrationError::Network(error.to_string()));
            }
        };

        let status = response.status();
        if status == reqwest::StatusCode::CREATED {
            let receipt = response
                .json::<DeviceRegistrationReceipt>()
                .await
                .map_err(|_| DeviceRegistrationError::InvalidReceipt)?;
            if !valid_receipt(&receipt) {
                return Err(DeviceRegistrationError::InvalidReceipt);
            }
            return Ok(receipt);
        }

        if status == reqwest::StatusCode::BAD_REQUEST {
            let nonce_header = response
                .headers()
                .get("DPoP-Nonce")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let code = parse_error_code(response).await;
            // Retry exactly once with a fresh proof carrying the demanded
            // nonce (same idempotency key, fresh jti).
            if code == "use_dpop_nonce"
                && !nonce_retry_used
                && let Some(demanded) = nonce_header.filter(|value| !value.is_empty())
            {
                nonce = Some(demanded);
                nonce_retry_used = true;
                continue;
            }
            return Err(DeviceRegistrationError::Rejected {
                status: status.as_u16(),
                code,
            });
        }

        let code = parse_error_code(response).await;
        // 401 unauthorized, 409 conflict and any other unexpected status are
        // terminal (fail-closed); 503 carries the dedicated admission-
        // unavailable semantic.
        return match status.as_u16() {
            503 => Err(DeviceRegistrationError::Unavailable),
            _ => Err(DeviceRegistrationError::Rejected {
                status: status.as_u16(),
                code,
            }),
        };
    }
}

/// Parse the `error` code from the Auth Center's structured error body
/// (verified: device_registration.go:58-62, 365-373). An unparsable body
/// yields an empty code — the status still fails the login.
async fn parse_error_code(response: reqwest::Response) -> String {
    response
        .json::<DeviceRegistrationErrorBody>()
        .await
        .ok()
        .and_then(|body| body.error)
        .unwrap_or_default()
}

/// Minimal receipt sanity gate: identifiers present, timestamps parse as
/// RFC 3339. `binding_version` / `authority_epoch` are stored as opaque
/// counters rather than re-validated against server-side constants.
fn valid_receipt(receipt: &DeviceRegistrationReceipt) -> bool {
    !receipt.device_id.is_empty()
        && !receipt.status.is_empty()
        && chrono::DateTime::parse_from_rfc3339(&receipt.registered_at).is_ok()
        && chrono::DateTime::parse_from_rfc3339(&receipt.updated_at).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_key_is_deterministic_per_jkt_and_canonical_uuidv4_shaped() {
        let first = derive_device_idempotency_key("jkt-value-a");
        let second = derive_device_idempotency_key("jkt-value-a");
        assert_eq!(first, second, "same jkt must derive the identical key");

        let other = derive_device_idempotency_key("jkt-value-b");
        assert_ne!(first, other, "different jkt must derive different keys");

        // Canonical lowercase UUIDv4 shape: 8-4-4-4-12, version nibble 4,
        // RFC 4122 variant (8/9/a/b).
        assert_eq!(first.len(), 36);
        let parts: Vec<&str> = first.split('-').collect();
        assert_eq!(
            parts.iter().map(|part| part.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(
            first
                .chars()
                .all(|ch| ch == '-' || ch.is_ascii_digit() || ('a'..='f').contains(&ch))
        );
        assert_eq!(first.chars().nth(14), Some('4'), "version nibble must be 4");
        assert!(
            matches!(first.chars().nth(19), Some('8' | '9' | 'a' | 'b')),
            "variant must be RFC 4122"
        );
    }

    #[test]
    fn invalid_receipts_are_rejected() {
        let base = DeviceRegistrationReceipt {
            device_id: "device-1".into(),
            status: "active".into(),
            binding_version: 1,
            authority_epoch: 1,
            registered_at: "2026-09-12T00:00:00.123456789Z".into(),
            updated_at: "2026-09-12T00:00:00.123456789Z".into(),
        };
        assert!(valid_receipt(&base));

        let empty_device = DeviceRegistrationReceipt {
            device_id: String::new(),
            ..base.clone()
        };
        assert!(!valid_receipt(&empty_device));

        let bad_timestamp = DeviceRegistrationReceipt {
            updated_at: "not-a-timestamp".into(),
            ..base
        };
        assert!(!valid_receipt(&bad_timestamp));
    }
}
