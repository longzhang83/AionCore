//! Shared throwaway test material and helpers for the run admission receive
//! face tests (B2a router tests + B2b listener e2e tests). All material is
//! one-off openssl output for tests only — never a real key.

use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::json;
use wiremock::MockServer;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

use crate::run_admission_receive::RunAdmissionRecord;
use aionui_auth::VerifiedClientLeaf;
use aionui_db::{DbError, IRunAdmissionRepository, NewRunAdmission, RunAdmissionOutcome, StoredRunAdmission};

/// In-memory write-once admission store shared by the receive-face tests.
#[derive(Default)]
pub(crate) struct MemoryAdmissionStore {
    pub(crate) held: StdMutex<HashMap<String, String>>,
    /// Insertion order of `held` identities — `list` mirrors the SQLite
    /// store's delivery-order contract. (The fake's read surface is
    /// `record_json`; `idempotency_key` round-tripping is covered by the
    /// SQLite integration tests.)
    pub(crate) delivery_order: StdMutex<Vec<String>>,
    pub(crate) fail_admissions: AtomicBool,
}

#[async_trait::async_trait]
impl IRunAdmissionRepository for MemoryAdmissionStore {
    async fn admit(&self, admission: &NewRunAdmission) -> Result<RunAdmissionOutcome, DbError> {
        if self.fail_admissions.load(Ordering::SeqCst) {
            return Err(DbError::Conflict("forced storage failure".into()));
        }
        let mut held = self.held.lock().expect("store lock");
        if held.contains_key(&admission.run_admission_id) {
            return Ok(RunAdmissionOutcome::Duplicate);
        }
        held.insert(admission.run_admission_id.clone(), admission.record_json.clone());
        self.delivery_order
            .lock()
            .expect("store lock")
            .push(admission.run_admission_id.clone());
        Ok(RunAdmissionOutcome::Admitted)
    }

    async fn list(&self) -> Result<Vec<StoredRunAdmission>, DbError> {
        let order = self.delivery_order.lock().expect("store lock");
        let held = self.held.lock().expect("store lock");
        Ok(order
            .iter()
            .map(|run_admission_id| StoredRunAdmission {
                run_admission_id: run_admission_id.clone(),
                idempotency_key: String::new(),
                record_json: held[run_admission_id].clone(),
            })
            .collect())
    }
}

/// Decodes one labeled PEM section into DER bytes.
pub(crate) fn pem_section(body: &str, label: &str) -> Vec<u8> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut inside = false;
    let mut encoded = String::new();
    for line in body.lines() {
        if line.trim() == begin {
            inside = true;
            continue;
        }
        if line.trim() == end {
            break;
        }
        if inside {
            encoded.push_str(line.trim());
        }
    }
    BASE64_STANDARD
        .decode(encoded.as_bytes())
        .expect("test PEM base64 must decode")
}

// ---------------------------------------------------------------------------
// TLS material (CA + server + client, EC P-256, CN localhost SAN)
// ---------------------------------------------------------------------------

pub(crate) const TEST_CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBpTCCAUugAwIBAgIUb6uRtocEVopdyY36KxFD+/XPGXcwCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVYWNwLWFkbWlzc2lvbi10ZXN0LWNhMB4XDTI2MDkxMzEyMjUz
M1oXDTI2MTAxMzEyMjUzM1owIDEeMBwGA1UEAwwVYWNwLWFkbWlzc2lvbi10ZXN0
LWNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB1NpbfDJWenG0jQCWwcM4/ci
AZVGn2W0YoMzjGzehCZC6ZuERC9i4InVIevGfNVppmxaFi2ShKGxgDExik8nTqNj
MGEwHQYDVR0OBBYEFGtOV/NfG5+dwAXqs+ytuh/Hh3TvMB8GA1UdIwQYMBaAFGtO
V/NfG5+dwAXqs+ytuh/Hh3TvMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
AgIEMAoGCCqGSM49BAMCA0gAMEUCIH0lhy5rsfNJGHXPG61tqCEX5zrq9qGTKt/c
2puGCTt3AiEAiw5auwD7J2pc3lfXy9/HCD/P7JfaONra2iKoCyBqvh0=
-----END CERTIFICATE-----
";

pub(crate) const TEST_SERVER_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBqDCCAU+gAwIBAgIUZtpkM4gL/FVDPt7aJvpIoFiLos8wCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVYWNwLWFkbWlzc2lvbi10ZXN0LWNhMB4XDTI2MDkxMzEyMjUz
M1oXDTI2MTAxMzEyMjUzM1owFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEWsPmYbGYPoYM0EFpIDBolEz3mVGdklbtpX6DothV
VvewTSv8k+ExTUPdcEZ2UYk3eiPioo6yjh1wCP6CtPmAJaNzMHEwGgYDVR0RBBMw
EYIJbG9jYWxob3N0hwR/AAABMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQW
BBSnr9rkZ0uyD7gyAmOpABaFhmKJMjAfBgNVHSMEGDAWgBRrTlfzXxufncAF6rPs
rbofx4d07zAKBggqhkjOPQQDAgNHADBEAiAXBVheb5hNrqZH77xr/hAQxN1LAzbu
sjCTPKOjCY+r6wIgWT/0gr/d75IPfi9GBluh3eD/Ml4UwA+E6QiHpDHNS9w=
-----END CERTIFICATE-----
";

pub(crate) const TEST_SERVER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrqlKXS7NHt9Zl49Y
ZvixBcrKtUPctrDlz5gIOFH2++ihRANCAARaw+ZhsZg+hgzQQWkgMGiUTPeZUZ2S
Vu2lfoOi2FVW97BNK/yT4TFNQ91wRnZRiTd6I+KijrKOHXAI/oK0+YAl
-----END PRIVATE KEY-----
";

pub(crate) const TEST_CLIENT_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBnTCCAUOgAwIBAgIUZtpkM4gL/FVDPt7aJvpIoFiLotAwCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVYWNwLWFkbWlzc2lvbi10ZXN0LWNhMB4XDTI2MDkxMzEyMjUz
M1oXDTI2MTAxMzEyMjUzM1owJDEiMCAGA1UEAwwZYWNwLWFkbWlzc2lvbi10ZXN0
LWNsaWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPy781v4HYc84Zg8hsg7
en5EewZtlCD8oSetHj6Eb9rJeXcG3id8kRUybL3calmpBR9PkKN0yQ6jGNSmyoNu
VaOjVzBVMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBSduZISF0woIMUB
UtjNSefAtSVTzTAfBgNVHSMEGDAWgBRrTlfzXxufncAF6rPsrbofx4d07zAKBggq
hkjOPQQDAgNIADBFAiBohz0flCbADtyaxtTzconyDIN2VZuY+DA4XXPB1KLXXAIh
AOfUUDrFU0p+3HUw4SU6BaiIGJyPmAV7pyNlU6C4wzpG
-----END CERTIFICATE-----
";

pub(crate) const TEST_CLIENT_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcZ7pIVYURWHUpLnT
PKni0ji4TJOEjzhJWl5/iJn4vCGhRANCAAT8u/Nb+B2HPOGYPIbIO3p+RHsGbZQg
/KEnrR4+hG/ayXl3Bt4nfJEVMmy93GpZqQUfT5CjdMkOoxjUpsqDblWj
-----END PRIVATE KEY-----
";

// ---------------------------------------------------------------------------
// ACP service token minting material (RSA, wiremock JWKS)
// ---------------------------------------------------------------------------

pub(crate) const TEST_RSA_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkDq/OryfhgfMh
8DBvbv1Qnbf7FkzHWkIAaQzsB+UszsoH0dJK/xL6XZ8KWLGZHSqsJEq9XYQWkVDX
K5erRHMFkUSQuTQk6TeAHusjriMylCF3kMYxZBFiRKB073LfEIXM8xGjWTdTk78J
AB6EPMMVrrm4Vve91xxCA7+CB+zvXFgdn2SBYOb3ioxxW9+Qpr0+PxUzeeTsNJTs
437sg7KdEpmZndGFmVRxjPL4+QbnZuOrXk1yeezbwZaKSp0u9eWD/Z9dUzB8p9V5
Iz3oCBMFZCKaDkyNlJ8bVmFAGVEQfgFOQ8N3iLYkii8GTete6KfmMJT/G24ltrcw
8nAVDMlBAgMBAAECggEALx6EwiEunCddtIau8qJ3IRtbh0M9ZBh5UnLZokUWPota
HWrXMnEWe1A+aJNW1vo4kl6OFNtyH6U3CcXcdvVe799sSQDYiC1vol2+/W17cIB5
KEUtl2v9TjMVvuAzJvww4c+CZl8uc9PAj444NZTaFzUq5FYeK6lH1XIMJAWwuIJf
2aVjqRotV8CFPyqP5vaAGYonaDEyuHsN1xtIYAcsvsyEySCAs2ZP9gOOBr27V2GQ
oy2auZ2PTE7jQUvdX+RTwvhr79j37gl8Y4zRtueF85lJMnnRwicKSBZmJTretQK2
satC5yI0Tkixq6wmPZ+H0baDib6UT3u91CuBiISqnQKBgQDlSOODfY8LUv/hYHZo
saJVP9CU3PAK1i+mYyznZVe41MI7siwC+ZBH+cE6UTpLSf3ZAfK+dCAfoiOgp711
+0yAhwnESA3KqYLGkczAVPGK+g62gMutKs4js4L/MUt2CacnD7KgBXXxc72UoZBz
UJqOsnQTfnc2Y4LGIXzDMbvQDwKBgQC3LDHYMffS/m2vkm3SIt0yCmWDHxTc0vV2
uuCAcaYD2Nysi9sMhnj9EWC9eresU5a2I4/YgCmd3s4EPpVixliLgBW/zAxD/Kk8
CvfQjeOx9YB4YhAYD/qbPgk8xUe+OQTaYA078rfGmgTCe4J1RVlTi19oaAJ0QJOy
m8+h3w6BrwKBgCY29syUocHGbKV4uWOLr727rB0TkeKMflaiEvriNjO1KkZe1N0O
EVEdvGnm3etsgqWnoHjDzBLZqEx/iKFgaAjH+QXA6KONiyFjbZfk0HlUYh1i7A+J
od/rbHryEVy0ESr+f8wR/O1oWAGsx/GgTpJYBea13lKvVT2GmU/DO0VbAoGAMrBw
OrvZMPJnuCZ1baloPOjTnq2DQHjApNKiPek1X+srZjRtsdGkuaONeeHz4iRfmJfO
vsL4wU9fA52uCV+KMVCItELrQgUxcAQ4/+XEFQMzQh0hBwek+kD4nXCaofF1flkG
UIiigrsshgVX3MwMJCp1hJcD1tfoB41GsCzh/tECgYEAt5vlW4tT6FKovLK3E9Dw
VBDN/M/vjAdq67kwJU3snknhV9g55GmO9kHYcCefSZuOgVVCtQdRdQCNtViBE6oJ
Cv3ZOJbaWsi6QcSTS3P8gNYwIX8TrKB+sdFW3ThRtMUPR/gauEhxibdH+xgQ5w4r
rBvRnJmM3jrhq1dR+8Fcszk=
-----END PRIVATE KEY-----
";

pub(crate) const TEST_RSA_MODULUS_B64URL: &str = "pA6vzq8n4YHzIfAwb279UJ23-xZMx1pCAGkM7AflLM7KB9HSSv8S-l2fClixmR0qrCRKvV2EFpFQ1yuXq0RzBZFEkLk0JOk3gB7rI64jMpQhd5DGMWQRYkSgdO9y3xCFzPMRo1k3U5O_CQAehDzDFa65uFb3vdccQgO_ggfs71xYHZ9kgWDm94qMcVvfkKa9Pj8VM3nk7DSU7ON-7IOynRKZmZ3RhZlUcYzy-PkG52bjq15Ncnns28GWikqdLvXlg_2fXVMwfKfVeSM96AgTBWQimg5MjZSfG1ZhQBlREH4BTkPDd4i2JIovBk3rXuin5jCU_xtuJba3MPJwFQzJQQ";

pub(crate) const TEST_RSA_EXPONENT_B64URL: &str = "AQAB";
pub(crate) const TEST_KID: &str = "test-jwk-key-1";

/// Canonical UUIDv4 values for idempotency keys (version nibble `4`,
/// RFC 4122 variant).
pub(crate) const IDEMPOTENCY_KEY_1: &str = "3b241101-e2bb-4255-8caf-4136c566a962";
pub(crate) const IDEMPOTENCY_KEY_2: &str = "0f8e5c3a-92d1-4a7b-b2c3-8d9e0f1a2b3c";

#[derive(Clone)]
pub(crate) struct MintOverrides {
    /// Empty means "the issuer of the JWKS server under test".
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) exp_offset_seconds: i64,
    /// None means the thumbprint of the leaf under test (correct binding).
    pub(crate) cnf_thumbprint: Option<String>,
}

impl Default for MintOverrides {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            audience: aionui_auth::RUN_ADMISSION_RECEIVE_AUDIENCE.into(),
            exp_offset_seconds: 300,
            cnf_thumbprint: None,
        }
    }
}

pub(crate) fn mint_token(server_uri: &str, overrides: &MintOverrides, leaf: &VerifiedClientLeaf) -> String {
    let now = chrono::Utc::now();
    let mut claims = json!({
        "sub": "acp-service-1",
        "client_id": "acp-service-1",
        "principal_type": "machine",
        "jti": "jti-1",
        "tenant_id": "tenant-1",
        "service_role": "core",
        "workload_instance_id": "acp-instance-1",
        "service_authority_epoch": 3,
        "orgs": [{ "id": "org-1", "isPrimary": true }],
        "scope": "run-admission-receive:accept",
        "iss": if overrides.issuer.is_empty() { server_uri.to_string() } else { overrides.issuer.clone() },
        "aud": overrides.audience,
        "iat": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(overrides.exp_offset_seconds)).timestamp(),
    });
    let cnf = overrides
        .cnf_thumbprint
        .clone()
        .unwrap_or_else(|| leaf.thumbprint_s256());
    claims["cnf"] = json!({ "x5t#S256": cnf });

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(TEST_KID.into());
    header.typ = Some("at+jwt".into());
    let encoding_key =
        jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_SIGNING_KEY_PEM.as_bytes()).expect("test RSA key");
    jsonwebtoken::encode(&header, &claims, &encoding_key).expect("token minting")
}

pub(crate) async fn jwks_server() -> MockServer {
    let server = MockServer::start().await;
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": TEST_KID,
            "n": TEST_RSA_MODULUS_B64URL,
            "e": TEST_RSA_EXPONENT_B64URL,
        }]
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .mount(&server)
        .await;
    server
}

// ---------------------------------------------------------------------------
// Fixture record + canonical body helpers shared by both test modules
// ---------------------------------------------------------------------------

pub(crate) fn fixture_record() -> serde_json::Value {
    json!({
        "run_admission_id": "adm-018f3c2a-7b1c-4d5e-8f90-1a2b3c4d5e6f",
        "admission_version": 1,
        "actor_delegation_id": "delegation-1",
        "actor_delegation_consumption_id": "consumption-1",
        "admission_request_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "tenant_id": "tenant-1",
        "resource_organization_id": "org-1",
        "workspace_id": "workspace-1",
        "edit_session_id": "session-1",
        "base": {
            "kind": "workspace_head",
            "revision_id": "rev-1",
            "manifest_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        "scope": {
            "kind": "edit",
            "resource_paths": ["src/main.rs"]
        },
        "subject_id": "user-1",
        "device_id": "device-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "owner_epoch": 4,
        "core_principal": {
            "service_id": "acp-service-1",
            "service_role": "core",
            "workload_instance_id": "acp-instance-1",
            "credential_key_id": "credential-key-1",
            "certificate_thumbprint_s256": "cccccccccccccccccccccccccccccccccccccccccccccccccc",
            "service_authority_epoch": 3
        },
        "isolation_profile_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "command_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "execution_authority_epoch": 7,
        "data_classification": "synthetic",
        "environment": {
            "environment_authority_id": "env-authority-1",
            "environment_kind": "staging",
            "environment_authority_epoch": 2
        },
        "issued_at_ms": 1_757_000_000_000_i64,
        "authorization_ttl_seconds": 300,
        "expires_at_ms": 1_757_000_030_000_i64,
        "state": "issued"
    })
}

/// The canonical serialization of a strict-decoded fixture record — what a
/// 200 echo must look like byte-for-byte.
pub(crate) fn fixture_canonical_echo() -> String {
    let record: RunAdmissionRecord = serde_json::from_value(fixture_record()).expect("fixture decodes");
    serde_json::to_string(&record).expect("record serializes")
}

/// Extracts `error.code` from the receive-face error envelope.
pub(crate) fn error_code(body: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(body).expect("error envelope is JSON");
    value["error"]["code"]
        .as_str()
        .expect("error.code is a string")
        .to_string()
}
