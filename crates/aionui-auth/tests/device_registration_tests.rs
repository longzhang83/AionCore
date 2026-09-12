//! Integration tests for the Auth Center device-registration client
//! (`register_device`) and its wiring into the OIDC callback.
//!
//! Wire contract source of truth:
//! rsm_project/auth-center/internal/httpapi/device_registration.go
//! (handler) and internal/oauthdpop/proof.go (`unbound_management` proof
//! profile). The tests below assert the client produces exactly that shape
//! on the wire and fails closed on every contract error path.

use std::collections::HashSet;
use std::time::Duration;

use base64::Engine as _;
use p256::ecdsa::signature::Verifier;
use serde_json::{Value, json};
use wiremock::matchers::{body_string, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aionui_auth::{
    AuthCenterProtocolClient, DeviceRegistrationError, DeviceRegistrationReceipt, IDpopKeyStore, InMemoryDpopKeyStore,
    RsmAuthConfig, RsmOidcCallbackQuery, RsmOidcLoginQuery, RsmOidcStateStore, derive_device_idempotency_key,
    register_device,
};

const DEVICES_PATH: &str = "/api/auth-center/v1/devices";

fn receipt_json() -> Value {
    json!({
        "device_id": "3f2b8a1e-5c4d-4a2b-9e6f-0a1b2c3d4e5f",
        "status": "active",
        "binding_version": 1,
        "authority_epoch": 1,
        "registered_at": "2026-09-12T01:02:03.123456789Z",
        "updated_at": "2026-09-12T01:02:03.123456789Z"
    })
}

fn header_value(request: &wiremock::Request, name: &str) -> String {
    request
        .headers
        .get(name)
        .unwrap_or_else(|| panic!("header {name} must be present"))
        .to_str()
        .expect("header value is ASCII")
        .to_owned()
}

/// Canonical lowercase UUIDv4 shape: 8-4-4-4-12 hex, version nibble 4,
/// RFC 4122 variant. Mirrors the server's `canonicalDeviceRegistrationUUIDv4`
/// (device_registration.go:339-342) without adding a uuid dependency.
fn assert_canonical_uuidv4(value: &str) {
    let parts: Vec<&str> = value.split('-').collect();
    assert_eq!(
        parts.iter().map(|part| part.len()).collect::<Vec<_>>(),
        vec![8, 4, 4, 4, 12],
        "must be 8-4-4-4-12 grouped: {value}"
    );
    assert!(
        value
            .chars()
            .all(|ch| ch == '-' || ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
        "must be lowercase hex: {value}"
    );
    assert_eq!(value.chars().nth(14), Some('4'), "version nibble must be 4: {value}");
    assert!(
        matches!(value.chars().nth(19), Some('8' | '9' | 'a' | 'b')),
        "variant must be RFC 4122: {value}"
    );
}

fn decode_proof_segment(proof: &str, index: usize) -> Value {
    let segment = proof.split('.').nth(index).expect("DPoP proof has three segments");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .expect("DPoP proof segment is base64url");
    serde_json::from_slice(&bytes).expect("DPoP proof segment is JSON")
}

/// Self-verify the ES256 signature of a compact proof against the JWK in its
/// header, and return the RFC 7638 thumbprint of that header JWK.
fn verify_proof_signature_and_header_jkt(proof: &str) -> String {
    let segments: Vec<&str> = proof.split('.').collect();
    assert_eq!(segments.len(), 3);
    let header = decode_proof_segment(proof, 0);
    let jwk = &header["jwk"];
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwk["x"].as_str().unwrap())
        .unwrap();
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwk["y"].as_str().unwrap())
        .unwrap();
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let raw_signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segments[2])
        .unwrap();
    let (r, s) = raw_signature.split_at(32);
    let signature = {
        use p256::elliptic_curve::FieldBytes;
        p256::ecdsa::Signature::from_scalars(
            *FieldBytes::<p256::NistP256>::from_slice(r),
            *FieldBytes::<p256::NistP256>::from_slice(s),
        )
        .expect("64 raw bytes are always a valid r||s pair")
    };
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .expect("DPoP proof signature must verify with the header JWK");

    aionui_auth::jwk_thumbprint(&aionui_auth::DpopPublicJwk {
        kty: jwk["kty"].as_str().unwrap().to_owned(),
        crv: jwk["crv"].as_str().unwrap().to_owned(),
        x: jwk["x"].as_str().unwrap().to_owned(),
        y: jwk["y"].as_str().unwrap().to_owned(),
    })
}

// ---------------------------------------------------------------------------
// ① + ② Request shape and unbound-management proof profile on the happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registration_sends_exact_request_shape_and_unbound_profile_proof() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(201).set_body_json(receipt_json()))
        .mount(&server)
        .await;

    let store = InMemoryDpopKeyStore::new();
    let handle = store.generate().unwrap();
    let receipt = register_device(&reqwest::Client::new(), &server.uri(), "at-value", &handle)
        .await
        .expect("registration must succeed on 201");

    // ③ 201 receipt is parsed field by field.
    assert_eq!(
        receipt,
        DeviceRegistrationReceipt {
            device_id: "3f2b8a1e-5c4d-4a2b-9e6f-0a1b2c3d4e5f".into(),
            status: "active".into(),
            binding_version: 1,
            authority_epoch: 1,
            registered_at: "2026-09-12T01:02:03.123456789Z".into(),
            updated_at: "2026-09-12T01:02:03.123456789Z".into(),
        }
    );

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1, "exactly one request on the happy path");
    let request = &received[0];
    assert_eq!(request.url.path(), DEVICES_PATH);

    // ① Bearer scheme (the registration proof does not bind the token, so
    // the DPoP scheme must NOT be used).
    assert_eq!(header_value(request, "authorization"), "Bearer at-value");

    // ① Idempotency-Key: canonical lowercase UUIDv4, derived from the
    // session key's jkt (deterministic — retries reuse it).
    let key = header_value(request, "idempotency-key");
    assert_canonical_uuidv4(&key);
    assert_eq!(key, derive_device_idempotency_key(handle.jkt()));

    // ① Content-Type: exactly one value, application/json.
    assert_eq!(
        request.headers.get_all("content-type").iter().count(),
        1,
        "exactly one Content-Type value"
    );
    assert_eq!(header_value(request, "content-type"), "application/json");

    // Body is exactly `{}` — no device_label — so a same-key retry has an
    // identical request digest and the server can replay the receipt.
    assert_eq!(String::from_utf8(request.body.clone()).unwrap(), "{}");

    // ② Proof: dpop+jwt / ES256 with an EC P-256 JWK whose thumbprint is the
    // session key's jkt (device key == session key).
    let proof = header_value(request, "dpop");
    let proof_header = decode_proof_segment(&proof, 0);
    assert_eq!(proof_header["typ"], "dpop+jwt");
    assert_eq!(proof_header["alg"], "ES256");
    assert_eq!(proof_header["jwk"]["kty"], "EC");
    assert_eq!(proof_header["jwk"]["crv"], "P-256");
    assert_eq!(verify_proof_signature_and_header_jkt(&proof), handle.jkt());

    // ② Claims: htm/htu/iat/jti present, htu exact-match endpoint, NO ath
    // (unbound_management profile) and no nonce on the first attempt.
    let claims = decode_proof_segment(&proof, 1);
    assert_eq!(claims["htm"], "POST");
    assert_eq!(
        claims["htu"],
        format!("{}{}", server.uri().trim_end_matches('/'), DEVICES_PATH)
    );
    let iat = claims["iat"].as_i64().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!((iat - now).abs() <= 120, "iat must be within the freshness window");
    assert!(
        claims["jti"].as_str().unwrap().len() >= 16,
        "jti must satisfy isValidJTI"
    );
    assert!(claims.get("ath").is_none(), "registration proof must NOT carry ath");
    assert!(claims.get("nonce").is_none(), "first attempt must not carry a nonce");
}

// ---------------------------------------------------------------------------
// ④ Network failure → same Idempotency-Key retry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn network_failure_retries_with_the_same_idempotency_key() {
    let server = MockServer::start().await;
    // First two attempts are answered slower than the client's timeout —
    // from the client's perspective these are network errors/timeouts.
    Mock::given(method("POST"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(201).set_delay(Duration::from_millis(800)))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(201).set_body_json(receipt_json()))
        .mount(&server)
        .await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let store = InMemoryDpopKeyStore::new();
    let handle = store.generate().unwrap();
    let receipt = register_device(&client, &server.uri(), "at-value", &handle)
        .await
        .expect("two timed-out attempts must be retried, third succeeds");
    assert_eq!(receipt.device_id, "3f2b8a1e-5c4d-4a2b-9e6f-0a1b2c3d4e5f");

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 3, "two retries on top of the initial attempt");
    let keys: HashSet<String> = received
        .iter()
        .map(|request| header_value(request, "idempotency-key"))
        .collect();
    assert_eq!(keys.len(), 1, "every retry must reuse the same Idempotency-Key");
    assert_eq!(
        keys.into_iter().next().unwrap(),
        derive_device_idempotency_key(handle.jkt())
    );
    for request in &received {
        assert_eq!(String::from_utf8(request.body.clone()).unwrap(), "{}");
        assert_eq!(header_value(request, "authorization"), "Bearer at-value");
    }
}

// ---------------------------------------------------------------------------
// ⑤ use_dpop_nonce → exactly one nonce-carrying retry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn use_dpop_nonce_retries_once_with_the_demanded_nonce() {
    let server = MockServer::start().await;
    let demanded_nonce = "server-nonce-0123456789abcdef";
    Mock::given(method("POST"))
        .and(path(DEVICES_PATH))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "error_description": "A fresh DPoP nonce is required.",
                    "request_id": "req-1"
                }))
                .insert_header("DPoP-Nonce", demanded_nonce),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(201).set_body_json(receipt_json()))
        .mount(&server)
        .await;

    let store = InMemoryDpopKeyStore::new();
    let handle = store.generate().unwrap();
    let receipt = register_device(&reqwest::Client::new(), &server.uri(), "at-value", &handle)
        .await
        .expect("nonce retry must succeed");
    assert_eq!(receipt.device_id, "3f2b8a1e-5c4d-4a2b-9e6f-0a1b2c3d4e5f");

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2, "exactly one nonce retry");
    let first_key = header_value(&received[0], "idempotency-key");
    let second_key = header_value(&received[1], "idempotency-key");
    assert_eq!(first_key, second_key, "nonce retry must reuse the Idempotency-Key");

    let first_claims = decode_proof_segment(&header_value(&received[0], "dpop"), 1);
    assert!(
        first_claims.get("nonce").is_none(),
        "the rejected attempt must not have carried a nonce"
    );
    let second_claims = decode_proof_segment(&header_value(&received[1], "dpop"), 1);
    assert_eq!(
        second_claims["nonce"], demanded_nonce,
        "retry proof must carry the demanded nonce claim"
    );
    assert!(
        second_claims["jti"] != first_claims["jti"],
        "retry proof must use a fresh jti"
    );
    // Both proofs still self-verify with the same session key.
    assert_eq!(
        verify_proof_signature_and_header_jkt(&header_value(&received[0], "dpop")),
        handle.jkt()
    );
    assert_eq!(
        verify_proof_signature_and_header_jkt(&header_value(&received[1], "dpop")),
        handle.jkt()
    );
}

#[tokio::test]
async fn use_dpop_nonce_retry_is_capped_at_one_attempt() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DEVICES_PATH))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({ "error": "use_dpop_nonce" }))
                .insert_header("DPoP-Nonce", "server-nonce-0123456789abcdef"),
        )
        .mount(&server)
        .await;

    let store = InMemoryDpopKeyStore::new();
    let handle = store.generate().unwrap();
    let error = register_device(&reqwest::Client::new(), &server.uri(), "at-value", &handle)
        .await
        .expect_err("a second use_dpop_nonce must fail closed");
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2, "initial attempt plus exactly one nonce retry");
    assert!(matches!(error, DeviceRegistrationError::Rejected { status: 400, .. }));
}

// ---------------------------------------------------------------------------
// ⑥ 401 / 409 / 503 → fail-closed, no retry, no bundle
// ---------------------------------------------------------------------------

async fn mount_terminal(server: &MockServer, status: u16, code: &str) {
    Mock::given(method("POST"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(status).set_body_json(json!({ "error": code })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn unauthorized_401_fails_closed_without_retry() {
    let server = MockServer::start().await;
    mount_terminal(&server, 401, "unauthorized").await;
    let store = InMemoryDpopKeyStore::new();
    let handle = store.generate().unwrap();
    let error = register_device(&reqwest::Client::new(), &server.uri(), "at-value", &handle)
        .await
        .expect_err("401 must fail closed");
    assert!(matches!(
        error,
        DeviceRegistrationError::Rejected { status: 401, ref code } if code == "unauthorized"
    ));
    assert!(error.to_string().starts_with("Device registration failed"));
    assert_eq!(server.received_requests().await.unwrap().len(), 1, "terminal: no retry");
}

#[tokio::test]
async fn conflict_409_fails_closed_without_retry() {
    let server = MockServer::start().await;
    mount_terminal(&server, 409, "idempotency_conflict").await;
    let store = InMemoryDpopKeyStore::new();
    let handle = store.generate().unwrap();
    let error = register_device(&reqwest::Client::new(), &server.uri(), "at-value", &handle)
        .await
        .expect_err("409 must fail closed");
    assert!(matches!(
        error,
        DeviceRegistrationError::Rejected { status: 409, code } if code == "idempotency_conflict"
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1, "terminal: no retry");
}

#[tokio::test]
async fn admission_unavailable_503_fails_closed_without_retry() {
    let server = MockServer::start().await;
    mount_terminal(&server, 503, "device_admission_unavailable").await;
    let store = InMemoryDpopKeyStore::new();
    let handle = store.generate().unwrap();
    let error = register_device(&reqwest::Client::new(), &server.uri(), "at-value", &handle)
        .await
        .expect_err("503 must fail closed");
    assert!(matches!(error, DeviceRegistrationError::Unavailable));
    assert!(error.to_string().starts_with("Device registration failed"));
    assert_eq!(server.received_requests().await.unwrap().len(), 1, "terminal: no retry");
}

#[tokio::test]
async fn exhausted_network_retries_fail_closed_with_distinct_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DEVICES_PATH))
        .respond_with(ResponseTemplate::new(201).set_delay(Duration::from_millis(800)))
        .mount(&server)
        .await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let store = InMemoryDpopKeyStore::new();
    let handle = store.generate().unwrap();
    let error = register_device(&client, &server.uri(), "at-value", &handle)
        .await
        .expect_err("three timed-out attempts must exhaust the retry budget");
    assert!(matches!(error, DeviceRegistrationError::Network(_)));
    assert!(error.to_string().contains("Device registration failed"));
    // 3 attempts = initial + MAX_NETWORK_RETRIES retries.
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

// ---------------------------------------------------------------------------
// Callback wiring: registration failure fails the whole login, before any
// bundle is returned (so nothing can be stored in the vault).
// ---------------------------------------------------------------------------

fn oidc_config(base_url: String) -> RsmAuthConfig {
    RsmAuthConfig {
        enabled: true,
        issuer: Some(base_url),
        client_id: Some("agent-control-plane".to_owned()),
        client_secret: Some("server-side-secret".to_owned()),
        redirect_uri: Some("http://localhost:25808/api/auth/oidc/callback".to_owned()),
        additional_scopes: Vec::new(),
        app_code: "agent".to_owned(),
        internal_base_url: None,
        internal_token: None,
    }
}

async fn mount_discovery(mock_server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": mock_server.uri(),
            "authorization_endpoint": format!("{}/oauth/authorize", mock_server.uri()),
            "token_endpoint": format!("{}/oauth/token", mock_server.uri()),
            "userinfo_endpoint": format!("{}/oauth/userinfo", mock_server.uri()),
            "jwks_uri": format!("{}/.well-known/jwks.json", mock_server.uri())
        })))
        .mount(mock_server)
        .await;
}

#[tokio::test]
async fn oidc_callback_fails_closed_when_device_registration_is_rejected() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "exchanged-access-token",
            "token_type": "DPoP",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;
    mount_terminal(&server, 401, "unauthorized").await;

    let config = oidc_config(server.uri());
    let client = AuthCenterProtocolClient::new(reqwest::Client::new());
    let store = RsmOidcStateStore::new();
    let redirect = client
        .build_login_redirect(
            &config,
            &store,
            &axum::http::HeaderMap::new(),
            RsmOidcLoginQuery { return_to: None },
        )
        .await
        .unwrap();
    let state = reqwest::Url::parse(&redirect)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();

    let error = client
        .exchange_callback(
            &config,
            &store,
            &InMemoryDpopKeyStore::new(),
            RsmOidcCallbackQuery {
                code: Some("auth-code".to_owned()),
                state: Some(state),
                error: None,
                error_description: None,
            },
        )
        .await
        .expect_err("a rejected device registration must fail the whole login");

    // The error must clearly name device registration, not the token exchange.
    assert!(
        error.to_string().contains("Device registration failed"),
        "error must attribute the failure to device registration, got: {error}"
    );
    assert!(!error.to_string().contains("token exchange"));

    // Both the token POST and the registration POST happened exactly once —
    // the login aborted fail-closed with no silent retries beyond the contract.
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.iter().filter(|r| r.url.path() == "/oauth/token").count(), 1);
    assert_eq!(received.iter().filter(|r| r.url.path() == DEVICES_PATH).count(), 1);
}

#[tokio::test]
async fn oidc_callback_request_body_is_empty_object_even_after_prior_registration() {
    // Guard against accidentally adding device_label later: the server
    // replays receipts only for byte-identical requests under one key.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DEVICES_PATH))
        .and(body_string("{}"))
        .respond_with(ResponseTemplate::new(201).set_body_json(receipt_json()))
        .mount(&server)
        .await;
    let store = InMemoryDpopKeyStore::new();
    let handle = store.generate().unwrap();
    register_device(&reqwest::Client::new(), &server.uri(), "at-value", &handle)
        .await
        .expect("empty-object body must be accepted");
}
