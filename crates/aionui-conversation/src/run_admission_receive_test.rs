//! Router-level tests for the run admission receive face
//! (T0-ACP-ADMISSION-DELIVERY Slice B2a).
//!
//! Every test drives the real router through `tower::ServiceExt::oneshot`
//! with a hand-built request: the verified-leaf extension stands in for the
//! dedicated internal mTLS listener (Slice B2b), the ACP service token is
//! minted against a wiremock JWKS endpoint, and persistence is an in-memory
//! write-once store.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use aionui_auth::{AcpServiceTokenConfig, AcpServiceTokenVerifier, VerifiedClientLeaf};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::MockServer;

use crate::run_admission_receive::{
    RUN_ADMISSION_BODY_LIMIT, RUN_ADMISSION_DUPLICATE_CODE, RUN_ADMISSION_RECEIVE_PATH, RUN_ADMISSION_UNAVAILABLE_CODE,
    RunAdmissionReceiveState, RunAdmissionRecord, run_admission_receive_router,
};
use crate::run_admission_test_support::{
    IDEMPOTENCY_KEY_1, IDEMPOTENCY_KEY_2, MemoryAdmissionStore, MintOverrides, error_code, fixture_record, jwks_server,
    mint_token,
};

// ---------------------------------------------------------------------------
// Harness and request builders
// ---------------------------------------------------------------------------

struct Harness {
    router: Router,
    server: MockServer,
    leaf: VerifiedClientLeaf,
    store: Arc<MemoryAdmissionStore>,
}

async fn harness() -> Harness {
    let server = jwks_server().await;
    let verifier = AcpServiceTokenVerifier::new(
        AcpServiceTokenConfig::new(server.uri())
            .expect("issuer")
            .allow_insecure_http(),
    )
    .expect("verifier");
    let store = Arc::new(MemoryAdmissionStore::default());
    let router = run_admission_receive_router(RunAdmissionReceiveState {
        verifier,
        repository: store.clone(),
    });
    let leaf = VerifiedClientLeaf::from_der(b"acp-test-client-leaf-der");
    Harness {
        router,
        server,
        leaf,
        store,
    }
}

/// Stands in for the Slice B2b mTLS listener: the leaf extension is what the
/// accept loop inserts after the handshake.
fn admission_request(harness: &Harness, headers: &[(&str, String)], with_leaf: bool, body: Vec<u8>) -> Request<Body> {
    let mut builder = Request::builder().method("POST").uri(RUN_ADMISSION_RECEIVE_PATH);
    for (name, value) in headers {
        builder = builder.header(*name, value.clone());
    }
    if with_leaf {
        builder = builder.extension(harness.leaf.clone());
    }
    builder.body(Body::from(body)).expect("request body")
}

/// Well-formed headers for the standard admission request.
fn standard_headers(harness: &Harness) -> Vec<(&'static str, String)> {
    vec![
        ("Idempotency-Key", IDEMPOTENCY_KEY_1.to_string()),
        ("Content-Type", "application/json".to_string()),
        (
            "Authorization",
            format!(
                "Bearer {}",
                mint_token(&harness.server.uri(), &MintOverrides::default(), &harness.leaf)
            ),
        ),
    ]
}

async fn send(harness: &Harness, request: Request<Body>) -> Response {
    harness
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("router is infallible")
}

async fn response_body(response: Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes()
            .to_vec(),
    )
    .expect("response body is UTF-8")
}

// ---------------------------------------------------------------------------
// Fixture record (frozen ACP Go json tags)
// ---------------------------------------------------------------------------

/// Serializes the fixture body to exactly `target` bytes by widening
/// `scope.resource_paths[0]` (ASCII only, so byte length == JSON length).
fn fixture_body_of_length(target: usize) -> String {
    let mut value = fixture_record();
    let base_len = serde_json::to_string(&value).unwrap().len();
    assert!(target >= base_len, "fixture already exceeds the target size");
    // Replacing the 11 content chars of "src/main.rs"; the surrounding
    // JSON quotes exist on both sides and cancel out.
    let filler_len = target - base_len + 11;
    value["scope"]["resource_paths"][0] = Value::String("x".repeat(filler_len));
    let body = serde_json::to_string(&value).unwrap();
    assert_eq!(body.len(), target, "padding arithmetic");
    body
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admitted_request_answers_200_with_canonical_record_echo() {
    let harness = harness().await;
    let body = fixture_record().to_string();

    let response = send(
        &harness,
        admission_request(&harness, &standard_headers(&harness), true, body.clone().into_bytes()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let echoed = response_body(response).await;

    // The echo is the canonical projection of the decoded record: strict
    // round-trip plus byte-equality with the canonical serialization.
    let record: RunAdmissionRecord = serde_json::from_str(&echoed).expect("echo strict-decodes");
    assert_eq!(echoed, serde_json::to_string(&record).unwrap());

    // Identity triple echoed verbatim for the ACP deliverer's validation.
    assert_eq!(record.run_admission_id, "adm-018f3c2a-7b1c-4d5e-8f90-1a2b3c4d5e6f");
    assert_eq!(record.tenant_id, "tenant-1");
    assert_eq!(record.resource_organization_id, "org-1");

    // The stored record_json is the same canonical bytes the ACP received.
    let held = harness.store.held.lock().unwrap();
    assert_eq!(held.get(record.run_admission_id.as_str()).unwrap(), &echoed);
}

#[tokio::test]
async fn echo_is_canonical_not_verbatim() {
    let harness = harness().await;
    // Pretty-printed body: same record, different bytes than the echo.
    let body = serde_json::to_string_pretty(&fixture_record()).unwrap();

    let response = send(
        &harness,
        admission_request(&harness, &standard_headers(&harness), true, body.into_bytes()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let echoed = response_body(response).await;

    let record: RunAdmissionRecord = serde_json::from_str(&echoed).unwrap();
    assert_eq!(echoed, serde_json::to_string(&record).unwrap());
    assert_ne!(
        echoed,
        serde_json::to_string_pretty(&record).unwrap(),
        "the echo must be the canonical compact projection"
    );
}

// ---------------------------------------------------------------------------
// Duplicate and storage-failure outcomes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repeat_delivery_of_same_identity_is_409_duplicate() {
    let harness = harness().await;

    let first = send(
        &harness,
        admission_request(
            &harness,
            &standard_headers(&harness),
            true,
            fixture_record().to_string().into_bytes(),
        ),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    // Second delivery with a fresh idempotency key: still the same admission
    // identity, so 409 with the single legal code.
    let mut headers = standard_headers(&harness);
    headers[0] = ("Idempotency-Key", IDEMPOTENCY_KEY_2.to_string());
    let second = send(
        &harness,
        admission_request(&harness, &headers, true, fixture_record().to_string().into_bytes()),
    )
    .await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    assert_eq!(error_code(&response_body(second).await), RUN_ADMISSION_DUPLICATE_CODE);

    // The originally held record is untouched (write-once).
    let held = harness.store.held.lock().unwrap();
    assert_eq!(held.len(), 1);
}

#[tokio::test]
async fn storage_failure_is_503_unavailable() {
    let harness = harness().await;
    harness.store.fail_admissions.store(true, Ordering::SeqCst);

    let response = send(
        &harness,
        admission_request(
            &harness,
            &standard_headers(&harness),
            true,
            fixture_record().to_string().into_bytes(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        error_code(&response_body(response).await),
        RUN_ADMISSION_UNAVAILABLE_CODE
    );
}

// ---------------------------------------------------------------------------
// Authentication (all failures are 401, never a decoder oracle)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn request_without_verified_leaf_is_401() {
    let harness = harness().await;
    let response = send(
        &harness,
        admission_request(
            &harness,
            &standard_headers(&harness),
            false,
            fixture_record().to_string().into_bytes(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(&response_body(response).await), "unauthorized");
}

#[tokio::test]
async fn unauthenticated_request_never_reaches_the_decoder() {
    let harness = harness().await;
    // Garbage body and valid headers but no credential: authentication
    // precedes all parsing, so the answer is 401, not a body-shaped 400.
    let mut headers = standard_headers(&harness);
    headers.pop(); // drop Authorization
    let response = send(
        &harness,
        admission_request(&harness, &headers, true, b"not json".to_vec()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bearer_credential_failures_are_401() {
    let harness = harness().await;
    let body = fixture_record().to_string().into_bytes();
    let missing_auth = {
        let mut headers = standard_headers(&harness);
        headers.pop();
        headers
    };
    let cases: Vec<(&str, Vec<(&'static str, String)>)> = vec![
        ("missing header", missing_auth),
        (
            "blank bearer token",
            vec![
                ("Idempotency-Key", IDEMPOTENCY_KEY_1.to_string()),
                ("Content-Type", "application/json".to_string()),
                ("Authorization", "Bearer ".to_string()),
            ],
        ),
        (
            "wrong scheme",
            vec![
                ("Idempotency-Key", IDEMPOTENCY_KEY_1.to_string()),
                ("Content-Type", "application/json".to_string()),
                ("Authorization", "Basic dXNlcjpwYXNz".to_string()),
            ],
        ),
        (
            "duplicate authorization headers",
            vec![
                ("Idempotency-Key", IDEMPOTENCY_KEY_1.to_string()),
                ("Content-Type", "application/json".to_string()),
                ("Authorization", "Bearer one".to_string()),
                ("Authorization", "Bearer two".to_string()),
            ],
        ),
    ];
    for (name, headers) in cases {
        let response = send(&harness, admission_request(&harness, &headers, true, body.clone())).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{name}");
        assert_eq!(error_code(&response_body(response).await), "unauthorized", "{name}");
    }
}

#[tokio::test]
async fn token_failures_are_401() {
    let harness = harness().await;
    let body = fixture_record().to_string().into_bytes();

    // Expired token.
    let expired = mint_token(
        &harness.server.uri(),
        &MintOverrides {
            exp_offset_seconds: -600,
            ..MintOverrides::default()
        },
        &harness.leaf,
    );
    // Token bound to a different certificate.
    let wrong_binding = mint_token(
        &harness.server.uri(),
        &MintOverrides {
            cnf_thumbprint: Some("nOtThIsLeaFThUmbPrInT0000000000000000000000".to_string()),
            ..MintOverrides::default()
        },
        &harness.leaf,
    );
    for (name, token) in [("expired", expired), ("wrong certificate binding", wrong_binding)] {
        let headers = vec![
            ("Idempotency-Key", IDEMPOTENCY_KEY_1.to_string()),
            ("Content-Type", "application/json".to_string()),
            ("Authorization", format!("Bearer {token}")),
        ];
        let response = send(&harness, admission_request(&harness, &headers, true, body.clone())).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{name}");
        assert_eq!(error_code(&response_body(response).await), "unauthorized", "{name}");
    }
}

// ---------------------------------------------------------------------------
// Admission request headers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn idempotency_key_violations_are_400() {
    let harness = harness().await;
    let body = fixture_record().to_string().into_bytes();
    let valid_token = mint_token(&harness.server.uri(), &MintOverrides::default(), &harness.leaf);
    let bearer = format!("Bearer {valid_token}");
    let cases: Vec<(&str, Vec<(&'static str, String)>)> = vec![
        ("missing", {
            let mut headers = standard_headers(&harness);
            headers.remove(0);
            headers
        }),
        (
            "duplicated",
            vec![
                ("Idempotency-Key", IDEMPOTENCY_KEY_1.to_string()),
                ("Idempotency-Key", IDEMPOTENCY_KEY_2.to_string()),
                ("Content-Type", "application/json".to_string()),
                ("Authorization", bearer.clone()),
            ],
        ),
        (
            "not a uuid",
            vec![
                ("Idempotency-Key", "delivery-17".to_string()),
                ("Content-Type", "application/json".to_string()),
                ("Authorization", bearer.clone()),
            ],
        ),
        (
            "uuid v7 is not v4",
            vec![
                ("Idempotency-Key", Uuid::now_v7().to_string()),
                ("Content-Type", "application/json".to_string()),
                ("Authorization", bearer.clone()),
            ],
        ),
        (
            "uppercase v4 is not canonical",
            vec![
                ("Idempotency-Key", "3B241101-E2BB-4255-8CAF-4136C566A962".to_string()),
                ("Content-Type", "application/json".to_string()),
                ("Authorization", bearer.clone()),
            ],
        ),
    ];
    for (name, headers) in cases {
        let response = send(&harness, admission_request(&harness, &headers, true, body.clone())).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(error_code(&response_body(response).await), "invalid_request", "{name}");
    }
}

#[tokio::test]
async fn content_type_violations_are_400() {
    let harness = harness().await;
    let body = fixture_record().to_string().into_bytes();
    let valid_token = mint_token(&harness.server.uri(), &MintOverrides::default(), &harness.leaf);
    let bearer = format!("Bearer {valid_token}");
    let cases: Vec<(&str, Vec<(&'static str, String)>)> = vec![
        ("missing", {
            let mut headers = standard_headers(&harness);
            headers.remove(1);
            headers
        }),
        (
            "not json",
            vec![
                ("Idempotency-Key", IDEMPOTENCY_KEY_1.to_string()),
                ("Content-Type", "text/plain".to_string()),
                ("Authorization", bearer.clone()),
            ],
        ),
        (
            "duplicated",
            vec![
                ("Idempotency-Key", IDEMPOTENCY_KEY_1.to_string()),
                ("Content-Type", "application/json".to_string()),
                ("Content-Type", "application/json".to_string()),
                ("Authorization", bearer.clone()),
            ],
        ),
    ];
    for (name, headers) in cases {
        let response = send(&harness, admission_request(&harness, &headers, true, body.clone())).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(error_code(&response_body(response).await), "invalid_request", "{name}");
    }
}

#[tokio::test]
async fn content_type_with_parameters_is_accepted() {
    let harness = harness().await;
    let mut headers = standard_headers(&harness);
    headers[1] = ("Content-Type", "application/json; charset=utf-8".to_string());
    let response = send(
        &harness,
        admission_request(&harness, &headers, true, fixture_record().to_string().into_bytes()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Body discipline (64KB cap, strict decode, identity floor)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn body_decode_violations_are_400() {
    let harness = harness().await;
    let mut unknown_top_level = fixture_record();
    unknown_top_level["surprise"] = json!("nope");
    let mut unknown_nested = fixture_record();
    unknown_nested["base"]["surprise"] = json!("nope");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("invalid json", b"{not json".to_vec()),
        ("unknown top-level field", unknown_top_level.to_string().into_bytes()),
        ("unknown nested field", unknown_nested.to_string().into_bytes()),
        ("trailing data", {
            let mut body = fixture_record().to_string().into_bytes();
            body.extend_from_slice(b"{}");
            body
        }),
        (
            "one byte over the limit",
            fixture_body_of_length(RUN_ADMISSION_BODY_LIMIT + 1).into_bytes(),
        ),
    ];
    for (name, body) in cases {
        let response = send(
            &harness,
            admission_request(&harness, &standard_headers(&harness), true, body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(error_code(&response_body(response).await), "invalid_request", "{name}");
    }
}

#[tokio::test]
async fn body_at_exactly_the_limit_is_accepted() {
    let harness = harness().await;
    let body = fixture_body_of_length(RUN_ADMISSION_BODY_LIMIT).into_bytes();
    let response = send(
        &harness,
        admission_request(&harness, &standard_headers(&harness), true, body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn record_below_delivery_identity_floor_is_400() {
    let harness = harness().await;
    let mut blank_identity = fixture_record();
    blank_identity["run_admission_id"] = json!("   ");
    let mut missing_attempt = fixture_record();
    missing_attempt["attempt_id"] = json!("");
    let cases: Vec<(&str, Value)> = vec![
        ("blank run_admission_id", blank_identity),
        ("blank attempt_id", missing_attempt),
    ];
    for (name, record) in cases {
        let response = send(
            &harness,
            admission_request(
                &harness,
                &standard_headers(&harness),
                true,
                record.to_string().into_bytes(),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(error_code(&response_body(response).await), "invalid_request", "{name}");
    }
}
