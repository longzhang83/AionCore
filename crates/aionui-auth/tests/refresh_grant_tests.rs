//! Wiremock coverage for the DPoP-bound refresh grant on the Schedule BFF:
//! rotation success, failure semantics, single-flight dedup, no-retry, and
//! the pre-refresh-grant regression paths.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::MockServer;
use wiremock::{Mock, ResponseTemplate};

use aionui_auth::{
    AuthCenterTokenResponse, AuthCenterTokenVaultKey, AuthIdentityMode, AuthRouterState, CookieConfig,
    DeviceRegistrationReceipt, DpopError, DpopKeySelector, DpopSigningHandle, IAuthCenterTokenVault, IDpopKeyStore,
    InMemoryAuthCenterTokenVault, JwtService, QrTokenStore, RsmAuthConfig, RsmOidcStateStore, ScheduleBffConfig,
    auth_routes, bundle_from_token_response, dpop_ath, fingerprint_token,
};
use aionui_db::{IIamRepository, IUserRepository, SqliteIamRepository, SqliteUserRepository, init_database_memory};

const USER_ID: &str = "system_default_user";

struct TestContext {
    jwt_service: Arc<JwtService>,
    vault: Arc<InMemoryAuthCenterTokenVault>,
    dpop_key_store: Arc<dyn IDpopKeyStore>,
    _db: aionui_db::Database,
}

/// Build the BFF app against two wiremock servers: `acp` is the Agent Control
/// Plane upstream, `auth` plays the Auth Center (its URI becomes the issuer,
/// so the refresh token endpoint is `{auth.uri()}/oauth/token`).
async fn build_app(acp: &MockServer, auth: &MockServer, timeout: Duration) -> (Router, TestContext) {
    let db = init_database_memory().await.unwrap();
    let user_repo = Arc::new(SqliteUserRepository::new(db.pool().clone())) as Arc<dyn IUserRepository>;
    let iam_repo = Arc::new(SqliteIamRepository::new(db.pool().clone())) as Arc<dyn IIamRepository>;
    let jwt_service = Arc::new(JwtService::new("refresh_grant_test_secret".to_owned()));
    let vault = Arc::new(InMemoryAuthCenterTokenVault::new());
    let rsm_auth_config = RsmAuthConfig {
        enabled: true,
        issuer: Some(auth.uri()),
        client_id: Some("agent-control-plane".to_owned()),
        client_secret: Some("agent-control-plane-secret".to_owned()),
        redirect_uri: None,
        additional_scopes: Vec::new(),
        app_code: "agent".to_owned(),
        internal_base_url: None,
        internal_token: None,
    };
    let schedule_bff_config = ScheduleBffConfig::new_with_identity_contract(
        acp.uri(),
        timeout,
        &rsm_auth_config,
        Some("agent-control-plane"),
    )
    .unwrap();
    let dpop_key_store = schedule_bff_config.dpop_key_store().clone();
    let state = AuthRouterState {
        jwt_service: jwt_service.clone(),
        user_repo,
        fs_adopter: None,
        iam_repo,
        cookie_config: Arc::new(CookieConfig {
            secure: false,
            same_site: "Lax",
        }),
        qr_token_store: Arc::new(QrTokenStore::new()),
        identity_mode: AuthIdentityMode::UserSession,
        bootstrap_secret: None,
        session_revoked_hook: None,
        rsm_auth_config: Arc::new(rsm_auth_config),
        rsm_oidc_state_store: Arc::new(RsmOidcStateStore::new()),
        auth_center_token_vault: vault.clone(),
        schedule_bff_config: Arc::new(schedule_bff_config),
        http_client: reqwest::Client::new(),
        local: false,
        aionpro_mode: false,
    };
    (
        auth_routes(state),
        TestContext {
            jwt_service,
            vault,
            dpop_key_store,
            _db: db,
        },
    )
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

/// Bind an expiring vault bundle (optionally with a device receipt) plus its
/// DPoP session key, mirroring the OIDC callback. Returns the local token.
fn bind_expiring_token(
    ctx: &TestContext,
    access_token: &str,
    refresh_token: Option<&str>,
    expires_in: i64,
    receipt: Option<DeviceRegistrationReceipt>,
) -> String {
    let local_token = ctx.jwt_service.sign_auth_center_bound(USER_ID, "admin", 0).unwrap();
    let mut bundle = bundle_from_token_response(
        AuthCenterTokenResponse {
            access_token: access_token.to_owned(),
            refresh_token: refresh_token.map(str::to_owned),
            id_token: Some("id-token-must-stay-server-side".to_owned()),
            token_type: Some("Bearer".to_owned()),
            scope: Some("schedule:read schedule:write".to_owned()),
            expires_in: Some(expires_in),
        },
        now_ms(),
    );
    bundle.device_registration = receipt;
    let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, USER_ID);
    let handle = ctx.dpop_key_store.generate().unwrap();
    ctx.dpop_key_store
        .bind(
            handle,
            &DpopKeySelector::new(USER_ID, vault_key.token_fingerprint.clone()),
        )
        .unwrap();
    ctx.vault.store(vault_key, bundle);
    local_token
}

fn bound_session_key(ctx: &TestContext, local_token: &str) -> Option<DpopSigningHandle> {
    ctx.dpop_key_store
        .get(&DpopKeySelector::new(USER_ID, fingerprint_token(local_token)))
        .unwrap()
}

fn sample_receipt() -> DeviceRegistrationReceipt {
    DeviceRegistrationReceipt {
        device_id: "device-uuid-refresh-1".to_owned(),
        status: "active".to_owned(),
        binding_version: 1,
        authority_epoch: 1,
        registered_at: "2026-09-12T00:00:00.123456789Z".to_owned(),
        updated_at: "2026-09-12T00:00:00.123456789Z".to_owned(),
    }
}

fn rotated_token_response() -> Value {
    json!({
        "access_token": "rotated-access",
        "refresh_token": "rotated-refresh",
        "id_token": "rotated-id",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid profile email"
    })
}

async fn mount_schedule_upstream(acp: &MockServer, expected_authorization: &'static str) {
    let authorization = expected_authorization.to_owned();
    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/api/schedule/v1/schedules"))
        .respond_with(move |_request: &wiremock::Request| {
            // Echo the authorization the BFF actually sent so assertions can
            // read it back through received_requests().
            ResponseTemplate::new(200).set_body_json(json!({"items": [], "seen": authorization}))
        })
        .mount(acp)
        .await;
}

async fn mount_token_endpoint(auth: &MockServer, status: u16, body: Value, delay: Duration) {
    Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/oauth/token"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body).set_delay(delay))
        .mount(auth)
        .await;
}

fn get_schedules(local_token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri("/api/schedule/v1/schedules")
        .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
        .body(Body::empty())
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
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
    use aionui_auth::{DpopPublicJwk, jwk_thumbprint};
    use p256::ecdsa::signature::Verifier;

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
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segments[2])
        .unwrap();
    let (r, s) = signature_bytes.split_at(32);
    let signature = p256::ecdsa::Signature::from_scalars(
        *p256::elliptic_curve::FieldBytes::<p256::NistP256>::from_slice(r),
        *p256::elliptic_curve::FieldBytes::<p256::NistP256>::from_slice(s),
    )
    .unwrap();
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .expect("DPoP proof signature must verify with the header JWK");

    let header_jwk = DpopPublicJwk {
        kty: jwk["kty"].as_str().unwrap().to_owned(),
        crv: jwk["crv"].as_str().unwrap().to_owned(),
        x: jwk["x"].as_str().unwrap().to_owned(),
        y: jwk["y"].as_str().unwrap().to_owned(),
    };
    jwk_thumbprint(&header_jwk)
}

fn assert_refresh_form(body: &[u8], expected_refresh: &str) {
    let form: Vec<(String, String)> = url::form_urlencoded::parse(body)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    let get = |name: &str| {
        form.iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .unwrap_or_else(|| panic!("form field {name} missing: {form:?}"))
    };
    assert_eq!(get("grant_type"), "refresh_token");
    assert_eq!(get("refresh_token"), expected_refresh);
    assert_eq!(get("client_id"), "agent-control-plane");
    assert_eq!(get("client_secret"), "agent-control-plane-secret");
}

/// Assert the refresh grant carried a token-endpoint DPoP proof (self-signed,
/// POST, exact htu, no ath) bound to the session key.
fn assert_refresh_dpop_proof(request: &wiremock::Request, issuer: &str, session: &DpopSigningHandle) {
    let proof = request
        .headers
        .get("dpop")
        .expect("refresh grant must carry a DPoP header")
        .to_str()
        .unwrap();
    let claims = decode_proof_segment(proof, 1);
    assert_eq!(claims["htm"], "POST");
    assert_eq!(claims["htu"], format!("{issuer}/oauth/token"));
    assert!(claims.get("ath").is_none(), "token-endpoint proof must not carry ath");
    let header_jkt = verify_proof_signature_and_header_jkt(proof);
    assert_eq!(header_jkt, session.jkt(), "refresh proof must use the same session key");
}

// ---------------------------------------------------------------------------
// Gate ① success rotation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_bundle_rotates_via_dpop_bound_refresh_grant_and_upstream_continues() {
    let acp = MockServer::start().await;
    let auth = MockServer::start().await;
    mount_schedule_upstream(&acp, "Bearer rotated-access").await;
    mount_token_endpoint(&auth, 200, rotated_token_response(), Duration::ZERO).await;

    let (app, ctx) = build_app(&acp, &auth, Duration::from_secs(2)).await;
    let receipt = sample_receipt();
    let local_token = bind_expiring_token(&ctx, "stale-access", Some("stale-refresh"), -1, Some(receipt.clone()));
    let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, USER_ID);
    let session_key = bound_session_key(&ctx, &local_token).expect("session DPoP key bound");

    let response = app.oneshot(get_schedules(&local_token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Token endpoint: exactly one request with the frozen form + proof.
    let token_requests = auth.received_requests().await.unwrap();
    assert_eq!(token_requests.len(), 1);
    assert_eq!(token_requests[0].url.path(), "/oauth/token");
    assert_refresh_form(&token_requests[0].body, "stale-refresh");
    assert_refresh_dpop_proof(&token_requests[0], &auth.uri(), &session_key);

    // Vault bundle atomically updated: rotated secrets, preserved receipt.
    let bundle = ctx.vault.get(&vault_key).expect("bundle present after refresh");
    assert_eq!(bundle.access_token.expose(), "rotated-access");
    assert_eq!(
        bundle.refresh_token.as_ref().map(|s| s.expose()),
        Some("rotated-refresh")
    );
    let now = now_ms();
    assert!(
        bundle
            .expires_at_ms
            .is_some_and(|expires_at| expires_at > now + 3500 * 1000),
        "expires_at_ms must be recomputed from the new expires_in: {:?}",
        bundle.expires_at_ms
    );
    assert_eq!(bundle.device_registration, Some(receipt));

    // This upstream call continued with the new token and a resource-side
    // proof bound to it.
    let upstream = acp.received_requests().await.unwrap();
    assert_eq!(upstream.len(), 1);
    let authorization = upstream[0].headers.get("authorization").unwrap().to_str().unwrap();
    assert_eq!(authorization, "Bearer rotated-access");
    let proof = upstream[0].headers.get("dpop").unwrap().to_str().unwrap();
    let claims = decode_proof_segment(proof, 1);
    assert_eq!(claims["ath"], dpop_ath("rotated-access"));
    assert_eq!(claims["htu"], format!("{}/api/schedule/v1/schedules", acp.uri()));
    verify_proof_signature_and_header_jkt(proof);
}

// ---------------------------------------------------------------------------
// Gate ② rotation contract: auth-center always rotates → always replaced
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_response_omitting_refresh_token_keeps_the_previous_one() {
    let acp = MockServer::start().await;
    let auth = MockServer::start().await;
    mount_schedule_upstream(&acp, "Bearer rotated-access").await;
    mount_token_endpoint(
        &auth,
        200,
        json!({"access_token": "rotated-access", "token_type": "Bearer", "expires_in": 3600}),
        Duration::ZERO,
    )
    .await;

    let (app, ctx) = build_app(&acp, &auth, Duration::from_secs(2)).await;
    let local_token = bind_expiring_token(&ctx, "stale-access", Some("stale-refresh"), -1, None);
    let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, USER_ID);

    let response = app.oneshot(get_schedules(&local_token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bundle = ctx.vault.get(&vault_key).expect("bundle present after refresh");
    assert_eq!(bundle.access_token.expose(), "rotated-access");
    assert_eq!(
        bundle.refresh_token.as_ref().map(|s| s.expose()),
        Some("stale-refresh"),
        "an omitted refresh_token means 'keep the current one' (RFC 6749 §6)"
    );
}

// ---------------------------------------------------------------------------
// Gate ③ invalid grant → vault + key cleared + session required
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_invalid_grant_evicts_the_session_without_upstream_io() {
    let acp = MockServer::start().await;
    let auth = MockServer::start().await;
    mount_token_endpoint(&auth, 400, json!({"error": "invalid_grant"}), Duration::ZERO).await;

    let (app, ctx) = build_app(&acp, &auth, Duration::from_secs(2)).await;
    let local_token = bind_expiring_token(&ctx, "stale-access", Some("stale-refresh"), -1, None);
    let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, USER_ID);

    let response = app.oneshot(get_schedules(&local_token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(response).await;
    assert_eq!(body["code"], "AUTH_CENTER_SESSION_REQUIRED");
    assert!(ctx.vault.get(&vault_key).is_none(), "vault bundle must be cleared");
    assert!(
        bound_session_key(&ctx, &local_token).is_none(),
        "session DPoP key must be cleared"
    );
    // Exactly one grant attempt — never retried.
    assert_eq!(auth.received_requests().await.unwrap().len(), 1);
    assert!(acp.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn refresh_unauthorized_and_expired_refresh_shapes_also_evict() {
    for error in ["invalid_refresh_token", "expired_refresh_token", "user_disabled"] {
        let acp = MockServer::start().await;
        let auth = MockServer::start().await;
        let status = if *error == *"user_disabled" { 401 } else { 400 };
        mount_token_endpoint(&auth, status, json!({"error": error}), Duration::ZERO).await;
        let (app, ctx) = build_app(&acp, &auth, Duration::from_secs(2)).await;
        let local_token = bind_expiring_token(&ctx, "stale-access", Some("stale-refresh"), -1, None);
        let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, USER_ID);

        let response = app.oneshot(get_schedules(&local_token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "error: {error}");
        assert_eq!(json_body(response).await["code"], "AUTH_CENTER_SESSION_REQUIRED");
        assert!(ctx.vault.get(&vault_key).is_none(), "error: {error}");
        assert!(bound_session_key(&ctx, &local_token).is_none(), "error: {error}");
        assert!(acp.received_requests().await.unwrap().is_empty(), "error: {error}");
    }
}

// ---------------------------------------------------------------------------
// Gate ④ concurrent requests single-flight the refresh grant
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_expiring_requests_hit_the_token_endpoint_exactly_once() {
    let acp = MockServer::start().await;
    let auth = MockServer::start().await;
    mount_schedule_upstream(&acp, "Bearer rotated-access").await;
    // A wide delay keeps the first refresh in flight while the second request
    // queues on the single-flight slot.
    mount_token_endpoint(&auth, 200, rotated_token_response(), Duration::from_millis(200)).await;

    let (app, ctx) = build_app(&acp, &auth, Duration::from_secs(5)).await;
    let local_token = Arc::new(bind_expiring_token(
        &ctx,
        "stale-access",
        Some("stale-refresh"),
        -1,
        None,
    ));

    let (first, second) = {
        let app = app.clone();
        let token = Arc::clone(&local_token);
        let app2 = app.clone();
        let token2 = Arc::clone(&local_token);
        tokio::join!(
            async move { app.oneshot(get_schedules(&token)).await.unwrap() },
            async move { app2.oneshot(get_schedules(&token2)).await.unwrap() }
        )
    };
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);

    // Both upstream calls used the rotated token.
    let upstream = acp.received_requests().await.unwrap();
    assert_eq!(upstream.len(), 2);
    for request in &upstream {
        assert_eq!(
            request.headers.get("authorization").unwrap().to_str().unwrap(),
            "Bearer rotated-access"
        );
    }

    // The token endpoint saw exactly one grant: the second request reused the
    // winner's fresh bundle instead of presenting the consumed token.
    let token_requests = auth.received_requests().await.unwrap();
    assert_eq!(token_requests.len(), 1, "single-flight must dedup the refresh grant");
    assert_refresh_form(&token_requests[0].body, "stale-refresh");
}

// ---------------------------------------------------------------------------
// Gate ⑤ refresh failure does not retry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_error_response_is_never_retried_and_evicts_the_session() {
    let acp = MockServer::start().await;
    let auth = MockServer::start().await;
    // No /oauth/token mock mounted: the server answers 404 → terminal failure.
    let (app, ctx) = build_app(&acp, &auth, Duration::from_secs(2)).await;
    let local_token = bind_expiring_token(&ctx, "stale-access", Some("stale-refresh"), -1, None);
    let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, USER_ID);

    let response = app.oneshot(get_schedules(&local_token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["code"], "AUTH_CENTER_SESSION_REQUIRED");
    // 计数 = 1: the request was sent once, and no retry ever fired.
    assert_eq!(auth.received_requests().await.unwrap().len(), 1);
    assert!(ctx.vault.get(&vault_key).is_none());
    assert!(bound_session_key(&ctx, &local_token).is_none());
    assert!(acp.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn refresh_timeout_is_terminal_and_evicts_the_session() {
    let acp = MockServer::start().await;
    let auth = MockServer::start().await;
    // The token response arrives long after the BFF refresh timeout.
    mount_token_endpoint(&auth, 200, rotated_token_response(), Duration::from_millis(500)).await;

    let (app, ctx) = build_app(&acp, &auth, Duration::from_millis(50)).await;
    let local_token = bind_expiring_token(&ctx, "stale-access", Some("stale-refresh"), -1, None);
    let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, USER_ID);

    let response = app.oneshot(get_schedules(&local_token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["code"], "AUTH_CENTER_SESSION_REQUIRED");
    assert!(ctx.vault.get(&vault_key).is_none(), "ambiguous timeout must evict");
    assert!(bound_session_key(&ctx, &local_token).is_none());
    assert!(acp.received_requests().await.unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Gate ⑥ no refresh token → pre-existing eviction semantics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_bundle_without_refresh_token_keeps_the_original_eviction_semantics() {
    let acp = MockServer::start().await;
    let auth = MockServer::start().await;
    let (app, ctx) = build_app(&acp, &auth, Duration::from_secs(2)).await;
    let local_token = bind_expiring_token(&ctx, "stale-access", None, -1, None);
    let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, USER_ID);

    let response = app.oneshot(get_schedules(&local_token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["code"], "AUTH_CENTER_SESSION_REQUIRED");
    assert!(ctx.vault.get(&vault_key).is_none());
    assert!(bound_session_key(&ctx, &local_token).is_none());
    assert!(auth.received_requests().await.unwrap().is_empty());
    assert!(acp.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn expiring_bundle_without_refresh_token_but_not_expired_still_proceeds() {
    let acp = MockServer::start().await;
    let auth = MockServer::start().await;
    mount_schedule_upstream(&acp, "Bearer stale-access").await;
    let (app, ctx) = build_app(&acp, &auth, Duration::from_secs(2)).await;
    // 10 seconds of life: inside the proactive refresh window, but strictly
    // unexpired — without a refresh token the original semantics keep it.
    let local_token = bind_expiring_token(&ctx, "stale-access", None, 10, None);

    let response = app.oneshot(get_schedules(&local_token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(auth.received_requests().await.unwrap().is_empty());
    let upstream = acp.received_requests().await.unwrap();
    assert_eq!(upstream.len(), 1);
    assert_eq!(
        upstream[0].headers.get("authorization").unwrap().to_str().unwrap(),
        "Bearer stale-access"
    );
}

// ---------------------------------------------------------------------------
// Gate ⑦ unexpired bundle → no refresh (regression)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unexpired_bundle_does_not_touch_the_token_endpoint() {
    let acp = MockServer::start().await;
    let auth = MockServer::start().await;
    mount_schedule_upstream(&acp, "Bearer fresh-access").await;
    let (app, ctx) = build_app(&acp, &auth, Duration::from_secs(2)).await;
    let local_token = bind_expiring_token(&ctx, "fresh-access", Some("fresh-refresh"), 3600, None);
    let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, USER_ID);

    let response = app.oneshot(get_schedules(&local_token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(auth.received_requests().await.unwrap().is_empty());
    let bundle = ctx.vault.get(&vault_key).expect("bundle untouched");
    assert_eq!(bundle.access_token.expose(), "fresh-access");
    assert_eq!(bundle.refresh_token.as_ref().map(|s| s.expose()), Some("fresh-refresh"));
    let upstream = acp.received_requests().await.unwrap();
    assert_eq!(
        upstream[0].headers.get("authorization").unwrap().to_str().unwrap(),
        "Bearer fresh-access"
    );
}

// ---------------------------------------------------------------------------
// Fail-closed: no DPoP key → no refresh request, eviction
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_fails_closed_without_dpop_key_and_without_token_endpoint_io() {
    let acp = MockServer::start().await;
    let auth = MockServer::start().await;
    let (app, ctx) = build_app(&acp, &auth, Duration::from_secs(2)).await;
    // Bind the bundle WITHOUT a DPoP key (simulates a lost key binding).
    let local_token = ctx.jwt_service.sign_auth_center_bound(USER_ID, "admin", 0).unwrap();
    let mut bundle = bundle_from_token_response(
        AuthCenterTokenResponse {
            access_token: "stale-access".to_owned(),
            refresh_token: Some("stale-refresh".to_owned()),
            id_token: None,
            token_type: Some("Bearer".to_owned()),
            scope: None,
            expires_in: Some(-1),
        },
        now_ms(),
    );
    bundle.device_registration = None;
    ctx.vault
        .store(AuthCenterTokenVaultKey::from_token(&local_token, USER_ID), bundle);

    let response = app.oneshot(get_schedules(&local_token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["code"], "AUTH_CENTER_SESSION_REQUIRED");
    assert!(
        auth.received_requests().await.unwrap().is_empty(),
        "fail-closed: no bare Bearer refresh"
    );
    assert!(
        ctx.vault
            .get(&AuthCenterTokenVaultKey::from_token(&local_token, USER_ID))
            .is_none()
    );
    assert!(acp.received_requests().await.unwrap().is_empty());
}

/// Sanity guard for the helper: a missing DPoP key store yields the expected
/// error shape used by the fail-closed path above.
#[allow(dead_code)]
fn dpop_store_error_shape(error: DpopError) -> bool {
    matches!(error, DpopError::StoreUnavailable)
}
