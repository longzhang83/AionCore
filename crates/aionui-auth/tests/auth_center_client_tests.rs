use axum::http::HeaderMap;
use reqwest::Url;
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aionui_auth::{AuthCenterProtocolClient, RsmAuthConfig, RsmOidcLoginQuery, RsmOidcStateStore};

fn directory_config(base_url: String) -> RsmAuthConfig {
    RsmAuthConfig {
        enabled: true,
        issuer: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
        additional_scopes: Vec::new(),
        app_code: "agent".to_owned(),
        internal_base_url: Some(base_url),
        internal_token: Some("internal-secret".to_owned()),
    }
}

#[tokio::test]
async fn oidc_login_appends_configured_scopes_without_dropping_identity_scopes() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": mock_server.uri(),
            "authorization_endpoint": format!("{}/oauth/authorize", mock_server.uri()),
            "token_endpoint": format!("{}/oauth/token", mock_server.uri()),
            "userinfo_endpoint": format!("{}/oauth/userinfo", mock_server.uri()),
            "jwks_uri": format!("{}/.well-known/jwks.json", mock_server.uri())
        })))
        .mount(&mock_server)
        .await;

    let config = RsmAuthConfig {
        enabled: true,
        issuer: Some(mock_server.uri()),
        client_id: Some("agent-control-plane".to_owned()),
        client_secret: Some("server-side-secret".to_owned()),
        redirect_uri: Some("http://localhost:25808/api/auth/oidc/callback".to_owned()),
        additional_scopes: vec![
            "offline_access".to_owned(),
            "schedule:schedules:read".to_owned(),
            "schedule:schedules:write".to_owned(),
            "schedule:runs:read".to_owned(),
            "openid".to_owned(),
        ],
        app_code: "agent".to_owned(),
        internal_base_url: None,
        internal_token: None,
    };

    let redirect = AuthCenterProtocolClient::new(reqwest::Client::new())
        .build_login_redirect(
            &config,
            &RsmOidcStateStore::new(),
            &HeaderMap::new(),
            RsmOidcLoginQuery { return_to: None },
        )
        .await
        .unwrap();
    let redirect = Url::parse(&redirect).unwrap();
    let scope = redirect
        .query_pairs()
        .find(|(key, _)| key == "scope")
        .unwrap()
        .1
        .into_owned();

    assert_eq!(
        scope,
        "openid profile email offline_access schedule:schedules:read schedule:schedules:write schedule:runs:read"
    );
}

#[tokio::test]
async fn directory_users_send_bearer_since_and_parse_raw_array() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/internal/directory/apps/agent/users"))
        .and(header("Authorization", "Bearer internal-secret"))
        .and(query_param("since", "1970-01-01T00:00:01Z"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "id": "user-1",
                "username": "alice",
                "displayName": "Alice",
                "departments": ["dept-1"],
                "updatedAt": "2026-06-15T00:00:00Z"
            }
        ])))
        .mount(&mock_server)
        .await;

    let client = AuthCenterProtocolClient::new(reqwest::Client::new());
    let users = client
        .list_directory_users(&directory_config(mock_server.uri()), Some(1000))
        .await
        .unwrap();

    assert_eq!(users.len(), 1);
    assert_eq!(users[0].id, "user-1");
    assert_eq!(users[0].display_name.as_deref(), Some("Alice"));
    assert_eq!(users[0].departments, vec!["dept-1"]);
}

#[tokio::test]
async fn directory_users_parse_users_envelope() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/internal/directory/apps/agent/users"))
        .and(header("Authorization", "Bearer internal-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "users": [
                {
                    "id": "user-2",
                    "email": "bob@example.test",
                    "name": "Bob"
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let client = AuthCenterProtocolClient::new(reqwest::Client::new());
    let users = client
        .list_directory_users(&directory_config(mock_server.uri()), None)
        .await
        .unwrap();

    assert_eq!(users.len(), 1);
    assert_eq!(users[0].id, "user-2");
    assert_eq!(users[0].display_name.as_deref(), Some("Bob"));
    assert_eq!(users[0].email.as_deref(), Some("bob@example.test"));
}

#[tokio::test]
async fn directory_departments_parse_departments_envelope() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/internal/directory/apps/agent/departments"))
        .and(header("Authorization", "Bearer internal-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "departments": [
                {
                    "id": "dept-1",
                    "parentId": "root",
                    "name": "Finance",
                    "sort": 10,
                    "status": "enabled"
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let client = AuthCenterProtocolClient::new(reqwest::Client::new());
    let departments = client
        .list_directory_departments(&directory_config(mock_server.uri()), None)
        .await
        .unwrap();

    assert_eq!(departments.len(), 1);
    assert_eq!(departments[0].id, "dept-1");
    assert_eq!(departments[0].parent_id.as_deref(), Some("root"));
    assert_eq!(departments[0].name, "Finance");
    assert_eq!(departments[0].sort, 10);
}

#[tokio::test]
async fn directory_departments_parse_list_envelope() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/internal/directory/apps/agent/departments"))
        .and(header("Authorization", "Bearer internal-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "list": [
                {
                    "id": "dept-2",
                    "parent_id": "dept-1",
                    "name": "Tax"
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let client = AuthCenterProtocolClient::new(reqwest::Client::new());
    let departments = client
        .list_directory_departments(&directory_config(mock_server.uri()), None)
        .await
        .unwrap();

    assert_eq!(departments.len(), 1);
    assert_eq!(departments[0].id, "dept-2");
    assert_eq!(departments[0].parent_id.as_deref(), Some("dept-1"));
}

// ---------------------------------------------------------------------------
// DPoP (RFC 9449) proof on the OIDC token endpoint exchange
// ---------------------------------------------------------------------------

use base64::Engine as _;
use p256::ecdsa::signature::Verifier;
use serde_json::Value;

use aionui_auth::{DpopError, DpopPublicJwk, IDpopKeyStore, InMemoryDpopKeyStore, jwk_thumbprint};

fn decode_proof_segment(proof: &str, index: usize) -> Value {
    let segment = proof.split('.').nth(index).expect("DPoP proof has three segments");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .expect("DPoP proof segment is base64url");
    serde_json::from_slice(&bytes).expect("DPoP proof segment is JSON")
}

/// Rebuild an ES256 signature from the raw 64-byte r||s encoding.
fn signature_from_r_s(raw: &[u8]) -> p256::ecdsa::Signature {
    use p256::elliptic_curve::FieldBytes;
    let (r, s) = raw.split_at(32);
    p256::ecdsa::Signature::from_scalars(
        *FieldBytes::<p256::NistP256>::from_slice(r),
        *FieldBytes::<p256::NistP256>::from_slice(s),
    )
    .expect("64 raw bytes are always a valid r||s pair")
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
    let signature = signature_from_r_s(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segments[2])
            .unwrap(),
    );
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

async fn login_redirect_state(
    client: &AuthCenterProtocolClient,
    config: &RsmAuthConfig,
) -> (RsmOidcStateStore, String) {
    // The state store is in-memory: the SAME instance that issued the login
    // redirect must back exchange_callback's consume(state).
    let store = RsmOidcStateStore::new();
    let redirect = client
        .build_login_redirect(config, &store, &HeaderMap::new(), RsmOidcLoginQuery { return_to: None })
        .await
        .unwrap();
    let redirect = Url::parse(&redirect).unwrap();
    let state = redirect
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    (store, state)
}

#[tokio::test]
async fn oidc_callback_sends_dpop_token_endpoint_proof() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    // Token endpoint answers a bare access-token response with NO id_token:
    // the callback must fail AFTER the POST was captured, letting us assert
    // the DPoP proof on the wire without needing a real OIDC id_token.
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "captured-access-token",
            "token_type": "DPoP",
            "expires_in": 3600
        })))
        .mount(&mock_server)
        .await;
    // Device enrollment fires right after the successful token exchange, so
    // it must be mocked or the callback would fail closed before reaching
    // the (still failing) id_token validation this test pins down.
    Mock::given(method("POST"))
        .and(path("/api/auth-center/v1/devices"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "device_id": "00000000-0000-4000-8000-000000000000",
            "status": "active",
            "binding_version": 1,
            "authority_epoch": 1,
            "registered_at": "2026-09-12T00:00:00Z",
            "updated_at": "2026-09-12T00:00:00Z"
        })))
        .mount(&mock_server)
        .await;

    let config = oidc_config(mock_server.uri());
    let client = AuthCenterProtocolClient::new(reqwest::Client::new());
    let (state_store, state) = login_redirect_state(&client, &config).await;

    let store = InMemoryDpopKeyStore::new();
    let error = client
        .exchange_callback(
            &config,
            &state_store,
            &store,
            aionui_auth::RsmOidcCallbackQuery {
                code: Some("auth-code".to_owned()),
                state: Some(state),
                error: None,
                error_description: None,
            },
        )
        .await
        .expect_err("token response without id_token must fail identity extraction");
    assert!(
        error.to_string().contains("id_token"),
        "failure must come from missing id_token (after the token POST), got: {error}"
    );

    // The proof traveled on the token endpoint POST.
    let received = mock_server.received_requests().await.unwrap();
    let token_post = received
        .iter()
        .find(|request| request.url.path() == "/oauth/token")
        .expect("token endpoint must have been called");
    let proof = token_post
        .headers
        .get("dpop")
        .expect("token endpoint request must carry a DPoP header")
        .to_str()
        .unwrap()
        .to_owned();

    // Header shape: dpop+jwt / ES256 with an EC P-256 JWK.
    let header = decode_proof_segment(&proof, 0);
    assert_eq!(header["typ"], "dpop+jwt");
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["jwk"]["kty"], "EC");
    assert_eq!(header["jwk"]["crv"], "P-256");
    assert_eq!(header["jwk"]["x"].as_str().unwrap().len(), 43);
    assert_eq!(header["jwk"]["y"].as_str().unwrap().len(), 43);

    // Token-endpoint proof claims (ProofProfileTokenEndpoint): htm/htu/iat/jti,
    // explicitly WITHOUT ath.
    let claims = decode_proof_segment(&proof, 1);
    assert_eq!(claims["htm"], "POST");
    assert_eq!(claims["htu"], format!("{}/oauth/token", mock_server.uri()));
    let iat = claims["iat"].as_i64().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!((iat - now).abs() <= 120, "iat must be within the freshness window");
    let jti = claims["jti"].as_str().unwrap();
    assert!(jti.len() >= 16, "jti must satisfy the receiver's minimum length");
    assert!(
        claims.get("ath").is_none(),
        "token-endpoint proof must NOT carry ath (proof.go ProofProfileTokenEndpoint)"
    );

    // The signature is ES256 and self-verifies against the header JWK.
    verify_proof_signature_and_header_jkt(&proof);
}

#[derive(Debug)]
struct FailingDpopKeyStore;

impl IDpopKeyStore for FailingDpopKeyStore {
    fn generate(&self) -> Result<aionui_auth::DpopSigningHandle, DpopError> {
        Err(DpopError::StoreUnavailable)
    }

    fn bind(&self, _: aionui_auth::DpopSigningHandle, _: &aionui_auth::DpopKeySelector) -> Result<(), DpopError> {
        Err(DpopError::StoreUnavailable)
    }

    fn get(&self, _: &aionui_auth::DpopKeySelector) -> Result<Option<aionui_auth::DpopSigningHandle>, DpopError> {
        Err(DpopError::StoreUnavailable)
    }

    fn move_key(&self, _: &aionui_auth::DpopKeySelector, _: &aionui_auth::DpopKeySelector) -> Result<bool, DpopError> {
        Err(DpopError::StoreUnavailable)
    }

    fn clear(&self, _: &aionui_auth::DpopKeySelector) -> Result<bool, DpopError> {
        Err(DpopError::StoreUnavailable)
    }

    fn clear_all_for_holder(&self, _: &str) -> Result<usize, DpopError> {
        Err(DpopError::StoreUnavailable)
    }
}

#[tokio::test]
async fn oidc_callback_fails_closed_when_dpop_key_store_is_unavailable() {
    let mock_server = MockServer::start().await;
    mount_discovery(&mock_server).await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "never-issued-access-token",
            "token_type": "DPoP",
            "expires_in": 3600
        })))
        .mount(&mock_server)
        .await;

    let config = oidc_config(mock_server.uri());
    let client = AuthCenterProtocolClient::new(reqwest::Client::new());
    let (state_store, state) = login_redirect_state(&client, &config).await;

    let error = client
        .exchange_callback(
            &config,
            &state_store,
            &FailingDpopKeyStore,
            aionui_auth::RsmOidcCallbackQuery {
                code: Some("auth-code".to_owned()),
                state: Some(state),
                error: None,
                error_description: None,
            },
        )
        .await
        .expect_err("unavailable key store must fail the callback");
    assert!(
        error.to_string().contains("DPoP key generation failed"),
        "error must name the DPoP key generation failure, got: {error}"
    );

    // Fail-closed: only discovery traffic hit the wire (build_login_redirect
    // and exchange_callback each perform one discovery GET); the token POST
    // (and therefore any unbound token issuance) never happened.
    let received = mock_server.received_requests().await.unwrap();
    assert!(
        received
            .iter()
            .all(|request| request.url.path() == "/.well-known/openid-configuration"),
        "no request other than discovery may reach the wire, got paths: {:?}",
        received.iter().map(|request| request.url.path()).collect::<Vec<_>>()
    );
}
