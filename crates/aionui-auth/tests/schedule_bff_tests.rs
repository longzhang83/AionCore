use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::matchers::{header as wiremock_header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aionui_auth::{
    AuthCenterTokenResponse, AuthCenterTokenVaultKey, AuthIdentityMode, AuthRouterState, CookieConfig,
    IAuthCenterTokenVault, InMemoryAuthCenterTokenVault, JwtService, QrTokenStore, RsmAuthConfig, RsmOidcStateStore,
    ScheduleBffConfig, auth_routes, bundle_from_token_response,
};
use aionui_db::{IIamRepository, IUserRepository, SqliteIamRepository, SqliteUserRepository, init_database_memory};

const USER_ID: &str = "system_default_user";

struct TestContext {
    jwt_service: Arc<JwtService>,
    vault: Arc<InMemoryAuthCenterTokenVault>,
    _db: aionui_db::Database,
}

async fn test_app(upstream: &MockServer, timeout: Duration) -> (Router, TestContext) {
    let db = init_database_memory().await.unwrap();
    let user_repo = Arc::new(SqliteUserRepository::new(db.pool().clone())) as Arc<dyn IUserRepository>;
    let iam_repo = Arc::new(SqliteIamRepository::new(db.pool().clone())) as Arc<dyn IIamRepository>;
    let jwt_service = Arc::new(JwtService::new("schedule_bff_test_secret".to_owned()));
    let vault = Arc::new(InMemoryAuthCenterTokenVault::new());
    let rsm_auth_config = RsmAuthConfig {
        enabled: true,
        issuer: Some("https://auth.example".to_owned()),
        client_id: Some("agent-control-plane".to_owned()),
        client_secret: None,
        redirect_uri: None,
        additional_scopes: Vec::new(),
        app_code: "agent".to_owned(),
        internal_base_url: None,
        internal_token: None,
    };
    let schedule_bff_config = ScheduleBffConfig::new_with_identity_contract(
        upstream.uri(),
        timeout,
        &rsm_auth_config,
        Some("agent-control-plane"),
    )
    .unwrap();
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
            _db: db,
        },
    )
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn bind_upstream_token(ctx: &TestContext, upstream_token: &str, expires_in: i64) -> String {
    let local_token = ctx.jwt_service.sign_auth_center_bound(USER_ID, "admin", 0).unwrap();
    let bundle = bundle_from_token_response(
        AuthCenterTokenResponse {
            access_token: upstream_token.to_owned(),
            refresh_token: Some("refresh-must-stay-server-side".to_owned()),
            id_token: Some("id-token-must-stay-server-side".to_owned()),
            token_type: Some("Bearer".to_owned()),
            scope: Some("schedule:read schedule:write".to_owned()),
            expires_in: Some(expires_in),
        },
        now_ms(),
    );
    ctx.vault
        .store(AuthCenterTokenVaultKey::from_token(&local_token, USER_ID), bundle);
    local_token
}

fn request(method: Method, uri: &str, local_token: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
        .body(body)
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn schedule_bff_preserves_query_json_and_contract_headers_but_strips_browser_credentials() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/schedule/v1/schedules"))
        .and(query_param("workspace_id", "workspace-1"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .and(wiremock_header("idempotency-key", "idem-1"))
        .and(wiremock_header("x-request-id", "request-1"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"schedule_id": "schedule-1"})))
        .mount(&upstream)
        .await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);

    let body = json!({"workspace_id": "workspace-1", "title": "nightly"}).to_string();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/schedule/v1/schedules?workspace_id=workspace-1")
        .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
        .header(header::COOKIE, "aionui-session=browser-cookie")
        .header("x-csrf-token", "browser-csrf")
        .header(header::ORIGIN, "https://browser.example")
        .header(header::REFERER, "https://browser.example/settings")
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", "idem-1")
        .header("x-request-id", "request-1")
        .body(Body::from(body.clone()))
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        json_body(response).await,
        json!({"success": true, "data": {"schedule_id": "schedule-1"}})
    );

    let received = upstream.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(String::from_utf8(received[0].body.clone()).unwrap(), body);
    for stripped in ["cookie", "x-csrf-token", "origin", "referer"] {
        assert!(
            received[0].headers.get(stripped).is_none(),
            "forwarded sensitive header: {stripped}"
        );
    }
    let authorization = received[0].headers.get("authorization").unwrap().to_str().unwrap();
    assert_eq!(authorization, "Bearer upstream-access");
    assert!(!authorization.contains(&local_token));
}

#[tokio::test]
async fn schedule_bff_keeps_concurrent_browser_sessions_token_isolated() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/schedule/v1/schedules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
        .expect(2)
        .mount(&upstream)
        .await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_a = bind_upstream_token(&ctx, "upstream-a", 3600);
    let local_b = bind_upstream_token(&ctx, "upstream-b", 3600);

    for token in [&local_a, &local_b] {
        let response = app
            .clone()
            .oneshot(request(Method::GET, "/api/schedule/v1/schedules", token, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let mut authorizations = upstream
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .map(|req| req.headers.get("authorization").unwrap().to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    authorizations.sort();
    assert_eq!(authorizations, ["Bearer upstream-a", "Bearer upstream-b"]);
}

#[tokio::test]
async fn schedule_bff_exposes_only_the_frozen_path_and_method_allowlist() {
    let upstream = MockServer::start().await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);

    let unsupported_path = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/schedule/v1/admin/secrets",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(unsupported_path.status(), StatusCode::NOT_FOUND);

    let unsupported_method = app
        .oneshot(request(
            Method::DELETE,
            "/api/schedule/v1/schedules/schedule-1",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(unsupported_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn version_create_bff_forwards_exact_agent_and_skill_requests() {
    let upstream = MockServer::start().await;
    for (asset_kind, asset_id, idempotency_key, request_id, body) in [
        (
            "agents",
            "agent-1",
            "agent-create-1",
            "agent-request-1",
            json!({"manifest": {"summary": "Agent summary", "system_prompt": "Review"}}),
        ),
        (
            "skills",
            "skill-1",
            "skill-create-1",
            "skill-request-1",
            json!({"manifest": {"summary": "Skill summary", "instructions": "Review"}}),
        ),
    ] {
        Mock::given(method("POST"))
            .and(path(format!("/api/version/v1/{asset_kind}/{asset_id}/versions")))
            .and(wiremock_header("authorization", "Bearer upstream-access"))
            .and(wiremock_header("content-type", "application/json"))
            .and(wiremock_header("idempotency-key", idempotency_key))
            .and(wiremock_header("x-request-id", request_id))
            .and(wiremock::matchers::body_json(body))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("idempotent-replay", "false")
                    .insert_header("x-request-id", format!("upstream-{request_id}"))
                    .set_body_json(json!({"version_id": format!("{asset_id}-version-1"), "state": "draft"})),
            )
            .mount(&upstream)
            .await;
    }
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);

    for (asset_kind, asset_id, idempotency_key, request_id, body) in [
        (
            "agents",
            "agent-1",
            "agent-create-1",
            "agent-request-1",
            json!({"manifest": {"summary": "Agent summary", "system_prompt": "Review"}}),
        ),
        (
            "skills",
            "skill-1",
            "skill-create-1",
            "skill-request-1",
            json!({"manifest": {"summary": "Skill summary", "instructions": "Review"}}),
        ),
    ] {
        let body = body.to_string();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/version/v1/{asset_kind}/{asset_id}/versions"))
                    .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, "aionui-session=browser-cookie")
                    .header("x-csrf-token", "browser-csrf")
                    .header(header::ORIGIN, "https://browser.example")
                    .header(header::REFERER, "https://browser.example/settings")
                    .header("x-not-allowed", "private-browser-value")
                    .header("idempotency-key", idempotency_key)
                    .header("x-request-id", request_id)
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED, "asset kind: {asset_kind}");
        assert_eq!(response.headers().get("idempotent-replay").unwrap(), "false");
        assert_eq!(
            response.headers().get("x-request-id").unwrap(),
            format!("upstream-{request_id}").as_str()
        );
        assert_eq!(json_body(response).await["data"]["state"], "draft");

        let received = upstream.received_requests().await.unwrap();
        let forwarded = received
            .iter()
            .find(|request| request.url.path() == format!("/api/version/v1/{asset_kind}/{asset_id}/versions"))
            .expect("version create request forwarded upstream");
        assert_eq!(String::from_utf8(forwarded.body.clone()).unwrap(), body);
        assert_eq!(
            forwarded.headers.get("idempotency-key").unwrap().to_str().unwrap(),
            idempotency_key
        );
        assert_eq!(
            forwarded.headers.get("x-request-id").unwrap().to_str().unwrap(),
            request_id
        );
        for stripped in ["cookie", "x-csrf-token", "origin", "referer", "x-not-allowed"] {
            assert!(
                forwarded.headers.get(stripped).is_none(),
                "forwarded sensitive header: {stripped}"
            );
        }
    }
}

#[tokio::test]
async fn version_create_bff_rejects_missing_headers_query_and_invalid_ids_without_upstream_io() {
    let upstream = MockServer::start().await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);

    let missing_key = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/version/v1/agents/agent-1/versions")
                .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_key.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(missing_key).await["code"], "VERSION_BAD_REQUEST");

    let missing_request_id = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/version/v1/skills/skill-1/versions")
                .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "skill-create-1")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_request_id.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(missing_request_id).await["code"], "VERSION_BAD_REQUEST");

    let query = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/version/v1/skills/skill-1/versions?organization_id=org-1")
                .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "skill-create-1")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(query.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(query).await["code"], "VERSION_BAD_REQUEST");

    for uri in [
        "/api/version/v1/agents/%E5%90%AB%E4%B8%AD%E6%96%87/versions",
        "/api/version/v1/skills/skill.invalid/versions",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "create-invalid")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "uri: {uri}");
        assert_eq!(json_body(response).await["code"], "VERSION_INVALID_ID", "uri: {uri}");
    }

    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn acp_read_bff_forwards_only_frozen_catalog_and_workspace_get_routes() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/team-workspace/v1/workspaces"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "workspace_id": "workspace-1",
            "type": "team",
            "organization_id": "org-1",
            "status": "active",
            "created_at": "2026-08-29T00:00:00Z",
            "updated_at": "2026-08-29T00:00:00Z"
        }])))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/catalog/v1/agents"))
        .and(query_param("page_size", "100"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{
                "agent_id": "agent-1",
                "name": "Finance reviewer",
                "latest_published_version_id": "version-1"
            }],
            "meta": {"page": 1, "page_size": 100, "total": 1}
        })))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/catalog/v1/agents/agent-1/versions/version-1"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version_id": "version-1",
            "agent_id": "agent-1",
            "state": "published",
            "manifest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })))
        .mount(&upstream)
        .await;

    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);

    let workspaces = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/team-workspace/v1/workspaces",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(workspaces.status(), StatusCode::OK);
    assert_eq!(json_body(workspaces).await["data"][0]["workspace_id"], "workspace-1");

    let agents = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/catalog/v1/agents?page_size=100",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(agents.status(), StatusCode::OK);
    assert_eq!(json_body(agents).await["data"]["items"][0]["agent_id"], "agent-1");

    let version = app
        .oneshot(request(
            Method::GET,
            "/api/catalog/v1/agents/agent-1/versions/version-1",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(version.status(), StatusCode::OK);
    assert_eq!(json_body(version).await["data"]["version_id"], "version-1");
    assert_eq!(upstream.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn acp_read_bff_rejects_unfrozen_queries_paths_and_methods_without_upstream_io() {
    let upstream = MockServer::start().await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);

    let missing_query = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/catalog/v1/agents",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(missing_query.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(missing_query).await["code"], "CATALOG_BAD_REQUEST");

    let unknown_query = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/catalog/v1/agents?include_secrets=true",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(unknown_query.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(unknown_query).await["code"], "CATALOG_BAD_REQUEST");

    for query in [
        "page_size=99",
        "page_size=100&page_size=100",
        "visibility=team",
        "organization_id=org-1",
        "owner_user_id=user-1",
        "tag=finance",
        "q=reviewer",
    ] {
        let response = app
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/api/catalog/v1/agents?{query}"),
                &local_token,
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "query: {query}");
        assert_eq!(json_body(response).await["code"], "CATALOG_BAD_REQUEST");
    }

    let item_query = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/catalog/v1/agents/agent-1/versions/version-1?expand=secret",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(item_query.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(item_query).await["code"], "CATALOG_BAD_REQUEST");

    let workspace_query = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/team-workspace/v1/workspaces?all_tenants=true",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(workspace_query.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(workspace_query).await["code"], "WORKSPACE_BAD_REQUEST");

    let unsafe_id = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/catalog/v1/agents/agent%2Fadmin/versions/version-1",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        unsafe_id.status(),
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND
    ));

    let write = app
        .oneshot(request(
            Method::POST,
            "/api/catalog/v1/agents?page_size=100",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(write.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn acp_read_bff_maps_catalog_and_workspace_errors_without_leaking_upstream_messages() {
    let cases = [
        (
            "/api/catalog/v1/agents?page_size=100",
            403,
            json!({"code": "catalog_forbidden", "message": "private catalog details"}),
            "CATALOG_FORBIDDEN",
        ),
        (
            "/api/team-workspace/v1/workspaces",
            404,
            json!({"code": "workspace_not_found", "message": "private tenant details"}),
            "WORKSPACE_NOT_FOUND",
        ),
    ];

    for (bff_path, upstream_status, upstream_body, expected_code) in cases {
        let upstream = MockServer::start().await;
        let upstream_path = bff_path.split('?').next().expect("path is present");
        let mock = Mock::given(method("GET")).and(path(upstream_path));
        let mock = if bff_path.contains("page_size=100") {
            mock.and(query_param("page_size", "100"))
        } else {
            mock
        };
        mock.respond_with(ResponseTemplate::new(upstream_status).set_body_json(upstream_body))
            .mount(&upstream)
            .await;
        let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
        let local_token = bind_upstream_token(&ctx, "upstream-secret", 3600);
        let response = app
            .oneshot(request(Method::GET, bff_path, &local_token, Body::empty()))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!(body["code"], expected_code);
        let rendered = body.to_string();
        assert!(!rendered.contains("private catalog details"));
        assert!(!rendered.contains("private tenant details"));
        assert!(!rendered.contains("upstream-secret"));
    }
}

#[tokio::test]
async fn acp_read_bff_upstream_unauthorized_does_not_destroy_the_local_token_bundle() {
    for (path, upstream_body) in [
        (
            "/api/catalog/v1/agents?page_size=100",
            json!({"code": "unauthorized", "message": "private audience details"}),
        ),
        (
            "/api/team-workspace/v1/workspaces",
            json!({"code": "device_unbound", "message": "private device details"}),
        ),
    ] {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401).set_body_json(upstream_body))
            .mount(&upstream)
            .await;
        let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
        let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);
        let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, USER_ID);

        let response = app
            .oneshot(request(Method::GET, path, &local_token, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = json_body(response).await;
        assert!(matches!(
            body["code"].as_str(),
            Some("AUTH_CENTER_SESSION_REQUIRED" | "device_unbound")
        ));
        assert!(ctx.vault.get(&vault_key).is_some(), "path: {path}");
    }
}

#[tokio::test]
async fn schedule_bff_rejects_encoded_dot_segments_and_slashes_before_upstream_url_construction() {
    let upstream = MockServer::start().await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);

    for uri in [
        "/api/schedule/v1/schedules/%2e%2e",
        "/api/schedule/v1/schedules/schedule%2Fadmin",
        "/api/schedule/v1/schedules/schedule-1/runs/%2e%2e",
        "/api/schedule/v1/schedules/schedule-1/runs/run%2Fsecret",
    ] {
        let response = app
            .clone()
            .oneshot(request(Method::GET, uri, &local_token, Body::empty()))
            .await
            .unwrap();
        assert!(
            matches!(response.status(), StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND),
            "unexpected traversal response for {uri}: {}",
            response.status()
        );
    }
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn schedule_bff_missing_or_expired_bundle_fails_closed_without_upstream_request() {
    let upstream = MockServer::start().await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let missing = ctx.jwt_service.sign_auth_center_bound(USER_ID, "admin", 0).unwrap();
    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/schedule/v1/schedules",
            &missing,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["code"], "AUTH_CENTER_SESSION_REQUIRED");

    let expired = bind_upstream_token(&ctx, "expired-upstream", -1);
    let expired_key = AuthCenterTokenVaultKey::from_token(&expired, USER_ID);
    let response = app
        .oneshot(request(
            Method::GET,
            "/api/schedule/v1/schedules",
            &expired,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["code"], "AUTH_CENTER_SESSION_REQUIRED");
    assert!(ctx.vault.get(&expired_key).is_none());
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn schedule_bff_maps_upstream_identity_permission_conflict_and_server_errors_safely() {
    let cases = [
        (
            401,
            json!({"code": "device_unbound", "message": "Bind this device", "request_id": "rid-1"}),
            401,
            "device_unbound",
        ),
        (
            401,
            json!({"debug": "raw-token upstream-secret"}),
            401,
            "AUTH_CENTER_SESSION_REQUIRED",
        ),
        (
            403,
            json!({"code": "schedule_forbidden", "message": "private tenant details"}),
            403,
            "SCHEDULE_FORBIDDEN",
        ),
        (
            409,
            json!({"code": "schedule_local_job_conflict", "message": "private conflict details"}),
            409,
            "SCHEDULE_CONFLICT",
        ),
        (
            500,
            json!({"error": "database DSN and upstream-secret"}),
            502,
            "SCHEDULE_UPSTREAM_UNAVAILABLE",
        ),
    ];

    for (upstream_status, upstream_body, expected_status, expected_code) in cases {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/schedule/v1/schedules"))
            .respond_with(ResponseTemplate::new(upstream_status).set_body_json(upstream_body))
            .mount(&upstream)
            .await;
        let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
        let local_token = bind_upstream_token(&ctx, "upstream-secret", 3600);
        let response = app
            .oneshot(request(
                Method::GET,
                "/api/schedule/v1/schedules",
                &local_token,
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), expected_status);
        let body = json_body(response).await;
        assert_eq!(body["success"], false);
        assert_eq!(body["code"], expected_code);
        let rendered = body.to_string();
        assert!(!rendered.contains("upstream-secret"));
        assert!(!rendered.contains("private tenant details"));
        assert!(!rendered.contains("private conflict details"));
        assert!(!rendered.contains("database DSN"));
    }
}

#[tokio::test]
async fn schedule_bff_timeout_returns_stable_gateway_timeout_without_leaking_details() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/schedule/v1/schedules"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(json!({"items": []})),
        )
        .mount(&upstream)
        .await;
    let (app, ctx) = test_app(&upstream, Duration::from_millis(20)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);

    let response = app
        .oneshot(request(
            Method::GET,
            "/api/schedule/v1/schedules",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    let body = json_body(response).await;
    assert_eq!(body["code"], "SCHEDULE_UPSTREAM_TIMEOUT");
    assert!(!body.to_string().contains("upstream-access"));
}

#[tokio::test]
async fn schedule_bff_rejects_oversized_upstream_response_before_exposing_or_parsing_it() {
    let upstream = MockServer::start().await;
    let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
    Mock::given(method("GET"))
        .and(path("/api/schedule/v1/schedules"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(oversized))
        .mount(&upstream)
        .await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);

    let response = app
        .oneshot(request(
            Method::GET,
            "/api/schedule/v1/schedules",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = json_body(response).await;
    assert_eq!(body["code"], "SCHEDULE_UPSTREAM_INVALID_RESPONSE");
    assert!(!body.to_string().contains("upstream-access"));
}

#[tokio::test]
async fn acp_read_bff_forwards_skill_list_and_version_with_browser_credentials_stripped() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/catalog/v1/skills"))
        .and(query_param("page_size", "100"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{"skill_id": "skill-1", "name": "Code review"}],
            "meta": {"page": 1, "page_size": 100, "total": 1}
        })))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/catalog/v1/skills/skill-1/versions/version-1"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "skill_id": "skill-1",
            "version_id": "version-1",
            "state": "published",
            "manifest_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        })))
        .mount(&upstream)
        .await;

    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);

    let list = Request::builder()
        .method(Method::GET)
        .uri("/api/catalog/v1/skills?page_size=100")
        .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
        .header(header::COOKIE, "aionui-session=browser-cookie")
        .header("x-csrf-token", "browser-csrf")
        .header(header::ORIGIN, "https://browser.example")
        .header(header::REFERER, "https://browser.example/catalog")
        .body(Body::empty())
        .unwrap();
    let list = app.clone().oneshot(list).await.unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    assert_eq!(json_body(list).await["data"]["items"][0]["skill_id"], "skill-1");

    let version = Request::builder()
        .method(Method::GET)
        .uri("/api/catalog/v1/skills/skill-1/versions/version-1")
        .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
        .header(header::COOKIE, "aionui-session=browser-cookie")
        .header("x-csrf-token", "browser-csrf")
        .header(header::ORIGIN, "https://browser.example")
        .header(header::REFERER, "https://browser.example/catalog")
        .body(Body::empty())
        .unwrap();
    let version = app.oneshot(version).await.unwrap();
    assert_eq!(version.status(), StatusCode::OK);
    assert_eq!(json_body(version).await["data"]["version_id"], "version-1");

    let received = upstream.received_requests().await.unwrap();
    assert_eq!(received.len(), 2);
    for request in &received {
        let authorization = request.headers.get("authorization").unwrap().to_str().unwrap();
        assert_eq!(authorization, "Bearer upstream-access");
        assert!(!authorization.contains(&local_token));
        for stripped in ["cookie", "x-csrf-token", "origin", "referer"] {
            assert!(
                request.headers.get(stripped).is_none(),
                "forwarded sensitive header: {stripped}"
            );
        }
    }
}

#[tokio::test]
async fn acp_read_bff_skill_query_allowlist_accepts_only_exact_present_page_size_100() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/catalog/v1/skills"))
        .and(query_param("page_size", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": [], "meta": {"total": 0}})))
        .mount(&upstream)
        .await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);

    for uri in [
        "/api/catalog/v1/skills",
        "/api/catalog/v1/skills?page_size=100&page_size=100",
        "/api/catalog/v1/skills?page_size=99",
        "/api/catalog/v1/skills?page_size=1000",
        "/api/catalog/v1/skills?visibility=team",
        "/api/catalog/v1/skills?page_size=100&expand=manifest",
        "/api/catalog/v1/skills?owner_user_id=user-1",
        "/api/catalog/v1/skills?q=review",
    ] {
        let response = app
            .clone()
            .oneshot(request(Method::GET, uri, &local_token, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "uri: {uri}");
        assert_eq!(json_body(response).await["code"], "CATALOG_BAD_REQUEST", "uri: {uri}");
    }

    let version_query = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/catalog/v1/skills/skill-1/versions/version-1?expand=manifest",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(version_query.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(version_query).await["code"], "CATALOG_BAD_REQUEST");
}

#[tokio::test]
async fn acp_read_bff_skills_reject_invalid_ids_and_non_get_methods_without_upstream_io() {
    let upstream = MockServer::start().await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);

    for uri in [
        "/api/catalog/v1/skills/%E5%90%AB%E4%B8%AD%E6%96%87/versions/version-1",
        "/api/catalog/v1/skills/skill-1/versions/ver.sion%21",
    ] {
        let response = app
            .clone()
            .oneshot(request(Method::GET, uri, &local_token, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "uri: {uri}");
        assert_eq!(json_body(response).await["code"], "CATALOG_INVALID_ID", "uri: {uri}");
    }

    let encoded_slash = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/catalog/v1/skills/skill%2Fadmin/versions/version-1",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert!(
        matches!(encoded_slash.status(), StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND),
        "encoded slash status: {}",
        encoded_slash.status()
    );

    let write = app
        .oneshot(request(
            Method::POST,
            "/api/catalog/v1/skills?page_size=100",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(write.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn acp_read_bff_skills_require_an_auth_center_bound_session() {
    let upstream = MockServer::start().await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;

    let no_token = Request::builder()
        .method(Method::GET)
        .uri("/api/catalog/v1/skills?page_size=100")
        .body(Body::empty())
        .unwrap();
    let no_token = app.clone().oneshot(no_token).await.unwrap();
    assert_eq!(no_token.status(), StatusCode::UNAUTHORIZED);

    let local_only = ctx.jwt_service.sign_auth_center_bound(USER_ID, "admin", 0).unwrap();
    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/catalog/v1/skills?page_size=100",
            &local_only,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response).await["code"], "AUTH_CENTER_SESSION_REQUIRED");
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn acp_read_bff_skill_upstream_unauthorized_preserves_the_local_token_bundle() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/catalog/v1/skills"))
        .and(query_param("page_size", "100"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "code": "unauthorized",
            "message": "private audience details"
        })))
        .mount(&upstream)
        .await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);
    let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, USER_ID);

    let response = app
        .oneshot(request(
            Method::GET,
            "/api/catalog/v1/skills?page_size=100",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(response).await;
    assert_eq!(body["code"], "AUTH_CENTER_SESSION_REQUIRED");
    assert!(!body.to_string().contains("private audience details"));
    assert!(!body.to_string().contains("upstream-access"));
    assert!(ctx.vault.get(&vault_key).is_some());
}

#[tokio::test]
async fn share_bff_forwards_only_the_frozen_create_contract_and_strips_browser_credentials() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/share/v1/shares"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .and(wiremock_header("idempotency-key", "share-intent-1"))
        .and(wiremock_header("x-request-id", "share-request-1"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("idempotent-replay", "true")
                .insert_header("x-request-id", "upstream-share-request-1")
                .set_body_json(json!({"share_id": "share-1", "state": "active"})),
        )
        .mount(&upstream)
        .await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);
    let body = json!({
        "asset_kind": "agent",
        "asset_id": "agent-1",
        "asset_version_id": "version-1",
        "asset_version_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "target_workspace_id": "workspace-1",
        "scope": {"kind": "workspace", "values": []}
    })
    .to_string();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/share/v1/shares")
                .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
                .header(header::COOKIE, "aionui-session=browser-cookie")
                .header("x-csrf-token", "browser-csrf")
                .header(header::ORIGIN, "https://browser.example")
                .header(header::REFERER, "https://browser.example/settings")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "share-intent-1")
                .header("x-request-id", "share-request-1")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers().get("idempotent-replay").unwrap(), "true");
    assert_eq!(
        response.headers().get("x-request-id").unwrap(),
        "upstream-share-request-1"
    );
    assert_eq!(
        json_body(response).await,
        json!({"success": true, "data": {"share_id": "share-1", "state": "active"}})
    );

    let received = upstream.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(String::from_utf8(received[0].body.clone()).unwrap(), body);
    assert_eq!(
        received[0].headers.get("authorization").unwrap().to_str().unwrap(),
        "Bearer upstream-access"
    );
    for stripped in ["cookie", "x-csrf-token", "origin", "referer"] {
        assert!(
            received[0].headers.get(stripped).is_none(),
            "forwarded sensitive header: {stripped}"
        );
    }
}

#[tokio::test]
async fn share_bff_rejects_unfrozen_queries_methods_and_missing_write_contract_without_upstream_io() {
    let upstream = MockServer::start().await;
    let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
    let local_token = bind_upstream_token(&ctx, "upstream-access", 3600);
    let valid_body = Body::from(
        json!({
            "asset_kind": "skill",
            "asset_id": "skill-1",
            "asset_version_id": "version-1",
            "target_workspace_id": "workspace-1",
            "scope": {"kind": "workspace", "values": []}
        })
        .to_string(),
    );

    let query = Request::builder()
        .method(Method::POST)
        .uri("/api/share/v1/shares?owner_user_id=someone-else")
        .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", "share-intent-1")
        .body(valid_body)
        .unwrap();
    let query = app.clone().oneshot(query).await.unwrap();
    assert_eq!(query.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(query).await["code"], "SHARE_BAD_REQUEST");

    let missing_key = Request::builder()
        .method(Method::POST)
        .uri("/api/share/v1/shares")
        .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let missing_key = app.clone().oneshot(missing_key).await.unwrap();
    assert_eq!(missing_key.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(missing_key).await["code"], "SHARE_BAD_REQUEST");

    let empty_body = Request::builder()
        .method(Method::POST)
        .uri("/api/share/v1/shares")
        .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", "share-intent-2")
        .body(Body::empty())
        .unwrap();
    let empty_body = app.clone().oneshot(empty_body).await.unwrap();
    assert_eq!(empty_body.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(empty_body).await["code"], "SHARE_BAD_REQUEST");

    let get = app
        .oneshot(request(
            Method::GET,
            "/api/share/v1/shares",
            &local_token,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn share_bff_maps_upstream_errors_safely_and_preserves_the_local_token_bundle() {
    for (status, upstream_code, expected_code) in [
        (400, "share_scope_invalid", "SHARE_BAD_REQUEST"),
        (403, "share_forbidden", "SHARE_FORBIDDEN"),
        (409, "object_hash_mismatch", "SHARE_CONFLICT"),
        (401, "unauthorized", "AUTH_CENTER_SESSION_REQUIRED"),
    ] {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/share/v1/shares"))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "code": upstream_code,
                "message": "private upstream share details"
            })))
            .mount(&upstream)
            .await;
        let (app, ctx) = test_app(&upstream, Duration::from_secs(2)).await;
        let local_token = bind_upstream_token(&ctx, "upstream-secret", 3600);
        let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, USER_ID);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/share/v1/shares")
                    .header(header::AUTHORIZATION, format!("Bearer {local_token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", "share-intent-error")
                    .header("x-request-id", "share-request-error")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        let body = json_body(response).await;
        assert_eq!(body["code"], expected_code);
        assert!(!body.to_string().contains("private upstream share details"));
        assert!(!body.to_string().contains("upstream-secret"));
        assert!(ctx.vault.get(&vault_key).is_some());
    }
}
