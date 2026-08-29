mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use wiremock::matchers::{body_json as wiremock_body_json, header as wiremock_header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};

use common::{
    bind_auth_center_token_for_user, body_json, build_app, build_app_with_schedule_bff_mock, get_request,
    get_with_token, json_with_token, json_with_token_and_headers, runtime_get, runtime_json, setup_and_login,
};

const CONVERSATION_ID: &str = "schedule-bff-helper";

#[tokio::test]
async fn governed_publish_routes_proxy_exact_recovery_reads_and_writes() {
    let upstream = MockServer::start().await;
    for (path_value, version_id) in [
        ("/api/catalog/v1/agents/agent-1/versions", "agent-version-1"),
        ("/api/catalog/v1/skills/skill-1/versions", "skill-version-1"),
    ] {
        Mock::given(method("GET"))
            .and(path(path_value))
            .and(query_param("page_size", "100"))
            .and(wiremock_header("authorization", "Bearer upstream-access"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"version_id": version_id, "state": "draft"}],
                "meta": {"page": 1, "page_size": 100, "total": 1}
            })))
            .mount(&upstream)
            .await;
    }
    for (path_value, version_id, body) in [
        (
            "/api/version/v1/agents/agent-1/versions",
            "agent-version-created-1",
            json!({"manifest": {"summary": "Ready", "system_prompt": "Review"}}),
        ),
        (
            "/api/version/v1/skills/skill-1/versions",
            "skill-version-created-1",
            json!({"manifest": {"summary": "Ready", "instructions": "Review"}}),
        ),
    ] {
        Mock::given(method("POST"))
            .and(path(path_value))
            .and(wiremock_header("authorization", "Bearer upstream-access"))
            .and(wiremock_header("idempotency-key", "create-version-1"))
            .and(wiremock_header("x-request-id", "create-request-1"))
            .and(wiremock_body_json(body))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "version_id": version_id,
                "state": "draft"
            })))
            .mount(&upstream)
            .await;
    }
    for (path_value, version_id) in [
        (
            "/api/version/v1/agents/agent-1/versions/agent-version-1/transition",
            "agent-version-1",
        ),
        (
            "/api/version/v1/skills/skill-1/versions/skill-version-1/transition",
            "skill-version-1",
        ),
    ] {
        Mock::given(method("POST"))
            .and(path(path_value))
            .and(wiremock_header("authorization", "Bearer upstream-access"))
            .and(wiremock_header("idempotency-key", "idem-1"))
            .and(wiremock_body_json(json!({"target_state": "testing", "note": "ready"})))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("idempotent-replay", "false")
                    .set_body_json(json!({"version_id": version_id, "state": "testing"})),
            )
            .mount(&upstream)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/api/publish-request/v1/requests"))
        .and(query_param("asset_kind", "agent"))
        .and(query_param("asset_id", "agent-1"))
        .and(query_param("page", "1"))
        .and(query_param("page_size", "200"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "meta": {"page": 1, "page_size": 100, "total": 0}
        })))
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/publish-request/v1/requests"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .and(wiremock_header("idempotency-key", "publish-request-1"))
        .and(wiremock_body_json(json!({
            "asset_kind": "agent",
            "asset_id": "agent-1",
            "source_version_id": "agent-version-1",
            "source_version_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "organization_id": "org-1",
            "requested_visibility": "public"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "request_id": "request-1",
            "state": "submitted"
        })))
        .mount(&upstream)
        .await;
    for (action, body) in [
        ("withdraw", json!({"reason": "No longer ready"})),
        (
            "resubmit",
            json!({
                "source_version_id": "agent-version-1",
                "source_version_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "title": "Agent one"
            }),
        ),
    ] {
        Mock::given(method("POST"))
            .and(path(format!("/api/publish-request/v1/requests/request-1/{action}")))
            .and(wiremock_header("authorization", "Bearer upstream-access"))
            .and(wiremock_header("idempotency-key", format!("publish-{action}-1")))
            .and(wiremock_body_json(body))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "request_id": "request-1",
                "state": if action == "withdraw" { "withdrawn" } else { "submitted" }
            })))
            .mount(&upstream)
            .await;
    }

    let (mut app, services, vault) =
        build_app_with_schedule_bff_mock(&upstream, std::time::Duration::from_secs(2)).await;
    let (_, csrf) = setup_and_login(&mut app, &services, "admin", "StrongP@ss1").await;
    let token = bind_auth_center_token_for_user(&services, &vault, "admin", "upstream-access", 3600).await;

    for route in [
        "/api/catalog/v1/agents/agent-1/versions?page_size=100",
        "/api/catalog/v1/skills/skill-1/versions?page_size=100",
        "/api/publish-request/v1/requests?asset_kind=agent&asset_id=agent-1&page=1&page_size=200",
    ] {
        let response = app.clone().oneshot(get_with_token(route, &token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "route: {route}");
    }

    for (route, body) in [
        (
            "/api/version/v1/agents/agent-1/versions",
            json!({"manifest": {"summary": "Ready", "system_prompt": "Review"}}),
        ),
        (
            "/api/version/v1/skills/skill-1/versions",
            json!({"manifest": {"summary": "Ready", "instructions": "Review"}}),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(json_with_token_and_headers(
                "POST",
                route,
                body,
                &token,
                &csrf,
                &[
                    ("idempotency-key", "create-version-1"),
                    ("x-request-id", "create-request-1"),
                ],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED, "route: {route}");
        assert_eq!(body_json(response).await["data"]["state"], "draft");
    }

    for route in [
        "/api/version/v1/agents/agent-1/versions/agent-version-1/transition",
        "/api/version/v1/skills/skill-1/versions/skill-version-1/transition",
    ] {
        let response = app
            .clone()
            .oneshot(json_with_token_and_headers(
                "POST",
                route,
                json!({"target_state": "testing", "note": "ready"}),
                &token,
                &csrf,
                &[("idempotency-key", "idem-1"), ("x-request-id", "transition-request-1")],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "route: {route}");
    }

    let create = app
        .clone()
        .oneshot(json_with_token_and_headers(
            "POST",
            "/api/publish-request/v1/requests",
            json!({
                "asset_kind": "agent",
                "asset_id": "agent-1",
                "source_version_id": "agent-version-1",
                "source_version_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "organization_id": "org-1",
                "requested_visibility": "public"
            }),
            &token,
            &csrf,
            &[
                ("idempotency-key", "publish-request-1"),
                ("x-request-id", "publish-request-http-1"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    assert_eq!(body_json(create).await["data"]["request_id"], "request-1");

    for (action, body) in [
        ("withdraw", json!({"reason": "No longer ready"})),
        (
            "resubmit",
            json!({
                "source_version_id": "agent-version-1",
                "source_version_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "title": "Agent one"
            }),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(json_with_token_and_headers(
                "POST",
                &format!("/api/publish-request/v1/requests/request-1/{action}"),
                body,
                &token,
                &csrf,
                &[
                    ("idempotency-key", &format!("publish-{action}-1")),
                    ("x-request-id", &format!("publish-{action}-http-1")),
                ],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "action: {action}");
    }
}

#[tokio::test]
async fn schedule_bff_is_authenticated_and_requires_csrf_for_writes() {
    let (mut app, services) = build_app().await;
    let (token, csrf) = setup_and_login(&mut app, &services, "admin", "StrongP@ss1").await;

    let unauthenticated = app
        .clone()
        .oneshot(get_request("/api/schedule/v1/schedules"))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let local_only_session = app
        .clone()
        .oneshot(get_with_token("/api/schedule/v1/schedules", &token))
        .await
        .unwrap();
    assert_eq!(local_only_session.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(local_only_session).await["code"],
        "AUTH_CENTER_SESSION_REQUIRED"
    );

    let missing_csrf = Request::builder()
        .method("POST")
        .uri("/api/schedule/v1/schedules")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(json!({"workspace_id": "workspace-1"}).to_string()))
        .unwrap();
    let missing_csrf = app.clone().oneshot(missing_csrf).await.unwrap();
    assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(missing_csrf).await["code"], "CSRF_INVALID");

    let protected_write = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            "/api/schedule/v1/schedules",
            json!({"workspace_id": "workspace-1"}),
            &token,
            &csrf,
        ))
        .await
        .unwrap();
    assert_eq!(protected_write.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(protected_write).await["code"], "AUTH_CENTER_SESSION_REQUIRED");

    let missing_share_csrf = Request::builder()
        .method("POST")
        .uri("/api/share/v1/shares")
        .header("content-type", "application/json")
        .header("idempotency-key", "share-intent-local")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(json!({"asset_kind": "agent"}).to_string()))
        .unwrap();
    let missing_share_csrf = app.clone().oneshot(missing_share_csrf).await.unwrap();
    assert_eq!(missing_share_csrf.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(missing_share_csrf).await["code"], "CSRF_INVALID");

    let local_only_share = app
        .clone()
        .oneshot(json_with_token_and_headers(
            "POST",
            "/api/share/v1/shares",
            json!({"asset_kind": "agent"}),
            &token,
            &csrf,
            &[
                ("idempotency-key", "share-intent-local"),
                ("x-request-id", "share-request-local"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(local_only_share.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(local_only_share).await["code"],
        "AUTH_CENTER_SESSION_REQUIRED"
    );

    for path in [
        "/api/version/v1/agents/agent-1/versions",
        "/api/version/v1/skills/skill-1/versions",
        "/api/version/v1/agents/agent-1/versions/version-1/transition",
        "/api/publish-request/v1/requests",
        "/api/publish-request/v1/requests/request-1/withdraw",
        "/api/publish-request/v1/requests/request-1/resubmit",
    ] {
        let missing_csrf = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("idempotency-key", "publish-intent-local")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(json!({"target_state": "testing"}).to_string()))
            .unwrap();
        let response = app.clone().oneshot(missing_csrf).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "path: {path}");
        assert_eq!(body_json(response).await["code"], "CSRF_INVALID", "path: {path}");
    }
}

#[tokio::test]
async fn runtime_token_channel_cannot_bypass_bound_session_for_schedule_bff() {
    let upstream = MockServer::start().await;
    let (mut app, services, _) = build_app_with_schedule_bff_mock(&upstream, std::time::Duration::from_secs(2)).await;
    let _ = setup_and_login(&mut app, &services, "admin", "StrongP@ss1").await;
    let user = services
        .user_repo
        .find_by_username("admin")
        .await
        .unwrap()
        .expect("admin user should exist");
    let issue = services.runtime_token_service.issue(
        user.id.as_str(),
        CONVERSATION_ID,
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );

    for path in [
        "/api/schedule/v1/schedules",
        "/api/catalog/v1/agents?page_size=100",
        "/api/catalog/v1/agents/agent-1/versions?page_size=100",
        "/api/catalog/v1/skills?page_size=100",
        "/api/catalog/v1/skills/skill-1/versions?page_size=100",
        "/api/publish-request/v1/requests?asset_kind=agent&asset_id=agent-1&page=1&page_size=200",
        "/api/team-workspace/v1/workspaces",
    ] {
        let read = app
            .clone()
            .oneshot(runtime_get(path, &user.id, CONVERSATION_ID, &issue.token))
            .await
            .unwrap();
        assert_eq!(read.status(), StatusCode::UNAUTHORIZED, "path: {path}");
        assert_eq!(body_json(read).await["code"], "UNAUTHORIZED", "path: {path}");
    }

    // These BFF routes live under auth_routes(), where the runtime-token channel
    // is intentionally disabled. The helper token therefore fails closed in the
    // auth middleware itself rather than reaching the downstream bound-session
    // check, and must never produce upstream I/O.
    let write = app
        .clone()
        .oneshot(runtime_json(
            "POST",
            "/api/schedule/v1/schedules",
            json!({"workspace_id": "workspace-1"}),
            &user.id,
            CONVERSATION_ID,
            &issue.token,
        ))
        .await
        .unwrap();
    assert_eq!(write.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(write).await["code"], "UNAUTHORIZED");

    let share_write = app
        .clone()
        .oneshot(runtime_json(
            "POST",
            "/api/share/v1/shares",
            json!({"asset_kind": "agent"}),
            &user.id,
            CONVERSATION_ID,
            &issue.token,
        ))
        .await
        .unwrap();
    assert_eq!(share_write.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(share_write).await["code"], "UNAUTHORIZED");

    for path in [
        "/api/version/v1/agents/agent-1/versions",
        "/api/version/v1/skills/skill-1/versions",
        "/api/version/v1/agents/agent-1/versions/version-1/transition",
        "/api/publish-request/v1/requests",
        "/api/publish-request/v1/requests/request-1/withdraw",
        "/api/publish-request/v1/requests/request-1/resubmit",
    ] {
        let write = app
            .clone()
            .oneshot(runtime_json(
                "POST",
                path,
                json!({"target_state": "testing"}),
                &user.id,
                CONVERSATION_ID,
                &issue.token,
            ))
            .await
            .unwrap();
        assert_eq!(write.status(), StatusCode::UNAUTHORIZED, "path: {path}");
        assert_eq!(body_json(write).await["code"], "UNAUTHORIZED", "path: {path}");
    }

    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn auth_center_bound_session_reaches_schedule_catalog_and_workspace_bff() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/schedule/v1/schedules"))
        .and(query_param("workspace_id", "workspace-1"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": [{"schedule_id": "schedule-1"}]})))
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/share/v1/shares"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .and(wiremock_header("idempotency-key", "share-intent-1"))
        .and(wiremock_header("x-request-id", "share-request-1"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("idempotent-replay", "false")
                .insert_header("x-request-id", "upstream-share-request-1")
                .set_body_json(json!({"share_id": "share-1", "state": "active"})),
        )
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/schedule/v1/schedules"))
        .and(query_param("workspace_id", "workspace-1"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .and(wiremock_header("idempotency-key", "idem-1"))
        .and(wiremock_header("x-request-id", "request-1"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("idempotent-replay", "true")
                .insert_header("x-request-id", "upstream-rid-1")
                .set_body_json(json!({"schedule_id": "schedule-2"})),
        )
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/catalog/v1/agents"))
        .and(query_param("page_size", "100"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{"agent_id": "agent-1", "name": "Finance reviewer"}],
            "meta": {"page": 1, "page_size": 100, "total": 1}
        })))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/catalog/v1/skills"))
        .and(query_param("page_size", "100"))
        .and(wiremock_header("authorization", "Bearer upstream-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{"skill_id": "skill-1", "name": "Working paper review"}],
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
            "visibility": "public"
        })))
        .mount(&upstream)
        .await;
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
    let (mut app, services, vault) =
        build_app_with_schedule_bff_mock(&upstream, std::time::Duration::from_secs(2)).await;
    let (browser_token, csrf) = setup_and_login(&mut app, &services, "admin", "StrongP@ss1").await;
    let bound_token = bind_auth_center_token_for_user(&services, &vault, "admin", "upstream-access", 3600).await;

    let unauthenticated = app
        .clone()
        .oneshot(get_request("/api/catalog/v1/agents?page_size=100"))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let local_only = app
        .clone()
        .oneshot(get_with_token("/api/team-workspace/v1/workspaces", &browser_token))
        .await
        .unwrap();
    assert_eq!(local_only.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(local_only).await["code"], "AUTH_CENTER_SESSION_REQUIRED");

    let schedule_get = app
        .clone()
        .oneshot(get_with_token(
            "/api/schedule/v1/schedules?workspace_id=workspace-1",
            &bound_token,
        ))
        .await
        .unwrap();
    assert_eq!(schedule_get.status(), StatusCode::OK);
    assert_eq!(
        body_json(schedule_get).await,
        json!({"success": true, "data": {"items": [{"schedule_id": "schedule-1"}]}})
    );

    let schedule_body = json!({"workspace_id": "workspace-1", "title": "nightly"});
    let schedule_post = app
        .clone()
        .oneshot(json_with_token_and_headers(
            "POST",
            "/api/schedule/v1/schedules?workspace_id=workspace-1",
            schedule_body.clone(),
            &bound_token,
            &csrf,
            &[
                ("idempotency-key", "idem-1"),
                ("x-request-id", "request-1"),
                ("origin", "https://browser.example"),
                ("referer", "https://browser.example/settings"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(schedule_post.status(), StatusCode::CREATED);
    assert_eq!(schedule_post.headers().get("idempotent-replay").unwrap(), "true");
    assert_eq!(schedule_post.headers().get("x-request-id").unwrap(), "upstream-rid-1");
    assert_eq!(
        body_json(schedule_post).await,
        json!({"success": true, "data": {"schedule_id": "schedule-2"}})
    );

    let catalog = app
        .clone()
        .oneshot(get_with_token("/api/catalog/v1/agents?page_size=100", &bound_token))
        .await
        .unwrap();
    assert_eq!(catalog.status(), StatusCode::OK);
    assert_eq!(
        body_json(catalog).await,
        json!({"success": true, "data": {
            "items": [{"agent_id": "agent-1", "name": "Finance reviewer"}],
            "meta": {"page": 1, "page_size": 100, "total": 1}
        }})
    );

    let skills = app
        .clone()
        .oneshot(get_with_token("/api/catalog/v1/skills?page_size=100", &bound_token))
        .await
        .unwrap();
    assert_eq!(skills.status(), StatusCode::OK);
    assert_eq!(
        body_json(skills).await,
        json!({"success": true, "data": {
            "items": [{"skill_id": "skill-1", "name": "Working paper review"}],
            "meta": {"page": 1, "page_size": 100, "total": 1}
        }})
    );

    let skill_version = app
        .clone()
        .oneshot(get_with_token(
            "/api/catalog/v1/skills/skill-1/versions/version-1",
            &bound_token,
        ))
        .await
        .unwrap();
    assert_eq!(skill_version.status(), StatusCode::OK);
    assert_eq!(body_json(skill_version).await["data"]["version_id"], "version-1");

    let workspace = app
        .clone()
        .oneshot(get_with_token("/api/team-workspace/v1/workspaces", &bound_token))
        .await
        .unwrap();
    assert_eq!(workspace.status(), StatusCode::OK);
    assert_eq!(
        body_json(workspace).await,
        json!({"success": true, "data": [{
            "workspace_id": "workspace-1",
            "type": "team",
            "organization_id": "org-1",
            "status": "active",
            "created_at": "2026-08-29T00:00:00Z",
            "updated_at": "2026-08-29T00:00:00Z"
        }]})
    );

    let share_body = json!({
        "asset_kind": "agent",
        "asset_id": "agent-1",
        "asset_version_id": "version-1",
        "asset_version_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "target_workspace_id": "workspace-1",
        "scope": {"kind": "workspace", "values": []}
    });
    let share = app
        .oneshot(json_with_token_and_headers(
            "POST",
            "/api/share/v1/shares",
            share_body.clone(),
            &bound_token,
            &csrf,
            &[
                ("idempotency-key", "share-intent-1"),
                ("x-request-id", "share-request-1"),
                ("origin", "https://browser.example"),
                ("referer", "https://browser.example/settings"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(share.status(), StatusCode::CREATED);
    assert_eq!(share.headers().get("idempotent-replay").unwrap(), "false");
    assert_eq!(share.headers().get("x-request-id").unwrap(), "upstream-share-request-1");
    assert_eq!(
        body_json(share).await,
        json!({"success": true, "data": {"share_id": "share-1", "state": "active"}})
    );

    let received = upstream.received_requests().await.unwrap();
    assert_eq!(received.len(), 7);
    for request in &received {
        let authorization = request.headers.get("authorization").unwrap().to_str().unwrap();
        assert_eq!(authorization, "Bearer upstream-access");
        assert!(!authorization.contains(&browser_token));
        assert!(!authorization.contains(&bound_token));
        for stripped in ["cookie", "x-csrf-token", "origin", "referer"] {
            assert!(
                request.headers.get(stripped).is_none(),
                "forwarded sensitive header: {stripped}"
            );
        }
    }
    let schedule_post = received
        .iter()
        .find(|request| request.method.as_str() == "POST" && request.url.path() == "/api/schedule/v1/schedules")
        .expect("schedule POST forwarded upstream");
    assert_eq!(
        String::from_utf8(schedule_post.body.clone()).unwrap(),
        serde_json::to_string(&schedule_body).unwrap()
    );
    assert_eq!(
        schedule_post.headers.get("idempotency-key").unwrap().to_str().unwrap(),
        "idem-1"
    );
    assert_eq!(
        schedule_post.headers.get("x-request-id").unwrap().to_str().unwrap(),
        "request-1"
    );
    let share_post = received
        .iter()
        .find(|request| request.method.as_str() == "POST" && request.url.path() == "/api/share/v1/shares")
        .expect("share POST forwarded upstream");
    assert_eq!(
        String::from_utf8(share_post.body.clone()).unwrap(),
        serde_json::to_string(&share_body).unwrap()
    );
    assert_eq!(
        share_post.headers.get("idempotency-key").unwrap().to_str().unwrap(),
        "share-intent-1"
    );
    assert_eq!(
        share_post.headers.get("x-request-id").unwrap().to_str().unwrap(),
        "share-request-1"
    );
}

#[tokio::test]
async fn acp_catalog_and_workspace_read_bff_require_an_auth_center_bound_session() {
    let (mut app, services) = build_app().await;
    let (token, _) = setup_and_login(&mut app, &services, "admin", "StrongP@ss1").await;

    for path in [
        "/api/catalog/v1/agents?page_size=100",
        "/api/catalog/v1/agents/agent-1/versions?page_size=100",
        "/api/catalog/v1/agents/agent-1/versions/version-1",
        "/api/catalog/v1/skills?page_size=100",
        "/api/catalog/v1/skills/skill-1/versions?page_size=100",
        "/api/catalog/v1/skills/skill-1/versions/version-1",
        "/api/publish-request/v1/requests?asset_kind=agent&asset_id=agent-1&page=1&page_size=200",
        "/api/team-workspace/v1/workspaces",
    ] {
        let unauthenticated = app.clone().oneshot(get_request(path)).await.unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED, "path: {path}");

        let local_only_session = app.clone().oneshot(get_with_token(path, &token)).await.unwrap();
        assert_eq!(local_only_session.status(), StatusCode::UNAUTHORIZED, "path: {path}");
        assert_eq!(
            body_json(local_only_session).await["code"],
            "AUTH_CENTER_SESSION_REQUIRED",
            "path: {path}"
        );
    }
}
