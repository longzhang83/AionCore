mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use common::{body_json, build_app, get_request, get_with_token, json_with_token, setup_and_login};

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
}
