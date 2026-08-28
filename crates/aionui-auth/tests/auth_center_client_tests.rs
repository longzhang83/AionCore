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
