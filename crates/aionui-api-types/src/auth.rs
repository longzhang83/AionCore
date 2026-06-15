use serde::{Deserialize, Deserializer, Serialize};

/// Public user info returned in API responses.
///
/// Contains only the fields safe to expose to clients.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicUser {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub departments: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_source: Option<String>,
    pub source: String,
    pub status: String,
    pub is_admin: bool,
}

/// Public Auth Center login configuration for renderer clients.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthConfigResponse {
    pub success: bool,
    pub rsm_auth_enabled: bool,
    pub rsm_auth_issuer: Option<String>,
    pub rsm_auth_client_id: Option<String>,
    pub rsm_auth_app_code: String,
    pub local_login_enabled: bool,
}

/// Login request body for `POST /login`.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Login success response for `POST /login` and `POST /api/auth/qr-login`.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: String,
    pub user: PublicUser,
    pub token: String,
}

impl LoginResponse {
    pub fn new(user: PublicUser, token: String) -> Self {
        Self {
            success: true,
            message: "Login successful".to_owned(),
            user,
            token,
        }
    }
}

/// Change password request body for `POST /api/auth/change-password`.
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// QR code login request body for `POST /api/auth/qr-login`.
#[derive(Debug, Deserialize)]
pub struct QrLoginRequest {
    pub qr_token: String,
}

/// Auth status response for `GET /api/auth/status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthStatusResponse {
    pub success: bool,
    pub needs_setup: bool,
    pub user_count: u64,
    pub is_authenticated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IamOrganizationSummary {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub source: String,
    pub external_id: Option<String>,
    pub status: String,
    pub sort: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IamUserSummary {
    pub id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub mobile: Option<String>,
    pub source: String,
    pub status: String,
    pub external_status: Option<String>,
    pub is_admin: bool,
    pub auth_provider: Option<String>,
    pub auth_sub: Option<String>,
    pub auth_source: Option<String>,
    pub auth_app_code: Option<String>,
    pub organizations: Vec<IamOrganizationSummary>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IamDirectorySyncState {
    pub app_code: String,
    pub last_synced_at: Option<i64>,
    pub last_full_synced_at: Option<i64>,
    pub last_status: String,
    pub last_message: Option<String>,
    pub user_count: i64,
    pub department_count: i64,
    pub user_created: i64,
    pub user_updated: i64,
    pub user_disabled: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IamDirectorySyncResult {
    pub app_code: String,
    pub full: bool,
    pub user_count: i64,
    pub department_count: i64,
    pub user_created: i64,
    pub user_updated: i64,
    pub user_disabled: i64,
    pub synced_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct IamCreateUserRequest {
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub mobile: Option<String>,
    pub status: Option<String>,
    pub is_admin: Option<bool>,
    pub organization_ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IamCreateUserResponse {
    pub user: IamUserSummary,
    pub temporary_password: String,
}

#[derive(Debug, Deserialize)]
pub struct IamUpdateUserRequest {
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub mobile: Option<String>,
    pub status: Option<String>,
    pub is_admin: Option<bool>,
    pub organization_ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IamResetPasswordResponse {
    pub temporary_password: String,
}

#[derive(Debug, Deserialize)]
pub struct IamCreateOrganizationRequest {
    pub parent_id: Option<String>,
    pub name: String,
    pub status: Option<String>,
    pub sort: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct IamUpdateOrganizationRequest {
    #[serde(default)]
    pub parent_id: NullableStringUpdate,
    pub name: Option<String>,
    pub status: Option<String>,
    pub sort: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullableStringUpdate {
    Missing,
    Null,
    Value(String),
}

impl Default for NullableStringUpdate {
    fn default() -> Self {
        Self::Missing
    }
}

impl<'de> Deserialize<'de> for NullableStringUpdate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer).map(|value| match value {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct IamDirectorySyncRequest {
    pub full: Option<bool>,
}

/// Refresh token request body for `POST /api/auth/refresh`.
#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub token: String,
}

/// User info response for `GET /api/auth/user`.
#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    pub success: bool,
    pub user: PublicUser,
}

/// Refresh token response for `POST /api/auth/refresh`.
#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub success: bool,
    pub token: String,
}

/// WebSocket token response for `GET /api/ws-token`.
#[derive(Debug, Serialize)]
pub struct WsTokenResponse {
    pub success: bool,
    pub ws_token: String,
    pub expires_in: u64,
}

// ---------------------------------------------------------------------------
// Internal AionPro user provisioning endpoints
// ---------------------------------------------------------------------------

/// Request body for `PUT /api/auth/internal/external-users/{external_user_id}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnsureExternalUserRequest {
    pub user_type: ExternalUserType,
    pub username: Option<String>,
    pub email: Option<String>,
    pub avatar_path: Option<String>,
}

/// Supported external identity projection sources.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExternalUserType {
    Aionpro,
}

/// Response for successful internal external-user provisioning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnsureExternalUserResponse {
    pub user_id: String,
    pub user_type: ExternalUserType,
    pub external_user_id: String,
    pub session_generation: i64,
}

/// Request body for `POST /api/auth/internal/external-sessions`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnsureExternalSessionRequest {
    pub user_type: ExternalUserType,
    pub external_user_id: String,
}

/// Response for successful internal external-session exchange.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnsureExternalSessionResponse {
    pub user: PublicUser,
    pub session_generation: i64,
}

/// Request body for `POST /api/auth/internal/external-sessions/revoke`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokeExternalSessionRequest {
    pub user_type: ExternalUserType,
    pub external_user_id: String,
}

/// Response for successful internal external-session revocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokeExternalSessionResponse {
    pub user_id: String,
    pub session_generation: i64,
}

/// Stable internal auth error codes for AionPro/Core session exchange.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InternalAuthErrorCode {
    BootstrapSecretRequired,
    InvalidBootstrapSecret,
    UserContextRequired,
    UserDisabled,
    ExternalUserConflict,
}

// ---------------------------------------------------------------------------
// WebUI admin credential endpoints (local-only)
// ---------------------------------------------------------------------------

/// Change password request body for `POST /api/webui/change-password`.
///
/// No current_password field — this endpoint is local-mode only and assumes
/// the caller is the trusted Electron main process.
#[derive(Debug, Deserialize)]
pub struct WebuiChangePasswordRequest {
    pub new_password: String,
}

/// Change username request body for `POST /api/webui/change-username`.
#[derive(Debug, Deserialize)]
pub struct WebuiChangeUsernameRequest {
    pub new_username: String,
}

/// Response for `POST /api/webui/change-username`.
#[derive(Debug, Serialize, Deserialize)]
pub struct WebuiChangeUsernameResponse {
    pub username: String,
}

/// Response for `POST /api/webui/reset-password`.
///
/// Returns the freshly generated plaintext password. This is the only time
/// the caller sees it — subsequent reads hit the bcrypt hash only.
#[derive(Debug, Serialize, Deserialize)]
pub struct WebuiResetPasswordResponse {
    pub new_password: String,
}

/// Response for `POST /api/webui/generate-qr-token`.
///
/// Only the token and expiry are returned. URL assembly (host + port) is the
/// caller's responsibility, since only the Electron main process knows which
/// lanIP/port the WebUI is exposed on.
#[derive(Debug, Serialize, Deserialize)]
pub struct WebuiGenerateQrTokenResponse {
    pub token: String,
    pub expires_at_ms: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_public_user_serialization() {
        let user = PublicUser {
            id: "auth_1712345678_abc".into(),
            username: "admin".into(),
            display_name: None,
            email: None,
            mobile: None,
            departments: None,
            auth_source: None,
            source: "local".into(),
            status: "active".into(),
            is_admin: true,
        };
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["id"], "auth_1712345678_abc");
        assert_eq!(json["username"], "admin");
        assert_eq!(json["is_admin"], true);
    }

    #[test]
    fn test_login_request_deserialization() {
        let raw = r#"{"username":"admin","password":"secret123"}"#;
        let req: LoginRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.username, "admin");
        assert_eq!(req.password, "secret123");
    }

    #[test]
    fn test_login_request_missing_field() {
        let raw = r#"{"username":"admin"}"#;
        let result = serde_json::from_str::<LoginRequest>(raw);
        assert!(result.is_err());
    }

    #[test]
    fn test_login_response_new() {
        let user = PublicUser {
            id: "user_1".into(),
            username: "admin".into(),
            display_name: None,
            email: None,
            mobile: None,
            departments: None,
            auth_source: None,
            source: "local".into(),
            status: "active".into(),
            is_admin: true,
        };
        let resp = LoginResponse::new(user.clone(), "jwt_token".into());
        assert!(resp.success);
        assert_eq!(resp.message, "Login successful");
        assert_eq!(resp.user, user);
        assert_eq!(resp.token, "jwt_token");
    }

    #[test]
    fn test_login_response_serialization() {
        let resp = LoginResponse::new(
            PublicUser {
                id: "auth_123".into(),
                username: "admin".into(),
                display_name: None,
                email: None,
                mobile: None,
                departments: None,
                auth_source: None,
                source: "local".into(),
                status: "active".into(),
                is_admin: true,
            },
            "eyJhbGciOi".into(),
        );
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["message"], "Login successful");
        assert_eq!(json["user"]["id"], "auth_123");
        assert_eq!(json["user"]["username"], "admin");
        assert_eq!(json["token"], "eyJhbGciOi");
    }

    #[test]
    fn test_internal_external_user_contract_serialization() {
        let req = EnsureExternalUserRequest {
            user_type: ExternalUserType::Aionpro,
            username: Some("Pro User".into()),
            email: Some("pro@example.com".into()),
            avatar_path: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["user_type"], "aionpro");
        assert_eq!(json["username"], "Pro User");
        assert_eq!(json["email"], "pro@example.com");
        assert_eq!(json["avatar_path"], serde_json::Value::Null);

        let resp = EnsureExternalUserResponse {
            user_id: "user_123".into(),
            user_type: ExternalUserType::Aionpro,
            external_user_id: "external_123".into(),
            session_generation: 2,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["user_id"], "user_123");
        assert_eq!(json["user_type"], "aionpro");
        assert_eq!(json["external_user_id"], "external_123");
        assert_eq!(json["session_generation"], 2);

        let code = serde_json::to_value(InternalAuthErrorCode::UserContextRequired).unwrap();
        assert_eq!(code, "USER_CONTEXT_REQUIRED");
    }

    #[test]
    fn test_internal_external_session_revoke_contract_serialization() {
        let req = RevokeExternalSessionRequest {
            user_type: ExternalUserType::Aionpro,
            external_user_id: "external_123".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["user_type"], "aionpro");
        assert_eq!(json["external_user_id"], "external_123");

        let resp = RevokeExternalSessionResponse {
            user_id: "user_123".into(),
            session_generation: 3,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["user_id"], "user_123");
        assert_eq!(json["session_generation"], 3);
    }

    #[test]
    fn test_change_password_request_snake_case() {
        let raw = r#"{"current_password":"old123","new_password":"new456"}"#;
        let req: ChangePasswordRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.current_password, "old123");
        assert_eq!(req.new_password, "new456");
    }

    #[test]
    fn test_change_password_request_camel_case_rejected() {
        let raw = r#"{"currentPassword":"old","newPassword":"new"}"#;
        let result = serde_json::from_str::<ChangePasswordRequest>(raw);
        assert!(result.is_err());
    }

    #[test]
    fn test_qr_login_request_snake_case() {
        let raw = r#"{"qr_token":"abc123"}"#;
        let req: QrLoginRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.qr_token, "abc123");
    }

    #[test]
    fn test_qr_login_request_camel_case_rejected() {
        let raw = r#"{"qrToken":"abc"}"#;
        let result = serde_json::from_str::<QrLoginRequest>(raw);
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_status_response_snake_case() {
        let resp = AuthStatusResponse {
            success: true,
            needs_setup: true,
            user_count: 0,
            is_authenticated: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["needs_setup"], true);
        assert_eq!(json["user_count"], 0);
        assert_eq!(json["is_authenticated"], false);
        // Verify snake_case keys exist, not camelCase
        assert!(json.get("needsSetup").is_none());
        assert!(json.get("userCount").is_none());
        assert!(json.get("isAuthenticated").is_none());
    }

    #[test]
    fn test_auth_status_response_deserialization() {
        let raw = json!({
            "success": true,
            "needs_setup": false,
            "user_count": 3,
            "is_authenticated": true
        });
        let resp: AuthStatusResponse = serde_json::from_value(raw).unwrap();
        assert!(resp.success);
        assert!(!resp.needs_setup);
        assert_eq!(resp.user_count, 3);
        assert!(resp.is_authenticated);
    }

    #[test]
    fn test_refresh_token_request_deserialization() {
        let raw = r#"{"token":"eyJhbGciOiJIUzI1NiJ9"}"#;
        let req: RefreshTokenRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.token, "eyJhbGciOiJIUzI1NiJ9");
    }

    #[test]
    fn test_refresh_token_request_missing_token() {
        let raw = r#"{}"#;
        let result = serde_json::from_str::<RefreshTokenRequest>(raw);
        assert!(result.is_err());
    }
}
