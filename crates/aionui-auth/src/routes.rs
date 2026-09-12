#![allow(clippy::disallowed_types)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Json, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::from_fn_with_state;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Router};
use serde::{Deserialize, Serialize};

use aionui_api_types::{
    ApiResponse, AuthConfigResponse, AuthStatusResponse, ChangePasswordRequest, EnsureExternalSessionRequest,
    EnsureExternalUserRequest, EnsureExternalUserResponse, IamCreateOrganizationRequest, IamCreateUserRequest,
    IamCreateUserResponse, IamDirectorySyncRequest, IamDirectorySyncResult, IamDirectorySyncState,
    IamOrganizationSummary, IamResetPasswordResponse, IamUpdateOrganizationRequest, IamUpdateUserRequest,
    IamUserSummary, LoginRequest, LoginResponse, NullableStringUpdate, PublicUser, QrLoginRequest, RefreshResponse,
    RefreshTokenRequest, RevokeExternalSessionRequest, RevokeExternalSessionResponse, UserInfoResponse,
    WebuiChangePasswordRequest, WebuiChangeUsernameRequest, WebuiChangeUsernameResponse, WebuiGenerateQrTokenResponse,
    WebuiResetPasswordResponse, WsTokenResponse,
};
use aionui_common::ApiError;
use aionui_common::constants::COOKIE_MAX_AGE_DAYS;
use aionui_db::{
    CreateLocalUserParams, CreateOrganizationParams, DbError, IIamRepository, IUserRepository, SyncCounts,
    UpdateOrganizationParams, UpdateUserParams, UpsertExternalOrganizationParams, UpsertExternalUserParams, UserStatus,
    UserType,
    models::{DirectorySyncStateRow, OrganizationRow, User},
};

use crate::auth_center_client::{
    AuthCenterProtocolClient, DirectoryDepartment, DirectoryUser, RsmAuthConfig, RsmOidcCallbackQuery,
    RsmOidcLoginQuery, RsmOidcStateStore, directory_status_to_local_status, directory_user_is_admin, sanitize_username,
    timestamp_rfc3339_to_ms,
};
use crate::auth_center_tokens::{AuthCenterTokenVaultKey, IAuthCenterTokenVault};
use crate::dpop::DpopKeySelector;
use crate::error::{AuthCenterError, AuthError};
use crate::extract::extract_token_from_headers;
use crate::middleware::{AuthIdentityMode, AuthState, CurrentUser, auth_middleware};
use crate::password::{dummy_password_hash, generate_password, hash_password, verify_password_timed};
use crate::qr_token::QrTokenStore;
use crate::rate_limit::{
    RateLimiter, api_rate_limit_middleware, auth_rate_limit_middleware, authenticated_action_rate_limit_middleware,
};
use crate::schedule_bff::{ScheduleBffConfig, schedule_bff_routes};
use crate::service::{AuthProvisionService, ProvisionError};
use crate::validation::{validate_password, validate_username};
use crate::{CookieConfig, JwtService};

const BOOTSTRAP_SECRET_HEADER: &str = "x-aioncore-bootstrap-secret";

pub type SessionRevokedHook = dyn Fn(&str) + Send + Sync;

impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidCredentials => ApiError::Unauthorized("Invalid username or password".into()),
            AuthError::WeakPassword(msg) => ApiError::BadRequest(msg),
            AuthError::InvalidUsername(msg) => ApiError::BadRequest(msg),
            AuthError::TokenExpired => ApiError::Unauthorized("Token expired".into()),
            AuthError::TokenInvalid(msg) => ApiError::Unauthorized(msg),
            AuthError::TokenBlacklisted => ApiError::Unauthorized("Token has been revoked".into()),
            AuthError::RateLimited => ApiError::RateLimited,
            AuthError::HashError(msg) => ApiError::Internal(format!("Password hash error: {msg}")),
        }
    }
}

impl From<AuthCenterError> for ApiError {
    fn from(err: AuthCenterError) -> Self {
        match err {
            AuthCenterError::NotFound(msg) => ApiError::NotFound(msg),
            AuthCenterError::Internal(msg) => ApiError::Internal(msg),
            AuthCenterError::BadRequest(msg) => ApiError::BadRequest(msg),
            AuthCenterError::Unauthorized(msg) => ApiError::Unauthorized(msg),
            AuthCenterError::Forbidden(msg) => ApiError::Forbidden(msg),
            AuthCenterError::BadGateway(msg) => ApiError::BadGateway(msg),
        }
    }
}

fn db_error_to_api_error(err: DbError) -> ApiError {
    match err {
        DbError::NotFound(msg) => ApiError::NotFound(msg),
        DbError::Conflict(msg) => ApiError::Conflict(msg),
        DbError::Query(e) => ApiError::Internal(format!("Database error: {e}")),
        DbError::Migration(e) => ApiError::Internal(format!("Migration error: {e}")),
        DbError::Init(msg) => ApiError::Internal(format!("Database init error: {msg}")),
    }
}

fn public_user_from_user(user: User) -> PublicUser {
    PublicUser {
        id: user.id,
        username: user.username.unwrap_or_else(|| "external_user".to_string()),
        display_name: user.display_name,
        email: user.email,
        mobile: user.mobile,
        departments: user
            .department_ids
            .as_deref()
            .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok()),
        auth_source: user.auth_source,
        source: user.source,
        status: user.status.as_str().to_owned(),
        is_admin: user.is_admin != 0,
    }
}

fn organization_summary(row: OrganizationRow) -> IamOrganizationSummary {
    IamOrganizationSummary {
        id: row.id,
        parent_id: row.parent_id,
        name: row.name,
        source: row.source,
        external_id: row.external_id,
        status: row.status,
        sort: row.sort,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn directory_sync_state_summary(row: DirectorySyncStateRow) -> IamDirectorySyncState {
    IamDirectorySyncState {
        app_code: row.app_code,
        last_synced_at: row.last_synced_at,
        last_full_synced_at: row.last_full_synced_at,
        last_status: row.last_status,
        last_message: row.last_message,
        user_count: row.user_count,
        department_count: row.department_count,
        user_created: row.user_created,
        user_updated: row.user_updated,
        user_disabled: row.user_disabled,
        updated_at: row.updated_at,
    }
}

fn user_summary(user: User, organizations: Vec<IamOrganizationSummary>) -> IamUserSummary {
    IamUserSummary {
        id: user.id,
        username: user.username.unwrap_or_else(|| "external_user".to_string()),
        display_name: user.display_name,
        email: user.email,
        mobile: user.mobile,
        position: user.position,
        position_sort: user.position_sort,
        source: user.source,
        status: user.status.as_str().to_owned(),
        external_status: user.external_status,
        is_admin: user.is_admin != 0,
        auth_provider: user.auth_provider,
        auth_sub: user.auth_sub,
        auth_source: user.auth_source,
        auth_app_code: user.auth_app_code,
        organizations,
        created_at: user.created_at,
        updated_at: user.updated_at,
        last_login: user.last_login,
    }
}

async fn load_user_summary(iam_repo: &dyn IIamRepository, user: User) -> Result<IamUserSummary, ApiError> {
    let organizations = iam_repo
        .list_user_organizations(&user.id)
        .await
        .map_err(db_error_to_api_error)?
        .into_iter()
        .map(organization_summary)
        .collect();
    Ok(user_summary(user, organizations))
}

fn is_disabled(user: &User) -> bool {
    user.status == UserStatus::Disabled || user.external_status.as_deref() == Some("disabled")
}

fn normalize_status(value: Option<&str>) -> Result<Option<&str>, ApiError> {
    match value.map(str::trim) {
        None => Ok(None),
        Some("active") => Ok(Some("active")),
        Some("disabled") => Ok(Some("disabled")),
        Some(_) => Err(ApiError::BadRequest("status must be active or disabled".into())),
    }
}

fn ensure_admin(current_user: &CurrentUser) -> Result<(), ApiError> {
    if current_user.is_admin {
        return Ok(());
    }
    Err(ApiError::Forbidden("Admin permission required".into()))
}

/// Shared state for all auth route handlers.
#[derive(Clone)]
pub struct AuthRouterState {
    pub jwt_service: Arc<JwtService>,
    pub user_repo: Arc<dyn IUserRepository>,
    /// Optional on-disk adoption side-effect (AionUi → AionPro upgrade).
    pub fs_adopter: Option<Arc<dyn crate::service::SystemDefaultFilesystemAdopter>>,
    pub iam_repo: Arc<dyn IIamRepository>,
    pub cookie_config: Arc<CookieConfig>,
    pub qr_token_store: Arc<QrTokenStore>,
    pub identity_mode: AuthIdentityMode,
    pub bootstrap_secret: Option<Arc<str>>,
    pub session_revoked_hook: Option<Arc<SessionRevokedHook>>,
    pub rsm_auth_config: Arc<RsmAuthConfig>,
    pub rsm_oidc_state_store: Arc<RsmOidcStateStore>,
    /// Server-side vault for Auth Center token bundles, keyed by the local
    /// JWT fingerprint and owning user. Populated on successful OIDC
    /// callback, rotated with the local JWT, and drained on logout/revoke.
    pub auth_center_token_vault: Arc<dyn IAuthCenterTokenVault>,
    pub schedule_bff_config: Arc<ScheduleBffConfig>,
    pub http_client: reqwest::Client,
    pub local: bool,
    pub aionpro_mode: bool,
}

#[derive(Debug, Deserialize)]
struct CreateInternalUserRequest {
    username: String,
    password_hash: String,
}

#[derive(Debug, Deserialize)]
struct SetSystemUserCredentialsRequest {
    username: String,
    password_hash: String,
}

#[derive(Debug, Deserialize)]
struct UpdatePasswordHashRequest {
    password_hash: String,
}

#[derive(Debug, Deserialize)]
struct UpdateUsernameRequest {
    username: String,
}

#[derive(Debug, Deserialize)]
struct UpdateJwtSecretRequest {
    jwt_secret: String,
}

#[derive(Debug, Serialize)]
struct InternalUserResponse {
    id: String,
    user_type: UserType,
    external_user_id: Option<String>,
    username: Option<String>,
    email: Option<String>,
    avatar_path: Option<String>,
    status: UserStatus,
    session_generation: i64,
    created_at: i64,
    updated_at: i64,
    last_login: Option<i64>,
}

impl From<User> for InternalUserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            user_type: user.user_type,
            external_user_id: user.external_user_id,
            username: user.username,
            email: user.email,
            avatar_path: user.avatar_path,
            status: user.status,
            session_generation: user.session_generation,
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_login: user.last_login,
        }
    }
}

fn ensure_local_mode(local: bool) -> Result<(), ApiError> {
    if local {
        return Ok(());
    }
    Err(ApiError::Forbidden(
        "This endpoint is only available in local mode".into(),
    ))
}

fn require_bootstrap_secret(headers: &HeaderMap, expected: Option<&str>) -> Result<(), ApiError> {
    let Some(expected) = expected else {
        return Err(ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "BOOTSTRAP_SECRET_REQUIRED",
            "Bootstrap secret required.",
            None,
        ));
    };
    let Some(actual) = headers.get(BOOTSTRAP_SECRET_HEADER).and_then(|v| v.to_str().ok()) else {
        return Err(ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "BOOTSTRAP_SECRET_REQUIRED",
            "Bootstrap secret required.",
            None,
        ));
    };
    if constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "INVALID_BOOTSTRAP_SECRET",
            "Invalid bootstrap secret.",
            None,
        ))
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for idx in 0..max_len {
        let l = left.get(idx).copied().unwrap_or(0);
        let r = right.get(idx).copied().unwrap_or(0);
        diff |= usize::from(l ^ r);
    }
    diff == 0
}

fn provision_error_to_api_error(err: ProvisionError) -> ApiError {
    match err {
        ProvisionError::UnsupportedUserType => ApiError::BadRequest("Unsupported external user type".into()),
        ProvisionError::UserDisabled => ApiError::coded(StatusCode::FORBIDDEN, "USER_DISABLED", "User disabled.", None),
        ProvisionError::UserNotProvisioned => ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "USER_CONTEXT_REQUIRED",
            "User context required.",
            None,
        ),
        ProvisionError::Db(DbError::Conflict(_)) => ApiError::coded(
            StatusCode::CONFLICT,
            "EXTERNAL_USER_CONFLICT",
            "External user conflict.",
            None,
        ),
        ProvisionError::Db(e) => db_error_to_api_error(e),
        ProvisionError::Token(e) => ApiError::Internal(format!("Token signing error: {e}")),
    }
}

fn user_context_required() -> ApiError {
    ApiError::coded(
        StatusCode::UNAUTHORIZED,
        "USER_CONTEXT_REQUIRED",
        "User context required.",
        None,
    )
}

/// Build the auth router with all endpoints and middleware layers.
///
/// Returns a `Router` with these endpoints:
/// - `POST /login`
/// - `POST /logout`
/// - `GET /api/auth/config`
/// - `GET /api/auth/oidc/login`
/// - `GET /api/auth/oidc/callback`
/// - `GET /api/auth/status`
/// - `GET /api/auth/user`
/// - `POST /api/auth/change-password`
/// - `POST /api/auth/refresh`
/// - `GET /api/ws-token`
/// - `POST /api/auth/qr-login`
/// - `GET /qr-login`
/// - `POST /api/webui/change-password` (local-only)
/// - `POST /api/webui/change-username` (local-only)
/// - `POST /api/webui/reset-password` (local-only)
/// - `POST /api/webui/generate-qr-token` (local-only)
pub fn auth_routes(state: AuthRouterState) -> Router {
    let auth_limiter = Arc::new(RateLimiter::auth());
    let public_api_limiter = Arc::new(RateLimiter::api());
    let local_admin_limiter = Arc::new(RateLimiter::local_admin());
    let action_limiter = Arc::new(RateLimiter::authenticated_action());

    // Start periodic cleanup for rate limiters
    let cleanup_interval = Duration::from_secs(60);
    auth_limiter.start_cleanup_task(cleanup_interval);
    public_api_limiter.start_cleanup_task(cleanup_interval);
    local_admin_limiter.start_cleanup_task(cleanup_interval);
    action_limiter.start_cleanup_task(cleanup_interval);

    let auth_state = AuthState {
        jwt_service: state.jwt_service.clone(),
        user_repo: state.user_repo.clone(),
        identity_mode: if state.aionpro_mode {
            AuthIdentityMode::AionPro
        } else {
            AuthIdentityMode::UserSession
        },
        // Auth endpoints manage sessions themselves; the helper CLI never
        // calls them, so the runtime-token channel stays disabled here.
        runtime_token_verifier: None,
    };

    // Auth rate limited routes (login, qr-login)
    let auth_rate_limited = Router::new()
        .route("/login", post(login_handler))
        .route("/api/auth/oidc/login", get(oidc_login_handler))
        .route("/api/auth/oidc/callback", get(oidc_callback_handler))
        .route("/api/auth/qr-login", post(qr_login_handler))
        .route_layer(from_fn_with_state(auth_limiter, auth_rate_limit_middleware))
        .with_state(state.clone());

    // Public unauthenticated routes.
    let api_public = Router::new()
        .route("/api/auth/config", get(config_handler))
        .route("/api/auth/status", get(status_handler))
        .route_layer(from_fn_with_state(
            public_api_limiter.clone(),
            api_rate_limit_middleware,
        ))
        .with_state(state.clone());

    // Local-only admin/bootstrap routes.
    let local_admin = Router::new()
        .route(
            "/api/auth/internal/external-users/{external_user_id}",
            put(ensure_external_user_handler),
        )
        .route(
            "/api/auth/internal/external-sessions",
            post(create_external_session_handler),
        )
        .route(
            "/api/auth/internal/external-sessions/revoke",
            post(revoke_external_session_handler),
        )
        .route(
            "/api/auth/internal/users",
            get(list_internal_users_handler).post(create_internal_user_handler),
        )
        .route("/api/auth/internal/users/system", get(get_system_user_handler))
        .route(
            "/api/auth/internal/users/system/credentials",
            post(set_system_user_credentials_handler),
        )
        .route(
            "/api/auth/internal/users/by-username/{username}",
            get(find_user_by_username_handler),
        )
        .route("/api/auth/internal/users/{id}", get(find_user_by_id_handler))
        .route(
            "/api/auth/internal/users/{id}/password",
            post(update_user_password_hash_handler),
        )
        .route(
            "/api/auth/internal/users/{id}/username",
            post(update_user_username_handler),
        )
        .route(
            "/api/auth/internal/users/{id}/jwt-secret",
            post(update_user_jwt_secret_handler),
        )
        .route(
            "/api/auth/internal/users/{id}/last-login",
            post(update_user_last_login_handler),
        )
        // WebUI admin credential endpoints — local-only, enforced inside each handler.
        .route("/api/webui/change-password", post(webui_change_password_handler))
        .route("/api/webui/change-username", post(webui_change_username_handler))
        .route("/api/webui/reset-password", post(webui_reset_password_handler))
        .route("/api/webui/generate-qr-token", post(webui_generate_qr_token_handler))
        .route_layer(from_fn_with_state(local_admin_limiter, api_rate_limit_middleware))
        .with_state(state.clone());

    // Authenticated routes: api limiter -> auth -> action limiter
    // route_layer order: last added = outermost (first to process)
    let authenticated = Router::new()
        .merge(schedule_bff_routes())
        .route("/logout", post(logout_handler))
        .route("/api/auth/user", get(user_handler))
        .route("/api/auth/change-password", post(change_password_handler))
        .route("/api/ws-token", get(ws_token_handler))
        .route(
            "/api/iam/users",
            get(list_iam_users_handler).post(create_iam_user_handler),
        )
        .route("/api/iam/users/{id}", put(update_iam_user_handler))
        .route(
            "/api/iam/users/{id}/reset-password",
            post(reset_iam_user_password_handler),
        )
        .route(
            "/api/iam/organizations",
            get(list_iam_organizations_handler).post(create_iam_organization_handler),
        )
        .route(
            "/api/iam/organizations/{id}",
            put(update_iam_organization_handler).delete(delete_iam_organization_handler),
        )
        .route("/api/iam/directory-sync/status", get(directory_sync_status_handler))
        .route("/api/iam/directory-sync", post(directory_sync_handler))
        .route_layer(from_fn_with_state(
            action_limiter.clone(),
            authenticated_action_rate_limit_middleware,
        ))
        .route_layer(from_fn_with_state(auth_state, auth_middleware))
        .route_layer(from_fn_with_state(
            public_api_limiter.clone(),
            api_rate_limit_middleware,
        ))
        .with_state(state.clone());

    // API + action limited routes (token in body, no auth middleware)
    let api_action_limited = Router::new()
        .route("/api/auth/refresh", post(refresh_handler))
        .route_layer(from_fn_with_state(
            action_limiter,
            authenticated_action_rate_limit_middleware,
        ))
        .route_layer(from_fn_with_state(public_api_limiter, api_rate_limit_middleware))
        .with_state(state);

    // Static page (no middleware)
    let static_routes = Router::new().route("/qr-login", get(qr_login_page));

    Router::new()
        .merge(auth_rate_limited)
        .merge(api_public)
        .merge(local_admin)
        .merge(authenticated)
        .merge(api_action_limited)
        .merge(static_routes)
}

// ---------------------------------------------------------------------------
// PUT /api/auth/internal/external-users/{external_user_id}
// ---------------------------------------------------------------------------

async fn ensure_external_user_handler(
    State(state): State<AuthRouterState>,
    headers: HeaderMap,
    Path(external_user_id): Path<String>,
    body: Result<Json<EnsureExternalUserRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<EnsureExternalUserResponse>>, ApiError> {
    require_bootstrap_secret(&headers, state.bootstrap_secret.as_deref().map(AsRef::as_ref))?;
    let Json(req) = body.map_err(ApiError::from)?;
    let mut service = AuthProvisionService::new(state.user_repo, state.jwt_service);
    if let Some(fs_adopter) = state.fs_adopter {
        service = service.with_filesystem_adopter(fs_adopter);
    }
    let response = service
        .ensure_external_user(&external_user_id, req)
        .await
        .map_err(provision_error_to_api_error)?;
    tracing::info!(
        user_id = %response.user_id,
        user_type = ?response.user_type,
        "external user provision succeeded"
    );
    Ok(Json(ApiResponse::ok(response)))
}

// ---------------------------------------------------------------------------
// POST /api/auth/internal/external-sessions
// ---------------------------------------------------------------------------

async fn create_external_session_handler(
    State(state): State<AuthRouterState>,
    headers: HeaderMap,
    body: Result<Json<EnsureExternalSessionRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    require_bootstrap_secret(&headers, state.bootstrap_secret.as_deref().map(AsRef::as_ref))?;
    let Json(req) = body.map_err(ApiError::from)?;
    let service = AuthProvisionService::new(state.user_repo, state.jwt_service);
    let exchange = service
        .create_external_session(req)
        .await
        .map_err(provision_error_to_api_error)?;
    tracing::info!(
        user_id = %exchange.response.user.id,
        "external core session exchange succeeded"
    );
    let cookie = state.cookie_config.build_session_cookie(&exchange.token);
    Ok(([(header::SET_COOKIE, cookie)], Json(ApiResponse::ok(exchange.response))).into_response())
}

// ---------------------------------------------------------------------------
// POST /api/auth/internal/external-sessions/revoke
// ---------------------------------------------------------------------------

async fn revoke_external_session_handler(
    State(state): State<AuthRouterState>,
    headers: HeaderMap,
    body: Result<Json<RevokeExternalSessionRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<RevokeExternalSessionResponse>>, ApiError> {
    require_bootstrap_secret(&headers, state.bootstrap_secret.as_deref().map(AsRef::as_ref))?;
    let Json(req) = body.map_err(ApiError::from)?;
    let service = AuthProvisionService::new(state.user_repo, state.jwt_service);
    let response = service
        .revoke_external_session(req)
        .await
        .map_err(provision_error_to_api_error)?;
    tracing::info!(
        user_id = %response.user_id,
        session_generation = response.session_generation,
        "external core session revoked"
    );
    if let Some(hook) = &state.session_revoked_hook {
        hook(&response.user_id);
    }
    state.auth_center_token_vault.clear_all_for_user(&response.user_id);
    // Keys without their vault bundle are inert (no bundle, no proof-able
    // session), but revoke them anyway. Never block the revocation itself.
    if let Err(error) = state
        .schedule_bff_config
        .dpop_key_store()
        .clear_all_for_holder(&response.user_id)
    {
        tracing::warn!(
            user_id = %response.user_id,
            error = %error,
            "failed to clear DPoP keys for revoked user"
        );
    }
    Ok(Json(ApiResponse::ok(response)))
}

// ---------------------------------------------------------------------------
// GET /api/auth/config
// ---------------------------------------------------------------------------

async fn config_handler(State(state): State<AuthRouterState>) -> Json<AuthConfigResponse> {
    Json(state.rsm_auth_config.public_response())
}

// ---------------------------------------------------------------------------
// GET /api/auth/oidc/login
// ---------------------------------------------------------------------------

async fn oidc_login_handler(
    State(state): State<AuthRouterState>,
    headers: HeaderMap,
    Query(query): Query<RsmOidcLoginQuery>,
) -> Result<Redirect, ApiError> {
    let client = AuthCenterProtocolClient::new(state.http_client.clone());
    let url = client
        .build_login_redirect(&state.rsm_auth_config, &state.rsm_oidc_state_store, &headers, query)
        .await?;
    Ok(Redirect::temporary(&url))
}

// ---------------------------------------------------------------------------
// GET /api/auth/oidc/callback
// ---------------------------------------------------------------------------

async fn oidc_callback_handler(
    State(state): State<AuthRouterState>,
    Query(query): Query<RsmOidcCallbackQuery>,
) -> Result<Response, ApiError> {
    let client = AuthCenterProtocolClient::new(state.http_client.clone());
    let (return_to, identity, token_bundle, dpop_handle) = client
        .exchange_callback(
            &state.rsm_auth_config,
            &state.rsm_oidc_state_store,
            state.schedule_bff_config.dpop_key_store().as_ref(),
            query,
        )
        .await?;
    let departments_json = if identity.departments.is_empty() {
        None
    } else {
        Some(
            serde_json::to_string(&identity.departments)
                .map_err(|e| ApiError::Internal(format!("Failed to serialize departments: {e}")))?,
        )
    };
    let (user, _) = state
        .iam_repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: &identity.sub,
            username: &identity.username,
            display_name: identity.display_name.as_deref(),
            email: identity.email.as_deref(),
            mobile: identity.mobile.as_deref(),
            position: None,
            position_sort: None,
            departments_json: departments_json.as_deref(),
            auth_source: Some(&identity.auth_source),
            app_code: &identity.app_code,
            external_status: Some("active"),
            external_updated_at: None,
            is_admin: identity.is_admin,
        })
        .await
        .map_err(db_error_to_api_error)?;
    state
        .iam_repo
        .replace_external_user_organizations(&user.id, &identity.departments)
        .await
        .map_err(db_error_to_api_error)?;
    if is_disabled(&user) {
        return Err(ApiError::Forbidden("User is disabled".into()));
    }

    let token = state
        .jwt_service
        .sign_auth_center_bound(
            &user.id,
            user.username.as_deref().unwrap_or("external_user"),
            user.session_generation,
        )
        .map_err(|e| ApiError::Internal(format!("Token signing error: {e}")))?;
    if let Err(e) = state.user_repo.update_last_login(&user.id).await {
        tracing::warn!("Failed to update last login for {}: {e}", user.id);
    }

    // Persist the upstream Auth Center token bundle server-side, bound to
    // the freshly signed local JWT. The fingerprint is the storage key so
    // concurrent browser sessions for the same user do not collide. The
    // bundle is never echoed to the browser — only the local JWT crosses
    // the wire.
    let vault_key = AuthCenterTokenVaultKey::from_token(&token, &user.id);
    // Bind the login's DPoP key (whose thumbprint the Auth Center recorded
    // as `cnf.jkt` on the new access token) to this session's selector.
    // Fail-closed: an unbound key would make every later ACP proof fail, so
    // refuse the login instead of issuing a session that cannot prove
    // possession.
    state
        .schedule_bff_config
        .dpop_key_store()
        .bind(
            dpop_handle,
            &DpopKeySelector::new(user.id.clone(), vault_key.token_fingerprint.clone()),
        )
        .map_err(|error| {
            tracing::error!(user_id = %user.id, error = %error, "failed to bind login DPoP key");
            ApiError::Internal("DPoP key binding failed".into())
        })?;
    let prior = state.auth_center_token_vault.store(vault_key, token_bundle);
    if prior.is_some() {
        tracing::info!(
            user_id = %user.id,
            "rotated stored Auth Center token bundle for user"
        );
    }

    let cookie = state.cookie_config.build_session_cookie(&token);
    Ok(([(header::SET_COOKIE, cookie)], Redirect::temporary(&return_to)).into_response())
}

// ---------------------------------------------------------------------------
// POST /login
// ---------------------------------------------------------------------------

async fn login_handler(
    State(state): State<AuthRouterState>,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    if state.aionpro_mode {
        return Err(user_context_required());
    }

    let Json(req) = body.map_err(ApiError::from)?;

    // Input length validation (per API spec)
    if req.username.len() > 32 {
        return Err(ApiError::BadRequest("Username must not exceed 32 characters".into()));
    }
    if req.password.len() > 128 {
        return Err(ApiError::BadRequest("Password must not exceed 128 characters".into()));
    }

    // Look up user; run dummy verify on miss to prevent timing attacks
    let user = state
        .user_repo
        .find_by_username(&req.username)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    let (found_user, password_valid) = match user {
        Some(u) if u.password_hash.as_deref().unwrap_or_default().trim().is_empty() => {
            // Seeded user with no password yet (first-run local mode).
            // Treat as invalid credentials; run dummy verify for timing symmetry
            // and to avoid bcrypt error on empty hash leaking as a 500.
            let _ = verify_password_timed(&req.password, dummy_password_hash()).await;
            (None, false)
        }
        Some(u) => {
            let Some(password_hash) = u.password_hash.as_deref() else {
                let _ = verify_password_timed(&req.password, dummy_password_hash()).await;
                return Err(ApiError::Unauthorized("Invalid username or password".into()));
            };
            let valid = verify_password_timed(&req.password, password_hash).await?;
            (Some(u), valid)
        }
        None => {
            // Prevent user enumeration via timing
            let _ = verify_password_timed(&req.password, dummy_password_hash()).await;
            (None, false)
        }
    };

    if !password_valid {
        return Err(ApiError::Unauthorized("Invalid username or password".into()));
    }

    let user = found_user.ok_or_else(|| ApiError::Unauthorized("Invalid username or password".into()))?;
    if is_disabled(&user) {
        return Err(ApiError::Unauthorized("Invalid username or password".into()));
    }

    let token = state
        .jwt_service
        .sign_with_session_generation(
            &user.id,
            user.username.as_deref().unwrap_or("external_user"),
            user.session_generation,
        )
        .map_err(|e| ApiError::Internal(format!("Token signing error: {e}")))?;

    // Update last login (best-effort)
    if let Err(e) = state.user_repo.update_last_login(&user.id).await {
        tracing::warn!("Failed to update last login for {}: {e}", user.id);
    }

    let cookie = state.cookie_config.build_session_cookie(&token);
    let resp = LoginResponse::new(public_user_from_user(user), token);

    Ok(([(header::SET_COOKIE, cookie)], Json(resp)).into_response())
}

// ---------------------------------------------------------------------------
// POST /logout
// ---------------------------------------------------------------------------

async fn logout_handler(State(state): State<AuthRouterState>, headers: HeaderMap) -> Result<Response, ApiError> {
    if let Some(token) = extract_token_from_headers(&headers) {
        // Decode the presented token so we can drop the matching Auth
        // Center token bundle by the token's fingerprint. If the token is
        // already blacklisted (e.g. the user logged out twice) verify
        // returns TokenBlacklisted and we skip the clear — the prior
        // logout already drained the bundle and the blacklist is the
        // source of truth for an authenticated session. We must never log
        // the token, the fingerprint, or any other secret material.
        if let Ok(payload) = state.jwt_service.verify(&token) {
            let vault_key = AuthCenterTokenVaultKey::from_token(&token, &payload.user_id);
            let cleared = state.auth_center_token_vault.clear(&vault_key);
            if cleared {
                tracing::info!(
                    user_id = %payload.user_id,
                    "cleared stored Auth Center token bundle on logout"
                );
            }
            if let Err(error) = state
                .schedule_bff_config
                .dpop_key_store()
                .clear(&DpopKeySelector::new(&payload.user_id, &vault_key.token_fingerprint))
            {
                tracing::warn!(
                    user_id = %payload.user_id,
                    error = %error,
                    "failed to clear session DPoP key on logout"
                );
            }
        }
        state.jwt_service.blacklist_token(&token);
    }

    let cookie = state.cookie_config.clear_session_cookie();
    let resp = ApiResponse::message("Logged out successfully");

    Ok(([(header::SET_COOKIE, cookie)], Json(resp)).into_response())
}

// ---------------------------------------------------------------------------
// GET /api/auth/status
// ---------------------------------------------------------------------------

async fn status_handler(
    State(state): State<AuthRouterState>,
    headers: HeaderMap,
) -> Result<Json<AuthStatusResponse>, ApiError> {
    let has_users = state
        .user_repo
        .has_users()
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    let user_count = state
        .user_repo
        .count_users()
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    // Check authentication without requiring it
    let is_authenticated = extract_token_from_headers(&headers)
        .and_then(|token| state.jwt_service.verify(&token).ok())
        .is_some();

    Ok(Json(AuthStatusResponse {
        success: true,
        needs_setup: !has_users,
        user_count: user_count as u64,
        is_authenticated,
    }))
}

// ---------------------------------------------------------------------------
// Local-only internal user routes
// ---------------------------------------------------------------------------

async fn list_internal_users_handler(
    State(state): State<AuthRouterState>,
) -> Result<Json<ApiResponse<Vec<InternalUserResponse>>>, ApiError> {
    ensure_local_mode(state.local)?;
    let users = state.user_repo.list_users().await.map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(
        users.into_iter().map(InternalUserResponse::from).collect(),
    )))
}

async fn get_system_user_handler(
    State(state): State<AuthRouterState>,
) -> Result<Json<ApiResponse<Option<InternalUserResponse>>>, ApiError> {
    ensure_local_mode(state.local)?;
    let user = state.user_repo.get_system_user().await.map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(user.map(InternalUserResponse::from))))
}

async fn find_user_by_username_handler(
    State(state): State<AuthRouterState>,
    Path(username): Path<String>,
) -> Result<Json<ApiResponse<Option<InternalUserResponse>>>, ApiError> {
    ensure_local_mode(state.local)?;
    let user = state
        .user_repo
        .find_by_username(&username)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(user.map(InternalUserResponse::from))))
}

async fn find_user_by_id_handler(
    State(state): State<AuthRouterState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Option<InternalUserResponse>>>, ApiError> {
    ensure_local_mode(state.local)?;
    let user = state.user_repo.find_by_id(&id).await.map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(user.map(InternalUserResponse::from))))
}

async fn create_internal_user_handler(
    State(state): State<AuthRouterState>,
    body: Result<Json<CreateInternalUserRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<InternalUserResponse>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;
    let user = state
        .user_repo
        .create_user(&req.username, &req.password_hash)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(InternalUserResponse::from(user))))
}

async fn set_system_user_credentials_handler(
    State(state): State<AuthRouterState>,
    body: Result<Json<SetSystemUserCredentialsRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;
    state
        .user_repo
        .set_system_user_credentials(&req.username, &req.password_hash)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(())))
}

async fn update_user_password_hash_handler(
    State(state): State<AuthRouterState>,
    Path(id): Path<String>,
    body: Result<Json<UpdatePasswordHashRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;
    state
        .user_repo
        .update_password(&id, &req.password_hash)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(())))
}

async fn update_user_username_handler(
    State(state): State<AuthRouterState>,
    Path(id): Path<String>,
    body: Result<Json<UpdateUsernameRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;
    state
        .user_repo
        .update_username(&id, &req.username)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(())))
}

async fn update_user_jwt_secret_handler(
    State(state): State<AuthRouterState>,
    Path(id): Path<String>,
    body: Result<Json<UpdateJwtSecretRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;
    state
        .user_repo
        .update_jwt_secret(&id, &req.jwt_secret)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(())))
}

async fn update_user_last_login_handler(
    State(state): State<AuthRouterState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_local_mode(state.local)?;
    state
        .user_repo
        .update_last_login(&id)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(())))
}

// ---------------------------------------------------------------------------
// GET /api/auth/user
// ---------------------------------------------------------------------------

async fn user_handler(
    State(state): State<AuthRouterState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<UserInfoResponse>, ApiError> {
    let user = state
        .user_repo
        .find_by_id(&user.id)
        .await
        .map_err(db_error_to_api_error)?
        .ok_or_else(|| ApiError::Unauthorized("Invalid authentication subject".into()))?;
    if is_disabled(&user) {
        return Err(ApiError::Forbidden("User is disabled".into()));
    }
    Ok(Json(UserInfoResponse {
        success: true,
        user: public_user_from_user(user),
    }))
}

// ---------------------------------------------------------------------------
// POST /api/auth/change-password
// ---------------------------------------------------------------------------

async fn change_password_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    body: Result<Json<ChangePasswordRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;

    // Validate new password strength
    validate_password(&req.new_password)?;

    // Fetch user record
    let user = state
        .user_repo
        .find_by_id(&current_user.id)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| ApiError::NotFound("User not found".into()))?;

    // Verify current password
    let Some(password_hash) = user.password_hash.as_deref() else {
        return Err(ApiError::Unauthorized("Current password is incorrect".into()));
    };
    let valid = verify_password_timed(&req.current_password, password_hash).await?;
    if !valid {
        return Err(ApiError::Unauthorized("Current password is incorrect".into()));
    }

    // Hash new password on blocking thread
    let password = req.new_password.clone();
    let new_hash = tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| ApiError::Internal(format!("Task join error: {e}")))??;

    // Persist new password hash
    state
        .user_repo
        .update_password(&current_user.id, &new_hash)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    // Rotate JWT secret to invalidate all sessions
    let new_secret = state
        .jwt_service
        .rotate_secret()
        .map_err(|e| ApiError::Internal(format!("Secret rotation error: {e}")))?;

    // Persist new secret to database
    state
        .user_repo
        .update_jwt_secret(&current_user.id, &new_secret)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    Ok(Json(ApiResponse::message("Password changed successfully")))
}

// ---------------------------------------------------------------------------
// POST /api/auth/refresh
// ---------------------------------------------------------------------------

async fn refresh_handler(
    State(state): State<AuthRouterState>,
    body: Result<Json<RefreshTokenRequest>, JsonRejection>,
) -> Result<Json<RefreshResponse>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;

    let payload = state
        .jwt_service
        .verify(&req.token)
        .map_err(|_| ApiError::Unauthorized("Invalid or expired token".into()))?;

    let user = state
        .user_repo
        .find_active_by_id(&payload.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "refresh token user lookup failed");
            ApiError::Internal("Authentication service unavailable".into())
        })?
        .ok_or_else(|| ApiError::Unauthorized("Invalid authentication subject".into()))?;

    if state.aionpro_mode && user.user_type != aionui_db::UserType::Aionpro {
        return Err(user_context_required());
    }

    if payload.session_generation != user.session_generation {
        return Err(ApiError::Unauthorized("Invalid authentication session".into()));
    }

    let new_token = if payload.auth_center_bound {
        state.jwt_service.sign_auth_center_bound(
            &user.id,
            user.username.as_deref().unwrap_or("external_user"),
            user.session_generation,
        )
    } else {
        state.jwt_service.sign_with_session_generation(
            &user.id,
            user.username.as_deref().unwrap_or("external_user"),
            user.session_generation,
        )
    }
    .map_err(|e| ApiError::Internal(format!("Token signing error: {e}")))?;

    // The local JWT is being rotated, so the bundle must follow. Move it
    // from the presented token's fingerprint to the new token's fingerprint
    // atomically so the session is not orphaned. We must never log the
    // tokens, the fingerprints, or the bundle itself.
    let old_vault_key = AuthCenterTokenVaultKey::from_token(&req.token, &user.id);
    let new_vault_key = AuthCenterTokenVaultKey::from_token(&new_token, &user.id);
    let moved = state
        .auth_center_token_vault
        .move_bundle(&old_vault_key, new_vault_key.clone());
    if payload.auth_center_bound && moved.is_none() {
        state.jwt_service.blacklist_token(&req.token);
        return Err(ApiError::Unauthorized("Authentication session must be renewed".into()));
    }
    if moved.is_none() {
        tracing::debug!(
            user_id = %user.id,
            "refresh: no Auth Center token bundle to move (new login or first refresh)"
        );
    }
    if payload.auth_center_bound && moved.is_some() {
        // The DPoP key bound to the old fingerprint must follow the bundle,
        // or every later ACP proof for this session would fail closed.
        if let Err(error) = state.schedule_bff_config.dpop_key_store().move_key(
            &DpopKeySelector::new(&user.id, &old_vault_key.token_fingerprint),
            &DpopKeySelector::new(&user.id, &new_vault_key.token_fingerprint),
        ) {
            state.jwt_service.blacklist_token(&new_token);
            tracing::error!(user_id = %user.id, error = %error, "failed to move DPoP key on refresh");
            return Err(ApiError::Internal("DPoP key rotation failed".into()));
        }
    }
    state.jwt_service.blacklist_token(&req.token);

    Ok(Json(RefreshResponse {
        success: true,
        token: new_token,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/ws-token
// ---------------------------------------------------------------------------

async fn ws_token_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    headers: HeaderMap,
) -> Result<Json<WsTokenResponse>, ApiError> {
    // Reuse the existing session token for WebSocket connections
    let token = extract_token_from_headers(&headers).ok_or_else(|| ApiError::Unauthorized("No token found".into()))?;

    // Ensure user still exists
    state
        .user_repo
        .find_by_id(&current_user.id)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| ApiError::Unauthorized("User not found".into()))?;

    // Cookie max age in milliseconds
    let expires_in = u64::from(COOKIE_MAX_AGE_DAYS) * 24 * 60 * 60 * 1000;

    Ok(Json(WsTokenResponse {
        success: true,
        ws_token: token,
        expires_in,
    }))
}

// ---------------------------------------------------------------------------
// IAM admin routes
// ---------------------------------------------------------------------------

async fn list_iam_users_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<Vec<IamUserSummary>>>, ApiError> {
    ensure_admin(&current_user)?;
    let users = state.iam_repo.list_users().await.map_err(db_error_to_api_error)?;
    let orgs_by_id: HashMap<String, IamOrganizationSummary> = state
        .iam_repo
        .list_organizations()
        .await
        .map_err(db_error_to_api_error)?
        .into_iter()
        .map(|org| {
            let summary = organization_summary(org);
            (summary.id.clone(), summary)
        })
        .collect();
    let mut orgs_by_user: HashMap<String, Vec<IamOrganizationSummary>> = HashMap::new();
    for relation in state
        .iam_repo
        .list_all_user_organizations()
        .await
        .map_err(db_error_to_api_error)?
    {
        if let Some(org) = orgs_by_id.get(&relation.organization_id) {
            orgs_by_user.entry(relation.user_id).or_default().push(org.clone());
        }
    }
    let summaries = users
        .into_iter()
        .map(|user| {
            let organizations = orgs_by_user.remove(&user.id).unwrap_or_default();
            user_summary(user, organizations)
        })
        .collect();
    Ok(Json(ApiResponse::ok(summaries)))
}

async fn create_iam_user_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    body: Result<Json<IamCreateUserRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<IamCreateUserResponse>>, ApiError> {
    ensure_admin(&current_user)?;
    let Json(req) = body.map_err(ApiError::from)?;
    let username = req.username.trim().to_owned();
    validate_username(&username)?;
    let status = normalize_status(req.status.as_deref())?.unwrap_or("active");
    let temporary_password = generate_password(RESET_PASSWORD_LEN);
    let password_for_hash = temporary_password.clone();
    let password_hash = tokio::task::spawn_blocking(move || hash_password(&password_for_hash))
        .await
        .map_err(|e| ApiError::Internal(format!("Task join error: {e}")))??;

    let user = state
        .iam_repo
        .create_local_user(CreateLocalUserParams {
            username: &username,
            password_hash: &password_hash,
            display_name: req.display_name.as_deref(),
            email: req.email.as_deref(),
            mobile: req.mobile.as_deref(),
            status,
            is_admin: req.is_admin.unwrap_or(false),
        })
        .await
        .map_err(db_error_to_api_error)?;
    if let Some(organization_ids) = req.organization_ids.as_ref() {
        state
            .iam_repo
            .replace_local_user_organizations(&user.id, organization_ids)
            .await
            .map_err(db_error_to_api_error)?;
    }
    let user = state
        .iam_repo
        .get_user(&user.id)
        .await
        .map_err(db_error_to_api_error)?
        .ok_or_else(|| ApiError::NotFound("Created user not found".into()))?;
    let summary = load_user_summary(&*state.iam_repo, user).await?;
    Ok(Json(ApiResponse::ok(IamCreateUserResponse {
        user: summary,
        temporary_password,
    })))
}

async fn update_iam_user_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    body: Result<Json<IamUpdateUserRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<IamUserSummary>>, ApiError> {
    ensure_admin(&current_user)?;
    let Json(req) = body.map_err(ApiError::from)?;
    let existing = state
        .iam_repo
        .get_user(&id)
        .await
        .map_err(db_error_to_api_error)?
        .ok_or_else(|| ApiError::NotFound(format!("User '{id}' not found")))?;
    let status = normalize_status(req.status.as_deref())?;

    if existing.source == "auth_center"
        && (req.display_name.is_some() || req.email.is_some() || req.mobile.is_some() || req.organization_ids.is_some())
    {
        return Err(ApiError::BadRequest(
            "Auth Center users only allow local policy fields".into(),
        ));
    }

    let disables_active_admin = existing.is_admin != 0
        && existing.status == UserStatus::Active
        && (status == Some("disabled") || req.is_admin == Some(false));
    if disables_active_admin
        && state
            .iam_repo
            .count_active_admins_except(Some(&id))
            .await
            .map_err(db_error_to_api_error)?
            == 0
    {
        return Err(ApiError::Conflict(
            "The last active administrator cannot be disabled or demoted".into(),
        ));
    }

    let user = state
        .iam_repo
        .update_user(
            &id,
            UpdateUserParams {
                display_name: req.display_name.as_deref(),
                email: req.email.as_deref(),
                mobile: req.mobile.as_deref(),
                status,
                is_admin: req.is_admin,
            },
        )
        .await
        .map_err(db_error_to_api_error)?;
    if existing.source == "local"
        && let Some(organization_ids) = req.organization_ids.as_ref()
    {
        state
            .iam_repo
            .replace_local_user_organizations(&id, organization_ids)
            .await
            .map_err(db_error_to_api_error)?;
    }
    let summary = load_user_summary(&*state.iam_repo, user).await?;
    Ok(Json(ApiResponse::ok(summary)))
}

async fn reset_iam_user_password_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<IamResetPasswordResponse>>, ApiError> {
    ensure_admin(&current_user)?;
    let user = state
        .iam_repo
        .get_user(&id)
        .await
        .map_err(db_error_to_api_error)?
        .ok_or_else(|| ApiError::NotFound(format!("User '{id}' not found")))?;
    if user.source != "local" {
        return Err(ApiError::BadRequest(
            "Auth Center users do not have local passwords".into(),
        ));
    }
    let temporary_password = generate_password(RESET_PASSWORD_LEN);
    let password_for_hash = temporary_password.clone();
    let password_hash = tokio::task::spawn_blocking(move || hash_password(&password_for_hash))
        .await
        .map_err(|e| ApiError::Internal(format!("Task join error: {e}")))??;
    state
        .iam_repo
        .reset_user_password(&id, &password_hash)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(IamResetPasswordResponse { temporary_password })))
}

async fn list_iam_organizations_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<Vec<IamOrganizationSummary>>>, ApiError> {
    ensure_admin(&current_user)?;
    let organizations = state
        .iam_repo
        .list_organizations()
        .await
        .map_err(db_error_to_api_error)?
        .into_iter()
        .map(organization_summary)
        .collect();
    Ok(Json(ApiResponse::ok(organizations)))
}

async fn create_iam_organization_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    body: Result<Json<IamCreateOrganizationRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<IamOrganizationSummary>>, ApiError> {
    ensure_admin(&current_user)?;
    let Json(req) = body.map_err(ApiError::from)?;
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("Organization name is required".into()));
    }
    let status = normalize_status(req.status.as_deref())?.unwrap_or("active");
    let organization = state
        .iam_repo
        .create_local_organization(CreateOrganizationParams {
            parent_id: req.parent_id.as_deref().filter(|value| !value.trim().is_empty()),
            name,
            status,
            sort: req.sort.unwrap_or(0),
        })
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(organization_summary(organization))))
}

async fn update_iam_organization_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    body: Result<Json<IamUpdateOrganizationRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<IamOrganizationSummary>>, ApiError> {
    ensure_admin(&current_user)?;
    let Json(req) = body.map_err(ApiError::from)?;
    if matches!(&req.parent_id, NullableStringUpdate::Value(parent_id) if parent_id == &id) {
        return Err(ApiError::BadRequest("Organization cannot be its own parent".into()));
    }
    if let Some(name) = req.name.as_deref()
        && name.trim().is_empty()
    {
        return Err(ApiError::BadRequest("Organization name is required".into()));
    }
    let organization = state
        .iam_repo
        .update_local_organization(
            &id,
            UpdateOrganizationParams {
                parent_id: match &req.parent_id {
                    NullableStringUpdate::Missing => None,
                    NullableStringUpdate::Null => Some(None),
                    NullableStringUpdate::Value(parent_id) => Some(non_empty_trimmed(parent_id)),
                },
                name: req.name.as_deref().map(str::trim),
                status: normalize_status(req.status.as_deref())?,
                sort: req.sort,
            },
        )
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(organization_summary(organization))))
}

async fn delete_iam_organization_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_admin(&current_user)?;
    state
        .iam_repo
        .delete_local_organization(&id)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(())))
}

async fn directory_sync_status_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<Option<IamDirectorySyncState>>>, ApiError> {
    ensure_admin(&current_user)?;
    let sync_state = state
        .iam_repo
        .directory_sync_state(&state.rsm_auth_config.app_code)
        .await
        .map_err(db_error_to_api_error)?
        .map(directory_sync_state_summary);
    Ok(Json(ApiResponse::ok(sync_state)))
}

async fn directory_sync_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    body: Result<Json<IamDirectorySyncRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<IamDirectorySyncResult>>, ApiError> {
    ensure_admin(&current_user)?;
    let Json(req) = body.map_err(ApiError::from)?;
    let full = req.full.unwrap_or(false);
    let result = run_directory_sync(&state, full).await?;
    Ok(Json(ApiResponse::ok(result)))
}

async fn run_directory_sync(state: &AuthRouterState, full: bool) -> Result<IamDirectorySyncResult, ApiError> {
    match try_run_directory_sync(state, full).await {
        Ok(result) => Ok(result),
        Err(error) => {
            if let Err(save_error) = state
                .iam_repo
                .save_directory_sync_state(
                    &state.rsm_auth_config.app_code,
                    full,
                    "failed",
                    Some(&directory_sync_failure_message(&error)),
                    SyncCounts::default(),
                )
                .await
            {
                tracing::warn!(
                    error = ?save_error,
                    "failed to persist Auth Center directory sync failure state"
                );
            }
            Err(error)
        }
    }
}

async fn try_run_directory_sync(state: &AuthRouterState, full: bool) -> Result<IamDirectorySyncResult, ApiError> {
    let previous = state
        .iam_repo
        .directory_sync_state(&state.rsm_auth_config.app_code)
        .await
        .map_err(db_error_to_api_error)?;
    let since = if full {
        None
    } else {
        previous.and_then(|state| state.last_synced_at)
    };
    let client = AuthCenterProtocolClient::new(state.http_client.clone());
    let departments = client.list_directory_departments(&state.rsm_auth_config, since).await?;
    let users = client.list_directory_users(&state.rsm_auth_config, since).await?;

    let mut counts = SyncCounts {
        department_count: departments.len() as i64,
        user_count: users.len() as i64,
        ..SyncCounts::default()
    };

    upsert_directory_departments(&*state.iam_repo, &departments).await?;

    let mut seen_external_ids = Vec::new();
    for directory_user in users {
        if directory_user.id.trim().is_empty() {
            continue;
        }
        let username = directory_user_username(&directory_user);
        let departments_json = if directory_user.departments.is_empty() {
            None
        } else {
            Some(
                serde_json::to_string(&directory_user.departments)
                    .map_err(|e| ApiError::Internal(format!("Failed to serialize departments: {e}")))?,
            )
        };
        let (user, created) = state
            .iam_repo
            .upsert_external_user(UpsertExternalUserParams {
                external_id: &directory_user.id,
                username: &username,
                display_name: directory_user.display_name.as_deref(),
                email: directory_user.email.as_deref(),
                mobile: directory_user.mobile.as_deref(),
                position: directory_user.position.as_deref(),
                position_sort: directory_user.position_sort,
                departments_json: departments_json.as_deref(),
                auth_source: directory_user.source.as_deref().or(Some("auth-center-directory")),
                app_code: &state.rsm_auth_config.app_code,
                external_status: Some(directory_status_to_local_status(directory_user.status.as_deref())),
                external_updated_at: timestamp_rfc3339_to_ms(directory_user.updated_at.as_deref()),
                is_admin: directory_user_is_admin(&directory_user, &state.rsm_auth_config.app_code),
            })
            .await
            .map_err(db_error_to_api_error)?;
        state
            .iam_repo
            .replace_external_user_organizations(&user.id, &directory_user.departments)
            .await
            .map_err(db_error_to_api_error)?;
        if created {
            counts.user_created += 1;
        } else {
            counts.user_updated += 1;
        }
        seen_external_ids.push(directory_user.id);
    }

    if full {
        counts.user_disabled = state
            .iam_repo
            .disable_missing_external_users(&seen_external_ids)
            .await
            .map_err(db_error_to_api_error)?;
    }

    let sync_state = state
        .iam_repo
        .save_directory_sync_state(&state.rsm_auth_config.app_code, full, "success", None, counts)
        .await
        .map_err(db_error_to_api_error)?;

    Ok(IamDirectorySyncResult {
        app_code: sync_state.app_code,
        full,
        user_count: sync_state.user_count,
        department_count: sync_state.department_count,
        user_created: counts.user_created,
        user_updated: counts.user_updated,
        user_disabled: counts.user_disabled,
        synced_at: sync_state.updated_at,
    })
}

fn directory_sync_failure_message(error: &ApiError) -> String {
    const MAX_MESSAGE_LEN: usize = 512;
    let message = error.to_string();
    if message.len() <= MAX_MESSAGE_LEN {
        return message;
    }
    message.chars().take(MAX_MESSAGE_LEN).collect()
}

async fn upsert_directory_departments(
    iam_repo: &dyn IIamRepository,
    departments: &[DirectoryDepartment],
) -> Result<(), ApiError> {
    for _ in 0..2 {
        for department in departments {
            if department.id.trim().is_empty() || department.name.trim().is_empty() {
                continue;
            }
            iam_repo
                .upsert_external_organization(UpsertExternalOrganizationParams {
                    external_id: &department.id,
                    parent_external_id: department.parent_id.as_deref().filter(|value| !value.trim().is_empty()),
                    name: department.name.trim(),
                    status: directory_status_to_local_status(department.status.as_deref()),
                    sort: department.sort,
                })
                .await
                .map_err(db_error_to_api_error)?;
        }
    }
    Ok(())
}

fn directory_user_username(user: &DirectoryUser) -> String {
    let raw = user
        .username
        .as_deref()
        .or_else(|| user.email.as_deref().and_then(|value| value.split('@').next()))
        .or(user.display_name.as_deref())
        .unwrap_or(&user.id);
    sanitize_username(raw, &user.id)
}

fn non_empty_trimmed(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

// ---------------------------------------------------------------------------
// POST /api/auth/qr-login
// ---------------------------------------------------------------------------

async fn qr_login_handler(
    State(state): State<AuthRouterState>,
    body: Result<Json<QrLoginRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    if state.aionpro_mode {
        return Err(user_context_required());
    }

    let Json(req) = body.map_err(ApiError::from)?;

    // Validate and consume QR token (one-time use)
    state.qr_token_store.validate_and_consume(&req.qr_token)?;

    // Get primary WebUI user for QR login
    let user = state
        .user_repo
        .get_primary_webui_user()
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| ApiError::Internal("No primary user configured".into()))?;

    let token = state
        .jwt_service
        .sign_with_session_generation(
            &user.id,
            user.username.as_deref().unwrap_or("external_user"),
            user.session_generation,
        )
        .map_err(|e| ApiError::Internal(format!("Token signing error: {e}")))?;

    // Update last login (best-effort)
    if let Err(e) = state.user_repo.update_last_login(&user.id).await {
        tracing::warn!("Failed to update last login for {}: {e}", user.id);
    }

    let cookie = state.cookie_config.build_session_cookie(&token);
    let resp = LoginResponse::new(public_user_from_user(user), token);

    Ok(([(header::SET_COOKIE, cookie)], Json(resp)).into_response())
}

// ---------------------------------------------------------------------------
// GET /qr-login (static HTML page)
// ---------------------------------------------------------------------------

async fn qr_login_page() -> Html<&'static str> {
    Html(QR_LOGIN_HTML)
}

const QR_LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>QR Login - AionUI</title>
<style>
  body { font-family: system-ui, sans-serif; display: flex; justify-content: center;
         align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }
  .card { background: white; padding: 2rem; border-radius: 8px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; max-width: 400px; }
  .status { margin-top: 1rem; color: #666; }
  .error { color: #d32f2f; }
  .success { color: #388e3c; }
</style>
</head>
<body>
<div class="card">
  <h1>AionUI</h1>
  <p id="status" class="status">Processing login...</p>
</div>
<script>
(function() {
  var el = document.getElementById('status');
  var params = new URLSearchParams(window.location.search);
  var token = params.get('token');
  if (!token) {
    el.textContent = 'Error: No token provided';
    el.className = 'status error';
    return;
  }
  fetch('/api/auth/qr-login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ qrToken: token })
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    if (data.success) {
      el.textContent = 'Login successful! Redirecting...';
      el.className = 'status success';
      setTimeout(function() { window.location.href = '/'; }, 1000);
    } else {
      el.textContent = 'Login failed: ' + (data.error || 'Unknown error');
      el.className = 'status error';
    }
  })
  .catch(function(err) {
    el.textContent = 'Error: ' + err.message;
    el.className = 'status error';
  });
})();
</script>
</body>
</html>"#;

// ---------------------------------------------------------------------------
// WebUI admin credential endpoints (local-only)
// ---------------------------------------------------------------------------

/// Random password length for `/api/webui/reset-password`.
const RESET_PASSWORD_LEN: usize = 16;

/// Resolve the WebUI admin user, falling back to NotFound when absent.
async fn resolve_webui_admin(user_repo: &dyn IUserRepository) -> Result<User, ApiError> {
    user_repo
        .get_primary_webui_user()
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| ApiError::NotFound("No WebUI admin user configured".into()))
}

// ---------------------------------------------------------------------------
// POST /api/webui/change-password
// ---------------------------------------------------------------------------

async fn webui_change_password_handler(
    State(state): State<AuthRouterState>,
    body: Result<Json<WebuiChangePasswordRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;

    validate_password(&req.new_password)?;

    let user = resolve_webui_admin(&*state.user_repo).await?;

    let password = req.new_password;
    let new_hash = tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| ApiError::Internal(format!("Task join error: {e}")))??;

    state
        .user_repo
        .update_password(&user.id, &new_hash)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    Ok(Json(ApiResponse::message("Password changed successfully")))
}

// ---------------------------------------------------------------------------
// POST /api/webui/change-username
// ---------------------------------------------------------------------------

async fn webui_change_username_handler(
    State(state): State<AuthRouterState>,
    body: Result<Json<WebuiChangeUsernameRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<WebuiChangeUsernameResponse>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;

    let trimmed = req.new_username.trim().to_owned();
    validate_username(&trimmed)?;

    let user = resolve_webui_admin(&*state.user_repo).await?;

    if user.username.as_deref() != Some(trimmed.as_str()) {
        state
            .user_repo
            .update_username(&user.id, &trimmed)
            .await
            .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;
    }

    Ok(Json(ApiResponse::ok(WebuiChangeUsernameResponse { username: trimmed })))
}

// ---------------------------------------------------------------------------
// POST /api/webui/reset-password
// ---------------------------------------------------------------------------

async fn webui_reset_password_handler(
    State(state): State<AuthRouterState>,
) -> Result<Json<ApiResponse<WebuiResetPasswordResponse>>, ApiError> {
    ensure_local_mode(state.local)?;

    let user = resolve_webui_admin(&*state.user_repo).await?;

    let new_password = generate_password(RESET_PASSWORD_LEN);
    let password_for_hash = new_password.clone();
    let new_hash = tokio::task::spawn_blocking(move || hash_password(&password_for_hash))
        .await
        .map_err(|e| ApiError::Internal(format!("Task join error: {e}")))??;

    state
        .user_repo
        .update_password(&user.id, &new_hash)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    Ok(Json(ApiResponse::ok(WebuiResetPasswordResponse { new_password })))
}

// ---------------------------------------------------------------------------
// POST /api/webui/generate-qr-token
// ---------------------------------------------------------------------------

async fn webui_generate_qr_token_handler(
    State(state): State<AuthRouterState>,
) -> Result<Json<ApiResponse<WebuiGenerateQrTokenResponse>>, ApiError> {
    ensure_local_mode(state.local)?;

    let (token, expires_at_ms) = state.qr_token_store.generate_with_expiry();

    Ok(Json(ApiResponse::ok(WebuiGenerateQrTokenResponse {
        token,
        expires_at_ms,
    })))
}

#[cfg(test)]
mod error_mapping_tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn invalid_credentials_maps_to_unauthorized() {
        let api_err = ApiError::from(AuthError::InvalidCredentials);
        assert_eq!(api_err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn weak_password_maps_to_bad_request() {
        let api_err = ApiError::from(AuthError::WeakPassword("too short".into()));
        assert_eq!(api_err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn invalid_username_maps_to_bad_request() {
        let api_err = ApiError::from(AuthError::InvalidUsername("bad chars".into()));
        assert_eq!(api_err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn token_expired_maps_to_unauthorized() {
        let api_err = ApiError::from(AuthError::TokenExpired);
        assert_eq!(api_err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn token_invalid_maps_to_unauthorized() {
        let api_err = ApiError::from(AuthError::TokenInvalid("bad".into()));
        assert_eq!(api_err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn token_blacklisted_maps_to_unauthorized() {
        let api_err = ApiError::from(AuthError::TokenBlacklisted);
        assert_eq!(api_err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn rate_limited_maps_to_rate_limited() {
        let api_err = ApiError::from(AuthError::RateLimited);
        assert_eq!(api_err.status_code(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn hash_error_maps_to_internal() {
        let api_err = ApiError::from(AuthError::HashError("failed".into()));
        assert_eq!(api_err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
