//! Same-origin Schedule BFF transport.
//!
//! This module is intentionally a closed, route-level adapter rather than a
//! general reverse proxy. Browser credentials authenticate the local AionCore
//! request only. The downstream Agent Control Plane request is rebuilt from a
//! fixed route allowlist and uses only the Auth Center access token stored in
//! the server-side token vault.

#![allow(clippy::disallowed_types)] // This module is an HTTP boundary, like routes.rs.

use std::time::Duration;

use axum::body::to_bytes;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderName, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;

use aionui_api_types::ApiResponse;
use aionui_common::ApiError;

use crate::auth_center_tokens::AuthCenterTokenVaultKey;
use crate::extract::extract_token_from_headers;
use crate::middleware::CurrentUser;
use crate::routes::AuthRouterState;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 2 * 1024 * 1024;
const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");
const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
const IDEMPOTENT_REPLAY: HeaderName = HeaderName::from_static("idempotent-replay");

/// Fail-closed Schedule BFF configuration.
///
/// A missing base URL leaves the transport disabled. A present but invalid URL
/// is a startup configuration error; it is never silently replaced with a
/// default upstream.
#[derive(Debug, Clone)]
pub struct ScheduleBffConfig {
    base_url: Option<Url>,
    timeout: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum ScheduleBffConfigError {
    #[error("Agent Control Plane base URL is invalid")]
    InvalidBaseUrl,
    #[error("Agent Control Plane base URL must use http or https")]
    InvalidScheme,
    #[error("Agent Control Plane base URL must not contain credentials, query, or fragment components")]
    InvalidBaseUrlComponents,
    #[error("Schedule BFF timeout must be a positive integer number of milliseconds")]
    InvalidTimeout,
}

impl ScheduleBffConfig {
    pub fn disabled() -> Self {
        Self {
            base_url: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn new(base_url: impl AsRef<str>, timeout: Duration) -> Result<Self, ScheduleBffConfigError> {
        if timeout.is_zero() {
            return Err(ScheduleBffConfigError::InvalidTimeout);
        }
        let mut base_url = Url::parse(base_url.as_ref()).map_err(|_| ScheduleBffConfigError::InvalidBaseUrl)?;
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(ScheduleBffConfigError::InvalidScheme);
        }
        if !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(ScheduleBffConfigError::InvalidBaseUrlComponents);
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        Ok(Self {
            base_url: Some(base_url),
            timeout,
        })
    }

    pub fn from_env() -> Result<Self, ScheduleBffConfigError> {
        let base_url = ["RSM_AGENT_CONTROL_PLANE_BASE_URL", "AGENT_CONTROL_PLANE_BASE_URL"]
            .into_iter()
            .find_map(|name| std::env::var(name).ok())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let Some(base_url) = base_url else {
            return Ok(Self::disabled());
        };
        let timeout = match std::env::var("RSM_SCHEDULE_BFF_TIMEOUT_MS") {
            Ok(value) => {
                let millis = value
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .filter(|millis| *millis > 0)
                    .ok_or(ScheduleBffConfigError::InvalidTimeout)?;
                Duration::from_millis(millis)
            }
            Err(_) => DEFAULT_TIMEOUT,
        };
        Self::new(base_url, timeout)
    }

    fn upstream_url(&self, route: &ScheduleRoute, query: Option<&str>) -> Result<Url, ApiError> {
        let base_url = self.base_url.as_ref().ok_or_else(|| {
            ApiError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                "SCHEDULE_UPSTREAM_NOT_CONFIGURED",
                "Scheduled tasks are not configured.",
                None,
            )
        })?;
        let mut url = base_url.clone();
        let mut segments = url.path_segments_mut().map_err(|_| {
            ApiError::coded(
                StatusCode::BAD_GATEWAY,
                "SCHEDULE_UPSTREAM_UNAVAILABLE",
                "Scheduled tasks are temporarily unavailable.",
                None,
            )
        })?;
        segments.pop_if_empty();
        segments.extend(["api", "schedule", "v1", "schedules"]);
        match route {
            ScheduleRoute::Collection => {}
            ScheduleRoute::Schedule { schedule_id } => {
                segments.push(schedule_id);
            }
            ScheduleRoute::Action { schedule_id, action } => {
                segments.push(schedule_id);
                segments.push(action.as_segment());
            }
            ScheduleRoute::Runs { schedule_id } => {
                segments.push(schedule_id);
                segments.push("runs");
            }
            ScheduleRoute::Run { schedule_id, run_id } => {
                segments.push(schedule_id);
                segments.push("runs");
                segments.push(run_id);
            }
        }
        drop(segments);
        url.set_query(query);
        Ok(url)
    }
}

#[derive(Debug)]
enum ScheduleAction {
    Upgrade,
    Pause,
    Resume,
    Retire,
}

impl ScheduleAction {
    fn as_segment(&self) -> &'static str {
        match self {
            Self::Upgrade => "upgrade",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Retire => "retire",
        }
    }
}

#[derive(Debug)]
enum ScheduleRoute {
    Collection,
    Schedule {
        schedule_id: String,
    },
    Action {
        schedule_id: String,
        action: ScheduleAction,
    },
    Runs {
        schedule_id: String,
    },
    Run {
        schedule_id: String,
        run_id: String,
    },
}

impl ScheduleRoute {
    fn permits(&self, method: &Method) -> bool {
        match self {
            Self::Collection => matches!(*method, Method::GET | Method::POST),
            Self::Schedule { .. } | Self::Runs { .. } | Self::Run { .. } => *method == Method::GET,
            Self::Action { .. } => *method == Method::POST,
        }
    }
}

/// The only Schedule paths that AionCore will forward.
pub(crate) fn schedule_bff_routes() -> Router<AuthRouterState> {
    Router::new()
        .route(
            "/api/schedule/v1/schedules",
            get(proxy_collection).post(proxy_collection),
        )
        .route("/api/schedule/v1/schedules/{schedule_id}", get(proxy_schedule_item))
        .route("/api/schedule/v1/schedules/{schedule_id}/upgrade", post(proxy_upgrade))
        .route("/api/schedule/v1/schedules/{schedule_id}/pause", post(proxy_pause))
        .route("/api/schedule/v1/schedules/{schedule_id}/resume", post(proxy_resume))
        .route("/api/schedule/v1/schedules/{schedule_id}/retire", post(proxy_retire))
        .route("/api/schedule/v1/schedules/{schedule_id}/runs", get(proxy_runs))
        .route("/api/schedule/v1/schedules/{schedule_id}/runs/{run_id}", get(proxy_run))
}

async fn proxy_collection(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    request: Request,
) -> Response {
    proxy_response(state, current_user, ScheduleRoute::Collection, request).await
}

async fn proxy_schedule_item(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(schedule_id): Path<String>,
    request: Request,
) -> Response {
    proxy_response(
        state,
        current_user,
        ScheduleRoute::Schedule {
            schedule_id: match validate_id(schedule_id, "schedule_id") {
                Ok(id) => id,
                Err(error) => return error.into_response(),
            },
        },
        request,
    )
    .await
}

async fn proxy_upgrade(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(schedule_id): Path<String>,
    request: Request,
) -> Response {
    proxy_action(state, current_user, schedule_id, ScheduleAction::Upgrade, request).await
}

async fn proxy_pause(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(schedule_id): Path<String>,
    request: Request,
) -> Response {
    proxy_action(state, current_user, schedule_id, ScheduleAction::Pause, request).await
}

async fn proxy_resume(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(schedule_id): Path<String>,
    request: Request,
) -> Response {
    proxy_action(state, current_user, schedule_id, ScheduleAction::Resume, request).await
}

async fn proxy_retire(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(schedule_id): Path<String>,
    request: Request,
) -> Response {
    proxy_action(state, current_user, schedule_id, ScheduleAction::Retire, request).await
}

async fn proxy_action(
    state: AuthRouterState,
    current_user: CurrentUser,
    schedule_id: String,
    action: ScheduleAction,
    request: Request,
) -> Response {
    let schedule_id = match validate_id(schedule_id, "schedule_id") {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    proxy_response(
        state,
        current_user,
        ScheduleRoute::Action { schedule_id, action },
        request,
    )
    .await
}

async fn proxy_runs(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(schedule_id): Path<String>,
    request: Request,
) -> Response {
    let schedule_id = match validate_id(schedule_id, "schedule_id") {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    proxy_response(state, current_user, ScheduleRoute::Runs { schedule_id }, request).await
}

async fn proxy_run(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((schedule_id, run_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let schedule_id = match validate_id(schedule_id, "schedule_id") {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let run_id = match validate_id(run_id, "run_id") {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    proxy_response(state, current_user, ScheduleRoute::Run { schedule_id, run_id }, request).await
}

async fn proxy_response(
    state: AuthRouterState,
    current_user: CurrentUser,
    route: ScheduleRoute,
    request: Request,
) -> Response {
    match proxy_schedule_inner(state, current_user, route, request).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn proxy_schedule_inner(
    state: AuthRouterState,
    current_user: CurrentUser,
    route: ScheduleRoute,
    request: Request,
) -> Result<Response, ApiError> {
    let query = request.uri().query().map(str::to_owned);
    let (parts, body) = request.into_parts();
    let method = parts.method;
    let headers = parts.headers;
    if !route.permits(&method) {
        return Err(ApiError::coded(
            StatusCode::METHOD_NOT_ALLOWED,
            "METHOD_NOT_ALLOWED",
            "Method not allowed.",
            None,
        ));
    }
    let body = to_bytes(body, MAX_REQUEST_BODY_BYTES)
        .await
        .map_err(|_| ApiError::PayloadTooLarge("Schedule request body is too large".to_owned()))?;
    if method == Method::GET && !body.is_empty() {
        return Err(ApiError::BadRequest(
            "GET schedule requests must not include a body".to_owned(),
        ));
    }
    if !body.is_empty() && !is_json_content_type(&headers) {
        return Err(ApiError::UnsupportedMediaType(
            "Schedule request bodies must use application/json".to_owned(),
        ));
    }

    let local_token = extract_token_from_headers(&headers).ok_or_else(auth_center_session_required)?;
    let payload = state
        .jwt_service
        .verify(&local_token)
        .map_err(|_| auth_center_session_required())?;
    if !payload.auth_center_bound || payload.user_id != current_user.id {
        return Err(auth_center_session_required());
    }

    let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, &current_user.id);
    let bundle = state
        .auth_center_token_vault
        .get(&vault_key)
        .ok_or_else(auth_center_session_required)?;
    if bundle
        .expires_at_ms
        .is_some_and(|expires_at| expires_at <= chrono::Utc::now().timestamp_millis())
    {
        state.auth_center_token_vault.clear(&vault_key);
        return Err(auth_center_session_required());
    }

    let upstream_url = state.schedule_bff_config.upstream_url(&route, query.as_deref())?;
    let mut request = state
        .http_client
        .request(method, upstream_url)
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", bundle.access_token.expose()),
        )
        .header(header::ACCEPT, "application/json");
    if !body.is_empty() {
        request = request.header(header::CONTENT_TYPE, "application/json").body(body);
    }
    for name in [&IDEMPOTENCY_KEY, &REQUEST_ID] {
        if let Some(value) = headers.get(name) {
            request = request.header(name, value);
        }
    }

    let upstream = tokio::time::timeout(state.schedule_bff_config.timeout, async {
        let mut response = request.send().await.map_err(UpstreamReadError::Request)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BODY_BYTES as u64)
        {
            return Err(UpstreamReadError::TooLarge);
        }
        let status = response.status();
        let response_headers = response.headers().clone();
        let capacity = response
            .content_length()
            .map(|length| length.min(MAX_RESPONSE_BODY_BYTES as u64) as usize)
            .unwrap_or_default();
        let mut body = Vec::with_capacity(capacity);
        while let Some(chunk) = response.chunk().await.map_err(UpstreamReadError::Request)? {
            if chunk.len() > MAX_RESPONSE_BODY_BYTES.saturating_sub(body.len()) {
                return Err(UpstreamReadError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok((status, response_headers, body))
    })
    .await
    .map_err(|_| {
        ApiError::coded(
            StatusCode::GATEWAY_TIMEOUT,
            "SCHEDULE_UPSTREAM_TIMEOUT",
            "Scheduled tasks did not respond in time.",
            None,
        )
    })?
    .map_err(|error| match error {
        UpstreamReadError::Request(error) => {
            tracing::warn!(error = %error.without_url(), "schedule upstream request failed");
            ApiError::coded(
                StatusCode::BAD_GATEWAY,
                "SCHEDULE_UPSTREAM_UNAVAILABLE",
                "Scheduled tasks are temporarily unavailable.",
                None,
            )
        }
        UpstreamReadError::TooLarge => upstream_invalid_response(),
    })?;

    let (status, response_headers, response_body) = upstream;
    if status == StatusCode::UNAUTHORIZED {
        state.auth_center_token_vault.clear(&vault_key);
    }
    if !status.is_success() {
        return Err(map_upstream_error(status, &response_body));
    }

    let data: Value = serde_json::from_slice(&response_body).map_err(|_| upstream_invalid_response())?;
    let mut response = (status, Json(ApiResponse::ok(data))).into_response();
    copy_safe_response_header(&response_headers, response.headers_mut(), &REQUEST_ID);
    copy_safe_response_header(&response_headers, response.headers_mut(), &IDEMPOTENT_REPLAY);
    Ok(response)
}

enum UpstreamReadError {
    Request(reqwest::Error),
    TooLarge,
}

fn upstream_invalid_response() -> ApiError {
    ApiError::coded(
        StatusCode::BAD_GATEWAY,
        "SCHEDULE_UPSTREAM_INVALID_RESPONSE",
        "Scheduled tasks returned an invalid response.",
        None,
    )
}

fn validate_id(value: String, field: &'static str) -> Result<String, ApiError> {
    let valid = !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        return Ok(value);
    }
    Err(ApiError::coded(
        StatusCode::BAD_REQUEST,
        "SCHEDULE_INVALID_ID",
        format!("{field} is invalid."),
        None,
    ))
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
        })
}

fn copy_safe_response_header(source: &HeaderMap, destination: &mut HeaderMap, name: &HeaderName) {
    if let Some(value) = source.get(name) {
        destination.insert(name.clone(), value.clone());
    }
}

fn auth_center_session_required() -> ApiError {
    ApiError::coded(
        StatusCode::UNAUTHORIZED,
        "AUTH_CENTER_SESSION_REQUIRED",
        "Sign in again to use scheduled tasks.",
        None,
    )
}

#[derive(Debug, Deserialize)]
struct UpstreamErrorEnvelope {
    code: Option<String>,
}

fn map_upstream_error(status: StatusCode, body: &[u8]) -> ApiError {
    let upstream_code = serde_json::from_slice::<UpstreamErrorEnvelope>(body)
        .ok()
        .and_then(|envelope| envelope.code);
    match status {
        StatusCode::UNAUTHORIZED if upstream_code.as_deref() == Some("device_unbound") => ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "device_unbound",
            "Bind this device before using scheduled tasks.",
            None,
        ),
        StatusCode::UNAUTHORIZED => auth_center_session_required(),
        StatusCode::FORBIDDEN => ApiError::coded(
            StatusCode::FORBIDDEN,
            "SCHEDULE_FORBIDDEN",
            "You do not have permission to perform this scheduled task action.",
            None,
        ),
        StatusCode::CONFLICT => ApiError::coded(
            StatusCode::CONFLICT,
            "SCHEDULE_CONFLICT",
            "The scheduled task changed. Refresh and try again.",
            None,
        ),
        StatusCode::BAD_REQUEST => ApiError::coded(
            StatusCode::BAD_REQUEST,
            "SCHEDULE_BAD_REQUEST",
            "The scheduled task request is invalid.",
            None,
        ),
        StatusCode::NOT_FOUND => ApiError::coded(
            StatusCode::NOT_FOUND,
            "SCHEDULE_NOT_FOUND",
            "The scheduled task was not found.",
            None,
        ),
        StatusCode::TOO_MANY_REQUESTS => ApiError::coded(
            StatusCode::TOO_MANY_REQUESTS,
            "SCHEDULE_RATE_LIMITED",
            "Too many scheduled task requests. Try again later.",
            None,
        ),
        status if status.is_client_error() => ApiError::coded(
            StatusCode::BAD_GATEWAY,
            "SCHEDULE_UPSTREAM_REJECTED",
            "The scheduled task request could not be completed.",
            None,
        ),
        _ => ApiError::coded(
            StatusCode::BAD_GATEWAY,
            "SCHEDULE_UPSTREAM_UNAVAILABLE",
            "Scheduled tasks are temporarily unavailable.",
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_rejects_non_http_and_query_bearing_base_urls() {
        assert!(matches!(
            ScheduleBffConfig::new("file:///tmp/acp", Duration::from_secs(1)),
            Err(ScheduleBffConfigError::InvalidScheme)
        ));
        assert!(matches!(
            ScheduleBffConfig::new("https://acp.example/?secret=value", Duration::from_secs(1)),
            Err(ScheduleBffConfigError::InvalidBaseUrlComponents)
        ));
        assert!(matches!(
            ScheduleBffConfig::new("https://user:pass@acp.example", Duration::from_secs(1)),
            Err(ScheduleBffConfigError::InvalidBaseUrlComponents)
        ));
    }

    #[test]
    fn upstream_url_preserves_configured_path_prefix_and_request_query() {
        let config = ScheduleBffConfig::new("https://acp.example/internal", Duration::from_secs(1)).unwrap();
        assert_eq!(
            config
                .upstream_url(&ScheduleRoute::Collection, Some("page=2"))
                .unwrap()
                .as_str(),
            "https://acp.example/internal/api/schedule/v1/schedules?page=2"
        );
    }

    #[test]
    fn path_ids_accept_only_single_safe_segments() {
        for valid in ["schedule-1", "schedule_1", "01JABCDEF123"] {
            assert_eq!(validate_id(valid.to_owned(), "schedule_id").unwrap(), valid);
        }
        for invalid in ["", ".", "..", "schedule/other", "schedule%2Fother", "含中文"] {
            assert!(
                validate_id(invalid.to_owned(), "schedule_id").is_err(),
                "accepted {invalid:?}"
            );
        }
    }
}
