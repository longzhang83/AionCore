//! Same-origin Agent Control Plane BFF transport.
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

use crate::auth_center_client::RsmAuthConfig;
use crate::auth_center_tokens::AuthCenterTokenVaultKey;
use crate::extract::extract_token_from_headers;
use crate::middleware::CurrentUser;
use crate::routes::AuthRouterState;

mod route;
use route::{
    AcpRoute, CatalogRoute, ErrorDomain, PublishRequestAction, PublishRequestRoute, ReviewDocumentRoute,
    ScheduleAction, ScheduleRoute, ShareRoute, VersionRoute, WorkspaceRoute,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 2 * 1024 * 1024;
const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");
const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
const IDEMPOTENT_REPLAY: HeaderName = HeaderName::from_static("idempotent-replay");

/// Fail-closed Schedule BFF configuration.
///
/// A missing base URL leaves the transport disabled. When enabled, the Auth
/// Center OIDC client ID must match the audience enforced by the Agent Control
/// Plane, so a deployment mismatch fails at startup instead of on the first
/// proxied request. Invalid values are never replaced with defaults.
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
    #[error("Schedule BFF requires a ready Auth Center OIDC configuration")]
    AuthCenterOidcRequired,
    #[error("RSM_AGENT_CONTROL_PLANE_AUTH_AUDIENCE is required when Schedule BFF is enabled")]
    MissingAuthAudience,
    #[error("Schedule BFF OAuth client ID must match the Agent Control Plane auth audience")]
    AudienceClientMismatch,
}

impl ScheduleBffConfig {
    pub fn disabled() -> Self {
        Self {
            base_url: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    fn new_transport(base_url: impl AsRef<str>, timeout: Duration) -> Result<Self, ScheduleBffConfigError> {
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

    /// Builds an enabled transport from programmatic configuration while
    /// enforcing the same OIDC client/audience contract as [`Self::from_env`].
    pub fn new_with_identity_contract(
        base_url: impl AsRef<str>,
        timeout: Duration,
        rsm_auth_config: &RsmAuthConfig,
        expected_audience: Option<&str>,
    ) -> Result<Self, ScheduleBffConfigError> {
        if !rsm_auth_config.is_oidc_ready() {
            return Err(ScheduleBffConfigError::AuthCenterOidcRequired);
        }
        let expected_audience = expected_audience
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(ScheduleBffConfigError::MissingAuthAudience)?;
        let client_id = rsm_auth_config
            .client_id
            .as_deref()
            .ok_or(ScheduleBffConfigError::AuthCenterOidcRequired)?;
        if expected_audience != client_id {
            return Err(ScheduleBffConfigError::AudienceClientMismatch);
        }
        Self::new_transport(base_url, timeout)
    }

    fn from_values(
        base_url: Option<&str>,
        timeout: Duration,
        rsm_auth_config: &RsmAuthConfig,
        expected_audience: Option<&str>,
    ) -> Result<Self, ScheduleBffConfigError> {
        let Some(base_url) = base_url else {
            return Ok(Self::disabled());
        };
        Self::new_with_identity_contract(base_url, timeout, rsm_auth_config, expected_audience)
    }

    pub fn from_env(rsm_auth_config: &RsmAuthConfig) -> Result<Self, ScheduleBffConfigError> {
        let base_url = ["RSM_AGENT_CONTROL_PLANE_BASE_URL", "AGENT_CONTROL_PLANE_BASE_URL"]
            .into_iter()
            .find_map(|name| std::env::var(name).ok())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let Some(base_url) = base_url else {
            return Self::from_values(None, DEFAULT_TIMEOUT, rsm_auth_config, None);
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
        // Auth Center access tokens use the OAuth client ID as `aud`; ACP
        // verifies this exact configured audience before device/scope gates.
        let expected_audience = std::env::var("RSM_AGENT_CONTROL_PLANE_AUTH_AUDIENCE").ok();
        Self::from_values(Some(&base_url), timeout, rsm_auth_config, expected_audience.as_deref())
    }

    fn upstream_url(&self, route: &AcpRoute, query: Option<&str>) -> Result<Url, ApiError> {
        let domain = route.error_domain();
        let base_url = self.base_url.as_ref().ok_or_else(|| {
            ApiError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                domain.upstream_not_configured_code(),
                domain.not_configured_message(),
                None,
            )
        })?;
        let mut url = base_url.clone();
        let mut segments = url.path_segments_mut().map_err(|_| {
            ApiError::coded(
                StatusCode::BAD_GATEWAY,
                domain.upstream_unavailable_code(),
                domain.unavailable_message(),
                None,
            )
        })?;
        segments.pop_if_empty();
        for segment in route.upstream_segments() {
            segments.push(segment);
        }
        drop(segments);
        url.set_query(query);
        Ok(url)
    }
}

/// The only Agent Control Plane paths that AionCore will forward.
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
        .route("/api/catalog/v1/agents", get(proxy_catalog_agents))
        .route(
            "/api/catalog/v1/agents/{agent_id}/versions",
            get(proxy_catalog_agent_versions),
        )
        .route(
            "/api/catalog/v1/agents/{agent_id}/versions/{version_id}",
            get(proxy_catalog_agent_version),
        )
        .route("/api/catalog/v1/skills", get(proxy_catalog_skills))
        .route(
            "/api/catalog/v1/skills/{skill_id}/versions",
            get(proxy_catalog_skill_versions),
        )
        .route(
            "/api/catalog/v1/skills/{skill_id}/versions/{version_id}",
            get(proxy_catalog_skill_version),
        )
        .route("/api/team-workspace/v1/workspaces", get(proxy_workspaces))
        .route("/api/share/v1/shares", post(proxy_create_share))
        .route(
            "/api/version/v1/agents/{agent_id}/versions",
            post(proxy_agent_version_create),
        )
        .route(
            "/api/version/v1/agents/{agent_id}/versions/{version_id}/transition",
            post(proxy_agent_version_transition),
        )
        .route(
            "/api/version/v1/skills/{skill_id}/versions",
            post(proxy_skill_version_create),
        )
        .route(
            "/api/version/v1/skills/{skill_id}/versions/{version_id}/transition",
            post(proxy_skill_version_transition),
        )
        .route(
            "/api/publish-request/v1/requests",
            get(proxy_publish_requests).post(proxy_publish_requests),
        )
        .route(
            "/api/publish-request/v1/requests/{request_id}/withdraw",
            post(proxy_withdraw_publish_request),
        )
        .route(
            "/api/publish-request/v1/requests/{request_id}/resubmit",
            post(proxy_resubmit_publish_request),
        )
        .route("/api/review/v1/documents", get(proxy_review_documents))
        .route("/api/review/v1/documents/{document_id}", get(proxy_review_document))
        .route(
            "/api/review/v1/documents/{document_id}/drafts/{draft_id}",
            get(proxy_review_draft),
        )
}

async fn proxy_catalog_agents(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    request: Request,
) -> Response {
    proxy_response(state, current_user, AcpRoute::Catalog(CatalogRoute::Agents), request).await
}

async fn proxy_catalog_agent_version(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((agent_id, version_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let agent_id = match validate_id(agent_id, "agent_id", ErrorDomain::Catalog) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let version_id = match validate_id(version_id, "version_id", ErrorDomain::Catalog) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    proxy_response(
        state,
        current_user,
        AcpRoute::Catalog(CatalogRoute::AgentVersion { agent_id, version_id }),
        request,
    )
    .await
}

async fn proxy_catalog_agent_versions(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(agent_id): Path<String>,
    request: Request,
) -> Response {
    let agent_id = match validate_id(agent_id, "agent_id", ErrorDomain::Catalog) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    proxy_response(
        state,
        current_user,
        AcpRoute::Catalog(CatalogRoute::AgentVersions { agent_id }),
        request,
    )
    .await
}

async fn proxy_catalog_skills(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    request: Request,
) -> Response {
    proxy_response(state, current_user, AcpRoute::Catalog(CatalogRoute::Skills), request).await
}

async fn proxy_catalog_skill_version(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((skill_id, version_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let skill_id = match validate_id(skill_id, "skill_id", ErrorDomain::Catalog) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let version_id = match validate_id(version_id, "version_id", ErrorDomain::Catalog) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    proxy_response(
        state,
        current_user,
        AcpRoute::Catalog(CatalogRoute::SkillVersion { skill_id, version_id }),
        request,
    )
    .await
}

async fn proxy_catalog_skill_versions(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(skill_id): Path<String>,
    request: Request,
) -> Response {
    let skill_id = match validate_id(skill_id, "skill_id", ErrorDomain::Catalog) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    proxy_response(
        state,
        current_user,
        AcpRoute::Catalog(CatalogRoute::SkillVersions { skill_id }),
        request,
    )
    .await
}

async fn proxy_agent_version_create(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(agent_id): Path<String>,
    request: Request,
) -> Response {
    proxy_version_create(state, current_user, "agent_id", agent_id, request, true).await
}

async fn proxy_skill_version_create(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(skill_id): Path<String>,
    request: Request,
) -> Response {
    proxy_version_create(state, current_user, "skill_id", skill_id, request, false).await
}

async fn proxy_version_create(
    state: AuthRouterState,
    current_user: CurrentUser,
    asset_field: &'static str,
    asset_id: String,
    request: Request,
    is_agent: bool,
) -> Response {
    let asset_id = match validate_id(asset_id, asset_field, ErrorDomain::Version) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let route = if is_agent {
        VersionRoute::AgentCreate { agent_id: asset_id }
    } else {
        VersionRoute::SkillCreate { skill_id: asset_id }
    };
    proxy_response(state, current_user, AcpRoute::Version(route), request).await
}

async fn proxy_agent_version_transition(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((agent_id, version_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    proxy_version_transition(state, current_user, "agent_id", agent_id, version_id, request, true).await
}

async fn proxy_skill_version_transition(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((skill_id, version_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    proxy_version_transition(state, current_user, "skill_id", skill_id, version_id, request, false).await
}

async fn proxy_version_transition(
    state: AuthRouterState,
    current_user: CurrentUser,
    asset_field: &'static str,
    asset_id: String,
    version_id: String,
    request: Request,
    is_agent: bool,
) -> Response {
    let asset_id = match validate_id(asset_id, asset_field, ErrorDomain::Version) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let version_id = match validate_id(version_id, "version_id", ErrorDomain::Version) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let route = if is_agent {
        VersionRoute::AgentTransition {
            agent_id: asset_id,
            version_id,
        }
    } else {
        VersionRoute::SkillTransition {
            skill_id: asset_id,
            version_id,
        }
    };
    proxy_response(state, current_user, AcpRoute::Version(route), request).await
}

async fn proxy_publish_requests(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    request: Request,
) -> Response {
    proxy_response(
        state,
        current_user,
        AcpRoute::PublishRequest(PublishRequestRoute::Collection),
        request,
    )
    .await
}

async fn proxy_withdraw_publish_request(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(request_id): Path<String>,
    request: Request,
) -> Response {
    proxy_publish_request_action(state, current_user, request_id, PublishRequestAction::Withdraw, request).await
}

async fn proxy_resubmit_publish_request(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(request_id): Path<String>,
    request: Request,
) -> Response {
    proxy_publish_request_action(state, current_user, request_id, PublishRequestAction::Resubmit, request).await
}

async fn proxy_publish_request_action(
    state: AuthRouterState,
    current_user: CurrentUser,
    request_id: String,
    action: PublishRequestAction,
    request: Request,
) -> Response {
    let request_id = match validate_id(request_id, "request_id", ErrorDomain::PublishRequest) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    proxy_response(
        state,
        current_user,
        AcpRoute::PublishRequest(PublishRequestRoute::Action { request_id, action }),
        request,
    )
    .await
}

async fn proxy_workspaces(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    request: Request,
) -> Response {
    proxy_response(
        state,
        current_user,
        AcpRoute::Workspace(WorkspaceRoute::Workspaces),
        request,
    )
    .await
}

async fn proxy_review_documents(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    request: Request,
) -> Response {
    proxy_response(
        state,
        current_user,
        AcpRoute::ReviewDocument(ReviewDocumentRoute::Collection),
        request,
    )
    .await
}

async fn proxy_review_document(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(document_id): Path<String>,
    request: Request,
) -> Response {
    let document_id = match validate_id(document_id, "document_id", ErrorDomain::ReviewDocument) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    proxy_response(
        state,
        current_user,
        AcpRoute::ReviewDocument(ReviewDocumentRoute::Document { document_id }),
        request,
    )
    .await
}

async fn proxy_review_draft(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((document_id, draft_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let document_id = match validate_id(document_id, "document_id", ErrorDomain::ReviewDocument) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let draft_id = match validate_id(draft_id, "draft_id", ErrorDomain::ReviewDocument) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    proxy_response(
        state,
        current_user,
        AcpRoute::ReviewDocument(ReviewDocumentRoute::Draft { document_id, draft_id }),
        request,
    )
    .await
}

async fn proxy_create_share(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    request: Request,
) -> Response {
    proxy_response(state, current_user, AcpRoute::Share(ShareRoute::Create), request).await
}

async fn proxy_collection(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    request: Request,
) -> Response {
    proxy_response(
        state,
        current_user,
        AcpRoute::Schedule(ScheduleRoute::Collection),
        request,
    )
    .await
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
        AcpRoute::Schedule(ScheduleRoute::Schedule {
            schedule_id: match validate_id(schedule_id, "schedule_id", ErrorDomain::Schedule) {
                Ok(id) => id,
                Err(error) => return error.into_response(),
            },
        }),
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
    let schedule_id = match validate_id(schedule_id, "schedule_id", ErrorDomain::Schedule) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    proxy_response(
        state,
        current_user,
        AcpRoute::Schedule(ScheduleRoute::Action { schedule_id, action }),
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
    let schedule_id = match validate_id(schedule_id, "schedule_id", ErrorDomain::Schedule) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    proxy_response(
        state,
        current_user,
        AcpRoute::Schedule(ScheduleRoute::Runs { schedule_id }),
        request,
    )
    .await
}

async fn proxy_run(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((schedule_id, run_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let schedule_id = match validate_id(schedule_id, "schedule_id", ErrorDomain::Schedule) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let run_id = match validate_id(run_id, "run_id", ErrorDomain::Schedule) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    proxy_response(
        state,
        current_user,
        AcpRoute::Schedule(ScheduleRoute::Run { schedule_id, run_id }),
        request,
    )
    .await
}

async fn proxy_response(
    state: AuthRouterState,
    current_user: CurrentUser,
    route: AcpRoute,
    request: Request,
) -> Response {
    match proxy_acp_inner(state, current_user, route, request).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn proxy_acp_inner(
    state: AuthRouterState,
    current_user: CurrentUser,
    route: AcpRoute,
    request: Request,
) -> Result<Response, ApiError> {
    let query = request.uri().query().map(str::to_owned);
    route.validate_query(request.method(), query.as_deref())?;
    let error_domain = route.error_domain();
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
    if route.requires_idempotency_key(&method)
        && headers
            .get(&IDEMPOTENCY_KEY)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            match error_domain {
                ErrorDomain::Version => "VERSION_BAD_REQUEST",
                ErrorDomain::PublishRequest => "PUBLISH_REQUEST_BAD_REQUEST",
                ErrorDomain::Share => "SHARE_BAD_REQUEST",
                ErrorDomain::Schedule | ErrorDomain::Catalog | ErrorDomain::Workspace | ErrorDomain::ReviewDocument => {
                    "BAD_REQUEST"
                }
            },
            "Idempotency-Key is required for this request.",
            None,
        ));
    }
    if route.requires_request_id(&method)
        && headers
            .get(&REQUEST_ID)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            match error_domain {
                ErrorDomain::Version => "VERSION_BAD_REQUEST",
                ErrorDomain::PublishRequest => "PUBLISH_REQUEST_BAD_REQUEST",
                ErrorDomain::Share => "SHARE_BAD_REQUEST",
                ErrorDomain::Schedule | ErrorDomain::Catalog | ErrorDomain::Workspace | ErrorDomain::ReviewDocument => {
                    "BAD_REQUEST"
                }
            },
            "X-Request-ID is required for this request.",
            None,
        ));
    }
    let body = to_bytes(body, MAX_REQUEST_BODY_BYTES)
        .await
        .map_err(|_| ApiError::PayloadTooLarge("Agent Control Plane request body is too large".to_owned()))?;
    if route.requires_json_body(&method) && body.is_empty() {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            match error_domain {
                ErrorDomain::Version => "VERSION_BAD_REQUEST",
                ErrorDomain::PublishRequest => "PUBLISH_REQUEST_BAD_REQUEST",
                ErrorDomain::Share => "SHARE_BAD_REQUEST",
                ErrorDomain::Schedule | ErrorDomain::Catalog | ErrorDomain::Workspace | ErrorDomain::ReviewDocument => {
                    "BAD_REQUEST"
                }
            },
            "A JSON request body is required.",
            None,
        ));
    }
    if method == Method::GET && !body.is_empty() {
        return Err(ApiError::BadRequest("GET requests must not include a body".to_owned()));
    }
    if !body.is_empty() && !is_json_content_type(&headers) {
        return Err(ApiError::UnsupportedMediaType(
            "Agent Control Plane request bodies must use application/json".to_owned(),
        ));
    }

    let local_token = extract_token_from_headers(&headers).ok_or_else(|| auth_center_session_required(error_domain))?;
    let payload = state
        .jwt_service
        .verify(&local_token)
        .map_err(|_| auth_center_session_required(error_domain))?;
    if !payload.auth_center_bound || payload.user_id != current_user.id {
        return Err(auth_center_session_required(error_domain));
    }

    let vault_key = AuthCenterTokenVaultKey::from_token(&local_token, &current_user.id);
    let bundle = state
        .auth_center_token_vault
        .get(&vault_key)
        .ok_or_else(|| auth_center_session_required(error_domain))?;
    if bundle
        .expires_at_ms
        .is_some_and(|expires_at| expires_at <= chrono::Utc::now().timestamp_millis())
    {
        state.auth_center_token_vault.clear(&vault_key);
        return Err(auth_center_session_required(error_domain));
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
            error_domain.upstream_timeout_code(),
            error_domain.timeout_message(),
            None,
        )
    })?
    .map_err(|error| match error {
        UpstreamReadError::Request(error) => {
            tracing::warn!(
                domain = error_domain.prefix(),
                error = %error.without_url(),
                "Agent Control Plane upstream request failed"
            );
            ApiError::coded(
                StatusCode::BAD_GATEWAY,
                error_domain.upstream_unavailable_code(),
                error_domain.unavailable_message(),
                None,
            )
        }
        UpstreamReadError::TooLarge => upstream_invalid_response(error_domain),
    })?;

    let (status, response_headers, response_body) = upstream;
    if !status.is_success() {
        return Err(map_upstream_error(error_domain, status, &response_body));
    }

    let data: Value = serde_json::from_slice(&response_body).map_err(|_| upstream_invalid_response(error_domain))?;
    let mut response = (status, Json(ApiResponse::ok(data))).into_response();
    copy_safe_response_header(&response_headers, response.headers_mut(), &REQUEST_ID);
    copy_safe_response_header(&response_headers, response.headers_mut(), &IDEMPOTENT_REPLAY);
    Ok(response)
}

enum UpstreamReadError {
    Request(reqwest::Error),
    TooLarge,
}

fn upstream_invalid_response(domain: ErrorDomain) -> ApiError {
    ApiError::coded(
        StatusCode::BAD_GATEWAY,
        domain.upstream_invalid_response_code(),
        domain.invalid_response_message(),
        None,
    )
}

fn validate_id(value: String, field: &'static str, domain: ErrorDomain) -> Result<String, ApiError> {
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
        domain.invalid_id_code(),
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

fn auth_center_session_required(domain: ErrorDomain) -> ApiError {
    ApiError::coded(
        StatusCode::UNAUTHORIZED,
        "AUTH_CENTER_SESSION_REQUIRED",
        domain.session_required_message(),
        None,
    )
}

#[derive(Debug, Deserialize)]
struct UpstreamErrorEnvelope {
    code: Option<String>,
}

fn map_upstream_error(domain: ErrorDomain, status: StatusCode, body: &[u8]) -> ApiError {
    let upstream_code = serde_json::from_slice::<UpstreamErrorEnvelope>(body)
        .ok()
        .and_then(|envelope| envelope.code);
    match status {
        StatusCode::UNAUTHORIZED if upstream_code.as_deref() == Some("device_unbound") => ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "device_unbound",
            "Bind this device before using Agent Platform features.",
            None,
        ),
        StatusCode::UNAUTHORIZED => auth_center_session_required(domain),
        _ if !matches!(domain, ErrorDomain::Schedule) => map_platform_upstream_error(domain, status),
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

fn map_platform_upstream_error(domain: ErrorDomain, status: StatusCode) -> ApiError {
    let (code, message) = match (domain, status) {
        (ErrorDomain::Catalog, StatusCode::BAD_REQUEST) => {
            ("CATALOG_BAD_REQUEST", "The Agent catalog request is invalid.")
        }
        (ErrorDomain::Catalog, StatusCode::FORBIDDEN) => (
            "CATALOG_FORBIDDEN",
            "You do not have permission to browse this Agent catalog scope.",
        ),
        (ErrorDomain::Catalog, StatusCode::NOT_FOUND) => (
            "CATALOG_NOT_FOUND",
            "The requested Agent catalog resource was not found.",
        ),
        (ErrorDomain::Catalog, StatusCode::GONE) => (
            "CATALOG_VERSION_REVOKED",
            "The published Agent version has been revoked.",
        ),
        (ErrorDomain::Version, StatusCode::BAD_REQUEST) => {
            ("VERSION_BAD_REQUEST", "The Agent Platform version request is invalid.")
        }
        (ErrorDomain::Version, StatusCode::FORBIDDEN) => (
            "VERSION_FORBIDDEN",
            "You do not have permission to manage this Agent Platform version.",
        ),
        (ErrorDomain::Version, StatusCode::NOT_FOUND) => (
            "VERSION_NOT_FOUND",
            "The requested Agent Platform version was not found.",
        ),
        (ErrorDomain::Version, StatusCode::CONFLICT) => (
            "VERSION_CONFLICT",
            "The Agent Platform version changed. Refresh and try again.",
        ),
        (ErrorDomain::Version, StatusCode::GONE) => ("VERSION_REVOKED", "The Agent Platform version has been revoked."),
        (ErrorDomain::PublishRequest, StatusCode::BAD_REQUEST) => (
            "PUBLISH_REQUEST_BAD_REQUEST",
            "The Agent Platform publish request is invalid.",
        ),
        (ErrorDomain::PublishRequest, StatusCode::FORBIDDEN) => (
            "PUBLISH_REQUEST_FORBIDDEN",
            "You do not have permission to manage this publish request.",
        ),
        (ErrorDomain::PublishRequest, StatusCode::NOT_FOUND) => (
            "PUBLISH_REQUEST_NOT_FOUND",
            "The requested publish request was not found.",
        ),
        (ErrorDomain::PublishRequest, StatusCode::CONFLICT) => (
            "PUBLISH_REQUEST_CONFLICT",
            "The publish request changed. Refresh and try again.",
        ),
        (ErrorDomain::Workspace, StatusCode::BAD_REQUEST) => {
            ("WORKSPACE_BAD_REQUEST", "The team workspace request is invalid.")
        }
        (ErrorDomain::Workspace, StatusCode::FORBIDDEN) => (
            "WORKSPACE_FORBIDDEN",
            "You do not have permission to browse these team workspaces.",
        ),
        (ErrorDomain::Workspace, StatusCode::NOT_FOUND) => {
            ("WORKSPACE_NOT_FOUND", "The requested team workspace was not found.")
        }
        (ErrorDomain::Share, StatusCode::BAD_REQUEST) => {
            ("SHARE_BAD_REQUEST", "The Agent Platform share request is invalid.")
        }
        (ErrorDomain::Share, StatusCode::FORBIDDEN) => (
            "SHARE_FORBIDDEN",
            "You do not have permission to share this Agent Platform asset.",
        ),
        (ErrorDomain::Share, StatusCode::NOT_FOUND) => (
            "SHARE_NOT_FOUND",
            "The requested Agent Platform asset or workspace was not found.",
        ),
        (ErrorDomain::Share, StatusCode::CONFLICT) => (
            "SHARE_CONFLICT",
            "The Agent Platform share changed. Refresh and try again.",
        ),
        (ErrorDomain::Share, StatusCode::GONE) => ("SHARE_EXPIRED", "The Agent Platform share is no longer available."),
        (ErrorDomain::ReviewDocument, StatusCode::BAD_REQUEST) => {
            ("REVIEW_DOCUMENT_BAD_REQUEST", "The review document request is invalid.")
        }
        (ErrorDomain::ReviewDocument, StatusCode::FORBIDDEN) => (
            "REVIEW_DOCUMENT_FORBIDDEN",
            "You do not have permission to browse this review document scope.",
        ),
        (ErrorDomain::ReviewDocument, StatusCode::NOT_FOUND) => (
            "REVIEW_DOCUMENT_NOT_FOUND",
            "The requested review document was not found.",
        ),
        (ErrorDomain::ReviewDocument, StatusCode::CONFLICT) => (
            "REVIEW_DOCUMENT_CONFLICT",
            "The review document changed. Refresh and try again.",
        ),
        (ErrorDomain::ReviewDocument, StatusCode::GONE) => (
            "REVIEW_DOCUMENT_REVOKED",
            "The review document or draft is no longer available.",
        ),
        (_, StatusCode::TOO_MANY_REQUESTS) => (
            match domain {
                ErrorDomain::Catalog => "CATALOG_RATE_LIMITED",
                ErrorDomain::Version => "VERSION_RATE_LIMITED",
                ErrorDomain::PublishRequest => "PUBLISH_REQUEST_RATE_LIMITED",
                ErrorDomain::Workspace => "WORKSPACE_RATE_LIMITED",
                ErrorDomain::Share => "SHARE_RATE_LIMITED",
                ErrorDomain::ReviewDocument => "REVIEW_DOCUMENT_RATE_LIMITED",
                ErrorDomain::Schedule => unreachable!(),
            },
            "Too many Agent Platform requests. Try again later.",
        ),
        (_, status) if status.is_client_error() => (
            match domain {
                ErrorDomain::Catalog => "CATALOG_UPSTREAM_REJECTED",
                ErrorDomain::Version => "VERSION_UPSTREAM_REJECTED",
                ErrorDomain::PublishRequest => "PUBLISH_REQUEST_UPSTREAM_REJECTED",
                ErrorDomain::Workspace => "WORKSPACE_UPSTREAM_REJECTED",
                ErrorDomain::Share => "SHARE_UPSTREAM_REJECTED",
                ErrorDomain::ReviewDocument => "REVIEW_DOCUMENT_UPSTREAM_REJECTED",
                ErrorDomain::Schedule => unreachable!(),
            },
            "The Agent Platform request could not be completed.",
        ),
        _ => {
            return ApiError::coded(
                StatusCode::BAD_GATEWAY,
                domain.upstream_unavailable_code(),
                domain.unavailable_message(),
                None,
            );
        }
    };
    ApiError::coded(status, code, message, None)
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use super::*;

    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    const SCHEDULE_ENV_KEYS: [&str; 10] = [
        "RSM_AGENT_CONTROL_PLANE_BASE_URL",
        "AGENT_CONTROL_PLANE_BASE_URL",
        "RSM_AGENT_CONTROL_PLANE_AUTH_AUDIENCE",
        "RSM_SCHEDULE_BFF_TIMEOUT_MS",
        "RSM_AUTH_ENABLED",
        "AUTH_CENTER_ENABLED",
        "RSM_AUTH_ISSUER",
        "AUTH_CENTER_ISSUER",
        "RSM_AUTH_CLIENT_ID",
        "AUTH_CENTER_CLIENT_ID",
    ];

    struct EnvRestore(Vec<(&'static str, Option<String>)>);

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for name in SCHEDULE_ENV_KEYS {
                remove_env(name);
            }
            for (name, value) in &self.0 {
                if let Some(value) = value {
                    set_env(name, value);
                }
            }
        }
    }

    fn remove_env(name: &str) {
        // SAFETY: tests call this only while holding ENV_MUTEX, serializing
        // process-global environment mutations in this module.
        unsafe { std::env::remove_var(name) };
    }

    fn set_env(name: &str, value: &str) {
        // SAFETY: tests call this only while holding ENV_MUTEX, serializing
        // process-global environment mutations in this module.
        unsafe { std::env::set_var(name, value) };
    }

    fn rsm_auth_config(enabled: bool, client_id: Option<&str>) -> crate::RsmAuthConfig {
        crate::RsmAuthConfig {
            enabled,
            issuer: enabled.then(|| "https://auth.example".to_owned()),
            client_id: client_id.map(str::to_owned),
            client_secret: None,
            redirect_uri: None,
            additional_scopes: Vec::new(),
            app_code: "agent".to_owned(),
            internal_base_url: None,
            internal_token: None,
        }
    }

    fn with_schedule_env<R>(values: &[(&str, &str)], test: impl FnOnce() -> R) -> R {
        let _guard = ENV_MUTEX.get_or_init(|| Mutex::new(())).lock().unwrap();
        let previous = SCHEDULE_ENV_KEYS
            .iter()
            .map(|name| (*name, std::env::var(name).ok()))
            .collect::<Vec<_>>();

        for name in SCHEDULE_ENV_KEYS {
            remove_env(name);
        }
        for (name, value) in values {
            set_env(name, value);
        }
        let _restore = EnvRestore(previous);

        test()
    }

    #[test]
    fn governed_config_requires_ready_oidc_and_matching_audience() {
        let timeout = Duration::from_secs(1);

        assert!(matches!(
            ScheduleBffConfig::new_with_identity_contract(
                "https://acp.example",
                timeout,
                &rsm_auth_config(false, Some("agent-control-plane")),
                Some("agent-control-plane"),
            ),
            Err(ScheduleBffConfigError::AuthCenterOidcRequired)
        ));
        assert!(matches!(
            ScheduleBffConfig::new_with_identity_contract(
                "https://acp.example",
                timeout,
                &rsm_auth_config(true, None),
                Some("agent-control-plane"),
            ),
            Err(ScheduleBffConfigError::AuthCenterOidcRequired)
        ));
        assert!(matches!(
            ScheduleBffConfig::new_with_identity_contract(
                "https://acp.example",
                timeout,
                &rsm_auth_config(true, Some("agent-control-plane")),
                None,
            ),
            Err(ScheduleBffConfigError::MissingAuthAudience)
        ));
        assert!(matches!(
            ScheduleBffConfig::new_with_identity_contract(
                "https://acp.example",
                timeout,
                &rsm_auth_config(true, Some("agent-control-plane")),
                Some("   "),
            ),
            Err(ScheduleBffConfigError::MissingAuthAudience)
        ));
        assert!(matches!(
            ScheduleBffConfig::new_with_identity_contract(
                "https://acp.example",
                timeout,
                &rsm_auth_config(true, Some("agent-control-plane")),
                Some("rsm-agent-platform-webui"),
            ),
            Err(ScheduleBffConfigError::AudienceClientMismatch)
        ));
        assert!(
            ScheduleBffConfig::new_with_identity_contract(
                "https://acp.example",
                timeout,
                &rsm_auth_config(true, Some("agent-control-plane")),
                Some(" agent-control-plane "),
            )
            .is_ok()
        );
    }

    #[test]
    fn disabled_config_does_not_require_oidc_or_audience() {
        let config =
            ScheduleBffConfig::from_values(None, Duration::from_secs(1), &rsm_auth_config(false, None), None).unwrap();
        assert!(config.base_url.is_none());
    }

    #[test]
    fn env_config_enforces_oidc_and_audience_only_when_enabled() {
        with_schedule_env(&[], || {
            let config = ScheduleBffConfig::from_env(&crate::RsmAuthConfig::from_env()).unwrap();
            assert!(config.base_url.is_none());
        });

        with_schedule_env(
            &[
                ("RSM_AGENT_CONTROL_PLANE_BASE_URL", "https://acp.example"),
                ("RSM_AUTH_ENABLED", "true"),
                ("RSM_AUTH_ISSUER", "https://auth.example"),
                ("RSM_AUTH_CLIENT_ID", "agent-control-plane"),
            ],
            || {
                assert!(matches!(
                    ScheduleBffConfig::from_env(&crate::RsmAuthConfig::from_env()),
                    Err(ScheduleBffConfigError::MissingAuthAudience)
                ));
            },
        );

        with_schedule_env(
            &[
                ("RSM_AGENT_CONTROL_PLANE_BASE_URL", "https://acp.example"),
                ("RSM_AGENT_CONTROL_PLANE_AUTH_AUDIENCE", " rsm-agent-platform-webui "),
                ("RSM_AUTH_ENABLED", "true"),
                ("RSM_AUTH_ISSUER", "https://auth.example"),
                ("RSM_AUTH_CLIENT_ID", "agent-control-plane"),
            ],
            || {
                assert!(matches!(
                    ScheduleBffConfig::from_env(&crate::RsmAuthConfig::from_env()),
                    Err(ScheduleBffConfigError::AudienceClientMismatch)
                ));
            },
        );

        with_schedule_env(
            &[
                ("RSM_AGENT_CONTROL_PLANE_BASE_URL", " https://acp.example/internal "),
                ("RSM_AGENT_CONTROL_PLANE_AUTH_AUDIENCE", " agent-control-plane "),
                ("RSM_AUTH_ENABLED", "true"),
                ("RSM_AUTH_ISSUER", "https://auth.example"),
                ("RSM_AUTH_CLIENT_ID", " agent-control-plane "),
                ("RSM_SCHEDULE_BFF_TIMEOUT_MS", "2500"),
            ],
            || {
                let config = ScheduleBffConfig::from_env(&crate::RsmAuthConfig::from_env()).unwrap();
                assert_eq!(config.timeout, Duration::from_millis(2500));
                assert_eq!(
                    config
                        .upstream_url(&AcpRoute::Schedule(ScheduleRoute::Collection), None)
                        .unwrap()
                        .as_str(),
                    "https://acp.example/internal/api/schedule/v1/schedules"
                );
            },
        );
    }

    #[test]
    fn config_rejects_non_http_and_query_bearing_base_urls() {
        assert!(matches!(
            ScheduleBffConfig::new_with_identity_contract(
                "file:///tmp/acp",
                Duration::from_secs(1),
                &rsm_auth_config(true, Some("agent-control-plane")),
                Some("agent-control-plane"),
            ),
            Err(ScheduleBffConfigError::InvalidScheme)
        ));
        assert!(matches!(
            ScheduleBffConfig::new_with_identity_contract(
                "https://acp.example/?secret=value",
                Duration::from_secs(1),
                &rsm_auth_config(true, Some("agent-control-plane")),
                Some("agent-control-plane"),
            ),
            Err(ScheduleBffConfigError::InvalidBaseUrlComponents)
        ));
        assert!(matches!(
            ScheduleBffConfig::new_with_identity_contract(
                "https://user:pass@acp.example",
                Duration::from_secs(1),
                &rsm_auth_config(true, Some("agent-control-plane")),
                Some("agent-control-plane"),
            ),
            Err(ScheduleBffConfigError::InvalidBaseUrlComponents)
        ));
    }

    #[test]
    fn upstream_url_preserves_configured_path_prefix_and_request_query() {
        let config = ScheduleBffConfig::new_with_identity_contract(
            "https://acp.example/internal",
            Duration::from_secs(1),
            &rsm_auth_config(true, Some("agent-control-plane")),
            Some("agent-control-plane"),
        )
        .unwrap();
        assert_eq!(
            config
                .upstream_url(&AcpRoute::Schedule(ScheduleRoute::Collection), Some("page=2"))
                .unwrap()
                .as_str(),
            "https://acp.example/internal/api/schedule/v1/schedules?page=2"
        );
    }

    #[test]
    fn typed_diff_allowlist_and_upstream_path_are_exact() {
        assert_eq!(
            REVIEW_TYPED_DIFF_ROUTE,
            "/api/review/v1/documents/{document_id}/drafts/{draft_id}/typed-diff"
        );

        let config = ScheduleBffConfig::new_with_identity_contract(
            "https://acp.example/internal",
            Duration::from_secs(1),
            &rsm_auth_config(true, Some("agent-control-plane")),
            Some("agent-control-plane"),
        )
        .unwrap();
        let route = review_typed_diff_route("document-1".to_owned(), "draft_1".to_owned()).unwrap();

        assert_eq!(
            config.upstream_url(&route, None).unwrap().as_str(),
            "https://acp.example/internal/api/review/v1/documents/document-1/drafts/draft_1/typed-diff"
        );
    }

    #[test]
    fn path_ids_accept_only_single_safe_segments() {
        for valid in ["schedule-1", "schedule_1", "01JABCDEF123"] {
            assert_eq!(
                validate_id(valid.to_owned(), "schedule_id", ErrorDomain::Schedule).unwrap(),
                valid
            );
        }
        for invalid in ["", ".", "..", "schedule/other", "schedule%2Fother", "含中文"] {
            assert!(
                validate_id(invalid.to_owned(), "schedule_id", ErrorDomain::Schedule).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn review_document_path_ids_use_the_same_safe_segment_contract() {
        for valid in ["document-1", "draft_1", "01JABCDEF123"] {
            assert_eq!(
                validate_id(valid.to_owned(), "document_id", ErrorDomain::ReviewDocument).unwrap(),
                valid
            );
            assert_eq!(
                validate_id(valid.to_owned(), "draft_id", ErrorDomain::ReviewDocument).unwrap(),
                valid
            );
        }
        for invalid in [
            "",
            ".",
            "..",
            "document/other",
            "document%2Fother",
            "document.invalid",
            "含中文",
        ] {
            let document = validate_id(invalid.to_owned(), "document_id", ErrorDomain::ReviewDocument);
            assert!(document.is_err(), "accepted {invalid:?} as document_id");
            assert_eq!(document.unwrap_err().error_code(), "REVIEW_DOCUMENT_INVALID_ID");
            let draft = validate_id(invalid.to_owned(), "draft_id", ErrorDomain::ReviewDocument);
            assert!(draft.is_err(), "accepted {invalid:?} as draft_id");
            assert_eq!(draft.unwrap_err().error_code(), "REVIEW_DOCUMENT_INVALID_ID");
        }
    }

    #[test]
    fn typed_diff_rejects_either_invalid_id_before_building_an_upstream_route() {
        for invalid in ["", ".", "..", "other/path", "other%2Fpath", "other.invalid", "含中文"] {
            let invalid_document = review_typed_diff_route(invalid.to_owned(), "draft-1".to_owned());
            assert!(invalid_document.is_err(), "accepted {invalid:?} as document_id");
            assert_eq!(
                invalid_document.unwrap_err().error_code(),
                "REVIEW_DOCUMENT_INVALID_ID"
            );

            let invalid_draft = review_typed_diff_route("document-1".to_owned(), invalid.to_owned());
            assert!(invalid_draft.is_err(), "accepted {invalid:?} as draft_id");
            assert_eq!(invalid_draft.unwrap_err().error_code(), "REVIEW_DOCUMENT_INVALID_ID");
        }
    }
}
