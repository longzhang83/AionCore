use axum::http::{Method, StatusCode};

use aionui_common::ApiError;

#[derive(Debug)]
pub(super) enum ScheduleAction {
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
pub(super) enum ScheduleRoute {
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

#[derive(Debug)]
pub(super) enum CatalogRoute {
    Agents,
    AgentVersions { agent_id: String },
    AgentVersion { agent_id: String, version_id: String },
    Skills,
    SkillVersions { skill_id: String },
    SkillVersion { skill_id: String, version_id: String },
}

#[derive(Debug)]
pub(super) enum VersionRoute {
    AgentCreate { agent_id: String },
    AgentTransition { agent_id: String, version_id: String },
    SkillCreate { skill_id: String },
    SkillTransition { skill_id: String, version_id: String },
}

#[derive(Debug)]
pub(super) enum PublishRequestRoute {
    Collection,
    Action {
        request_id: String,
        action: PublishRequestAction,
    },
}

#[derive(Debug)]
pub(super) enum PublishRequestAction {
    Withdraw,
    Resubmit,
}

#[derive(Debug)]
pub(super) enum WorkspaceRoute {
    Workspaces,
}

#[derive(Debug)]
pub(super) enum ShareRoute {
    Create,
}

#[derive(Debug)]
pub(super) enum AcpRoute {
    Schedule(ScheduleRoute),
    Catalog(CatalogRoute),
    Version(VersionRoute),
    PublishRequest(PublishRequestRoute),
    Workspace(WorkspaceRoute),
    Share(ShareRoute),
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ErrorDomain {
    Schedule,
    Catalog,
    Version,
    PublishRequest,
    Workspace,
    Share,
}

impl ErrorDomain {
    pub(super) fn prefix(self) -> &'static str {
        match self {
            Self::Schedule => "SCHEDULE",
            Self::Catalog => "CATALOG",
            Self::Version => "VERSION",
            Self::PublishRequest => "PUBLISH_REQUEST",
            Self::Workspace => "WORKSPACE",
            Self::Share => "SHARE",
        }
    }

    pub(super) fn invalid_id_code(self) -> &'static str {
        match self {
            Self::Schedule => "SCHEDULE_INVALID_ID",
            Self::Catalog => "CATALOG_INVALID_ID",
            Self::Version => "VERSION_INVALID_ID",
            Self::PublishRequest => "PUBLISH_REQUEST_INVALID_ID",
            Self::Workspace => "WORKSPACE_INVALID_ID",
            Self::Share => "SHARE_INVALID_ID",
        }
    }

    pub(super) fn upstream_not_configured_code(self) -> &'static str {
        match self {
            Self::Schedule => "SCHEDULE_UPSTREAM_NOT_CONFIGURED",
            Self::Catalog => "CATALOG_UPSTREAM_NOT_CONFIGURED",
            Self::Version => "VERSION_UPSTREAM_NOT_CONFIGURED",
            Self::PublishRequest => "PUBLISH_REQUEST_UPSTREAM_NOT_CONFIGURED",
            Self::Workspace => "WORKSPACE_UPSTREAM_NOT_CONFIGURED",
            Self::Share => "SHARE_UPSTREAM_NOT_CONFIGURED",
        }
    }

    pub(super) fn upstream_timeout_code(self) -> &'static str {
        match self {
            Self::Schedule => "SCHEDULE_UPSTREAM_TIMEOUT",
            Self::Catalog => "CATALOG_UPSTREAM_TIMEOUT",
            Self::Version => "VERSION_UPSTREAM_TIMEOUT",
            Self::PublishRequest => "PUBLISH_REQUEST_UPSTREAM_TIMEOUT",
            Self::Workspace => "WORKSPACE_UPSTREAM_TIMEOUT",
            Self::Share => "SHARE_UPSTREAM_TIMEOUT",
        }
    }

    pub(super) fn upstream_unavailable_code(self) -> &'static str {
        match self {
            Self::Schedule => "SCHEDULE_UPSTREAM_UNAVAILABLE",
            Self::Catalog => "CATALOG_UPSTREAM_UNAVAILABLE",
            Self::Version => "VERSION_UPSTREAM_UNAVAILABLE",
            Self::PublishRequest => "PUBLISH_REQUEST_UPSTREAM_UNAVAILABLE",
            Self::Workspace => "WORKSPACE_UPSTREAM_UNAVAILABLE",
            Self::Share => "SHARE_UPSTREAM_UNAVAILABLE",
        }
    }

    pub(super) fn upstream_invalid_response_code(self) -> &'static str {
        match self {
            Self::Schedule => "SCHEDULE_UPSTREAM_INVALID_RESPONSE",
            Self::Catalog => "CATALOG_UPSTREAM_INVALID_RESPONSE",
            Self::Version => "VERSION_UPSTREAM_INVALID_RESPONSE",
            Self::PublishRequest => "PUBLISH_REQUEST_UPSTREAM_INVALID_RESPONSE",
            Self::Workspace => "WORKSPACE_UPSTREAM_INVALID_RESPONSE",
            Self::Share => "SHARE_UPSTREAM_INVALID_RESPONSE",
        }
    }

    pub(super) fn session_required_message(self) -> &'static str {
        match self {
            Self::Schedule => "Sign in again to use scheduled tasks.",
            Self::Catalog => "Sign in again to browse the Agent catalog.",
            Self::Version => "Sign in again to manage Agent Platform versions.",
            Self::PublishRequest => "Sign in again to manage publish requests.",
            Self::Workspace => "Sign in again to browse team workspaces.",
            Self::Share => "Sign in again to share Agent Platform assets.",
        }
    }

    pub(super) fn not_configured_message(self) -> &'static str {
        match self {
            Self::Schedule => "Scheduled tasks are not configured.",
            Self::Catalog => "The Agent catalog is not configured.",
            Self::Version => "Agent Platform version management is not configured.",
            Self::PublishRequest => "Agent Platform publish requests are not configured.",
            Self::Workspace => "Team workspaces are not configured.",
            Self::Share => "Agent Platform sharing is not configured.",
        }
    }

    pub(super) fn timeout_message(self) -> &'static str {
        match self {
            Self::Schedule => "Scheduled tasks did not respond in time.",
            Self::Catalog => "The Agent catalog did not respond in time.",
            Self::Version => "Agent Platform version management did not respond in time.",
            Self::PublishRequest => "Agent Platform publish requests did not respond in time.",
            Self::Workspace => "Team workspaces did not respond in time.",
            Self::Share => "Agent Platform sharing did not respond in time.",
        }
    }

    pub(super) fn unavailable_message(self) -> &'static str {
        match self {
            Self::Schedule => "Scheduled tasks are temporarily unavailable.",
            Self::Catalog => "The Agent catalog is temporarily unavailable.",
            Self::Version => "Agent Platform version management is temporarily unavailable.",
            Self::PublishRequest => "Agent Platform publish requests are temporarily unavailable.",
            Self::Workspace => "Team workspaces are temporarily unavailable.",
            Self::Share => "Agent Platform sharing is temporarily unavailable.",
        }
    }

    pub(super) fn invalid_response_message(self) -> &'static str {
        match self {
            Self::Schedule => "Scheduled tasks returned an invalid response.",
            Self::Catalog => "The Agent catalog returned an invalid response.",
            Self::Version => "Agent Platform version management returned an invalid response.",
            Self::PublishRequest => "Agent Platform publish requests returned an invalid response.",
            Self::Workspace => "Team workspaces returned an invalid response.",
            Self::Share => "Agent Platform sharing returned an invalid response.",
        }
    }
}

impl AcpRoute {
    pub(super) fn permits(&self, method: &Method) -> bool {
        match self {
            Self::Schedule(route) => route.permits(method),
            Self::Catalog(_) | Self::Workspace(_) => *method == Method::GET,
            Self::Version(_) => *method == Method::POST,
            Self::PublishRequest(PublishRequestRoute::Collection) => {
                matches!(*method, Method::GET | Method::POST)
            }
            Self::PublishRequest(PublishRequestRoute::Action { .. }) => *method == Method::POST,
            Self::Share(ShareRoute::Create) => *method == Method::POST,
        }
    }

    pub(super) fn error_domain(&self) -> ErrorDomain {
        match self {
            Self::Schedule(_) => ErrorDomain::Schedule,
            Self::Catalog(_) => ErrorDomain::Catalog,
            Self::Version(_) => ErrorDomain::Version,
            Self::PublishRequest(_) => ErrorDomain::PublishRequest,
            Self::Workspace(_) => ErrorDomain::Workspace,
            Self::Share(_) => ErrorDomain::Share,
        }
    }

    pub(super) fn upstream_segments(&self) -> Vec<&str> {
        match self {
            Self::Schedule(ScheduleRoute::Collection) => vec!["api", "schedule", "v1", "schedules"],
            Self::Schedule(ScheduleRoute::Schedule { schedule_id }) => {
                vec!["api", "schedule", "v1", "schedules", schedule_id]
            }
            Self::Schedule(ScheduleRoute::Action { schedule_id, action }) => {
                vec!["api", "schedule", "v1", "schedules", schedule_id, action.as_segment()]
            }
            Self::Schedule(ScheduleRoute::Runs { schedule_id }) => {
                vec!["api", "schedule", "v1", "schedules", schedule_id, "runs"]
            }
            Self::Schedule(ScheduleRoute::Run { schedule_id, run_id }) => {
                vec!["api", "schedule", "v1", "schedules", schedule_id, "runs", run_id]
            }
            Self::Catalog(CatalogRoute::Agents) => vec!["api", "catalog", "v1", "agents"],
            Self::Catalog(CatalogRoute::AgentVersions { agent_id }) => {
                vec!["api", "catalog", "v1", "agents", agent_id, "versions"]
            }
            Self::Catalog(CatalogRoute::AgentVersion { agent_id, version_id }) => {
                vec!["api", "catalog", "v1", "agents", agent_id, "versions", version_id]
            }
            Self::Catalog(CatalogRoute::Skills) => vec!["api", "catalog", "v1", "skills"],
            Self::Catalog(CatalogRoute::SkillVersions { skill_id }) => {
                vec!["api", "catalog", "v1", "skills", skill_id, "versions"]
            }
            Self::Catalog(CatalogRoute::SkillVersion { skill_id, version_id }) => {
                vec!["api", "catalog", "v1", "skills", skill_id, "versions", version_id]
            }
            Self::Workspace(WorkspaceRoute::Workspaces) => {
                vec!["api", "team-workspace", "v1", "workspaces"]
            }
            Self::Share(ShareRoute::Create) => vec!["api", "share", "v1", "shares"],
            Self::Version(VersionRoute::AgentCreate { agent_id }) => {
                vec!["api", "version", "v1", "agents", agent_id, "versions"]
            }
            Self::Version(VersionRoute::AgentTransition { agent_id, version_id }) => vec![
                "api",
                "version",
                "v1",
                "agents",
                agent_id,
                "versions",
                version_id,
                "transition",
            ],
            Self::Version(VersionRoute::SkillCreate { skill_id }) => {
                vec!["api", "version", "v1", "skills", skill_id, "versions"]
            }
            Self::Version(VersionRoute::SkillTransition { skill_id, version_id }) => vec![
                "api",
                "version",
                "v1",
                "skills",
                skill_id,
                "versions",
                version_id,
                "transition",
            ],
            Self::PublishRequest(PublishRequestRoute::Collection) => {
                vec!["api", "publish-request", "v1", "requests"]
            }
            Self::PublishRequest(PublishRequestRoute::Action { request_id, action }) => vec![
                "api",
                "publish-request",
                "v1",
                "requests",
                request_id,
                match action {
                    PublishRequestAction::Withdraw => "withdraw",
                    PublishRequestAction::Resubmit => "resubmit",
                },
            ],
        }
    }

    pub(super) fn validate_query(&self, method: &Method, query: Option<&str>) -> Result<(), ApiError> {
        match self {
            // Preserve the already-frozen Schedule proxy behavior. ACP remains
            // authoritative for Schedule query validation.
            Self::Schedule(_) => Ok(()),
            // Catalog lists accept only the frozen exact `page_size=100`
            // contract. Missing, duplicated, differently valued, or extra
            // query keys are rejected before any upstream I/O.
            Self::Catalog(CatalogRoute::Agents)
            | Self::Catalog(CatalogRoute::Skills)
            | Self::Catalog(CatalogRoute::AgentVersions { .. })
            | Self::Catalog(CatalogRoute::SkillVersions { .. }) => {
                validate_page_size_query(query, ErrorDomain::Catalog)
            }
            Self::PublishRequest(PublishRequestRoute::Collection) if *method == Method::GET => {
                validate_publish_request_list_query(query)
            }
            Self::PublishRequest(PublishRequestRoute::Collection) if query.is_some() => Err(ApiError::coded(
                StatusCode::BAD_REQUEST,
                "PUBLISH_REQUEST_BAD_REQUEST",
                "This request does not accept query parameters.",
                None,
            )),
            Self::PublishRequest(PublishRequestRoute::Collection) => Ok(()),
            Self::PublishRequest(PublishRequestRoute::Action { .. }) if query.is_some() => Err(ApiError::coded(
                StatusCode::BAD_REQUEST,
                "PUBLISH_REQUEST_BAD_REQUEST",
                "This request does not accept query parameters.",
                None,
            )),
            Self::PublishRequest(PublishRequestRoute::Action { .. }) => Ok(()),
            Self::Catalog(CatalogRoute::AgentVersion { .. })
            | Self::Catalog(CatalogRoute::SkillVersion { .. })
            | Self::Version(_)
            | Self::Workspace(_)
            | Self::Share(_)
                if query.is_some() =>
            {
                Err(ApiError::coded(
                    StatusCode::BAD_REQUEST,
                    match self.error_domain() {
                        ErrorDomain::Catalog => "CATALOG_BAD_REQUEST",
                        ErrorDomain::Version => "VERSION_BAD_REQUEST",
                        ErrorDomain::PublishRequest => "PUBLISH_REQUEST_BAD_REQUEST",
                        ErrorDomain::Workspace => "WORKSPACE_BAD_REQUEST",
                        ErrorDomain::Share => "SHARE_BAD_REQUEST",
                        ErrorDomain::Schedule => unreachable!(),
                    },
                    "This request does not accept query parameters.",
                    None,
                ))
            }
            Self::Catalog(CatalogRoute::AgentVersion { .. })
            | Self::Catalog(CatalogRoute::SkillVersion { .. })
            | Self::Version(_)
            | Self::Workspace(_)
            | Self::Share(_) => Ok(()),
        }
    }

    pub(super) fn requires_idempotency_key(&self, method: &Method) -> bool {
        matches!(
            (self, method),
            (Self::Share(ShareRoute::Create), &Method::POST)
                | (Self::Version(_), &Method::POST)
                | (Self::PublishRequest(_), &Method::POST)
        )
    }

    pub(super) fn requires_request_id(&self, method: &Method) -> bool {
        matches!(
            (self, method),
            (Self::Share(ShareRoute::Create), &Method::POST)
                | (Self::Version(_), &Method::POST)
                | (Self::PublishRequest(_), &Method::POST)
        )
    }

    pub(super) fn requires_json_body(&self, method: &Method) -> bool {
        matches!(
            (self, method),
            (Self::Share(ShareRoute::Create), &Method::POST)
                | (Self::Version(_), &Method::POST)
                | (Self::PublishRequest(_), &Method::POST)
        )
    }
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

/// Validates the frozen Catalog list query: one exact `page_size=100` pair.
fn validate_page_size_query(query: Option<&str>, domain: ErrorDomain) -> Result<(), ApiError> {
    let Some(query) = query else {
        return Err(list_query_error(domain));
    };
    let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    if pairs.len() == 1 && pairs[0].0 == "page_size" && pairs[0].1 == "100" {
        Ok(())
    } else {
        Err(list_query_error(domain))
    }
}

fn validate_publish_request_list_query(query: Option<&str>) -> Result<(), ApiError> {
    let Some(query) = query else {
        return Err(list_query_error(ErrorDomain::PublishRequest));
    };
    let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    if pairs.len() != 4 {
        return Err(list_query_error(ErrorDomain::PublishRequest));
    }

    let mut asset_kind = None;
    let mut asset_id = None;
    let mut page = None;
    let mut page_size = None;
    for (key, value) in pairs {
        let slot = match key.as_ref() {
            "asset_kind" => &mut asset_kind,
            "asset_id" => &mut asset_id,
            "page" => &mut page,
            "page_size" => &mut page_size,
            _ => return Err(list_query_error(ErrorDomain::PublishRequest)),
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err(list_query_error(ErrorDomain::PublishRequest));
        }
    }

    let valid_asset_id = asset_id.as_deref().is_some_and(|value| {
        !value.is_empty()
            && value.len() <= 255
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    });
    let valid_page = page
        .as_deref()
        .and_then(|value| value.parse::<u32>().ok())
        .is_some_and(|value| value >= 1);
    if matches!(asset_kind.as_deref(), Some("agent" | "skill"))
        && valid_asset_id
        && valid_page
        && page_size.as_deref() == Some("200")
    {
        Ok(())
    } else {
        Err(list_query_error(ErrorDomain::PublishRequest))
    }
}

fn list_query_error(domain: ErrorDomain) -> ApiError {
    ApiError::coded(
        StatusCode::BAD_REQUEST,
        match domain {
            ErrorDomain::Catalog => "CATALOG_BAD_REQUEST",
            ErrorDomain::PublishRequest => "PUBLISH_REQUEST_BAD_REQUEST",
            _ => unreachable!(),
        },
        match domain {
            ErrorDomain::Catalog => "The catalog query is invalid.",
            ErrorDomain::PublishRequest => "The publish request query is invalid.",
            _ => unreachable!(),
        },
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_lists_accept_only_the_fixed_page_size_query() {
        let catalog = AcpRoute::Catalog(CatalogRoute::AgentVersions {
            agent_id: "agent-1".to_owned(),
        });
        let publish = AcpRoute::PublishRequest(PublishRequestRoute::Collection);

        assert!(catalog.validate_query(&Method::GET, Some("page_size=100")).is_ok());
        assert!(publish.validate_query(&Method::GET, Some("page_size=100")).is_err());
        assert!(
            publish
                .validate_query(
                    &Method::GET,
                    Some("asset_kind=agent&asset_id=agent-1&page=2&page_size=200"),
                )
                .is_ok()
        );
        assert!(catalog.validate_query(&Method::GET, Some("page_size=99")).is_err());
        assert!(
            publish
                .validate_query(&Method::GET, Some("page_size=100&organization_id=org-1"))
                .is_err()
        );
    }

    #[test]
    fn publish_collection_requires_write_guards_only_for_post() {
        let route = AcpRoute::PublishRequest(PublishRequestRoute::Collection);

        assert!(route.validate_query(&Method::POST, None).is_ok());
        assert!(!route.requires_idempotency_key(&Method::GET));
        assert!(!route.requires_json_body(&Method::GET));
        assert!(route.requires_idempotency_key(&Method::POST));
        assert!(route.requires_json_body(&Method::POST));
    }
}
