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
    AgentVersion { agent_id: String, version_id: String },
    Skills,
    SkillVersion { skill_id: String, version_id: String },
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
    Workspace(WorkspaceRoute),
    Share(ShareRoute),
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ErrorDomain {
    Schedule,
    Catalog,
    Workspace,
    Share,
}

impl ErrorDomain {
    pub(super) fn prefix(self) -> &'static str {
        match self {
            Self::Schedule => "SCHEDULE",
            Self::Catalog => "CATALOG",
            Self::Workspace => "WORKSPACE",
            Self::Share => "SHARE",
        }
    }

    pub(super) fn invalid_id_code(self) -> &'static str {
        match self {
            Self::Schedule => "SCHEDULE_INVALID_ID",
            Self::Catalog => "CATALOG_INVALID_ID",
            Self::Workspace => "WORKSPACE_INVALID_ID",
            Self::Share => "SHARE_INVALID_ID",
        }
    }

    pub(super) fn upstream_not_configured_code(self) -> &'static str {
        match self {
            Self::Schedule => "SCHEDULE_UPSTREAM_NOT_CONFIGURED",
            Self::Catalog => "CATALOG_UPSTREAM_NOT_CONFIGURED",
            Self::Workspace => "WORKSPACE_UPSTREAM_NOT_CONFIGURED",
            Self::Share => "SHARE_UPSTREAM_NOT_CONFIGURED",
        }
    }

    pub(super) fn upstream_timeout_code(self) -> &'static str {
        match self {
            Self::Schedule => "SCHEDULE_UPSTREAM_TIMEOUT",
            Self::Catalog => "CATALOG_UPSTREAM_TIMEOUT",
            Self::Workspace => "WORKSPACE_UPSTREAM_TIMEOUT",
            Self::Share => "SHARE_UPSTREAM_TIMEOUT",
        }
    }

    pub(super) fn upstream_unavailable_code(self) -> &'static str {
        match self {
            Self::Schedule => "SCHEDULE_UPSTREAM_UNAVAILABLE",
            Self::Catalog => "CATALOG_UPSTREAM_UNAVAILABLE",
            Self::Workspace => "WORKSPACE_UPSTREAM_UNAVAILABLE",
            Self::Share => "SHARE_UPSTREAM_UNAVAILABLE",
        }
    }

    pub(super) fn upstream_invalid_response_code(self) -> &'static str {
        match self {
            Self::Schedule => "SCHEDULE_UPSTREAM_INVALID_RESPONSE",
            Self::Catalog => "CATALOG_UPSTREAM_INVALID_RESPONSE",
            Self::Workspace => "WORKSPACE_UPSTREAM_INVALID_RESPONSE",
            Self::Share => "SHARE_UPSTREAM_INVALID_RESPONSE",
        }
    }

    pub(super) fn session_required_message(self) -> &'static str {
        match self {
            Self::Schedule => "Sign in again to use scheduled tasks.",
            Self::Catalog => "Sign in again to browse the Agent catalog.",
            Self::Workspace => "Sign in again to browse team workspaces.",
            Self::Share => "Sign in again to share Agent Platform assets.",
        }
    }

    pub(super) fn not_configured_message(self) -> &'static str {
        match self {
            Self::Schedule => "Scheduled tasks are not configured.",
            Self::Catalog => "The Agent catalog is not configured.",
            Self::Workspace => "Team workspaces are not configured.",
            Self::Share => "Agent Platform sharing is not configured.",
        }
    }

    pub(super) fn timeout_message(self) -> &'static str {
        match self {
            Self::Schedule => "Scheduled tasks did not respond in time.",
            Self::Catalog => "The Agent catalog did not respond in time.",
            Self::Workspace => "Team workspaces did not respond in time.",
            Self::Share => "Agent Platform sharing did not respond in time.",
        }
    }

    pub(super) fn unavailable_message(self) -> &'static str {
        match self {
            Self::Schedule => "Scheduled tasks are temporarily unavailable.",
            Self::Catalog => "The Agent catalog is temporarily unavailable.",
            Self::Workspace => "Team workspaces are temporarily unavailable.",
            Self::Share => "Agent Platform sharing is temporarily unavailable.",
        }
    }

    pub(super) fn invalid_response_message(self) -> &'static str {
        match self {
            Self::Schedule => "Scheduled tasks returned an invalid response.",
            Self::Catalog => "The Agent catalog returned an invalid response.",
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
            Self::Share(ShareRoute::Create) => *method == Method::POST,
        }
    }

    pub(super) fn error_domain(&self) -> ErrorDomain {
        match self {
            Self::Schedule(_) => ErrorDomain::Schedule,
            Self::Catalog(_) => ErrorDomain::Catalog,
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
            Self::Catalog(CatalogRoute::AgentVersion { agent_id, version_id }) => {
                vec!["api", "catalog", "v1", "agents", agent_id, "versions", version_id]
            }
            Self::Catalog(CatalogRoute::Skills) => vec!["api", "catalog", "v1", "skills"],
            Self::Catalog(CatalogRoute::SkillVersion { skill_id, version_id }) => {
                vec!["api", "catalog", "v1", "skills", skill_id, "versions", version_id]
            }
            Self::Workspace(WorkspaceRoute::Workspaces) => {
                vec!["api", "team-workspace", "v1", "workspaces"]
            }
            Self::Share(ShareRoute::Create) => vec!["api", "share", "v1", "shares"],
        }
    }

    pub(super) fn validate_query(&self, query: Option<&str>) -> Result<(), ApiError> {
        match self {
            // Preserve the already-frozen Schedule proxy behavior. ACP remains
            // authoritative for Schedule query validation.
            Self::Schedule(_) => Ok(()),
            // Catalog lists accept only the frozen exact `page_size=100`
            // contract. Missing, duplicated, differently valued, or extra
            // query keys are rejected before any upstream I/O.
            Self::Catalog(CatalogRoute::Agents) | Self::Catalog(CatalogRoute::Skills) => {
                validate_catalog_list_query(query)
            }
            Self::Catalog(CatalogRoute::AgentVersion { .. })
            | Self::Catalog(CatalogRoute::SkillVersion { .. })
            | Self::Workspace(_)
            | Self::Share(_)
                if query.is_some() =>
            {
                Err(ApiError::coded(
                    StatusCode::BAD_REQUEST,
                    match self.error_domain() {
                        ErrorDomain::Catalog => "CATALOG_BAD_REQUEST",
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
            | Self::Workspace(_)
            | Self::Share(_) => Ok(()),
        }
    }

    pub(super) fn requires_idempotency_key(&self) -> bool {
        matches!(self, Self::Share(ShareRoute::Create))
    }

    pub(super) fn requires_json_body(&self) -> bool {
        matches!(self, Self::Share(ShareRoute::Create))
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
fn validate_catalog_list_query(query: Option<&str>) -> Result<(), ApiError> {
    let Some(query) = query else {
        return Err(catalog_query_error());
    };
    let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    if pairs.len() == 1 && pairs[0].0 == "page_size" && pairs[0].1 == "100" {
        Ok(())
    } else {
        Err(catalog_query_error())
    }
}

fn catalog_query_error() -> ApiError {
    ApiError::coded(
        StatusCode::BAD_REQUEST,
        "CATALOG_BAD_REQUEST",
        "The catalog query is invalid.",
        None,
    )
}
