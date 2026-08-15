//! Business-logic layer for the ai-agent crate.
//!
//! Per `AGENTS.md` "Domain Crate Structure", this is the sole location
//! for agent-related business logic. HTTP handlers in `routes/` should
//! only extract inputs, call methods on this service, and wrap the
//! result in `ApiResponse`.
//!
//! Session-scoped operations (mode/model/config/usage/capabilities/
//! slash-commands/side-question/workspace/openclaw-runtime) now live in
//! `aionui-conversation::ConversationService`, which dispatches through
//! `AgentInstance`. This service retains only agent-catalog and
//! ACP health-check responsibilities, plus support for the custom-agent
//! CRUD endpoints (see `services::custom`).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use aionui_api_types::{
    AgentLogoEntry, AgentManagementRow, AgentSource, AgentWarmupRequest, AgentWarmupResponse, AgentWarmupResult,
    AgentWarmupStatus, ProviderHealthCheckRequest, ProviderHealthCheckResponse,
};
use aionui_common::AgentType;
use aionui_db::IProviderRepository;
use aionui_realtime::EventBroadcaster;

use super::availability::{AgentAvailabilityFeedbackPort, AgentAvailabilityService};
use super::provider_health::ProviderHealthCheckService;
use crate::error::AgentError;
use crate::registry::AgentRegistry;

pub struct AgentService {
    registry: Arc<AgentRegistry>,
    broadcaster: Arc<dyn EventBroadcaster>,
    provider_health: ProviderHealthCheckService,
    availability: AgentAvailabilityService,
}

impl AgentService {
    pub fn new(
        registry: Arc<AgentRegistry>,
        broadcaster: Arc<dyn EventBroadcaster>,
        provider_repo: Arc<dyn IProviderRepository>,
        encryption_key: [u8; 32],
        data_dir: PathBuf,
    ) -> Arc<Self> {
        let provider_health = ProviderHealthCheckService::new(provider_repo.clone(), encryption_key, data_dir.clone());
        let availability = AgentAvailabilityService::new(registry.clone(), provider_repo);
        Arc::new(Self {
            registry,
            broadcaster,
            provider_health,
            availability,
        })
    }

    /// Registry accessor consumed by the `services::custom` submodule
    /// for direct repository access (upsert / delete / enable toggle).
    pub(crate) fn registry(&self) -> &Arc<AgentRegistry> {
        &self.registry
    }

    pub(crate) fn broadcaster(&self) -> &Arc<dyn EventBroadcaster> {
        &self.broadcaster
    }

    pub fn availability_feedback_port(&self) -> Arc<dyn AgentAvailabilityFeedbackPort> {
        Arc::new(self.availability.clone())
    }
}

// Agent operations
impl AgentService {
    pub async fn list_management_agents(&self, user_id: &str) -> Result<Vec<AgentManagementRow>, AgentError> {
        self.availability.list_management_rows(user_id).await
    }

    /// Backend → logo URL catalog for business surfaces.
    ///
    /// Business pages (guid, team, cron, conversation lists) must render
    /// an agent logo from a backend identifier alone, without owning a
    /// hardcoded path map. This projects every known agent row — including
    /// user-disabled or currently-missing ones, so historical conversations
    /// still resolve a logo — down to its `backend` and stored `icon` URL.
    pub async fn list_agent_logos(&self) -> Result<Vec<AgentLogoEntry>, AgentError> {
        let mut seen = std::collections::HashSet::new();
        let mut entries = Vec::new();
        for agent in self.registry.list_all_including_hidden().await {
            let Some(logo) = agent.icon.filter(|value| !value.is_empty()) else {
                continue;
            };
            // Frontend rows resolve a logo from the conversation's runtime key,
            // which is the vendor `backend` for ACP agents but the `agent_type`
            // for backends without a vendor label (e.g. aionrs, where `backend`
            // is NULL). Key on `backend` when present, otherwise the agent_type.
            let key = agent
                .backend
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| agent.agent_type.serde_name().to_owned());
            if key.is_empty() {
                continue;
            }
            if seen.insert(key.clone()) {
                entries.push(AgentLogoEntry { backend: key, logo });
            }
        }
        Ok(entries)
    }

    pub async fn health_check_agent_by_id(&self, user_id: &str, id: &str) -> Result<AgentManagementRow, AgentError> {
        self.availability.run_manual_health_check(user_id, id).await
    }

    pub async fn provider_health_check(
        &self,
        user_id: &str,
        req: ProviderHealthCheckRequest,
    ) -> Result<ProviderHealthCheckResponse, AgentError> {
        self.provider_health.health_check(user_id, req).await
    }

    pub async fn set_agent_overrides(
        &self,
        user_id: &str,
        id: &str,
        req: aionui_api_types::SetAgentOverridesRequest,
    ) -> Result<AgentManagementRow, AgentError> {
        let repo = self.registry.repo_handle();
        let row = repo
            .get_for_user(user_id, id)
            .await
            .map_err(|e| AgentError::internal(format!("repo.get_for_user: {e}")))?
            .ok_or_else(|| AgentError::not_found(format!("Agent '{id}' not found")))?;

        let command_override = req
            .command_override
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let has_env_override = req
            .env_override
            .as_ref()
            .is_some_and(|entries| entries.iter().any(|entry| !entry.name.trim().is_empty()));

        if (command_override.is_some() || has_env_override) && is_internal_aion_cli_row(&row) {
            return Err(AgentError::bad_request("Internal Aion CLI does not support overrides"));
        }

        // Launch-path overrides only make sense for direct-CLI rows. Bridge-launched
        // rows (e.g. `npx`) keep the bridge's own arguments in `args` (such as
        // `-y <package> acp`); swapping `command` for a launch path would feed those
        // bridge arguments to the target binary and break startup. Reject the write so
        // the stored spawn command stays coherent (env overrides remain allowed).
        if command_override.is_some() && is_bridge_launched_row(&row) {
            return Err(AgentError::bad_request(
                "This agent launches through a package runner (npx); its launch path cannot be overridden. Use environment variables instead.",
            ));
        }

        let env_json = match req.env_override {
            Some(entries) if !entries.is_empty() => Some(
                serde_json::to_string(&entries)
                    .map_err(|e| AgentError::internal(format!("encode env_override: {e}")))?,
            ),
            _ => None,
        };

        repo.update_agent_overrides_for_user(user_id, id, command_override.as_deref(), env_json.as_deref())
            .await
            .map_err(|e| AgentError::internal(format!("repo.update_agent_overrides_for_user: {e}")))?;

        self.availability.run_manual_health_check(user_id, id).await
    }

    pub async fn get_agent_overrides(
        &self,
        user_id: &str,
        id: &str,
    ) -> Result<aionui_api_types::AgentOverridesResponse, AgentError> {
        let row = self
            .registry
            .repo_handle()
            .get_for_user(user_id, id)
            .await
            .map_err(|e| AgentError::internal(format!("repo.get_for_user: {e}")))?
            .ok_or_else(|| AgentError::not_found(format!("Agent '{id}' not found")))?;

        let env_override = row
            .env_override
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<aionui_api_types::AgentEnvEntry>>(s).ok())
            .unwrap_or_default();

        Ok(aionui_api_types::AgentOverridesResponse {
            command_override: if is_internal_aion_cli_row(&row) {
                None
            } else {
                row.command_override
            },
            env_override,
        })
    }

    pub async fn warmup_agents(
        &self,
        user_id: &str,
        req: AgentWarmupRequest,
    ) -> Result<AgentWarmupResponse, AgentError> {
        let mut results = Vec::with_capacity(req.backends.len());
        let mut seen = HashSet::new();

        for raw_backend in req.backends {
            let backend = raw_backend.trim().to_lowercase();
            if backend.is_empty() || !seen.insert(backend.clone()) {
                continue;
            }

            results.push(self.warmup_backend(user_id, &backend).await);
        }

        Ok(AgentWarmupResponse { results })
    }

    async fn warmup_backend(&self, user_id: &str, backend: &str) -> AgentWarmupResult {
        let Some(meta) = self.registry.find_builtin_by_backend(backend).await else {
            return AgentWarmupResult {
                backend: backend.to_owned(),
                status: AgentWarmupStatus::Skipped,
                agent_id: None,
                error: Some("agent backend is not registered".into()),
            };
        };

        if meta.agent_type != AgentType::Acp || meta.agent_source != AgentSource::Builtin {
            return AgentWarmupResult {
                backend: backend.to_owned(),
                status: AgentWarmupStatus::Skipped,
                agent_id: Some(meta.id),
                error: Some("agent backend is not a builtin ACP agent".into()),
            };
        }

        let Some(command) = meta.resolved_command.clone() else {
            return AgentWarmupResult {
                backend: backend.to_owned(),
                status: AgentWarmupStatus::Skipped,
                agent_id: Some(meta.id),
                error: Some("agent CLI is not available".into()),
            };
        };

        let mut env: HashMap<String, String> = meta
            .env
            .iter()
            .map(|entry| (entry.name.clone(), entry.value.clone()))
            .collect();
        if meta.backend.as_deref() == Some("claude") {
            env.extend(crate::cc_switch::read_claude_provider_env());
        }

        match crate::protocol::custom_agent_probe::runtime_initialize(command, &meta.args, &env).await {
            Ok(handshake) => {
                if handshake.agent_capabilities.is_some() || handshake.auth_methods.is_some() {
                    self.registry
                        .catalog_sender()
                        .send_partial(user_id.to_owned(), meta.id.clone(), handshake);
                }
                AgentWarmupResult {
                    backend: backend.to_owned(),
                    status: AgentWarmupStatus::Ready,
                    agent_id: Some(meta.id),
                    error: None,
                }
            }
            Err(error) => AgentWarmupResult {
                backend: backend.to_owned(),
                status: AgentWarmupStatus::Failed,
                agent_id: Some(meta.id),
                error: Some(error),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use aionui_api_types::{AgentWarmupReason, AgentWarmupRequest, AgentWarmupStatus};
    use aionui_db::{
        IAgentMetadataRepository, IProviderRepository, SqliteAgentMetadataRepository, SqliteProviderRepository,
        UpsertAgentMetadataParams,
    };
    use aionui_realtime::EventBroadcaster;

    use super::*;

    struct NoopBroadcaster;

    impl EventBroadcaster for NoopBroadcaster {
        fn broadcast(&self, _msg: aionui_api_types::WebSocketMessage<serde_json::Value>) {}
    }

    async fn setup_service() -> (Arc<AgentService>, Arc<dyn IAgentMetadataRepository>) {
        let db = aionui_db::init_database_memory().await.unwrap();
        let repo: Arc<dyn IAgentMetadataRepository> = Arc::new(SqliteAgentMetadataRepository::new(db.pool().clone()));
        let provider_repo: Arc<dyn IProviderRepository> = Arc::new(SqliteProviderRepository::new(db.pool().clone()));
        let registry = AgentRegistry::new(repo.clone());
        registry.hydrate().await.unwrap();
        (
            AgentService::new(
                registry,
                Arc::new(NoopBroadcaster),
                provider_repo,
                [0; 32],
                PathBuf::from(std::env::temp_dir()),
            ),
            repo,
        )
    }

    fn missing_builtin_params<'a>(id: &'a str, backend: &'a str) -> UpsertAgentMetadataParams<'a> {
        UpsertAgentMetadataParams {
            id,
            icon: None,
            name: "Missing Warmup Agent",
            name_i18n: None,
            description: Some("missing warmup test row"),
            description_i18n: None,
            backend: Some(backend),
            agent_type: "acp",
            agent_source: "builtin",
            agent_source_info: Some(r#"{"binary_name":"aionui-definitely-missing-warmup"}"#),
            enabled: true,
            command: Some("aionui-definitely-missing-warmup"),
            args: Some("[]"),
            env: Some("[]"),
            native_skills_dirs: None,
            behavior_policy: None,
            yolo_id: None,
            agent_capabilities: None,
            auth_methods: None,
            config_options: None,
            available_modes: None,
            available_models: None,
            available_commands: None,
            sort_order: 9900,
        }
    }

    #[tokio::test]
    async fn warmup_empty_backends_returns_empty_results() {
        let (service, _repo) = setup_service().await;

        let resp = service
            .warmup_agents(
                "system_default_user",
                AgentWarmupRequest {
                    backends: vec![],
                    reason: AgentWarmupReason::Idle,
                },
            )
            .await
            .unwrap();

        assert!(resp.results.is_empty());
    }

    #[tokio::test]
    async fn warmup_unknown_backend_returns_structured_skip() {
        let (service, _repo) = setup_service().await;

        let resp = service
            .warmup_agents(
                "system_default_user",
                AgentWarmupRequest {
                    backends: vec!["not-real-agent".into()],
                    reason: AgentWarmupReason::UserSelect,
                },
            )
            .await
            .unwrap();

        assert_eq!(resp.results.len(), 1);
        assert_eq!(resp.results[0].backend, "not-real-agent");
        assert_eq!(resp.results[0].status, AgentWarmupStatus::Skipped);
        assert!(resp.results[0].error.as_deref().unwrap().contains("not registered"));
    }

    #[tokio::test]
    async fn warmup_missing_builtin_cli_returns_structured_skip() {
        let (service, repo) = setup_service().await;
        repo.upsert(&missing_builtin_params("missing-warmup", "missing-warmup"))
            .await
            .unwrap();
        service.registry.hydrate().await.unwrap();

        let resp = service
            .warmup_agents(
                "system_default_user",
                AgentWarmupRequest {
                    backends: vec!["missing-warmup".into()],
                    reason: AgentWarmupReason::BeforeSend,
                },
            )
            .await
            .unwrap();

        assert_eq!(resp.results.len(), 1);
        assert_eq!(resp.results[0].status, AgentWarmupStatus::Skipped);
        assert_eq!(resp.results[0].agent_id.as_deref(), Some("missing-warmup"));
        assert!(resp.results[0].error.as_deref().unwrap().contains("not available"));
    }
}

/// True when the row is launched through a bridge binary (e.g. `npx`) rather
/// than a direct CLI. Such rows store the bridge's own arguments in `args`
/// (e.g. `-y <package> acp`), so replacing `command` with a launch path would
/// forward those bridge arguments to the target binary. Launch-path overrides
/// are therefore only valid for direct-CLI rows (`command == binary_name`, no
/// bridge). Unparseable or absent `agent_source_info` is treated as direct.
fn is_bridge_launched_row(row: &aionui_db::AgentMetadataRow) -> bool {
    let Some(raw) = row.agent_source_info.as_deref() else {
        return false;
    };
    let Ok(info) = serde_json::from_str::<aionui_api_types::AgentSourceInfo>(raw) else {
        return false;
    };
    match info.bridge_binary.as_deref() {
        Some(bridge) => info.binary_name.as_deref() != Some(bridge),
        None => false,
    }
}

fn is_internal_aion_cli_row(row: &aionui_db::AgentMetadataRow) -> bool {
    row.agent_type.eq_ignore_ascii_case("aionrs") && row.agent_source.eq_ignore_ascii_case("internal")
}
