#![allow(clippy::disallowed_types)]

use aionui_common::ApiError;

use crate::error::AgentError;
use crate::protocol::runtime_error::RuntimeError;

pub(crate) fn agent_error_to_api_error(err: AgentError) -> ApiError {
    match err {
        AgentError::BadRequest(message) => ApiError::BadRequest(message),
        AgentError::Unauthorized(message) => ApiError::Unauthorized(message),
        AgentError::Forbidden(message) => ApiError::Forbidden(message),
        AgentError::NotFound(message) => ApiError::NotFound(message),
        AgentError::Conflict(message) => ApiError::Conflict(message),
        AgentError::BadGateway(message) => ApiError::BadGateway(message),
        AgentError::Timeout(message) => ApiError::Timeout(message),
        AgentError::RateLimited => ApiError::RateLimited,
        AgentError::ConversationArchived(message) => ApiError::ConversationArchived(message),
        AgentError::WorkspacePathRuntimeUnavailable(path) => ApiError::WorkspacePathRuntimeUnavailable(path),
        AgentError::Internal(message) => ApiError::Internal(message),
        AgentError::Runtime(err) => runtime_error_to_api_error(err),
    }
}

fn runtime_error_to_api_error(err: RuntimeError) -> ApiError {
    match &err {
        RuntimeError::SpawnFailed { .. } | RuntimeError::StartupCrash { .. } | RuntimeError::Disconnected { .. } => {
            ApiError::BadGateway(runtime_error_public_message(&err))
        }
        RuntimeError::AuthRequired => ApiError::Unauthorized("Agent requires authentication".into()),
        RuntimeError::ProtocolParseError { .. } => ApiError::BadGateway(runtime_error_public_message(&err)),
        RuntimeError::InvalidRequest { .. } => ApiError::BadRequest(runtime_error_public_message(&err)),
        RuntimeError::SessionNotFound { .. } => ApiError::NotFound(runtime_error_public_message(&err)),
        RuntimeError::ResourceNotFound { .. } => ApiError::NotFound(runtime_error_public_message(&err)),
        RuntimeError::MethodNotFound { .. } => ApiError::BadRequest(runtime_error_public_message(&err)),
        RuntimeError::InvalidParams { .. } => ApiError::BadRequest(runtime_error_public_message(&err)),
        RuntimeError::AgentInternal { .. } => ApiError::BadGateway(runtime_error_public_message(&err)),
        RuntimeError::OtherProtocolError { .. } => ApiError::BadGateway(runtime_error_public_message(&err)),
        RuntimeError::NotConnected => ApiError::BadGateway(runtime_error_public_message(&err)),
        RuntimeError::InitTimeout { .. } => ApiError::BadGateway(runtime_error_public_message(&err)),
        // Short config/mode/model RPC timeout: connection is alive, the agent
        // just did not answer in time. Surface as a retryable Timeout so the
        // user can immediately retry the config change (see ELECTRON-3MS).
        RuntimeError::RequestTimeout { .. } => ApiError::Timeout(runtime_error_public_message(&err)),
    }
}

fn runtime_error_public_message(err: &RuntimeError) -> String {
    match err {
        RuntimeError::SpawnFailed { .. } | RuntimeError::StartupCrash { .. } | RuntimeError::Disconnected { .. } => {
            "Agent process is unavailable.".to_owned()
        }
        RuntimeError::AuthRequired => "Agent requires authentication.".to_owned(),
        RuntimeError::ProtocolParseError { .. } => "Agent returned malformed protocol data.".to_owned(),
        RuntimeError::InvalidRequest { .. } => "Agent rejected an invalid protocol request.".to_owned(),
        RuntimeError::SessionNotFound { .. } => "Agent session was not found.".to_owned(),
        RuntimeError::ResourceNotFound { .. } => "Agent resource was not found.".to_owned(),
        RuntimeError::MethodNotFound { .. } => "Agent method is not supported.".to_owned(),
        RuntimeError::InvalidParams { .. } => "Invalid ACP request parameters.".to_owned(),
        RuntimeError::AgentInternal { code, .. } => format!("Agent internal error (code {code})"),
        RuntimeError::OtherProtocolError { code, .. } => format!("Agent protocol error (code {code})"),
        RuntimeError::NotConnected => "ACP protocol is not connected.".to_owned(),
        RuntimeError::InitTimeout { .. } => "Agent initialization timed out.".to_owned(),
        RuntimeError::RequestTimeout { .. } => "Agent did not respond to the request in time.".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn runtime_error_to_api_error_status_codes() {
        let cases = vec![
            (
                RuntimeError::SpawnFailed { message: "x".into() },
                StatusCode::BAD_GATEWAY,
            ),
            (RuntimeError::AuthRequired, StatusCode::UNAUTHORIZED),
            (
                RuntimeError::ProtocolParseError {
                    message: "Parse error".into(),
                },
                StatusCode::BAD_GATEWAY,
            ),
            (
                RuntimeError::InvalidRequest {
                    message: "Invalid request".into(),
                },
                StatusCode::BAD_REQUEST,
            ),
            (
                RuntimeError::SessionNotFound { session_id: "s".into() },
                StatusCode::NOT_FOUND,
            ),
            (
                RuntimeError::ResourceNotFound {
                    resource: Some("file:///missing.txt".into()),
                    message: "Resource not found".into(),
                },
                StatusCode::NOT_FOUND,
            ),
            (
                RuntimeError::MethodNotFound { method: "m".into() },
                StatusCode::BAD_REQUEST,
            ),
            (
                RuntimeError::InvalidParams { message: "p".into() },
                StatusCode::BAD_REQUEST,
            ),
            (
                RuntimeError::AgentInternal {
                    message: "e".into(),
                    code: -1,
                    data: None,
                },
                StatusCode::BAD_GATEWAY,
            ),
            (
                RuntimeError::OtherProtocolError {
                    code: -32099,
                    message: "custom error".into(),
                    data: None,
                },
                StatusCode::BAD_GATEWAY,
            ),
            (RuntimeError::NotConnected, StatusCode::BAD_GATEWAY),
            (RuntimeError::InitTimeout { timeout_secs: 30 }, StatusCode::BAD_GATEWAY),
        ];

        for (runtime_err, expected_status) in cases {
            let api_err = runtime_error_to_api_error(runtime_err);
            assert_eq!(api_err.status_code(), expected_status, "Mismatch for {api_err:?}");
        }
    }

    #[test]
    fn runtime_error_to_api_error_omits_stderr_and_structured_data() {
        let startup = runtime_error_to_api_error(RuntimeError::StartupCrash {
            exit_code: Some(1),
            signal: None,
            stderr: "Authorization: Bearer sk-secret".into(),
        });
        assert!(!startup.to_string().contains("sk-secret"));
        assert!(!startup.to_string().contains("Authorization"));

        let internal = runtime_error_to_api_error(RuntimeError::AgentInternal {
            message: "Internal error".into(),
            code: -32603,
            data: Some(serde_json::json!({
                "error": "Failed to connect MCP servers",
                "api_key": "sk-secret"
            })),
        });
        let rendered = internal.to_string();
        assert!(rendered.contains("Agent internal error (code -32603)"));
        assert!(!rendered.contains("Failed to connect MCP servers"));
        assert!(!rendered.contains("sk-secret"));
        assert!(!rendered.contains("api_key"));
    }

    #[test]
    fn runtime_error_to_api_error_uses_fixed_public_messages() {
        let cases = vec![
            runtime_error_to_api_error(RuntimeError::SpawnFailed {
                message: "spawn failed at /tmp/agent with token sk-secret".into(),
            }),
            runtime_error_to_api_error(RuntimeError::SessionNotFound {
                session_id: "/tmp/session-123".into(),
            }),
            runtime_error_to_api_error(RuntimeError::MethodNotFound {
                method: "debug.dumpSecrets".into(),
            }),
            runtime_error_to_api_error(RuntimeError::InvalidParams {
                message: "invalid path /tmp/private and token sk-secret".into(),
            }),
            runtime_error_to_api_error(RuntimeError::InitTimeout { timeout_secs: 42 }),
        ];

        for api_err in cases {
            let rendered = api_err.public_message();
            assert!(!rendered.contains("/tmp"), "leaked path in {rendered}");
            assert!(!rendered.contains("sk-secret"), "leaked token in {rendered}");
            assert!(!rendered.contains("debug.dumpSecrets"), "leaked method in {rendered}");
            assert!(!rendered.contains("42"), "leaked internal timeout in {rendered}");
        }
    }
}
