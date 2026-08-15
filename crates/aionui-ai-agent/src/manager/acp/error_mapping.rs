use crate::error::AgentError;
use crate::protocol::runtime_error::RuntimeError;
use crate::protocol::runtime_send_error::RuntimeSendError;

#[derive(Debug)]
pub(super) enum AcpSendFailure {
    Agent(AgentError),
    Acp(RuntimeError),
}

impl AcpSendFailure {
    #[allow(dead_code)]
    pub(super) fn to_agent_send_error(&self) -> RuntimeSendError {
        match self {
            AcpSendFailure::Agent(err) => RuntimeSendError::from_agent_error_ref(err),
            AcpSendFailure::Acp(err) => RuntimeSendError::from_runtime_error_ref(err),
        }
    }

    pub(super) fn to_agent_send_error_for_backend(&self, backend: Option<&str>) -> RuntimeSendError {
        match self {
            AcpSendFailure::Agent(err) => RuntimeSendError::from_agent_error_ref_for_backend(err, backend),
            AcpSendFailure::Acp(err) => RuntimeSendError::from_runtime_error_ref_for_backend(err, backend),
        }
    }

    pub(super) fn into_agent_error(self) -> AgentError {
        match self {
            AcpSendFailure::Agent(err) => err,
            AcpSendFailure::Acp(err) => AgentError::Runtime(err),
        }
    }
}

impl From<AgentError> for AcpSendFailure {
    fn from(err: AgentError) -> Self {
        AcpSendFailure::Agent(err)
    }
}

impl From<RuntimeError> for AcpSendFailure {
    fn from(err: RuntimeError) -> Self {
        AcpSendFailure::Acp(err)
    }
}

impl std::fmt::Display for AcpSendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcpSendFailure::Agent(err) => std::fmt::Display::fmt(err, f),
            AcpSendFailure::Acp(err) => f.write_str(&acp_error_public_message(err)),
        }
    }
}

impl std::error::Error for AcpSendFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AcpSendFailure::Agent(err) => Some(err),
            AcpSendFailure::Acp(err) => Some(err),
        }
    }
}

pub(super) fn is_acp_session_not_found(err: &RuntimeError) -> bool {
    matches!(err, RuntimeError::SessionNotFound { .. })
}

pub(super) fn is_missing_resumed_session(err: &RuntimeError, resumed_session_id: &str) -> bool {
    is_acp_session_not_found(err)
        || matches!(
            err,
            RuntimeError::ResourceNotFound {
                resource: Some(resource),
                ..
            } if resource == resumed_session_id
        )
}

fn acp_error_public_message(err: &RuntimeError) -> String {
    match err {
        RuntimeError::AgentInternal { code, .. } => format!("Agent internal error (code {code})"),
        _ => err.to_string(),
    }
}
