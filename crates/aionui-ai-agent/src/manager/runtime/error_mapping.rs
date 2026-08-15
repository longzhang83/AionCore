use crate::error::AgentError;
use crate::protocol::runtime_error::RuntimeError;
use crate::protocol::runtime_send_error::RuntimeSendError;

#[derive(Debug)]
pub(super) enum ProtocolSendFailure {
    Agent(AgentError),
    Protocol(RuntimeError),
}

impl ProtocolSendFailure {
    #[allow(dead_code)]
    pub(super) fn to_agent_send_error(&self) -> RuntimeSendError {
        match self {
            ProtocolSendFailure::Agent(err) => RuntimeSendError::from_agent_error_ref(err),
            ProtocolSendFailure::Protocol(err) => RuntimeSendError::from_runtime_error_ref(err),
        }
    }

    pub(super) fn to_agent_send_error_for_backend(&self, backend: Option<&str>) -> RuntimeSendError {
        match self {
            ProtocolSendFailure::Agent(err) => RuntimeSendError::from_agent_error_ref_for_backend(err, backend),
            ProtocolSendFailure::Protocol(err) => RuntimeSendError::from_runtime_error_ref_for_backend(err, backend),
        }
    }

    pub(super) fn into_agent_error(self) -> AgentError {
        match self {
            ProtocolSendFailure::Agent(err) => err,
            ProtocolSendFailure::Protocol(err) => AgentError::Runtime(err),
        }
    }
}

impl From<AgentError> for ProtocolSendFailure {
    fn from(err: AgentError) -> Self {
        ProtocolSendFailure::Agent(err)
    }
}

impl From<RuntimeError> for ProtocolSendFailure {
    fn from(err: RuntimeError) -> Self {
        ProtocolSendFailure::Protocol(err)
    }
}

impl std::fmt::Display for ProtocolSendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolSendFailure::Agent(err) => std::fmt::Display::fmt(err, f),
            ProtocolSendFailure::Protocol(err) => f.write_str(&protocol_error_public_message(err)),
        }
    }
}

impl std::error::Error for ProtocolSendFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProtocolSendFailure::Agent(err) => Some(err),
            ProtocolSendFailure::Protocol(err) => Some(err),
        }
    }
}

pub(super) fn is_protocol_session_not_found(err: &RuntimeError) -> bool {
    matches!(err, RuntimeError::SessionNotFound { .. })
}

pub(super) fn is_missing_resumed_session(err: &RuntimeError, resumed_session_id: &str) -> bool {
    is_protocol_session_not_found(err)
        || matches!(
            err,
            RuntimeError::ResourceNotFound {
                resource: Some(resource),
                ..
            } if resource == resumed_session_id
        )
}

fn protocol_error_public_message(err: &RuntimeError) -> String {
    match err {
        RuntimeError::AgentInternal { code, .. } => format!("Agent internal error (code {code})"),
        _ => err.to_string(),
    }
}
