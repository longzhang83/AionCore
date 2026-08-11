/// Authentication-layer errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Password validation failed: {0}")]
    WeakPassword(String),

    #[error("Username validation failed: {0}")]
    InvalidUsername(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("Token invalid: {0}")]
    TokenInvalid(String),

    #[error("Token blacklisted")]
    TokenBlacklisted,

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("Password hash error: {0}")]
    HashError(String),
}

/// Auth Center protocol-client errors.
///
/// Owned by `aionui-auth` so the HTTP client layer stays free of
/// `aionui_common::ApiError`; route handlers map it to `ApiError` at the
/// API boundary.
#[derive(Debug, thiserror::Error)]
pub enum AuthCenterError {
    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Internal(String),

    #[error("{0}")]
    BadRequest(String),

    #[error("{0}")]
    Unauthorized(String),

    #[error("{0}")]
    Forbidden(String),

    #[error("{0}")]
    BadGateway(String),
}
