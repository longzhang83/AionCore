use aionui_common::TimestampMs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserType {
    Local,
    Aionpro,
}

impl UserType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Aionpro => "aionpro",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Disabled,
}

impl UserStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

/// Row mapping for the `users` table.
///
/// All fields match the SQLite column names and types exactly.
/// Optional fields correspond to nullable columns.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub user_type: UserType,
    pub external_user_id: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub password_hash: Option<String>,
    pub auth_sub: Option<String>,
    pub auth_provider: Option<String>,
    pub display_name: Option<String>,
    pub mobile: Option<String>,
    pub department_ids: Option<String>,
    pub auth_source: Option<String>,
    pub auth_app_code: Option<String>,
    pub source: String,
    pub external_status: Option<String>,
    pub is_admin: i64,
    pub external_updated_at: Option<TimestampMs>,
    pub avatar_path: Option<String>,
    pub jwt_secret: Option<String>,
    pub status: UserStatus,
    pub session_generation: i64,
    pub created_at: TimestampMs,
    pub updated_at: TimestampMs,
    pub last_login: Option<TimestampMs>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalUserProjection {
    pub username: Option<String>,
    pub email: Option<String>,
    pub avatar_path: Option<String>,
}
