use aionui_common::TimestampMs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct OrganizationRow {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub source: String,
    pub external_id: Option<String>,
    pub status: String,
    pub sort: i64,
    pub created_at: TimestampMs,
    pub updated_at: TimestampMs,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserOrganizationRow {
    pub user_id: String,
    pub organization_id: String,
    pub source: String,
    pub is_primary: i64,
    pub created_at: TimestampMs,
    pub updated_at: TimestampMs,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DirectorySyncStateRow {
    pub app_code: String,
    pub last_synced_at: Option<TimestampMs>,
    pub last_full_synced_at: Option<TimestampMs>,
    pub last_status: String,
    pub last_message: Option<String>,
    pub user_count: i64,
    pub department_count: i64,
    pub user_created: i64,
    pub user_updated: i64,
    pub user_disabled: i64,
    pub updated_at: TimestampMs,
}
