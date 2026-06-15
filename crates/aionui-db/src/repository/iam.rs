use crate::error::DbError;
use crate::models::{DirectorySyncStateRow, OrganizationRow, User, UserOrganizationRow};

#[derive(Debug, Clone)]
pub struct CreateLocalUserParams<'a> {
    pub username: &'a str,
    pub password_hash: &'a str,
    pub display_name: Option<&'a str>,
    pub email: Option<&'a str>,
    pub mobile: Option<&'a str>,
    pub status: &'a str,
    pub is_admin: bool,
}

#[derive(Debug, Clone)]
pub struct UpdateUserParams<'a> {
    pub display_name: Option<&'a str>,
    pub email: Option<&'a str>,
    pub mobile: Option<&'a str>,
    pub status: Option<&'a str>,
    pub is_admin: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct CreateOrganizationParams<'a> {
    pub parent_id: Option<&'a str>,
    pub name: &'a str,
    pub status: &'a str,
    pub sort: i64,
}

#[derive(Debug, Clone)]
pub struct UpdateOrganizationParams<'a> {
    pub parent_id: Option<Option<&'a str>>,
    pub name: Option<&'a str>,
    pub status: Option<&'a str>,
    pub sort: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct UpsertExternalOrganizationParams<'a> {
    pub external_id: &'a str,
    pub parent_external_id: Option<&'a str>,
    pub name: &'a str,
    pub status: &'a str,
    pub sort: i64,
}

#[derive(Debug, Clone)]
pub struct UpsertExternalUserParams<'a> {
    pub external_id: &'a str,
    pub username: &'a str,
    pub display_name: Option<&'a str>,
    pub email: Option<&'a str>,
    pub mobile: Option<&'a str>,
    pub departments_json: Option<&'a str>,
    pub auth_source: Option<&'a str>,
    pub app_code: &'a str,
    pub external_status: Option<&'a str>,
    pub external_updated_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SyncCounts {
    pub user_count: i64,
    pub department_count: i64,
    pub user_created: i64,
    pub user_updated: i64,
    pub user_disabled: i64,
}

#[async_trait::async_trait]
pub trait IIamRepository: Send + Sync {
    async fn list_users(&self) -> Result<Vec<User>, DbError>;
    async fn get_user(&self, id: &str) -> Result<Option<User>, DbError>;
    async fn create_local_user(&self, params: CreateLocalUserParams<'_>) -> Result<User, DbError>;
    async fn update_user(&self, id: &str, params: UpdateUserParams<'_>) -> Result<User, DbError>;
    async fn reset_user_password(&self, id: &str, password_hash: &str) -> Result<(), DbError>;
    async fn count_active_admins_except(&self, except_user_id: Option<&str>) -> Result<i64, DbError>;

    async fn list_organizations(&self) -> Result<Vec<OrganizationRow>, DbError>;
    async fn get_organization(&self, id: &str) -> Result<Option<OrganizationRow>, DbError>;
    async fn create_local_organization(&self, params: CreateOrganizationParams<'_>)
    -> Result<OrganizationRow, DbError>;
    async fn update_local_organization(
        &self,
        id: &str,
        params: UpdateOrganizationParams<'_>,
    ) -> Result<OrganizationRow, DbError>;
    async fn delete_local_organization(&self, id: &str) -> Result<(), DbError>;

    async fn replace_local_user_organizations(&self, user_id: &str, organization_ids: &[String])
    -> Result<(), DbError>;
    async fn replace_external_user_organizations(
        &self,
        user_id: &str,
        organization_external_ids: &[String],
    ) -> Result<(), DbError>;
    async fn list_user_organizations(&self, user_id: &str) -> Result<Vec<OrganizationRow>, DbError>;
    async fn list_all_user_organizations(&self) -> Result<Vec<UserOrganizationRow>, DbError>;

    async fn upsert_external_organization(
        &self,
        params: UpsertExternalOrganizationParams<'_>,
    ) -> Result<OrganizationRow, DbError>;
    async fn upsert_external_user(&self, params: UpsertExternalUserParams<'_>) -> Result<(User, bool), DbError>;
    async fn disable_missing_external_users(&self, seen_external_ids: &[String]) -> Result<i64, DbError>;
    async fn save_directory_sync_state(
        &self,
        app_code: &str,
        full: bool,
        status: &str,
        message: Option<&str>,
        counts: SyncCounts,
    ) -> Result<DirectorySyncStateRow, DbError>;
    async fn directory_sync_state(&self, app_code: &str) -> Result<Option<DirectorySyncStateRow>, DbError>;
}
