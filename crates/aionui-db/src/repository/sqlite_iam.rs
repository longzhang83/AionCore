use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use crate::error::DbError;
use crate::models::{DirectorySyncStateRow, OrganizationRow, User, UserOrganizationRow};
use crate::repository::iam::{
    CreateLocalUserParams, CreateOrganizationParams, IIamRepository, SyncCounts, UpdateOrganizationParams,
    UpdateUserParams, UpsertExternalOrganizationParams, UpsertExternalUserParams,
};

const AUTH_CENTER_PROVIDER: &str = "rsm-auth-center";

#[derive(Clone, Debug)]
pub struct SqliteIamRepository {
    pool: SqlitePool,
}

impl SqliteIamRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl IIamRepository for SqliteIamRepository {
    async fn list_users(&self) -> Result<Vec<User>, DbError> {
        sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(DbError::Query)
    }

    async fn get_user(&self, id: &str) -> Result<Option<User>, DbError> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(DbError::Query)
    }

    async fn create_local_user(&self, params: CreateLocalUserParams<'_>) -> Result<User, DbError> {
        let id = aionui_common::generate_prefixed_id("user");
        let now = aionui_common::now_ms();
        sqlx::query(
            r#"
INSERT INTO users (
    id, username, email, password_hash, display_name, mobile, source, status, is_admin, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, 'local', ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(params.username)
        .bind(params.email)
        .bind(params.password_hash)
        .bind(params.display_name)
        .bind(params.mobile)
        .bind(params.status)
        .bind(bool_to_i64(params.is_admin))
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_unique_user_error(params.username))?;

        self.get_user(&id)
            .await?
            .ok_or_else(|| DbError::NotFound(format!("User '{id}' not found after insert")))
    }

    async fn update_user(&self, id: &str, params: UpdateUserParams<'_>) -> Result<User, DbError> {
        let now = aionui_common::now_ms();
        let existing = self
            .get_user(id)
            .await?
            .ok_or_else(|| DbError::NotFound(format!("User '{id}' not found")))?;
        sqlx::query(
            r#"
UPDATE users
SET display_name = ?,
    email = ?,
    mobile = ?,
    status = ?,
    is_admin = ?,
    updated_at = ?
WHERE id = ?
            "#,
        )
        .bind(params.display_name.or(existing.display_name.as_deref()))
        .bind(params.email.or(existing.email.as_deref()))
        .bind(params.mobile.or(existing.mobile.as_deref()))
        .bind(params.status.unwrap_or(existing.status.as_str()))
        .bind(params.is_admin.map(bool_to_i64).unwrap_or(existing.is_admin))
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(map_unique_user_error(existing.username.as_deref().unwrap_or("")))?;

        self.get_user(id)
            .await?
            .ok_or_else(|| DbError::NotFound(format!("User '{id}' not found after update")))
    }

    async fn reset_user_password(&self, id: &str, password_hash: &str) -> Result<(), DbError> {
        let now = aionui_common::now_ms();
        let result = sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
            .bind(password_hash)
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("User '{id}' not found")));
        }
        Ok(())
    }

    async fn count_active_admins_except(&self, except_user_id: Option<&str>) -> Result<i64, DbError> {
        match except_user_id {
            Some(user_id) => {
                sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND status = 'active' AND id != ?")
                    .bind(user_id)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(DbError::Query)
            }
            None => sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND status = 'active'")
                .fetch_one(&self.pool)
                .await
                .map_err(DbError::Query),
        }
    }

    async fn list_organizations(&self) -> Result<Vec<OrganizationRow>, DbError> {
        sqlx::query_as::<_, OrganizationRow>(
            "SELECT * FROM organizations ORDER BY sort ASC, name COLLATE NOCASE ASC, created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(DbError::Query)
    }

    async fn get_organization(&self, id: &str) -> Result<Option<OrganizationRow>, DbError> {
        sqlx::query_as::<_, OrganizationRow>("SELECT * FROM organizations WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(DbError::Query)
    }

    async fn create_local_organization(
        &self,
        params: CreateOrganizationParams<'_>,
    ) -> Result<OrganizationRow, DbError> {
        let id = aionui_common::generate_prefixed_id("org");
        let now = aionui_common::now_ms();
        sqlx::query(
            r#"
INSERT INTO organizations (id, parent_id, name, source, status, sort, created_at, updated_at)
VALUES (?, ?, ?, 'local', ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(params.parent_id)
        .bind(params.name)
        .bind(params.status)
        .bind(params.sort)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(DbError::Query)?;
        self.get_organization(&id)
            .await?
            .ok_or_else(|| DbError::NotFound(format!("Organization '{id}' not found after insert")))
    }

    async fn update_local_organization(
        &self,
        id: &str,
        params: UpdateOrganizationParams<'_>,
    ) -> Result<OrganizationRow, DbError> {
        let existing = self
            .get_organization(id)
            .await?
            .ok_or_else(|| DbError::NotFound(format!("Organization '{id}' not found")))?;
        if existing.source != "local" {
            return Err(DbError::Conflict("Auth Center organizations are read-only".into()));
        }
        let now = aionui_common::now_ms();
        sqlx::query(
            r#"
UPDATE organizations
SET parent_id = ?, name = ?, status = ?, sort = ?, updated_at = ?
WHERE id = ?
            "#,
        )
        .bind(params.parent_id.unwrap_or(existing.parent_id.as_deref()))
        .bind(params.name.unwrap_or(&existing.name))
        .bind(params.status.unwrap_or(&existing.status))
        .bind(params.sort.unwrap_or(existing.sort))
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(DbError::Query)?;
        self.get_organization(id)
            .await?
            .ok_or_else(|| DbError::NotFound(format!("Organization '{id}' not found after update")))
    }

    async fn delete_local_organization(&self, id: &str) -> Result<(), DbError> {
        let existing = self
            .get_organization(id)
            .await?
            .ok_or_else(|| DbError::NotFound(format!("Organization '{id}' not found")))?;
        if existing.source != "local" {
            return Err(DbError::Conflict("Auth Center organizations are read-only".into()));
        }
        sqlx::query("DELETE FROM organizations WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(DbError::Query)?;
        Ok(())
    }

    async fn replace_local_user_organizations(
        &self,
        user_id: &str,
        organization_ids: &[String],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(DbError::Query)?;
        let now = aionui_common::now_ms();
        sqlx::query("DELETE FROM user_organizations WHERE user_id = ? AND source = 'local'")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(DbError::Query)?;
        for (idx, org_id) in organization_ids.iter().enumerate() {
            sqlx::query(
                r#"
INSERT INTO user_organizations (user_id, organization_id, source, is_primary, created_at, updated_at)
VALUES (?, ?, 'local', ?, ?, ?)
                "#,
            )
            .bind(user_id)
            .bind(org_id)
            .bind(if idx == 0 { 1_i64 } else { 0_i64 })
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(DbError::Query)?;
        }
        tx.commit().await.map_err(DbError::Query)
    }

    async fn replace_external_user_organizations(
        &self,
        user_id: &str,
        organization_external_ids: &[String],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(DbError::Query)?;
        let now = aionui_common::now_ms();
        sqlx::query("DELETE FROM user_organizations WHERE user_id = ? AND source = 'auth_center'")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(DbError::Query)?;

        for (idx, external_id) in organization_external_ids.iter().enumerate() {
            let org_id: Option<String> =
                sqlx::query_scalar("SELECT id FROM organizations WHERE source = 'auth_center' AND external_id = ?")
                    .bind(external_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(DbError::Query)?;
            if let Some(org_id) = org_id {
                sqlx::query(
                    r#"
INSERT INTO user_organizations (user_id, organization_id, source, is_primary, created_at, updated_at)
VALUES (?, ?, 'auth_center', ?, ?, ?)
                    "#,
                )
                .bind(user_id)
                .bind(org_id)
                .bind(if idx == 0 { 1_i64 } else { 0_i64 })
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(DbError::Query)?;
            }
        }
        tx.commit().await.map_err(DbError::Query)
    }

    async fn list_user_organizations(&self, user_id: &str) -> Result<Vec<OrganizationRow>, DbError> {
        sqlx::query_as::<_, OrganizationRow>(
            r#"
SELECT organizations.*
FROM organizations
JOIN user_organizations ON user_organizations.organization_id = organizations.id
WHERE user_organizations.user_id = ?
ORDER BY user_organizations.is_primary DESC, organizations.sort ASC, organizations.name COLLATE NOCASE ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(DbError::Query)
    }

    async fn list_all_user_organizations(&self) -> Result<Vec<UserOrganizationRow>, DbError> {
        sqlx::query_as::<_, UserOrganizationRow>("SELECT * FROM user_organizations")
            .fetch_all(&self.pool)
            .await
            .map_err(DbError::Query)
    }

    async fn upsert_external_organization(
        &self,
        params: UpsertExternalOrganizationParams<'_>,
    ) -> Result<OrganizationRow, DbError> {
        let now = aionui_common::now_ms();
        let parent_id: Option<String> = match params.parent_external_id.filter(|value| !value.is_empty()) {
            Some(parent_external_id) => {
                sqlx::query_scalar("SELECT id FROM organizations WHERE source = 'auth_center' AND external_id = ?")
                    .bind(parent_external_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(DbError::Query)?
            }
            None => None,
        };
        let existing_id: Option<String> =
            sqlx::query_scalar("SELECT id FROM organizations WHERE source = 'auth_center' AND external_id = ?")
                .bind(params.external_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(DbError::Query)?;

        let id = match existing_id {
            Some(id) => {
                sqlx::query(
                    r#"
UPDATE organizations
SET parent_id = ?, name = ?, status = ?, sort = ?, updated_at = ?
WHERE id = ?
                    "#,
                )
                .bind(parent_id.as_deref())
                .bind(params.name)
                .bind(params.status)
                .bind(params.sort)
                .bind(now)
                .bind(&id)
                .execute(&self.pool)
                .await
                .map_err(DbError::Query)?;
                id
            }
            None => {
                let id = aionui_common::generate_prefixed_id("org");
                sqlx::query(
                    r#"
INSERT INTO organizations (
    id, parent_id, name, source, external_id, status, sort, created_at, updated_at
) VALUES (?, ?, ?, 'auth_center', ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(&id)
                .bind(parent_id.as_deref())
                .bind(params.name)
                .bind(params.external_id)
                .bind(params.status)
                .bind(params.sort)
                .bind(now)
                .bind(now)
                .execute(&self.pool)
                .await
                .map_err(DbError::Query)?;
                id
            }
        };

        self.get_organization(&id)
            .await?
            .ok_or_else(|| DbError::NotFound(format!("Organization '{id}' not found after upsert")))
    }

    async fn upsert_external_user(&self, params: UpsertExternalUserParams<'_>) -> Result<(User, bool), DbError> {
        let now = aionui_common::now_ms();
        let existing: Option<User> =
            sqlx::query_as::<_, User>("SELECT * FROM users WHERE auth_provider = ? AND auth_sub = ?")
                .bind(AUTH_CENTER_PROVIDER)
                .bind(params.external_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(DbError::Query)?;

        match existing {
            Some(user) => {
                sqlx::query(
                    r#"
UPDATE users
SET email = ?, display_name = ?, mobile = ?, department_ids = ?, auth_source = ?,
    auth_app_code = ?, source = 'auth_center', external_status = ?, external_updated_at = ?, updated_at = ?
WHERE id = ?
                    "#,
                )
                .bind(params.email)
                .bind(params.display_name)
                .bind(params.mobile)
                .bind(params.departments_json)
                .bind(params.auth_source)
                .bind(params.app_code)
                .bind(params.external_status)
                .bind(params.external_updated_at)
                .bind(now)
                .bind(&user.id)
                .execute(&self.pool)
                .await
                .map_err(DbError::Query)?;
                let updated = self
                    .get_user(&user.id)
                    .await?
                    .ok_or_else(|| DbError::NotFound(format!("User '{}' not found after update", user.id)))?;
                Ok((updated, false))
            }
            None => {
                let id = aionui_common::generate_prefixed_id("user");
                let username = unique_username(&self.pool, params.username).await?;
                sqlx::query(
                    r#"
INSERT INTO users (
    id, username, email, password_hash, auth_sub, auth_provider, display_name, mobile, department_ids,
    auth_source, auth_app_code, source, status, external_status, is_admin, external_updated_at, created_at, updated_at
) VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, 'auth_center', 'active', ?, 0, ?, ?, ?)
                    "#,
                )
                .bind(&id)
                .bind(&username)
                .bind(params.email)
                .bind(params.external_id)
                .bind(AUTH_CENTER_PROVIDER)
                .bind(params.display_name)
                .bind(params.mobile)
                .bind(params.departments_json)
                .bind(params.auth_source)
                .bind(params.app_code)
                .bind(params.external_status)
                .bind(params.external_updated_at)
                .bind(now)
                .bind(now)
                .execute(&self.pool)
                .await
                .map_err(map_unique_user_error(&username))?;
                let created = self
                    .get_user(&id)
                    .await?
                    .ok_or_else(|| DbError::NotFound(format!("User '{id}' not found after insert")))?;
                Ok((created, true))
            }
        }
    }

    async fn disable_missing_external_users(&self, seen_external_ids: &[String]) -> Result<i64, DbError> {
        let now = aionui_common::now_ms();
        if seen_external_ids.is_empty() {
            let result = sqlx::query(
                r#"
UPDATE users
SET external_status = 'disabled', updated_at = ?
WHERE source = 'auth_center' AND auth_provider = ? AND COALESCE(external_status, '') != 'disabled'
                "#,
            )
            .bind(now)
            .bind(AUTH_CENTER_PROVIDER)
            .execute(&self.pool)
            .await
            .map_err(DbError::Query)?;
            return Ok(result.rows_affected() as i64);
        }

        let mut builder: QueryBuilder<'_, Sqlite> =
            QueryBuilder::new("UPDATE users SET external_status = 'disabled', updated_at = ");
        builder.push_bind(now);
        builder.push(" WHERE source = 'auth_center' AND auth_provider = ");
        builder.push_bind(AUTH_CENTER_PROVIDER);
        builder.push(" AND COALESCE(external_status, '') != 'disabled' AND auth_sub NOT IN (");
        let mut separated = builder.separated(", ");
        for id in seen_external_ids {
            separated.push_bind(id);
        }
        separated.push_unseparated(")");
        let result = builder.build().execute(&self.pool).await.map_err(DbError::Query)?;
        Ok(result.rows_affected() as i64)
    }

    async fn save_directory_sync_state(
        &self,
        app_code: &str,
        full: bool,
        status: &str,
        message: Option<&str>,
        counts: SyncCounts,
    ) -> Result<DirectorySyncStateRow, DbError> {
        let now = aionui_common::now_ms();
        sqlx::query(
            r#"
INSERT INTO auth_center_directory_sync_states (
    app_code, last_synced_at, last_full_synced_at, last_status, last_message,
    user_count, department_count, user_created, user_updated, user_disabled, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(app_code) DO UPDATE SET
    last_synced_at = excluded.last_synced_at,
    last_full_synced_at = COALESCE(excluded.last_full_synced_at, auth_center_directory_sync_states.last_full_synced_at),
    last_status = excluded.last_status,
    last_message = excluded.last_message,
    user_count = excluded.user_count,
    department_count = excluded.department_count,
    user_created = excluded.user_created,
    user_updated = excluded.user_updated,
    user_disabled = excluded.user_disabled,
    updated_at = excluded.updated_at
            "#,
        )
        .bind(app_code)
        .bind(if status == "success" { Some(now) } else { None })
        .bind(if full && status == "success" { Some(now) } else { None })
        .bind(status)
        .bind(message)
        .bind(counts.user_count)
        .bind(counts.department_count)
        .bind(counts.user_created)
        .bind(counts.user_updated)
        .bind(counts.user_disabled)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(DbError::Query)?;
        self.directory_sync_state(app_code)
            .await?
            .ok_or_else(|| DbError::NotFound(format!("Directory sync state '{app_code}' not found after upsert")))
    }

    async fn directory_sync_state(&self, app_code: &str) -> Result<Option<DirectorySyncStateRow>, DbError> {
        sqlx::query_as::<_, DirectorySyncStateRow>("SELECT * FROM auth_center_directory_sync_states WHERE app_code = ?")
            .bind(app_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(DbError::Query)
    }
}

async fn unique_username(pool: &SqlitePool, requested: &str) -> Result<String, DbError> {
    let base = requested.trim().chars().take(32).collect::<String>();
    for suffix in 0..1000 {
        let candidate = if suffix == 0 {
            base.clone()
        } else {
            let max_base = 31_usize.saturating_sub(suffix.to_string().len());
            format!("{}_{}", base.chars().take(max_base).collect::<String>(), suffix)
        };
        let exists: bool = sqlx::query_scalar("SELECT COUNT(*) > 0 FROM users WHERE username = ?")
            .bind(&candidate)
            .fetch_one(pool)
            .await
            .map_err(DbError::Query)?;
        if !exists {
            return Ok(candidate);
        }
    }
    Err(DbError::Conflict(format!(
        "Could not allocate username for '{requested}'"
    )))
}

fn bool_to_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn map_unique_user_error(username: &str) -> impl FnOnce(sqlx::Error) -> DbError + '_ {
    move |error| match &error {
        sqlx::Error::Database(db_err) if is_unique_violation(db_err.as_ref()) => {
            DbError::Conflict(format!("Username '{username}' already exists"))
        }
        _ => DbError::Query(error),
    }
}

fn is_unique_violation(err: &dyn sqlx::error::DatabaseError) -> bool {
    err.code().is_some_and(|code| code == "2067" || code == "1555")
}
