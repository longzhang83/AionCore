use aionui_db::{
    CreateOrganizationParams, IIamRepository, SqliteIamRepository, SyncCounts, UpdateOrganizationParams,
    UpsertExternalOrganizationParams, UpsertExternalUserParams, UserStatus, init_database_memory,
};

async fn repo() -> SqliteIamRepository {
    let db = init_database_memory().await.unwrap();
    SqliteIamRepository::new(db.pool().clone())
}

#[tokio::test]
async fn local_organization_update_can_clear_parent() {
    let repo = repo().await;
    let parent = repo
        .create_local_organization(CreateOrganizationParams {
            parent_id: None,
            name: "Parent",
            status: "active",
            sort: 1,
        })
        .await
        .unwrap();
    let child = repo
        .create_local_organization(CreateOrganizationParams {
            parent_id: Some(&parent.id),
            name: "Child",
            status: "active",
            sort: 2,
        })
        .await
        .unwrap();

    let updated = repo
        .update_local_organization(
            &child.id,
            UpdateOrganizationParams {
                parent_id: Some(None),
                name: None,
                status: None,
                sort: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.id, child.id);
    assert_eq!(updated.parent_id, None);
}

#[tokio::test]
async fn external_organization_tree_and_user_relations_are_idempotent() {
    let repo = repo().await;
    let root = repo
        .upsert_external_organization(UpsertExternalOrganizationParams {
            external_id: "dept-root",
            parent_external_id: None,
            name: "Root",
            status: "active",
            sort: 1,
        })
        .await
        .unwrap();
    let child = repo
        .upsert_external_organization(UpsertExternalOrganizationParams {
            external_id: "dept-child",
            parent_external_id: Some("dept-root"),
            name: "Child",
            status: "active",
            sort: 2,
        })
        .await
        .unwrap();
    assert_eq!(child.parent_id.as_deref(), Some(root.id.as_str()));

    let (user, created) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "auth-user-1",
            username: "alice",
            display_name: Some("Alice"),
            email: Some("alice@example.test"),
            mobile: None,
            position: None,
            position_sort: None,
            departments_json: Some(r#"["dept-child"]"#),
            auth_source: Some("auth-center-directory"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: Some(1000),
            is_admin: false,
        })
        .await
        .unwrap();
    assert!(created);
    repo.replace_external_user_organizations(&user.id, &[String::from("dept-child")])
        .await
        .unwrap();
    let orgs = repo.list_user_organizations(&user.id).await.unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0].id, child.id);

    let (updated, created) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "auth-user-1",
            username: "alice-renamed",
            display_name: Some("Alice Updated"),
            email: Some("alice2@example.test"),
            mobile: Some("123"),
            position: None,
            position_sort: None,
            departments_json: Some(r#"["dept-root"]"#),
            auth_source: Some("auth-center-directory"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: Some(2000),
            is_admin: false,
        })
        .await
        .unwrap();
    assert!(!created);
    assert_eq!(updated.id, user.id);
    assert_eq!(updated.display_name.as_deref(), Some("Alice Updated"));

    repo.replace_external_user_organizations(&updated.id, &[String::from("dept-root")])
        .await
        .unwrap();
    let orgs = repo.list_user_organizations(&updated.id).await.unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0].id, root.id);
}

#[tokio::test]
async fn external_user_upsert_treats_blank_email_as_missing() {
    let repo = repo().await;
    let (first, first_created) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "auth-user-blank-email-1",
            username: "blank_email_one",
            display_name: Some("Blank Email One"),
            email: Some(""),
            mobile: None,
            position: None,
            position_sort: None,
            departments_json: None,
            auth_source: Some("wecom"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: None,
            is_admin: false,
        })
        .await
        .unwrap();
    let (second, second_created) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "auth-user-blank-email-2",
            username: "blank_email_two",
            display_name: Some("Blank Email Two"),
            email: Some("   "),
            mobile: None,
            position: None,
            position_sort: None,
            departments_json: None,
            auth_source: Some("wecom"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: None,
            is_admin: false,
        })
        .await
        .unwrap();

    assert!(first_created);
    assert!(second_created);
    assert_ne!(first.id, second.id);
    assert_eq!(first.email, None);
    assert_eq!(second.email, None);
}

#[tokio::test]
async fn external_user_upsert_persists_position_metadata() {
    let repo = repo().await;
    let (created, created_flag) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "auth-position-user",
            username: "auth_position",
            display_name: Some("Auth Position"),
            email: Some("auth-position@example.test"),
            mobile: None,
            position: Some("Consultant"),
            position_sort: Some(30),
            departments_json: None,
            auth_source: Some("wecom"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: None,
            is_admin: false,
        })
        .await
        .unwrap();

    assert!(created_flag);
    assert_eq!(created.position.as_deref(), Some("Consultant"));
    assert_eq!(created.position_sort, Some(30));

    let (updated, updated_flag) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "auth-position-user",
            username: "auth_position",
            display_name: Some("Auth Position"),
            email: Some("auth-position@example.test"),
            mobile: None,
            position: Some("Manager"),
            position_sort: Some(10),
            departments_json: None,
            auth_source: Some("wecom"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: None,
            is_admin: false,
        })
        .await
        .unwrap();

    assert!(!updated_flag);
    assert_eq!(updated.id, created.id);
    assert_eq!(updated.position.as_deref(), Some("Manager"));
    assert_eq!(updated.position_sort, Some(10));
}

#[tokio::test]
async fn external_user_upsert_mirrors_disabled_external_status_to_local_status() {
    let repo = repo().await;
    let (disabled, created) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "auth-disabled-user",
            username: "auth_disabled",
            display_name: Some("Auth Disabled"),
            email: Some("auth-disabled@example.test"),
            mobile: None,
            position: None,
            position_sort: None,
            departments_json: None,
            auth_source: Some("wecom"),
            app_code: "agent",
            external_status: Some("disabled"),
            external_updated_at: None,
            is_admin: false,
        })
        .await
        .unwrap();

    assert!(created);
    assert_eq!(disabled.status, UserStatus::Disabled);
    assert_eq!(disabled.external_status.as_deref(), Some("disabled"));

    let (enabled, updated_created) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "auth-disabled-user",
            username: "auth_disabled",
            display_name: Some("Auth Enabled"),
            email: Some("auth-disabled@example.test"),
            mobile: None,
            position: None,
            position_sort: None,
            departments_json: None,
            auth_source: Some("wecom"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: None,
            is_admin: false,
        })
        .await
        .unwrap();

    assert!(!updated_created);
    assert_eq!(enabled.status, UserStatus::Active);
    assert_eq!(enabled.external_status.as_deref(), Some("active"));
}

#[tokio::test]
async fn disable_missing_external_users_repairs_local_status_when_external_status_was_already_disabled() {
    let db = init_database_memory().await.unwrap();
    let repo = SqliteIamRepository::new(db.pool().clone());
    let (user, _) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "auth-stale-disabled-user",
            username: "auth_stale_disabled",
            display_name: Some("Auth Stale Disabled"),
            email: Some("auth-stale-disabled@example.test"),
            mobile: None,
            position: None,
            position_sort: None,
            departments_json: None,
            auth_source: Some("wecom"),
            app_code: "agent",
            external_status: Some("disabled"),
            external_updated_at: None,
            is_admin: false,
        })
        .await
        .unwrap();
    sqlx::query("UPDATE users SET status = 'active' WHERE id = ?")
        .bind(&user.id)
        .execute(db.pool())
        .await
        .unwrap();

    let disabled_count = repo.disable_missing_external_users(&[]).await.unwrap();
    let repaired = repo.get_user(&user.id).await.unwrap().unwrap();

    assert_eq!(disabled_count, 1);
    assert_eq!(repaired.status, UserStatus::Disabled);
    assert_eq!(repaired.external_status.as_deref(), Some("disabled"));
}

#[tokio::test]
async fn list_users_orders_by_position_sort_from_directory_metadata() {
    let repo = repo().await;
    for (external_id, username, display_name, position, position_sort) in [
        (
            "auth-position-late",
            "late_position",
            "Late Position",
            Some("Consultant"),
            Some(30),
        ),
        (
            "auth-position-unsorted",
            "unsorted_position",
            "Unsorted Position",
            None,
            None,
        ),
        (
            "auth-position-early",
            "early_position",
            "Early Position",
            Some("Manager"),
            Some(10),
        ),
    ] {
        repo.upsert_external_user(UpsertExternalUserParams {
            external_id,
            username,
            display_name: Some(display_name),
            email: None,
            mobile: None,
            position,
            position_sort,
            departments_json: None,
            auth_source: Some("wecom"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: None,
            is_admin: false,
        })
        .await
        .unwrap();
    }

    let users = repo.list_users().await.unwrap();
    let external_users: Vec<_> = users.into_iter().filter(|user| user.source == "auth_center").collect();

    assert_eq!(
        external_users
            .iter()
            .map(|user| user.username.as_deref().unwrap())
            .collect::<Vec<_>>(),
        vec!["early_position", "late_position", "unsorted_position"]
    );
}

#[tokio::test]
async fn external_user_upsert_uses_authoritative_admin_flag() {
    let repo = repo().await;
    let (created, created_flag) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "auth-admin-user",
            username: "auth_admin",
            display_name: Some("Auth Admin"),
            email: Some("auth-admin@example.test"),
            mobile: None,
            position: None,
            position_sort: None,
            departments_json: None,
            auth_source: Some("wecom"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: None,
            is_admin: true,
        })
        .await
        .unwrap();

    assert!(created_flag);
    assert_eq!(created.is_admin, 1);

    let (demoted, demoted_created) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "auth-admin-user",
            username: "auth_admin",
            display_name: Some("Auth Admin"),
            email: Some("auth-admin@example.test"),
            mobile: None,
            position: None,
            position_sort: None,
            departments_json: None,
            auth_source: Some("wecom"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: None,
            is_admin: false,
        })
        .await
        .unwrap();

    assert!(!demoted_created);
    assert_eq!(demoted.id, created.id);
    assert_eq!(demoted.is_admin, 0);
}

#[tokio::test]
async fn full_sync_disable_missing_external_users_only_touches_unseen_external_users() {
    let repo = repo().await;
    let (seen_user, _) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "seen",
            username: "seen",
            display_name: None,
            email: None,
            mobile: None,
            position: None,
            position_sort: None,
            departments_json: None,
            auth_source: Some("auth-center-directory"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: None,
            is_admin: false,
        })
        .await
        .unwrap();
    let (missing_user, _) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "missing",
            username: "missing",
            display_name: None,
            email: None,
            mobile: None,
            position: None,
            position_sort: None,
            departments_json: None,
            auth_source: Some("auth-center-directory"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: None,
            is_admin: false,
        })
        .await
        .unwrap();

    let disabled = repo
        .disable_missing_external_users(&[String::from("seen")])
        .await
        .unwrap();

    assert_eq!(disabled, 1);
    let seen = repo.get_user(&seen_user.id).await.unwrap().unwrap();
    let missing = repo.get_user(&missing_user.id).await.unwrap().unwrap();
    assert_eq!(seen.external_status.as_deref(), Some("active"));
    assert_eq!(missing.external_status.as_deref(), Some("disabled"));
}

#[tokio::test]
async fn directory_sync_state_upsert_tracks_incremental_and_full_success() {
    let repo = repo().await;
    repo.upsert_external_organization(UpsertExternalOrganizationParams {
        external_id: "dept-root",
        parent_external_id: None,
        name: "Root",
        status: "active",
        sort: 1,
    })
    .await
    .unwrap();
    repo.upsert_external_user(UpsertExternalUserParams {
        external_id: "auth-user-1",
        username: "alice",
        display_name: None,
        email: Some("alice@example.test"),
        mobile: None,
        position: None,
        position_sort: None,
        departments_json: None,
        auth_source: Some("wecom"),
        app_code: "agent",
        external_status: Some("active"),
        external_updated_at: None,
        is_admin: false,
    })
    .await
    .unwrap();
    repo.upsert_external_user(UpsertExternalUserParams {
        external_id: "auth-user-2",
        username: "bob",
        display_name: None,
        email: Some("bob@example.test"),
        mobile: None,
        position: None,
        position_sort: None,
        departments_json: None,
        auth_source: Some("wecom"),
        app_code: "agent",
        external_status: Some("active"),
        external_updated_at: None,
        is_admin: false,
    })
    .await
    .unwrap();
    repo.upsert_external_user(UpsertExternalUserParams {
        external_id: "auth-user-3",
        username: "disabled_user",
        display_name: None,
        email: Some("disabled@example.test"),
        mobile: None,
        position: None,
        position_sort: None,
        departments_json: None,
        auth_source: Some("wecom"),
        app_code: "agent",
        external_status: Some("disabled"),
        external_updated_at: None,
        is_admin: false,
    })
    .await
    .unwrap();

    let full = repo
        .save_directory_sync_state(
            "agent",
            true,
            "success",
            Some("full ok"),
            SyncCounts {
                user_count: 3,
                department_count: 1,
                user_created: 3,
                user_updated: 0,
                user_disabled: 0,
            },
        )
        .await
        .unwrap();
    assert_eq!(full.app_code, "agent");
    assert_eq!(full.last_message.as_deref(), Some("full ok"));
    assert!(full.last_synced_at.is_some());
    assert!(full.last_full_synced_at.is_some());
    assert_eq!(full.user_count, 3);
    assert_eq!(full.department_count, 1);

    let incremental = repo
        .save_directory_sync_state("agent", false, "success", None, SyncCounts::default())
        .await
        .unwrap();

    assert_eq!(incremental.user_count, 3);
    assert_eq!(incremental.department_count, 1);
    assert_eq!(incremental.user_created, 0);
    assert_eq!(incremental.user_updated, 0);
    assert_eq!(incremental.user_disabled, 0);
    assert_eq!(incremental.last_full_synced_at, full.last_full_synced_at);
}

#[tokio::test]
async fn directory_sync_state_failure_preserves_last_success_timestamps() {
    let repo = repo().await;
    repo.upsert_external_organization(UpsertExternalOrganizationParams {
        external_id: "dept-root",
        parent_external_id: None,
        name: "Root",
        status: "active",
        sort: 1,
    })
    .await
    .unwrap();
    repo.upsert_external_user(UpsertExternalUserParams {
        external_id: "auth-user-1",
        username: "alice",
        display_name: None,
        email: Some("alice@example.test"),
        mobile: None,
        position: None,
        position_sort: None,
        departments_json: None,
        auth_source: Some("wecom"),
        app_code: "agent",
        external_status: Some("active"),
        external_updated_at: None,
        is_admin: false,
    })
    .await
    .unwrap();

    let success = repo
        .save_directory_sync_state(
            "agent",
            true,
            "success",
            None,
            SyncCounts {
                user_count: 2,
                department_count: 1,
                user_created: 2,
                user_updated: 0,
                user_disabled: 0,
            },
        )
        .await
        .unwrap();

    let failed = repo
        .save_directory_sync_state(
            "agent",
            false,
            "failed",
            Some("upstream unavailable"),
            SyncCounts::default(),
        )
        .await
        .unwrap();

    assert_eq!(failed.last_status, "failed");
    assert_eq!(failed.last_message.as_deref(), Some("upstream unavailable"));
    assert_eq!(failed.last_synced_at, success.last_synced_at);
    assert_eq!(failed.last_full_synced_at, success.last_full_synced_at);
    assert_eq!(failed.user_count, 1);
    assert_eq!(failed.department_count, 1);
}
