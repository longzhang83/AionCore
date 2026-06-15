use aionui_db::{
    CreateOrganizationParams, IIamRepository, SqliteIamRepository, SyncCounts, UpdateOrganizationParams,
    UpsertExternalOrganizationParams, UpsertExternalUserParams, init_database_memory,
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
            departments_json: Some(r#"["dept-child"]"#),
            auth_source: Some("auth-center-directory"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: Some(1000),
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
            departments_json: Some(r#"["dept-root"]"#),
            auth_source: Some("auth-center-directory"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: Some(2000),
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
async fn full_sync_disable_missing_external_users_only_touches_unseen_external_users() {
    let repo = repo().await;
    let (seen_user, _) = repo
        .upsert_external_user(UpsertExternalUserParams {
            external_id: "seen",
            username: "seen",
            display_name: None,
            email: None,
            mobile: None,
            departments_json: None,
            auth_source: Some("auth-center-directory"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: None,
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
            departments_json: None,
            auth_source: Some("auth-center-directory"),
            app_code: "agent",
            external_status: Some("active"),
            external_updated_at: None,
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
    let incremental = repo
        .save_directory_sync_state(
            "agent",
            false,
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
    assert!(incremental.last_synced_at.is_some());
    assert!(incremental.last_full_synced_at.is_none());

    let full = repo
        .save_directory_sync_state(
            "agent",
            true,
            "success",
            Some("full ok"),
            SyncCounts {
                user_count: 1,
                department_count: 1,
                user_created: 0,
                user_updated: 1,
                user_disabled: 1,
            },
        )
        .await
        .unwrap();

    assert_eq!(full.app_code, "agent");
    assert_eq!(full.last_message.as_deref(), Some("full ok"));
    assert!(full.last_synced_at.is_some());
    assert!(full.last_full_synced_at.is_some());
    assert_eq!(full.user_updated, 1);
    assert_eq!(full.user_disabled, 1);
}
