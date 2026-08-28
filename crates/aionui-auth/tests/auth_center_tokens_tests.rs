//! Integration tests for the Auth Center server-side token bundle and the
//! in-memory vault. These exercise the crate's public surface so callers
//! can rely on the documented re-exports.

use std::sync::Arc;

use aionui_auth::{
    AuthCenterTokenResponse, AuthCenterTokenSecret, AuthCenterTokenVaultKey, IAuthCenterTokenVault,
    InMemoryAuthCenterTokenVault, bundle_from_token_response, compute_expires_at_ms, fingerprint_token,
};

fn sample_response() -> AuthCenterTokenResponse {
    AuthCenterTokenResponse {
        access_token: "AT-123".to_owned(),
        refresh_token: Some("RT-123".to_owned()),
        id_token: Some("IT-123".to_owned()),
        token_type: Some("Bearer".to_owned()),
        scope: Some("openid profile".to_owned()),
        expires_in: Some(1800),
    }
}

#[test]
fn parse_response_then_bundle_round_trip_exposes_known_values() {
    let response = sample_response();
    let bundle = bundle_from_token_response(response, 1_700_000_000_000);

    assert_eq!(bundle.access_token.expose(), "AT-123");
    assert_eq!(
        bundle.refresh_token.as_ref().map(AuthCenterTokenSecret::expose),
        Some("RT-123")
    );
    assert_eq!(
        bundle.id_token.as_ref().map(AuthCenterTokenSecret::expose),
        Some("IT-123")
    );
    assert_eq!(bundle.token_type.as_deref(), Some("Bearer"));
    assert_eq!(bundle.scope.as_deref(), Some("openid profile"));
    assert_eq!(bundle.issued_at_ms, 1_700_000_000_000);
    assert_eq!(bundle.expires_at_ms, Some(1_700_000_000_000 + 1800 * 1000));
}

#[test]
fn bundle_debug_output_never_contains_raw_token_values() {
    let bundle = bundle_from_token_response(sample_response(), 42);
    let rendered = format!("{bundle:?}");
    for secret in ["AT-123", "RT-123", "IT-123"] {
        assert!(
            !rendered.contains(secret),
            "Debug output leaked secret value {secret}: {rendered}"
        );
    }
    // Non-secret fields are preserved so log readers can still diagnose.
    assert!(rendered.contains("Bearer"));
    assert!(rendered.contains("openid profile"));
    assert!(rendered.contains("42"));
}

#[test]
fn parse_response_handles_optional_fields_missing() {
    let json = r#"{"access_token":"only-access"}"#;
    let parsed: AuthCenterTokenResponse = serde_json::from_str(json).expect("parse minimal token response");
    let bundle = bundle_from_token_response(parsed, 0);
    assert_eq!(bundle.access_token.expose(), "only-access");
    assert!(bundle.refresh_token.is_none());
    assert!(bundle.id_token.is_none());
    assert!(bundle.token_type.is_none());
    assert!(bundle.scope.is_none());
    assert!(bundle.expires_at_ms.is_none());
    assert_eq!(bundle.issued_at_ms, 0);
}

#[test]
fn compute_expires_at_ms_handles_none_and_overflow_safely() {
    assert_eq!(compute_expires_at_ms(0, None), None);
    assert_eq!(compute_expires_at_ms(0, Some(60)), Some(60_000));
    // Saturating mul prevents the rare overflow case from panicking.
    let huge = i64::MAX / 1000;
    assert_eq!(compute_expires_at_ms(huge, Some(i64::MAX)), Some(i64::MAX));
}

#[test]
fn fingerprint_is_stable_across_calls_and_unique_per_token() {
    let a1 = fingerprint_token("jwt-token-A");
    let a2 = fingerprint_token("jwt-token-A");
    let b = fingerprint_token("jwt-token-B");
    assert_eq!(a1, a2);
    assert_ne!(a1, b);
    // 64 hex chars (256 bits).
    assert_eq!(a1.len(), 64);
    assert!(a1.chars().all(|ch| ch.is_ascii_hexdigit()));
}

#[test]
fn in_memory_vault_trait_object_round_trip() {
    // Drive the vault through the trait object so the public API contract
    // (Arc<dyn IAuthCenterTokenVault>) is the one under test.
    let vault: Arc<dyn IAuthCenterTokenVault> = Arc::new(InMemoryAuthCenterTokenVault::new());
    let key = AuthCenterTokenVaultKey::from_token("jwt-A", "user-1");
    let bundle = bundle_from_token_response(sample_response(), 1_000);

    assert!(vault.get(&key).is_none());
    assert!(vault.store(key.clone(), bundle.clone()).is_none());
    assert_eq!(vault.len(), 1);

    let stored = vault.get(&key).expect("bundle must be retrievable after store");
    assert_eq!(stored.access_token.expose(), "AT-123");
    assert_eq!(
        stored.refresh_token.as_ref().map(AuthCenterTokenSecret::expose),
        Some("RT-123")
    );

    assert!(vault.clear(&key));
    assert!(!vault.clear(&key), "second clear must report absent");
    assert!(vault.is_empty());
}

#[test]
fn two_concurrent_sessions_for_same_user_remain_isolated() {
    // The original review caught this: with per-user session_generation as
    // the key, one login would replace another and one logout would clear
    // both. Keying by the local JWT fingerprint keeps the two browser
    // sessions fully independent — even though they share user_id (and
    // could share session_generation).
    let vault: Arc<dyn IAuthCenterTokenVault> = Arc::new(InMemoryAuthCenterTokenVault::new());
    let key_a = AuthCenterTokenVaultKey::from_token("jwt-A", "user-1");
    let key_b = AuthCenterTokenVaultKey::from_token("jwt-B", "user-1");

    let mut response_a = sample_response();
    response_a.access_token = "AT-A".to_owned();
    let mut response_b = sample_response();
    response_b.access_token = "AT-B".to_owned();
    vault.store(key_a.clone(), bundle_from_token_response(response_a, 1));
    vault.store(key_b.clone(), bundle_from_token_response(response_b, 2));

    // Both are visible.
    assert_eq!(vault.get(&key_a).unwrap().access_token.expose(), "AT-A");
    assert_eq!(vault.get(&key_b).unwrap().access_token.expose(), "AT-B");

    // Logging out session A must not touch session B.
    assert!(vault.clear(&key_a));
    assert!(vault.get(&key_a).is_none());
    assert!(vault.get(&key_b).is_some(), "session B must survive A's logout");

    // Re-login on session A (same fingerprint path) must not touch B.
    let mut response_a2 = sample_response();
    response_a2.access_token = "AT-A2".to_owned();
    vault.store(key_a.clone(), bundle_from_token_response(response_a2, 3));
    assert_eq!(vault.get(&key_a).unwrap().access_token.expose(), "AT-A2");
    assert_eq!(vault.get(&key_b).unwrap().access_token.expose(), "AT-B");
    assert_eq!(vault.len(), 2);
}

#[test]
fn refresh_moves_bundle_for_only_the_presented_session() {
    // Simulates /api/auth/refresh for a user with two browser sessions.
    // Session A is being refreshed: the bundle must follow the new local
    // JWT and session B must be left alone.
    let vault: Arc<dyn IAuthCenterTokenVault> = Arc::new(InMemoryAuthCenterTokenVault::new());
    let user = "user-1";

    let mut response_a = sample_response();
    response_a.access_token = "AT-A".to_owned();
    let mut response_b = sample_response();
    response_b.access_token = "AT-B".to_owned();

    let key_a_old = AuthCenterTokenVaultKey::from_token("jwt-A-old", user);
    let key_a_new = AuthCenterTokenVaultKey::from_token("jwt-A-new", user);
    let key_b = AuthCenterTokenVaultKey::from_token("jwt-B", user);

    vault.store(key_a_old.clone(), bundle_from_token_response(response_a, 1_000));
    vault.store(key_b.clone(), bundle_from_token_response(response_b, 2_000));
    assert_eq!(vault.len(), 2);

    // Refresh session A: the bundle must move to the new fingerprint.
    let moved = vault
        .move_bundle(&key_a_old, key_a_new.clone())
        .expect("bundle must be moved on refresh");
    assert_eq!(moved.access_token.expose(), "AT-A");

    // Old fingerprint is empty; new one holds the bundle.
    assert!(
        vault.get(&key_a_old).is_none(),
        "old fingerprint must be empty after refresh"
    );
    let current_a = vault
        .get(&key_a_new)
        .expect("new fingerprint must hold the refreshed session's bundle");
    assert_eq!(current_a.access_token.expose(), "AT-A");

    // Session B is untouched by session A's refresh.
    let current_b = vault.get(&key_b).unwrap();
    assert_eq!(current_b.access_token.expose(), "AT-B");
    assert_eq!(vault.len(), 2);

    // If session A refreshes again, the move follows the latest JWT.
    let key_a_third = AuthCenterTokenVaultKey::from_token("jwt-A-third", user);
    let moved_again = vault.move_bundle(&key_a_new, key_a_third.clone()).expect("second move");
    assert_eq!(moved_again.access_token.expose(), "AT-A");
    assert!(vault.get(&key_a_new).is_none());
    assert!(vault.get(&key_a_third).is_some());
    assert!(vault.get(&key_b).is_some());
}

#[test]
fn refresh_with_no_prior_bundle_is_a_no_op() {
    // First refresh on a freshly logged-in session (or any session whose
    // bundle was already cleared) must not insert a phantom entry.
    let vault: Arc<dyn IAuthCenterTokenVault> = Arc::new(InMemoryAuthCenterTokenVault::new());
    let key_missing = AuthCenterTokenVaultKey::from_token("jwt-missing", "user-1");
    let key_new = AuthCenterTokenVaultKey::from_token("jwt-new", "user-1");
    assert!(vault.move_bundle(&key_missing, key_new.clone()).is_none());
    assert!(vault.get(&key_new).is_none());
    assert!(vault.is_empty());
}

#[test]
fn replacing_bundle_returns_prior_for_rotation() {
    let vault: Arc<dyn IAuthCenterTokenVault> = Arc::new(InMemoryAuthCenterTokenVault::new());
    let key = AuthCenterTokenVaultKey::from_token("jwt-A", "user-1");

    let first = bundle_from_token_response(sample_response(), 100);
    let mut replacement_response = sample_response();
    replacement_response.access_token = "AT-NEW".to_owned();
    let replacement = bundle_from_token_response(replacement_response, 200);

    assert!(vault.store(key.clone(), first).is_none());
    let prior = vault
        .store(key.clone(), replacement)
        .expect("prior bundle returned on replace");
    assert_eq!(prior.access_token.expose(), "AT-123");
    assert_eq!(prior.issued_at_ms, 100);

    let current = vault.get(&key).unwrap();
    assert_eq!(current.access_token.expose(), "AT-NEW");
    assert_eq!(current.issued_at_ms, 200);
}

#[test]
fn clear_all_for_user_drains_every_fingerprint_but_leaves_others() {
    let vault: Arc<dyn IAuthCenterTokenVault> = Arc::new(InMemoryAuthCenterTokenVault::new());
    for token in ["jwt-A1", "jwt-A2", "jwt-A3"] {
        vault.store(
            AuthCenterTokenVaultKey::from_token(token, "alice"),
            bundle_from_token_response(sample_response(), 1),
        );
    }
    let other = AuthCenterTokenVaultKey::from_token("jwt-B1", "bob");
    vault.store(other.clone(), bundle_from_token_response(sample_response(), 1));

    let removed = vault.clear_all_for_user("alice");
    assert_eq!(removed, 3);
    assert!(
        vault
            .get(&AuthCenterTokenVaultKey::from_token("jwt-A1", "alice"))
            .is_none()
    );
    assert!(
        vault
            .get(&AuthCenterTokenVaultKey::from_token("jwt-A2", "alice"))
            .is_none()
    );
    assert!(
        vault
            .get(&AuthCenterTokenVaultKey::from_token("jwt-A3", "alice"))
            .is_none()
    );
    assert!(vault.get(&other).is_some(), "bob's session must survive");
    assert_eq!(vault.len(), 1);
}

#[test]
fn vault_entry_survives_arc_sharing() {
    // The trait object is shared via Arc — make sure concurrency-style
    // ownership doesn't lose data.
    let vault: Arc<dyn IAuthCenterTokenVault> = Arc::new(InMemoryAuthCenterTokenVault::new());
    let vault_b = vault.clone();
    let key = AuthCenterTokenVaultKey::from_token("jwt-A", "user-1");
    vault.store(key.clone(), bundle_from_token_response(sample_response(), 1));
    let bundle = vault_b.get(&key).unwrap();
    assert_eq!(bundle.access_token.expose(), "AT-123");
}
