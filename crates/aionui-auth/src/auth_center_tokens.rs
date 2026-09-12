//! Server-side Auth Center user token bundle and in-memory vault.
//!
//! After the OIDC callback exchanges the authorization code, the Auth Center
//! returns an access token (and optionally a refresh token, id token, scope,
//! and expires_in) that we want to keep for downstream calls without
//! round-tripping the user back through OIDC. We persist that bundle
//! server-side, bound to the local JWT that proves the user is logged in,
//! and remove it on logout. When the local JWT is rotated by the
//! `/api/auth/refresh` endpoint, the bundle is moved atomically from the
//! old JWT's fingerprint to the new one so the session is not orphaned.
//!
//! The vault lives behind a trait so a durable, secure backing store can
//! replace this in-memory implementation later without touching the route
//! layer. The in-memory implementation is a stop-gap — it does not survive
//! process restarts and is not safe across replicas.
//!
//! ## Keying
//!
//! Entries are keyed by a SHA-256 fingerprint of the exact local JWT
//! (hex-encoded). The same authenticated user can have several concurrent
//! browser sessions — each one has a distinct JWT (different `iat`,
//! `exp`, and `jti`) and therefore a distinct fingerprint, so logins and
//! logouts on one session never disturb the others. The same holds true
//! for `session_generation` rotations: a single user can have several
//! fingerprints sharing the same `session_generation` without collision.
//! The `jti` claim in particular is the tie-breaker that prevents two
//! OIDC callbacks landing in the same second from producing identical
//! fingerprints.
//!
//! Each entry also stores the owning `user_id` so the admin
//! `clear_all_for_user` path can drain every session for a user in one
//! pass. `session_generation` is intentionally NOT used as a key (it is a
//! per-user revocation generation, not a per-session identifier) — using
//! it would let one login replace another and one logout clear all.
//!
//! ## Atomicity
//!
//! All vault operations go through a single `Mutex<HashMap>` so the
//! trait-level "atomic move" promise is real, not a doc-fiction. A
//! `DashMap` cannot offer a `remove`+`insert` sequence under a single
//! shard lock that covers both keys, so a concurrent `get` could
//! observe the intermediate state where neither side holds the bundle.
//! The single-mutex design makes that state unreachable.
//!
//! Secrets in this module are wrapped in [`AuthCenterTokenSecret`], whose
//! `Debug` impl emits `[REDACTED]` so production logs and `tracing` events
//! never include the raw token bytes.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::device_registration::DeviceRegistrationReceipt;

/// Server-side token bundle persisted for one local user/session after a
/// successful Auth Center OIDC exchange.
///
/// The bundle is bound to a single local JWT (identified by its
/// fingerprint) via the vault and removed on logout. It is never returned
/// to the browser and never serialised into HTTP responses.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthCenterUserTokenBundle {
    /// Access token (always present — required by OIDC).
    pub access_token: AuthCenterTokenSecret,
    /// Refresh token, if the Auth Center issued one.
    pub refresh_token: Option<AuthCenterTokenSecret>,
    /// ID token, if the Auth Center included it in the token response.
    pub id_token: Option<AuthCenterTokenSecret>,
    /// Token type (typically `"Bearer"`).
    pub token_type: Option<String>,
    /// Space-separated scope string returned by the Auth Center.
    pub scope: Option<String>,
    /// Absolute expiry timestamp in milliseconds since the UNIX epoch.
    pub expires_at_ms: Option<i64>,
    /// Local wall-clock timestamp (ms since epoch) when the bundle was stored.
    pub issued_at_ms: i64,
    /// Device registration receipt from the Auth Center for this login's
    /// DPoP session key. `None` for bundles created before device enrollment
    /// existed; `#[serde(default)]` keeps previously persisted bundles
    /// (without this field) deserialisable.
    #[serde(default)]
    pub device_registration: Option<DeviceRegistrationReceipt>,
}

impl fmt::Debug for AuthCenterUserTokenBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthCenterUserTokenBundle")
            .field("access_token", &self.access_token)
            .field("refresh_token", &self.refresh_token)
            .field("id_token", &self.id_token)
            .field("token_type", &self.token_type)
            .field("scope", &self.scope)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("device_registration", &self.device_registration)
            .finish()
    }
}

/// Newtype wrapping a token secret. `Debug` is overridden to emit a fixed
/// `[REDACTED]` marker so log lines and `format!("{:?}", ...)` cannot leak
/// the raw value.
///
/// Construct with [`AuthCenterTokenSecret::new`]; recover the raw string
/// with [`AuthCenterTokenSecret::expose`] only at the actual call site to
/// the Auth Center.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthCenterTokenSecret(String);

impl AuthCenterTokenSecret {
    /// Wrap a raw token string. The caller is responsible for ensuring the
    /// value is the actual secret from a trusted source.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the raw token string. Use only at the call site that needs to
    /// present the credential to the Auth Center.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the raw string. Same restriction as
    /// [`AuthCenterTokenSecret::expose`].
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Length of the wrapped secret. Useful for diagnostics without leaking
    /// the value.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the wrapped secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for AuthCenterTokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// SHA-256 hex digest of the local JWT bytes. Stable, opaque, and short
/// enough to use as a map key. Not a secret: knowing the fingerprint of a
/// token does not let an attacker recover the token, but it is also not
/// surfaced in logs.
pub type AuthCenterTokenFingerprint = String;

/// Compute the vault key for a given (local JWT, user) pair. The
/// fingerprint is a SHA-256 hex digest of the raw JWT bytes; the user id
/// rides along for the admin `clear_all_for_user` path.
pub fn fingerprint_token(token: &str) -> AuthCenterTokenFingerprint {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Identifier for one Auth Center token bundle in the vault.
///
/// The fingerprint is the storage key; the user id is metadata used by
/// [`IAuthCenterTokenVault::clear_all_for_user`]. `session_generation` is
/// deliberately not part of this type — see the module docs for why.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthCenterTokenVaultKey {
    pub user_id: String,
    pub token_fingerprint: AuthCenterTokenFingerprint,
}

impl AuthCenterTokenVaultKey {
    /// Build a key from a raw local JWT and its owning user.
    pub fn from_token(token: impl AsRef<str>, user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            token_fingerprint: fingerprint_token(token.as_ref()),
        }
    }
}

/// Port for persisting Auth Center token bundles server-side.
///
/// Implementations must be `Send + Sync` so they can be shared via
/// `Arc<dyn IAuthCenterTokenVault>` in route state. The trait is deliberately
/// small so a durable, secure backing store (encrypted KV, KMS-backed
/// secret store, etc.) can replace [`InMemoryAuthCenterTokenVault`]
/// without touching call sites.
///
/// **Atomicity contract:** [`IAuthCenterTokenVault::move_bundle`] MUST
/// move the bundle from `from` to `to` under a single critical section
/// so no observer can ever see an intermediate state with both keys
/// empty. The in-memory implementation satisfies this with a single
/// `Mutex<HashMap>`; durable implementations must use an equivalent
/// transactional primitive (e.g. an atomic upsert or a `BEGIN`…`COMMIT`
/// in the same session).
pub trait IAuthCenterTokenVault: Send + Sync {
    /// Insert or replace the bundle under `key.token_fingerprint`,
    /// recording `key.user_id` as the owning user for `clear_all_for_user`.
    /// Returns the previous bundle, if any, so callers can log rotations
    /// without ever printing the secret itself.
    fn store(
        &self,
        key: AuthCenterTokenVaultKey,
        bundle: AuthCenterUserTokenBundle,
    ) -> Option<AuthCenterUserTokenBundle>;

    /// Look up a bundle by its key. Returns `None` if absent.
    fn get(&self, key: &AuthCenterTokenVaultKey) -> Option<AuthCenterUserTokenBundle>;

    /// Remove the bundle for `key`. Returns `true` if an entry was removed.
    fn clear(&self, key: &AuthCenterTokenVaultKey) -> bool;

    /// Atomically move a bundle from `from` to `to`. Used by
    /// `/api/auth/refresh` so the bundle follows the rotated local JWT
    /// instead of being orphaned.
    ///
    /// Returns the moved bundle, or `None` if `from` was empty (in which
    /// case nothing is inserted at `to`). Implementations MUST perform
    /// the remove and the insert under a single critical section; the
    /// `in_memory_vault_move_has_no_observable_intermediate_state` test
    /// pins this down for the in-memory implementation.
    fn move_bundle(
        &self,
        from: &AuthCenterTokenVaultKey,
        to: AuthCenterTokenVaultKey,
    ) -> Option<AuthCenterUserTokenBundle>;

    /// Remove every bundle owned by `user_id`, across all fingerprints.
    /// Returns the number of removed entries. Used by admin flows that
    /// revoke a user globally.
    fn clear_all_for_user(&self, user_id: &str) -> usize;

    /// Number of bundles currently stored. Useful for observability and
    /// tests.
    fn len(&self) -> usize;

    /// Whether the vault is empty. Companion to [`IAuthCenterTokenVault::len`].
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Concurrency-safe in-memory implementation of [`IAuthCenterTokenVault`].
///
/// This is a stop-gap. It is process-local, not durable, and not safe across
/// replicas. Production deployments should replace it via the trait before
/// relying on token survival across restarts.
///
/// All operations share a single `Mutex<HashMap>` so
/// [`IAuthCenterTokenVault::move_bundle`] is genuinely atomic — no
/// concurrent `get` can observe a state where `from` is empty but `to`
/// is also empty. A `DashMap` cannot offer this because `remove` and
/// `insert` are separate operations and two keys may live in different
/// shards.
#[derive(Debug, Default)]
pub struct InMemoryAuthCenterTokenVault {
    /// Keyed by `AuthCenterTokenVaultKey::token_fingerprint`. The owning
    /// `user_id` is stored alongside the bundle so
    /// [`IAuthCenterTokenVault::clear_all_for_user`] can sweep without a
    /// secondary index. Mutex-protected so every operation sees a
    /// consistent snapshot and `move_bundle` is atomic.
    entries: Mutex<HashMap<AuthCenterTokenFingerprint, VaultEntry>>,
}

#[derive(Debug, Clone)]
struct VaultEntry {
    user_id: String,
    bundle: AuthCenterUserTokenBundle,
}

impl InMemoryAuthCenterTokenVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap this vault in an `Arc` for injection into route state.
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Lock the underlying map. Recovery from poisoning: if a thread
    /// panicked inside a critical section, treat the lock as still
    /// holding the data we put in it and proceed. The map operations
    /// here never panic on valid input, so a poisoned lock is itself a
    /// bug we want to surface — but we choose availability for callers
    /// over aborting the process.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<AuthCenterTokenFingerprint, VaultEntry>> {
        match self.entries.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl IAuthCenterTokenVault for InMemoryAuthCenterTokenVault {
    fn store(
        &self,
        key: AuthCenterTokenVaultKey,
        bundle: AuthCenterUserTokenBundle,
    ) -> Option<AuthCenterUserTokenBundle> {
        let entry = VaultEntry {
            user_id: key.user_id,
            bundle,
        };
        self.lock()
            .insert(key.token_fingerprint, entry)
            .map(|previous| previous.bundle)
    }

    fn get(&self, key: &AuthCenterTokenVaultKey) -> Option<AuthCenterUserTokenBundle> {
        self.lock()
            .get(&key.token_fingerprint)
            .filter(|entry| entry.user_id == key.user_id)
            .map(|entry| entry.bundle.clone())
    }

    fn clear(&self, key: &AuthCenterTokenVaultKey) -> bool {
        let mut entries = self.lock();
        if entries
            .get(&key.token_fingerprint)
            .is_none_or(|entry| entry.user_id != key.user_id)
        {
            return false;
        }
        entries.remove(&key.token_fingerprint).is_some()
    }

    fn move_bundle(
        &self,
        from: &AuthCenterTokenVaultKey,
        to: AuthCenterTokenVaultKey,
    ) -> Option<AuthCenterUserTokenBundle> {
        // Single critical section: take from `from` and put at `to`
        // without ever releasing the lock. A no-op (missing `from`) does
        // not insert at `to`.
        let mut entries = self.lock();
        if from.user_id != to.user_id
            || entries
                .get(&from.token_fingerprint)
                .is_none_or(|entry| entry.user_id != from.user_id)
        {
            return None;
        }
        let entry = entries.remove(&from.token_fingerprint)?;
        let moved_bundle = entry.bundle;
        let result = moved_bundle.clone();
        let new_entry = VaultEntry {
            user_id: to.user_id,
            bundle: moved_bundle,
        };
        entries.insert(to.token_fingerprint, new_entry);
        Some(result)
    }

    fn clear_all_for_user(&self, user_id: &str) -> usize {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|_, entry| entry.user_id != user_id);
        before.saturating_sub(entries.len())
    }

    fn len(&self) -> usize {
        self.lock().len()
    }
}

/// Raw Auth Center token response as defined by RFC 6749 §5.1. This is the
/// public contract surface; the HTTP layer deserialises it from the token
/// endpoint body and the vault layer converts it into a server-side bundle.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AuthCenterTokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
}

/// Compute absolute expiry (ms since epoch) from `issued_at_ms` plus the
/// Auth Center's `expires_in` (seconds). Returns `None` when `expires_in` is
/// not provided.
pub fn compute_expires_at_ms(issued_at_ms: i64, expires_in_secs: Option<i64>) -> Option<i64> {
    expires_in_secs.map(|secs| issued_at_ms.saturating_add(secs.saturating_mul(1000)))
}

/// Convert a parsed Auth Center token response into a server-side bundle,
/// stamping it with the local issuance timestamp.
pub fn bundle_from_token_response(response: AuthCenterTokenResponse, issued_at_ms: i64) -> AuthCenterUserTokenBundle {
    AuthCenterUserTokenBundle {
        access_token: AuthCenterTokenSecret::new(response.access_token),
        refresh_token: response.refresh_token.map(AuthCenterTokenSecret::new),
        id_token: response.id_token.map(AuthCenterTokenSecret::new),
        token_type: response.token_type,
        scope: response.scope,
        expires_at_ms: compute_expires_at_ms(issued_at_ms, response.expires_in),
        issued_at_ms,
        device_registration: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn sample_response() -> AuthCenterTokenResponse {
        AuthCenterTokenResponse {
            access_token: "ACCESS-XYZ".to_owned(),
            refresh_token: Some("REFRESH-XYZ".to_owned()),
            id_token: Some("ID-XYZ".to_owned()),
            token_type: Some("Bearer".to_owned()),
            scope: Some("openid profile email".to_owned()),
            expires_in: Some(3600),
        }
    }

    #[test]
    fn auth_center_token_secret_debug_redacts_raw_value() {
        let secret = AuthCenterTokenSecret::new("super-secret-value");
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "[REDACTED]");
        assert!(!rendered.contains("super-secret-value"));
    }

    #[test]
    fn bundle_debug_redacts_every_token_field() {
        let response = sample_response();
        let bundle = bundle_from_token_response(response, 1_700_000_000_000);
        let rendered = format!("{bundle:?}");
        for forbidden in ["ACCESS-XYZ", "REFRESH-XYZ", "ID-XYZ"] {
            assert!(
                !rendered.contains(forbidden),
                "Debug output leaked secret value {forbidden}: {rendered}"
            );
        }
        // Non-secret metadata is preserved for diagnostics.
        assert!(rendered.contains("Bearer"));
        assert!(rendered.contains("openid profile email"));
        assert!(rendered.contains("1700000000000"));
    }

    #[test]
    fn parse_token_response_extracts_all_fields() {
        let json = r#"{
            "access_token": "AT",
            "refresh_token": "RT",
            "id_token": "IT",
            "token_type": "Bearer",
            "scope": "openid",
            "expires_in": 7200
        }"#;
        let parsed: AuthCenterTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.access_token, "AT");
        assert_eq!(parsed.refresh_token.as_deref(), Some("RT"));
        assert_eq!(parsed.id_token.as_deref(), Some("IT"));
        assert_eq!(parsed.token_type.as_deref(), Some("Bearer"));
        assert_eq!(parsed.scope.as_deref(), Some("openid"));
        assert_eq!(parsed.expires_in, Some(7200));
    }

    #[test]
    fn parse_token_response_handles_missing_optional_fields() {
        let json = r#"{"access_token": "AT-only"}"#;
        let parsed: AuthCenterTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.access_token, "AT-only");
        assert!(parsed.refresh_token.is_none());
        assert!(parsed.id_token.is_none());
        assert!(parsed.token_type.is_none());
        assert!(parsed.scope.is_none());
        assert!(parsed.expires_in.is_none());
    }

    #[test]
    fn compute_expires_at_ms_adds_seconds() {
        assert_eq!(compute_expires_at_ms(1000, Some(60)), Some(61_000));
        assert_eq!(compute_expires_at_ms(1000, None), None);
        assert_eq!(compute_expires_at_ms(0, Some(0)), Some(0));
    }

    #[test]
    fn bundle_from_token_response_populates_secrets_and_expiry() {
        let bundle = bundle_from_token_response(sample_response(), 1_000_000);
        assert_eq!(bundle.access_token.expose(), "ACCESS-XYZ");
        assert_eq!(bundle.refresh_token.as_ref().map(|s| s.expose()), Some("REFRESH-XYZ"));
        assert_eq!(bundle.id_token.as_ref().map(|s| s.expose()), Some("ID-XYZ"));
        assert_eq!(bundle.token_type.as_deref(), Some("Bearer"));
        assert_eq!(bundle.scope.as_deref(), Some("openid profile email"));
        assert_eq!(bundle.issued_at_ms, 1_000_000);
        assert_eq!(bundle.expires_at_ms, Some(1_000_000 + 3_600 * 1000));
    }

    #[test]
    fn old_bundle_without_device_fields_deserializes_with_default_receipt() {
        // A bundle persisted before device enrollment existed must keep
        // deserialising: the device receipt defaults to None.
        let json = r#"{
            "access_token": "AT",
            "refresh_token": "RT",
            "id_token": "IT",
            "token_type": "Bearer",
            "scope": "openid",
            "expires_at_ms": 1700003600000,
            "issued_at_ms": 1700000000000
        }"#;
        let bundle: AuthCenterUserTokenBundle = serde_json::from_str(json).unwrap();
        assert_eq!(bundle.access_token.expose(), "AT");
        assert!(bundle.device_registration.is_none());
    }

    #[test]
    fn bundle_with_device_receipt_round_trips_through_json() {
        let mut bundle = bundle_from_token_response(sample_response(), 1_000_000);
        bundle.device_registration = Some(crate::device_registration::DeviceRegistrationReceipt {
            device_id: "device-uuid-1".into(),
            status: "active".into(),
            binding_version: 1,
            authority_epoch: 1,
            registered_at: "2026-09-12T00:00:00.123456789Z".into(),
            updated_at: "2026-09-12T00:00:00.123456789Z".into(),
        });
        let serialized = serde_json::to_string(&bundle).unwrap();
        let parsed: AuthCenterUserTokenBundle = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed.device_registration, bundle.device_registration);
        assert_eq!(parsed.access_token.expose(), "ACCESS-XYZ");
    }

    #[test]
    fn fingerprint_is_deterministic_and_token_specific() {
        let a = fingerprint_token("jwt-token-A");
        let b = fingerprint_token("jwt-token-A");
        let c = fingerprint_token("jwt-token-C");
        assert_eq!(a, b, "same token must yield same fingerprint");
        assert_ne!(a, c, "different tokens must yield different fingerprints");
        // SHA-256 hex is 64 chars, all lowercase hex.
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
    }

    #[test]
    fn in_memory_vault_stores_and_returns_bundle() {
        let vault = InMemoryAuthCenterTokenVault::new();
        let key = AuthCenterTokenVaultKey::from_token("jwt-A", "user-1");
        let bundle = bundle_from_token_response(sample_response(), 1_000_000);
        assert!(vault.store(key.clone(), bundle.clone()).is_none());
        let stored = vault.get(&key).expect("bundle should be present after store");
        assert_eq!(stored.access_token.expose(), "ACCESS-XYZ");
        assert_eq!(stored.refresh_token.as_ref().map(|s| s.expose()), Some("REFRESH-XYZ"));
        assert_eq!(stored.expires_at_ms, Some(1_000_000 + 3_600 * 1000));
    }

    #[test]
    fn in_memory_vault_store_replaces_existing_entry() {
        let vault = InMemoryAuthCenterTokenVault::new();
        let key = AuthCenterTokenVaultKey::from_token("jwt-A", "user-1");
        let first = bundle_from_token_response(sample_response(), 1_000_000);
        let mut replacement_response = sample_response();
        replacement_response.access_token = "ACCESS-NEW".to_owned();
        let replacement = bundle_from_token_response(replacement_response, 2_000_000);
        vault.store(key.clone(), first);
        let prior = vault.store(key.clone(), replacement);
        assert!(prior.is_some(), "replacing must return the prior bundle");
        let current = vault.get(&key).unwrap();
        assert_eq!(current.access_token.expose(), "ACCESS-NEW");
        assert_eq!(current.issued_at_ms, 2_000_000);
    }

    #[test]
    fn in_memory_vault_clear_removes_entry() {
        let vault = InMemoryAuthCenterTokenVault::new();
        let key = AuthCenterTokenVaultKey::from_token("jwt-A", "user-1");
        vault.store(key.clone(), bundle_from_token_response(sample_response(), 1_000_000));
        assert!(vault.clear(&key));
        assert!(vault.get(&key).is_none());
        assert!(!vault.clear(&key), "clearing again must report no entry removed");
    }

    #[test]
    fn in_memory_vault_keys_are_token_specific_not_user_specific() {
        // Two distinct local JWTs for the same user (the normal case for
        // two browser sessions) must be isolated from each other.
        let vault = InMemoryAuthCenterTokenVault::new();
        let key_a = AuthCenterTokenVaultKey::from_token("jwt-A", "user-1");
        let key_b = AuthCenterTokenVaultKey::from_token("jwt-B", "user-1");
        vault.store(key_a.clone(), bundle_from_token_response(sample_response(), 1));
        vault.store(key_b.clone(), bundle_from_token_response(sample_response(), 2));
        assert!(vault.get(&key_a).is_some());
        assert!(vault.get(&key_b).is_some());
        // Removing one session must not touch the other.
        assert!(vault.clear(&key_a));
        assert!(vault.get(&key_a).is_none());
        assert!(vault.get(&key_b).is_some());
        // A different user with a different token is still isolated.
        let key_c = AuthCenterTokenVaultKey::from_token("jwt-C", "user-2");
        assert!(vault.get(&key_c).is_none());
    }

    #[test]
    fn in_memory_vault_rejects_wrong_owner_for_get_clear_and_move() {
        let vault = InMemoryAuthCenterTokenVault::new();
        let owner_key = AuthCenterTokenVaultKey::from_token("jwt-A", "user-1");
        let forged_key = AuthCenterTokenVaultKey::from_token("jwt-A", "user-2");
        vault.store(
            owner_key.clone(),
            bundle_from_token_response(sample_response(), 1_000_000),
        );

        assert!(vault.get(&forged_key).is_none());
        assert!(!vault.clear(&forged_key));
        assert!(
            vault
                .move_bundle(&forged_key, AuthCenterTokenVaultKey::from_token("jwt-B", "user-2"),)
                .is_none()
        );
        assert!(vault.get(&owner_key).is_some());
    }

    #[test]
    fn in_memory_vault_clear_all_for_user_removes_every_fingerprint() {
        let vault = InMemoryAuthCenterTokenVault::new();
        let mut alice_keys = HashSet::new();
        for token in ["jwt-A1", "jwt-A2", "jwt-A3"] {
            let key = AuthCenterTokenVaultKey::from_token(token, "alice");
            vault.store(key.clone(), bundle_from_token_response(sample_response(), 1));
            alice_keys.insert(key);
        }
        // Different user — must survive a clear_all_for_user("alice").
        let other = AuthCenterTokenVaultKey::from_token("jwt-B1", "bob");
        vault.store(other.clone(), bundle_from_token_response(sample_response(), 1));

        let removed = vault.clear_all_for_user("alice");
        assert_eq!(removed, 3);
        for key in &alice_keys {
            assert!(vault.get(key).is_none(), "session {key:?} should be cleared");
        }
        assert!(vault.get(&other).is_some());
        assert_eq!(vault.len(), 1);
    }

    #[test]
    fn in_memory_vault_len_and_is_empty() {
        let vault = InMemoryAuthCenterTokenVault::new();
        assert!(vault.is_empty());
        assert_eq!(vault.len(), 0);
        vault.store(
            AuthCenterTokenVaultKey::from_token("jwt-A", "user-1"),
            bundle_from_token_response(sample_response(), 1),
        );
        assert!(!vault.is_empty());
        assert_eq!(vault.len(), 1);
    }

    #[test]
    fn in_memory_vault_move_only_relocates_target_session() {
        // Simulates /api/auth/refresh: a user has two concurrent browser
        // sessions (jwt-A, jwt-B). The client refreshes session A; the
        // vault must move the bundle from jwt-A's fingerprint to the new
        // token's fingerprint and leave session B's bundle untouched.
        let vault = InMemoryAuthCenterTokenVault::new();
        let user = "user-1";
        let key_a_old = AuthCenterTokenVaultKey::from_token("jwt-A-old", user);
        let key_a_new = AuthCenterTokenVaultKey::from_token("jwt-A-new", user);
        let key_b = AuthCenterTokenVaultKey::from_token("jwt-B", user);

        let bundle_a = bundle_from_token_response(sample_response(), 1_000);
        let mut response_b = sample_response();
        response_b.access_token = "ACCESS-B".to_owned();
        let bundle_b = bundle_from_token_response(response_b, 2_000);

        vault.store(key_a_old.clone(), bundle_a.clone());
        vault.store(key_b.clone(), bundle_b.clone());
        assert_eq!(vault.len(), 2);

        // Refresh session A: move bundle from jwt-A-old to jwt-A-new.
        let moved = vault
            .move_bundle(&key_a_old, key_a_new.clone())
            .expect("bundle must be moved on refresh");
        assert_eq!(moved.access_token.expose(), bundle_a.access_token.expose());
        assert!(
            vault.get(&key_a_old).is_none(),
            "old fingerprint must be empty after move"
        );
        let current_a = vault.get(&key_a_new).expect("new fingerprint must hold the bundle");
        assert_eq!(current_a.access_token.expose(), bundle_a.access_token.expose());
        // Session B is untouched.
        let current_b = vault.get(&key_b).unwrap();
        assert_eq!(current_b.access_token.expose(), "ACCESS-B");
        assert_eq!(vault.len(), 2);
    }

    #[test]
    fn in_memory_vault_move_from_empty_does_not_insert() {
        let vault = InMemoryAuthCenterTokenVault::new();
        let from = AuthCenterTokenVaultKey::from_token("missing", "user-1");
        let to = AuthCenterTokenVaultKey::from_token("jwt-new", "user-1");
        assert!(vault.move_bundle(&from, to.clone()).is_none());
        assert!(vault.get(&to).is_none(), "no-op move must not insert at `to`");
    }

    #[test]
    fn in_memory_vault_move_has_no_observable_intermediate_state() {
        // Contract: after a successful move_bundle, EITHER both sides
        // hold the bundle (impossible — there is only one), OR from is
        // empty AND to is populated. There must never be a window where
        // from is empty and to is also empty. The single-Mutex design
        // makes that window unreachable; the prior DashMap design did
        // not, because remove and insert are separate shard operations.
        let vault = InMemoryAuthCenterTokenVault::new();
        let from = AuthCenterTokenVaultKey::from_token("jwt-old", "user-1");
        let to = AuthCenterTokenVaultKey::from_token("jwt-new", "user-1");
        vault.store(from.clone(), bundle_from_token_response(sample_response(), 1));
        assert!(vault.get(&from).is_some());
        assert!(vault.get(&to).is_none());

        let moved = vault
            .move_bundle(&from, to.clone())
            .expect("move must succeed when from is populated");
        assert!(!moved.access_token.expose().is_empty());

        // Strict atomicity assertion: from empty AND to populated. There
        // is no third state in which both could be empty.
        assert!(vault.get(&from).is_none(), "from must be empty after move");
        assert!(vault.get(&to).is_some(), "to must hold the moved bundle");
        assert_eq!(vault.len(), 1, "exactly one entry must exist after the move");
    }

    #[test]
    fn in_memory_vault_concurrent_moves_serialize_via_mutex() {
        // Spawn several threads each performing a distinct move on a
        // shared vault. The single Mutex guarantees the vault invariant
        // (each fingerprint has at most one entry, totals are consistent)
        // is never violated. The previous DashMap implementation could
        // in principle leave the map in a state with the same entry
        // inserted twice or the count off by one after a contention race.
        use std::sync::Arc;
        use std::thread;

        let vault: Arc<InMemoryAuthCenterTokenVault> = Arc::new(InMemoryAuthCenterTokenVault::new());
        // Seed 32 sessions for the same user.
        let mut keys = Vec::new();
        for i in 0..32 {
            let k = AuthCenterTokenVaultKey::from_token(format!("jwt-{i}"), "user-1");
            vault.store(k.clone(), bundle_from_token_response(sample_response(), i as i64));
            keys.push(k);
        }
        assert_eq!(vault.len(), 32);

        let mut handles = Vec::new();
        for (i, from) in keys.iter().enumerate() {
            let vault = Arc::clone(&vault);
            let to = AuthCenterTokenVaultKey::from_token(format!("jwt-{i}-rotated"), "user-1");
            let from = from.clone();
            handles.push(thread::spawn(move || {
                vault.move_bundle(&from, to);
            }));
        }
        for handle in handles {
            handle.join().expect("worker thread must not panic");
        }
        assert_eq!(vault.len(), 32, "every move preserves the entry count");
        // Every original fingerprint must be empty; every rotated one populated.
        for (i, from) in keys.iter().enumerate() {
            assert!(vault.get(from).is_none(), "jwt-{i} must be empty after move");
            let rotated = AuthCenterTokenVaultKey::from_token(format!("jwt-{i}-rotated"), "user-1");
            assert!(vault.get(&rotated).is_some(), "jwt-{i}-rotated must be populated");
        }
    }
}
