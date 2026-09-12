//! Auth Center refresh grant: DPoP-bound rotation of the session token bundle.
//!
//! When a session's Auth Center access token is expired (or about to expire)
//! and the vault bundle carries a refresh token, the Schedule BFF exchanges it
//! for a fresh token response instead of evicting the session. The exchange is
//! sender-constrained like the original token exchange: the request carries a
//! token-endpoint DPoP proof signed with the *same* session key (the refresh
//! grant never changes the key — the vault fingerprint comes from the local
//! session JWT, which a refresh does not touch).
//!
//! Wire contract (verified against the auth-center server source):
//! - `POST {issuer}/oauth/token`, form `grant_type=refresh_token`,
//!   `refresh_token`, `client_id`, `client_secret` (the token endpoint
//!   authenticates the client from Basic auth or the form pair
//!   `client_id`/`client_secret`; verified:
//!   rsm_project/auth-center/internal/httpapi/oauth_user_authorization.go:32-62).
//! - Exactly one `DPoP` header with a token-endpoint proof: `htm=POST`,
//!   `htu` = the canonical `{issuer}/oauth/token`, `iat`/`jti`, **no `ath`**
//!   (verified: rsm_project/auth-center/internal/httpapi/oauth_dpop.go:296-329
//!   and `dpopTokenEndpoint` at oauth_dpop.go:260-262).
//! - Success is the standard token response (`types.go:10-17`). The Auth
//!   Center **always rotates**: a successful refresh response carries a new,
//!   different `refresh_token` (verified:
//!   rsm_project/auth-center/internal/httpapi/oauth_dpop_test.go:598 and
//!   oauth_contract_test.go:205). A response that omits `refresh_token` is
//!   handled defensively as "keep the current one" (RFC 6749 §6) — never drop
//!   a still-valid refresh token.
//! - Failure shapes: 400 `invalid_refresh_token` / `expired_refresh_token`
//!   (verified: oauth_authorize.go:206-209), 400 `invalid_grant` when the
//!   token authority rejects the grant — notably a stale-generation replay,
//!   which revokes the whole refresh family (verified:
//!   oauth_dpop.go:376-378 and the `exchangeDPoPRefreshToken` doc comment at
//!   oauth_dpop.go:548-550), 401 `user_disabled`, 400 `invalid_dpop_proof`.
//!
//! ## No retry after the request is sent
//!
//! A refresh consumes the presented refresh token server-side. If the request
//! was sent and the outcome is unknown (transport error, timeout, unparsable
//! 2xx), retrying could replay a consumed token and trigger the family
//! revocation above — so callers must treat every failure as terminal and
//! fall back to the session-required semantics. Only one attempt is ever made.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::auth_center_client::RsmAuthConfig;
use crate::auth_center_tokens::{
    AuthCenterTokenResponse, AuthCenterTokenVaultKey, AuthCenterUserTokenBundle, bundle_from_token_response,
};
use crate::dpop::{DpopKeySelector, DpopSigningHandle, IDpopKeyStore, build_dpop_proof, generate_dpop_jti};

/// A bundle is refreshed once its access token is expired or within this
/// window of expiring, so an in-flight upstream call is not cut down by an
/// expiry race.
pub(crate) const REFRESH_WINDOW_MS: i64 = 30_000;

/// Whether the bundle's access token is expired or about to expire (within
/// [`REFRESH_WINDOW_MS`]). Bundles without an absolute expiry are treated as
/// never refreshing, matching the pre-refresh-grant validity check.
pub(crate) fn bundle_needs_refresh(bundle: &AuthCenterUserTokenBundle) -> bool {
    bundle
        .expires_at_ms
        .is_some_and(|expires_at| expires_at <= chrono::Utc::now().timestamp_millis() + REFRESH_WINDOW_MS)
}

/// Whether the bundle's access token is strictly expired (the pre-existing
/// eviction condition, without the proactive refresh window).
pub(crate) fn bundle_is_expired(bundle: &AuthCenterUserTokenBundle) -> bool {
    bundle
        .expires_at_ms
        .is_some_and(|expires_at| expires_at <= chrono::Utc::now().timestamp_millis())
}

/// Terminal refresh-grant failures. Every variant maps to the same eviction
/// semantics at the call site; the classification exists for logs only.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RefreshGrantError {
    /// The Auth Center answered with a non-success status (invalid or expired
    /// refresh token, replayed generation, disabled user, rejected client).
    #[error("Auth Center rejected the refresh grant (HTTP {status})")]
    Rejected { status: u16 },
    /// The request was sent but produced no decidable success response
    /// (transport error, timeout, unparsable 2xx). The grant may already have
    /// been consumed — never retried.
    #[error("Auth Center refresh request did not complete: {0}")]
    Ambiguous(String),
    /// DPoP proof minting failed — fail-closed, no request was sent.
    #[error("DPoP refresh proof failed: {0}")]
    Dpop(String),
}

/// One keyed async mutex per vault key: at most one refresh grant is ever in
/// flight for one session. Under auth-center rotation semantics a concurrent
/// second refresh would present the already-consumed token and revoke the
/// whole refresh family, so this is a correctness guard, not an optimization.
///
/// Slots accumulate one entry per session fingerprint ever seen; each entry is
/// a tiny `Arc<tokio::sync::Mutex<()>>` and sessions are bounded by logins, so
/// no eviction is attempted.
#[derive(Debug, Default)]
pub(crate) struct RefreshSingleFlight {
    slots: Mutex<HashMap<AuthCenterTokenVaultKey, Arc<tokio::sync::Mutex<()>>>>,
}

impl RefreshSingleFlight {
    /// Acquire (creating if needed) the single-flight slot for `key`. Lock the
    /// returned mutex around the vault re-check plus refresh grant.
    pub(crate) fn slot(&self, key: &AuthCenterTokenVaultKey) -> Arc<tokio::sync::Mutex<()>> {
        match self.slots.lock() {
            Ok(mut slots) => slots.entry(key.clone()).or_default().clone(),
            // Same recovery policy as the vault: a poisoned lock still holds
            // consistent data; prefer availability over aborting.
            Err(poisoned) => poisoned.into_inner().entry(key.clone()).or_default().clone(),
        }
    }
}

/// Canonical Auth Center token endpoint for the refresh grant. The DPoP
/// proof's `htu` must equal the server's canonical token endpoint
/// (`dpopTokenEndpoint` = `publicURL(Issuer, "/oauth/token")`; verified:
/// rsm_project/auth-center/internal/httpapi/oauth_dpop.go:260-262).
pub(crate) fn token_endpoint_url(issuer: &str) -> String {
    format!("{}/oauth/token", issuer.trim_end_matches('/'))
}

#[derive(Serialize)]
struct RefreshTokenForm<'a> {
    grant_type: &'static str,
    refresh_token: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
}

/// Exchange `refresh_token` for a fresh Auth Center token response.
///
/// Fail-closed: a missing DPoP key, a key-store failure, or a signing failure
/// aborts before the request is sent — the grant is never presented with a
/// bare Bearer request. At most one request is sent; a response that arrives
/// but cannot be decoded as a success is [`RefreshGrantError::Ambiguous`].
pub(crate) async fn refresh_grant(
    http_client: &reqwest::Client,
    config: &RsmAuthConfig,
    dpop_key_store: &Arc<dyn IDpopKeyStore>,
    selector: &DpopKeySelector,
    refresh_token: &str,
    timeout: Duration,
) -> Result<AuthCenterTokenResponse, RefreshGrantError> {
    let issuer = config
        .issuer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RefreshGrantError::Ambiguous("RSM_AUTH_ISSUER is not configured".to_owned()))?;
    let client_id = config
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RefreshGrantError::Ambiguous("RSM_AUTH_CLIENT_ID is not configured".to_owned()))?;
    let token_endpoint = token_endpoint_url(issuer);

    let handle: DpopSigningHandle = dpop_key_store
        .get(selector)
        .map_err(|error| {
            tracing::error!(holder = %selector.holder, error = %error, "DPoP key store lookup failed for refresh grant");
            RefreshGrantError::Dpop(error.to_string())
        })?
        .ok_or_else(|| {
            tracing::error!(holder = %selector.holder, "no DPoP key bound for the refresh grant");
            RefreshGrantError::Dpop("no DPoP key bound for the refresh grant".to_owned())
        })?;
    let proof = build_dpop_proof(
        &handle,
        "POST",
        &token_endpoint,
        chrono::Utc::now().timestamp(),
        &generate_dpop_jti(),
        // Token-endpoint profile: no `ath` (verified: oauthdpop/proof.go via
        // the dpop.rs module docs).
        None,
        None,
    )
    .map_err(|error| {
        tracing::error!(holder = %selector.holder, error = %error, "DPoP token endpoint proof failed for refresh grant");
        RefreshGrantError::Dpop(error.to_string())
    })?;

    // Same client authentication as the authorization-code exchange: the
    // auth-center token endpoint requires the client_id/client_secret pair
    // (verified: oauth_user_authorization.go:32-62).
    let form = RefreshTokenForm {
        grant_type: "refresh_token",
        refresh_token,
        client_id,
        client_secret: config.client_secret.as_deref().unwrap_or(""),
    };

    let response = http_client
        .post(&token_endpoint)
        .timeout(timeout)
        .form(&form)
        .header(reqwest::header::HeaderName::from_static("dpop"), proof)
        .send()
        .await
        .map_err(|error| {
            // Network ambiguity: the grant may have been consumed even though
            // no response arrived. Callers must not retry.
            RefreshGrantError::Ambiguous(error.to_string())
        })?;

    let status = response.status();
    if !status.is_success() {
        return Err(RefreshGrantError::Rejected {
            status: status.as_u16(),
        });
    }
    response.json::<AuthCenterTokenResponse>().await.map_err(|error| {
        // A 2xx that does not parse is equally ambiguous: the presented
        // refresh token is presumed consumed.
        RefreshGrantError::Ambiguous(format!("unparsable token response: {error}"))
    })
}

/// Merge a successful refresh-grant response into the previous bundle.
///
/// The Auth Center always rotates the refresh token, so the response's
/// `refresh_token` normally replaces the old one; a response that omits it
/// means "keep using the current one" (RFC 6749 §6). The device registration
/// receipt is bound to the session's DPoP key, which the refresh grant does
/// not change — it is carried over untouched.
pub(crate) fn refreshed_bundle(
    previous: &AuthCenterUserTokenBundle,
    response: AuthCenterTokenResponse,
    issued_at_ms: i64,
) -> AuthCenterUserTokenBundle {
    let mut refreshed = bundle_from_token_response(response, issued_at_ms);
    if refreshed.refresh_token.is_none() {
        refreshed.refresh_token = previous.refresh_token.clone();
    }
    if refreshed.id_token.is_none() {
        refreshed.id_token = previous.id_token.clone();
    }
    if refreshed.token_type.is_none() {
        refreshed.token_type = previous.token_type.clone();
    }
    if refreshed.scope.is_none() {
        refreshed.scope = previous.scope.clone();
    }
    refreshed.device_registration = previous.device_registration.clone();
    refreshed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bundle(access: &str, refresh: Option<&str>, expires_in: i64) -> AuthCenterUserTokenBundle {
        let mut bundle = bundle_from_token_response(
            AuthCenterTokenResponse {
                access_token: access.to_owned(),
                refresh_token: refresh.map(str::to_owned),
                id_token: Some("id-old".to_owned()),
                token_type: Some("Bearer".to_owned()),
                scope: Some("openid".to_owned()),
                expires_in: Some(expires_in),
            },
            chrono::Utc::now().timestamp_millis(),
        );
        bundle.device_registration = Some(crate::device_registration::DeviceRegistrationReceipt {
            device_id: "device-1".to_owned(),
            status: "active".to_owned(),
            binding_version: 1,
            authority_epoch: 1,
            registered_at: "2026-09-12T00:00:00Z".to_owned(),
            updated_at: "2026-09-12T00:00:00Z".to_owned(),
        });
        bundle
    }

    #[test]
    fn needs_refresh_covers_expiry_and_the_proactive_window() {
        let expired = sample_bundle("a", Some("r"), -1);
        assert!(bundle_is_expired(&expired));
        assert!(bundle_needs_refresh(&expired));

        // Half the refresh window of life left (expires_in is seconds).
        let within_window = sample_bundle("a", Some("r"), REFRESH_WINDOW_MS / 2000);
        assert!(!bundle_is_expired(&within_window));
        assert!(bundle_needs_refresh(&within_window));

        let fresh = sample_bundle("a", Some("r"), 3600);
        assert!(!bundle_is_expired(&fresh));
        assert!(!bundle_needs_refresh(&fresh));

        let mut no_expiry = sample_bundle("a", Some("r"), 3600);
        no_expiry.expires_at_ms = None;
        assert!(!bundle_is_expired(&no_expiry));
        assert!(!bundle_needs_refresh(&no_expiry));
    }

    #[test]
    fn refreshed_bundle_replaces_rotated_secrets_and_preserves_the_device_receipt() {
        let previous = sample_bundle("access-old", Some("refresh-old"), -1);
        let response = AuthCenterTokenResponse {
            access_token: "access-new".to_owned(),
            refresh_token: Some("refresh-new".to_owned()),
            id_token: Some("id-new".to_owned()),
            token_type: Some("Bearer".to_owned()),
            scope: Some("openid profile".to_owned()),
            expires_in: Some(3600),
        };
        let issued_at = 5_000_000;
        let refreshed = refreshed_bundle(&previous, response, issued_at);

        assert_eq!(refreshed.access_token.expose(), "access-new");
        assert_eq!(
            refreshed.refresh_token.as_ref().map(|s| s.expose()),
            Some("refresh-new")
        );
        assert_eq!(refreshed.id_token.as_ref().map(|s| s.expose()), Some("id-new"));
        assert_eq!(refreshed.expires_at_ms, Some(issued_at + 3600 * 1000));
        // The receipt travels untouched across rotation.
        assert_eq!(refreshed.device_registration, previous.device_registration);
    }

    #[test]
    fn refreshed_bundle_keeps_previous_values_when_the_response_omits_them() {
        let previous = sample_bundle("access-old", Some("refresh-old"), -1);
        let response = AuthCenterTokenResponse {
            access_token: "access-new".to_owned(),
            refresh_token: None,
            id_token: None,
            token_type: None,
            scope: None,
            expires_in: Some(3600),
        };
        let refreshed = refreshed_bundle(&previous, response, 1_000);

        assert_eq!(
            refreshed.refresh_token.as_ref().map(|s| s.expose()),
            Some("refresh-old")
        );
        assert_eq!(refreshed.id_token.as_ref().map(|s| s.expose()), Some("id-old"));
        assert_eq!(refreshed.token_type.as_deref(), Some("Bearer"));
        assert_eq!(refreshed.scope.as_deref(), Some("openid"));
        assert_eq!(refreshed.device_registration, previous.device_registration);
    }

    #[test]
    fn token_endpoint_url_strips_trailing_slashes_from_the_issuer() {
        assert_eq!(
            token_endpoint_url("https://auth.example"),
            "https://auth.example/oauth/token"
        );
        assert_eq!(
            token_endpoint_url("https://auth.example/"),
            "https://auth.example/oauth/token"
        );
    }

    #[test]
    fn single_flight_slot_is_shared_per_vault_key_and_distinct_across_keys() {
        let flight = RefreshSingleFlight::default();
        let key_a = AuthCenterTokenVaultKey::from_token("jwt-a", "user-1");
        let key_a_again = AuthCenterTokenVaultKey::from_token("jwt-a", "user-1");
        let key_b = AuthCenterTokenVaultKey::from_token("jwt-b", "user-1");

        let first = flight.slot(&key_a);
        assert!(
            Arc::ptr_eq(&first, &flight.slot(&key_a_again)),
            "same session shares one slot"
        );
        assert!(
            !Arc::ptr_eq(&first, &flight.slot(&key_b)),
            "different sessions get distinct slots"
        );
    }
}
