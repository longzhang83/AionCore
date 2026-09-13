//! ACP service-token authentication for the run-admission receive face
//! (T0-ACP-ADMISSION-DELIVERY Slice B1).
//!
//! This is the Rust mirror of the ACP run-face authenticator
//! (`internal/authn/service_token.go`): Core is the receiving authority that
//! authenticates the Agent Control Plane caller presenting its own
//! certificate-bound machine service identity with audience
//! `core:run-admission-receive`.
//!
//! Verification is fail-closed end to end:
//! - RS256 only, issuer + audience + exp + iat enforced with zero leeway;
//! - a machine identity claims profile (client_id == sub, principal_type ==
//!   "machine", non-blank jti/tenant_id/service_role/workload_instance_id,
//!   service_authority_epoch >= 1, exactly one primary organization);
//! - RFC 9068 certificate binding: the `cnf."x5t#S256"` confirmation must
//!   match the SHA-256 thumbprint of the client certificate the TLS runtime
//!   actually verified during the handshake — never a header the caller
//!   controls. Under a mandatory [`rustls::server::WebPkiClientVerifier`] a
//!   completed handshake proves the presented chain was verified, which is
//!   the rustls equivalent of Go's `VerifiedChains`-only discipline.
//! - JWKS keys are fetched from `<issuer>/.well-known/jwks.json`, cached with
//!   a TTL, refreshed at most once per verification on an unknown kid, and
//!   filtered to RSA/RS256 signature keys.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::Mutex;
use url::Url;

/// Audience of the ACP service token presented to the Core run-admission
/// receive face (frozen in the T0-ACP-ADMISSION-DELIVERY wire contract).
pub const RUN_ADMISSION_RECEIVE_AUDIENCE: &str = "core:run-admission-receive";

/// JWKS cache lifetime default, mirroring the ACP verifier.
pub const DEFAULT_JWKS_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
/// Per-request HTTP budget for JWKS fetches, mirroring the ACP verifier.
const DEFAULT_JWKS_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum JWKS response body size; one byte more is a rejection, not a
/// truncation, mirroring the ACP verifier's read cap.
const MAX_JWKS_RESPONSE_BYTES: usize = 1 << 20;

const JWKS_PATH: &str = "/.well-known/jwks.json";

/// Configuration failure for the ACP service-token verifier. Construction is
/// fail-closed: any missing or malformed piece aborts startup.
#[derive(Debug, Error)]
pub enum AcpServiceTokenConfigError {
    #[error("acp service token verifier issuer is required (disable the face by not wiring it, not by a blank issuer)")]
    IssuerRequired,
    #[error("acp service token verifier issuer is not an absolute URL: {0}")]
    IssuerNotAbsolute(String),
    #[error("acp service token verifier issuer must not carry userinfo, a query, or a fragment: {0}")]
    IssuerCarriesForbiddenParts(String),
    #[error(
        "acp service token verifier issuer scheme {0} requires https unless the development-only insecure HTTP flag is set"
    )]
    IssuerSchemeNotHttps(String),
    #[error("acp service token verifier audience must be a non-blank string")]
    AudienceBlank,
    #[error("acp service token verifier JWKS cache TTL must be positive")]
    TtlNotPositive,
}

/// Verification failure for an ACP service token. Every variant is a
/// rejection: callers must treat the token as absent, never degrade.
#[derive(Debug, Error)]
pub enum AcpServiceTokenError {
    #[error("acp service token is missing")]
    #[allow(dead_code)]
    MissingToken,
    #[error("acp service token is malformed")]
    MalformedToken,
    #[error("acp service token signature is invalid")]
    InvalidSignature,
    #[error("acp service token is expired")]
    ExpiredToken,
    #[error("acp service token issuer does not match")]
    IssuerMismatch,
    #[error("acp service token claims are invalid")]
    InvalidClaims,
    #[error("acp service token does not carry a valid machine service identity profile")]
    ClaimsProfile,
    #[error("acp service token is not bound to the presented client certificate")]
    Binding,
    #[error("acp service token JWKS is unavailable")]
    JwksUnavailable,
    #[error("acp service token JWKS is malformed")]
    JwksMalformed,
    #[error("acp service token references an unknown signing key")]
    UnknownKeyId,
}

/// Configuration for [`AcpServiceTokenVerifier`]. `disabled()` produces the
/// not-wired state; [`AcpServiceTokenVerifier::new`] on a disabled or
/// malformed config fails closed.
#[derive(Clone)]
pub struct AcpServiceTokenConfig {
    issuer: Option<String>,
    audience: String,
    jwks_cache_ttl: Option<Duration>,
    allow_insecure_http: bool,
    http_client: Option<reqwest::Client>,
}

impl Default for AcpServiceTokenConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

impl std::fmt::Debug for AcpServiceTokenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcpServiceTokenConfig")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("jwks_cache_ttl", &self.jwks_cache_ttl)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .finish_non_exhaustive()
    }
}

impl AcpServiceTokenConfig {
    /// The not-wired state: B2 assembly skips the receive face entirely when
    /// the issuer is unset.
    pub fn disabled() -> Self {
        Self {
            issuer: None,
            audience: RUN_ADMISSION_RECEIVE_AUDIENCE.to_string(),
            jwks_cache_ttl: None,
            allow_insecure_http: false,
            http_client: None,
        }
    }

    /// Shape-validates the issuer (absolute URL without userinfo, query, or
    /// fragment). The https requirement is enforced by
    /// [`AcpServiceTokenVerifier::new`] together with the development-only
    /// insecure-HTTP flag.
    pub fn new(issuer: impl Into<String>) -> Result<Self, AcpServiceTokenConfigError> {
        let issuer = issuer.into();
        let trimmed = issuer.trim();
        if trimmed.is_empty() {
            return Err(AcpServiceTokenConfigError::IssuerRequired);
        }
        let parsed = Url::parse(trimmed).map_err(|_| AcpServiceTokenConfigError::IssuerNotAbsolute(issuer.clone()))?;
        if parsed.host_str().is_none() || parsed.host_str().unwrap_or_default().is_empty() {
            return Err(AcpServiceTokenConfigError::IssuerNotAbsolute(issuer.clone()));
        }
        if parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(AcpServiceTokenConfigError::IssuerCarriesForbiddenParts(issuer.clone()));
        }
        Ok(Self {
            issuer: Some(trimmed.to_string()),
            ..Self::disabled()
        })
    }

    /// Overrides the expected token audience. Defaults to
    /// [`RUN_ADMISSION_RECEIVE_AUDIENCE`].
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Overrides the JWKS cache TTL. Defaults to [`DEFAULT_JWKS_CACHE_TTL`].
    pub fn with_jwks_cache_ttl(mut self, ttl: Duration) -> Self {
        self.jwks_cache_ttl = Some(ttl);
        self
    }

    /// Development-only escape hatch that allows an `http://` issuer (local
    /// wiremock-style JWKS in tests). Never enable in production.
    pub fn allow_insecure_http(mut self) -> Self {
        self.allow_insecure_http = true;
        self
    }

    /// Injects an HTTP client for the JWKS origin (tests).
    pub fn with_http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    /// True when the face is not wired: assembly must skip it entirely
    /// rather than construct a verifier.
    pub fn is_disabled(&self) -> bool {
        self.issuer.is_none()
    }
}

/// The ACP service identity projected from a verified token. This is the
/// machine principal the run-admission receive face attributes requests to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcpServicePrincipal {
    /// `sub` — the ACP service identity (equals `client_id`).
    pub service_id: String,
    /// `service_role` — e.g. `core`.
    pub service_role: String,
    /// `workload_instance_id` — the issuing ACP deployment instance.
    pub workload_instance_id: String,
    /// `service_authority_epoch` — the ACP-side authority epoch at issuance.
    pub service_authority_epoch: i64,
    /// `tenant_id` — tenant the service identity belongs to.
    pub tenant_id: String,
    /// `id` of the single primary organization claim.
    pub primary_organization_id: String,
    /// `scope` of the token.
    pub scope: String,
    /// `kid` of the signing key that verified the token.
    pub credential_key_id: String,
    /// SHA-256 thumbprint (base64url, no padding) of the verified client
    /// leaf certificate the token is bound to.
    pub certificate_thumbprint_s256: String,
}

/// Claims of an ACP service token (RFC 9068 access token JWT profile plus the
/// RSM machine identity extension). Field names follow the frozen Go
/// projection; unknown claims are ignored.
#[derive(Debug, Deserialize)]
pub(crate) struct ServiceTokenClaims {
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub principal_type: String,
    #[serde(default)]
    pub jti: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub orgs: Vec<OrganizationClaim>,
    #[serde(default)]
    pub cnf: Option<ConfirmationClaim>,
    #[serde(default)]
    pub service_role: String,
    #[serde(default)]
    pub workload_instance_id: String,
    #[serde(default)]
    pub service_authority_epoch: i64,
}

/// One organization grant inside `orgs`. Only `id` and `isPrimary` matter for
/// the primary-organization fence.
#[derive(Debug, Deserialize)]
pub(crate) struct OrganizationClaim {
    #[serde(default)]
    pub id: String,
    #[serde(rename = "isPrimary", default)]
    pub is_primary: bool,
}

/// RFC 9068 certificate-thumbprint confirmation claim.
#[derive(Debug, Deserialize)]
pub(crate) struct ConfirmationClaim {
    #[serde(rename = "x5t#S256", default)]
    pub x5t_s256: String,
}

/// Lenient JWKS key document: keys that are not RSA/RS256 signature keys are
/// skipped (mirroring the ACP Go client) instead of failing the whole parse.
#[derive(Debug, Deserialize)]
struct LenientJwk {
    #[serde(default)]
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(rename = "use", default)]
    use_: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LenientJwksDocument {
    #[serde(default)]
    keys: Vec<LenientJwk>,
}

struct JwksState {
    keys: Option<HashMap<String, DecodingKey>>,
    expires_at: Option<Instant>,
}

/// JWKS client with a TTL cache and at-most-once refresh per unknown kid,
/// mirroring the ACP verifier's JWKS discipline.
struct JwksClient {
    url: String,
    http_client: reqwest::Client,
    ttl: Duration,
    state: Mutex<JwksState>,
}

impl JwksClient {
    fn new(url: String, http_client: reqwest::Client, ttl: Duration) -> Self {
        Self {
            url,
            http_client,
            ttl,
            state: Mutex::new(JwksState {
                keys: None,
                expires_at: None,
            }),
        }
    }

    async fn verification_key(&self, kid: &str) -> Result<DecodingKey, AcpServiceTokenError> {
        // The cache lock is held across refresh: verification callers serialize
        // behind one fetch instead of stampeding the JWKS origin.
        let mut state = self.state.lock().await;
        // A cold or stale cache always triggers an initial fetch.
        if state.keys.is_none() || state.expires_at.is_none_or(|expires_at| Instant::now() >= expires_at) {
            self.refresh_into(&mut state).await?;
        }
        if let Some(key) = state.keys.as_ref().and_then(|keys| keys.get(kid)) {
            return Ok(key.clone());
        }
        // A cache miss can mean the ACP issuer rotated its signing key before
        // the TTL elapsed. Refresh exactly once so a newly published kid is
        // accepted without weakening fail-closed behavior for an actually
        // unknown kid.
        self.refresh_into(&mut state).await?;
        state
            .keys
            .as_ref()
            .and_then(|keys| keys.get(kid))
            .cloned()
            .ok_or(AcpServiceTokenError::UnknownKeyId)
    }

    async fn refresh_into(&self, state: &mut JwksState) -> Result<(), AcpServiceTokenError> {
        let keys = self.fetch_keys().await?;
        state.keys = Some(keys);
        state.expires_at = Some(Instant::now() + self.ttl);
        Ok(())
    }

    async fn fetch_keys(&self) -> Result<HashMap<String, DecodingKey>, AcpServiceTokenError> {
        let mut response = self
            .http_client
            .get(&self.url)
            .timeout(DEFAULT_JWKS_HTTP_TIMEOUT)
            .send()
            .await
            .map_err(|_| AcpServiceTokenError::JwksUnavailable)?;
        if !response.status().is_success() {
            return Err(AcpServiceTokenError::JwksUnavailable);
        }
        // Read with a hard cap: one byte past the limit is a rejection, never
        // a truncation.
        let mut payload: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AcpServiceTokenError::JwksUnavailable)?
        {
            if payload.len() + chunk.len() > MAX_JWKS_RESPONSE_BYTES {
                return Err(AcpServiceTokenError::JwksUnavailable);
            }
            payload.extend_from_slice(&chunk);
        }
        let document: LenientJwksDocument =
            serde_json::from_slice(&payload).map_err(|_| AcpServiceTokenError::JwksMalformed)?;
        let mut keys: HashMap<String, DecodingKey> = HashMap::new();
        for jwk in document.keys {
            // Mirror the Go filter: RSA modulus/exponent, RS256, sig use (or
            // unspecified), non-blank kid. Anything else is skipped.
            if jwk.kty != "RSA"
                || jwk.alg.as_deref() != Some("RS256")
                || jwk.use_.as_deref().is_some_and(|use_| use_ != "sig")
            {
                continue;
            }
            let kid = match jwk.kid.as_deref() {
                Some(kid) if !kid.trim().is_empty() => kid.to_string(),
                _ => return Err(AcpServiceTokenError::JwksMalformed),
            };
            let (n, e) = match (jwk.n.as_deref(), jwk.e.as_deref()) {
                (Some(n), Some(e)) if !n.is_empty() && !e.is_empty() => (n, e),
                _ => return Err(AcpServiceTokenError::JwksMalformed),
            };
            let decoding_key =
                DecodingKey::from_rsa_components(n, e).map_err(|_| AcpServiceTokenError::JwksMalformed)?;
            if keys.insert(kid, decoding_key).is_some() {
                return Err(AcpServiceTokenError::JwksMalformed);
            }
        }
        if keys.is_empty() {
            return Err(AcpServiceTokenError::JwksMalformed);
        }
        Ok(keys)
    }
}

/// Verifier for ACP service tokens on the Core run-admission receive face.
/// Construct with [`AcpServiceTokenVerifier::new`]; every construction
/// failure is a deployment fault.
pub struct AcpServiceTokenVerifier {
    issuer: String,
    audience: String,
    jwks: JwksClient,
}

impl std::fmt::Debug for AcpServiceTokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcpServiceTokenVerifier")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

impl AcpServiceTokenVerifier {
    /// Fail-closed construction: validates the issuer shape and scheme, the
    /// audience, and the cache TTL before any verification happens.
    pub fn new(config: AcpServiceTokenConfig) -> Result<Self, AcpServiceTokenConfigError> {
        let issuer = config
            .issuer
            .clone()
            .ok_or(AcpServiceTokenConfigError::IssuerRequired)?;
        let parsed = Url::parse(&issuer).map_err(|_| AcpServiceTokenConfigError::IssuerNotAbsolute(issuer.clone()))?;
        let scheme = parsed.scheme().to_string();
        if scheme != "https" && !(scheme == "http" && config.allow_insecure_http) {
            return Err(AcpServiceTokenConfigError::IssuerSchemeNotHttps(scheme));
        }
        let audience = config.audience.trim().to_string();
        if audience.is_empty() {
            return Err(AcpServiceTokenConfigError::AudienceBlank);
        }
        let ttl = config.jwks_cache_ttl.unwrap_or(DEFAULT_JWKS_CACHE_TTL);
        if ttl.is_zero() {
            return Err(AcpServiceTokenConfigError::TtlNotPositive);
        }
        let http_client = config.http_client.unwrap_or_else(|| {
            reqwest::Client::builder()
                .build()
                .expect("reqwest client with default options must build")
        });
        let jwks_url = format!("{}{JWKS_PATH}", issuer.trim_end_matches('/'));
        Ok(Self {
            issuer,
            audience,
            jwks: JwksClient::new(jwks_url, http_client, ttl),
        })
    }

    /// Verifies an ACP service token against the verified client leaf
    /// certificate the TLS runtime presented for this connection. On success
    /// returns the machine service principal.
    pub async fn verify(
        &self,
        token: &str,
        leaf: &VerifiedClientLeaf,
    ) -> Result<AcpServicePrincipal, AcpServiceTokenError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(AcpServiceTokenError::MissingToken);
        }
        let header = jsonwebtoken::decode_header(token).map_err(|_| AcpServiceTokenError::MalformedToken)?;
        // Mirror the delivered ACP verifier: RS256 only. No typ check — the
        // Go verifier does not enforce one, so the mirror must not add one.
        if header.alg != Algorithm::RS256 {
            return Err(AcpServiceTokenError::InvalidSignature);
        }
        let kid = match header.kid {
            Some(kid) if !kid.trim().is_empty() => kid,
            _ => return Err(AcpServiceTokenError::MalformedToken),
        };
        let decoding_key = self.jwks.verification_key(&kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.validate_exp = true;
        validation.leeway = 0;
        // Mirror the Go verifier: exp and iat must both be present.
        validation.required_spec_claims = HashSet::from(["exp".to_string(), "iat".to_string()]);
        let token_data =
            jsonwebtoken::decode::<ServiceTokenClaims>(token, &decoding_key, &validation).map_err(map_jwt_error)?;

        let claims = token_data.claims;
        validate_machine_identity_profile(&claims)?;
        verify_certificate_binding(&claims, leaf)?;
        Ok(AcpServicePrincipal {
            service_id: claims.sub,
            service_role: claims.service_role,
            workload_instance_id: claims.workload_instance_id,
            service_authority_epoch: claims.service_authority_epoch,
            tenant_id: claims.tenant_id,
            primary_organization_id: primary_organization_id(&claims.orgs),
            scope: claims.scope,
            credential_key_id: kid,
            certificate_thumbprint_s256: leaf.thumbprint_s256(),
        })
    }
}

fn map_jwt_error(error: jsonwebtoken::errors::Error) -> AcpServiceTokenError {
    use jsonwebtoken::errors::ErrorKind;
    match error.kind() {
        ErrorKind::ExpiredSignature => AcpServiceTokenError::ExpiredToken,
        ErrorKind::InvalidIssuer => AcpServiceTokenError::IssuerMismatch,
        ErrorKind::InvalidSignature => AcpServiceTokenError::InvalidSignature,
        ErrorKind::InvalidAudience
        | ErrorKind::InvalidSubject
        | ErrorKind::ImmatureSignature
        | ErrorKind::MissingRequiredClaim(_) => AcpServiceTokenError::InvalidClaims,
        _ => AcpServiceTokenError::MalformedToken,
    }
}

/// Enforces the machine service identity claims profile, mirroring
/// `validateServiceTokenClaims` in the ACP verifier.
fn validate_machine_identity_profile(claims: &ServiceTokenClaims) -> Result<(), AcpServiceTokenError> {
    let non_blank = |value: &str| !value.trim().is_empty();
    if !non_blank(&claims.sub) || claims.client_id != claims.sub {
        return Err(AcpServiceTokenError::ClaimsProfile);
    }
    if claims.principal_type != "machine"
        || !non_blank(&claims.jti)
        || !non_blank(&claims.tenant_id)
        || !non_blank(&claims.service_role)
        || !non_blank(&claims.workload_instance_id)
        || claims.service_authority_epoch < 1
    {
        return Err(AcpServiceTokenError::ClaimsProfile);
    }
    if claims.orgs.iter().filter(|org| org.is_primary).count() != 1 {
        return Err(AcpServiceTokenError::ClaimsProfile);
    }
    if claims.orgs.iter().any(|org| org.is_primary && !non_blank(&org.id)) {
        return Err(AcpServiceTokenError::ClaimsProfile);
    }
    Ok(())
}

fn primary_organization_id(orgs: &[OrganizationClaim]) -> String {
    orgs.iter()
        .find(|org| org.is_primary)
        .map(|org| org.id.clone())
        .unwrap_or_default()
}

/// Compares two byte strings in constant time relative to their shared
/// length. Length differences short-circuit (both sides are public values),
/// matching `subtle.ConstantTimeCompare` semantics.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

fn verify_certificate_binding(
    claims: &ServiceTokenClaims,
    leaf: &VerifiedClientLeaf,
) -> Result<(), AcpServiceTokenError> {
    let claimed_thumbprint = claims.cnf.as_ref().map(|cnf| cnf.x5t_s256.trim()).unwrap_or_default();
    if claimed_thumbprint.is_empty() {
        return Err(AcpServiceTokenError::Binding);
    }
    let expected = leaf.thumbprint_s256();
    if !constant_time_eq(claimed_thumbprint.as_bytes(), expected.as_bytes()) {
        return Err(AcpServiceTokenError::Binding);
    }
    Ok(())
}

/// The leaf client certificate of a client chain that the TLS runtime
/// verified during the handshake.
///
/// Construct ONLY from a completed server-side rustls handshake whose
/// `ServerConfig` was built with a mandatory
/// [`rustls::server::WebPkiClientVerifier`]: under that verifier a completed
/// handshake proves the presented chain was validated, which is the rustls
/// equivalent of Go's `VerifiedChains`-only discipline. A connection without
/// a presented client certificate never yields a leaf.
#[derive(Clone)]
pub struct VerifiedClientLeaf {
    der: Vec<u8>,
}

impl std::fmt::Debug for VerifiedClientLeaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedClientLeaf")
            .field("der_len", &self.der.len())
            .field("thumbprint_s256", &self.thumbprint_s256())
            .finish()
    }
}

impl VerifiedClientLeaf {
    /// Extracts the verified leaf from a completed rustls server-side
    /// handshake. Fails closed when no client certificate was presented.
    pub fn from_rustls_server_connection(
        connection: &rustls::server::ServerConnection,
    ) -> Result<Self, AcpServiceTokenError> {
        let certificates = connection.peer_certificates().ok_or(AcpServiceTokenError::Binding)?;
        let leaf = certificates.first().ok_or(AcpServiceTokenError::Binding)?;
        Ok(Self {
            der: leaf.as_ref().to_vec(),
        })
    }

    /// Builds a leaf from raw DER (tests and assembly-side plumbing only;
    /// production paths must go through
    /// [`VerifiedClientLeaf::from_rustls_server_connection`]).
    pub fn from_der(der: &[u8]) -> Self {
        Self { der: der.to_vec() }
    }

    /// The DER encoding of the leaf certificate.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// RFC 9068 `x5t#S256` value: base64url (no padding) SHA-256 over the
    /// leaf DER.
    pub fn thumbprint_s256(&self) -> String {
        let digest = Sha256::digest(&self.der);
        URL_SAFE_NO_PAD.encode(digest)
    }
}

#[cfg(test)]
#[path = "acp_service_token_test.rs"]
mod acp_service_token_test;
