//! Server-side DPoP (RFC 9449) holder: ES256 key lifecycle and proof minting.
//!
//! AionCore acts as the DPoP holder for Auth Center access tokens on behalf
//! of browser sessions. Before each OIDC token exchange a fresh ES256
//! (P-256) key pair is generated for that login; the resulting access token
//! is bound to the key's JWK thumbprint (`cnf.jkt`) by the Auth Center, and
//! every outbound ACP request is accompanied by a proof signed with the same
//! key. The proof shapes are dictated by the Auth Center verifier:
//! `oauthdpop/proof.go` (verified:
//! rsm_project/auth-center/internal/oauthdpop/proof.go — header
//! `typ=dpop+jwt`/`alg=ES256` plus an EC P-256 `jwk`; claims
//! `jti`/`htm`/`htu`/`iat` and optional `nonce`/`ath`; `ath` must be absent
//! on the token-endpoint profile and equal to
//! base64url(SHA-256(access_token)) on the protected-resource profile).
//!
//! ## Private key containment
//!
//! Private key material lives only inside the store that generated it. The
//! [`DpopSigningHandle`] handed out by [`IDpopKeyStore`] can sign proof
//! payloads and expose public JWK data, but never the private key bytes.
//! This mirrors the token vault's redaction discipline
//! (`AuthCenterTokenSecret`): `Debug` output never contains key material.
//!
//! ## Selector dimensions
//!
//! [`IDpopKeyStore`] is keyed by holder + device. Until the device
//! enrollment card lands, the local session JWT fingerprint (the same
//! SHA-256 fingerprint used as the token vault key) plays the device
//! dimension: each browser session owns exactly one DPoP key whose lifetime
//! is tied 1:1 to that session's vault bundle. The key is created during the
//! OIDC callback (before the token exchange), bound under the session's
//! selector after the local JWT is minted, moved along on `/api/auth/refresh`,
//! and cleared wherever the bundle is cleared.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Errors raised by the DPoP key store and proof builder.
///
/// All variants are fail-closed signals: callers must abort the upstream
/// request instead of falling back to a bare Bearer token.
#[derive(Debug, thiserror::Error)]
pub enum DpopError {
    #[error("DPoP key generation failed")]
    KeyGeneration,
    #[error("DPoP signing failed")]
    Signing,
    #[error("DPoP key store unavailable")]
    StoreUnavailable,
    #[error("DPoP proof encoding failed")]
    ProofEncoding,
    #[error("DPoP proof input is invalid")]
    InvalidProofInput,
}

/// Serialisable EC P-256 public JWK, shaped exactly as the Auth Center proof
/// verifier expects (`oauthdpop/proof.go` `P256PublicJWK`): only `kty`, `crv`,
/// `x`, `y`, with coordinates as 43-character unpadded base64url.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DpopPublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

/// Identifies one DPoP key binding: the local user (holder) and, until real
/// device enrollment exists, the local session JWT fingerprint (device).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DpopKeySelector {
    pub holder: String,
    pub device: String,
}

impl DpopKeySelector {
    pub fn new(holder: impl Into<String>, device: impl Into<String>) -> Self {
        Self {
            holder: holder.into(),
            device: device.into(),
        }
    }
}

struct DpopKeyMaterial {
    signing_key: SigningKey,
    public_jwk: DpopPublicJwk,
    jkt: String,
}

impl fmt::Debug for DpopKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render key material. The public JWK is safe to show; the
        // signing key is deliberately omitted.
        f.debug_struct("DpopKeyMaterial")
            .field("public_jwk", &self.public_jwk)
            .field("jkt", &self.jkt)
            .finish_non_exhaustive()
    }
}

/// Opaque handle to one ES256 key pair held inside its originating
/// [`IDpopKeyStore`]. Cloneable and cheap (an `Arc`). Signing happens through
/// [`DpopSigningHandle::sign`]; the private key never leaves the store.
#[derive(Clone)]
pub struct DpopSigningHandle {
    inner: Arc<DpopKeyMaterial>,
}

impl fmt::Debug for DpopSigningHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopSigningHandle")
            .field("jkt", &self.inner.jkt)
            .finish()
    }
}

impl DpopSigningHandle {
    fn new(material: DpopKeyMaterial) -> Self {
        Self {
            inner: Arc::new(material),
        }
    }

    /// Public JWK embedded in the DPoP proof header. Its RFC 7638 thumbprint
    /// is [`DpopSigningHandle::jkt`].
    pub fn public_jwk(&self) -> DpopPublicJwk {
        self.inner.public_jwk.clone()
    }

    /// RFC 7638 JWK thumbprint (unpadded base64url of SHA-256 over the
    /// canonical `{"crv","kty","x","y"}` JSON). This is the value the Auth
    /// Center records as `cnf.jkt` on the access token.
    pub fn jkt(&self) -> &str {
        &self.inner.jkt
    }

    /// Sign `signing_input` (the `header.payload` compact-JWT segments) with
    /// ES256, returning the raw 64-byte `r||s` signature.
    pub fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, DpopError> {
        let signature = self.inner.signing_key.sign(signing_input);
        Ok(signature.to_vec())
    }
}

/// Port for DPoP key lifecycle management, keyed by holder + device.
///
/// Implementations must be `Send + Sync` so they can be shared via
/// `Arc<dyn IDpopKeyStore>`. The trait never exposes private key bytes:
/// [`IDpopKeyStore::generate`] mints a key inside the store and returns a
/// signing handle, and [`IDpopKeyStore::bind`] registers a generated handle
/// under a selector. A durable store can replace
/// [`InMemoryDpopKeyStore`] without touching call sites.
///
/// **Lifecycle contract:** keys live and die with their session's token
/// vault bundle. Call sites bind at OIDC callback (bundle store), move on
/// local JWT refresh (bundle move), and clear on logout / revocation /
/// expired-bundle eviction (bundle clear).
pub trait IDpopKeyStore: fmt::Debug + Send + Sync {
    /// Generate a fresh ES256 (P-256) key pair inside the store. The handle
    /// is unbound until [`IDpopKeyStore::bind`] registers it.
    fn generate(&self) -> Result<DpopSigningHandle, DpopError>;

    /// Register `handle` under `selector`, replacing any previous binding.
    fn bind(&self, handle: DpopSigningHandle, selector: &DpopKeySelector) -> Result<(), DpopError>;

    /// Return the signing handle bound to `selector`, or `None` if absent.
    fn get(&self, selector: &DpopKeySelector) -> Result<Option<DpopSigningHandle>, DpopError>;

    /// Atomically move a binding from `from` to `to` (local JWT refresh).
    /// Returns `true` if a binding was moved; a missing `from` moves nothing.
    fn move_key(&self, from: &DpopKeySelector, to: &DpopKeySelector) -> Result<bool, DpopError>;

    /// Remove the binding for `selector`. Returns `true` if one was removed.
    fn clear(&self, selector: &DpopKeySelector) -> Result<bool, DpopError>;

    /// Remove every binding owned by `holder`. Returns the number removed.
    fn clear_all_for_holder(&self, holder: &str) -> Result<usize, DpopError>;
}

/// In-memory [`IDpopKeyStore`] implementation. Process-local stop-gap,
/// mirroring the token vault: keys do not survive restarts (a fresh OIDC
/// login restores them) and are not shared across replicas.
#[derive(Debug, Default)]
pub struct InMemoryDpopKeyStore {
    bindings: Mutex<HashMap<DpopKeySelector, DpopSigningHandle>>,
}

impl InMemoryDpopKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<DpopKeySelector, DpopSigningHandle>> {
        // Same recovery policy as the token vault: a poisoned lock still
        // holds consistent data; prefer availability over aborting.
        match self.bindings.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl IDpopKeyStore for InMemoryDpopKeyStore {
    fn generate(&self) -> Result<DpopSigningHandle, DpopError> {
        Ok(DpopSigningHandle::new(generate_key_material()?))
    }

    fn bind(&self, handle: DpopSigningHandle, selector: &DpopKeySelector) -> Result<(), DpopError> {
        self.lock().insert(selector.clone(), handle);
        Ok(())
    }

    fn get(&self, selector: &DpopKeySelector) -> Result<Option<DpopSigningHandle>, DpopError> {
        Ok(self.lock().get(selector).cloned())
    }

    fn move_key(&self, from: &DpopKeySelector, to: &DpopKeySelector) -> Result<bool, DpopError> {
        let mut bindings = self.lock();
        match bindings.remove(from) {
            Some(handle) => {
                bindings.insert(to.clone(), handle);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn clear(&self, selector: &DpopKeySelector) -> Result<bool, DpopError> {
        Ok(self.lock().remove(selector).is_some())
    }

    fn clear_all_for_holder(&self, holder: &str) -> Result<usize, DpopError> {
        let mut bindings = self.lock();
        let before = bindings.len();
        bindings.retain(|selector, _| selector.holder != holder);
        Ok(before.saturating_sub(bindings.len()))
    }
}

/// Generate one ES256 key pair and derive its public JWK + thumbprint.
fn generate_key_material() -> Result<DpopKeyMaterial, DpopError> {
    let mut seed = [0_u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| DpopError::KeyGeneration)?;
    let signing_key = SigningKey::from_bytes(&seed).map_err(|_| DpopError::KeyGeneration)?;
    let verifying_key = VerifyingKey::from(&signing_key);

    let encoded = verifying_key.to_encoded_point(false);
    let x_bytes = encoded.x().ok_or(DpopError::KeyGeneration)?;
    let y_bytes = encoded.y().ok_or(DpopError::KeyGeneration)?;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x_bytes.as_slice());
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y_bytes.as_slice());
    let public_jwk = DpopPublicJwk {
        kty: "EC".to_owned(),
        crv: "P-256".to_owned(),
        x,
        y,
    };
    let jkt = jwk_thumbprint(&public_jwk);
    Ok(DpopKeyMaterial {
        signing_key,
        public_jwk,
        jkt,
    })
}

/// RFC 7638 thumbprint: SHA-256 over the canonical lexicographically ordered
/// JWK JSON `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`, unpadded base64url.
/// Byte-identical to the Auth Center's `p256JWKThumbprint`
/// (verified: rsm_project/auth-center/internal/oauthdpop/proof.go:356-371).
pub fn jwk_thumbprint(jwk: &DpopPublicJwk) -> String {
    // Built by hand (not serde) to pin the exact canonical byte form.
    let canonical = format!(
        "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    let digest = Sha256::digest(canonical.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// DPoP proof JWT compact serialisation: header + payload + ES256 signature.
#[derive(Serialize)]
struct ProofHeader<'a> {
    typ: &'static str,
    alg: &'static str,
    jwk: &'a DpopPublicJwk,
}

#[derive(Serialize)]
struct ProofClaims<'a> {
    jti: &'a str,
    htm: &'a str,
    htu: &'a str,
    iat: i64,
    /// Present only on the protected-resource profile; the token-endpoint
    /// profile must NOT carry it (verified: oauthdpop/proof.go:177-180).
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<&'a str>,
}

/// Mint a DPoP proof (compact `typ=dpop+jwt` JWT) signed with `handle`.
///
/// * `htm` — uppercase HTTP method of the request the proof covers.
/// * `htu` — HTTP target URI without query/fragment (RFC 9449 §4.3); use
///   [`dpop_resource_htu`] for resource requests.
/// * `iat` — UNIX seconds; receivers enforce a freshness window.
/// * `jti` — stateless unique identifier; replay adjudication happens in the
///   Auth Center replay ledger, AionCore stores nothing.
/// * `ath` — `Some(base64url(SHA-256(access_token)))` for resource requests,
///   `None` for the token-endpoint request.
pub fn build_dpop_proof(
    handle: &DpopSigningHandle,
    htm: &str,
    htu: &str,
    iat: i64,
    jti: &str,
    ath: Option<&str>,
) -> Result<String, DpopError> {
    if htm.is_empty() || htu.is_empty() || jti.is_empty() || htm.contains(char::is_whitespace) {
        return Err(DpopError::InvalidProofInput);
    }
    let header = ProofHeader {
        typ: "dpop+jwt",
        alg: "ES256",
        jwk: &handle.inner.public_jwk,
    };
    let claims = ProofClaims {
        jti,
        htm,
        htu,
        iat,
        ath,
    };
    let encode = |value: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes());
    let header_segment = encode(&serde_json::to_string(&header).map_err(|_| DpopError::ProofEncoding)?);
    let claims_segment = encode(&serde_json::to_string(&claims).map_err(|_| DpopError::ProofEncoding)?);
    let signing_input = format!("{header_segment}.{claims_segment}");
    let signature = handle.sign(signing_input.as_bytes())?;
    let signature_segment = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);
    Ok(format!("{signing_input}.{signature_segment}"))
}

/// `ath` claim value: unpadded base64url of SHA-256 over the access token
/// (verified: oauthdpop/proof.go `sha256Base64URL`, `ath` comparison at
/// proof.go:184).
pub fn dpop_ath(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Stateless DPoP `jti`: 43-character unpadded base64url of 32 random bytes.
/// Satisfies the Auth Center's `isValidJTI` (16–255 canonical characters;
/// verified: oauthdpop/claims.go:214-217). Nothing is persisted.
pub fn generate_dpop_jti() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS randomness unavailable");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Canonical `htu` for a resource request: absolute URL with query and
/// fragment stripped (RFC 9449 §4.3). The Auth Center verifier rejects any
/// `htu` carrying a query (`oauthdpop/proof.go` `validHTU`), so the ACP-side
/// canonical comparison must see the stripped form.
pub fn dpop_resource_htu(url: &url::Url) -> String {
    let mut stripped = url.clone();
    stripped.set_query(None);
    stripped.set_fragment(None);
    stripped.to_string()
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use sha2::Digest;

    use super::*;

    fn decoded_segment(proof: &str, index: usize) -> serde_json::Value {
        let segment = proof.split('.').nth(index).expect("proof has three segments");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .expect("segment is valid base64url");
        serde_json::from_slice(&bytes).expect("segment is valid JSON")
    }

    /// Rebuild an ES256 signature from the raw 64-byte r||s encoding.
    fn signature_from_r_s(raw: &[u8]) -> Signature {
        use p256::elliptic_curve::FieldBytes;
        let (r, s) = raw.split_at(32);
        Signature::from_scalars(
            *FieldBytes::<p256::NistP256>::from_slice(r),
            *FieldBytes::<p256::NistP256>::from_slice(s),
        )
        .expect("64 raw bytes are always a valid r||s pair")
    }

    #[test]
    fn generated_handle_exposes_jwk_and_canonical_thumbprint() {
        let handle = InMemoryDpopKeyStore::new().generate().unwrap();
        let jwk = handle.public_jwk();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.x.len(), 43, "coordinate must be 43-char base64url");
        assert_eq!(jwk.y.len(), 43);
        // Independent thumbprint recomputation from the exposed JWK.
        let expected = {
            let canonical = format!(
                "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\",\"y\":\"{}\"}}",
                jwk.crv, jwk.kty, jwk.x, jwk.y
            );
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
        };
        assert_eq!(handle.jkt(), expected);
        // Thumbprint must also be derivable from a re-serialised JWK.
        let parsed: DpopPublicJwk = serde_json::from_slice(&serde_json::to_vec(&jwk).unwrap()).unwrap();
        assert_eq!(jwk_thumbprint(&parsed), handle.jkt());
    }

    #[test]
    fn debug_output_never_contains_private_material() {
        let handle = InMemoryDpopKeyStore::new().generate().unwrap();
        let rendered = format!("{handle:?} {handle:?}", handle = handle);
        // The handle renders only the thumbprint; there is no secret-string
        // field to leak, but pin the contract for future edits.
        assert!(rendered.contains(&handle.jkt().to_owned()));
        assert!(!rendered.contains("SigningKey"));
    }

    #[test]
    fn token_endpoint_proof_has_exact_shape_and_self_verifies() {
        let handle = InMemoryDpopKeyStore::new().generate().unwrap();
        let proof = build_dpop_proof(
            &handle,
            "POST",
            "https://auth.example/oauth/token",
            1_700_000_000,
            &generate_dpop_jti(),
            None,
        )
        .unwrap();

        let segments: Vec<&str> = proof.split('.').collect();
        assert_eq!(segments.len(), 3);

        let header = decoded_segment(&proof, 0);
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["jwk"]["kty"], "EC");
        assert_eq!(header["jwk"]["crv"], "P-256");

        let claims = decoded_segment(&proof, 1);
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "https://auth.example/oauth/token");
        assert_eq!(claims["iat"], 1_700_000_000);
        assert!(claims["jti"].as_str().unwrap().len() >= 16);
        // Token-endpoint profile must NOT carry ath.
        assert!(claims.get("ath").is_none());

        // Self-verify the ES256 signature with the JWK from the header.
        let jwk = handle.public_jwk();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&jwk.x).unwrap();
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&jwk.y).unwrap();
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        let verifying_key = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        let signature = signature_from_r_s(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(segments[2])
                .unwrap(),
        );
        let signing_input = format!("{}.{}", segments[0], segments[1]);
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .expect("proof signature must verify with the header JWK");
    }

    #[test]
    fn resource_proof_binds_ath_to_access_token_and_verifies() {
        let handle = InMemoryDpopKeyStore::new().generate().unwrap();
        let access_token = "upstream-access-token-value";
        let ath = dpop_ath(access_token);
        assert_eq!(ath.len(), 43);
        let proof = build_dpop_proof(
            &handle,
            "GET",
            "https://acp.example/api/schedule/v1/schedules",
            1_700_000_001,
            &generate_dpop_jti(),
            Some(&ath),
        )
        .unwrap();

        let claims = decoded_segment(&proof, 1);
        assert_eq!(claims["ath"], ath.as_str());
        // ath is SHA-256(access_token), base64url unpadded.
        let expected_ath =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
        assert_eq!(ath, expected_ath);

        // Tampered access token hash must be detectable by the receiver.
        assert_ne!(dpop_ath("other-token"), ath);

        // And the signature still self-verifies.
        let segments: Vec<&str> = proof.split('.').collect();
        let jwk = handle.public_jwk();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&jwk.x).unwrap();
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&jwk.y).unwrap();
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        let verifying_key = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        let signing_input = format!("{}.{}", segments[0], segments[1]);
        let signature = signature_from_r_s(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(segments[2])
                .unwrap(),
        );
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .expect("resource proof signature must verify");
    }

    #[test]
    fn resource_htu_strips_query_and_fragment() {
        let url = url::Url::parse("https://acp.example/api/x?workspace_id=w&b=2#frag").unwrap();
        assert_eq!(dpop_resource_htu(&url), "https://acp.example/api/x");
        let clean = url::Url::parse("https://acp.example/api/x").unwrap();
        assert_eq!(dpop_resource_htu(&clean), "https://acp.example/api/x");
    }

    #[test]
    fn invalid_proof_input_is_rejected() {
        let handle = InMemoryDpopKeyStore::new().generate().unwrap();
        assert!(matches!(
            build_dpop_proof(&handle, "", "https://a.example/x", 1, "jti-jti-jti-jti", None),
            Err(DpopError::InvalidProofInput)
        ));
        assert!(matches!(
            build_dpop_proof(&handle, "GET", "", 1, "jti-jti-jti-jti", None),
            Err(DpopError::InvalidProofInput)
        ));
        assert!(matches!(
            build_dpop_proof(&handle, "GET", "https://a.example/x", 1, "", None),
            Err(DpopError::InvalidProofInput)
        ));
    }

    #[test]
    fn jti_is_random_unique_and_canonical() {
        let first = generate_dpop_jti();
        let second = generate_dpop_jti();
        assert_ne!(first, second);
        assert_eq!(first.len(), 43);
        assert!(
            first
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }

    #[test]
    fn in_memory_store_binds_gets_moves_and_clears_by_selector() {
        let store = InMemoryDpopKeyStore::new();
        let alice = DpopKeySelector::new("user-1", "device-a");
        let bob = DpopKeySelector::new("user-2", "device-a");

        let handle = store.generate().unwrap();
        store.bind(handle.clone(), &alice).unwrap();
        let fetched = store.get(&alice).unwrap().expect("binding present");
        assert_eq!(fetched.jkt(), handle.jkt());
        assert!(store.get(&bob).unwrap().is_none(), "selectors are isolated");

        // Refresh: move to a new device dimension.
        let alice_rotated = DpopKeySelector::new("user-1", "device-b");
        assert!(store.move_key(&alice, &alice_rotated).unwrap());
        assert!(store.get(&alice).unwrap().is_none());
        assert_eq!(store.get(&alice_rotated).unwrap().unwrap().jkt(), handle.jkt());
        assert!(
            !store.move_key(&alice, &alice_rotated).unwrap(),
            "missing move is a no-op"
        );

        // Holder-wide clear removes all of user-1, none of user-2.
        let bob_handle = store.generate().unwrap();
        store.bind(bob_handle, &bob).unwrap();
        assert_eq!(store.clear_all_for_holder("user-1").unwrap(), 1);
        assert!(store.get(&alice_rotated).unwrap().is_none());
        assert!(store.get(&bob).unwrap().is_some());
        assert!(store.clear(&bob).unwrap(), "existing binding must clear");
        assert!(!store.clear(&bob).unwrap(), "second clear reports nothing removed");
    }
}
