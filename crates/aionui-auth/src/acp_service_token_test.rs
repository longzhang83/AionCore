use crate::acp_service_token;

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Throwaway test material (generated once with openssl for this file only).
// Never used outside unit tests; never a real credential. Mirrors the embedded
// run_face.rs test certificate precedent.
// ---------------------------------------------------------------------------

const TEST_CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBpTCCAUugAwIBAgIUb6uRtocEVopdyY36KxFD+/XPGXcwCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVYWNwLWFkbWlzc2lvbi10ZXN0LWNhMB4XDTI2MDkxMzEyMjUz
M1oXDTI2MTAxMzEyMjUzM1owIDEeMBwGA1UEAwwVYWNwLWFkbWlzc2lvbi10ZXN0
LWNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB1NpbfDJWenG0jQCWwcM4/ci
AZVGn2W0YoMzjGzehCZC6ZuERC9i4InVIevGfNVppmxaFi2ShKGxgDExik8nTqNj
MGEwHQYDVR0OBBYEFGtOV/NfG5+dwAXqs+ytuh/Hh3TvMB8GA1UdIwQYMBaAFGtO
V/NfG5+dwAXqs+ytuh/Hh3TvMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
AgIEMAoGCCqGSM49BAMCA0gAMEUCIH0lhy5rsfNJGHXPG61tqCEX5zrq9qGTKt/c
2puGCTt3AiEAiw5auwD7J2pc3lfXy9/HCD/P7JfaONra2iKoCyBqvh0=
-----END CERTIFICATE-----
";

const TEST_SERVER_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBqDCCAU+gAwIBAgIUZtpkM4gL/FVDPt7aJvpIoFiLos8wCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVYWNwLWFkbWlzc2lvbi10ZXN0LWNhMB4XDTI2MDkxMzEyMjUz
M1oXDTI2MTAxMzEyMjUzM1owFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEWsPmYbGYPoYM0EFpIDBolEz3mVGdklbtpX6DothV
VvewTSv8k+ExTUPdcEZ2UYk3eiPioo6yjh1wCP6CtPmAJaNzMHEwGgYDVR0RBBMw
EYIJbG9jYWxob3N0hwR/AAABMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQW
BBSnr9rkZ0uyD7gyAmOpABaFhmKJMjAfBgNVHSMEGDAWgBRrTlfzXxufncAF6rPs
rbofx4d07zAKBggqhkjOPQQDAgNHADBEAiAXBVheb5hNrqZH77xr/hAQxN1LAzbu
sjCTPKOjCY+r6wIgWT/0gr/d75IPfi9GBluh3eD/Ml4UwA+E6QiHpDHNS9w=
-----END CERTIFICATE-----
";

const TEST_SERVER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrqlKXS7NHt9Zl49Y
ZvixBcrKtUPctrDlz5gIOFH2++ihRANCAARaw+ZhsZg+hgzQQWkgMGiUTPeZUZ2S
Vu2lfoOi2FVW97BNK/yT4TFNQ91wRnZRiTd6I+KijrKOHXAI/oK0+YAl
-----END PRIVATE KEY-----
";

const TEST_CLIENT_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBnTCCAUOgAwIBAgIUZtpkM4gL/FVDPt7aJvpIoFiLotAwCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVYWNwLWFkbWlzc2lvbi10ZXN0LWNhMB4XDTI2MDkxMzEyMjUz
M1oXDTI2MTAxMzEyMjUzM1owJDEiMCAGA1UEAwwZYWNwLWFkbWlzc2lvbi10ZXN0
LWNsaWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPy781v4HYc84Zg8hsg7
en5EewZtlCD8oSetHj6Eb9rJeXcG3id8kRUybL3calmpBR9PkKN0yQ6jGNSmyoNu
VaOjVzBVMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBSduZISF0woIMUB
UtjNSefAtSVTzTAfBgNVHSMEGDAWgBRrTlfzXxufncAF6rPsrbofx4d07zAKBggq
hkjOPQQDAgNIADBFAiBohz0flCbADtyaxtTzconyDIN2VZuY+DA4XXPB1KLXXAIh
AOfUUDrFU0p+3HUw4SU6BaiIGJyPmAV7pyNlU6C4wzpG
-----END CERTIFICATE-----
";

const TEST_CLIENT_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcZ7pIVYURWHUpLnT
PKni0ji4TJOEjzhJWl5/iJn4vCGhRANCAAT8u/Nb+B2HPOGYPIbIO3p+RHsGbZQg
/KEnrR4+hG/ayXl3Bt4nfJEVMmy93GpZqQUfT5CjdMkOoxjUpsqDblWj
-----END PRIVATE KEY-----
";

const TEST_RSA_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkDq/OryfhgfMh
8DBvbv1Qnbf7FkzHWkIAaQzsB+UszsoH0dJK/xL6XZ8KWLGZHSqsJEq9XYQWkVDX
K5erRHMFkUSQuTQk6TeAHusjriMylCF3kMYxZBFiRKB073LfEIXM8xGjWTdTk78J
AB6EPMMVrrm4Vve91xxCA7+CB+zvXFgdn2SBYOb3ioxxW9+Qpr0+PxUzeeTsNJTs
437sg7KdEpmZndGFmVRxjPL4+QbnZuOrXk1yeezbwZaKSp0u9eWD/Z9dUzB8p9V5
Iz3oCBMFZCKaDkyNlJ8bVmFAGVEQfgFOQ8N3iLYkii8GTete6KfmMJT/G24ltrcw
8nAVDMlBAgMBAAECggEALx6EwiEunCddtIau8qJ3IRtbh0M9ZBh5UnLZokUWPota
HWrXMnEWe1A+aJNW1vo4kl6OFNtyH6U3CcXcdvVe799sSQDYiC1vol2+/W17cIB5
KEUtl2v9TjMVvuAzJvww4c+CZl8uc9PAj444NZTaFzUq5FYeK6lH1XIMJAWwuIJf
2aVjqRotV8CFPyqP5vaAGYonaDEyuHsN1xtIYAcsvsyEySCAs2ZP9gOOBr27V2GQ
oy2auZ2PTE7jQUvdX+RTwvhr79j37gl8Y4zRtueF85lJMnnRwicKSBZmJTretQK2
satC5yI0Tkixq6wmPZ+H0baDib6UT3u91CuBiISqnQKBgQDlSOODfY8LUv/hYHZo
saJVP9CU3PAK1i+mYyznZVe41MI7siwC+ZBH+cE6UTpLSf3ZAfK+dCAfoiOgp711
+0yAhwnESA3KqYLGkczAVPGK+g62gMutKs4js4L/MUt2CacnD7KgBXXxc72UoZBz
UJqOsnQTfnc2Y4LGIXzDMbvQDwKBgQC3LDHYMffS/m2vkm3SIt0yCmWDHxTc0vV2
uuCAcaYD2Nysi9sMhnj9EWC9eresU5a2I4/YgCmd3s4EPpVixliLgBW/zAxD/Kk8
CvfQjeOx9YB4YhAYD/qbPgk8xUe+OQTaYA078rfGmgTCe4J1RVlTi19oaAJ0QJOy
m8+h3w6BrwKBgCY29syUocHGbKV4uWOLr727rB0TkeKMflaiEvriNjO1KkZe1N0O
EVEdvGnm3etsgqWnoHjDzBLZqEx/iKFgaAjH+QXA6KONiyFjbZfk0HlUYh1i7A+J
od/rbHryEVy0ESr+f8wR/O1oWAGsx/GgTpJYBea13lKvVT2GmU/DO0VbAoGAMrBw
OrvZMPJnuCZ1baloPOjTnq2DQHjApNKiPek1X+srZjRtsdGkuaONeeHz4iRfmJfO
vsL4wU9fA52uCV+KMVCItELrQgUxcAQ4/+XEFQMzQh0hBwek+kD4nXCaofF1flkG
UIiigrsshgVX3MwMJCp1hJcD1tfoB41GsCzh/tECgYEAt5vlW4tT6FKovLK3E9Dw
VBDN/M/vjAdq67kwJU3snknhV9g55GmO9kHYcCefSZuOgVVCtQdRdQCNtViBE6oJ
Cv3ZOJbaWsi6QcSTS3P8gNYwIX8TrKB+sdFW3ThRtMUPR/gauEhxibdH+xgQ5w4r
rBvRnJmM3jrhq1dR+8Fcszk=
-----END PRIVATE KEY-----
";

const TEST_RSA_MODULUS_B64URL: &str = "pA6vzq8n4YHzIfAwb279UJ23-xZMx1pCAGkM7AflLM7KB9HSSv8S-l2fClixmR0qrCRKvV2EFpFQ1yuXq0RzBZFEkLk0JOk3gB7rI64jMpQhd5DGMWQRYkSgdO9y3xCFzPMRo1k3U5O_CQAehDzDFa65uFb3vdccQgO_ggfs71xYHZ9kgWDm94qMcVvfkKa9Pj8VM3nk7DSU7ON-7IOynRKZmZ3RhZlUcYzy-PkG52bjq15Ncnns28GWikqdLvXlg_2fXVMwfKfVeSM96AgTBWQimg5MjZSfG1ZhQBlREH4BTkPDd4i2JIovBk3rXuin5jCU_xtuJba3MPJwFQzJQQ";

const TEST_RSA_EXPONENT_B64URL: &str = "AQAB";
const TEST_KID: &str = "test-jwk-key-1";
const TEST_ISSUER: &str = "https://acp-issuer.test";

fn pem_section(body: &str, label: &str) -> Vec<u8> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut inside = false;
    let mut encoded = String::new();
    for line in body.lines() {
        if line.trim() == begin {
            inside = true;
            continue;
        }
        if line.trim() == end {
            break;
        }
        if inside {
            encoded.push_str(line.trim());
        }
    }
    BASE64_STANDARD
        .decode(encoded.as_bytes())
        .expect("test PEM base64 must decode")
}

fn test_ca_der() -> Vec<u8> {
    pem_section(TEST_CA_CERT_PEM, "CERTIFICATE")
}

fn verified_client_leaf_from_handshake() -> acp_service_token::VerifiedClientLeaf {
    // Build a real rustls server-side handshake with a mandatory
    // WebPkiClientVerifier and extract the leaf the way production code will.
    let provider: Arc<rustls::crypto::CryptoProvider> = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(test_ca_der()))
        .expect("test CA must parse");

    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .expect("client verifier must build");

    let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(pem_section(
        TEST_SERVER_KEY_PEM,
        "PRIVATE KEY",
    )));
    let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(pem_section(
                TEST_SERVER_CERT_PEM,
                "CERTIFICATE",
            ))],
            server_key,
        )
        .expect("server cert material");

    let client_cert = rustls::pki_types::CertificateDer::from(pem_section(TEST_CLIENT_CERT_PEM, "CERTIFICATE"));
    let client_key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(pem_section(
        TEST_CLIENT_KEY_PEM,
        "PRIVATE KEY",
    )));
    let mut client_roots = rustls::RootCertStore::empty();
    client_roots
        .add(rustls::pki_types::CertificateDer::from(test_ca_der()))
        .expect("test CA must parse");
    let client_config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(client_roots)
        .with_client_auth_cert(vec![client_cert], client_key)
        .expect("client cert material");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let addr = listener.local_addr().expect("local addr");

    let (connection_tx, connection_rx) = std::sync::mpsc::channel();
    let server_handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut connection = rustls::ServerConnection::new(Arc::new(server_config)).expect("server connection");
        while connection.is_handshaking() {
            connection.complete_io(&mut sock).expect("server handshake io");
        }
        let _ = connection_tx.send(connection);
    });

    let mut sock = std::net::TcpStream::connect(addr).expect("connect");
    let mut client_connection = rustls::ClientConnection::new(
        Arc::new(client_config),
        rustls::pki_types::ServerName::try_from("localhost".to_string()).expect("dns name"),
    )
    .expect("client connection");
    while client_connection.is_handshaking() {
        client_connection.complete_io(&mut sock).expect("client handshake io");
    }
    server_handle.join().expect("server thread");

    let server_connection = connection_rx.recv().expect("server connection returned");
    acp_service_token::VerifiedClientLeaf::from_rustls_server_connection(&server_connection)
        .expect("verified leaf from mandatory-verifier handshake")
}

#[derive(Clone)]
struct TestClaimsOverrides {
    sub: String,
    client_id: String,
    principal_type: String,
    jti: String,
    tenant_id: String,
    service_role: String,
    workload_instance_id: String,
    service_authority_epoch: i64,
    orgs: serde_json::Value,
    cnf_thumbprint: Option<String>,
    issuer: String,
    audience: String,
    exp_offset_seconds: i64,
    kid: String,
}

impl Default for TestClaimsOverrides {
    fn default() -> Self {
        Self {
            sub: "acp-service-1".into(),
            client_id: "acp-service-1".into(),
            principal_type: "machine".into(),
            jti: "jti-1".into(),
            tenant_id: "tenant-1".into(),
            service_role: "core".into(),
            workload_instance_id: "acp-instance-1".into(),
            service_authority_epoch: 3,
            orgs: json!([{ "id": "org-1", "isPrimary": true }]),
            cnf_thumbprint: None,
            // Empty means "auto-fill from the server under test" in mint_for;
            // an explicit issuer is preserved for wrong-issuer cases.
            issuer: String::new(),
            audience: acp_service_token::RUN_ADMISSION_RECEIVE_AUDIENCE.into(),
            exp_offset_seconds: 300,
            kid: TEST_KID.into(),
        }
    }
}

fn mint_service_token(overrides: &TestClaimsOverrides, leaf: &acp_service_token::VerifiedClientLeaf) -> String {
    let now = Utc::now();
    let mut claims = json!({
        "sub": overrides.sub,
        "client_id": overrides.client_id,
        "principal_type": overrides.principal_type,
        "jti": overrides.jti,
        "tenant_id": overrides.tenant_id,
        "service_role": overrides.service_role,
        "workload_instance_id": overrides.workload_instance_id,
        "service_authority_epoch": overrides.service_authority_epoch,
        "orgs": overrides.orgs,
        "scope": "run-admission-receive:accept",
        "iss": overrides.issuer,
        "aud": overrides.audience,
        "iat": now.timestamp(),
        "exp": (now + ChronoDuration::seconds(overrides.exp_offset_seconds)).timestamp(),
    });
    let cnf = overrides
        .cnf_thumbprint
        .clone()
        .unwrap_or_else(|| leaf.thumbprint_s256());
    claims["cnf"] = json!({ "x5t#S256": cnf });

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(overrides.kid.clone());
    header.typ = Some("at+jwt".into());
    let encoding_key = EncodingKey::from_rsa_pem(TEST_RSA_SIGNING_KEY_PEM.as_bytes()).expect("test RSA key");
    jsonwebtoken::encode(&header, &claims, &encoding_key).expect("token minting")
}

async fn jwks_server() -> MockServer {
    let server = MockServer::start().await;
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": TEST_KID,
            "n": TEST_RSA_MODULUS_B64URL,
            "e": TEST_RSA_EXPONENT_B64URL,
        }]
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .mount(&server)
        .await;
    server
}

fn test_verifier(issuer_base_url: &str) -> acp_service_token::AcpServiceTokenVerifier {
    acp_service_token::AcpServiceTokenVerifier::new(
        acp_service_token::AcpServiceTokenConfig::new(issuer_base_url)
            .expect("issuer")
            .allow_insecure_http(),
    )
    .expect("verifier")
}

// Mints a token whose issuer matches the verifier under test unless the
// override pins a different (wrong) issuer explicitly.
fn mint_for(issuer: &str, overrides: &TestClaimsOverrides, leaf: &acp_service_token::VerifiedClientLeaf) -> String {
    let mut overrides = overrides.clone();
    if overrides.issuer.is_empty() {
        overrides.issuer = issuer.to_string();
    }
    mint_service_token(&overrides, leaf)
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_validation_failures() {
    let cases: Vec<(&str, String, bool)> = vec![
        ("blank issuer", String::new(), false),
        ("relative issuer", "acp-issuer.test".into(), false),
        ("unsupported scheme", "ftp://acp-issuer.test".into(), false),
        ("http without dev flag", "http://acp-issuer.test".into(), false),
        ("userinfo issuer", "https://svc@acp-issuer.test".into(), false),
        ("query issuer", "https://acp-issuer.test?x=1".into(), false),
        ("fragment issuer", "https://acp-issuer.test#f".into(), false),
    ];
    for (name, issuer, allow_insecure) in cases {
        let mut config = acp_service_token::AcpServiceTokenConfig::new(issuer)
            .unwrap_or_else(|_| acp_service_token::AcpServiceTokenConfig::disabled());
        if allow_insecure {
            config = config.allow_insecure_http();
        }
        let error = acp_service_token::AcpServiceTokenVerifier::new(config)
            .err()
            .unwrap_or_else(|| panic!("{name}: expected construction error"));
        assert!(!error.to_string().is_empty(), "{name}: error must carry context");
    }

    // The http case passes with the explicit development-only flag.
    let config = acp_service_token::AcpServiceTokenConfig::new("http://acp-issuer.test")
        .expect("shape-valid issuer")
        .allow_insecure_http();
    acp_service_token::AcpServiceTokenVerifier::new(config).expect("http issuer allowed with the dev flag");

    // Disabled config never constructs.
    assert!(acp_service_token::AcpServiceTokenConfig::disabled().is_disabled());
    let error = acp_service_token::AcpServiceTokenVerifier::new(acp_service_token::AcpServiceTokenConfig::disabled())
        .expect_err("disabled config must fail construction");
    assert!(error.to_string().contains("issuer"));

    // Blank audience and non-positive TTL fail closed at construction.
    let error = acp_service_token::AcpServiceTokenVerifier::new(
        acp_service_token::AcpServiceTokenConfig::new(TEST_ISSUER)
            .expect("issuer")
            .with_audience("  "),
    )
    .expect_err("blank audience must fail construction");
    assert!(error.to_string().contains("audience"));
    let error = acp_service_token::AcpServiceTokenVerifier::new(
        acp_service_token::AcpServiceTokenConfig::new(TEST_ISSUER)
            .expect("issuer")
            .with_jwks_cache_ttl(std::time::Duration::ZERO),
    )
    .expect_err("zero TTL must fail construction");
    assert!(error.to_string().contains("TTL"));
}

// ---------------------------------------------------------------------------
// End-to-end verification against a real handshake leaf and JWKS server
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verifies_certificate_bound_service_token_end_to_end() {
    let leaf = verified_client_leaf_from_handshake();
    let server = jwks_server().await;
    let verifier = test_verifier(&server.uri());
    let token = mint_for(&server.uri(), &TestClaimsOverrides::default(), &leaf);

    let principal = verifier.verify(&token, &leaf).await.expect("token must verify");
    assert_eq!(principal.service_id, "acp-service-1");
    assert_eq!(principal.service_role, "core");
    assert_eq!(principal.workload_instance_id, "acp-instance-1");
    assert_eq!(principal.credential_key_id, TEST_KID);
    assert_eq!(principal.certificate_thumbprint_s256, leaf.thumbprint_s256());
    assert_eq!(principal.service_authority_epoch, 3);
    assert_eq!(principal.tenant_id, "tenant-1");
    assert_eq!(principal.primary_organization_id, "org-1");
    assert_eq!(principal.scope, "run-admission-receive:accept");

    // Thumbprint is base64url-no-pad SHA-256 of the client leaf DER: 43 chars
    // of URL-safe alphabet.
    let thumbprint = leaf.thumbprint_s256();
    assert_eq!(thumbprint.len(), 43, "sha256 base64url-nopad is 43 chars");
    assert!(
        thumbprint
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "thumbprint must be URL-safe: {thumbprint}"
    );
}

#[tokio::test]
async fn rejects_token_bound_to_a_different_certificate() {
    let leaf = verified_client_leaf_from_handshake();
    let server = jwks_server().await;
    let verifier = test_verifier(&server.uri());
    // Bind the token to the SERVER certificate instead of the presenting
    // client leaf: same issuer/keys, wrong proof-of-possession.
    let overrides = TestClaimsOverrides {
        cnf_thumbprint: Some(
            acp_service_token::VerifiedClientLeaf::from_der(&pem_section(TEST_SERVER_CERT_PEM, "CERTIFICATE"))
                .thumbprint_s256(),
        ),
        ..TestClaimsOverrides::default()
    };
    let token = mint_for(&server.uri(), &overrides, &leaf);

    let error = verifier
        .verify(&token, &leaf)
        .await
        .expect_err("mismatched binding must fail");
    assert!(matches!(error, acp_service_token::AcpServiceTokenError::Binding));
}

#[tokio::test]
async fn rejects_token_without_confirmation_claim() {
    let leaf = verified_client_leaf_from_handshake();
    let server = jwks_server().await;
    let verifier = test_verifier(&server.uri());
    let overrides = TestClaimsOverrides {
        cnf_thumbprint: Some(String::new()),
        ..TestClaimsOverrides::default()
    };
    let token = mint_for(&server.uri(), &overrides, &leaf);

    let error = verifier
        .verify(&token, &leaf)
        .await
        .expect_err("missing confirmation must fail");
    assert!(matches!(error, acp_service_token::AcpServiceTokenError::Binding));
}

// ---------------------------------------------------------------------------
// Machine identity claims profile
// ---------------------------------------------------------------------------

#[tokio::test]
async fn enforces_machine_identity_claims_profile() {
    let leaf = verified_client_leaf_from_handshake();
    let server = jwks_server().await;
    let verifier = test_verifier(&server.uri());

    type ClaimsProfileCase = (&'static str, Box<dyn Fn(&mut TestClaimsOverrides)>);
    let cases: Vec<ClaimsProfileCase> = vec![
        (
            "client_id differs from sub",
            Box::new(|o: &mut TestClaimsOverrides| {
                o.client_id = "someone-else".into();
            }),
        ),
        (
            "human principal type",
            Box::new(|o: &mut TestClaimsOverrides| {
                o.principal_type = "human".into();
            }),
        ),
        (
            "blank jti",
            Box::new(|o: &mut TestClaimsOverrides| {
                o.jti = "  ".into();
            }),
        ),
        (
            "blank tenant",
            Box::new(|o: &mut TestClaimsOverrides| {
                o.tenant_id = "".into();
            }),
        ),
        (
            "blank service role",
            Box::new(|o: &mut TestClaimsOverrides| {
                o.service_role = "".into();
            }),
        ),
        (
            "blank workload instance",
            Box::new(|o: &mut TestClaimsOverrides| {
                o.workload_instance_id = "".into();
            }),
        ),
        (
            "non-positive epoch",
            Box::new(|o: &mut TestClaimsOverrides| {
                o.service_authority_epoch = 0;
            }),
        ),
        (
            "no organizations",
            Box::new(|o: &mut TestClaimsOverrides| {
                o.orgs = json!([]);
            }),
        ),
        (
            "two primary organizations",
            Box::new(|o: &mut TestClaimsOverrides| {
                o.orgs = json!([
                    { "id": "org-1", "isPrimary": true },
                    { "id": "org-2", "isPrimary": true },
                ]);
            }),
        ),
    ];

    for (name, mutate) in cases {
        let mut overrides = TestClaimsOverrides::default();
        mutate(&mut overrides);
        let token = mint_for(&server.uri(), &overrides, &leaf);
        let error = verifier
            .verify(&token, &leaf)
            .await
            .err()
            .unwrap_or_else(|| panic!("{name}: expected claims-profile rejection"));
        assert!(
            matches!(error, acp_service_token::AcpServiceTokenError::ClaimsProfile),
            "{name}: got {error:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Signature, temporal, and header discipline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_tampered_signature() {
    let leaf = verified_client_leaf_from_handshake();
    let server = jwks_server().await;
    let verifier = test_verifier(&server.uri());
    let token = mint_for(&server.uri(), &TestClaimsOverrides::default(), &leaf);

    let mut tampered = token.clone();
    let last = tampered.pop().expect("non-empty token");
    // Replace the final signature character with a different one whose low
    // four bits are zero (canonical base64url tail), keeping the token shape
    // and decode canonicality so the failure is a signature verification
    // failure rather than a base64 rejection.
    let replacement = if last == 'w' { 'g' } else { 'w' };
    tampered.push(replacement);

    let error = verifier
        .verify(&tampered, &leaf)
        .await
        .expect_err("tampered token must fail");
    if !matches!(error, acp_service_token::AcpServiceTokenError::InvalidSignature) {
        panic!("expected InvalidSignature, got {error:?}");
    }
}

#[tokio::test]
async fn maps_temporal_and_issuer_failures() {
    let leaf = verified_client_leaf_from_handshake();
    let server = jwks_server().await;
    let verifier = test_verifier(&server.uri());

    let expired = TestClaimsOverrides {
        exp_offset_seconds: -30,
        ..TestClaimsOverrides::default()
    };
    let error = verifier
        .verify(&mint_for(&server.uri(), &expired, &leaf), &leaf)
        .await
        .expect_err("expired token must fail");
    assert!(matches!(error, acp_service_token::AcpServiceTokenError::ExpiredToken));

    let wrong_issuer = TestClaimsOverrides {
        issuer: "https://someone-else.test".into(),
        ..TestClaimsOverrides::default()
    };
    let error = verifier
        .verify(&mint_for(&server.uri(), &wrong_issuer, &leaf), &leaf)
        .await
        .expect_err("issuer mismatch must fail");
    assert!(matches!(error, acp_service_token::AcpServiceTokenError::IssuerMismatch));

    let wrong_audience = TestClaimsOverrides {
        audience: "agent-control-plane:run-authority".into(),
        ..TestClaimsOverrides::default()
    };
    let error = verifier
        .verify(&mint_for(&server.uri(), &wrong_audience, &leaf), &leaf)
        .await
        .expect_err("audience mismatch must fail");
    assert!(matches!(error, acp_service_token::AcpServiceTokenError::InvalidClaims));
}

#[tokio::test]
async fn enforces_header_discipline() {
    let leaf = verified_client_leaf_from_handshake();
    let server = jwks_server().await;
    let verifier = test_verifier(&server.uri());

    // Missing kid: minted without kid must fail as malformed.
    let token = mint_for(&server.uri(), &TestClaimsOverrides::default(), &leaf);
    let forged_no_kid = {
        // Re-sign with the same claims but a kid-less header.
        let parts: Vec<&str> = token.split('.').collect();
        let claims = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).expect("claims segment")).expect("claims json");
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        let encoding_key = EncodingKey::from_rsa_pem(TEST_RSA_SIGNING_KEY_PEM.as_bytes()).expect("test RSA key");
        jsonwebtoken::encode(
            &header,
            &serde_json::from_str::<serde_json::Value>(&claims).expect("claims"),
            &encoding_key,
        )
        .expect("re-sign")
    };
    let error = verifier
        .verify(&forged_no_kid, &leaf)
        .await
        .expect_err("kid-less token must fail");
    assert!(matches!(error, acp_service_token::AcpServiceTokenError::MalformedToken));

    // Blank token: missing-credential class.
    let error = verifier.verify("   ", &leaf).await.expect_err("blank token must fail");
    assert!(matches!(error, acp_service_token::AcpServiceTokenError::MissingToken));
}

// ---------------------------------------------------------------------------
// JWKS discipline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refreshes_once_on_unknown_kid_then_fails_closed() {
    let leaf = verified_client_leaf_from_handshake();
    let server = MockServer::start().await;
    // JWKS published under a different kid than the token presents.
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "some-other-key",
            "n": TEST_RSA_MODULUS_B64URL,
            "e": TEST_RSA_EXPONENT_B64URL,
        }]
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .expect(2)
        .mount(&server)
        .await;
    let verifier = test_verifier(&server.uri());
    let token = mint_for(&server.uri(), &TestClaimsOverrides::default(), &leaf);

    let error = verifier.verify(&token, &leaf).await.expect_err("unknown kid must fail");
    assert!(matches!(error, acp_service_token::AcpServiceTokenError::UnknownKeyId));
}

#[tokio::test]
async fn unavailable_jwks_fails_closed() {
    let leaf = verified_client_leaf_from_handshake();
    // A JWKS origin that returns 404: the fetch fails closed.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let verifier = test_verifier(&server.uri());
    let token = mint_for(&server.uri(), &TestClaimsOverrides::default(), &leaf);

    let error = verifier
        .verify(&token, &leaf)
        .await
        .expect_err("unavailable JWKS must fail");
    assert!(matches!(
        error,
        acp_service_token::AcpServiceTokenError::JwksUnavailable
    ));
}

#[tokio::test]
async fn malformed_jwks_documents_fail_closed() {
    let leaf = verified_client_leaf_from_handshake();
    let cases: Vec<(&str, serde_json::Value)> = vec![
        ("no RSA keys", json!({ "keys": [] })),
        (
            "empty kid",
            json!({ "keys": [{ "kty": "RSA", "alg": "RS256", "kid": "", "n": TEST_RSA_MODULUS_B64URL, "e": TEST_RSA_EXPONENT_B64URL }] }),
        ),
        (
            "duplicate kid",
            json!({ "keys": [
                { "kty": "RSA", "alg": "RS256", "kid": TEST_KID, "n": TEST_RSA_MODULUS_B64URL, "e": TEST_RSA_EXPONENT_B64URL },
                { "kty": "RSA", "alg": "RS256", "kid": TEST_KID, "n": TEST_RSA_MODULUS_B64URL, "e": TEST_RSA_EXPONENT_B64URL },
            ] }),
        ),
        (
            "incomplete RSA key",
            json!({ "keys": [{ "kty": "RSA", "alg": "RS256", "kid": TEST_KID, "n": TEST_RSA_MODULUS_B64URL }] }),
        ),
    ];
    for (name, jwks) in cases {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;
        let verifier = test_verifier(&server.uri());
        let token = mint_for(&server.uri(), &TestClaimsOverrides::default(), &leaf);
        let error = verifier
            .verify(&token, &leaf)
            .await
            .err()
            .unwrap_or_else(|| panic!("{name}: expected JWKS rejection"));
        match error {
            acp_service_token::AcpServiceTokenError::JwksMalformed => {}
            other => panic!("{name}: expected JwksMalformed, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Verified leaf extraction discipline
// ---------------------------------------------------------------------------

#[test]
fn leaf_extraction_requires_presented_client_certificate() {
    // A server connection without a verified client certificate chain never
    // yields a leaf. Drive a real handshake where the server accepts no
    // client certificate: the extraction must fail closed.
    let provider: Arc<rustls::crypto::CryptoProvider> = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

    let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(pem_section(
        TEST_SERVER_KEY_PEM,
        "PRIVATE KEY",
    )));
    let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(pem_section(
                TEST_SERVER_CERT_PEM,
                "CERTIFICATE",
            ))],
            server_key,
        )
        .expect("server cert material");

    let mut client_roots = rustls::RootCertStore::empty();
    client_roots
        .add(rustls::pki_types::CertificateDer::from(test_ca_der()))
        .expect("test CA must parse");
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(client_roots)
        .with_no_client_auth();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let addr = listener.local_addr().expect("local addr");
    let server_handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut connection = rustls::ServerConnection::new(Arc::new(server_config)).expect("server connection");
        while connection.is_handshaking() {
            connection.complete_io(&mut sock).ok();
        }
        connection
    });

    let mut sock = std::net::TcpStream::connect(addr).expect("connect");
    let mut client_connection = rustls::ClientConnection::new(
        Arc::new(client_config),
        rustls::pki_types::ServerName::try_from("localhost".to_string()).expect("dns name"),
    )
    .expect("client connection");
    while client_connection.is_handshaking() {
        client_connection.complete_io(&mut sock).expect("client handshake io");
    }
    let server_connection = server_handle.join().expect("server thread");

    let error = acp_service_token::VerifiedClientLeaf::from_rustls_server_connection(&server_connection)
        .expect_err("no client certificate must fail extraction");
    assert!(matches!(error, acp_service_token::AcpServiceTokenError::Binding));
}
