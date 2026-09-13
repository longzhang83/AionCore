//! Production ACP HTTP transports for the run ports (T0-RUN-EXECUTOR Slice
//! E3).
//!
//! One client, two faces: [`AcpRunTransport`] implements both
//! [`RunOutputUplink`] and [`RunInputDownlink`] against the ACP run routes —
//! `POST /api/team-workspace/v1/run-output-manifests`,
//! `GET .../run-admissions/{id}/input-manifest`, and
//! `GET .../run-admissions/{id}/input-objects/{object_key}`. The object key
//! is the member's `content_id` (the ACP deliverer resolves membership by
//! content identity and unescapes the wildcard path segment).
//!
//! Authentication mirrors the ACP remote admission deliverer (T0-RUN-FACE-AUTH):
//! a certificate-bound service token is presented as a Bearer credential over
//! mTLS, with the token arriving through deployment configuration exactly as
//! it does on the ACP side — the transport never mints or fetches tokens
//! (IdP issuance is a later card). Fail-closed transport posture:
//!
//! - HTTPS only (the run face binds tokens to TLS client certificates, so a
//!   plaintext base URL can never authenticate);
//! - the server CA is pinned from configuration and built-in root stores are
//!   disabled — the transport trusts exactly the configured authority;
//! - redirects are disabled — following one would replay the Bearer
//!   credential to a non-ACP origin.
//!
//! Wire error mapping keeps the ACP error envelope's `code` (both the flat
//! `{code, message, request_id}` shape and the auth middleware's
//! `{error, error_description}` shape) so callers can distinguish retry
//! classes exactly as the acceptor/deliverer contracts intend.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::Url;
use thiserror::Error;

use crate::run_input_downlink::{
    RunInputDownlink, RunInputDownlinkError, RunInputManifest, RunInputManifestMember, RunInputObjectReceipt,
    VerifiedObjectWriter,
};
use crate::run_output_uplink::{RunOutputManifest, RunOutputUplink, RunOutputUplinkError};

/// Path prefix of the ACP run face, mounted directly on the server root.
const RUN_FACE_PATH_PREFIX: &str = "/api/team-workspace/v1";

#[derive(Debug, Error)]
pub enum AcpRunTransportBuildError {
    #[error("ACP run transport base URL must be an HTTPS origin: {0}")]
    BaseUrl(String),
    #[error("ACP run transport service token is blank")]
    BlankServiceToken,
    #[error("ACP run transport TLS material is unusable: {0}")]
    TlsMaterial(String),
}

/// The production transport over the ACP run face. Cheap to clone via
/// construction; hold one per process.
pub struct AcpRunTransport {
    base_url: Url,
    service_token: String,
    client: reqwest::Client,
}

impl AcpRunTransport {
    /// Build the transport. `client_cert_pem` and `client_key_pem` form the
    /// mTLS identity whose certificate the service token's `cnf.x5t#S256`
    /// claim binds to; `server_ca_pem` is the only trusted server authority.
    pub fn new(
        base_url: &str,
        service_token: &str,
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
        server_ca_pem: &[u8],
    ) -> Result<Self, AcpRunTransportBuildError> {
        let mut base_url = Url::parse(base_url).map_err(|_| AcpRunTransportBuildError::BaseUrl(base_url.to_owned()))?;
        if base_url.scheme() != "https" || base_url.host_str().is_none() {
            return Err(AcpRunTransportBuildError::BaseUrl(base_url.to_string()));
        }
        base_url.set_path("");
        base_url.set_query(None);
        base_url.set_fragment(None);
        if service_token.trim().is_empty() {
            return Err(AcpRunTransportBuildError::BlankServiceToken);
        }

        let mut bundle = client_cert_pem.to_vec();
        bundle.extend_from_slice(client_key_pem);
        let identity = reqwest::Identity::from_pem(&bundle)
            .map_err(|error| AcpRunTransportBuildError::TlsMaterial(format!("client identity: {error}")))?;
        let server_ca = reqwest::Certificate::from_pem(server_ca_pem)
            .map_err(|error| AcpRunTransportBuildError::TlsMaterial(format!("server CA: {error}")))?;

        let client = reqwest::Client::builder()
            .identity(identity)
            .add_root_certificate(server_ca)
            // Pin trust to the configured CA only.
            .tls_built_in_root_certs(false)
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| AcpRunTransportBuildError::TlsMaterial(format!("client build: {error}")))?;
        Ok(Self {
            base_url,
            service_token: service_token.to_owned(),
            client,
        })
    }

    fn face_url(&self, path: &str) -> Result<Url, AcpRunTransportBuildError> {
        // Url normalizes an empty path to "/", so the origin always carries a
        // trailing slash here — strip it before appending the face prefix.
        let origin = self.base_url.as_str().trim_end_matches('/');
        let candidate = format!("{origin}{RUN_FACE_PATH_PREFIX}{path}");
        Url::parse(&candidate).map_err(|_| AcpRunTransportBuildError::BaseUrl(candidate))
    }

    /// The ACP error `code` from either envelope shape; `unknown` when the
    /// body is not the expected JSON (a proxy interference marker, not a
    /// contract state).
    async fn rejection_code(response: reqwest::Response) -> String {
        let Ok(body) = response.text().await else {
            return "unreadable".to_owned();
        };
        let value: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
        value
            .get("code")
            .or_else(|| value.get("error"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_owned()
    }
}

#[async_trait]
impl RunOutputUplink for AcpRunTransport {
    async fn submit_output_manifest(
        &self,
        manifest: &RunOutputManifest,
    ) -> Result<RunOutputManifest, RunOutputUplinkError> {
        let url = self
            .face_url("/run-output-manifests")
            .map_err(|_| RunOutputUplinkError::Unavailable)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(&self.service_token)
            .json(manifest)
            .send()
            .await
            .map_err(|_| RunOutputUplinkError::Unavailable)?;
        let status = response.status();
        if status.as_u16() != 201 {
            let code = Self::rejection_code(response).await;
            return Err(RunOutputUplinkError::Rejected {
                status: status.as_u16(),
                code,
            });
        }
        let body = response.bytes().await.map_err(|_| RunOutputUplinkError::Unavailable)?;
        serde_json::from_slice(&body).map_err(|_| RunOutputUplinkError::InvalidResponse)
    }
}

/// The `RunInputDelivery` envelope: the delivery face returns the admission
/// record alongside the manifest; Core already holds the admission from its
/// receive face, so the record is parsed leniently and only the manifest is
/// surfaced.
#[derive(serde::Deserialize)]
struct RunInputDeliveryEnvelope {
    #[serde(default)]
    #[allow(dead_code)]
    admission: serde_json::Value,
    input_manifest: RunInputManifest,
}

#[async_trait]
impl RunInputDownlink for AcpRunTransport {
    async fn fetch_input_manifest(&self, run_admission_id: &str) -> Result<RunInputManifest, RunInputDownlinkError> {
        let path = format!("/run-admissions/{run_admission_id}/input-manifest");
        let url = self.face_url(&path).map_err(|_| RunInputDownlinkError::Unavailable)?;
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.service_token)
            .send()
            .await
            .map_err(|_| RunInputDownlinkError::Unavailable)?;
        let status = response.status();
        if status.as_u16() != 200 {
            let code = Self::rejection_code(response).await;
            return Err(RunInputDownlinkError::Rejected {
                status: status.as_u16(),
                code,
            });
        }
        let envelope: RunInputDeliveryEnvelope = response
            .json()
            .await
            .map_err(|_| RunInputDownlinkError::InvalidManifest)?;
        Ok(envelope.input_manifest)
    }

    async fn fetch_input_object(
        &self,
        run_admission_id: &str,
        member: &RunInputManifestMember,
        destination: &std::path::Path,
    ) -> Result<RunInputObjectReceipt, RunInputDownlinkError> {
        let path = format!("/run-admissions/{run_admission_id}/input-objects");
        let mut url = self.face_url(&path).map_err(|_| RunInputDownlinkError::Unavailable)?;
        // Membership resolves by content identity; the segment push
        // percent-encodes the key and the ACP wildcard route unescapes it.
        url.path_segments_mut()
            .map_err(|_| RunInputDownlinkError::Unavailable)?
            .push(&member.content.content_id);
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.service_token)
            .send()
            .await
            .map_err(|_| RunInputDownlinkError::Unavailable)?;
        let status = response.status();
        if status.as_u16() != 200 {
            let code = Self::rejection_code(response).await;
            return Err(RunInputDownlinkError::Rejected {
                status: status.as_u16(),
                code,
            });
        }

        let mut writer = VerifiedObjectWriter::create(destination, &member.content).await?;
        let mut response = response;
        while let Some(chunk) = response.chunk().await.map_err(|_| RunInputDownlinkError::Unavailable)? {
            writer.write_chunk(&chunk).await?;
        }
        writer.finish().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http_body_util::BodyExt;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use rustls::RootCertStore;
    use rustls::server::WebPkiClientVerifier;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use sha2::Digest;

    use crate::run_admission_test_support::{
        TEST_CA_CERT_PEM, TEST_CLIENT_CERT_PEM, TEST_CLIENT_KEY_PEM, TEST_SERVER_CERT_PEM, TEST_SERVER_KEY_PEM,
        pem_section,
    };
    use crate::run_input_downlink::RunContentIdentity;

    /// One scripted response: status + body, keyed by nothing — the handler
    /// closure decides per request.
    type Handler = Arc<dyn Fn(&str, &str, &[u8]) -> (u16, String) + Send + Sync>;

    struct ScriptedServer {
        base_url: String,
        requests: Arc<std::sync::Mutex<Vec<String>>>,
    }

    /// Starts a real mTLS HTTPS server (the B2b test TLS material, client
    /// certificates required) that records each request's path + authorization
    /// header and answers through `handler`.
    async fn start_scripted_server(handler: Handler) -> ScriptedServer {
        let mut roots = RootCertStore::empty();
        roots
            .add(pem_section(TEST_CA_CERT_PEM, "CERTIFICATE").into())
            .expect("test CA must parse");
        let provider: Arc<rustls::crypto::CryptoProvider> = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .expect("client verifier");
        let server_cert = vec![pem_section(TEST_SERVER_CERT_PEM, "CERTIFICATE").into()];
        let server_key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(pem_section(TEST_SERVER_KEY_PEM, "PRIVATE KEY").into());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_cert, server_key)
            .expect("server cert material");

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        std_listener.set_nonblocking(true).expect("non-blocking");
        let addr = std_listener.local_addr().expect("addr");
        let listener = TcpListener::from_std(std_listener).expect("tokio listener");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let requests: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = requests.clone();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let handler = handler.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(tls),
                            service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                                let handler = handler.clone();
                                let recorded = recorded.clone();
                                async move {
                                    let path = request.uri().path().to_owned();
                                    let authorization = request
                                        .headers()
                                        .get("authorization")
                                        .and_then(|value| value.to_str().ok())
                                        .unwrap_or_default()
                                        .to_owned();
                                    let body = request
                                        .into_body()
                                        .collect()
                                        .await
                                        .map(|collected| collected.to_bytes().to_vec())
                                        .unwrap_or_default();
                                    recorded.lock().unwrap().push(format!("{path} {authorization}"));
                                    let (status, body) = handler(&path, &authorization, &body);
                                    let response = hyper::Response::builder()
                                        .status(status)
                                        .header("content-type", "application/json")
                                        .body(http_body_util::Full::new(axum::body::Bytes::from(body)))
                                        .expect("static response");
                                    Ok::<_, std::convert::Infallible>(response)
                                }
                            }),
                        )
                        .await;
                });
            }
        });

        ScriptedServer {
            base_url: format!("https://localhost:{}", addr.port()),
            requests,
        }
    }

    fn transport(server: &ScriptedServer) -> AcpRunTransport {
        AcpRunTransport::new(
            &server.base_url,
            "test-service-token",
            TEST_CLIENT_CERT_PEM.as_bytes(),
            TEST_CLIENT_KEY_PEM.as_bytes(),
            TEST_CA_CERT_PEM.as_bytes(),
        )
        .expect("transport builds from the test TLS material")
    }

    fn output_manifest() -> RunOutputManifest {
        serde_json::from_str(
            r#"{
                "output_manifest_id": "om-1",
                "manifest_format": "rsm-output-manifest-v1",
                "run_admission_id": "adm-1",
                "admission_version": 1,
                "run_id": "run-1",
                "attempt_id": "attempt-1",
                "owner_epoch": 1,
                "tenant_id": "tenant-1",
                "resource_organization_id": "org-1",
                "workspace_id": "ws-1",
                "input_base": {"kind": "revision", "revision_id": "rev-1", "manifest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                "input_manifest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "captured_output_snapshot_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "members": [],
                "captured_at_ms": 1760000000000,
                "state": "fixed",
                "manifest_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }"#,
        )
        .expect("fixture manifest")
    }

    fn member(resource_path: &str, content_id: &str) -> RunInputManifestMember {
        member_with_size(resource_path, content_id, 4)
    }

    fn member_with_size(resource_path: &str, content_id: &str, size: i64) -> RunInputManifestMember {
        RunInputManifestMember {
            resource_path: resource_path.to_owned(),
            content: RunContentIdentity {
                content_id: content_id.to_owned(),
                plaintext_sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
                plaintext_size: size,
            },
        }
    }

    #[tokio::test]
    async fn submission_presents_the_bearer_token_and_round_trips_the_persisted_echo() {
        let mut echo = output_manifest();
        echo.state = "persisted".to_owned();
        let echo_json = serde_json::to_string(&echo).unwrap();
        let server = start_scripted_server(Arc::new(move |path, authorization, body| {
            assert_eq!(path, "/api/team-workspace/v1/run-output-manifests");
            assert_eq!(authorization, "Bearer test-service-token");
            let submitted: serde_json::Value = serde_json::from_slice(body).expect("submission is valid JSON");
            assert_eq!(submitted["output_manifest_id"], "om-1");
            assert_eq!(submitted["state"], "fixed");
            (201, echo_json.clone())
        }))
        .await;

        let persisted = transport(&server)
            .submit_output_manifest(&output_manifest())
            .await
            .expect("submission should succeed");

        assert_eq!(persisted.state, "persisted");
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn wire_rejections_keep_the_envelope_code_from_both_shapes() {
        let server = start_scripted_server(Arc::new(|_, _, _| {
            (
                409,
                r#"{"code":"run_output_manifest_conflict","message":"duplicate","request_id":"r-1"}"#.to_owned(),
            )
        }))
        .await;
        let outcome = transport(&server).submit_output_manifest(&output_manifest()).await;
        assert!(
            matches!(outcome, Err(RunOutputUplinkError::Rejected { status: 409, code }) if code == "run_output_manifest_conflict")
        );

        let auth_shape = start_scripted_server(Arc::new(|_, _, _| {
            (
                401,
                r#"{"error":"unauthorized","error_description":"A certificate-bound Core service principal is required"}"#
                    .to_owned(),
            )
        }))
        .await;
        let outcome = transport(&auth_shape).submit_output_manifest(&output_manifest()).await;
        assert!(matches!(outcome, Err(RunOutputUplinkError::Rejected { status: 401, code }) if code == "unauthorized"));
    }

    #[tokio::test]
    async fn a_server_not_signed_by_the_pinned_ca_is_a_transport_failure() {
        // Trust the client certificate as the server CA: the test server's
        // certificate cannot verify, so the handshake must fail closed
        // instead of falling back to any built-in root store.
        let server = start_scripted_server(Arc::new(|_, _, _| (201, "{}".to_owned()))).await;
        let mispinned = AcpRunTransport::new(
            &server.base_url,
            "test-service-token",
            TEST_CLIENT_CERT_PEM.as_bytes(),
            TEST_CLIENT_KEY_PEM.as_bytes(),
            TEST_CLIENT_CERT_PEM.as_bytes(),
        )
        .expect("transport builds");
        let outcome = mispinned.submit_output_manifest(&output_manifest()).await;
        assert!(matches!(outcome, Err(RunOutputUplinkError::Unavailable)));
        assert!(server.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn fetch_input_manifest_parses_the_delivery_envelope() {
        let envelope = r#"{
            "admission": {"run_admission_id": "adm-1"},
            "input_manifest": {
                "manifest_format": "rsm-workspace-content-manifest-v1",
                "manifest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "members": [{"resource_path": "docs/a.txt", "content": {
                    "content_id": "object-key-1",
                    "plaintext_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "plaintext_size": 5
                }}]
            }
        }"#;
        let server = start_scripted_server(Arc::new(move |path, authorization, _| {
            assert_eq!(path, "/api/team-workspace/v1/run-admissions/adm-1/input-manifest");
            assert_eq!(authorization, "Bearer test-service-token");
            (200, envelope.to_owned())
        }))
        .await;

        let manifest = transport(&server)
            .fetch_input_manifest("adm-1")
            .await
            .expect("manifest fetch should succeed");

        assert_eq!(manifest.manifest_format, "rsm-workspace-content-manifest-v1");
        assert_eq!(manifest.members.len(), 1);
        assert_eq!(manifest.members[0].content.content_id, "object-key-1");
    }

    #[tokio::test]
    async fn fetch_input_object_streams_into_the_verified_writer() {
        const KEY: &str = "object-key-1";
        let body = "alpha".as_bytes().to_vec();
        let expected_digest = hex::encode(sha2::Sha256::digest(&body));
        // The pinned identity must match the served bytes or verification
        // fails: same discipline as the E1 fake downlink.
        let pinned = {
            let mut pinned = member_with_size("docs/a.txt", KEY, body.len() as i64);
            pinned.content.plaintext_sha256 = expected_digest.clone();
            pinned
        };
        let server = start_scripted_server(Arc::new(move |path, _, _| {
            // The wildcard route captures the encoded key; the deliverer
            // resolves membership by content identity.
            assert!(path.starts_with("/api/team-workspace/v1/run-admissions/adm-1/input-objects/"));
            (200, String::from_utf8(body.clone()).expect("ascii body"))
        }))
        .await;
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("input/docs/a.txt");
        tokio::fs::create_dir_all(destination.parent().unwrap()).await.unwrap();

        let receipt = transport(&server)
            .fetch_input_object("adm-1", &pinned, &destination)
            .await
            .expect("object fetch should succeed");

        assert_eq!(receipt.plaintext_sha256, expected_digest);
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"alpha".to_vec());
        // The requested segment is the member's content_id.
        let recorded = server.requests.lock().unwrap();
        assert!(
            recorded[0].starts_with("/api/team-workspace/v1/run-admissions/adm-1/input-objects/object-key-1"),
            "object path should carry the content id, got {}",
            recorded[0]
        );
    }

    #[tokio::test]
    async fn object_and_manifest_rejections_surface_as_typed_rejections() {
        let server = start_scripted_server(Arc::new(|path, _, _| {
            if path.contains("input-objects") {
                (
                    404,
                    r#"{"code":"object_not_in_input_manifest","message":"missing","request_id":"r-1"}"#.to_owned(),
                )
            } else {
                (
                    404,
                    r#"{"code":"run_admission_not_found","message":"missing","request_id":"r-1"}"#.to_owned(),
                )
            }
        }))
        .await;
        let client = transport(&server);

        let outcome = client.fetch_input_manifest("adm-404").await;
        assert!(
            matches!(outcome, Err(RunInputDownlinkError::Rejected { status: 404, code }) if code == "run_admission_not_found")
        );

        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("a.txt");
        let outcome = client
            .fetch_input_object("adm-1", &member("a.txt", "k"), &destination)
            .await;
        assert!(
            matches!(outcome, Err(RunInputDownlinkError::Rejected { status: 404, code }) if code == "object_not_in_input_manifest")
        );
        assert!(!tokio::fs::try_exists(&destination).await.unwrap());
    }

    #[tokio::test]
    async fn a_digest_mismatching_stream_fails_verification() {
        // Exactly the pinned size (4 bytes) with wrong content: the size
        // guard passes and the digest check fails.
        let server = start_scripted_server(Arc::new(|_, _, _| (200, "bad1".to_owned()))).await;
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("a.txt");

        let outcome = transport(&server)
            .fetch_input_object("adm-1", &member("a.txt", "k"), &destination)
            .await;

        assert!(matches!(outcome, Err(RunInputDownlinkError::ObjectDigestMismatch)));
        assert!(!tokio::fs::try_exists(&destination).await.unwrap());
    }
}
