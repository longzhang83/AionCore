//! End-to-end tests for the dedicated internal mTLS listener
//! (T0-ACP-ADMISSION-DELIVERY Slice B2b).
//!
//! Each test starts the real listener — `build_mtls_server_config` material,
//! `spawn_run_admission_listener` accept loop, receive-face router — on an
//! ephemeral loopback port and connects with a real rustls client, so the
//! handshake → leaf-extraction → router path is exercised over actual TLS.

use std::sync::Arc;

use aionui_auth::{AcpServiceTokenConfig, AcpServiceTokenVerifier};
use axum::Router;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::run_admission_listener::{build_mtls_server_config, spawn_run_admission_listener};
use crate::run_admission_receive::{
    RUN_ADMISSION_DUPLICATE_CODE, RUN_ADMISSION_RECEIVE_PATH, RunAdmissionReceiveState,
};
use crate::run_admission_test_support::{
    IDEMPOTENCY_KEY_1, IDEMPOTENCY_KEY_2, MemoryAdmissionStore, MintOverrides, TEST_CA_CERT_PEM, TEST_CLIENT_CERT_PEM,
    TEST_CLIENT_KEY_PEM, TEST_SERVER_CERT_PEM, TEST_SERVER_KEY_PEM, error_code, fixture_canonical_echo, fixture_record,
    jwks_server, mint_token, pem_section,
};

struct ListenerFixture {
    addr: std::net::SocketAddr,
    store: Arc<MemoryAdmissionStore>,
    server: wiremock::MockServer,
}

async fn start_listener() -> ListenerFixture {
    let server = jwks_server().await;
    let verifier = AcpServiceTokenVerifier::new(
        AcpServiceTokenConfig::new(server.uri())
            .expect("issuer")
            .allow_insecure_http(),
    )
    .expect("verifier");
    let store = Arc::new(MemoryAdmissionStore::default());
    let router: Router = crate::run_admission_receive::run_admission_receive_router(RunAdmissionReceiveState {
        verifier,
        repository: store.clone(),
    });
    let tls = build_mtls_server_config(
        TEST_SERVER_CERT_PEM.as_bytes(),
        TEST_SERVER_KEY_PEM.as_bytes(),
        TEST_CA_CERT_PEM.as_bytes(),
    )
    .expect("mTLS server config");

    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    std_listener
        .set_nonblocking(true)
        .expect("listener non-blocking for tokio");
    let addr = std_listener.local_addr().expect("local addr");
    let listener = tokio::net::TcpListener::from_std(std_listener).expect("tokio listener");
    spawn_run_admission_listener(listener, tls, router);
    ListenerFixture { addr, store, server }
}

/// Builds a rustls client connector; with_client_cert controls whether the
/// client presents the test client certificate.
async fn client_connector(with_client_cert: bool) -> TlsConnector {
    let provider: Arc<rustls::crypto::CryptoProvider> = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(pem_section(TEST_CA_CERT_PEM, "CERTIFICATE")))
        .expect("test CA must parse");
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots);
    let config = if with_client_cert {
        builder
            .with_client_auth_cert(
                vec![CertificateDer::from(pem_section(TEST_CLIENT_CERT_PEM, "CERTIFICATE"))],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pem_section(
                    TEST_CLIENT_KEY_PEM,
                    "PRIVATE KEY",
                ))),
            )
            .expect("client cert material")
    } else {
        builder.with_no_client_auth()
    };
    TlsConnector::from(Arc::new(config))
}

/// Sends one raw HTTP/1.1 request over the mTLS connection and returns the
/// full response bytes (Connection: close makes the server end the stream).
async fn post_admission(
    connector: &TlsConnector,
    addr: std::net::SocketAddr,
    token: &str,
    idempotency_key: &str,
    body: &str,
) -> Vec<u8> {
    let mut tls_stream = connector
        .connect(
            ServerName::try_from("localhost".to_string()).expect("dns name"),
            TcpStream::connect(addr).await.expect("tcp connect"),
        )
        .await
        .expect("mTLS handshake");
    let request = format!(
        "POST {RUN_ADMISSION_RECEIVE_PATH} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Idempotency-Key: {idempotency_key}\r\n\
         Content-Type: application/json\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    tls_stream.write_all(request.as_bytes()).await.expect("write request");
    tls_stream.write_all(body.as_bytes()).await.expect("write body");
    tls_stream.flush().await.expect("flush request");

    let mut response = Vec::new();
    tls_stream.read_to_end(&mut response).await.expect("read response");
    response
}

fn response_status_and_body(response: &[u8]) -> (u16, String) {
    let text = String::from_utf8(response.to_vec()).expect("response is UTF-8");
    let (head, body) = text
        .split_once("\r\n\r\n")
        .expect("response has a header/body separator");
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status line");
    (status, body.to_string())
}

#[tokio::test]
async fn end_to_end_admission_delivery_over_mtls() {
    let fixture = start_listener().await;
    // Mint the token against the real client certificate: the listener
    // extracts the same leaf from the handshake, so the cnf binding matches.
    let leaf = aionui_auth::VerifiedClientLeaf::from_der(&pem_section(TEST_CLIENT_CERT_PEM, "CERTIFICATE"));
    let token = mint_token(&fixture.server.uri(), &MintOverrides::default(), &leaf);
    let connector = client_connector(true).await;

    let response = post_admission(
        &connector,
        fixture.addr,
        &token,
        IDEMPOTENCY_KEY_1,
        &fixture_record().to_string(),
    )
    .await;
    let (status, body) = response_status_and_body(&response);
    assert_eq!(status, 200, "response: {response:?}");
    assert_eq!(body, fixture_canonical_echo());

    let held = fixture.store.held.lock().unwrap();
    assert_eq!(held.len(), 1);
}

#[tokio::test]
async fn client_without_certificate_is_rejected_at_handshake() {
    let fixture = start_listener().await;
    let connector = client_connector(false).await;

    // The client's state machine may complete before the server's
    // rejection alert arrives, so the invariant is not "connect errs" but
    // "no successful admission response is obtainable": the exchange either
    // fails outright (handshake alert) or returns no HTTP 200.
    let exchange = async {
        let mut tls_stream = connector
            .connect(
                ServerName::try_from("localhost".to_string()).expect("dns name"),
                TcpStream::connect(fixture.addr).await.expect("tcp connect"),
            )
            .await?;
        tls_stream.write_all(b"POST /internal/run-authority/v1/admissions HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
        tls_stream.flush().await?;
        let mut response = Vec::new();
        tls_stream.read_to_end(&mut response).await?;
        Ok::<Vec<u8>, std::io::Error>(response)
    }
    .await;
    match exchange {
        Err(_) => {} // rejected at the handshake or by a TLS alert on read
        Ok(response) => {
            let (status, _) = response_status_and_body(&response);
            assert_ne!(status, 200, "a certless client must never admit: {response:?}");
        }
    }
}

#[tokio::test]
async fn wrong_certificate_binding_is_401_over_mtls() {
    let fixture = start_listener().await;
    let leaf = aionui_auth::VerifiedClientLeaf::from_der(&pem_section(TEST_CLIENT_CERT_PEM, "CERTIFICATE"));
    let token = mint_token(
        &fixture.server.uri(),
        &MintOverrides {
            cnf_thumbprint: Some("mismatched-thumbprint-value-00000000000000000".to_string()),
            ..MintOverrides::default()
        },
        &leaf,
    );
    let connector = client_connector(true).await;

    let response = post_admission(
        &connector,
        fixture.addr,
        &token,
        IDEMPOTENCY_KEY_2,
        &fixture_record().to_string(),
    )
    .await;
    let (status, body) = response_status_and_body(&response);
    assert_eq!(status, 401, "response: {response:?}");
    assert_eq!(error_code(&body), "unauthorized");
}

#[tokio::test]
async fn repeat_delivery_over_mtls_is_409_duplicate() {
    let fixture = start_listener().await;
    let leaf = aionui_auth::VerifiedClientLeaf::from_der(&pem_section(TEST_CLIENT_CERT_PEM, "CERTIFICATE"));
    let token = mint_token(&fixture.server.uri(), &MintOverrides::default(), &leaf);
    let connector = client_connector(true).await;
    let body = fixture_record().to_string();

    let first = post_admission(&connector, fixture.addr, &token, IDEMPOTENCY_KEY_1, &body).await;
    assert_eq!(response_status_and_body(&first).0, 200);

    let second = post_admission(&connector, fixture.addr, &token, IDEMPOTENCY_KEY_2, &body).await;
    let (status, resp_body) = response_status_and_body(&second);
    assert_eq!(status, 409);
    assert_eq!(error_code(&resp_body), RUN_ADMISSION_DUPLICATE_CODE);
}
