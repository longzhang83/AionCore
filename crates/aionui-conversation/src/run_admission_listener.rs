//! Dedicated internal mTLS listener for the run admission receive face
//! (T0-ACP-ADMISSION-DELIVERY Slice B2b).
//!
//! The product API server stays plain HTTP; admissions are accepted on a
//! separate TLS-only socket whose `ServerConfig` is built with a **mandatory**
//! `WebPkiClientVerifier` — the handshake completes only for clients presenting
//! a chain under the configured CA, which is the rustls counterpart of Go's
//! `VerifiedChains`-only discipline (see `VerifiedClientLeaf`). After each
//! successful handshake the verified leaf is inserted into the request
//! extensions and the connection is served by the receive-face router; a
//! request without a leaf is a 401, so this listener is the only legitimate
//! mount.

use std::io::BufReader;
use std::sync::Arc;

use aionui_auth::VerifiedClientLeaf;
use axum::Router;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

/// Builds the receive-face mTLS `ServerConfig` from PEM material: the
/// listener certificate + key and the CA that signs ACP workload client
/// certificates. Client authentication is mandatory — connections without a
/// verifiable client chain never complete the handshake.
pub fn build_mtls_server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
    client_ca_pem: &[u8],
) -> Result<Arc<ServerConfig>, RunAdmissionListenerError> {
    let provider: Arc<rustls::crypto::CryptoProvider> = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

    let cert_chain: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_pem))
        .collect::<Result<_, _>>()
        .map_err(|error| RunAdmissionListenerError::ServerCertificate(error.to_string()))?;
    if cert_chain.is_empty() {
        return Err(RunAdmissionListenerError::ServerCertificate(
            "no certificate found in PEM".into(),
        ));
    }
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem))
        .map_err(|error| RunAdmissionListenerError::ServerKey(error.to_string()))?
        .ok_or_else(|| RunAdmissionListenerError::ServerKey("no private key found in PEM".into()))?;

    let mut roots = RootCertStore::empty();
    let cas: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(client_ca_pem))
        .collect::<Result<_, _>>()
        .map_err(|error| RunAdmissionListenerError::ClientCa(error.to_string()))?;
    if cas.is_empty() {
        return Err(RunAdmissionListenerError::ClientCa(
            "no certificate found in PEM".into(),
        ));
    }
    for ca in cas {
        roots
            .add(ca)
            .map_err(|error| RunAdmissionListenerError::ClientCa(error.to_string()))?;
    }

    let client_verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|error| RunAdmissionListenerError::ClientVerifier(rustls::Error::General(error.to_string())))?;

    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(RunAdmissionListenerError::ServerConfig)?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|error| RunAdmissionListenerError::ServerConfig(rustls::Error::General(error.to_string())))?;
    Ok(Arc::new(config))
}

/// Binds nothing and starts the accept loop: every accepted connection is
/// handshaken with the mTLS config, its verified leaf inserted into request
/// extensions, and served by the receive-face router over HTTP/1.1. The
/// listener runs for the process lifetime; handshake and connection failures
/// are logged and the connection dropped (fail closed).
pub fn spawn_run_admission_listener(listener: TcpListener, tls: Arc<ServerConfig>, router: Router) {
    let acceptor = TlsAcceptor::from(tls);
    tokio::spawn(async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(error = %error, "run admission listener: accept failed");
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let router = router.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(tcp).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        tracing::debug!(
                            error = %error,
                            peer = %peer,
                            "run admission listener: tls handshake failed"
                        );
                        return;
                    }
                };
                // The handshake completed under a mandatory client verifier,
                // so a successfully extracted leaf is a verified client
                // identity (VerifiedClientLeaf discipline).
                let leaf = match VerifiedClientLeaf::from_rustls_server_connection(tls_stream.get_ref().1) {
                    Ok(leaf) => leaf,
                    Err(error) => {
                        tracing::debug!(
                            error = %error,
                            peer = %peer,
                            "run admission listener: verified leaf extraction failed"
                        );
                        return;
                    }
                };
                let service = service_fn(move |mut request: hyper::Request<Incoming>| {
                    let router = router.clone();
                    let leaf = leaf.clone();
                    async move {
                        request.extensions_mut().insert(leaf);
                        // Router is infallible as a Service; the never type
                        // satisfies hyper's error bound.
                        router
                            .oneshot(request.map(axum::body::Body::new))
                            .await
                            .map_err(|never| match never {})
                    }
                });
                if let Err(error) = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls_stream), service)
                    .await
                {
                    tracing::debug!(error = %error, peer = %peer, "run admission listener: connection ended");
                }
            });
        }
    });
}

/// Listener setup failures. All variants are startup faults: a configured
/// receive face that cannot build its TLS material must abort startup, never
/// silently skip wiring.
#[derive(Debug, thiserror::Error)]
pub enum RunAdmissionListenerError {
    #[error("admission receive TLS server certificate is missing or unparsable: {0}")]
    ServerCertificate(String),
    #[error("admission receive TLS server key is missing or unparsable: {0}")]
    ServerKey(String),
    #[error("admission receive client CA is missing or unparsable: {0}")]
    ClientCa(String),
    #[error("admission receive client verifier build failed: {0}")]
    ClientVerifier(#[source] rustls::Error),
    #[error("admission receive TLS server config build failed: {0}")]
    ServerConfig(#[source] rustls::Error),
}
