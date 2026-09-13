//! Agent Control Plane run-face machine client (T0-CORE-INPUT-DOWNLINK-CLIENT).
//!
//! This module is the Core-side transport for the certificate-bound run face
//! the V3 security design §3 freezes: mTLS client identity plus a
//! certificate-bound service token (audience
//! `agent-control-plane:run-authority`, scope `run-authority:execute`). It is
//! machine identity — deliberately unlike the schedule BFF, which proxies
//! human DPoP sessions. The client identity is loaded from deployment
//! configuration (cert/key PEM files; production provisioning belongs to the
//! IdP issuance card) and is never embedded in source.
//!
//! Fail-closed configuration: enabling the client (a base URL) requires the
//! client cert/key material AND a bearer token — a run-face caller that
//! cannot present its full identity is rejected at construction, never on
//! the first run.

#![allow(clippy::disallowed_types)] // This module is an HTTP boundary, like schedule_bff.rs.

use std::path::PathBuf;
use std::time::Duration;

use axum::http::StatusCode;
use reqwest::Url;
use thiserror::Error;

use crate::auth_center_tokens::AuthCenterTokenSecret;

const RUN_FACE_SCOPE_AUDIENCE: &str = "agent-control-plane:run-authority";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Streaming objects are bounded: a run-face response that keeps sending past
/// this cap is a broken or hostile upstream and is cut off mid-stream.
pub const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

/// Fail-closed run-face client configuration.
///
/// A missing base URL leaves the client disabled (the run input downlink port
/// has no production implementation). When enabled, the client certificate +
/// key PEM files and the certificate-bound service token are all required —
/// the ACP run face rejects partial identities with 401, so constructing a
/// client that cannot authenticate would only move the same failure to a
/// worse place.
#[derive(Debug, Clone)]
pub struct RunFaceClientConfig {
    base_url: Option<Url>,
    timeout: Duration,
    client_cert_pem_path: Option<PathBuf>,
    client_key_pem_path: Option<PathBuf>,
    bearer_token: Option<AuthCenterTokenSecret>,
    max_object_bytes: u64,
}

#[derive(Debug, Error)]
pub enum RunFaceConfigError {
    #[error("run-face base URL is invalid")]
    InvalidBaseUrl,
    #[error("run-face base URL must use http or https")]
    InvalidScheme,
    #[error("run-face base URL must not contain credentials, query, or fragment components")]
    InvalidBaseUrlComponents,
    #[error("run-face timeout must be a positive integer number of milliseconds")]
    InvalidTimeout,
    #[error("run-face client certificate PEM file is required when the run face is enabled")]
    MissingClientCert,
    #[error("run-face client key PEM file is required when the run face is enabled")]
    MissingClientKey,
    #[error("run-face service token is required when the run face is enabled")]
    MissingBearerToken,
    #[error("run-face client cert/key files could not be read or parsed: {0}")]
    IdentityUnusable(String),
    #[error("run-face max object bytes must be a positive integer")]
    InvalidMaxObjectBytes,
}

impl RunFaceClientConfig {
    /// The disabled client: the run input downlink has no transport.
    pub fn disabled() -> Self {
        Self {
            base_url: None,
            timeout: DEFAULT_TIMEOUT,
            client_cert_pem_path: None,
            client_key_pem_path: None,
            bearer_token: None,
            max_object_bytes: MAX_OBJECT_BYTES,
        }
    }

    fn new_transport(
        base_url: impl AsRef<str>,
        timeout: Duration,
        client_cert_pem_path: PathBuf,
        client_key_pem_path: PathBuf,
        bearer_token: AuthCenterTokenSecret,
    ) -> Result<Self, RunFaceConfigError> {
        if timeout.is_zero() {
            return Err(RunFaceConfigError::InvalidTimeout);
        }
        let mut base_url = Url::parse(base_url.as_ref()).map_err(|_| RunFaceConfigError::InvalidBaseUrl)?;
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(RunFaceConfigError::InvalidScheme);
        }
        if !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(RunFaceConfigError::InvalidBaseUrlComponents);
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        if !client_cert_pem_path.is_file() {
            return Err(RunFaceConfigError::IdentityUnusable(format!(
                "{} is not a file",
                client_cert_pem_path.display()
            )));
        }
        if !client_key_pem_path.is_file() {
            return Err(RunFaceConfigError::IdentityUnusable(format!(
                "{} is not a file",
                client_key_pem_path.display()
            )));
        }
        Ok(Self {
            base_url: Some(base_url),
            timeout,
            client_cert_pem_path: Some(client_cert_pem_path),
            client_key_pem_path: Some(client_key_pem_path),
            bearer_token: Some(bearer_token),
            max_object_bytes: MAX_OBJECT_BYTES,
        })
    }

    pub fn max_object_bytes(&self) -> u64 {
        self.max_object_bytes
    }

    /// Override the streaming cap (used by tests; deployments keep the
    /// workspace default).
    pub fn with_max_object_bytes(mut self, max_object_bytes: u64) -> Self {
        self.max_object_bytes = max_object_bytes;
        self
    }

    /// Builds an enabled client from programmatic configuration.
    pub fn new_with_material(
        base_url: impl AsRef<str>,
        timeout: Duration,
        client_cert_pem_path: PathBuf,
        client_key_pem_path: PathBuf,
        bearer_token: AuthCenterTokenSecret,
    ) -> Result<Self, RunFaceConfigError> {
        if client_cert_pem_path.as_os_str().is_empty() {
            return Err(RunFaceConfigError::MissingClientCert);
        }
        if client_key_pem_path.as_os_str().is_empty() {
            return Err(RunFaceConfigError::MissingClientKey);
        }
        if bearer_token.expose().is_empty() {
            return Err(RunFaceConfigError::MissingBearerToken);
        }
        Self::new_transport(
            base_url,
            timeout,
            client_cert_pem_path,
            client_key_pem_path,
            bearer_token,
        )
    }

    fn from_values(
        base_url: Option<&str>,
        timeout: Duration,
        client_cert_pem_path: Option<PathBuf>,
        client_key_pem_path: Option<PathBuf>,
        bearer_token: Option<AuthCenterTokenSecret>,
    ) -> Result<Self, RunFaceConfigError> {
        let Some(base_url) = base_url else {
            return Ok(Self::disabled());
        };
        Self::new_with_material(
            base_url,
            timeout,
            client_cert_pem_path.unwrap_or_default(),
            client_key_pem_path.unwrap_or_default(),
            bearer_token.unwrap_or_else(|| AuthCenterTokenSecret::new(String::new())),
        )
    }

    /// Loads the configuration from the environment. An unset
    /// `RSM_RUN_FACE_BASE_URL` disables the client; every other failure is
    /// surfaced as a config error instead of a default.
    pub fn from_env() -> Result<Self, RunFaceConfigError> {
        let base_url = std::env::var("RSM_RUN_FACE_BASE_URL")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let Some(base_url) = base_url else {
            return Self::from_values(None, DEFAULT_TIMEOUT, None, None, None);
        };
        let timeout = match std::env::var("RSM_RUN_FACE_TIMEOUT_MS") {
            Ok(value) => {
                let millis = value
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .filter(|millis| *millis > 0)
                    .ok_or(RunFaceConfigError::InvalidTimeout)?;
                Duration::from_millis(millis)
            }
            Err(_) => DEFAULT_TIMEOUT,
        };
        let cert_path = std::env::var("RSM_RUN_FACE_CLIENT_CERT_FILE")
            .ok()
            .map(|value| PathBuf::from(value.trim()))
            .filter(|path| !path.as_os_str().is_empty());
        let key_path = std::env::var("RSM_RUN_FACE_CLIENT_KEY_FILE")
            .ok()
            .map(|value| PathBuf::from(value.trim()))
            .filter(|path| !path.as_os_str().is_empty());
        let token = std::env::var("RSM_RUN_FACE_BEARER_TOKEN")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(AuthCenterTokenSecret::new);
        Self::from_values(Some(&base_url), timeout, cert_path, key_path, token)
    }

    /// The audience every run-face service token must carry. Exposed so the
    /// future IdP/dev token minting path validates against the same constant
    /// the transport was built for.
    pub fn run_face_audience() -> &'static str {
        RUN_FACE_SCOPE_AUDIENCE
    }

    fn base(&self) -> Result<&Url, RunFaceConfigError> {
        self.base_url.as_ref().ok_or(RunFaceConfigError::InvalidBaseUrl)
    }
}

/// One JSON exchange over the run face: status plus the raw body bytes. The
/// caller (the input downlink adapter) owns domain mapping of the ACP error
/// envelope. Deliberately not `Debug`: bodies carry workspace data.
pub struct RunFaceJsonResponse {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

/// An open object stream over the run face. Callers pull chunks with
/// [`RunFaceObjectStream::next_chunk`] and must drain or drop the stream;
/// `bytes_read` tracks the consumed total against the configured cap.
pub struct RunFaceObjectStream {
    response: reqwest::Response,
    bytes_read: u64,
    max_object_bytes: u64,
}

impl RunFaceObjectStream {
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, RunFaceTransportError> {
        let Some(chunk) = self
            .response
            .chunk()
            .await
            .map_err(|_| RunFaceTransportError::Unavailable)?
        else {
            return Ok(None);
        };
        self.bytes_read += chunk.len() as u64;
        if self.bytes_read > self.max_object_bytes {
            return Err(RunFaceTransportError::ObjectTooLarge);
        }
        Ok(Some(chunk.to_vec()))
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
}

#[derive(Debug, Error)]
pub enum RunFaceTransportError {
    #[error("run-face request failed before a response arrived")]
    Unavailable,
    #[error("run-face object stream exceeded the configured byte cap")]
    ObjectTooLarge,
    #[error("run-face object key is not a safe request path: {0}")]
    InvalidObjectKey(String),
}

/// The machine client for the ACP run face. Construction loads and parses
/// the PEM identity eagerly, so a deployment with unusable material fails at
/// startup rather than on the first run.
pub struct RunFaceClient {
    base_url: Url,
    http: reqwest::Client,
    bearer_token: AuthCenterTokenSecret,
    max_object_bytes: u64,
}

impl RunFaceClient {
    pub fn new(config: RunFaceClientConfig) -> Result<Self, RunFaceConfigError> {
        let cert = std::fs::read(
            config
                .client_cert_pem_path
                .as_ref()
                .ok_or(RunFaceConfigError::MissingClientCert)?,
        )
        .map_err(|error| RunFaceConfigError::IdentityUnusable(error.to_string()))?;
        let key = std::fs::read(
            config
                .client_key_pem_path
                .as_ref()
                .ok_or(RunFaceConfigError::MissingClientKey)?,
        )
        .map_err(|error| RunFaceConfigError::IdentityUnusable(error.to_string()))?;
        // reqwest's rustls backend exposes no two-file constructor
        // (`from_pkcs8_pem` is native-tls-only); `from_pem` accepts one
        // combined buffer with the certificate and key in any section order.
        let mut identity_pem = cert;
        identity_pem.extend_from_slice(&key);
        let identity = reqwest::Identity::from_pem(&identity_pem)
            .map_err(|error| RunFaceConfigError::IdentityUnusable(error.to_string()))?;
        let base_url = config.base().cloned()?;
        let http = reqwest::Client::builder()
            .identity(identity)
            .connect_timeout(config.timeout)
            .build()
            .map_err(|error| RunFaceConfigError::IdentityUnusable(error.to_string()))?;
        Ok(Self {
            base_url,
            http,
            bearer_token: config.bearer_token.ok_or(RunFaceConfigError::MissingBearerToken)?,
            max_object_bytes: config.max_object_bytes,
        })
    }

    fn run_admission_url(&self, run_admission_id: &str, suffix: &str) -> Result<Url, RunFaceTransportError> {
        let mut url = self.base_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| RunFaceTransportError::Unavailable)?;
            segments.pop_if_empty();
            segments.push("api");
            segments.push("team-workspace");
            segments.push("v1");
            segments.push("run-admissions");
            segments.push(run_admission_id);
            for segment in suffix.split('/') {
                segments.push(segment);
            }
        }
        Ok(url)
    }

    /// Build the object URL from a member content id that may carry path
    /// separators (`documents/input.txt`). Every segment is validated — a
    /// key that could escape the fixed route prefix is rejected instead of
    /// URL-tricksed.
    fn input_object_url(&self, run_admission_id: &str, object_key: &str) -> Result<Url, RunFaceTransportError> {
        for segment in object_key.split('/') {
            let safe = !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.len() <= 255
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
            if !safe {
                return Err(RunFaceTransportError::InvalidObjectKey(object_key.to_owned()));
            }
        }
        self.run_admission_url(run_admission_id, "input-objects")
            .map(|mut url| {
                if let Ok(mut segments) = url.path_segments_mut() {
                    for segment in object_key.split('/') {
                        segments.push(segment);
                    }
                }
                url
            })
    }

    fn authorize(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        builder.bearer_auth(self.bearer_token.expose())
    }

    /// GET the admission's pinned input manifest as a JSON exchange.
    pub async fn fetch_input_manifest(
        &self,
        run_admission_id: &str,
    ) -> Result<RunFaceJsonResponse, RunFaceTransportError> {
        if run_admission_id.is_empty() || run_admission_id.len() > 255 {
            return Err(RunFaceTransportError::InvalidObjectKey(run_admission_id.to_owned()));
        }
        let url = self.run_admission_url(run_admission_id, "input-manifest")?;
        let response = self
            .authorize(self.http.get(url))
            .send()
            .await
            .map_err(|_| RunFaceTransportError::Unavailable)?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|_| RunFaceTransportError::Unavailable)?
            .to_vec();
        Ok(RunFaceJsonResponse { status, body })
    }

    /// Open the object stream for one manifest member. The response status is
    /// carried on the stream: only a 200 response yields a drainable stream,
    /// every other status is surfaced as a JSON-shaped rejection with the
    /// ACP error envelope body.
    pub async fn open_input_object(
        &self,
        run_admission_id: &str,
        object_key: &str,
    ) -> Result<Result<RunFaceObjectStream, RunFaceJsonResponse>, RunFaceTransportError> {
        let url = self.input_object_url(run_admission_id, object_key)?;
        let response = self
            .authorize(self.http.get(url))
            .send()
            .await
            .map_err(|_| RunFaceTransportError::Unavailable)?;
        let status = response.status();
        if status != StatusCode::OK {
            let body = response
                .bytes()
                .await
                .map_err(|_| RunFaceTransportError::Unavailable)?
                .to_vec();
            return Ok(Err(RunFaceJsonResponse { status, body }));
        }
        Ok(Ok(RunFaceObjectStream {
            response,
            bytes_read: 0,
            max_object_bytes: self.max_object_bytes,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use super::*;

    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    const RUN_FACE_ENV_KEYS: [&str; 5] = [
        "RSM_RUN_FACE_BASE_URL",
        "RSM_RUN_FACE_TIMEOUT_MS",
        "RSM_RUN_FACE_CLIENT_CERT_FILE",
        "RSM_RUN_FACE_CLIENT_KEY_FILE",
        "RSM_RUN_FACE_BEARER_TOKEN",
    ];

    /// Throwaway self-signed P-256 pair (CN=acp-run-face-test, 30 days at
    /// generation time) — a test fixture, never a deployed credential.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBjjCCATOgAwIBAgIUSz4tKqjUkcLsovajU6e8gqUsXu4wCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRYWNwLXJ1bi1mYWNlLXRlc3QwHhcNMjYwOTEzMTA0NjQ1WhcN
MjYxMDEzMTA0NjQ1WjAcMRowGAYDVQQDDBFhY3AtcnVuLWZhY2UtdGVzdDBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABOHvh54Ujgq+QpY3WxkBikSuSX7/DPYhStIe
j5eJlUxINuOjrMVSwr+UxMLGY/vGJCHaG2tGTum+XIg5TORAeVejUzBRMB0GA1Ud
DgQWBBRiNeb8UXIQCWUyCnqn3rsUo1NNeTAfBgNVHSMEGDAWgBRiNeb8UXIQCWUy
Cnqn3rsUo1NNeTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCC
i1OICKkWHw2mdCkr7TdPsbqXg0bu0hJzB7edgh4u/QIhAIFfWtRwWmTwa4FY3HOb
8qtzyX+wyLQzlp+41nnSVU5p
-----END CERTIFICATE-----
";
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg17H34anO9IM1rpez
3uZPv12dEXWkFW0PGdmcI2/ZHC2hRANCAATh74eeFI4KvkKWN1sZAYpErkl+/wz2
IUrSHo+XiZVMSDbjo6zFUsK/lMTCxmP7xiQh2htrRk7pvlyIOUzkQHlX
-----END PRIVATE KEY-----
";

    struct EnvRestore(Vec<(&'static str, Option<String>)>);

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for name in RUN_FACE_ENV_KEYS {
                remove_env(name);
            }
            for (name, value) in &self.0 {
                if let Some(value) = value {
                    set_env(name, value);
                }
            }
        }
    }

    fn remove_env(name: &str) {
        // SAFETY: tests call this only while holding ENV_MUTEX, serializing
        // process-global environment mutations in this module.
        unsafe { std::env::remove_var(name) };
    }

    fn set_env(name: &str, value: &str) {
        // SAFETY: tests call this only while holding ENV_MUTEX, serializing
        // process-global environment mutations in this module.
        unsafe { std::env::set_var(name, value) };
    }

    fn with_run_face_env<R>(values: &[(&str, &str)], test: impl FnOnce() -> R) -> R {
        let _guard = ENV_MUTEX.get_or_init(|| Mutex::new(())).lock().unwrap();
        let previous = RUN_FACE_ENV_KEYS
            .iter()
            .map(|name| (*name, std::env::var(name).ok()))
            .collect::<Vec<_>>();
        for name in RUN_FACE_ENV_KEYS {
            remove_env(name);
        }
        for (name, value) in values {
            set_env(name, value);
        }
        let _restore = EnvRestore(previous);
        test()
    }

    fn write_test_identity(dir: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        let cert = dir.path().join("client-cert.pem");
        let key = dir.path().join("client-key.pem");
        std::fs::write(&cert, TEST_CERT_PEM).unwrap();
        std::fs::write(&key, TEST_KEY_PEM).unwrap();
        (cert, key)
    }

    fn enabled_config() -> (RunFaceClientConfig, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_test_identity(&dir);
        let config = RunFaceClientConfig::new_with_material(
            "https://acp.example/internal",
            Duration::from_secs(1),
            cert,
            key,
            AuthCenterTokenSecret::new("run-face-token"),
        )
        .unwrap();
        (config, dir)
    }

    #[test]
    fn unset_base_url_disables_the_client() {
        with_run_face_env(&[], || {
            let config = RunFaceClientConfig::from_env().unwrap();
            assert!(config.base_url.is_none());
            assert_eq!(config.max_object_bytes(), MAX_OBJECT_BYTES);
        });
    }

    #[test]
    fn enabled_client_requires_full_identity_material() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_test_identity(&dir);
        let token = AuthCenterTokenSecret::new("run-face-token");
        assert!(matches!(
            RunFaceClientConfig::new_with_material(
                "https://acp.example",
                Duration::from_secs(1),
                PathBuf::new(),
                key.clone(),
                token.clone()
            ),
            Err(RunFaceConfigError::MissingClientCert)
        ));
        assert!(matches!(
            RunFaceClientConfig::new_with_material(
                "https://acp.example",
                Duration::from_secs(1),
                cert.clone(),
                PathBuf::new(),
                token.clone()
            ),
            Err(RunFaceConfigError::MissingClientKey)
        ));
        assert!(matches!(
            RunFaceClientConfig::new_with_material(
                "https://acp.example",
                Duration::from_secs(1),
                cert.clone(),
                key.clone(),
                AuthCenterTokenSecret::new(String::new())
            ),
            Err(RunFaceConfigError::MissingBearerToken)
        ));
        assert!(
            RunFaceClientConfig::new_with_material("https://acp.example", Duration::from_secs(1), cert, key, token)
                .is_ok()
        );
    }

    #[test]
    fn enabled_client_rejects_missing_identity_files() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.pem");
        assert!(matches!(
            RunFaceClientConfig::new_with_material(
                "https://acp.example",
                Duration::from_secs(1),
                missing.clone(),
                dir.path().join("absent-key.pem"),
                AuthCenterTokenSecret::new("t")
            ),
            Err(RunFaceConfigError::IdentityUnusable(_))
        ));
    }

    #[test]
    fn config_rejects_non_http_and_component_bearing_base_urls() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_test_identity(&dir);
        let token = || AuthCenterTokenSecret::new("run-face-token");
        assert!(matches!(
            RunFaceClientConfig::new_with_material(
                "file:///tmp/acp",
                Duration::from_secs(1),
                cert.clone(),
                key.clone(),
                token()
            ),
            Err(RunFaceConfigError::InvalidScheme)
        ));
        assert!(matches!(
            RunFaceClientConfig::new_with_material(
                "https://acp.example/?secret=value",
                Duration::from_secs(1),
                cert.clone(),
                key.clone(),
                token()
            ),
            Err(RunFaceConfigError::InvalidBaseUrlComponents)
        ));
        assert!(matches!(
            RunFaceClientConfig::new_with_material(
                "https://user:pass@acp.example",
                Duration::from_secs(1),
                cert,
                key,
                token()
            ),
            Err(RunFaceConfigError::InvalidBaseUrlComponents)
        ));
    }

    #[test]
    fn env_config_loads_material_paths_and_trims_values() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_test_identity(&dir);
        with_run_face_env(
            &[
                ("RSM_RUN_FACE_BASE_URL", " https://acp.example/internal "),
                ("RSM_RUN_FACE_TIMEOUT_MS", "2500"),
                ("RSM_RUN_FACE_CLIENT_CERT_FILE", cert.to_str().unwrap()),
                ("RSM_RUN_FACE_CLIENT_KEY_FILE", key.to_str().unwrap()),
                ("RSM_RUN_FACE_BEARER_TOKEN", " run-face-token "),
            ],
            || {
                let config = RunFaceClientConfig::from_env().unwrap();
                assert_eq!(config.timeout, Duration::from_millis(2500));
                assert_eq!(
                    config.base_url.as_ref().unwrap().as_str(),
                    "https://acp.example/internal/"
                );
                assert_eq!(config.client_cert_pem_path.as_ref().unwrap(), &cert);
                assert_eq!(config.client_key_pem_path.as_ref().unwrap(), &key);
            },
        );
    }

    #[test]
    fn construction_rejects_unusable_identity_pem_and_missing_token_is_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let garbage = dir.path().join("garbage.pem");
        std::fs::write(&garbage, "not a pem").unwrap();
        let config = RunFaceClientConfig::new_with_material(
            "https://acp.example",
            Duration::from_secs(1),
            garbage.clone(),
            garbage,
            AuthCenterTokenSecret::new("run-face-token"),
        )
        .unwrap();
        assert!(matches!(
            RunFaceClient::new(config),
            Err(RunFaceConfigError::IdentityUnusable(_))
        ));
        assert_eq!(
            RunFaceClientConfig::run_face_audience(),
            "agent-control-plane:run-authority"
        );
    }

    #[tokio::test]
    async fn manifest_and_object_routes_are_exact_and_token_is_presented() {
        let seen = std::sync::Arc::new(Mutex::new(Vec::<(String, Option<String>)>::new()));
        let seen_for_manifest = seen.clone();
        let app = axum::Router::new().route(
            "/internal/api/team-workspace/v1/run-admissions/admission-1/input-manifest",
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let seen = seen_for_manifest.clone();
                async move {
                    seen.lock().unwrap().push((
                        "manifest".to_owned(),
                        headers
                            .get(axum::http::header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok().map(str::to_owned)),
                    ));
                    axum::Json(serde_json::json!({
                        "admission": {"run_admission_id": "admission-1"},
                        "input_manifest": {
                            "manifest_format": "rsm.workspace.manifest.v1",
                            "members": [],
                            "manifest_sha256": "b".repeat(64)
                        }
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // Point a fresh client at the loopback server.
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_test_identity(&dir);
        let loopback = RunFaceClient::new(
            RunFaceClientConfig::new_with_material(
                format!("http://{addr}/internal"),
                Duration::from_secs(2),
                cert,
                key,
                AuthCenterTokenSecret::new("run-face-token"),
            )
            .unwrap(),
        )
        .unwrap();

        let response = match loopback.fetch_input_manifest("admission-1").await {
            Ok(response) => response,
            Err(error) => panic!("manifest fetch failed: {error}"),
        };
        assert_eq!(response.status, StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["admission"]["run_admission_id"], "admission-1");
        assert_eq!(body["input_manifest"]["manifest_format"], "rsm.workspace.manifest.v1");

        let seen_manifest = seen.lock().unwrap().remove(0);
        assert_eq!(seen_manifest.0, "manifest");
        assert_eq!(seen_manifest.1.as_deref(), Some("Bearer run-face-token"));

        server.abort();
    }

    #[tokio::test]
    async fn object_stream_drains_chunks_and_non_ok_status_carries_envelope() {
        let app = axum::Router::new()
            .route(
                "/internal/api/team-workspace/v1/run-admissions/admission-1/input-objects/documents/input.txt",
                axum::routing::get(|| async { "input-bytes" }),
            )
            .route(
                "/internal/api/team-workspace/v1/run-admissions/admission-1/input-objects/documents/missing.txt",
                axum::routing::get(|| async {
                    (
                        axum::http::StatusCode::NOT_FOUND,
                        axum::Json(serde_json::json!({"code": "object_not_in_input_manifest"})),
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_test_identity(&dir);
        let loopback = RunFaceClient::new(
            RunFaceClientConfig::new_with_material(
                format!("http://{addr}/internal"),
                Duration::from_secs(2),
                cert,
                key,
                AuthCenterTokenSecret::new("run-face-token"),
            )
            .unwrap(),
        )
        .unwrap();

        let Ok(Ok(mut stream)) = loopback.open_input_object("admission-1", "documents/input.txt").await else {
            panic!("expected open object stream");
        };
        let mut body = Vec::new();
        while let Some(chunk) = stream.next_chunk().await.unwrap() {
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, b"input-bytes");
        assert_eq!(stream.bytes_read(), 11);

        let Ok(Err(rejected)) = loopback.open_input_object("admission-1", "documents/missing.txt").await else {
            panic!("expected object rejection");
        };
        assert_eq!(rejected.status, StatusCode::NOT_FOUND);
        let envelope: serde_json::Value = serde_json::from_slice(&rejected.body).unwrap();
        assert_eq!(envelope["code"], "object_not_in_input_manifest");

        server.abort();
    }

    #[tokio::test]
    async fn object_keys_are_validated_before_a_request_is_built() {
        let (config, _dir) = enabled_config();
        let client = RunFaceClient::new(config).unwrap();
        for invalid in [
            "",
            "..",
            "documents/../escape",
            "back\\slash",
            "%2e%2e",
            "documents//double",
        ] {
            assert!(
                matches!(
                    client.open_input_object("admission-1", invalid).await,
                    Err(RunFaceTransportError::InvalidObjectKey(_))
                ),
                "accepted {invalid:?}"
            );
        }
        // A valid multi-segment key resolves to the exact wire route.
        let url = client.input_object_url("admission-1", "documents/input.txt").unwrap();
        assert_eq!(
            url.as_str(),
            "https://acp.example/internal/api/team-workspace/v1/run-admissions/admission-1/input-objects/documents/input.txt"
        );
    }
}
