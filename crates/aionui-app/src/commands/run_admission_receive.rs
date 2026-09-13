//! Run admission receive face assembly (T0-ACP-ADMISSION-DELIVERY Slice B2b).
//!
//! The face is **opt-in and fail-closed**: it is wired only when
//! `RSM_CORE_RUN_ADMISSION_RECEIVE_BIND` is set, and setting it makes the rest
//! of the env family (`_TLS_CERT_FILE`, `_TLS_KEY_FILE`, `_CLIENT_CA_FILE`,
//! `_ACP_ISSUER_URL`) mandatory — a partial family is a startup failure that
//! names every missing variable, never a silently half-wired listener. The
//! service-token verifier is built without the development-only insecure-HTTP
//! flag, so the ACP issuer must be an `https://` URL.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use aionui_app::AppServices;
use aionui_auth::{AcpServiceTokenConfig, AcpServiceTokenVerifier};
use aionui_conversation::run_admission_listener::{build_mtls_server_config, spawn_run_admission_listener};
use aionui_conversation::run_admission_receive::{RunAdmissionReceiveState, run_admission_receive_router};
use aionui_db::SqliteRunAdmissionRepository;
use tokio::net::TcpListener;
use tracing::info;

use crate::bootstrap::{BootstrapError, BootstrapErrorCode};

pub(crate) const ENV_BIND: &str = "RSM_CORE_RUN_ADMISSION_RECEIVE_BIND";
pub(crate) const ENV_TLS_CERT_FILE: &str = "RSM_CORE_RUN_ADMISSION_RECEIVE_TLS_CERT_FILE";
pub(crate) const ENV_TLS_KEY_FILE: &str = "RSM_CORE_RUN_ADMISSION_RECEIVE_TLS_KEY_FILE";
pub(crate) const ENV_CLIENT_CA_FILE: &str = "RSM_CORE_RUN_ADMISSION_RECEIVE_CLIENT_CA_FILE";
pub(crate) const ENV_ACP_ISSUER_URL: &str = "RSM_CORE_RUN_ADMISSION_RECEIVE_ACP_ISSUER_URL";

const CONFIG_STAGE: &str = "run_admission_receive.config";
const BIND_STAGE: &str = "bind.run_admission_receive";

/// Fully resolved receive-face settings. Exists only for a complete env
/// family; there is no partially-populated state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunAdmissionReceiveSettings {
    bind: SocketAddr,
    tls_cert_file: PathBuf,
    tls_key_file: PathBuf,
    client_ca_file: PathBuf,
    acp_issuer_url: String,
}

fn is_blank(value: Option<String>) -> bool {
    value.is_none_or(|v| v.trim().is_empty())
}

fn config_invalid(message: &'static str) -> BootstrapError {
    BootstrapError::new(BootstrapErrorCode::ConfigInvalid, CONFIG_STAGE, message)
}

/// Resolves the receive-face env family. Returns `Ok(None)` when the face is
/// not enabled (BIND unset); any enabled-but-incomplete family is a
/// `ConfigInvalid` startup failure naming every missing variable.
pub(crate) fn resolve_run_admission_receive_settings(
    getenv: impl Fn(&str) -> Option<String>,
) -> Result<Option<RunAdmissionReceiveSettings>, BootstrapError> {
    let bind_raw = match getenv(ENV_BIND) {
        None => return Ok(None),
        Some(raw) if raw.trim().is_empty() => {
            return Err(
                config_invalid("run admission receive bind address is set but empty").with_field("env", ENV_BIND)
            );
        }
        Some(raw) => raw,
    };

    let mut missing: Vec<&'static str> = Vec::new();
    for name in [
        ENV_TLS_CERT_FILE,
        ENV_TLS_KEY_FILE,
        ENV_CLIENT_CA_FILE,
        ENV_ACP_ISSUER_URL,
    ] {
        if is_blank(getenv(name)) {
            missing.push(name);
        }
    }
    if !missing.is_empty() {
        return Err(config_invalid(
            "run admission receive face is enabled but required environment variables are missing",
        )
        .with_field("missing", missing.join(",")));
    }

    // Unwrap is safe: `missing` is empty, so every required variable is
    // present and non-blank.
    let tls_cert_file = PathBuf::from(getenv(ENV_TLS_CERT_FILE).expect("checked above"));
    let tls_key_file = PathBuf::from(getenv(ENV_TLS_KEY_FILE).expect("checked above"));
    let client_ca_file = PathBuf::from(getenv(ENV_CLIENT_CA_FILE).expect("checked above"));
    let acp_issuer_url = getenv(ENV_ACP_ISSUER_URL).expect("checked above");
    let bind = bind_raw.parse::<SocketAddr>().map_err(|_| {
        config_invalid("run admission receive bind address is not a valid socket address")
            .with_field("env", ENV_BIND)
            .with_field("value", bind_raw)
    })?;

    Ok(Some(RunAdmissionReceiveSettings {
        bind,
        tls_cert_file,
        tls_key_file,
        client_ca_file,
        acp_issuer_url,
    }))
}

/// Thin wrapper over [`resolve_run_admission_receive_settings`] reading the
/// process environment.
pub(crate) fn resolve_run_admission_receive_settings_from_env()
-> Result<Option<RunAdmissionReceiveSettings>, BootstrapError> {
    resolve_run_admission_receive_settings(|name| std::env::var(name).ok())
}

fn read_pem_file(path: &PathBuf, env_name: &'static str) -> Result<Vec<u8>, BootstrapError> {
    std::fs::read(path).map_err(|error| {
        config_invalid("run admission receive TLS material file could not be read")
            .with_field("env", env_name)
            .with_field("source", error.to_string())
    })
}

/// Resolves, builds and starts the receive face. `Ok(())` with the face not
/// configured is the normal unwired state; every configuration or material
/// failure aborts server startup.
pub(crate) async fn start_run_admission_receive_face(services: &AppServices) -> Result<(), BootstrapError> {
    let settings = match resolve_run_admission_receive_settings_from_env()? {
        Some(settings) => settings,
        None => {
            info!("run admission receive face not configured; not wired");
            return Ok(());
        }
    };

    // No `allow_insecure_http`: the production ACP issuer must be https.
    let token_config = AcpServiceTokenConfig::new(&settings.acp_issuer_url).map_err(|error| {
        config_invalid("run admission receive ACP issuer URL is invalid")
            .with_field("env", ENV_ACP_ISSUER_URL)
            .with_source(error)
    })?;
    let verifier = AcpServiceTokenVerifier::new(token_config).map_err(|error| {
        config_invalid("run admission receive service-token verifier could not be built")
            .with_field("env", ENV_ACP_ISSUER_URL)
            .with_source(error)
    })?;

    let cert_pem = read_pem_file(&settings.tls_cert_file, ENV_TLS_CERT_FILE)?;
    let key_pem = read_pem_file(&settings.tls_key_file, ENV_TLS_KEY_FILE)?;
    let client_ca_pem = read_pem_file(&settings.client_ca_file, ENV_CLIENT_CA_FILE)?;
    let tls = build_mtls_server_config(&cert_pem, &key_pem, &client_ca_pem).map_err(|error| {
        config_invalid("run admission receive mTLS configuration could not be built").with_source(error)
    })?;

    let repository = Arc::new(SqliteRunAdmissionRepository::new(services.database.pool().clone()));
    let router = run_admission_receive_router(RunAdmissionReceiveState { verifier, repository });

    let listener = TcpListener::bind(settings.bind).await.map_err(|error| {
        BootstrapError::new(
            BootstrapErrorCode::BindFailed,
            BIND_STAGE,
            "failed to bind run admission receive listener",
        )
        .with_source(error)
        .with_field("address", settings.bind.to_string())
    })?;
    spawn_run_admission_listener(listener, tls, router);
    info!(
        address = %settings.bind,
        "run admission receive face listening over mTLS"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn getenv_from(pairs: Vec<(&'static str, &'static str)>) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    }

    fn full_family() -> Vec<(&'static str, &'static str)> {
        vec![
            (ENV_BIND, "127.0.0.1:0"),
            (ENV_TLS_CERT_FILE, "/etc/aioncore/receive-tls.crt"),
            (ENV_TLS_KEY_FILE, "/etc/aioncore/receive-tls.key"),
            (ENV_CLIENT_CA_FILE, "/etc/aioncore/acp-client-ca.crt"),
            (ENV_ACP_ISSUER_URL, "https://auth.example.com"),
        ]
    }

    #[test]
    fn bind_unset_means_face_not_wired() {
        let resolved =
            resolve_run_admission_receive_settings(getenv_from(Vec::new())).expect("resolution should succeed");
        assert_eq!(resolved, None);
    }

    #[test]
    fn bind_set_but_empty_is_config_invalid() {
        let getenv = getenv_from(vec![(ENV_BIND, "   ")]);

        let error = resolve_run_admission_receive_settings(getenv).unwrap_err();

        assert_eq!(error.code(), BootstrapErrorCode::ConfigInvalid);
        assert_eq!(error.stage(), CONFIG_STAGE);
    }

    #[test]
    fn enabled_family_requires_every_variable_and_names_all_missing() {
        // Only BIND is set: all four remaining variables must be listed.
        let getenv = getenv_from(vec![(ENV_BIND, "127.0.0.1:0")]);

        let error = resolve_run_admission_receive_settings(getenv).unwrap_err();

        assert_eq!(error.code(), BootstrapErrorCode::ConfigInvalid);
        let stderr = error.stderr_line();
        for name in [
            ENV_TLS_CERT_FILE,
            ENV_TLS_KEY_FILE,
            ENV_CLIENT_CA_FILE,
            ENV_ACP_ISSUER_URL,
        ] {
            assert!(stderr.contains(name), "missing variable {name} must be named: {stderr}");
        }
        // Blank values count as missing too (no silent empty-string fallback).
        let getenv = getenv_from(vec![
            (ENV_BIND, "127.0.0.1:0"),
            (ENV_TLS_CERT_FILE, "cert.pem"),
            (ENV_TLS_KEY_FILE, "  "),
            (ENV_CLIENT_CA_FILE, "ca.pem"),
            (ENV_ACP_ISSUER_URL, "https://auth.example.com"),
        ]);
        let error = resolve_run_admission_receive_settings(getenv).unwrap_err();
        assert!(error.stderr_line().contains(ENV_TLS_KEY_FILE));
    }

    #[test]
    fn complete_family_resolves_all_settings() {
        let getenv = getenv_from(full_family());

        let resolved = resolve_run_admission_receive_settings(getenv).expect("complete family must resolve");

        let settings = resolved.expect("face is enabled");
        assert_eq!(settings.bind, "127.0.0.1:0".parse::<SocketAddr>().unwrap());
        assert_eq!(settings.tls_cert_file, PathBuf::from("/etc/aioncore/receive-tls.crt"));
        assert_eq!(settings.tls_key_file, PathBuf::from("/etc/aioncore/receive-tls.key"));
        assert_eq!(
            settings.client_ca_file,
            PathBuf::from("/etc/aioncore/acp-client-ca.crt")
        );
        assert_eq!(settings.acp_issuer_url, "https://auth.example.com");
    }

    #[test]
    fn unparseable_bind_address_is_config_invalid() {
        let mut family = full_family();
        family[0] = (ENV_BIND, "127.0.0.1:not-a-port");
        let getenv = getenv_from(family);

        let error = resolve_run_admission_receive_settings(getenv).unwrap_err();

        assert_eq!(error.code(), BootstrapErrorCode::ConfigInvalid);
        assert!(error.stderr_line().contains(ENV_BIND));
    }
}
