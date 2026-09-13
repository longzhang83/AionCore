//! Run input downlink port (T0-CORE-INPUT-DOWNLINK-CLIENT).
//!
//! The run executor consumes [`RunInputDownlink`] — a thin port over the
//! Agent Control Plane run-face input delivery — and never HTTP directly.
//! The port's contract mirrors the frozen ACP run-face wire shape: one
//! admission, one pinned input manifest, and manifest-member objects whose
//! plaintext identity (`PlaintextSHA256` + size) is verified while the bytes
//! stream in, using the same 64 KB chunk-hashing discipline as `run_dir.rs`.
//! A member that fails verification never reaches the run dir under its
//! final name: the write lands in a `.part` sibling that is renamed only
//! after the digest and size both check out.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The pinned plaintext identity of one manifest member (ACP wire shape,
/// snake_case field names verbatim).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RunContentIdentity {
    pub content_id: String,
    pub plaintext_sha256: String,
    pub plaintext_size: i64,
}

/// One member of the admission's pinned input manifest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RunInputManifestMember {
    pub resource_path: String,
    pub content: RunContentIdentity,
}

/// The admission's pinned input manifest (`GET .../input-manifest` response
/// body's `input_manifest` field, verbatim ACP wire shape).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RunInputManifest {
    pub manifest_format: String,
    pub members: Vec<RunInputManifestMember>,
    pub manifest_sha256: String,
}

/// Domain errors for the input downlink. Wire rejections keep the ACP error
/// envelope's code so callers can distinguish fixable from fatal classes.
#[derive(Debug, Error)]
pub enum RunInputDownlinkError {
    #[error("run input request was rejected: {status} {code}")]
    Rejected { status: u16, code: String },
    #[error("run input transport failed")]
    Unavailable,
    #[error("input manifest response is not well-formed")]
    InvalidManifest,
    #[error("input object stream ended before the pinned size")]
    ObjectSizeMismatch,
    #[error("input object stream exceeded the pinned size")]
    ObjectSizeExceeded,
    #[error("input object digest mismatch")]
    ObjectDigestMismatch,
    #[error("input object destination is not writable")]
    DestinationUnwritable,
    #[error("input manifest member resource path is unsafe: {0}")]
    UnsafeResourcePath(String),
}

/// The result of one verified input-object fetch: bytes written to
/// `destination` and the hex SHA-256 that was verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInputObjectReceipt {
    pub bytes_written: u64,
    pub plaintext_sha256: String,
}

/// The run input downlink port. Implementations own the transport (HTTP +
/// mTLS identity in production) and must present objects that match the
/// member's pinned plaintext identity; verification helpers in this module
/// exist so implementations share one audited discipline.
#[async_trait]
pub trait RunInputDownlink: Send + Sync {
    async fn fetch_input_manifest(&self, run_admission_id: &str) -> Result<RunInputManifest, RunInputDownlinkError>;

    /// Stream one manifest member's object into `destination`, verifying the
    /// member's pinned `PlaintextSHA256` and size while the bytes arrive.
    async fn fetch_input_object(
        &self,
        run_admission_id: &str,
        member: &RunInputManifestMember,
        destination: &Path,
    ) -> Result<RunInputObjectReceipt, RunInputDownlinkError>;
}

/// Streaming verifier for one input object: chunked SHA-256 over a `.part`
/// sibling of `destination`, atomic rename only after the pinned digest and
/// size both check out. Size is enforced during streaming (early abort on
/// overrun) and again at finish (truncated stream).
pub struct VerifiedObjectWriter {
    file: tokio::fs::File,
    hasher: Sha256,
    temp_path: PathBuf,
    destination: PathBuf,
    total: u64,
    expected_size: u64,
    expected_digest: String,
}

impl VerifiedObjectWriter {
    /// Create the `.part` writer for one member's destination.
    pub async fn create(destination: &Path, expected: &RunContentIdentity) -> Result<Self, RunInputDownlinkError> {
        if expected.plaintext_size < 0 {
            return Err(RunInputDownlinkError::InvalidManifest);
        }
        let Some(file_name) = destination.file_name() else {
            return Err(RunInputDownlinkError::DestinationUnwritable);
        };
        let mut part_name = file_name.to_os_string();
        part_name.push(".part");
        let temp_path = destination.with_file_name(part_name);
        let file = tokio::fs::File::create(&temp_path)
            .await
            .map_err(|_| RunInputDownlinkError::DestinationUnwritable)?;
        Ok(Self {
            file,
            hasher: Sha256::new(),
            temp_path,
            destination: destination.to_path_buf(),
            total: 0,
            expected_size: expected.plaintext_size as u64,
            expected_digest: expected.plaintext_sha256.clone(),
        })
    }

    /// Absorb one streamed chunk. Aborts early once the pinned size would be
    /// exceeded — a stream that keeps going past the manifest's own identity
    /// is already wrong; waiting for EOF would only burn the run's budget.
    pub async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), RunInputDownlinkError> {
        let new_total = self.total + chunk.len() as u64;
        if new_total > self.expected_size {
            return Err(RunInputDownlinkError::ObjectSizeExceeded);
        }
        use tokio::io::AsyncWriteExt;
        self.file
            .write_all(chunk)
            .await
            .map_err(|_| RunInputDownlinkError::DestinationUnwritable)?;
        self.hasher.update(chunk);
        self.total = new_total;
        Ok(())
    }

    /// Finish the stream: verify digest and size, then atomically rename the
    /// `.part` file onto its destination. Any failure removes the `.part`
    /// file — a partially streamed member never appears under its final name.
    pub async fn finish(mut self) -> Result<RunInputObjectReceipt, RunInputDownlinkError> {
        use tokio::io::AsyncWriteExt;
        let outcome = async {
            self.file
                .flush()
                .await
                .map_err(|_| RunInputDownlinkError::DestinationUnwritable)?;
            if self.total != self.expected_size {
                return Err(if self.total < self.expected_size {
                    RunInputDownlinkError::ObjectSizeMismatch
                } else {
                    RunInputDownlinkError::ObjectSizeExceeded
                });
            }
            let digest = hex::encode(self.hasher.finalize());
            if digest != self.expected_digest {
                return Err(RunInputDownlinkError::ObjectDigestMismatch);
            }
            tokio::fs::rename(&self.temp_path, &self.destination)
                .await
                .map_err(|_| RunInputDownlinkError::DestinationUnwritable)?;
            Ok(RunInputObjectReceipt {
                bytes_written: self.total,
                plaintext_sha256: digest,
            })
        }
        .await;
        if outcome.is_err() {
            let _ = tokio::fs::remove_file(&self.temp_path).await;
        }
        outcome
    }
}

/// Validate a manifest member's resource path before materializing it under
/// the run dir. Members are admission-scoped on the ACP side, but the path
/// still ends up joined under a local directory: reject absolute paths,
/// traversal segments, backslashes, and NUL bytes outright.
pub fn validate_member_resource_path(path: &str) -> Result<(), RunInputDownlinkError> {
    let invalid = || RunInputDownlinkError::UnsafeResourcePath(path.to_owned());
    if path.is_empty() || path.len() > 255 || path.contains('\0') || path.contains('\\') {
        return Err(invalid());
    }
    if Path::new(path).is_absolute()
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn identity(size: i64, digest: &str) -> RunContentIdentity {
        RunContentIdentity {
            content_id: "documents/input.txt".to_owned(),
            plaintext_sha256: digest.to_owned(),
            plaintext_size: size,
        }
    }

    /// The frozen ACP wire shape for the input-manifest delivery response —
    /// deserialization must accept it exactly as the ACP serves it.
    #[test]
    fn input_manifest_parses_acp_wire_shape() {
        let raw = r#"{
            "manifest_format": "rsm.workspace.manifest.v1",
            "members": [
                {
                    "resource_path": "documents/input.txt",
                    "content": {
                        "content_id": "documents/input.txt",
                        "plaintext_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "plaintext_size": 11
                    }
                }
            ],
            "manifest_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }"#;
        let manifest: RunInputManifest = serde_json::from_str(raw).unwrap();
        assert_eq!(manifest.manifest_format, "rsm.workspace.manifest.v1");
        assert_eq!(manifest.members.len(), 1);
        assert_eq!(manifest.members[0].resource_path, "documents/input.txt");
        assert_eq!(manifest.members[0].content.content_id, "documents/input.txt");
        assert_eq!(manifest.members[0].content.plaintext_size, 11);
        assert_eq!(
            manifest.manifest_sha256,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[tokio::test]
    async fn verified_writer_accepts_matching_stream_and_renames_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("input.txt");
        let body = b"input-bytes";
        let digest = {
            let mut hasher = Sha256::new();
            hasher.update(body);
            hex::encode(hasher.finalize())
        };
        let expected = identity(body.len() as i64, &digest);
        let mut writer = VerifiedObjectWriter::create(&destination, &expected).await.unwrap();
        writer.write_chunk(body).await.unwrap();
        writer.write_chunk(b"").await.unwrap();
        let receipt = writer.finish().await.unwrap();
        assert_eq!(receipt.bytes_written, body.len() as u64);
        assert_eq!(receipt.plaintext_sha256, digest);
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), body);
        assert!(
            !tokio::fs::try_exists(destination.with_file_name("input.txt.part"))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn verified_writer_rejects_digest_mismatch_and_removes_part_file() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("input.txt");
        let expected = identity(11, SHA_A);
        let mut writer = VerifiedObjectWriter::create(&destination, &expected).await.unwrap();
        writer.write_chunk(b"input-bytes").await.unwrap();
        assert!(matches!(
            writer.finish().await,
            Err(RunInputDownlinkError::ObjectDigestMismatch)
        ));
        assert!(!tokio::fs::try_exists(&destination).await.unwrap());
        assert!(!tokio::fs::try_exists(dir.path().join("input.txt.part")).await.unwrap());
    }

    #[tokio::test]
    async fn verified_writer_aborts_early_on_size_overrun() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("input.txt");
        let expected = identity(4, SHA_A);
        let mut writer = VerifiedObjectWriter::create(&destination, &expected).await.unwrap();
        writer.write_chunk(b"inpu").await.unwrap();
        assert!(matches!(
            writer.write_chunk(b"t-bytes").await,
            Err(RunInputDownlinkError::ObjectSizeExceeded)
        ));
        drop(writer);
        assert!(!tokio::fs::try_exists(&destination).await.unwrap());
    }

    #[tokio::test]
    async fn verified_writer_rejects_truncated_stream() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("input.txt");
        let expected = identity(11, SHA_A);
        let mut writer = VerifiedObjectWriter::create(&destination, &expected).await.unwrap();
        writer.write_chunk(b"input").await.unwrap();
        assert!(matches!(
            writer.finish().await,
            Err(RunInputDownlinkError::ObjectSizeMismatch)
        ));
        assert!(!tokio::fs::try_exists(&destination).await.unwrap());
    }

    #[tokio::test]
    async fn verified_writer_accepts_empty_content_service_object() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("service.txt");
        let digest = {
            let mut hasher = Sha256::new();
            hasher.update(b"");
            hex::encode(hasher.finalize())
        };
        let expected = identity(0, &digest);
        let writer = VerifiedObjectWriter::create(&destination, &expected).await.unwrap();
        let receipt = writer.finish().await.unwrap();
        assert_eq!(receipt.bytes_written, 0);
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn resource_path_validation_rejects_traversal_and_accepts_plain_members() {
        for valid in ["documents/input.txt", "notes.md", "a/b/c/data.json"] {
            assert!(validate_member_resource_path(valid).is_ok(), "rejected {valid:?}");
        }
        for invalid in [
            "",
            "/absolute/path",
            "../escape.txt",
            "documents/../escape.txt",
            "documents//double",
            "documents/./here",
            "back\\slash.txt",
            "nul\0byte",
        ] {
            assert!(
                matches!(
                    validate_member_resource_path(invalid),
                    Err(RunInputDownlinkError::UnsafeResourcePath(_))
                ),
                "accepted {invalid:?}"
            );
        }
    }
}
