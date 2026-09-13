//! Run input materialization: manifest digest re-verification + member-driven
//! fetch into the run dir (T0-RUN-EXECUTOR Slice E1).
//!
//! This is the deferred production glue from T0-CORE-INPUT-DOWNLINK-CLIENT:
//! the composition of the [`RunInputDownlink`] port, the pinned manifest's
//! own canonicalization digest, and the [`VerifiedObjectWriter`] destination
//! wiring into a run directory. Fail-closed order:
//!
//! 1. the received manifest's `manifest_sha256` must equal the recomputed
//!    RFC 8785/JCS workspace-manifest digest (a tampered or mis-projected
//!    manifest never drives a single fetch);
//! 2. when the caller supplies the admission-bound base digest, the
//!    recomputed digest must also equal it — this is the anchor against a
//!    re-signed manifest from anywhere but the admission's issuance;
//! 3. duplicate member resource paths fail closed (an issuance integrity
//!    violation, and the digest projection would still "verify");
//! 4. members are fetched in manifest order, each into
//!    `input_dir/<resource_path>` through the verified writer — a member
//!    that fails digest/size verification never appears under its final
//!    name, and materialization stops at the first failed member.

use std::collections::HashSet;
use std::path::Path;

use thiserror::Error;

use crate::run_input_downlink::{
    RunInputDownlink, RunInputManifestMember, RunInputObjectReceipt, validate_member_resource_path,
};
use crate::run_manifest_digest::workspace_manifest_digest;

#[derive(Debug, Error)]
pub enum RunInputMaterializeError {
    #[error("input manifest digest does not match its canonical recomputation")]
    ManifestDigestMismatch,
    #[error("input manifest lists the same resource path more than once")]
    DuplicateResourcePath,
    #[error(transparent)]
    Downlink(#[from] crate::run_input_downlink::RunInputDownlinkError),
}

/// Verify `manifest` against its canonical digest (and, when provided, the
/// admission-bound base digest), then fetch every member into `input_dir` in
/// manifest order. Returns the per-member receipts paired with their members
/// in manifest order.
pub async fn materialize_run_input(
    downlink: &dyn RunInputDownlink,
    run_admission_id: &str,
    manifest: &crate::run_input_downlink::RunInputManifest,
    expected_manifest_sha256: Option<&str>,
    input_dir: &Path,
) -> Result<Vec<(RunInputManifestMember, RunInputObjectReceipt)>, RunInputMaterializeError> {
    let recomputed = workspace_manifest_digest(&manifest.manifest_format, &manifest.members);
    if recomputed != manifest.manifest_sha256 {
        return Err(RunInputMaterializeError::ManifestDigestMismatch);
    }
    if let Some(expected) = expected_manifest_sha256
        && recomputed != expected
    {
        return Err(RunInputMaterializeError::ManifestDigestMismatch);
    }

    let mut seen: HashSet<&str> = HashSet::with_capacity(manifest.members.len());
    for member in &manifest.members {
        if !seen.insert(member.resource_path.as_str()) {
            return Err(RunInputMaterializeError::DuplicateResourcePath);
        }
    }

    tokio::fs::create_dir_all(input_dir)
        .await
        .map_err(|_| crate::run_input_downlink::RunInputDownlinkError::DestinationUnwritable)?;

    let mut materialized = Vec::with_capacity(manifest.members.len());
    for member in &manifest.members {
        validate_member_resource_path(&member.resource_path)?;
        let destination = input_dir.join(&member.resource_path);
        // Defense in depth behind the path validation: the joined target
        // must stay inside the snapshot directory.
        if !destination.starts_with(input_dir) {
            return Err(crate::run_input_downlink::RunInputDownlinkError::UnsafeResourcePath(
                member.resource_path.clone(),
            )
            .into());
        }
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|_| crate::run_input_downlink::RunInputDownlinkError::DestinationUnwritable)?;
        }
        let receipt = downlink
            .fetch_input_object(run_admission_id, member, &destination)
            .await?;
        materialized.push((member.clone(), receipt));
    }
    Ok(materialized)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use sha2::Digest;

    use super::*;
    use crate::run_input_downlink::{RunContentIdentity, RunInputDownlinkError, RunInputManifest};

    struct FakeDownlink {
        bodies: Mutex<std::collections::HashMap<String, Vec<u8>>>,
        fetches: Mutex<Vec<String>>,
    }

    impl FakeDownlink {
        fn new(bodies: std::collections::HashMap<String, Vec<u8>>) -> Self {
            Self {
                bodies: Mutex::new(bodies),
                fetches: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl RunInputDownlink for FakeDownlink {
        async fn fetch_input_manifest(
            &self,
            _run_admission_id: &str,
        ) -> Result<RunInputManifest, RunInputDownlinkError> {
            unreachable!("materialization drives fetch_input_object, not the manifest fetch")
        }

        async fn fetch_input_object(
            &self,
            _run_admission_id: &str,
            member: &RunInputManifestMember,
            destination: &Path,
        ) -> Result<RunInputObjectReceipt, RunInputDownlinkError> {
            self.fetches.lock().unwrap().push(member.resource_path.clone());
            let identity = RunContentIdentity {
                content_id: member.content.content_id.clone(),
                plaintext_sha256: member.content.plaintext_sha256.clone(),
                plaintext_size: member.content.plaintext_size,
            };
            let body = self
                .bodies
                .lock()
                .unwrap()
                .get(&member.content.content_id)
                .cloned()
                .unwrap_or_default();
            let mut writer = crate::run_input_downlink::VerifiedObjectWriter::create(destination, &identity).await?;
            for chunk in body.chunks(4) {
                writer.write_chunk(chunk).await?;
            }
            writer.finish().await
        }
    }

    fn identity(content_id: &str, body: &[u8]) -> RunContentIdentity {
        RunContentIdentity {
            content_id: content_id.to_owned(),
            plaintext_sha256: hex::encode(sha2::Sha256::digest(body)),
            plaintext_size: body.len() as i64,
        }
    }

    fn member(resource_path: &str, body: &[u8]) -> RunInputManifestMember {
        RunInputManifestMember {
            resource_path: resource_path.to_owned(),
            content: identity(resource_path, body),
        }
    }

    fn manifest_with(members: Vec<RunInputManifestMember>) -> RunInputManifest {
        RunInputManifest {
            manifest_format: "rsm-workspace-content-manifest-v1".to_owned(),
            manifest_sha256: workspace_manifest_digest("rsm-workspace-content-manifest-v1", &members),
            members,
        }
    }

    #[tokio::test]
    async fn materializes_members_in_manifest_order_into_the_run_dir() {
        let dir = tempfile::tempdir().unwrap();
        let input_dir = dir.path().join("input");
        let mut bodies = std::collections::HashMap::new();
        bodies.insert("docs/a.txt".to_owned(), b"alpha-bytes".to_vec());
        bodies.insert("docs/b.txt".to_owned(), b"beta".to_vec());
        let downlink = FakeDownlink::new(bodies);
        let manifest = manifest_with(vec![
            member("docs/a.txt", b"alpha-bytes"),
            member("docs/b.txt", b"beta"),
        ]);

        let receipts = materialize_run_input(&downlink, "adm-1", &manifest, None, &input_dir)
            .await
            .expect("materialization should succeed");

        assert_eq!(
            downlink.fetches.lock().unwrap().clone(),
            vec!["docs/a.txt".to_owned(), "docs/b.txt".to_owned()]
        );
        assert_eq!(receipts.len(), 2);
        assert_eq!(
            tokio::fs::read(input_dir.join("docs/a.txt")).await.unwrap(),
            b"alpha-bytes"
        );
        assert_eq!(tokio::fs::read(input_dir.join("docs/b.txt")).await.unwrap(), b"beta");
    }

    #[tokio::test]
    async fn tampered_manifest_digest_fails_before_any_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let downlink = FakeDownlink::new(std::collections::HashMap::new());
        let mut manifest = manifest_with(vec![member("docs/a.txt", b"alpha-bytes")]);
        manifest.manifest_sha256 = "0".repeat(64);

        let outcome = materialize_run_input(&downlink, "adm-1", &manifest, None, dir.path()).await;

        assert!(matches!(outcome, Err(RunInputMaterializeError::ManifestDigestMismatch)));
        assert!(downlink.fetches.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn manifest_matching_a_foreign_admission_base_digest_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let downlink = FakeDownlink::new(std::collections::HashMap::new());
        let manifest = manifest_with(vec![member("docs/a.txt", b"alpha-bytes")]);

        let outcome = materialize_run_input(&downlink, "adm-1", &manifest, Some(&"f".repeat(64)), dir.path()).await;

        assert!(matches!(outcome, Err(RunInputMaterializeError::ManifestDigestMismatch)));
        assert!(downlink.fetches.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn duplicate_resource_paths_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let downlink = FakeDownlink::new(std::collections::HashMap::new());
        let manifest = manifest_with(vec![
            member("docs/a.txt", b"alpha-bytes"),
            member("docs/a.txt", b"other-bytes"),
        ]);

        let outcome = materialize_run_input(&downlink, "adm-1", &manifest, None, dir.path()).await;

        assert!(matches!(outcome, Err(RunInputMaterializeError::DuplicateResourcePath)));
        assert!(downlink.fetches.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unsafe_resource_path_fails_before_the_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let downlink = FakeDownlink::new(std::collections::HashMap::new());
        let manifest = manifest_with(vec![member("../escape.txt", b"escape")]);

        let outcome = materialize_run_input(&downlink, "adm-1", &manifest, None, dir.path()).await;

        assert!(matches!(
            outcome,
            Err(RunInputMaterializeError::Downlink(
                RunInputDownlinkError::UnsafeResourcePath(_)
            ))
        ));
        assert!(downlink.fetches.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn digest_mismatch_member_stops_materialization_at_the_first_failure() {
        let dir = tempfile::tempdir().unwrap();
        let input_dir = dir.path().join("input");
        let mut bodies = std::collections::HashMap::new();
        bodies.insert("docs/a.txt".to_owned(), b"alpha-bytes".to_vec());
        bodies.insert("docs/b.txt".to_owned(), b"tampered".to_vec());
        let downlink = FakeDownlink::new(bodies);
        // The manifest pins b.txt to the digest of different bytes than the
        // transport serves: the member fails verification mid-stream.
        let manifest = manifest_with(vec![
            member("docs/a.txt", b"alpha-bytes"),
            member("docs/b.txt", b"expected"),
        ]);

        let outcome = materialize_run_input(&downlink, "adm-1", &manifest, None, &input_dir).await;

        assert!(matches!(
            outcome,
            Err(RunInputMaterializeError::Downlink(
                RunInputDownlinkError::ObjectDigestMismatch
            ))
        ));
        // The failed member never appears under its final name; the
        // succeeded earlier member stays materialized.
        assert!(!tokio::fs::try_exists(input_dir.join("docs/b.txt")).await.unwrap());
        assert_eq!(
            tokio::fs::read(input_dir.join("docs/a.txt")).await.unwrap(),
            b"alpha-bytes"
        );
        assert!(!tokio::fs::try_exists(input_dir.join("docs/b.txt.part")).await.unwrap());
    }
}
