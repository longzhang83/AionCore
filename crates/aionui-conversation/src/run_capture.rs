//! Run capture (T0-RUN-CONSUMER Slice R1): post-run workspace inventory.
//!
//! Bridges execution to E2 assembly: walks the run's workspace directory and
//! produces the `captured` member list `assemble_run_output` consumes. Core
//! authors the captured snapshot, so capture pre-mirrors the same ACP shape
//! rules E2 enforces (canonical resource path, content identity) — an
//! uncapturable state fails typed and local instead of producing a manifest
//! the ACP acceptor would reject.
//!
//! content_id contract (amended in the coordination doc's R2 record): the
//! exact delta (E1) and its ACP mirror (`validator.go` `validateExactDelta`)
//! compare full content identity INCLUDING content_id — Go struct equality.
//! Two consequences for capture:
//!
//! 1. Unchanged content must keep the input manifest's content_id. Capture
//!    therefore reuses the pinned input member's content_id whenever a
//!    captured file's `(plaintext_sha256, plaintext_size)` matches an input
//!    member's; otherwise the file is genuinely new content and gets a
//!    CONTENT-ADDRESSED id (`content_id = plaintext_sha256`). Without the
//!    reuse rule, id-namespace drift (ACP object keys on the input side vs
//!    Core minted ids on the capture side) would report every untouched
//!    file as a modify and the manifest would misrepresent every run.
//! 2. The minted digest ids make the S card's
//!    `captured-objects/{content_id}` route digest-verifiable by
//!    construction and let ACP's content-addressed pool dedup identical
//!    bytes. (If an input manifest carried two members with equal
//!    (sha, size) under different ids, reuse resolves last-wins in manifest
//!    order — the registered snapshot pins the choice, so the ACP delta
//!    recompute stays consistent.)
//!
//! Fail-closed posture:
//! - symlinks and other non-regular entries are rejected — the ACP manifest
//!   has no symlink representation, and capturing a link's target bytes would
//!   misrepresent the run's state;
//! - a file that cannot be read aborts the capture — a silent skip would
//!   understate the captured state and fabricate a deletion in the exact
//!   delta the assembly derives;
//! - non-UTF-8 names are rejected (`CanonicalResourcePath` is a string
//!   contract; NFC divergence — the APFS reality — fails the same gate);
//! - the walk never follows symlinks, so no entry can escape the root.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Component, Path};

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::run_input_downlink::{RunContentIdentity, RunInputManifestMember};
use crate::run_output_assembly::canonical_resource_path;

#[derive(Debug, thiserror::Error)]
pub enum RunCaptureError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("capture root missing or not a directory: {0}")]
    Root(String),
    #[error("workspace walk failed at {path}: {source}")]
    WalkFailed { path: String, source: std::io::Error },
    #[error("unsupported entry — symlinks and special files have no manifest representation: {0}")]
    UnsupportedEntry(String),
    #[error("non-UTF-8 path in captured workspace: {0}")]
    NonUtf8Path(String),
    #[error("captured path is not a canonical resource path: {0}")]
    NonCanonicalPath(String),
    #[error("captured file too large for content identity: {0}")]
    SizeOverflow(String),
}

const READ_BUFFER_BYTES: usize = 64 * 1024;

/// Captures the full current state of `root` as the member list
/// `assemble_run_output` turns into the registered snapshot and the exact
/// delta. `input` is the admission's pinned input manifest members — the
/// reuse source for unchanged content identities (see the module docs).
/// Members come back sorted by path byte order — the order the assembly
/// re-validates. Scope enforcement is NOT capture's job: the whole state is
/// captured truthfully and `assemble_run_output` pre-mirrors
/// `validateOutputScope` (including the rule that a deleted out-of-scope file
/// is an out-of-scope change and must fail the run).
pub fn capture_workspace_state(
    root: &Path,
    input: &[RunInputManifestMember],
) -> Result<Vec<RunInputManifestMember>, RunCaptureError> {
    // (digest, size) → the pinned object id that already holds this content
    // in ACP's store. Last member wins in manifest order (Go map semantics).
    let mut input_content_ids: HashMap<(&str, i64), &str> = HashMap::with_capacity(input.len());
    for member in input {
        input_content_ids.insert(
            (member.content.plaintext_sha256.as_str(), member.content.plaintext_size),
            member.content.content_id.as_str(),
        );
    }

    let metadata = std::fs::metadata(root).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => RunCaptureError::Root(root.display().to_string()),
        _ => RunCaptureError::Io(error),
    })?;
    if !metadata.is_dir() {
        return Err(RunCaptureError::Root(root.display().to_string()));
    }

    let mut members = Vec::new();
    for entry in WalkDir::new(root).min_depth(1) {
        let entry = entry.map_err(|error| {
            let path = error.path().unwrap_or(root).display().to_string();
            let source = error
                .into_io_error()
                .unwrap_or_else(|| std::io::Error::other("walk failure without io cause"));
            RunCaptureError::WalkFailed { path, source }
        })?;
        let path = entry.path();

        let file_type = entry.file_type();
        if file_type.is_dir() {
            continue;
        }
        if !file_type.is_file() {
            return Err(RunCaptureError::UnsupportedEntry(path.display().to_string()));
        }

        let relative = path.strip_prefix(root).map_err(|_| RunCaptureError::WalkFailed {
            path: path.display().to_string(),
            source: std::io::Error::other("walkdir entry escaped the capture root"),
        })?;
        let mut canonical = String::new();
        for component in relative.components() {
            let part = match component {
                Component::Normal(part) => part,
                // walkdir under a fixed root cannot yield these; fail closed
                // rather than trusting the invariant.
                _ => return Err(RunCaptureError::UnsupportedEntry(path.display().to_string())),
            };
            let part_str = part
                .to_str()
                .ok_or_else(|| RunCaptureError::NonUtf8Path(path.display().to_string()))?;
            if !canonical.is_empty() {
                canonical.push('/');
            }
            canonical.push_str(part_str);
        }
        if canonical.is_empty() {
            return Err(RunCaptureError::NonCanonicalPath(String::new()));
        }
        // Validation gate only — the member keeps the original canonical
        // string; the lowercased alias identity lives in the assembly.
        canonical_resource_path(&canonical).map_err(|_| RunCaptureError::NonCanonicalPath(canonical.clone()))?;

        let (plaintext_sha256, size) = digest_file(path)?;
        let plaintext_size =
            i64::try_from(size).map_err(|_| RunCaptureError::SizeOverflow(path.display().to_string()))?;
        // Unchanged content keeps the pinned object id; new content is
        // content-addressed. Either way the exact delta compares truthfully.
        let content_id = match input_content_ids.get(&(plaintext_sha256.as_str(), plaintext_size)) {
            Some(pinned) => (*pinned).to_owned(),
            None => plaintext_sha256.clone(),
        };
        members.push(RunInputManifestMember {
            resource_path: canonical,
            content: RunContentIdentity {
                content_id,
                plaintext_sha256,
                plaintext_size,
            },
        });
    }

    members.sort_unstable_by(|left, right| left.resource_path.cmp(&right.resource_path));
    Ok(members)
}

/// Streams the file once, computing the SHA-256 hex digest and byte size in
/// the same pass. Any read failure aborts the capture.
fn digest_file(path: &Path) -> Result<(String, u64), std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(READ_BUFFER_BYTES, file);
    let mut digest = Sha256::new();
    let mut size: u64 = 0;
    let mut chunk = [0u8; READ_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        digest.update(&chunk[..read]);
        size += read as u64;
    }
    Ok((hex::encode(digest.finalize()), size))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_file(root: &Path, relative: &str, body: &[u8]) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("relative path has a parent")).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn expected_digest(body: &[u8]) -> String {
        hex::encode(Sha256::digest(body))
    }

    #[test]
    fn captures_files_with_correct_identity_in_byte_order() {
        let dir = tempfile::tempdir().unwrap();
        // Created deliberately out of byte order; output must still sort.
        create_file(dir.path(), "reports/summary.txt", b"summary");
        create_file(dir.path(), ".hidden", b"dot");
        create_file(dir.path(), "a.txt", b"alpha");

        let members = capture_workspace_state(dir.path(), &[]).expect("capture should succeed");

        let paths: Vec<&str> = members.iter().map(|m| m.resource_path.as_str()).collect();
        assert_eq!(paths, vec![".hidden", "a.txt", "reports/summary.txt"]);
        assert_eq!(members[0].content.plaintext_size, 3);
        assert_eq!(members[0].content.plaintext_sha256, expected_digest(b"dot"));
        assert_eq!(members[1].content.plaintext_size, 5);
        assert_eq!(members[1].content.plaintext_sha256, expected_digest(b"alpha"));
        assert_eq!(members[2].content.plaintext_size, 7);
        assert_eq!(members[2].content.plaintext_sha256, expected_digest(b"summary"));
        // content_id: content-addressed — equal to the plaintext digest.
        for member in &members {
            assert_eq!(member.content.content_id, member.content.plaintext_sha256);
        }
    }

    #[test]
    fn empty_workspace_captures_an_empty_member_list() {
        let dir = tempfile::tempdir().unwrap();
        let members = capture_workspace_state(dir.path(), &[]).expect("capture should succeed");
        assert!(members.is_empty());
    }

    #[test]
    fn missing_or_non_directory_root_fails_closed() {
        let error = capture_workspace_state(Path::new("/nonexistent-capture-root"), &[]).unwrap_err();
        assert!(matches!(error, RunCaptureError::Root(_)));
        let file = tempfile::tempdir().unwrap();
        let path = file.path().join("plain.txt");
        std::fs::write(&path, b"x").unwrap();
        let error = capture_workspace_state(&path, &[]).unwrap_err();
        assert!(matches!(error, RunCaptureError::Root(_)));
    }

    #[test]
    #[cfg(unix)]
    fn symlink_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        create_file(dir.path(), "real.txt", b"real");
        std::os::unix::fs::symlink("real.txt", dir.path().join("link.txt")).unwrap();

        let error = capture_workspace_state(dir.path(), &[]).unwrap_err();
        assert!(matches!(error, RunCaptureError::UnsupportedEntry(_)));
    }

    #[test]
    #[cfg(unix)]
    fn nfd_filename_fails_the_canonical_path_gate() {
        // APFS stores NFD names; construct the NFD spelling explicitly so the
        // test does not depend on the filesystem's normalization.
        let dir = tempfile::tempdir().unwrap();
        create_file(dir.path(), "e\u{301}.txt", b"nfd");

        let error = capture_workspace_state(dir.path(), &[]).unwrap_err();
        assert!(matches!(error, RunCaptureError::NonCanonicalPath(_)));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn non_utf8_filename_fails_closed() {
        // APFS rejects non-UTF-8 names at the filesystem layer (EILSEQ), so
        // this fixture is only constructible on byte-transparent filesystems
        // (ext4 et al.) — the gate stays for Linux run hosts.
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OsStr::from_bytes(b"\xff.txt"));
        std::fs::write(path, b"raw").unwrap();

        let error = capture_workspace_state(dir.path(), &[]).unwrap_err();
        assert!(matches!(error, RunCaptureError::NonUtf8Path(_)));
    }

    #[test]
    fn repeated_capture_is_fully_identity_stable() {
        // Two captures of an unchanged tree agree on the FULL member
        // identity — path, digest, size, and the content-addressed id. This
        // is what keeps the exact delta's no-op suppression truthful across
        // captures (and what the consumer's drift check relies on).
        let dir = tempfile::tempdir().unwrap();
        create_file(dir.path(), "out/result.bin", &[1u8, 2, 3, 4]);

        let first = capture_workspace_state(dir.path(), &[]).unwrap();
        let second = capture_workspace_state(dir.path(), &[]).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn different_content_yields_different_content_ids() {
        let dir = tempfile::tempdir().unwrap();
        create_file(dir.path(), "a.txt", b"one");
        create_file(dir.path(), "b.txt", b"two");

        let members = capture_workspace_state(dir.path(), &[]).unwrap();

        assert_eq!(members.len(), 2);
        assert_ne!(members[0].content.content_id, members[1].content.content_id);
    }

    #[test]
    fn unchanged_content_reuses_the_pinned_input_identity() {
        // The exact delta compares full identity including content_id, so an
        // unchanged file MUST keep the input manifest's object id — otherwise
        // an untouched file reports as a modify. A genuinely new file gets
        // the content-addressed digest id.
        let dir = tempfile::tempdir().unwrap();
        create_file(dir.path(), "docs/a.txt", b"alpha");
        create_file(dir.path(), "out/new.txt", b"new");

        let pinned = vec![ws_member("docs/a.txt", "obj-a", &expected_digest(b"alpha"), 5)];
        let members = capture_workspace_state(dir.path(), &pinned).unwrap();

        assert_eq!(members.len(), 2);
        let unchanged = members.iter().find(|m| m.resource_path == "docs/a.txt").unwrap();
        assert_eq!(unchanged.content.content_id, "obj-a");
        let added = members.iter().find(|m| m.resource_path == "out/new.txt").unwrap();
        assert_eq!(added.content.content_id, added.content.plaintext_sha256);
    }

    fn ws_member(resource_path: &str, content_id: &str, digest: &str, size: i64) -> RunInputManifestMember {
        RunInputManifestMember {
            resource_path: resource_path.to_owned(),
            content: RunContentIdentity {
                content_id: content_id.to_owned(),
                plaintext_sha256: digest.to_owned(),
                plaintext_size: size,
            },
        }
    }
}
