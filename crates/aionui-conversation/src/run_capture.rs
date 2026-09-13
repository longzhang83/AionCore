//! Run capture (T0-RUN-CONSUMER Slice R1): post-run workspace inventory.
//!
//! Bridges execution to E2 assembly: walks the run's workspace directory and
//! produces the `captured` member list `assemble_run_output` consumes. Core
//! authors the captured snapshot, so capture pre-mirrors the same ACP shape
//! rules E2 enforces (canonical resource path, content identity) — an
//! uncapturable state fails typed and local instead of producing a manifest
//! the ACP acceptor would reject.
//!
//! content_id contract (frozen in the coordination doc's card-split record):
//! Core mints time-ordered UUIDv7 ids at capture time; the ACP
//! captured-snapshot registration card accepts them as opaque ids (shape
//! validation only) and never re-derives object keys from them. Content
//! identity is carried by `plaintext_sha256` + `plaintext_size`; two captures
//! of identical bytes intentionally mint distinct ids.
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

use sha2::{Digest, Sha256};
use uuid::Uuid;
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
/// delta. Members come back sorted by path byte order — the order the
/// assembly re-validates. Scope enforcement is NOT capture's job: the whole
/// state is captured truthfully and `assemble_run_output` pre-mirrors
/// `validateOutputScope` (including the rule that a deleted out-of-scope file
/// is an out-of-scope change and must fail the run).
pub fn capture_workspace_state(root: &Path) -> Result<Vec<RunInputManifestMember>, RunCaptureError> {
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
        members.push(RunInputManifestMember {
            resource_path: canonical,
            content: RunContentIdentity {
                content_id: Uuid::now_v7().to_string(),
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

        let members = capture_workspace_state(dir.path()).expect("capture should succeed");

        let paths: Vec<&str> = members.iter().map(|m| m.resource_path.as_str()).collect();
        assert_eq!(paths, vec![".hidden", "a.txt", "reports/summary.txt"]);
        assert_eq!(members[0].content.plaintext_size, 3);
        assert_eq!(members[0].content.plaintext_sha256, expected_digest(b"dot"));
        assert_eq!(members[1].content.plaintext_size, 5);
        assert_eq!(members[1].content.plaintext_sha256, expected_digest(b"alpha"));
        assert_eq!(members[2].content.plaintext_size, 7);
        assert_eq!(members[2].content.plaintext_sha256, expected_digest(b"summary"));
        // content_id: opaque, bounded, a parseable UUID (v7 mint contract).
        for member in &members {
            let id = member.content.content_id.as_str();
            assert!(!id.trim().is_empty() && id.len() <= 255);
            Uuid::parse_str(id).expect("content_id must be a UUID");
        }
    }

    #[test]
    fn empty_workspace_captures_an_empty_member_list() {
        let dir = tempfile::tempdir().unwrap();
        let members = capture_workspace_state(dir.path()).expect("capture should succeed");
        assert!(members.is_empty());
    }

    #[test]
    fn missing_or_non_directory_root_fails_closed() {
        let error = capture_workspace_state(Path::new("/nonexistent-capture-root")).unwrap_err();
        assert!(matches!(error, RunCaptureError::Root(_)));
        let file = tempfile::tempdir().unwrap();
        let path = file.path().join("plain.txt");
        std::fs::write(&path, b"x").unwrap();
        let error = capture_workspace_state(&path).unwrap_err();
        assert!(matches!(error, RunCaptureError::Root(_)));
    }

    #[test]
    #[cfg(unix)]
    fn symlink_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        create_file(dir.path(), "real.txt", b"real");
        std::os::unix::fs::symlink("real.txt", dir.path().join("link.txt")).unwrap();

        let error = capture_workspace_state(dir.path()).unwrap_err();
        assert!(matches!(error, RunCaptureError::UnsupportedEntry(_)));
    }

    #[test]
    #[cfg(unix)]
    fn nfd_filename_fails_the_canonical_path_gate() {
        // APFS stores NFD names; construct the NFD spelling explicitly so the
        // test does not depend on the filesystem's normalization.
        let dir = tempfile::tempdir().unwrap();
        create_file(dir.path(), "e\u{301}.txt", b"nfd");

        let error = capture_workspace_state(dir.path()).unwrap_err();
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

        let error = capture_workspace_state(dir.path()).unwrap_err();
        assert!(matches!(error, RunCaptureError::NonUtf8Path(_)));
    }

    #[test]
    fn repeated_capture_keeps_content_identity_and_mints_fresh_ids() {
        // Two captures of an unchanged tree mint distinct content_ids (the
        // object identity is per capture) while digests, sizes and paths —
        // the content identity — stay identical.
        let dir = tempfile::tempdir().unwrap();
        create_file(dir.path(), "out/result.bin", &[1u8, 2, 3, 4]);

        let first = capture_workspace_state(dir.path()).unwrap();
        let second = capture_workspace_state(dir.path()).unwrap();

        assert_eq!(first[0].resource_path, second[0].resource_path);
        assert_eq!(first[0].content.plaintext_sha256, second[0].content.plaintext_sha256);
        assert_eq!(first[0].content.plaintext_size, second[0].content.plaintext_size);
        assert_ne!(first[0].content.content_id, second[0].content.content_id);
    }
}
