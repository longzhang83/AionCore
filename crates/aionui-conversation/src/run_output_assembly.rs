//! Run output manifest assembly (T0-RUN-EXECUTOR Slice E2).
//!
//! The composition that turns a captured run-dir state into a submittable
//! output manifest: bind the admission identity, canonicalize the captured
//! snapshot, compute the exact delta, and mint `manifest_sha256` — Core is
//! the execution authority, so the digest is minted here and only verified
//! on the ACP acceptor side. Every check below pre-mirrors a step of the ACP
//! acceptor chain (`output_manifest_acceptor.go` + `validator.go`) so a
//! submission Core knows cannot pass is never sent: digest self-check and
//! admission binding (input digest = manifest digest = admission base), the
//! captured snapshot's `validateWorkspaceManifest` shape (canonical ordered
//! alias-unique members, ≤1000), `validateOutputScope`, and the
//! `validateOutputManifest` member/limits shape.
//!
//! The captured members carry content identities authored by the capture
//! process; `content_id` is a closed identity class on the ACP side (object
//! key or content-service id), so assigning real content ids is part of the
//! captured-output-snapshot registration card — this module takes the
//! identities as given and validates their shape only.

use std::collections::HashSet;

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

use crate::run_admission_receive::RunAdmissionRecord;
use crate::run_input_downlink::{RunContentIdentity, RunInputManifest, RunInputManifestMember};
use crate::run_manifest_digest::{
    OUTPUT_MANIFEST_FORMAT_V1, WORKSPACE_MANIFEST_FORMAT_V1, output_manifest_digest, workspace_manifest_digest,
};
use crate::run_output_uplink::{RunExpectedBase, RunOutputManifest, compute_exact_output_members};

/// `run_authority`'s canonical bounds, mirrored fail-closed.
const MAX_CANONICAL_PATH_BYTES: usize = 1024;
const MAX_WORKSPACE_MANIFEST_MEMBERS: usize = 1000;
const MAX_OUTPUT_MANIFEST_MEMBERS: usize = 2000;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Error)]
pub enum RunOutputAssemblyError {
    #[error("captured_at_ms is not a valid unix millisecond timestamp")]
    InvalidCapturedAt,
    #[error("input manifest digest does not match its canonical recomputation or the admission base")]
    InputDigestMismatch,
    #[error("captured member path violates rsm-portable-relative-path-v1: {0}")]
    InvalidCapturedPath(String),
    #[error("captured output members contain duplicate resource paths")]
    DuplicateCapturedPath,
    #[error("captured member content identity is invalid: {0}")]
    InvalidCapturedContent(String),
    #[error("captured output snapshot exceeds {MAX_WORKSPACE_MANIFEST_MEMBERS} members")]
    SnapshotTooLarge,
    #[error("output delta exceeds {MAX_OUTPUT_MANIFEST_MEMBERS} members")]
    DeltaTooLarge,
    #[error("admission scope path violates rsm-portable-relative-path-v1: {0}")]
    InvalidScopePath(String),
    #[error("output member path {0} is outside the admission's path scope")]
    ScopeViolation(String),
}

/// One assembled, digest-minted output plus the captured snapshot it was
/// computed from. The snapshot is a registrable workspace content manifest
/// (format + digest-consistent members) — the artifact the captured-output-
/// snapshot registration route will accept once it exists; the output
/// manifest's `captured_output_snapshot_sha256` names it by construction.
pub struct AssembledRunOutput {
    pub manifest: RunOutputManifest,
    pub captured_snapshot: RunInputManifest,
}

/// Assemble and mint the run-terminal output manifest (state `fixed`) from
/// the received admission, the pinned input manifest, and the captured
/// run-dir members. `captured` may arrive in any order; assembly sorts it
/// into the canonical byte order the ACP workspace-manifest validator
/// requires before both the snapshot digest and the delta are computed.
pub fn assemble_run_output(
    admission: &RunAdmissionRecord,
    input_manifest: &RunInputManifest,
    captured: &[RunInputManifestMember],
    captured_at_ms: i64,
) -> Result<AssembledRunOutput, RunOutputAssemblyError> {
    if !(0..=MAX_SAFE_INTEGER).contains(&captured_at_ms) {
        return Err(RunOutputAssemblyError::InvalidCapturedAt);
    }
    if captured.len() > MAX_WORKSPACE_MANIFEST_MEMBERS {
        return Err(RunOutputAssemblyError::SnapshotTooLarge);
    }

    // Admission binding, pre-mirrored: the input manifest Core submits must
    // be exactly the admission's approved base — its canonical recomputation,
    // its own pinned digest, and the admission base digest must all agree.
    // (The ACP acceptor re-loads the registered row; failing here turns that
    // 422 into a typed local error.)
    let recomputed = workspace_manifest_digest(&input_manifest.manifest_format, &input_manifest.members);
    if recomputed != input_manifest.manifest_sha256 || recomputed != admission.base.manifest_sha256 {
        return Err(RunOutputAssemblyError::InputDigestMismatch);
    }

    // Canonicalize the captured members: path shape + content identity shape
    // + alias uniqueness (Core authors these, so every ACP shape rule is
    // pre-mirrored), then sort into the strict byte order the registered
    // snapshot must have.
    let mut aliases: HashSet<String> = HashSet::with_capacity(captured.len());
    for member in captured {
        validate_content_identity(&member.content, &member.resource_path)?;
        let alias = canonical_resource_path(&member.resource_path)
            .map_err(|_| RunOutputAssemblyError::InvalidCapturedPath(member.resource_path.clone()))?;
        if !aliases.insert(alias) {
            return Err(RunOutputAssemblyError::DuplicateCapturedPath);
        }
    }
    let mut snapshot_members: Vec<RunInputManifestMember> = captured.to_vec();
    snapshot_members.sort_unstable_by(|left, right| left.resource_path.cmp(&right.resource_path));
    let captured_snapshot = RunInputManifest {
        manifest_format: WORKSPACE_MANIFEST_FORMAT_V1.to_owned(),
        manifest_sha256: workspace_manifest_digest(WORKSPACE_MANIFEST_FORMAT_V1, &snapshot_members),
        members: snapshot_members,
    };

    let members = compute_exact_output_members(&input_manifest.members, &captured_snapshot.members);
    if members.len() > MAX_OUTPUT_MANIFEST_MEMBERS {
        return Err(RunOutputAssemblyError::DeltaTooLarge);
    }
    validate_output_scope(&admission.scope.kind, &admission.scope.resource_paths, &members)?;

    let manifest = RunOutputManifest {
        output_manifest_id: uuid::Uuid::new_v4().to_string(),
        manifest_format: OUTPUT_MANIFEST_FORMAT_V1.to_owned(),
        run_admission_id: admission.run_admission_id.clone(),
        admission_version: admission.admission_version,
        run_id: admission.run_id.clone(),
        attempt_id: admission.attempt_id.clone(),
        owner_epoch: admission.owner_epoch,
        tenant_id: admission.tenant_id.clone(),
        resource_organization_id: admission.resource_organization_id.clone(),
        workspace_id: admission.workspace_id.clone(),
        input_base: RunExpectedBase {
            kind: admission.base.kind.clone(),
            revision_id: admission.base.revision_id.clone(),
            manifest_sha256: admission.base.manifest_sha256.clone(),
        },
        input_manifest_sha256: admission.base.manifest_sha256.clone(),
        captured_output_snapshot_sha256: captured_snapshot.manifest_sha256.clone(),
        members,
        captured_at_ms,
        state: "fixed".to_owned(),
        manifest_sha256: String::new(),
    };
    let mut manifest = manifest;
    manifest.manifest_sha256 = output_manifest_digest(&manifest);
    Ok(AssembledRunOutput {
        manifest,
        captured_snapshot,
    })
}

/// `run_authority.CanonicalResourcePath` (rsm-portable-relative-path-v1),
/// returning only the alias: collision/scope checks lowercase the path while
/// the canonical path keeps NFC and original case. The alias is the mirror
/// of Go's `cases.Lower(language.Und)` — Unicode default full case mapping —
/// which is what Rust's `to_lowercase` implements; exotic-codepoint
/// divergence fails closed (ACP re-canonicalizes with its own authority and
/// rejects what this pre-screen wrongly passed).
/// Shared pre-mirror of `run_authority.CanonicalResourcePath`. Returns the
/// lowercased alias (the dedup identity); callers that author members keep
/// their original canonical string and use the `Ok` value only for aliasing.
pub(crate) fn canonical_resource_path(value: &str) -> Result<String, ()> {
    if value.is_empty()
        || value.len() > MAX_CANONICAL_PATH_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.nfc().collect::<String>() != value
    {
        return Err(());
    }
    if value.chars().any(|r| r <= '\u{1f}' || r == '\u{7f}') {
        return Err(());
    }
    if value
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(());
    }
    Ok(value.to_lowercase())
}

/// `run_authority.validateContent` shape mirror for Core-authored content
/// identities: opaque id, lowercase-hex SHA-256, safe size.
fn validate_content_identity(content: &RunContentIdentity, path: &str) -> Result<(), RunOutputAssemblyError> {
    let invalid = || RunOutputAssemblyError::InvalidCapturedContent(path.to_owned());
    let id = content.content_id.as_str();
    if id.trim().is_empty() || id.len() > 255 {
        return Err(invalid());
    }
    if content.plaintext_sha256.len() != 64
        || !content
            .plaintext_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    if !(0..=MAX_SAFE_INTEGER).contains(&content.plaintext_size) {
        return Err(invalid());
    }
    Ok(())
}

/// `run_authority.validateOutputScope` mirror: a workspace scope admits every
/// path; any other scope kind is a path scope whose alias set must contain
/// every member's alias. Invalid scope paths fail closed before membership.
fn validate_output_scope(
    scope_kind: &str,
    scope_paths: &[String],
    members: &[crate::run_output_uplink::RunOutputManifestMember],
) -> Result<(), RunOutputAssemblyError> {
    if scope_kind == "workspace" {
        return Ok(());
    }
    let mut allowed: HashSet<String> = HashSet::with_capacity(scope_paths.len());
    for path in scope_paths {
        let alias =
            canonical_resource_path(path).map_err(|_| RunOutputAssemblyError::InvalidScopePath(path.clone()))?;
        allowed.insert(alias);
    }
    for member in members {
        let alias = canonical_resource_path(&member.resource_path)
            .map_err(|_| RunOutputAssemblyError::InvalidCapturedPath(member.resource_path.clone()))?;
        if !allowed.contains(&alias) {
            return Err(RunOutputAssemblyError::ScopeViolation(member.resource_path.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_admission_receive::{
        RunAdmissionCorePrincipal, RunAdmissionEditScope, RunAdmissionEnvironmentAuthority, RunAdmissionExpectedBase,
    };

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const SHA_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn ws_member(resource_path: &str, digest: &str, size: i64) -> RunInputManifestMember {
        RunInputManifestMember {
            resource_path: resource_path.to_owned(),
            content: RunContentIdentity {
                content_id: resource_path.to_owned(),
                plaintext_sha256: digest.to_owned(),
                plaintext_size: size,
            },
        }
    }

    fn admission(input_manifest: &RunInputManifest) -> RunAdmissionRecord {
        RunAdmissionRecord {
            run_admission_id: "adm-1".to_owned(),
            admission_version: 1,
            actor_delegation_id: "del-1".to_owned(),
            actor_delegation_consumption_id: "con-1".to_owned(),
            admission_request_sha256: SHA_A.to_owned(),
            tenant_id: "tenant-1".to_owned(),
            resource_organization_id: "org-1".to_owned(),
            workspace_id: "ws-1".to_owned(),
            edit_session_id: "session-1".to_owned(),
            base: RunAdmissionExpectedBase {
                kind: "revision".to_owned(),
                revision_id: "rev-1".to_owned(),
                manifest_sha256: input_manifest.manifest_sha256.clone(),
            },
            scope: RunAdmissionEditScope {
                kind: "workspace".to_owned(),
                resource_paths: Vec::new(),
            },
            subject_id: "user-1".to_owned(),
            device_id: "device-1".to_owned(),
            run_id: "run-1".to_owned(),
            attempt_id: "attempt-1".to_owned(),
            owner_epoch: 1,
            core_principal: RunAdmissionCorePrincipal {
                service_id: "core-1".to_owned(),
                service_role: "core".to_owned(),
                workload_instance_id: "wi-1".to_owned(),
                credential_key_id: "ck-1".to_owned(),
                certificate_thumbprint_s256: "a".repeat(43),
                service_authority_epoch: 1,
            },
            isolation_profile_sha256: SHA_B.to_owned(),
            command_sha256: SHA_C.to_owned(),
            execution_authority_epoch: 1,
            data_classification: "synthetic".to_owned(),
            environment: RunAdmissionEnvironmentAuthority {
                environment_authority_id: "env-1".to_owned(),
                environment_kind: "non-production".to_owned(),
                environment_authority_epoch: 1,
            },
            issued_at_ms: 1_760_000_000_000,
            authorization_ttl_seconds: 30,
            expires_at_ms: 1_760_000_003_000,
            state: "active".to_owned(),
        }
    }

    fn input_manifest() -> RunInputManifest {
        let members = vec![ws_member("docs/a.txt", SHA_A, 5), ws_member("docs/b.txt", SHA_B, 5)];
        RunInputManifest {
            manifest_format: WORKSPACE_MANIFEST_FORMAT_V1.to_owned(),
            manifest_sha256: workspace_manifest_digest(WORKSPACE_MANIFEST_FORMAT_V1, &members),
            members,
        }
    }

    /// The captured final state: a.txt untouched, b.txt modified, new.txt
    /// added. Deliberately unsorted — assembly must normalize.
    fn captured() -> Vec<RunInputManifestMember> {
        vec![
            ws_member("reports/new.txt", SHA_D, 4),
            ws_member("docs/a.txt", SHA_A, 5),
            ws_member("docs/b.txt", SHA_C, 9),
        ]
    }

    #[test]
    fn assembly_pins_the_admission_identity_and_mints_a_self_consistent_digest() {
        let input = input_manifest();
        let record = admission(&input);

        let assembled =
            assemble_run_output(&record, &input, &captured(), 1_760_000_010_000).expect("assembly should succeed");
        let manifest = &assembled.manifest;

        assert_eq!(manifest.manifest_format, "rsm-output-manifest-v1");
        assert_eq!(manifest.run_admission_id, "adm-1");
        assert_eq!(manifest.admission_version, 1);
        assert_eq!(manifest.run_id, "run-1");
        assert_eq!(manifest.attempt_id, "attempt-1");
        assert_eq!(manifest.owner_epoch, 1);
        assert_eq!(manifest.tenant_id, "tenant-1");
        assert_eq!(manifest.resource_organization_id, "org-1");
        assert_eq!(manifest.workspace_id, "ws-1");
        assert_eq!(manifest.input_base.kind, "revision");
        assert_eq!(manifest.input_base.revision_id, "rev-1");
        assert_eq!(manifest.input_base.manifest_sha256, input.manifest_sha256);
        assert_eq!(manifest.input_manifest_sha256, input.manifest_sha256);
        assert_eq!(manifest.state, "fixed");
        assert_eq!(manifest.captured_at_ms, 1_760_000_010_000);
        // The snapshot digest is minted over the snapshot assembly returns.
        assert_eq!(
            manifest.captured_output_snapshot_sha256,
            assembled.captured_snapshot.manifest_sha256
        );
        // Digest self-check: the minted manifest digest is its own
        // recomputation (the ACP acceptor's first gate).
        assert_eq!(manifest.manifest_sha256, output_manifest_digest(manifest));
        // Ids are minted UUIDs.
        assert!(uuid::Uuid::parse_str(&manifest.output_manifest_id).is_ok());

        // The delta: byte-order paths, modify + add, no member for a.txt.
        let paths: Vec<&str> = manifest.members.iter().map(|m| m.resource_path.as_str()).collect();
        assert_eq!(paths, vec!["docs/b.txt", "reports/new.txt"]);
        assert_eq!(manifest.members[0].change.change_kind, "modify");
        assert_eq!(manifest.members[1].change.change_kind, "add");
        let ids: HashSet<&str> = manifest.members.iter().map(|m| m.output_member_id.as_str()).collect();
        assert_eq!(ids.len(), 2);

        // The captured snapshot is the sorted full final state, digest-consistent.
        let snapshot_paths: Vec<&str> = assembled
            .captured_snapshot
            .members
            .iter()
            .map(|m| m.resource_path.as_str())
            .collect();
        assert_eq!(snapshot_paths, vec!["docs/a.txt", "docs/b.txt", "reports/new.txt"]);
        assert_eq!(
            assembled.captured_snapshot.manifest_sha256,
            workspace_manifest_digest(WORKSPACE_MANIFEST_FORMAT_V1, &assembled.captured_snapshot.members)
        );
    }

    #[test]
    fn input_manifest_not_matching_the_admission_base_is_rejected() {
        let input = input_manifest();
        let mut record = admission(&input);
        record.base.manifest_sha256 = "0".repeat(64);

        let outcome = assemble_run_output(&record, &input, &captured(), 1);

        assert!(matches!(outcome, Err(RunOutputAssemblyError::InputDigestMismatch)));
    }

    #[test]
    fn tampered_input_manifest_digest_is_rejected() {
        let mut input = input_manifest();
        input.manifest_sha256 = "0".repeat(64);
        let record = admission(&input);

        let outcome = assemble_run_output(&record, &input, &captured(), 1);

        assert!(matches!(outcome, Err(RunOutputAssemblyError::InputDigestMismatch)));
    }

    #[test]
    fn duplicate_captured_paths_fail_closed_even_across_case_variants() {
        let input = input_manifest();
        let record = admission(&input);
        for duplicated in [
            vec![ws_member("docs/a.txt", SHA_C, 1), ws_member("docs/a.txt", SHA_D, 2)],
            vec![ws_member("Docs/a.txt", SHA_C, 1), ws_member("docs/a.txt", SHA_D, 2)],
        ] {
            let outcome = assemble_run_output(&record, &input, &duplicated, 1);
            assert!(
                matches!(outcome, Err(RunOutputAssemblyError::DuplicateCapturedPath)),
                "expected duplicate rejection"
            );
        }
    }

    #[test]
    fn captured_paths_must_satisfy_the_canonical_path_rules() {
        let input = input_manifest();
        let record = admission(&input);
        for invalid in [
            "../escape.txt",
            "a\u{7}.txt",
            // NFD-decomposed é — APFS stores names like this.
            "e\u{301}.txt",
            "trailing/.txt/",
            "double//slash.txt",
        ] {
            let captured = vec![ws_member(invalid, SHA_C, 1)];
            let outcome = assemble_run_output(&record, &input, &captured, 1);
            assert!(
                matches!(outcome, Err(RunOutputAssemblyError::InvalidCapturedPath(path)) if path == invalid),
                "expected invalid path rejection for {invalid:?}"
            );
        }
    }

    #[test]
    fn captured_content_identities_must_satisfy_the_shape_rules() {
        let input = input_manifest();
        let record = admission(&input);
        let mut bad_digest = ws_member("docs/c.txt", SHA_C, 1);
        bad_digest.content.plaintext_sha256 = "XYZ".to_owned();
        let mut negative_size = ws_member("docs/c.txt", SHA_C, -1);
        negative_size.content.plaintext_size = -1;
        let mut blank_id = ws_member("docs/c.txt", SHA_C, 1);
        blank_id.content.content_id = "  ".to_owned();
        for bad in [bad_digest, negative_size, blank_id] {
            let outcome = assemble_run_output(&record, &input, &[bad], 1);
            assert!(
                matches!(outcome, Err(RunOutputAssemblyError::InvalidCapturedContent(_))),
                "expected invalid content identity rejection"
            );
        }
    }

    #[test]
    fn path_scoped_admissions_reject_members_outside_the_scope() {
        let input = input_manifest();
        let mut record = admission(&input);
        record.scope = RunAdmissionEditScope {
            kind: "paths".to_owned(),
            resource_paths: vec!["docs/b.txt".to_owned()],
        };

        // new.txt is outside the scope.
        let outcome = assemble_run_output(&record, &input, &captured(), 1);
        assert!(matches!(outcome, Err(RunOutputAssemblyError::ScopeViolation(path)) if path == "reports/new.txt"));

        // Within the scope it assembles — the captured state must still
        // contain the unscoped a.txt, or its delete would breach the scope.
        let within = vec![ws_member("docs/a.txt", SHA_A, 5), ws_member("docs/b.txt", SHA_C, 9)];
        let outcome = assemble_run_output(&record, &input, &within, 1);
        assert!(outcome.is_ok());
    }

    #[test]
    fn an_invalid_scope_path_fails_closed_before_membership() {
        let input = input_manifest();
        let mut record = admission(&input);
        record.scope = RunAdmissionEditScope {
            kind: "paths".to_owned(),
            resource_paths: vec!["../escape.txt".to_owned()],
        };

        let outcome = assemble_run_output(&record, &input, &captured(), 1);

        assert!(matches!(outcome, Err(RunOutputAssemblyError::InvalidScopePath(_))));
    }

    #[test]
    fn snapshot_and_delta_member_limits_fail_closed() {
        let record = admission(&input_manifest());
        let oversized_snapshot: Vec<RunInputManifestMember> = (0..1001)
            .map(|index| ws_member(&format!("docs/f{index}.txt"), SHA_C, 1))
            .collect();
        let outcome = assemble_run_output(&record, &input_manifest(), &oversized_snapshot, 1);
        assert!(matches!(outcome, Err(RunOutputAssemblyError::SnapshotTooLarge)));

        // A delta can only breach 2000 when the input manifest itself is over
        // the workspace-manifest member bound — a body ACP would never have
        // registered, so assembly rejects before minting.
        let oversized_input_members: Vec<RunInputManifestMember> = (0..1001)
            .map(|index| ws_member(&format!("in/f{index}.txt"), SHA_A, 1))
            .collect();
        let oversized_input = RunInputManifest {
            manifest_format: WORKSPACE_MANIFEST_FORMAT_V1.to_owned(),
            manifest_sha256: workspace_manifest_digest(WORKSPACE_MANIFEST_FORMAT_V1, &oversized_input_members),
            members: oversized_input_members,
        };
        let oversized_record = admission(&oversized_input);
        let disjoint_captured: Vec<RunInputManifestMember> = (0..1000)
            .map(|index| ws_member(&format!("out/f{index}.txt"), SHA_D, 1))
            .collect();
        let outcome = assemble_run_output(&oversized_record, &oversized_input, &disjoint_captured, 1);
        assert!(matches!(outcome, Err(RunOutputAssemblyError::DeltaTooLarge)));
    }

    #[test]
    fn identical_capture_produces_a_memberless_manifest() {
        let input = input_manifest();
        let record = admission(&input);
        let captured = vec![ws_member("docs/a.txt", SHA_A, 5), ws_member("docs/b.txt", SHA_B, 5)];

        let assembled = assemble_run_output(&record, &input, &captured, 1_760_000_010_000)
            .expect("identical capture should assemble");

        assert!(assembled.manifest.members.is_empty());
        assert_eq!(
            assembled.manifest.manifest_sha256,
            output_manifest_digest(&assembled.manifest)
        );
    }

    #[test]
    fn negative_captured_at_ms_is_rejected() {
        let input = input_manifest();
        let record = admission(&input);
        let outcome = assemble_run_output(&record, &input, &captured(), -1);
        assert!(matches!(outcome, Err(RunOutputAssemblyError::InvalidCapturedAt)));
    }
}
