//! Run output uplink port (T0-CORE-OUTPUT-UPLINK).
//!
//! The run executor consumes [`RunOutputUplink`] — a thin port over the
//! Agent Control Plane run-terminal output uplink (`POST
//! /api/team-workspace/v1/run-output-manifests`) — and never HTTP directly.
//! Wire types mirror the frozen ACP `run_authority` Go json tags verbatim.
//! Unlike the input downlink, here Core is the authority: the executor mints
//! `output_manifest_id` and `manifest_sha256` (RFC 8785/JCS canonical digest,
//! executor-card concern), ACP only verifies and persists — a duplicate
//! submission is a 409, never an idempotent success. The successful reply is
//! ACP's persisted echo of the manifest and is the authoritative record of
//! `state` for the provenance wiring card.

use async_trait::async_trait;
use thiserror::Error;

use crate::run_input_downlink::{RunContentIdentity, RunInputManifestMember};

/// One endpoint of a content diff (`run_authority.ContentState`): a kind plus
/// the pinned content identity when the state references actual content.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RunContentState {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<RunContentIdentity>,
}

/// The base a member's change is measured against
/// (`run_authority.ExpectedBase`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RunExpectedBase {
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub revision_id: String,
    pub manifest_sha256: String,
}

/// The change one output member records (`run_authority.OutputManifestMemberChange`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RunOutputMemberChange {
    pub change_kind: String,
    pub operation: String,
    pub base_content: RunContentState,
    pub output_content: RunContentState,
}

/// One member of the output manifest (`run_authority.OutputManifestMember`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RunOutputManifestMember {
    pub output_member_id: String,
    pub resource_path: String,
    pub change: RunOutputMemberChange,
}

/// The run-terminal output manifest Core submits to ACP
/// (`run_authority.OutputManifest`, verbatim ACP wire shape).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RunOutputManifest {
    pub output_manifest_id: String,
    pub manifest_format: String,
    pub run_admission_id: String,
    pub admission_version: i64,
    pub run_id: String,
    pub attempt_id: String,
    pub owner_epoch: i64,
    pub tenant_id: String,
    pub resource_organization_id: String,
    pub workspace_id: String,
    pub input_base: RunExpectedBase,
    pub input_manifest_sha256: String,
    pub captured_output_snapshot_sha256: String,
    pub members: Vec<RunOutputManifestMember>,
    pub captured_at_ms: i64,
    pub state: String,
    pub manifest_sha256: String,
}

/// Domain errors for the output uplink. Wire rejections keep the ACP error
/// envelope's code so callers can distinguish retry classes exactly the way
/// the acceptor contract intends (404 run_admission vs 404 workspace
/// manifest vs 409 duplicate identity vs 422 invalid).
#[derive(Debug, Error)]
pub enum RunOutputUplinkError {
    #[error("output manifest submission was rejected: {status} {code}")]
    Rejected { status: u16, code: String },
    #[error("output uplink transport failed")]
    Unavailable,
    #[error("accepted output manifest response is not well-formed")]
    InvalidResponse,
}

/// The run output uplink port. Implementations own the transport (HTTP +
/// mTLS identity in production) and submit the executor-minted manifest;
/// the returned value is ACP's persisted echo, not the submitted copy.
#[async_trait]
pub trait RunOutputUplink: Send + Sync {
    async fn submit_output_manifest(
        &self,
        manifest: &RunOutputManifest,
    ) -> Result<RunOutputManifest, RunOutputUplinkError>;
}

/// Compute the exact output delta between the admission-bound input manifest
/// and the captured output snapshot (T0-RUN-EXECUTOR Slice E1).
///
/// This is the mint-side mirror of the ACP acceptor's
/// `validateExactDelta`: members appear in byte-order-sorted resource-path
/// order, and every member is exactly one of —
/// - `add`/`upsert` (absent → present): a path only in the snapshot;
/// - `delete`/`delete` (present → absent): a path only in the input;
/// - `modify`/`upsert` (present → present, differing content identity).
///
/// A path present on both sides with identical content produces no member.
/// Duplicate resource paths follow the Go map semantics (last entry wins for
/// content) — but the input materialization adapter rejects duplicates
/// upstream, so verified manifests never exercise that branch. The caller
/// supplies the `output_member_id` minter because member ids enter the
/// canonical digest; production mints crypto-random UUIDv4 ids.
pub fn compute_exact_output_members_with_ids(
    input: &[RunInputManifestMember],
    captured: &[RunInputManifestMember],
    member_id: impl FnMut() -> String,
) -> Vec<RunOutputManifestMember> {
    let mut input_by_path: std::collections::HashMap<&str, &RunContentIdentity> =
        std::collections::HashMap::with_capacity(input.len());
    let mut captured_by_path: std::collections::HashMap<&str, &RunContentIdentity> =
        std::collections::HashMap::with_capacity(captured.len());
    let mut paths: Vec<&str> = Vec::with_capacity(input.len() + captured.len());
    for member in input {
        input_by_path.insert(member.resource_path.as_str(), &member.content);
        paths.push(member.resource_path.as_str());
    }
    for member in captured {
        captured_by_path.insert(member.resource_path.as_str(), &member.content);
        if !input_by_path.contains_key(member.resource_path.as_str()) {
            paths.push(member.resource_path.as_str());
        }
    }
    // Byte-order comparison — the Go acceptor sorts with strings.Compare,
    // and member order is part of the canonical digest.
    paths.sort_unstable();

    let mut member_id = member_id;
    paths
        .into_iter()
        .filter_map(|path| {
            let base = input_by_path.get(path).copied();
            let current = captured_by_path.get(path).copied();
            let change = match (base, current) {
                (None, Some(current)) => RunOutputMemberChange {
                    change_kind: "add".to_owned(),
                    operation: "upsert".to_owned(),
                    base_content: RunContentState {
                        kind: "absent".to_owned(),
                        content: None,
                    },
                    output_content: RunContentState {
                        kind: "present".to_owned(),
                        content: Some(current.clone()),
                    },
                },
                (Some(base), None) => RunOutputMemberChange {
                    change_kind: "delete".to_owned(),
                    operation: "delete".to_owned(),
                    base_content: RunContentState {
                        kind: "present".to_owned(),
                        content: Some(base.clone()),
                    },
                    output_content: RunContentState {
                        kind: "absent".to_owned(),
                        content: None,
                    },
                },
                (Some(base), Some(current)) if base != current => RunOutputMemberChange {
                    change_kind: "modify".to_owned(),
                    operation: "upsert".to_owned(),
                    base_content: RunContentState {
                        kind: "present".to_owned(),
                        content: Some(base.clone()),
                    },
                    output_content: RunContentState {
                        kind: "present".to_owned(),
                        content: Some(current.clone()),
                    },
                },
                _ => return None,
            };
            Some(RunOutputManifestMember {
                output_member_id: member_id(),
                resource_path: path.to_owned(),
                change,
            })
        })
        .collect()
}

/// [`compute_exact_output_members_with_ids`] with crypto-random UUIDv4
/// member ids (the production minter).
pub fn compute_exact_output_members(
    input: &[RunInputManifestMember],
    captured: &[RunInputManifestMember],
) -> Vec<RunOutputManifestMember> {
    compute_exact_output_members_with_ids(input, captured, || uuid::Uuid::new_v4().to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn identity() -> RunContentIdentity {
        RunContentIdentity {
            content_id: "reports/out.txt".to_owned(),
            plaintext_sha256: SHA_B.to_owned(),
            plaintext_size: 5,
        }
    }

    fn manifest() -> RunOutputManifest {
        RunOutputManifest {
            output_manifest_id: "om-1".to_owned(),
            manifest_format: "rsm.run.output.v1".to_owned(),
            run_admission_id: "admission-1".to_owned(),
            admission_version: 1,
            run_id: "run-1".to_owned(),
            attempt_id: "attempt-1".to_owned(),
            owner_epoch: 1,
            tenant_id: "tenant-1".to_owned(),
            resource_organization_id: "org-1".to_owned(),
            workspace_id: "ws-1".to_owned(),
            input_base: RunExpectedBase {
                kind: "workspace_manifest".to_owned(),
                revision_id: String::new(),
                manifest_sha256: SHA_A.to_owned(),
            },
            input_manifest_sha256: SHA_A.to_owned(),
            captured_output_snapshot_sha256: SHA_A.to_owned(),
            members: vec![RunOutputManifestMember {
                output_member_id: "member-1".to_owned(),
                resource_path: "reports/out.txt".to_owned(),
                change: RunOutputMemberChange {
                    change_kind: "add".to_owned(),
                    operation: "create".to_owned(),
                    base_content: RunContentState {
                        kind: "absent".to_owned(),
                        content: None,
                    },
                    output_content: RunContentState {
                        kind: "content".to_owned(),
                        content: Some(identity()),
                    },
                },
            }],
            captured_at_ms: 1_760_000_000_000,
            state: "terminal".to_owned(),
            manifest_sha256: SHA_A.to_owned(),
        }
    }

    /// The serialized submission must match the frozen ACP Go json tags
    /// byte-for-byte in shape: snake_case keys, `revision_id` omitted when
    /// empty (Go omitempty), member `content` omitted when absent
    /// (Go omitempty on pointer).
    #[test]
    fn submission_serializes_acp_wire_shape() {
        let json = serde_json::to_value(manifest()).unwrap();
        assert_eq!(json["output_manifest_id"], "om-1");
        assert_eq!(json["manifest_format"], "rsm.run.output.v1");
        assert_eq!(json["run_admission_id"], "admission-1");
        assert_eq!(json["admission_version"], 1);
        assert_eq!(json["run_id"], "run-1");
        assert_eq!(json["attempt_id"], "attempt-1");
        assert_eq!(json["owner_epoch"], 1);
        assert_eq!(json["tenant_id"], "tenant-1");
        assert_eq!(json["resource_organization_id"], "org-1");
        assert_eq!(json["workspace_id"], "ws-1");
        assert_eq!(json["input_base"]["kind"], "workspace_manifest");
        assert_eq!(json["input_base"]["manifest_sha256"], SHA_A);
        assert!(
            json["input_base"].get("revision_id").is_none(),
            "empty revision_id must be omitted"
        );
        assert_eq!(json["input_manifest_sha256"], SHA_A);
        assert_eq!(json["captured_output_snapshot_sha256"], SHA_A);
        assert_eq!(json["members"][0]["output_member_id"], "member-1");
        assert_eq!(json["members"][0]["resource_path"], "reports/out.txt");
        assert_eq!(json["members"][0]["change"]["change_kind"], "add");
        assert_eq!(json["members"][0]["change"]["operation"], "create");
        assert_eq!(json["members"][0]["change"]["base_content"]["kind"], "absent");
        assert!(
            json["members"][0]["change"]["base_content"].get("content").is_none(),
            "absent base content must be omitted"
        );
        assert_eq!(
            json["members"][0]["change"]["output_content"]["content"]["content_id"],
            "reports/out.txt"
        );
        assert_eq!(
            json["members"][0]["change"]["output_content"]["content"]["plaintext_size"],
            5
        );
        assert_eq!(json["captured_at_ms"], 1_760_000_000_000i64);
        assert_eq!(json["state"], "terminal");
        assert_eq!(json["manifest_sha256"], SHA_A);
    }

    /// ACP echoes the persisted manifest (201 body). Parsing must accept it
    /// exactly as Go marshals it — including omitted empty fields.
    #[test]
    fn acp_persisted_echo_parses_back() {
        let echo = serde_json::json!({
            "output_manifest_id": "om-1",
            "manifest_format": "rsm.run.output.v1",
            "run_admission_id": "admission-1",
            "admission_version": 1,
            "run_id": "run-1",
            "attempt_id": "attempt-1",
            "owner_epoch": 1,
            "tenant_id": "tenant-1",
            "resource_organization_id": "org-1",
            "workspace_id": "ws-1",
            "input_base": {"kind": "workspace_manifest", "manifest_sha256": SHA_A},
            "input_manifest_sha256": SHA_A,
            "captured_output_snapshot_sha256": SHA_A,
            "members": [{
                "output_member_id": "member-1",
                "resource_path": "reports/out.txt",
                "change": {
                    "change_kind": "add",
                    "operation": "create",
                    "base_content": {"kind": "absent"},
                    "output_content": {"kind": "content", "content": {
                        "content_id": "reports/out.txt",
                        "plaintext_sha256": SHA_B,
                        "plaintext_size": 5
                    }}
                }
            }],
            "captured_at_ms": 1_760_000_000_000_i64,
            "state": "persisted",
            "manifest_sha256": SHA_A
        });
        let parsed: RunOutputManifest = serde_json::from_value(echo).unwrap();
        assert_eq!(parsed.state, "persisted");
        assert_eq!(parsed.input_base.revision_id, "");
        assert!(parsed.members[0].change.base_content.content.is_none());
        assert_eq!(
            parsed.members[0]
                .change
                .output_content
                .content
                .as_ref()
                .unwrap()
                .plaintext_size,
            5
        );
        // A round-trip through the port's own types stays wire-stable.
        let reserialized = serde_json::to_value(&parsed).unwrap();
        assert_eq!(reserialized["state"], "persisted");
        assert!(reserialized["input_base"].get("revision_id").is_none());
    }

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

    #[test]
    fn exact_delta_emits_add_delete_modify_and_skips_noop() {
        let input = vec![
            ws_member("kept.txt", SHA_B, 5),
            ws_member("removed.txt", SHA_B, 5),
            ws_member("changed.txt", SHA_B, 5),
        ];
        let captured = vec![
            ws_member("kept.txt", SHA_B, 5),
            ws_member("changed.txt", SHA_A, 9),
            ws_member("reports/new.txt", SHA_B, 5),
        ];

        let members = compute_exact_output_members_with_ids(&input, &captured, || next_id().to_string());

        // Byte-order path order: "removed.txt" < "reports/new.txt" ('m' < 'p').
        // kept.txt is identical on both sides: no member, not a no-op modify.
        let paths: Vec<&str> = members.iter().map(|m| m.resource_path.as_str()).collect();
        assert_eq!(paths, vec!["changed.txt", "removed.txt", "reports/new.txt"]);

        assert_eq!(members[0].change.change_kind, "modify");
        assert_eq!(members[0].change.operation, "upsert");
        assert_eq!(
            members[0]
                .change
                .base_content
                .content
                .as_ref()
                .unwrap()
                .plaintext_sha256,
            SHA_B
        );
        assert_eq!(
            members[0]
                .change
                .output_content
                .content
                .as_ref()
                .unwrap()
                .plaintext_sha256,
            SHA_A
        );

        assert_eq!(members[1].change.change_kind, "delete");
        assert_eq!(members[1].change.operation, "delete");
        assert!(members[1].change.base_content.content.is_some());
        assert!(members[1].change.output_content.content.is_none());

        assert_eq!(members[2].change.change_kind, "add");
        assert_eq!(members[2].change.operation, "upsert");
        assert!(members[2].change.base_content.content.is_none());
        assert_eq!(members[2].change.output_content.kind, "present");

        // Every member got a distinct id from the minter (ids enter the digest).
        let ids: HashSet<&str> = members.iter().map(|m| m.output_member_id.as_str()).collect();
        assert_eq!(ids.len(), 3);
    }

    fn next_id() -> u32 {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(1);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn exact_delta_matches_the_go_acceptor_sort_semantics() {
        // paths.sort uses byte order (strings.Compare), NOT UTF-16 order.
        // "a/b" < "a.txt" in byte order ('/' 0x2F < '.' 0x2E is FALSE —
        // actually '.' 0x2E < '/' 0x2F, so "a.txt" sorts first), and this is
        // the order the ACP acceptor expects member-by-member.
        let input = Vec::new();
        let captured = vec![ws_member("a/b", SHA_B, 5), ws_member("a.txt", SHA_B, 5)];
        let members = compute_exact_output_members_with_ids(&input, &captured, || "m".to_owned());
        let paths: Vec<&str> = members.iter().map(|m| m.resource_path.as_str()).collect();
        assert_eq!(paths, vec!["a.txt", "a/b"]);
    }

    #[test]
    fn exact_delta_last_wins_for_duplicate_captured_paths() {
        // Go mirror semantics: a duplicated captured path keeps the last
        // content for the map, but every paths entry emits a member — the
        // materialization adapter rejects duplicates upstream, so verified
        // manifests never exercise this branch.
        let input = Vec::new();
        let captured = vec![ws_member("dup.txt", SHA_A, 1), ws_member("dup.txt", SHA_B, 2)];
        let members = compute_exact_output_members_with_ids(&input, &captured, || "m".to_owned());
        assert_eq!(members.len(), 2);
        for member in &members {
            assert_eq!(
                member.change.output_content.content.as_ref().unwrap().plaintext_sha256,
                SHA_B
            );
        }
    }
}
