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

use crate::run_input_downlink::RunContentIdentity;

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

#[cfg(test)]
mod tests {
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
}
