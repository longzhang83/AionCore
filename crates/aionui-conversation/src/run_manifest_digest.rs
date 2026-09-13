//! Run manifest digest minting & verification (T0-RUN-EXECUTOR Slice E1).
//!
//! Core is the execution authority for output manifests: it MINTS
//! `manifest_sha256` before submission and RE-VERIFIES the pinned input
//! manifest it receives. Both directions use the exact canonicalization the
//! ACP `run_authority` package froze (`internal/run_authority/canonical.go`),
//! so the two implementations must agree byte-for-byte:
//!
//! - objects: keys sorted by UTF-16 code-unit order (RFC 8785 §3.2.3), no
//!   whitespace, `"key":value`;
//! - strings: only `"`, `\`, and <0x20 controls escaped (`\n`, `\r`, `\t`
//!   short forms, other controls `\u00xx` lowercase); `<`, `>`, `&`, U+2028
//!   and U+2029 stay literal (the Go implementation marshals with HTML
//!   escaping and then strips exactly those escapes — the net profile);
//! - integers: plain decimal (the manifest wire types carry no floats, so
//!   the IEEE 754 formatting rules of RFC 8785 never engage);
//! - digest: SHA-256 over the canonical bytes, lowercase hex.
//!
//! The digest covers a FIXED FIELD PROJECTION, not the wire JSON: for the
//! output manifest `manifest_sha256` is omitted (it names the digest itself)
//! and `revision_id` enters only when `input_base.kind == "revision"` — the
//! same conditions as the Go projection. Divergence here fails closed on the
//! ACP side (digest self-check), which is exactly what the frozen vectors
//! below guard against.

use sha2::{Digest, Sha256};

use crate::run_input_downlink::RunInputManifestMember;
use crate::run_output_uplink::RunOutputManifest;

/// The frozen ACP workspace-content-manifest format
/// (`run_authority.WorkspaceManifestFormatV1`).
pub const WORKSPACE_MANIFEST_FORMAT_V1: &str = "rsm-workspace-content-manifest-v1";
/// The frozen ACP output-manifest format (`run_authority.OutputManifestFormatV1`).
pub const OUTPUT_MANIFEST_FORMAT_V1: &str = "rsm-output-manifest-v1";

/// A closed canonical value model covering exactly the shapes the manifest
/// projections produce (the wire types carry no bools, nulls, or floats).
/// Every variant has a canonical rendering, so canonicalization is
/// infallible — the Go implementation returns errors only because it accepts
/// `any` (floats, channels, …).
enum CanonicalValue {
    Int(i64),
    String(String),
    Array(Vec<CanonicalValue>),
    /// Key order is irrelevant here — keys are sorted at write time by
    /// UTF-16 code-unit order, mirroring the Go `utf16Less` discipline.
    Object(Vec<(String, CanonicalValue)>),
}

/// UTF-16 code-unit ordering (RFC 8785 §3.2.3): element-wise code-unit
/// comparison, shorter prefix sorts first. NOT byte order — astral-plane
/// characters sort *before* some BMP characters (surrogates 0xD800-0xDFFF).
fn utf16_less(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn escape_json_string(value: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in value.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            // Everything else — including `<`, `>`, `&`, U+2028, U+2029 and
            // all non-ASCII — stays literal UTF-8.
            c => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn write_canonical(value: &CanonicalValue, out: &mut Vec<u8>) {
    match value {
        CanonicalValue::Int(value) => out.extend_from_slice(value.to_string().as_bytes()),
        CanonicalValue::String(value) => escape_json_string(value, out),
        CanonicalValue::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        CanonicalValue::Object(entries) => {
            let mut keys: Vec<&str> = entries.iter().map(|(key, _)| key.as_str()).collect();
            keys.sort_by(|left, right| utf16_less(left, right));
            out.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                escape_json_string(key, out);
                out.push(b':');
                let value = entries
                    .iter()
                    .find(|(entry_key, _)| entry_key == *key)
                    .map(|(_, value)| value)
                    .expect("key came from the same entries");
                write_canonical(value, out);
            }
            out.push(b'}');
        }
    }
}

fn digest_canonical(value: &CanonicalValue) -> String {
    let mut bytes = Vec::new();
    write_canonical(value, &mut bytes);
    hex::encode(Sha256::digest(&bytes))
}

fn string(value: &str) -> CanonicalValue {
    CanonicalValue::String(value.to_owned())
}

fn content_identity_value(content: &crate::run_input_downlink::RunContentIdentity) -> CanonicalValue {
    CanonicalValue::Object(vec![
        ("content_id".to_owned(), string(&content.content_id)),
        ("plaintext_sha256".to_owned(), string(&content.plaintext_sha256)),
        ("plaintext_size".to_owned(), CanonicalValue::Int(content.plaintext_size)),
    ])
}

/// The RFC 8785/JCS SHA-256 (lowercase hex) over the workspace-manifest
/// identity — the pinned input manifest Core receives. `members` renders as
/// `[]` when empty; a JSON `null` members array cannot deserialize into the
/// port's wire type, so the nil-vs-empty Go distinction cannot arise here.
pub fn workspace_manifest_digest(manifest_format: &str, members: &[RunInputManifestMember]) -> String {
    let members = CanonicalValue::Array(
        members
            .iter()
            .map(|member| {
                CanonicalValue::Object(vec![
                    ("content".to_owned(), content_identity_value(&member.content)),
                    ("resource_path".to_owned(), string(&member.resource_path)),
                ])
            })
            .collect(),
    );
    digest_canonical(&CanonicalValue::Object(vec![
        ("manifest_format".to_owned(), string(manifest_format)),
        ("members".to_owned(), members),
    ]))
}

fn content_state_value(kind: &str, content: Option<&crate::run_input_downlink::RunContentIdentity>) -> CanonicalValue {
    let mut entries = vec![("kind".to_owned(), string(kind))];
    if let Some(content) = content {
        entries.push(("content".to_owned(), content_identity_value(content)));
    }
    CanonicalValue::Object(entries)
}

fn expected_base_value(base: &crate::run_output_uplink::RunExpectedBase) -> CanonicalValue {
    let mut entries = vec![
        ("kind".to_owned(), string(&base.kind)),
        ("manifest_sha256".to_owned(), string(&base.manifest_sha256)),
    ];
    // Digest topology is NOT the wire topology: the wire omits an empty
    // `revision_id` (omitempty); the digest includes it whenever the base
    // kind is "revision", even empty — exactly the Go projection.
    if base.kind == "revision" {
        entries.push(("revision_id".to_owned(), string(&base.revision_id)));
    }
    CanonicalValue::Object(entries)
}

/// The RFC 8785/JCS SHA-256 (lowercase hex) over the output-manifest
/// identity with `manifest_sha256` omitted — the digest Core mints before
/// submission and ACP recomputes on acceptance.
pub fn output_manifest_digest(manifest: &RunOutputManifest) -> String {
    let members = CanonicalValue::Array(
        manifest
            .members
            .iter()
            .map(|member| {
                CanonicalValue::Object(vec![
                    (
                        "change".to_owned(),
                        CanonicalValue::Object(vec![
                            (
                                "base_content".to_owned(),
                                content_state_value(
                                    &member.change.base_content.kind,
                                    member.change.base_content.content.as_ref(),
                                ),
                            ),
                            ("change_kind".to_owned(), string(&member.change.change_kind)),
                            ("operation".to_owned(), string(&member.change.operation)),
                            (
                                "output_content".to_owned(),
                                content_state_value(
                                    &member.change.output_content.kind,
                                    member.change.output_content.content.as_ref(),
                                ),
                            ),
                        ]),
                    ),
                    ("output_member_id".to_owned(), string(&member.output_member_id)),
                    ("resource_path".to_owned(), string(&member.resource_path)),
                ])
            })
            .collect(),
    );
    digest_canonical(&CanonicalValue::Object(vec![
        (
            "admission_version".to_owned(),
            CanonicalValue::Int(manifest.admission_version),
        ),
        ("attempt_id".to_owned(), string(&manifest.attempt_id)),
        (
            "captured_at_ms".to_owned(),
            CanonicalValue::Int(manifest.captured_at_ms),
        ),
        (
            "captured_output_snapshot_sha256".to_owned(),
            string(&manifest.captured_output_snapshot_sha256),
        ),
        ("input_base".to_owned(), expected_base_value(&manifest.input_base)),
        (
            "input_manifest_sha256".to_owned(),
            string(&manifest.input_manifest_sha256),
        ),
        ("manifest_format".to_owned(), string(&manifest.manifest_format)),
        ("members".to_owned(), members),
        ("output_manifest_id".to_owned(), string(&manifest.output_manifest_id)),
        ("owner_epoch".to_owned(), CanonicalValue::Int(manifest.owner_epoch)),
        (
            "resource_organization_id".to_owned(),
            string(&manifest.resource_organization_id),
        ),
        ("run_admission_id".to_owned(), string(&manifest.run_admission_id)),
        ("run_id".to_owned(), string(&manifest.run_id)),
        ("state".to_owned(), string(&manifest.state)),
        ("tenant_id".to_owned(), string(&manifest.tenant_id)),
        ("workspace_id".to_owned(), string(&manifest.workspace_id)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_input_downlink::RunContentIdentity;
    use crate::run_output_uplink::{
        RunContentState, RunExpectedBase, RunOutputManifest, RunOutputManifestMember, RunOutputMemberChange,
    };

    /// The three digests are frozen in the ACP Go test suite
    /// (`TestManifestDigestsMatchFrozenJCSVectors`) — the Rust mint must
    /// reproduce them byte-for-byte or every submission fails the ACP
    /// digest self-check.
    const WORKSPACE_DIGEST_ETXT: &str = "fd7231c4bd5489ab5aa388f4a3699a2aa26d0e57fcc2e31fb1d8ca426b1d3f56";
    const OUTPUT_DIGEST_FULL: &str = "e6eee7bbb55731774bfaa889610579c0acab47a6c822a774659e5d5a5431cf7d";
    const WORKSPACE_DIGEST_SPECIAL: &str = "615bfaac83ffbe5fd16e86353d5fc3ac7dbc203bde5e36319179f5756a18ecb5";

    fn content(id: &str, digit: char, size: i64) -> RunContentIdentity {
        RunContentIdentity {
            content_id: id.to_owned(),
            plaintext_sha256: std::iter::repeat_n(digit, 64).collect(),
            plaintext_size: size,
        }
    }

    fn workspace_member(resource_path: &str, content: RunContentIdentity) -> RunInputManifestMember {
        RunInputManifestMember {
            resource_path: resource_path.to_owned(),
            content,
        }
    }

    #[test]
    fn workspace_manifest_digest_matches_frozen_go_vector() {
        let digest = workspace_manifest_digest(
            "rsm-workspace-content-manifest-v1",
            &[workspace_member("é.txt", content("content-1", '1', 3))],
        );
        assert_eq!(digest, WORKSPACE_DIGEST_ETXT);
    }

    #[test]
    fn special_character_manifest_matches_frozen_go_vector() {
        // İ probes UTF-16 key ordering; the content id carries the escaped
        // HTML characters and a U+2028 that must stay literal.
        let digest = workspace_manifest_digest(
            "rsm-workspace-content-manifest-v1",
            &[workspace_member("İ/<&😀\u{2028}.txt", content("<&😀\u{2028}", '1', 3))],
        );
        assert_eq!(digest, WORKSPACE_DIGEST_SPECIAL);
    }

    fn full_output_manifest() -> RunOutputManifest {
        RunOutputManifest {
            output_manifest_id: "out-1".to_owned(),
            manifest_format: "rsm-output-manifest-v1".to_owned(),
            run_admission_id: "adm-1".to_owned(),
            admission_version: 1,
            run_id: "run-1".to_owned(),
            attempt_id: "attempt-1".to_owned(),
            owner_epoch: 1,
            tenant_id: "tenant-1".to_owned(),
            resource_organization_id: "org-1".to_owned(),
            workspace_id: "ws-1".to_owned(),
            input_base: RunExpectedBase {
                kind: "revision".to_owned(),
                revision_id: "rev-1".to_owned(),
                manifest_sha256: "a".repeat(64),
            },
            input_manifest_sha256: "a".repeat(64),
            captured_output_snapshot_sha256: "b".repeat(64),
            members: Vec::new(),
            captured_at_ms: 10,
            state: "fixed".to_owned(),
            manifest_sha256: String::new(),
        }
    }

    #[test]
    fn output_manifest_digest_matches_frozen_go_vector() {
        assert_eq!(output_manifest_digest(&full_output_manifest()), OUTPUT_DIGEST_FULL);
    }

    #[test]
    fn manifest_sha256_field_is_irrelevant_to_the_output_digest() {
        // The digest projection omits manifest_sha256 entirely: mutating it
        // must not change the recomputation.
        let mut manifest = full_output_manifest();
        manifest.manifest_sha256 = "0".repeat(64);
        assert_eq!(output_manifest_digest(&manifest), OUTPUT_DIGEST_FULL);
    }

    #[test]
    fn revision_base_kind_admits_empty_revision_id_into_the_digest() {
        // Wire topology omits an empty revision_id; the digest projection
        // includes it whenever kind == "revision". The two topologies differ.
        let mut manifest = full_output_manifest();
        manifest.input_base.revision_id = String::new();
        let with_empty = output_manifest_digest(&manifest);
        manifest.input_base.revision_id = "x".to_owned();
        let with_value = output_manifest_digest(&manifest);
        assert_ne!(with_empty, with_value);
        // And the empty variant is distinct from a non-revision base with the
        // same remaining fields.
        manifest.input_base.kind = "workspace_manifest".to_owned();
        manifest.input_base.revision_id = String::new();
        assert_ne!(output_manifest_digest(&manifest), with_empty);
    }

    #[test]
    fn canonical_string_rendering_follows_the_frozen_escape_profile() {
        let value = CanonicalValue::String("<>&\"\\\n\t\u{8}\u{1}\u{2028}\u{2029}é😀".to_owned());
        let mut bytes = Vec::new();
        write_canonical(&value, &mut bytes);
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "\"<>&\\\"\\\\\\n\\t\\u0008\\u0001\u{2028}\u{2029}é😀\""
        );
    }

    #[test]
    fn key_ordering_is_utf16_not_byte_order() {
        // U+FFFD sorts AFTER the 😀 surrogates in UTF-16 order but BEFORE it
        // in UTF-8 byte order — the discriminator between the two orders.
        let value = CanonicalValue::Object(vec![
            ("\u{FFFD}".to_owned(), CanonicalValue::Int(1)),
            ("😀".to_owned(), CanonicalValue::Int(2)),
        ]);
        let mut bytes = Vec::new();
        write_canonical(&value, &mut bytes);
        assert_eq!(String::from_utf8(bytes).unwrap(), "{\"😀\":2,\"�\":1}");
    }

    #[test]
    fn content_state_and_identity_topologies_match_go_projection() {
        // absent state: {"kind":"absent"}; present state adds content; empty
        // members array renders as [].
        let mut manifest = full_output_manifest();
        manifest.members = vec![RunOutputManifestMember {
            output_member_id: "member-1".to_owned(),
            resource_path: "reports/out.txt".to_owned(),
            change: RunOutputMemberChange {
                change_kind: "add".to_owned(),
                operation: "upsert".to_owned(),
                base_content: RunContentState {
                    kind: "absent".to_owned(),
                    content: None,
                },
                output_content: RunContentState {
                    kind: "present".to_owned(),
                    content: Some(content("reports/out.txt", 'c', 7)),
                },
            },
        }];
        let digest = output_manifest_digest(&manifest);
        // Stability: recompute is deterministic; distinct member content
        // changes the digest.
        assert_eq!(digest, output_manifest_digest(&manifest));
        let mut other = manifest.clone();
        other.members[0]
            .change
            .output_content
            .content
            .as_mut()
            .unwrap()
            .plaintext_size = 8;
        assert_ne!(digest, output_manifest_digest(&other));
    }
}
