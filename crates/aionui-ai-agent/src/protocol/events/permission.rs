use agent_client_protocol::schema::v1::Meta as SdkMeta;
use aionui_common::{Confirmation, ConfirmationOption};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::tool_call::{ProtocolToolCallStatus, ToolCallKind, ToolLocationItem, ToolResultContentItem};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestEventData {
    #[serde(default)]
    pub session_id: String,
    pub tool_call: ApprovalToolCall,
    pub options: Vec<ApprovalOptionData>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<SdkMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalToolCall {
    pub tool_call_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ProtocolToolCallStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<ToolCallKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_input: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Vec<ToolResultContentItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<ToolLocationItem>>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<SdkMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalOptionData {
    pub option_id: String,
    pub name: String,
    pub kind: ApprovalOptionKind,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<SdkMeta>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOptionKind {
    AllowOnce,
    AllowAlways,
    RejectOnce,
    RejectAlways,
}

impl ApprovalRequestEventData {
    pub fn to_confirmation(&self) -> Confirmation {
        Confirmation {
            id: self.tool_call.tool_call_id.clone(),
            call_id: self.tool_call.tool_call_id.clone(),
            title: self.tool_call.title.clone(),
            action: None,
            // Only a real `description` string. The old fallback dumped the
            // WHOLE raw_input via `Value::to_string()` into this field, so an
            // agent that smuggles structured data through the permission
            // channel (qwen/kimi AskUserQuestion) rendered a wall of one-line
            // JSON as the card's description (user report, 2026-08-05). The
            // card's own detail block already shows raw_input readably; an
            // empty description simply omits the line.
            description: self
                .tool_call
                .raw_input
                .as_ref()
                .and_then(|raw| raw.get("description").and_then(Value::as_str))
                .map(ToOwned::to_owned)
                .unwrap_or_default(),
            command_type: self.tool_call.kind.map(|kind| match kind {
                ToolCallKind::Read => "read".to_owned(),
                ToolCallKind::Edit => "edit".to_owned(),
                ToolCallKind::Execute => "execute".to_owned(),
            }),
            // Recovery carries the structured questions when the agent put them
            // in raw_input (qwen/kimi smuggle ask_user_question through the
            // permission channel). Without this the recovered card has NO source
            // for the question text at all — `Confirmation` has no raw_input
            // field, so the frontend's raw-input fallback cannot run on the
            // recovery path. Shape-keyed only, no per-agent branching: an array
            // under `questions` whose entries carry `question` + `options`.
            questions: self
                .tool_call
                .raw_input
                .as_ref()
                .and_then(|raw| raw.get("questions"))
                .filter(|qs| {
                    qs.as_array().is_some_and(|arr| {
                        !arr.is_empty()
                            && arr
                                .iter()
                                .all(|q| q.get("question").is_some() && q.get("options").is_some())
                    })
                })
                .cloned(),
            options: self
                .options
                .iter()
                .map(|opt| ConfirmationOption {
                    label: opt.name.clone(),
                    value: Value::String(opt.option_id.clone()),
                    params: None,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod to_confirmation_tests {
    use super::*;
    use serde_json::json;

    fn request(raw_input: serde_json::Value) -> ApprovalRequestEventData {
        ApprovalRequestEventData {
            session_id: "s1".into(),
            tool_call: ApprovalToolCall {
                tool_call_id: "call-1".into(),
                status: None,
                title: Some("Ask user 1 question".into()),
                kind: None,
                raw_input: Some(raw_input),
                raw_output: None,
                content: None,
                locations: None,
                meta: None,
            },
            options: Vec::new(),
            meta: None,
        }
    }

    /// The old fallback stringified the WHOLE raw_input into `description`,
    /// rendering a wall of one-line JSON on the card (user report 2026-08-05).
    #[test]
    fn description_is_empty_without_a_real_description_string() {
        let conf = request(json!({ "questions": [{ "question": "Q?", "options": [] }] })).to_confirmation();
        assert_eq!(
            conf.description, "",
            "raw_input must never be dumped as the description"
        );
    }

    #[test]
    fn description_keeps_a_real_description_string() {
        let conf = request(json!({ "description": "Write /tmp/a.txt" })).to_confirmation();
        assert_eq!(conf.description, "Write /tmp/a.txt");
    }

    /// Recovery source for the question text: `Confirmation` has no raw_input
    /// field, so without this the recovered card shows no question at all.
    #[test]
    fn questions_ride_along_for_structured_asks() {
        let conf = request(json!({
            "questions": [{ "question": "早餐吃什么？", "options": [{ "label": "包子" }] }]
        }))
        .to_confirmation();
        let qs = conf.questions.expect("structured questions are carried into recovery");
        assert_eq!(qs[0]["question"], "早餐吃什么？");
    }

    /// Shape-keyed, not agent-keyed: a `questions` value that is not a list of
    /// {question, options} entries must not be mistaken for an ask.
    #[test]
    fn malformed_questions_are_not_carried() {
        assert!(
            request(json!({ "questions": "nope" }))
                .to_confirmation()
                .questions
                .is_none()
        );
        assert!(
            request(json!({ "questions": [] }))
                .to_confirmation()
                .questions
                .is_none()
        );
        assert!(
            request(json!({ "questions": [{ "question": "Q?" }] }))
                .to_confirmation()
                .questions
                .is_none(),
            "an entry without options is not an answerable question"
        );
    }
}
