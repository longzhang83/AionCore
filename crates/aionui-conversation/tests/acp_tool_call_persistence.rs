use std::sync::Arc;

use aionui_ai_agent::protocol::events::{
    AgentStreamEvent, FinishEventData,
    tool_call::{ToolCallEventData, ToolCallStatus, ToolResultEventData, ToolResultStatus},
};
use aionui_common::now_ms;
use aionui_conversation::stream_relay::StreamRelay;
use aionui_db::models::ConversationRow;
use aionui_db::{
    IConversationRepository, IUserRepository, MessagePageDirection, MessagePageParams, SqliteConversationRepository,
    SqliteUserRepository, init_database_memory,
};
use serde_json::json;
use tokio::sync::broadcast;

#[tokio::test]
async fn run_acp_tool_call_update_without_insert_creates_placeholder() {
    let db = init_database_memory().await.unwrap();
    let user_repo = SqliteUserRepository::new(db.pool().clone());
    let user = user_repo.create_user("user-1", "hash").await.unwrap();
    let user_id = user.id.clone();
    let repo = Arc::new(SqliteConversationRepository::new(db.pool().clone()));
    repo.create(&ConversationRow {
        id: "conv-1".into(),
        user_id: user_id.clone(),
        name: "test".into(),
        r#type: "acp".into(),
        extra: "{}".into(),
        model: None,
        status: Some("running".into()),
        source: Some("aionui".into()),
        channel_chat_id: None,
        pinned: false,
        pinned_at: None,
        created_at: now_ms(),
        updated_at: now_ms(),
        project_id: None,
        folder_id: None,
        name_source: None,
    })
    .await
    .unwrap();

    let bus = Arc::new(aionui_realtime::BroadcastEventBus::new(64));
    let (tx, _) = broadcast::channel(64);
    let relay = StreamRelay::new(
        "conv-1".into(),
        "asst-1".into(),
        "turn-1".into(),
        user_id.clone(),
        repo.clone(),
        bus,
    );
    let rx = tx.subscribe();

    tx.send(AgentStreamEvent::ToolResult(ToolResultEventData {
        call_id: "atc-late".into(),
        status: ToolResultStatus::Completed,
        session_id: Some("sess-1".into()),
        name: Some("Read".into()),
        input: None,
        output: Some("done".into()),
        raw_output: Some(json!("done")),
        content: None,
        locations: None,
        meta: None,
    }))
    .unwrap();
    tx.send(AgentStreamEvent::RunComplete(FinishEventData::default()))
        .unwrap();

    relay.consume(rx).await;

    let messages = repo
        .list_messages_page(
            &user_id,
            "conv-1",
            &MessagePageParams {
                limit: 20,
                direction: MessagePageDirection::InitialLatest,
            },
        )
        .await
        .unwrap()
        .items;
    assert!(messages.iter().any(|m| m.id == "atc-late" && m.r#type == "tool_call"));
}

#[tokio::test]
async fn run_acp_tool_call_late_initial_event_merges_with_update_placeholder() {
    let db = init_database_memory().await.unwrap();
    let user_repo = SqliteUserRepository::new(db.pool().clone());
    let user = user_repo.create_user("user-1", "hash").await.unwrap();
    let user_id = user.id.clone();
    let repo = Arc::new(SqliteConversationRepository::new(db.pool().clone()));
    repo.create(&ConversationRow {
        id: "conv-1".into(),
        user_id: user_id.clone(),
        name: "test".into(),
        r#type: "acp".into(),
        extra: "{}".into(),
        model: None,
        status: Some("running".into()),
        source: Some("aionui".into()),
        channel_chat_id: None,
        pinned: false,
        pinned_at: None,
        created_at: now_ms(),
        updated_at: now_ms(),
        project_id: None,
        folder_id: None,
        name_source: None,
    })
    .await
    .unwrap();

    let bus = Arc::new(aionui_realtime::BroadcastEventBus::new(64));
    let (tx, _) = broadcast::channel(64);
    let relay = StreamRelay::new(
        "conv-1".into(),
        "asst-1".into(),
        "turn-1".into(),
        user_id.clone(),
        repo.clone(),
        bus,
    );
    let rx = tx.subscribe();

    tx.send(AgentStreamEvent::ToolResult(ToolResultEventData {
        call_id: "atc-out-of-order".into(),
        status: ToolResultStatus::Completed,
        session_id: Some("sess-1".into()),
        name: None,
        input: None,
        output: Some("exit 0".into()),
        raw_output: Some(json!("exit 0")),
        content: None,
        locations: None,
        meta: None,
    }))
    .unwrap();
    tx.send(AgentStreamEvent::ToolCall(ToolCallEventData {
        call_id: "atc-out-of-order".into(),
        name: "Bash".into(),
        args: json!({"command": "echo hi"}),
        status: ToolCallStatus::Running,
        input: Some(json!({"command": "echo hi"})),
        output: None,
        description: None,
    }))
    .unwrap();
    tx.send(AgentStreamEvent::RunComplete(FinishEventData::default()))
        .unwrap();

    relay.consume(rx).await;

    let messages = repo
        .list_messages_page(
            &user_id,
            "conv-1",
            &MessagePageParams {
                limit: 20,
                direction: MessagePageDirection::InitialLatest,
            },
        )
        .await
        .unwrap()
        .items;
    let msg = messages
        .iter()
        .find(|m| m.id == "atc-out-of-order" && m.r#type == "tool_call")
        .expect("tool call row should be persisted");
    assert_eq!(msg.status.as_deref(), Some("finish"));

    let content: serde_json::Value = serde_json::from_str(&msg.content).unwrap();
    assert_eq!(content["status"], "completed");
    assert_eq!(content["name"], "Bash");
    assert_eq!(content["input"]["command"], "echo hi");
    assert_eq!(content["raw_output"], "exit 0");
}
