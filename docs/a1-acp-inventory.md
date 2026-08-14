<!--
A1 AionCore Acp* 依赖盘点（V3 中性事件迁移准备）
来源: codex app-server (approvalPolicy=never, 只读)
会话: 019fff61-b66f-7f43-9f61-0c09e1a06f2d
基线: codex/rsm-backend-sync-v0.1.63 @ 1ef89709
日期: 2026-08-14

关键前提（codex 自述）: codebase-memory 索引未指向本工作区（旧路径），按回退规则改用 rg 精确检索。
-->

# Codex ACP 代码盘点

## 结论摘要

源码显示：Codex 已经不走旧 `AcpAgentManager`/`AcpProtocol` 包装，而是被明确路由到基于官方 app-server JSON-RPC 的 `CodexSessionBackend → SessionBackend → SessionAgentTask` 路径：

- 路由定义：`crates/aionui-ai-agent/src/factory/acp.rs:25-46`
- 强制 direct-CLI、禁止回退 ACP manager：`crates/aionui-ai-agent/src/factory/acp.rs:93-100`
- Codex 后端定义：`crates/aionui-session/src/backend/codex_conn.rs:657`
- `SessionBackend` 实现：`crates/aionui-session/src/backend/codex_conn.rs:3550`
- 转换为应用事件：`crates/aionui-ai-agent/src/session_agent.rs:2331`、`:3886`

因此 V3 的准确目标应是：清理遗留的 ACP 命名、DTO 和 `AgentStreamEvent::Acp*` 前端兼容包装，而不是再次替换 Codex 传输层。

---

## 1、5. 全部 `Acp*` 类型及 Runtime 中性映射

共找到 44 个真实 Rust 类型。没有 `Acp*` trait、type alias 或 union。

说明：“建议事件”严格使用给定词汇；管理器、存储行、连接等非事件类型另附建议中性类型名，避免把基础设施误命名成事件。

### 会话、连接与基础设施

| 当前类型 | 种类 | 定义 | 建议事件族 | 建议中性类型名 |
|---|---|---|---|---|
| `AcpAgentManager` | struct | `crates/aionui-ai-agent/src/manager/acp/agent.rs:512` | `SessionInfo` | `RuntimeAgentManager` |
| `AcpConnection` | struct | `crates/aionui-session/src/backend/acp_conn.rs:56` | `SessionInfo` | `RuntimeConnection` |
| `AcpSessionBackend` | struct | `crates/aionui-session/src/backend/acp_conn.rs:292` | `SessionInfo` | `RuntimeSessionBackend` |
| `AcpReaderState` | struct | `crates/aionui-session/src/backend/acp_conn.rs:896` | `SessionInfo` | `RuntimeReaderState` |
| `AcpWakeRecipe` | struct | `crates/aionui-session/src/backend/acp_conn.rs:950` | `SessionInfo` | `RuntimeWakeRecipe` |
| `AcpProtocol` | struct | `crates/aionui-ai-agent/src/protocol/acp.rs:137` | `SessionInfo` | `RuntimeProtocolDriver` |
| `AcpConnectionPhase` | enum | `crates/aionui-ai-agent/src/protocol/acp.rs:87` | `SessionInfo`；关闭时 `RunComplete` | `RuntimeConnectionPhase` |
| `AcpStartupConnection` | struct | `crates/aionui-ai-agent/src/manager/acp/agent.rs:90` | `SessionInfo` | `RuntimeStartupConnection` |
| `AcpSession` | struct | `crates/aionui-ai-agent/src/manager/acp/session.rs:74` | `SessionInfo` | `RuntimeSession` |
| `AcpSessionParams` | struct | `crates/aionui-ai-agent/src/factory/acp_assembler.rs:22` | `SessionInfo` | `RuntimeSessionParams` |
| `AcpSessionBuildContext` | struct | `crates/aionui-ai-agent/src/session_context.rs:49` | `SessionInfo` | `RuntimeSessionBuildContext` |
| `AcpSessionRow` | struct | `crates/aionui-db/src/models/acp_session.rs:9` | `SessionInfo` | `RuntimeSessionRow` |
| `AcpSessionSyncService` | struct | `crates/aionui-ai-agent/src/persistence/acp_session_sync.rs:32` | `SessionInfo` | `RuntimeSessionSyncService` |
| `AcpSessionEvent` | enum | `crates/aionui-ai-agent/src/manager/acp/agent_event_tracker.rs:27` | 按 variant 拆为 `SessionInfo` / `ModeInfo` / `ModelInfo` / `ConfigOption` / `ContextUsage` | `RuntimeSessionEvent` |
| `AcpSkillManager` | struct | `crates/aionui-ai-agent/src/capability/skill_manager/mod.rs:47` | `ConfigOption` | `RuntimeSkillManager` |
| `AcpLaunchPolicyInput` | struct | `crates/aionui-ai-agent/src/factory/acp_launch_policy.rs:12` | `ConfigOption` | `RuntimeLaunchPolicyInput` |

### API、配置和 MCP DTO

| 当前类型 | 种类 | 定义 | 建议事件族 | 建议中性类型名 |
|---|---|---|---|---|
| `AcpBuildExtra` | struct | `crates/aionui-api-types/src/agent_build_extra.rs:65` | `ConfigOption` | `RuntimeBuildConfig` |
| `AcpEnvResponse` | struct | `crates/aionui-api-types/src/acp.rs:24` | `ConfigOption` | `RuntimeEnvResponse` |
| `AcpConfigSelectOptionDto` | struct | `crates/aionui-api-types/src/acp.rs:65` | `ConfigOption` | `RuntimeConfigSelectOptionDto` |
| `AcpConfigOptionDto` | struct | `crates/aionui-api-types/src/acp.rs:77` | `ConfigOption` | `RuntimeConfigOptionDto` |
| `AcpModelInfo` | struct | `crates/aionui-api-types/src/agent_build_extra.rs:135` | `ModelInfo` | `RuntimeModelInfo` |
| `AcpSessionMcpServer` | enum | `crates/aionui-mcp/src/session_injection.rs:32` | `ConfigOption` | `RuntimeSessionMcpServer` |
| `AcpMcpCapabilities` | struct | `crates/aionui-mcp/src/session_injection.rs:64` | `ConfigOption` | `RuntimeMcpCapabilities` |
| `AcpPromptHookWarningPayload` | struct | `crates/aionui-api-types/src/acp_prompt_hook.rs:7` | `PromptHookWarning` | `PromptHookWarningPayload` |

### ToolCall / ToolResult

| 当前类型 | 种类 | 定义 | 建议映射 |
|---|---|---|---|
| `AcpToolCallEventData` | struct | `crates/aionui-ai-agent/src/protocol/events/tool_call.rs:28` | 按状态拆成 `ToolCall` / `ToolResult` |
| `AcpToolCallUpdateData` | struct | `crates/aionui-ai-agent/src/protocol/events/tool_call.rs:36` | 按 update kind 拆成 `ToolCall` / `ToolResult` |
| `AcpToolCallSessionUpdateKind` | enum | `crates/aionui-ai-agent/src/protocol/events/tool_call.rs:58` | `ToolCall`；终态 update 为 `ToolResult` |
| `AcpToolCallStatus` | enum | `crates/aionui-ai-agent/src/protocol/events/tool_call.rs:65` | `Pending/InProgress → ToolCall`；`Completed/Failed → ToolResult` |
| `AcpToolCallKind` | enum | `crates/aionui-ai-agent/src/protocol/events/tool_call.rs:74` | `ToolCall` |
| `AcpToolCallContentItem` | enum | `crates/aionui-ai-agent/src/protocol/events/tool_call.rs:82` | `ToolResult` |
| `AcpToolCallTextBlock` | struct | `crates/aionui-ai-agent/src/protocol/events/tool_call.rs:95` | `ToolResult` |
| `AcpToolCallTextBlockType` | enum | `crates/aionui-ai-agent/src/protocol/events/tool_call.rs:103` | `ToolResult` |
| `AcpToolCallLocationItem` | struct | `crates/aionui-ai-agent/src/protocol/events/tool_call.rs:108` | `ToolCall` 或 `ToolResult`，随所属 payload |

这里最值得改的是把当前“一个 update DTO 同时表达开始和结果”的设计拆开。现有中性 `SessionEvent` 已经这样做了：

- `SessionEvent::ToolCall`：`crates/aionui-session/src/event.rs:94`
- `SessionEvent::ToolResult`：`crates/aionui-session/src/event.rs:126`

### Approval

| 当前类型 | 种类 | 定义 | 建议映射 |
|---|---|---|---|
| `AcpPermissionEventData` | enum | `crates/aionui-ai-agent/src/protocol/events/permission.rs:15` | `Request → ApprovalRequest`；`Confirmation → ApprovalComplete` |
| `AcpPermissionRequestData` | struct | `crates/aionui-ai-agent/src/protocol/events/permission.rs:21` | `ApprovalRequest` |
| `AcpPermissionToolCall` | struct | `crates/aionui-ai-agent/src/protocol/events/permission.rs:31` | `ApprovalRequest` |
| `AcpPermissionOptionData` | struct | `crates/aionui-ai-agent/src/protocol/events/permission.rs:52` | `ApprovalRequest` |
| `AcpPermissionOptionKind` | enum | `crates/aionui-ai-agent/src/protocol/events/permission.rs:62` | `ApprovalRequest` |

现有中性源事件也已分开：

- `SessionEvent::Permission`：`crates/aionui-session/src/event.rs:232`
- `SessionEvent::PermissionResolved`：`crates/aionui-session/src/event.rs:277`

### 错误、诊断和方言信号

| 当前类型 | 种类 | 定义 | 建议映射 |
|---|---|---|---|
| `AcpError` | enum | `crates/aionui-ai-agent/src/protocol/error.rs:95` | `RunError` |
| `AcpSendFailure` | enum | `crates/aionui-ai-agent/src/manager/acp/error_mapping.rs:6` | `RunError` |
| `AcpStartupConnectError` | enum | `crates/aionui-ai-agent/src/manager/acp/agent.rs:123` | `RunError` |
| `AcpLogSummary` | struct | `crates/aionui-ai-agent/src/protocol/acp.rs:1035` | `RunError` 的诊断元数据 |
| `AcpDialectSignalKind` | enum | `crates/aionui-ai-agent/src/protocol/events/mod.rs:174` | `SessionEnd → RunComplete`；`TokenPressure → ContextUsage` |
| `AcpDialectSignalData` | struct | `crates/aionui-ai-agent/src/protocol/events/mod.rs:212` | 应拆成 `RunComplete` / `ContextUsage` |

### `AgentStreamEvent` 中不是类型、但同样需要迁移的 `Acp*` variants

定义：`crates/aionui-ai-agent/src/protocol/events/mod.rs:28`

| 当前 variant | 行号 | 建议中性事件 |
|---|---:|---|
| `AcpToolCall` | 34 | `ToolCall` / `ToolResult` |
| `AcpPermission` | 40 | `ApprovalRequest` / `ApprovalComplete` |
| `AcpModelInfo` | 52 | `ModelInfo` |
| `AcpModeInfo` | 53 | `ModeInfo` |
| `AcpConfigOption` | 54 | `ConfigOption` |
| `AcpSessionInfo` | 55 | `SessionInfo` |
| `AcpContextUsage` | 56 | `ContextUsage` |
| `AcpTerminalOutput` | 61 | `TerminalOutput` |
| `AcpPromptHookWarning` | 62 | `PromptHookWarning` |
| `AcpDialectSignal` | 113 | `RunComplete` / `ContextUsage` |

已有 `AgentStreamEvent::Error` 和 `Finish` 位于 `:65-66`，V3 可直接语义化为 `RunError` 和 `RunComplete`。

文档里另有三个代码块形式的伪定义，不是编译类型：

- `crates/aionui-team/docs/phase1/backend-audit.md:272`
- `crates/aionui-team/docs/phase1/interface-contracts.md:77`
- `crates/aionui-team/docs/phase1/interface-contracts.md:887`

---

## 2. `aionrs` / `antigravity` crate 引用位置

### AionRS 外部 crates

根 workspace 声明：

- `Cargo.toml:62-67`
- `crates/aionui-ai-agent/Cargo.toml:39-44`
- `crates/aionui-app/Cargo.toml:43`

锁定来源为 `aionrs.git` tag `v0.2.10`。`Cargo.lock` package 起始位置：

- `aion-agent:118`
- `aion-compact:149`
- `aion-config:161`
- `aion-mcp:186`
- `aion-memory:207`
- `aion-process:221`
- `aion-protocol:232`
- `aion-providers:245`
- `aion-skills:274`
- `aion-tools:301`
- `aion-types:323`
- `workspace-hack:7067`

直接 Rust crate-path 引用：

- `crates/aionui-ai-agent/src/services/provider_health.rs:7-11,337`
- `crates/aionui-ai-agent/src/factory/aionrs_model_settings_test.rs:1-2`
- `crates/aionui-ai-agent/src/factory/aionrs.rs:4-7,433,435`
- `crates/aionui-ai-agent/src/capability/backend_output_sink.rs:1`
- `crates/aionui-ai-agent/src/capability/backend_protocol_sink.rs:3-4,112`
- `crates/aionui-ai-agent/src/capability/image_input.rs:4`
- `crates/aionui-ai-agent/src/capability/image_input_test.rs:1`
- `crates/aionui-ai-agent/src/types.rs:4-5,161,163`
- `crates/aionui-ai-agent/src/manager/aionrs/agent.rs:8-16`
- `crates/aionui-ai-agent/src/manager/aionrs/agent_test.rs:7`
- `crates/aionui-ai-agent/src/manager/aionrs/content.rs:1`
- `crates/aionui-ai-agent/src/manager/aionrs/content_test.rs:1`
- `crates/aionui-ai-agent/src/manager/aionrs/history_sanitize.rs:34`
- `crates/aionui-ai-agent/src/manager/aionrs/history_sanitize_test.rs:2`
- `crates/aionui-ai-agent/src/manager/aionrs/error.rs:1-2`

内部 `aionrs` module 引用：

- `crates/aionui-mcp/src/adapters/mod.rs:1,11`
- `crates/aionui-mcp/tests/file_adapter_integration.rs:248`
- `crates/aionui-ai-agent/src/services/provider_health.rs:19`
- `crates/aionui-ai-agent/src/agent_task.rs:21`
- `crates/aionui-ai-agent/src/manager/mod.rs:2`
- `crates/aionui-ai-agent/src/factory/mod.rs:5,82`
- `crates/aionui-ai-agent/src/factory/aionrs.rs:24`
- `crates/aionui-ai-agent/tests/agent_types_integration.rs:12`
- `crates/aionui-app/src/bootstrap/tracing_init.rs:300`

### Antigravity

没有名为 `antigravity` 或 `aionui-antigravity` 的 Cargo crate，也没有对应外部 dependency。它是两个内部模块：

Session 后端模块：

- `crates/aionui-session/src/backend/mod.rs:12`
- `crates/aionui-session/src/backend/mod.rs:23`
- 内部测试引用：`crates/aionui-session/src/backend/antigravity/translate.rs:361`
- 版本模块说明：`crates/aionui-session/src/backend/cli_version.rs:16`

AI agent factory 模块：

- `crates/aionui-ai-agent/src/factory/mod.rs:6`
- `crates/aionui-ai-agent/src/factory/mod.rs:83`
- `crates/aionui-ai-agent/src/factory/acp.rs:79`

主要跨模块消费入口：

- `crates/aionui-ai-agent/src/session_agent.rs:1509,1578`
- `crates/aionui-ai-agent/src/session_context.rs:45,63`
- `crates/aionui-conversation/src/session_context.rs:7,208-211`
- `crates/aionui-session/src/lib.rs:56,62`
- `crates/aionui-app/src/router/antigravity_hook.rs:17-104`
- `crates/aionui-app/src/commands/cmd_antigravity_hook.rs:15-102`
- `crates/aionui-api-types/src/antigravity_hook.rs:21-125`

---

## 3. 四个核心抽象的位置

| 符号 | 定义 | 实现 |
|---|---|---|
| `SessionBackend` | `crates/aionui-session/src/backend/mod.rs:70` | 生产 impl：Antigravity `backend/antigravity/conn.rs:735`；ACP `backend/acp_conn.rs:2231`；Claude `backend/claude_conn.rs:2610`；Codex `backend/codex_conn.rs:3550` |
| `CodexSessionBackend` | `crates/aionui-session/src/backend/codex_conn.rs:657` | inherent impl `:901`、`:4296`；`SessionBackend` impl `:3550`；`Drop` impl `:4302` |
| `SessionAgentTask` | `crates/aionui-ai-agent/src/session_agent.rs:330` | inherent impl `:362`、`:1278`；`IAgentTask` impl `:1080`；事件 pump `:2331`；中性事件转换 `:3886` |
| `AgentStreamEvent` | `crates/aionui-ai-agent/src/protocol/events/mod.rs:28` | 无独立 `impl AgentStreamEvent`；主要构造/投影位于 `session_agent.rs:3886-4233`，旧 ACP SDK 翻译位于 `protocol/events/translate.rs:20` |

关键链路：

```text
CodexSessionBackend
  → SessionBackend::events()
  → SessionEvent
  → SessionAgentTask::spawn_event_pump()
  → translate_event()
  → AgentStreamEvent
```

`SessionEvent` 本身定义在 `crates/aionui-session/src/event.rs:48`，已经具备绝大多数 Runtime 中性语义。

---

## 4. 测试、fixture、snapshot、数据字典与开发数据

### 显式测试文件

ACP manager / protocol：

- `crates/aionui-ai-agent/tests/acp_agent_integration.rs:1-325`
- `crates/aionui-ai-agent/tests/acp_error_public.rs:1-8`
- `crates/aionui-ai-agent/tests/acp_module_surface.rs:11-16`
- `crates/aionui-ai-agent/tests/prompt_pipeline_integration.rs:4-222`
- `crates/aionui-ai-agent/tests/skill_manager_integration.rs:19-281`
- `crates/aionui-ai-agent/tests/factory_provider_integration.rs:4-84`
- `crates/aionui-ai-agent/tests/agent_types_integration.rs:182`

Session aggregate / snapshot：

- `crates/aionui-ai-agent/src/manager/acp/session_tests.rs:1-1505`
- `crates/aionui-ai-agent/src/manager/acp/session_close_tests.rs:1`
- `crates/aionui-ai-agent/src/manager/acp/session_config_snapshot_tests.rs:11-467`

Conversation / relay：

- `crates/aionui-conversation/tests/acp_tool_call_persistence.rs:5-157`
- `crates/aionui-conversation/src/service_test.rs:17-8296`
- `crates/aionui-conversation/src/stream_relay.rs:1525-2663`
- `crates/aionui-conversation/src/session_context.rs:235-879`

Session/MCP/API/App/Team：

- `crates/aionui-session/tests/terminate_delegation.rs:4-57`
- `crates/aionui-session/src/backend/acp_conn.rs:2846-4026`
- `crates/aionui-mcp/tests/session_injection_integration.rs:10-509`
- `crates/aionui-mcp/src/session_injection.rs:291-704`
- `crates/aionui-api-types/src/acp.rs:244,252,333`
- `crates/aionui-api-types/src/acp_prompt_hook.rs:20-36`
- `crates/aionui-api-types/src/agent_build_extra.rs:168-181`
- `crates/aionui-app/tests/common/mod.rs:203-236`
- `crates/aionui-app/tests/agent_integration_e2e.rs:589,613`
- `crates/aionui-team/tests/session_service_integration.rs:9-1418`
- `crates/aionui-team/src/test_utils.rs:355,942,950`

### Fixture

没有 ACP fixture 文件。

现有 `crates/aionui-session/tests/fixtures/` 全部是 Claude/通用 trace NDJSON，未发现任何 `Acp*` 类型引用。`acp_agent_integration.rs:43-123` 使用测试代码内嵌的 mock shell/JSON-RPC，而不是独立 fixture。

### Snapshot

- 唯一 ACP snapshot 专用位置：`crates/aionui-ai-agent/src/manager/acp/session_config_snapshot_tests.rs`
- 它是普通 Rust snapshot-state 单元测试，不是 `insta` 的 `.snap` 文件。
- 仓库中未发现引用 `Acp*` 的 `.snap` 文件。

### 数据字典与开发数据

- 未发现 data dictionary 文件引用 `Acp*` 类型。
- 未发现 `dev-data/`、`data/`、`seed/` 等开发数据目录引用这些类型。
- `crates/aionui-db/migrations/029_add_mimo_code_builtin_acp_agent.sql:7` 仅在注释中提到外部 `AcpCommand`，不是本 workspace 的 Rust 类型引用。

---

## V3 建议落点

最优终态是以 `aionui-session::SessionEvent` 为唯一 Runtime 中性事件层：

1. Codex app-server wire 只在 `CodexSessionBackend` 内解析。
2. 后端统一产出 `SessionEvent`。
3. 将 `SessionAgentTask::translate_event()` 中残留的 `AgentStreamEvent::Acp*` 投影替换成中性 variants。
4. 拆开两个混合 union：
   - `AcpToolCall*` → `ToolCall` / `ToolResult`
   - `AcpPermissionEventData` → `ApprovalRequest` / `ApprovalComplete`
5. 最后再迁移 API DTO、数据库 `acp_session` 命名和旧 `AcpAgentManager`，避免先改存储名却仍保留协议耦合。

本次仅执行只读检索；`git status --short` 为空，没有修改、commit 或 push。

---

## 6. V3 A1 clean-cut 第 3 步进度（2026-08-14）

状态：已实现并验证。

- `AgentStreamEvent` 外层 variant 已去除 `Acp*`：工具事件使用 `ToolCall` / `ToolResult`，审批使用 `ApprovalRequest` / `ApprovalComplete`，其余 catalog、session、usage、terminal、hook、error、finish 事件使用冻结的 Runtime 中性名称。
- `SessionAgentTask::translate_event()` 已由测试固定：`SessionEvent::ToolCall → AgentStreamEvent::ToolCall`，`SessionEvent::Permission → AgentStreamEvent::ApprovalRequest`。
- 方言信号在产生点完成中性投影：`SessionEnd → RunComplete`，`TokenPressure → ContextUsage { kind: "token_pressure" }`；消费方不再匹配 `AgentStreamEvent::AcpDialectSignal`。
- `AcpToolCall*` 与 `AcpPermissionEventData` payload 类型保持不拆，符合本切片边界；下一步再按 tool update/status 和 permission inner kind 完成内部 DTO 拆分。
- WebSocket stream tag 随 variant 更新为 snake_case 中性名称；Rust 侧 relay、后台流、channel、cron、team、测试消费方已同步。
- 可观测性：现有 stream event-kind 日志已同步中性名称；本次仅改事件命名/投影，现有终止、错误与 relay 日志足够，无需新增日志点。

验证：

- RED：新增投影测试首次编译以 `E0599` 失败，证明 `AgentStreamEvent::ApprovalRequest` 尚不存在。
- GREEN：`cargo test -p aionui-ai-agent -p aionui-session -p aionui-conversation -p aionui-channel -p aionui-team -p aionui-cron` 通过。
- `cargo fmt --all -- --check` 通过。
- `cargo clippy --workspace --all-targets -- -D warnings` 通过。

未纳入本切片：API DTO、DB `acp_session`、旧 `AcpAgentManager`、aionrs/antigravity 删除，以及 `AcpToolCall*` / `AcpPermissionEventData` 内部拆分。
