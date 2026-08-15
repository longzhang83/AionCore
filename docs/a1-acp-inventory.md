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

---

## 7. V3 A1 clean-cut 第 4 步进度（2026-08-14）

状态：已实现并验证。

- 工具生命周期 payload 已按语义拆分：`Pending` / `InProgress` 的 ACP tool call 与 update 投影为 `AgentStreamEvent::ToolCall(ToolCallEventData)`；`Completed` / `Failed` 投影为 `AgentStreamEvent::ToolResult(ToolResultEventData)`，终态 status 由只能表达 `Completed` / `Failed` 的 `ToolResultStatus` 承载。
- `SessionAgentTask::translate_event()` 已同步：`SessionEvent::ToolCall → ToolCall`，`SessionEvent::ToolResult → ToolResult`。工具名称 ledger、后台 workflow live-card 屏蔽、relay 与持久化消费方均显式处理独立终态。
- 旧混合工具 wrapper `AcpToolCallEventData` / `AcpToolCallUpdateData` 及 `AcpToolCallSessionUpdateKind` 已删除。工具起始与结果现在合并写入同一个 `tool_call` message row，乱序的晚到起始帧不会把已完成状态回退为运行中。
- 审批 payload 已按语义拆分：`ApprovalRequest` 只接受 `ApprovalRequestEventData`，`ApprovalComplete` 只接受 `Confirmation`；旧 untagged `AcpPermissionEventData::{Request, Confirmation}` union 已删除。
- 可观测性：现有 stream event-kind、relay persistence error 与 session pump 日志已覆盖本次路由；本切片没有引入新的不可观察分支，因此无需新增生产日志。

验证：

- RED（工具运行时）：`pending_session_tool_call_maps_to_tool_call` 首次运行失败，实际值为 `ToolResult(AcpToolCallEventData { status: Pending, ... })`，exit 101。
- RED（审批编译时）：类型约束测试首次以 `E0425` 失败，证明 `ApprovalRequestEventData` 尚不存在，exit 101。
- GREEN：`cargo test -p aionui-ai-agent -p aionui-session -p aionui-conversation -p aionui-channel -p aionui-team -p aionui-cron` 通过，exit 0。
- `cargo fmt --all -- --check` 通过，exit 0。
- `cargo clippy --workspace --all-targets -- -D warnings` 通过，exit 0。

未纳入本切片：API DTO、DB `acp_session`、旧 `AcpAgentManager`、aionrs/antigravity 删除。其余叶子 `Acp*` 类型命名继续留给第 5 步统一迁移。

---

## 8. V3 A1 clean-cut 第 5 步进度（2026-08-15）

状态：已实现并验证。

- 19 个存活叶子 `Acp*` 类型按本盘点建议统一迁移为 Runtime 中性命名，共 351 处、35 个文件：
  - API DTO：`AcpConfigOptionDto -> RuntimeConfigOptionDto`、`AcpConfigSelectOptionDto -> RuntimeConfigSelectOptionDto`、
    `AcpEnvResponse -> RuntimeEnvResponse`、`AcpBuildExtra -> RuntimeBuildConfig`、`AcpModelInfo -> RuntimeModelInfo`、
    `AcpPromptHookWarningPayload -> PromptHookWarningPayload`（去前缀）；
  - MCP 注入：`AcpSessionMcpServer -> RuntimeSessionMcpServer`、`AcpMcpCapabilities -> RuntimeMcpCapabilities`；
  - 工具叶子：`AcpToolCallKind -> ToolCallKind`、`AcpToolCallContentItem -> ToolResultContentItem`、
    `AcpToolCallTextBlock(Type) -> ToolResultTextBlock(Type)`、`AcpToolCallLocationItem -> ToolLocationItem`；
  - 审批叶子：`AcpPermissionOptionData -> ApprovalOptionData`、`AcpPermissionOptionKind -> ApprovalOptionKind`、
    `AcpPermissionToolCall -> ApprovalToolCall`；
  - 方言信号叶子（旧驱动内部）：`AcpDialectSignalKind/Data -> DialectSignalKind/Data`（仅去前缀）。
- 命名冲突修正：`AcpToolCallStatus`（Pending/InProgress/Completed/Failed 协议态）不得并入既有中性
  `ToolCallStatus`（Running/Completed/Error/Canceled fold 层态）--两者 wire 词汇不同，`tool_call.rs` 内注释
  已明确禁止混用。本步改名为 `ProtocolToolCallStatus`，保持两个词汇独立。
- 纯重命名切片：serde 属性均在字段/variant 级，类型名不进 wire；`agent_type = "acp"`、
  `conversation type = "acp"`、`acp_args` 等 wire/DB 值不在本切片范围（留给 API DTO/DB 命名步骤）。
- wrapper 删除范围类型未动（`AcpAgentManager`、`AcpProtocol`、`acp_conn.rs` 后端、`AcpSessionRow` 等），
  留给后续删除与 DB 步骤。

验证：

- `cargo check --workspace --all-targets` 通过。
- `cargo test -p aionui-ai-agent -p aionui-session -p aionui-conversation -p aionui-channel -p aionui-team -p aionui-cron` 通过（1302 passed / 0 failed，exit 0）。
- `cargo fmt --all -- --check` 通过。
- `cargo clippy --workspace --all-targets -- -D warnings` 通过。

未纳入本切片：API DTO 模块/文件级重命名（`api-types/src/acp.rs`）、DB `acp_session` 命名、旧 `AcpAgentManager`
与 aionrs/antigravity 删除、wire 层 `"acp"` 字符串清理。

---

## 9. V3 A1 clean-cut Slice 1 进度（2026-08-15）

状态：已实现并验证。

- `manager/acp/` 的叶子模块已迁移到中性 Runtime / Agent / PromptHook / Approval 词汇：
  `mode_normalize -> runtime_mode`、`config_options -> runtime_config`、
  `config_option_catalog -> runtime_config_catalog`、`permission_router -> approval_router`、
  `stderr_error_extractor -> runtime_error_extractor`、`hooks -> prompt_hook`、
  `legacy_session_model -> legacy_runtime_model`、`catalog_forwarder -> runtime_catalog_forwarder`、
  `agent_reconcile -> agent_reconciler`。
- factory 叶子模块已迁移：`acp_assembler -> runtime_assembler`、
  `acp_launch_policy -> runtime_launch_policy`。
- 局部 DTO 已按既有映射迁移：`AcpSessionParams -> RuntimeSessionParams`、
  `AcpLaunchPolicyInput -> RuntimeLaunchPolicyInput`；所有 crate 内导入和测试引用同步更新。
- 这是纯重命名切片：未修改 wire/DB 值、serde 属性、函数逻辑、控制流或行为；现有日志足够，本切片未增加日志。

验证：

- `cargo check -p aionui-ai-agent` 通过（exit 0）。
- `cargo test -p aionui-ai-agent --lib manager::` 通过（340 passed / 0 failed，exit 0）。

未纳入本切片：clean-cut Slice 2–6 的任何变更。

---

## 10. V3 A1 clean-cut Slice 2 进度（2026-08-15）

状态：已实现并验证。

- 协议适配层迁移到中性 Runtime 词汇：`acp.rs -> runtime.rs`、
  `acp_dialect.rs -> runtime_dialect.rs`、`error.rs -> runtime_error.rs`、
  `send_error.rs -> runtime_send_error.rs`。
- 公开与内部类型同步改名：`AcpProtocol -> RuntimeProtocol`、
  `AcpError -> RuntimeError`、`AgentSendError -> RuntimeSendError`，并将
  `AgentError::Acp` 改为 `AgentError::Runtime`。
- ACP 在线协议、`initialize` 握手和 `agent-client-protocol` SDK 的事实性说明、
  外部错误码与既有诊断事件保持不变；这是纯命名迁移，不改变 wire/DB 值、协议行为或控制流。
- 未新增日志：既有 ACP 诊断事件仍提供该适配层的生产可观测性。

验证：

- `cargo check -p aionui-ai-agent` 通过（exit 0）。
- `cargo test -p aionui-ai-agent protocol::` 通过（145 passed / 0 failed）。
- `cargo test -p aionui-ai-agent --test acp_error_public` 通过（3 passed / 0 failed）。

未纳入本切片：`manager/acp`、factory、API DTO、DB 和 wire 中的 ACP 命名仍保留给后续 slice。

---

## 11. V3 A1 clean-cut Slice 3a 进度（2026-08-15）

状态：已实现并验证。

- manager 辅助模块迁移为 Runtime 词汇：`agent_close -> runtime_close`、
  `agent_event_tracker -> runtime_event_tracker`、`agent_session_flow -> runtime_session_flow`。
- 跟踪器定义的内部领域事件改名：`AcpSessionEvent -> RuntimeSessionEvent`；
  `agent.rs`、`session.rs`、测试与持久化消费者仅同步模块导入和符号调用，未改其内部结构或控制流。
- 持久化消费者迁移：`acp_session_sync -> runtime_session_sync`、
  `AcpSessionSyncService -> RuntimeSessionSyncService`，并更新 crate 公开导出与 factory 注入类型。
- ACP SDK、`session/new` / `session/load` 等线上协议事实性注释，以及既有 `AcpAgentManager` /
  `AcpSession` 和数据库 `acp_session` 命名均保留；本切片未改变 wire、DB、serde 或运行行为。
- 未新增日志：这是一项可由编译和现有 manager 单元测试覆盖的纯重命名，现有日志足够。

验证：

- `/Users/zhanglong/.cargo/bin/cargo check -p aionui-ai-agent` 通过（exit 0）。
- `/Users/zhanglong/.cargo/bin/cargo test -p aionui-ai-agent --lib manager::` 通过（340 passed / 0 failed，exit 0）。
- `/Users/zhanglong/.cargo/bin/cargo fmt --all -- --check` 与 `git diff --check` 通过。

未纳入本切片：`AcpAgentManager`、`AcpSession`、数据库 `acp_session`、ACP wire/SDK 术语，以及 Slice 3b 及之后的迁移。

---

## 12. V3 A1 clean-cut Slice 3b 进度（2026-08-15）

状态：已实现并验证。

- manager 核心类型改名：`AcpAgentManager -> RuntimeAgentManager`、
  `AcpSession -> RuntimeAgentSession`；`RuntimeSessionEvent` 保持 Slice 3a 的名称。
- `agent.rs` 的本地启动辅助类型改名：`AcpStartupConnection -> RuntimeStartupConnection`、
  `AcpStartupConnectError -> RuntimeStartupConnectError`。所有 crate 内类型引用、测试与
  `manager/acp/mod.rs` re-export 已同步。
- `manager/acp/` 目录、数据库/持久化 `acp_session` 命名、DB 列名以及 ACP wire/SDK 的
  事实性术语均保持不变；未改变 wire、DB、serde、控制流或日志。
- 未新增日志：这是由编译与既有 manager 单元测试充分覆盖的纯类型重命名。

验证：

- `/Users/zhanglong/.cargo/bin/cargo check -p aionui-ai-agent` 通过（exit 0）。
- `GOCACHE=/tmp/aionui-gocache /Users/zhanglong/.cargo/bin/cargo test -p aionui-ai-agent --lib manager::`
  通过（340 passed / 0 failed，exit 0）。测试期间有既有 npm 缓存权限警告，未影响测试结果。
- `git diff --check` 通过；全 crate `src/` 已无旧核心类型或启动辅助类型标识。

未纳入本切片：`AcpSessionBuildContext`、`AcpSkillManager`、API DTO、数据库 `acp_session`、
ACP wire/SDK 术语以及后续 clean-cut slices。

---

## 13. V3 A1 clean-cut Slice 6 进度（2026-08-15）

状态：已实现并验证（全 workspace 格式门禁仍受 4 处既有未格式化文件阻塞）。

- 集成测试文件已收口：`acp_agent_integration.rs -> runtime_agent_integration.rs`、
  `acp_module_surface.rs -> runtime_module_surface.rs`、
  `acp_error_public.rs -> runtime_error_public.rs`。
- 测试导入、局部变量、函数名及 module-surface 探针已改用 Runtime 名称；仅协议 fixture 字段和
  既有 `AgentInstance::Acp` 兼容 variant 保留。
- 旧内部流程注释改为中性“previous runtime flow”；真实 ACP wire/SDK、前端兼容帧、数据库命名和
  `AcpSkillManager` 等尚未纳入本 slice 的类型保留。
- 未新增日志：这是纯命名与注释收口，现有编译和测试信号足够。

验证：

- `/Users/zhanglong/.cargo/bin/cargo check -p aionui-ai-agent` 通过（exit 0）。
- `GOCACHE=/tmp/aionui-gocache /Users/zhanglong/.cargo/bin/cargo test -p aionui-ai-agent`
  通过（exit 0；测试期间既有 npm 缓存权限警告未影响结果）。
- `git diff --check` 通过；`cargo fmt --all -- --check` 仅报告本 slice 外的
  `src/agent_task.rs`、`src/manager/mod.rs` 和 `src/manager/runtime/agent.rs` 既有格式差异。

未纳入本切片：`AgentInstance::Acp`、`AgentError::Acp`（已在 Slice 2 改为 `Runtime`）、
`AcpSendFailure::Acp` 及 wire/SDK、DB、兼容帧、`AcpSkillManager` 命名。
