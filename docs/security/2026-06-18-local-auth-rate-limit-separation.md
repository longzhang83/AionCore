---
date: 2026-06-18
type: security
project: /Users/zhanglong/Desktop/RSM智能体平台/AionCLI-rsm-iam-v0.1.29
tags: [auth, rate-limit, local-mode, webui]
status: active
---

# 本地认证状态接口与 internal admin 接口限流拆分

## 背景

本地桌面和 Web CLI 启动链路会高频轮询 `/api/auth/status`，随后访问
`/api/auth/internal/users/system` 与 `/api/auth/internal/users/system/credentials`。
原实现把这些本地 internal / WebUI admin 接口与匿名公共 API 绑定到同一个
`60 requests / minute / IP` 限流桶，导致状态探活先耗尽配额后，internal admin
接口直接返回 `{"success":false,"error":"Rate limited","code":"RATE_LIMITED"}`。

## 决策/变更内容

1. 保持登录失败限流不变，继续使用 `5 failed attempts / 15 minutes`。
2. 将公共匿名 API limiter 调整为 `300 requests / minute`，缓解本地状态轮询触发 429。
3. 新增 local admin limiter，给 local-only internal user 和 WebUI bootstrap/admin
   接口单独分配 `600 requests / minute`。
4. 路由层将 `/api/auth/status` 与 `/api/auth/internal/users*`、`/api/webui/*`
   拆到不同 limiter，避免共享同一桶。
5. 不新增日志；当前 429 响应和新增回归测试已足够定位该问题。

## 影响范围

- `crates/aionui-auth/src/rate_limit.rs` - 提升公共 API 默认阈值并新增 local admin limiter
- `crates/aionui-auth/src/routes.rs` - 拆分公共状态路由与 local admin/bootstrap 路由
- `crates/aionui-auth/tests/route_tests.rs` - 新增共享配额回归测试

## 验证结果

- `cargo fmt --all -- --check` ✅
- `cargo clippy -p aionui-auth -- -D warnings` ✅
- `cargo test -p aionui-auth` ✅
- `cargo test --workspace` ✅

## 后续行动

- [ ] 将同样的 limiter 拆分同步到仍保留旧认证路由实现的相邻 AionCLI 分支

## 更新记录

### 2026-06-18

**变更**: OIDC 成功跳转不再消耗认证失败限流配额。

**详情**:

- 根因定位到 `crates/aionui-auth/src/rate_limit.rs` 的 `auth_rate_limit_middleware`。
- 旧逻辑把所有非 `2xx` 响应都记为失败尝试；而 `/api/auth/oidc/login` 与
  `/api/auth/oidc/callback` 的成功路径本身就是 `307 Temporary Redirect`。
- 结果是一次正常的退出重登会至少消耗两次“失败”计数，连续 2-3 次就能耗尽
  `5 failed attempts / 15 minutes` 配额，随后 callback 直接返回 `429`。
- 修复后仅对 `4xx` client error 记录失败尝试，保留错误凭证/非法请求的保护，
  但不再把成功 redirect 当成失败。
- 未新增日志；现有 HTTP trace、RED/GREEN 回归测试和运行态重放已足够诊断。

**影响范围**:

- `crates/aionui-auth/src/rate_limit.rs` - auth limiter 只对 `4xx` 计数
- `crates/aionui-auth/tests/middleware_tests.rs` - 新增 `307` redirect 回归测试

**验证**:

- RED: `cargo test -p aionui-auth auth_rate_limit_skips_redirect_responses --test middleware_tests`
  失败，表现为第 3 次请求开始从预期 `307` 变成 `429`
- GREEN: 同一测试在修复后通过
- `cargo test -p aionui-auth` ✅
- `cargo build -p aionui-app --bin aioncore` ✅
- 重启 `aionui-25808` 后，连续 6 次请求
  `GET /api/auth/oidc/login?return_to=%2F` 全部返回 `307`
- `/tmp/aionui-authcenter-25808/logs/2026-06-18.aioncore.log` 中对应 6 次请求均记录为
  `status=307`，未再出现该重放场景下的 `429`
- `cargo clippy -p aionui-auth -- -D warnings` 未通过，阻塞点为
  `crates/aionui-api-types/src/auth.rs` 中已有的 `clippy::derivable_impls`，
  与本次限流修复无关
