---
date: 2026-08-15
type: progress
project: rsm-agent-backend-a1
tags: [clean-cut, runtime, path-closure]
status: active
---

# Clean-cut Slice 4b: Runtime path closure

## Change

Completed the path-only portion of Slice 4 in `aionui-ai-agent` without changing
symbols, control flow, wire behavior, database state, or integration-test files.

- `src/factory/acp.rs` moved to `src/factory/runtime.rs`; the temporary
  `#[path = "acp.rs"]` bridge was removed.
- `src/manager/acp/` moved to `src/manager/runtime/` (19 Rust files).
- Crate source imports and module exports now use `factory::runtime` and
  `manager::runtime`.

## Verification

- `/Users/zhanglong/.cargo/bin/cargo check -p aionui-ai-agent` passed (exit 0).
- `GOCACHE=/tmp/aionui-gocache /Users/zhanglong/.cargo/bin/cargo test -p
  aionui-ai-agent --lib` passed (932 passed / 0 failed, exit 0). The shell's
  bare `cargo` command was unavailable because `PATH` omitted its directory;
  the verified command uses the same Cargo binary explicitly.
- `git diff --check` passed; a source-tree search found no old
  `factory::acp`, `manager::acp`, or temporary bridge reference.

## Follow-up

Integration-test files named `tests/acp_*` remain untouched for Slice 6.
