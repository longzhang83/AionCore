//! Persistence consumers — subscribers that mirror in-memory state to
//! durable storage (SQLite) without carrying business semantics.
//!
//! Today this layer only holds [`runtime_session_sync`], which drains
//! `RuntimeSessionEvent`s from a running ACP agent into the
//! `acp_session.session_config.runtime` row.

pub mod runtime_session_sync;

pub use runtime_session_sync::RuntimeSessionSyncService;
