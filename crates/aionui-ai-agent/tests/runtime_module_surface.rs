//! Compile-only smoke test for the runtime manager's public surface.
//!
//! During the Stage 1 refactor (splitting the runtime manager into smaller
//! submodules), this file pins the set of type names that must remain
//! reachable through `aionui_ai_agent::manager::runtime`. It proves nothing about
//! behaviour — only that the rename/move did not accidentally drop a public
//! export. Behavioural correctness is guarded by the byte-level diff of the
//! moved function bodies and by the stage's new targeted tests.
#![allow(dead_code, unused_imports)]

use aionui_ai_agent::manager::runtime::{
    CatalogForwarder, PermissionRouter, ReconcileAction, RuntimeAgentSession, RuntimeSessionEvent,
};
use aionui_ai_agent::shared_kernel::PersistedSessionState;

fn _surface_probe() {
    let _ = std::any::type_name::<RuntimeAgentSession>();
    let _ = std::any::type_name::<RuntimeSessionEvent>();
    let _ = std::any::type_name::<CatalogForwarder>();
    let _ = std::any::type_name::<PermissionRouter>();
    let _ = std::any::type_name::<PersistedSessionState>();
    let _ = std::any::type_name::<ReconcileAction>();
}

#[test]
fn public_surface_compiles() {
    // The real assertion is that this file compiled at all.
}
