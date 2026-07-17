//! Firewall management — a visual frontend for `nftables` / `ufw` / `iptables`,
//! the second **Seam A** runtime handle to land in Vantage's `AppState` (after
//! the docker client).
//!
//! The backend is detected at startup by probing each binary in turn (the first
//! that responds wins; the operator can force one via `firewall_backend` in
//! `config.json`). Rules live in `firewall_rule` (our SQLite mirror) and are
//! applied by shelling out through the typed `kls-agent` boundary.
//!
//! **Adaptation vs. the monolith:** the monolith's *automatic* lockout counted
//! recent `auth.login.fail` rows in its `audit_log` table and blocked the source
//! IP. Vantage has no `audit_log` table — login-failure throttling is the
//! in-memory per-IP [`crate::lockout`] (Step B2) — so that audit-driven path is
//! dropped here. What remains is the manual lockout list + the expiry reaper;
//! wiring the in-memory login lockout to also add a firewall block is a later
//! refinement.
pub mod backend;
pub mod lockout;
pub mod routes; // HTTP handlers for this admin feature (see main.rs router)
pub mod storage;
pub mod sync;

pub use backend::{Backend, BackendKind};
pub use storage::{FirewallRule, LockoutRow};

use std::time::Duration;

use tracing::{error, info};

use crate::AppState;

/// Rolls back the rules an armed apply added (§11.1).
///
/// Apply only ever *adds* to the host — it never removes a disabled rule — so its
/// whole effect is the set of rules it pushed, and undoing it is removing exactly
/// those. That is why the rollback is expressed in terms of the already-tested
/// [`Backend::remove`] rather than a raw ruleset snapshot: it works on every
/// backend, handle lookups and all, and it cannot revert more than the apply did.
///
/// Best-effort per rule: one that is already gone (an operator lifted it by hand)
/// is not an error, it is the state the rollback wanted. The outcome is audited so
/// "the firewall reverted itself at 3am" is a fact with a row behind it.
pub async fn revert_applied(state: &AppState, rules: &[FirewallRule]) {
    let Some(backend) = state.firewall_backend() else {
        return;
    };
    let mut removed = 0usize;
    let mut errors: Vec<String> = Vec::new();
    for rule in rules {
        match backend.remove(rule).await {
            Ok(_) => removed += 1,
            Err(e) => {
                tracing::warn!(id = rule.id, error = %e, "revert: could not remove an applied rule from the host");
                errors.push(format!("rule {}: {e}", rule.id));
            }
        }
    }
    crate::audit::system_event("firewall.apply.reverted", "revert-timer")
        .detail(serde_json::json!({ "removed": removed, "errors": &errors }))
        .ok(errors.is_empty())
        .record(&state.db)
        .await;
}

/// Hooks the firewall background tasks:
///   * lockout reaper — releases expired auto/manual blocks every minute.
pub fn spawn_workers(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            match lockout::reap_expired(&state).await {
                Ok(n) if n > 0 => info!(count = n, "firewall: released {n} expired lockouts"),
                Ok(_) => {}
                Err(e) => error!(error = %e, "firewall: lockout reaper failed"),
            }
        }
    });
}
