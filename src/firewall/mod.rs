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
