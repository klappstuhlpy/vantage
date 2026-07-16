//! Lockout helpers: the expiry reaper + the backend block/unblock primitive.
//!
//! The monolith also had an *automatic* trigger (`register_failure`) that counted
//! recent `auth.login.fail` rows in `audit_log` and blocked the source IP once a
//! threshold was crossed. Vantage keeps no `audit_log` table (its login-failure
//! throttling is the in-memory per-IP [`crate::lockout`], Step B2), so that path
//! is intentionally absent here — the constants below are still surfaced on the
//! dashboard as informational "auto-lockout policy" numbers, and manual lockouts
//! plus the reaper carry the feature. Re-introducing an auto-block (driven off
//! the in-memory login lockout) is a later refinement.

use crate::AppState;

/// How many failed logins within the window would trigger an auto-lockout
/// (informational on the dashboard until the auto path is wired).
pub const DEFAULT_THRESHOLD: i64 = 8;
/// Lockout window for the failure count.
pub const DEFAULT_WINDOW_SECS: i64 = 600;
/// How long a single lockout lasts.
pub const DEFAULT_LOCKOUT_SECS: i64 = 60 * 60;

/// Releases every lockout whose `expires_at` has passed, removing the kernel
/// block for each. Runs on the firewall worker's one-minute tick.
pub async fn reap_expired(state: &AppState) -> anyhow::Result<usize> {
    let released = super::storage::release_expired(state).await?;
    let n = released.len();
    for ip in released {
        apply_backend_block(state, &ip, false).await;
    }
    Ok(n)
}

/// Add (`add = true`) or remove a kernel block for `ip` via the detected
/// backend. A no-op when no backend is configured or the backend has no lockout
/// command (e.g. `Disabled`).
pub async fn apply_backend_block(state: &AppState, ip: &str, add: bool) {
    let Some(backend) = state.firewall_backend() else {
        return;
    };
    let Some(argv) = backend.lockout_command(ip, add) else {
        return;
    };
    if let Err(e) = backend.exec(argv.clone()).await {
        tracing::warn!(error = %e, ?argv, "firewall backend exec failed");
    }
}
