//! Health checks / uptime monitoring — an internal Uptime-Kuma. Moved from the
//! monolith's `admin/health/` (ADMIN_SEPARATION_PLAN Phase 4, Step C5a).
//!
//! Architecture:
//!   * `checker` — runs one probe (http / tcp / keyword / ssl), returns a
//!     [`CheckOutcome`].  Sync-free, async-only. Ported **verbatim**.
//!   * `storage` — persistence: targets CRUD, samples ring buffer pruning,
//!     incident open/close, aggregations for the dashboard. Ported **verbatim**
//!     (reads `admin.db` through [`AppState::database`]).
//!   * this file — orchestration: `spawn_monitor` schedules per-target probe
//!     loops; `run_check_now` performs a one-off probe and records the result.
//!
//! Down/recovery alerts ride the incident bookkeeping: `run_check_now` calls
//! `AppState::send_alert` exactly when an incident opens or closes, so the
//! open-incident dedup is also the alert dedup. The live `/ws` publishing
//! (this is the hub's **second publisher**, after metrics) is unchanged from
//! the monolith.
pub mod routes; // HTTP handlers for this admin feature (see main.rs router)

pub mod checker;
pub mod storage;

pub use checker::{CheckOutcome, CheckStatus};
pub use storage::{HealthTarget, IncidentRow, SampleRow, TargetSummary, UptimeStats};

use crate::AppState;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{error, info};

/// How often the scheduler re-reads the target list from the DB.  New
/// targets added through the UI become live within this window.
const RELOAD_INTERVAL: Duration = Duration::from_secs(30);

/// How many consecutive failing samples trigger a new incident.  Set to 1
/// so users see incidents immediately — Uptime Kuma uses the same default.
const INCIDENT_THRESHOLD: i64 = 1;

/// Prune samples older than this on each loop tick.  30 days is plenty
/// for uptime stats and incident summaries.
pub const SAMPLE_RETENTION: Duration = Duration::from_secs(60 * 60 * 24 * 30);

/// Per-target task handle.  The scheduler reconciles this map against the
/// DB on every reload so adding/disabling/deleting a target in the UI
/// stops/starts the corresponding probe loop without a restart.
type TaskMap = Arc<Mutex<HashMap<i64, tokio::task::JoinHandle<()>>>>;

pub fn spawn_monitor(state: AppState) {
    let tasks: TaskMap = Arc::new(Mutex::new(HashMap::new()));

    // Background pruner — clean old samples once an hour.
    let prune_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            if let Err(e) = storage::prune_old_samples(&prune_state, SAMPLE_RETENTION).await {
                error!(error = %e, "health: sample pruning failed");
            }
        }
    });

    // Reconciler — keeps the per-target probe loops in sync with the DB.
    tokio::spawn(async move {
        // Initial small delay so the DB pool is warm.
        tokio::time::sleep(Duration::from_secs(2)).await;
        loop {
            if let Err(e) = reconcile(&state, &tasks).await {
                error!(error = %e, "health: reconcile failed");
            }
            tokio::time::sleep(RELOAD_INTERVAL).await;
        }
    });
}

async fn reconcile(state: &AppState, tasks: &TaskMap) -> anyhow::Result<()> {
    let targets = storage::list_targets(state).await?;
    let active_ids: std::collections::HashSet<i64> = targets.iter().filter(|t| t.enabled).map(|t| t.id).collect();

    let mut tasks_guard = tasks.lock().await;

    // Stop tasks whose target was deleted or disabled.
    let stale: Vec<i64> = tasks_guard
        .keys()
        .copied()
        .filter(|id| !active_ids.contains(id))
        .collect();
    for id in stale {
        if let Some(handle) = tasks_guard.remove(&id) {
            handle.abort();
            info!(target_id = id, "health: probe loop stopped");
        }
    }

    // Start tasks for newly added/enabled targets.
    for target in targets {
        if !target.enabled {
            continue;
        }
        if tasks_guard.contains_key(&target.id) {
            continue;
        }
        let bg_state = state.clone();
        let target_id = target.id;
        let interval_secs = target.interval_seconds.max(10) as u64;
        let handle = tokio::spawn(async move {
            // Stagger the very first probe so we don't slam a backend if
            // many targets have the same interval.
            tokio::time::sleep(Duration::from_secs((target_id as u64) % 7)).await;
            loop {
                if let Err(e) = run_check_now(&bg_state, target_id).await {
                    error!(target_id, error = %e, "health: probe failed");
                }
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
            }
        });
        tasks_guard.insert(target.id, handle);
        info!(target_id = target.id, name = %target.name, "health: probe loop started");
    }
    Ok(())
}

/// Run one probe for a target and persist the result.  Public so the
/// "Check now" button can invoke it directly.  Returns the outcome so
/// the route can echo it back to the client.
pub async fn run_check_now(state: &AppState, target_id: i64) -> anyhow::Result<CheckOutcome> {
    let target = storage::get_target(state, target_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("target not found"))?;

    let outcome = checker::run(&target, &state.client).await;

    storage::record_sample(state, target_id, &outcome).await?;

    // An `ssl` probe is the only place the box learns a certificate's remaining
    // life, so the expiry ladder is driven from here rather than from a second
    // timer that would have to re-probe the same endpoint to find out.
    if let Some(days) = outcome.ssl_days_left {
        crate::certs::note_expiry(state, &target, days).await;
    }

    let prev_open = storage::get_open_incident(state, target_id).await?;

    match (&outcome.status, prev_open) {
        (CheckStatus::Up, Some(inc)) => {
            // Recovered → close the incident.
            storage::close_incident(state, inc.id).await?;
            state.send_alert(recovery_alert(&target, &outcome));
            broadcast_event(state, target_id, "recovered", &outcome);
        }
        (CheckStatus::Down | CheckStatus::Degraded, Some(inc)) => {
            // Extend the open incident.
            storage::extend_incident(state, inc.id, outcome.error.as_deref()).await?;
        }
        (CheckStatus::Down | CheckStatus::Degraded, None) => {
            // Open a new incident once we hit the threshold.
            let consecutive = storage::consecutive_failures(state, target_id, INCIDENT_THRESHOLD).await?;
            if consecutive >= INCIDENT_THRESHOLD {
                let status_label = match outcome.status {
                    CheckStatus::Down => "down",
                    CheckStatus::Degraded => "degraded",
                    CheckStatus::Up => "up",
                };
                storage::open_incident(state, target_id, status_label, outcome.error.as_deref()).await?;
                state.send_alert(incident_alert(&target, &outcome));
                broadcast_event(state, target_id, "down", &outcome);
            }
        }
        (CheckStatus::Up, None) => { /* steady state */ }
    }

    state.live_publish(
        "health",
        json!({
            "target_id": target_id,
            "status": outcome.status_str(),
            "latency_ms": outcome.latency_ms,
            "status_code": outcome.status_code,
            "ssl_days_left": outcome.ssl_days_left,
            "error": outcome.error,
        }),
    );

    Ok(outcome)
}

fn broadcast_event(state: &AppState, target_id: i64, event: &'static str, outcome: &CheckOutcome) {
    state.live_publish(
        "health.event",
        json!({
            "target_id": target_id,
            "event": event,
            "status": outcome.status_str(),
            "latency_ms": outcome.latency_ms,
            "error": outcome.error,
        }),
    );
}

/// Discord-shaped alert for an incident opening. The neutral sinks derive
/// their text from this via `AlertNotification::from_discord_value`.
fn incident_alert(target: &HealthTarget, outcome: &CheckOutcome) -> serde_json::Value {
    json!({
        "username": "vantage",
        "embeds": [{
            "title": format!("\u{1f534} {} is {}", target.name, outcome.status_str()),
            "description": outcome.error.clone().unwrap_or_else(|| "probe failed".to_owned()),
            "color": if matches!(outcome.status, CheckStatus::Down) { 0xef4444u32 } else { 0xf59e0bu32 },
            "fields": [{ "name": "Target", "value": target.target.clone(), "inline": true }],
        }]
    })
}

/// Discord-shaped alert for an incident closing.
fn recovery_alert(target: &HealthTarget, outcome: &CheckOutcome) -> serde_json::Value {
    json!({
        "username": "vantage",
        "embeds": [{
            "title": format!("\u{1f7e2} {} recovered", target.name),
            "description": match outcome.latency_ms {
                Some(ms) => format!("Probe succeeded in {ms} ms."),
                None => "Probe succeeded.".to_owned(),
            },
            "color": 0x22c55eu32,
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> HealthTarget {
        HealthTarget {
            id: 1,
            name: "blog".into(),
            kind: "http".into(),
            target: "https://example.com".into(),
            config_json: "{}".into(),
            interval_seconds: 60,
            timeout_ms: 5000,
            degraded_ms: 1000,
            enabled: true,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn outcome(status: CheckStatus, error: Option<&str>) -> CheckOutcome {
        CheckOutcome {
            status,
            latency_ms: Some(42),
            status_code: None,
            error: error.map(str::to_owned),
            ssl_days_left: None,
        }
    }

    #[test]
    fn incident_alert_names_target_and_reason() {
        let v = incident_alert(&target(), &outcome(CheckStatus::Down, Some("timeout")));
        let embed = &v["embeds"][0];
        assert_eq!(embed["title"], "\u{1f534} blog is down");
        assert_eq!(embed["description"], "timeout");
        assert_eq!(embed["color"], 0xef4444u32);
        assert_eq!(embed["fields"][0]["value"], "https://example.com");
    }

    #[test]
    fn degraded_incident_alerts_amber_with_fallback_reason() {
        let v = incident_alert(&target(), &outcome(CheckStatus::Degraded, None));
        let embed = &v["embeds"][0];
        assert_eq!(embed["title"], "\u{1f534} blog is degraded");
        assert_eq!(embed["description"], "probe failed");
        assert_eq!(embed["color"], 0xf59e0bu32);
    }

    #[test]
    fn recovery_alert_is_green_and_reports_latency() {
        let v = recovery_alert(&target(), &outcome(CheckStatus::Up, None));
        let embed = &v["embeds"][0];
        assert_eq!(embed["title"], "\u{1f7e2} blog recovered");
        assert_eq!(embed["description"], "Probe succeeded in 42 ms.");
        assert_eq!(embed["color"], 0x22c55eu32);
    }
}
