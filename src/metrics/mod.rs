//! Live server metrics — collection, storage, and the live-hub publish
//! (ADMIN_SEPARATION_PLAN Phase 4, Step C4).
//!
//! Two concerns live here:
//!
//! 1. **Collection** (`host`, `docker`): scrape one snapshot of the system. The
//!    host module parses `/proc` and `/sys` directly (paths overridable via
//!    `HOST_PROC` / `HOST_SYS` so the app can read host metrics from inside a
//!    container). The docker module shells out to `docker stats` via `kls-agent`.
//!
//! 2. **Storage** (`storage`): write samples into `metric_sample` / `docker_stat`
//!    (see `sql/1.sql`) and read them back for the dashboard endpoints.
//!
//! A single background task ([`spawn_collector`]) ties these together, scraping
//! every 30 s and publishing a compact snapshot to `/ws` subscribers on the
//! `metrics` topic — the hub's **first real publisher**. A second task
//! ([`spawn_pruner`]) trims samples older than 30 days hourly.
//!
//! **Threshold alerts are deferred**: the monolith's `alerts` sub-module fires a
//! Discord webhook via the alert-sink Seam (`has_any_alert_sink`/`send_alert`),
//! which lands in Vantage with the alerts slice — `scrape_once` will call it
//! then.

pub mod docker;
mod host;
pub mod routes;
mod storage;

pub use docker::DockerStat;
pub use host::Sample;
pub use storage::{fetch_current, fetch_docker_history, fetch_history, CurrentView, DockerHistoryPoint, HistoryPoint};

use std::time::Duration;
use tracing::{debug, error};

use crate::AppState;

/// How often the collector scrapes /proc, /sys and `docker stats`.
pub const SCRAPE_INTERVAL: Duration = Duration::from_secs(30);

/// How long samples are kept before pruning.
pub const RETENTION: time::Duration = time::Duration::days(30);

/// Spawns the background scrape task. Runs forever; logs and continues on error.
pub fn spawn_collector(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SCRAPE_INTERVAL);
        // Skip the immediate-fire on the first tick — we want a sane delay after
        // startup before the first scrape.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await; // consume the immediate tick

        loop {
            interval.tick().await;
            if let Err(e) = scrape_once(&state).await {
                error!(error = %e, "metrics scrape failed");
            }
        }
    });
}

/// Spawns the hourly pruner that drops samples older than [`RETENTION`].
pub fn spawn_pruner(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        interval.tick().await; // consume immediate
        loop {
            interval.tick().await;
            if let Err(e) = storage::prune_older_than(&state.db, RETENTION).await {
                error!(error = %e, "metric prune failed");
            }
        }
    });
}

async fn scrape_once(state: &AppState) -> anyhow::Result<()> {
    // Heartbeat so every scrape attempt is visible in the log file. Debug level
    // since it fires every SCRAPE_INTERVAL and would otherwise spam the log.
    debug!(target: "metrics", "scrape: starting");

    let sample = host::collect().await.map_err(|e| {
        tracing::error!(target: "metrics", error = %e, "host::collect failed");
        e
    })?;
    let containers = docker::collect().await.unwrap_or_else(|e| {
        tracing::warn!(target: "metrics", error = %e, "docker::collect failed (continuing)");
        Vec::new()
    });
    // This scrape is the only `docker stats` the box should normally run: publish
    // it so the /metrics and /docker request handlers read a snapshot instead of
    // each spawning their own (see `docker::collect_cached`).
    docker::store(containers.clone()).await;
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();

    storage::insert_sample(&state.db, ts, &sample).await?;
    storage::insert_docker_stats(&state.db, ts, &containers).await?;

    // Push to /ws subscribers so live dashboards refresh without polling. We ship
    // a compact subset — enough for the tile row + container table. Charts still
    // use the /history endpoint.
    state.live_publish(
        "metrics",
        serde_json::json!({
            "ts": ts,
            "cpu_total": sample.cpu_total_pct(),
            "mem_used": sample.mem_used as i64,
            "mem_total": sample.mem_total as i64,
            "mem_used_pct": sample.mem_used_pct(),
            "disk_used": sample.disk_used as i64,
            "disk_total": sample.disk_total as i64,
            "disk_used_pct": sample.disk_used_pct(),
            "load_1": sample.load_1,
            "load_5": sample.load_5,
            "load_15": sample.load_15,
            "net_rx_bytes": sample.net_rx_bytes as i64,
            "net_tx_bytes": sample.net_tx_bytes as i64,
            "disk_read_bytes":  sample.disk_read_bytes as i64,
            "disk_write_bytes": sample.disk_write_bytes as i64,
            "disk_read_ops":  sample.disk_read_ops as i64,
            "disk_write_ops": sample.disk_write_ops as i64,
            "containers": containers,
        }),
    );

    debug!(target: "metrics", "scrape ok: cpu={:.1}% mem={:.1}% containers={}",
          sample.cpu_total_pct(), sample.mem_used_pct(), containers.len());
    Ok(())
}
