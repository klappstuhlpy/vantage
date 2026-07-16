//! Persistence + dashboard reads for health monitoring.

use crate::AppState;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use time::OffsetDateTime;

use super::checker::{CheckOutcome, CheckStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthTarget {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub target: String,
    pub config_json: String,
    pub interval_seconds: i64,
    pub timeout_ms: i64,
    pub degraded_ms: i64,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl HealthTarget {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            name: row.get("name")?,
            kind: row.get("kind")?,
            target: row.get("target")?,
            config_json: row.get("config_json")?,
            interval_seconds: row.get("interval_seconds")?,
            timeout_ms: row.get("timeout_ms")?,
            degraded_ms: row.get("degraded_ms")?,
            enabled: row.get::<_, i64>("enabled")? != 0,
            created_at: row.get("created_at")?,
        })
    }
}

/// Latest sample + uptime/incident metadata used by the dashboard listing.
#[derive(Debug, Clone, Serialize)]
pub struct TargetSummary {
    #[serde(flatten)]
    pub target: HealthTarget,
    pub last_status: Option<String>,
    pub last_latency_ms: Option<i64>,
    pub last_ssl_days_left: Option<i64>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_check: Option<OffsetDateTime>,
    pub uptime_24h: f64,
    pub avg_latency_24h: Option<f64>,
    pub open_incident_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SampleRow {
    pub id: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub status: String,
    pub latency_ms: Option<i64>,
    pub status_code: Option<i64>,
    pub error: Option<String>,
    pub ssl_days_left: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IncidentRow {
    pub id: i64,
    pub target_id: i64,
    pub target_name: Option<String>,
    pub status: String,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub ended_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
    pub sample_count: i64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct UptimeStats {
    pub uptime_24h: f64,
    pub uptime_7d: f64,
    pub uptime_30d: f64,
    pub avg_latency_ms: Option<f64>,
    pub p95_latency_ms: Option<f64>,
    pub total_samples: i64,
}

// ─── Targets ────────────────────────────────────────────────────────

pub async fn list_targets(state: &AppState) -> rusqlite::Result<Vec<HealthTarget>> {
    state
        .database()
        .call(|conn| -> rusqlite::Result<Vec<HealthTarget>> {
            let mut stmt = conn.prepare_cached(
                "SELECT id, name, kind, target, config_json, interval_seconds,
                        timeout_ms, degraded_ms, enabled, created_at
                 FROM health_target
                 ORDER BY name ASC",
            )?;
            let rows: rusqlite::Result<Vec<HealthTarget>> = stmt.query_map([], HealthTarget::from_row)?.collect();
            rows
        })
        .await
}

pub async fn get_target(state: &AppState, id: i64) -> rusqlite::Result<Option<HealthTarget>> {
    state
        .database()
        .call(move |conn| -> rusqlite::Result<Option<HealthTarget>> {
            let mut stmt = conn.prepare_cached(
                "SELECT id, name, kind, target, config_json, interval_seconds,
                        timeout_ms, degraded_ms, enabled, created_at
                 FROM health_target WHERE id = ?",
            )?;
            match stmt.query_row([id], HealthTarget::from_row) {
                Ok(t) => Ok(Some(t)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await
}

pub struct NewTarget {
    pub name: String,
    pub kind: String,
    pub target: String,
    pub config_json: String,
    pub interval_seconds: i64,
    pub timeout_ms: i64,
    pub degraded_ms: i64,
    pub enabled: bool,
}

pub async fn create_target(state: &AppState, target: NewTarget) -> rusqlite::Result<i64> {
    state
        .database()
        .call(move |conn| -> rusqlite::Result<i64> {
            conn.execute(
                "INSERT INTO health_target
                   (name, kind, target, config_json, interval_seconds,
                    timeout_ms, degraded_ms, enabled)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                rusqlite::params![
                    target.name,
                    target.kind,
                    target.target,
                    target.config_json,
                    target.interval_seconds,
                    target.timeout_ms,
                    target.degraded_ms,
                    if target.enabled { 1 } else { 0 },
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
}

pub async fn update_target(state: &AppState, id: i64, target: NewTarget) -> rusqlite::Result<usize> {
    state
        .database()
        .call(move |conn| -> rusqlite::Result<usize> {
            conn.execute(
                "UPDATE health_target SET
                    name = ?, kind = ?, target = ?, config_json = ?,
                    interval_seconds = ?, timeout_ms = ?, degraded_ms = ?, enabled = ?
                 WHERE id = ?",
                rusqlite::params![
                    target.name,
                    target.kind,
                    target.target,
                    target.config_json,
                    target.interval_seconds,
                    target.timeout_ms,
                    target.degraded_ms,
                    if target.enabled { 1 } else { 0 },
                    id,
                ],
            )
        })
        .await
}

pub async fn delete_target(state: &AppState, id: i64) -> rusqlite::Result<usize> {
    state
        .database()
        .call(move |conn| conn.execute("DELETE FROM health_target WHERE id = ?", [id]))
        .await
}

pub async fn set_enabled(state: &AppState, id: i64, enabled: bool) -> rusqlite::Result<usize> {
    state
        .database()
        .call(move |conn| {
            conn.execute(
                "UPDATE health_target SET enabled = ? WHERE id = ?",
                rusqlite::params![if enabled { 1 } else { 0 }, id],
            )
        })
        .await
}

// ─── Samples ────────────────────────────────────────────────────────

pub async fn record_sample(state: &AppState, target_id: i64, outcome: &CheckOutcome) -> rusqlite::Result<()> {
    let status = match outcome.status {
        CheckStatus::Up => "up",
        CheckStatus::Down => "down",
        CheckStatus::Degraded => "degraded",
    };
    let latency = outcome.latency_ms;
    let code = outcome.status_code;
    let err = outcome.error.clone();
    let ssl = outcome.ssl_days_left;
    state
        .database()
        .execute(
            "INSERT INTO health_check_sample
                (target_id, status, latency_ms, status_code, error, ssl_days_left)
             VALUES (?, ?, ?, ?, ?, ?)",
            (target_id, status, latency, code, err, ssl),
        )
        .await?;
    Ok(())
}

pub async fn list_samples(state: &AppState, target_id: i64, limit: i64) -> rusqlite::Result<Vec<SampleRow>> {
    state
        .database()
        .call(move |conn| -> rusqlite::Result<Vec<SampleRow>> {
            let mut stmt = conn.prepare_cached(
                "SELECT id, ts, status, latency_ms, status_code, error, ssl_days_left
                 FROM health_check_sample
                 WHERE target_id = ?
                 ORDER BY ts DESC, id DESC
                 LIMIT ?",
            )?;
            let rows: rusqlite::Result<Vec<SampleRow>> = stmt
                .query_map([target_id, limit], |row| {
                    Ok(SampleRow {
                        id: row.get(0)?,
                        ts: row.get(1)?,
                        status: row.get(2)?,
                        latency_ms: row.get(3)?,
                        status_code: row.get(4)?,
                        error: row.get(5)?,
                        ssl_days_left: row.get(6)?,
                    })
                })?
                .collect();
            rows
        })
        .await
}

pub async fn consecutive_failures(state: &AppState, target_id: i64, look_back: i64) -> rusqlite::Result<i64> {
    let limit = look_back.max(1);
    state
        .database()
        .call(move |conn| -> rusqlite::Result<i64> {
            let mut stmt = conn.prepare_cached(
                "SELECT status FROM health_check_sample
                 WHERE target_id = ?
                 ORDER BY ts DESC, id DESC
                 LIMIT ?",
            )?;
            let rows: Vec<String> = stmt
                .query_map([target_id, limit], |r| r.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect();
            let mut count = 0;
            for s in rows {
                if s == "up" {
                    break;
                }
                count += 1;
            }
            Ok(count)
        })
        .await
}

pub async fn prune_old_samples(state: &AppState, retain: Duration) -> rusqlite::Result<usize> {
    let secs = retain.as_secs() as i64;
    state
        .database()
        .call(move |conn| -> rusqlite::Result<usize> {
            let n = conn.execute(
                "DELETE FROM health_check_sample
                 WHERE ts < datetime('now', ?)",
                rusqlite::params![format!("-{secs} seconds")],
            )?;
            // Trim closed incidents older than the retention as well.
            conn.execute(
                "DELETE FROM health_incident
                 WHERE ended_at IS NOT NULL AND ended_at < datetime('now', ?)",
                rusqlite::params![format!("-{secs} seconds")],
            )?;
            Ok(n)
        })
        .await
}

// ─── Incidents ──────────────────────────────────────────────────────

pub async fn get_open_incident(state: &AppState, target_id: i64) -> rusqlite::Result<Option<IncidentRow>> {
    state
        .database()
        .call(move |conn| -> rusqlite::Result<Option<IncidentRow>> {
            let mut stmt = conn.prepare_cached(
                "SELECT id, target_id, status, started_at, ended_at, last_error, sample_count
                 FROM health_incident
                 WHERE target_id = ? AND ended_at IS NULL
                 ORDER BY started_at DESC LIMIT 1",
            )?;
            match stmt.query_row([target_id], |row| {
                Ok(IncidentRow {
                    id: row.get(0)?,
                    target_id: row.get(1)?,
                    target_name: None,
                    status: row.get(2)?,
                    started_at: row.get(3)?,
                    ended_at: row.get(4)?,
                    last_error: row.get(5)?,
                    sample_count: row.get(6)?,
                })
            }) {
                Ok(v) => Ok(Some(v)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await
}

pub async fn open_incident(
    state: &AppState,
    target_id: i64,
    status: &str,
    error: Option<&str>,
) -> rusqlite::Result<i64> {
    let status = status.to_string();
    let error = error.map(|s| s.to_string());
    state
        .database()
        .call(move |conn| -> rusqlite::Result<i64> {
            conn.execute(
                "INSERT INTO health_incident(target_id, status, last_error)
                 VALUES (?, ?, ?)",
                rusqlite::params![target_id, status, error],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
}

pub async fn extend_incident(state: &AppState, id: i64, error: Option<&str>) -> rusqlite::Result<usize> {
    let error = error.map(|s| s.to_string());
    state
        .database()
        .call(move |conn| -> rusqlite::Result<usize> {
            conn.execute(
                "UPDATE health_incident
                    SET sample_count = sample_count + 1,
                        last_error = COALESCE(?, last_error)
                  WHERE id = ?",
                rusqlite::params![error, id],
            )
        })
        .await
}

pub async fn close_incident(state: &AppState, id: i64) -> rusqlite::Result<usize> {
    state
        .database()
        .call(move |conn| -> rusqlite::Result<usize> {
            conn.execute(
                "UPDATE health_incident SET ended_at = CURRENT_TIMESTAMP WHERE id = ?",
                [id],
            )
        })
        .await
}

pub async fn list_incidents(
    state: &AppState,
    target_id: Option<i64>,
    limit: i64,
) -> rusqlite::Result<Vec<IncidentRow>> {
    state
        .database()
        .call(move |conn| -> rusqlite::Result<Vec<IncidentRow>> {
            let sql = if target_id.is_some() {
                "SELECT i.id, i.target_id, t.name, i.status, i.started_at, i.ended_at,
                        i.last_error, i.sample_count
                 FROM health_incident i
                 LEFT JOIN health_target t ON t.id = i.target_id
                 WHERE i.target_id = ?
                 ORDER BY i.started_at DESC
                 LIMIT ?"
            } else {
                "SELECT i.id, i.target_id, t.name, i.status, i.started_at, i.ended_at,
                        i.last_error, i.sample_count
                 FROM health_incident i
                 LEFT JOIN health_target t ON t.id = i.target_id
                 ORDER BY i.started_at DESC
                 LIMIT ?"
            };
            let mut stmt = conn.prepare(sql)?;
            let mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<IncidentRow> {
                Ok(IncidentRow {
                    id: row.get(0)?,
                    target_id: row.get(1)?,
                    target_name: row.get(2)?,
                    status: row.get(3)?,
                    started_at: row.get(4)?,
                    ended_at: row.get(5)?,
                    last_error: row.get(6)?,
                    sample_count: row.get(7)?,
                })
            };
            if let Some(id) = target_id {
                stmt.query_map(rusqlite::params![id, limit], mapper)?.collect()
            } else {
                stmt.query_map([limit], mapper)?.collect()
            }
        })
        .await
}

// ─── Aggregations ───────────────────────────────────────────────────

pub async fn uptime_stats(state: &AppState, target_id: i64) -> rusqlite::Result<UptimeStats> {
    state
        .database()
        .call(move |conn| -> rusqlite::Result<UptimeStats> {
            let pct = |window: &str| -> rusqlite::Result<(f64, i64)> {
                let mut stmt = conn.prepare_cached(&format!(
                    "SELECT
                       SUM(CASE WHEN status = 'up' OR status = 'degraded' THEN 1 ELSE 0 END) * 1.0
                       / NULLIF(COUNT(*), 0),
                       COUNT(*)
                     FROM health_check_sample
                     WHERE target_id = ? AND ts >= datetime('now', '-{window}')"
                ))?;
                stmt.query_row([target_id], |r| {
                    Ok((r.get::<_, Option<f64>>(0)?.unwrap_or(0.0), r.get::<_, i64>(1)?))
                })
            };
            let (uptime_24h, _) = pct("1 day")?;
            let (uptime_7d, _) = pct("7 day")?;
            let (uptime_30d, total) = pct("30 day")?;
            let avg_latency_ms: Option<f64> = conn
                .prepare_cached(
                    "SELECT AVG(latency_ms) FROM health_check_sample
                     WHERE target_id = ? AND latency_ms IS NOT NULL
                       AND ts >= datetime('now', '-1 day')",
                )?
                .query_row([target_id], |r| r.get(0))
                .ok()
                .flatten();

            // p95 via an ordered scan — fine for ~1k samples/day per target.
            let mut latencies: Vec<i64> = conn
                .prepare_cached(
                    "SELECT latency_ms FROM health_check_sample
                     WHERE target_id = ? AND latency_ms IS NOT NULL
                       AND ts >= datetime('now', '-1 day')
                     ORDER BY latency_ms ASC",
                )?
                .query_map([target_id], |r| r.get::<_, i64>(0))?
                .filter_map(Result::ok)
                .collect();
            let p95 = if latencies.is_empty() {
                None
            } else {
                latencies.sort_unstable();
                let idx = ((latencies.len() as f64) * 0.95) as usize;
                let idx = idx.min(latencies.len() - 1);
                Some(latencies[idx] as f64)
            };
            Ok(UptimeStats {
                uptime_24h,
                uptime_7d,
                uptime_30d,
                avg_latency_ms,
                p95_latency_ms: p95,
                total_samples: total,
            })
        })
        .await
}

/// The latest sample for one target, as the summary query returns it:
/// `(status, latency_ms, status_code, error, ssl_days_left, ts)`. A named alias
/// so the `list_summaries` closure signature stays readable (clippy).
type LastSample = (
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<OffsetDateTime>,
);

pub async fn list_summaries(state: &AppState) -> rusqlite::Result<Vec<TargetSummary>> {
    let targets = list_targets(state).await?;
    let mut out = Vec::with_capacity(targets.len());
    for target in targets {
        let id = target.id;
        let (last_status, last_latency, last_code, last_error_opt, last_ssl_days, last_check) = state
            .database()
            .call(move |conn| -> rusqlite::Result<LastSample> {
                let mut stmt = conn.prepare_cached(
                    "SELECT status, latency_ms, status_code, error, ssl_days_left, ts
                     FROM health_check_sample
                     WHERE target_id = ?
                     ORDER BY ts DESC, id DESC LIMIT 1",
                )?;
                match stmt.query_row([id], |r| {
                    Ok((
                        Some(r.get::<_, String>(0)?),
                        r.get::<_, Option<i64>>(1)?,
                        r.get::<_, Option<i64>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<i64>>(4)?,
                        Some(r.get::<_, OffsetDateTime>(5)?),
                    ))
                }) {
                    Ok(v) => Ok(v),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok((None, None, None, None, None, None)),
                    Err(e) => Err(e),
                }
            })
            .await?;
        let _ = (last_code, last_error_opt); // unused in summary

        let stats = uptime_stats(state, id).await?;
        let open = get_open_incident(state, id).await?;
        out.push(TargetSummary {
            target,
            last_status,
            last_latency_ms: last_latency,
            last_ssl_days_left: last_ssl_days,
            last_check,
            uptime_24h: stats.uptime_24h,
            avg_latency_24h: stats.avg_latency_ms,
            open_incident_id: open.map(|i| i.id),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::checker::{CheckOutcome, CheckStatus};
    use std::path::Path;

    /// A hermetic in-memory state running the real migrations — the health
    /// tables (`sql/2.sql`) are present, so the storage SQL is exercised end
    /// to end. `:memory:` forces a single connection (each such connection is
    /// its own database), which the pool guarantees.
    async fn mem_state() -> crate::AppState {
        crate::build_state_with(crate::config::Config::test_default(), Path::new(":memory:"))
            .await
            .expect("build state")
    }

    fn outcome(status: CheckStatus, latency: i64, error: Option<&str>) -> CheckOutcome {
        CheckOutcome {
            status,
            latency_ms: Some(latency),
            status_code: Some(200),
            error: error.map(|s| s.to_string()),
            ssl_days_left: None,
        }
    }

    fn http_target(name: &str) -> NewTarget {
        NewTarget {
            name: name.to_string(),
            kind: "http".to_string(),
            target: "https://example.com".to_string(),
            config_json: "{}".to_string(),
            interval_seconds: 60,
            timeout_ms: 5000,
            degraded_ms: 1000,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn target_crud_and_summary_roundtrip() {
        let state = mem_state().await;

        let id = create_target(&state, http_target("site")).await.unwrap();
        assert!(get_target(&state, id).await.unwrap().is_some());
        assert_eq!(list_targets(&state).await.unwrap().len(), 1);

        // Record an up then a down sample; the summary reflects the latest.
        record_sample(&state, id, &outcome(CheckStatus::Up, 42, None))
            .await
            .unwrap();
        record_sample(&state, id, &outcome(CheckStatus::Down, 90, Some("boom")))
            .await
            .unwrap();

        let summaries = list_summaries(&state).await.unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].last_status.as_deref(), Some("down"));

        let stats = uptime_stats(&state, id).await.unwrap();
        assert_eq!(stats.total_samples, 2);

        // Two consecutive non-up samples? Only the latest is down (the first was up),
        // so exactly one consecutive failure from the tail.
        assert_eq!(consecutive_failures(&state, id, 10).await.unwrap(), 1);

        // Delete cascades the samples away.
        assert_eq!(delete_target(&state, id).await.unwrap(), 1);
        assert!(list_targets(&state).await.unwrap().is_empty());
        assert!(list_samples(&state, id, 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn incident_open_extend_and_close() {
        let state = mem_state().await;
        let id = create_target(&state, http_target("api")).await.unwrap();

        assert!(get_open_incident(&state, id).await.unwrap().is_none());

        let inc = open_incident(&state, id, "down", Some("first")).await.unwrap();
        let open = get_open_incident(&state, id).await.unwrap().expect("open incident");
        assert_eq!(open.id, inc);
        assert_eq!(open.status, "down");

        extend_incident(&state, inc, Some("still down")).await.unwrap();
        let open = get_open_incident(&state, id).await.unwrap().unwrap();
        assert_eq!(open.sample_count, 2);
        assert_eq!(open.last_error.as_deref(), Some("still down"));

        close_incident(&state, inc).await.unwrap();
        assert!(get_open_incident(&state, id).await.unwrap().is_none());

        // The closed incident still lists (with an ended_at).
        let incidents = list_incidents(&state, Some(id), 10).await.unwrap();
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].ended_at.is_some());
    }
}
