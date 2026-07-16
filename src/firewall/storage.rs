//! Persistence layer for firewall rules and lockouts.

use crate::AppState;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: i64,
    pub action: String,
    pub direction: String,
    pub proto: String,
    pub source: Option<String>,
    pub port: Option<i64>,
    pub country: Option<String>,
    pub rate_per_s: Option<i64>,
    pub note: Option<String>,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub meta_json: Option<String>,
}

impl FirewallRule {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            action: row.get("action")?,
            direction: row.get("direction")?,
            proto: row.get("proto")?,
            source: row.get("source")?,
            port: row.get("port")?,
            country: row.get("country")?,
            rate_per_s: row.get("rate_per_s")?,
            note: row.get("note")?,
            enabled: row.get::<_, i64>("enabled")? != 0,
            created_at: row.get("created_at")?,
            meta_json: row.get("meta_json")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NewRule {
    pub action: String,
    pub direction: String,
    pub proto: String,
    pub source: Option<String>,
    pub port: Option<i64>,
    pub country: Option<String>,
    pub rate_per_s: Option<i64>,
    pub note: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockoutRow {
    pub id: i64,
    pub ip: String,
    pub reason: String,
    pub hit_count: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub locked_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub status: String,
}

impl LockoutRow {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            ip: row.get("ip")?,
            reason: row.get("reason")?,
            hit_count: row.get("hit_count")?,
            locked_at: row.get("locked_at")?,
            expires_at: row.get("expires_at")?,
            status: row.get("status")?,
        })
    }
}

pub async fn list_rules(state: &AppState) -> rusqlite::Result<Vec<FirewallRule>> {
    state
        .database()
        .call(|conn| -> rusqlite::Result<Vec<FirewallRule>> {
            let mut stmt = conn.prepare_cached(
                "SELECT id, action, direction, proto, source, port, country,
                        rate_per_s, note, enabled, created_at, meta_json
                 FROM firewall_rule
                 ORDER BY id DESC",
            )?;
            let rows: rusqlite::Result<Vec<_>> = stmt.query_map([], FirewallRule::from_row)?.collect();
            rows
        })
        .await
}

pub async fn get_rule(state: &AppState, id: i64) -> rusqlite::Result<Option<FirewallRule>> {
    state
        .database()
        .call(move |conn| -> rusqlite::Result<Option<FirewallRule>> {
            let mut stmt = conn.prepare_cached(
                "SELECT id, action, direction, proto, source, port, country,
                        rate_per_s, note, enabled, created_at, meta_json
                 FROM firewall_rule WHERE id = ?",
            )?;
            match stmt.query_row([id], FirewallRule::from_row) {
                Ok(r) => Ok(Some(r)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await
}

pub async fn create_rule(state: &AppState, rule: NewRule) -> rusqlite::Result<i64> {
    state
        .database()
        .call(move |conn| -> rusqlite::Result<i64> {
            conn.execute(
                "INSERT INTO firewall_rule
                   (action, direction, proto, source, port, country,
                    rate_per_s, note, enabled)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rusqlite::params![
                    rule.action,
                    rule.direction,
                    rule.proto,
                    rule.source,
                    rule.port,
                    rule.country,
                    rule.rate_per_s,
                    rule.note,
                    if rule.enabled { 1 } else { 0 },
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
}

/// Insert a rule that was imported from the live backend ruleset.  Unlike
/// [`create_rule`] this also records `meta_json` so the sync reconciler can
/// recognise (and later prune) rows it owns.
pub async fn create_imported_rule(state: &AppState, rule: NewRule, meta_json: String) -> rusqlite::Result<i64> {
    state
        .database()
        .call(move |conn| -> rusqlite::Result<i64> {
            conn.execute(
                "INSERT INTO firewall_rule
                   (action, direction, proto, source, port, country,
                    rate_per_s, note, enabled, meta_json)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rusqlite::params![
                    rule.action,
                    rule.direction,
                    rule.proto,
                    rule.source,
                    rule.port,
                    rule.country,
                    rule.rate_per_s,
                    rule.note,
                    if rule.enabled { 1 } else { 0 },
                    meta_json,
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
}

/// List rows previously imported from ufw, returning `(id, meta_json)` so the
/// reconciler can compare signatures and prune stale entries.
pub async fn list_imported_ufw(state: &AppState) -> rusqlite::Result<Vec<(i64, Option<String>)>> {
    state
        .database()
        .call(|conn| -> rusqlite::Result<Vec<(i64, Option<String>)>> {
            let mut stmt = conn.prepare_cached(
                "SELECT id, meta_json FROM firewall_rule
                 WHERE meta_json LIKE '%\"source\":\"ufw\"%'",
            )?;
            let rows: rusqlite::Result<Vec<_>> = stmt
                .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?)))?
                .collect();
            rows
        })
        .await
}

pub async fn delete_rule(state: &AppState, id: i64) -> rusqlite::Result<usize> {
    state
        .database()
        .call(move |conn| conn.execute("DELETE FROM firewall_rule WHERE id = ?", [id]))
        .await
}

pub async fn toggle_rule(state: &AppState, id: i64, enabled: bool) -> rusqlite::Result<usize> {
    state
        .database()
        .call(move |conn| {
            conn.execute(
                "UPDATE firewall_rule SET enabled = ? WHERE id = ?",
                rusqlite::params![if enabled { 1 } else { 0 }, id],
            )
        })
        .await
}

// ─── Lockouts ───────────────────────────────────────────────────────

pub async fn list_lockouts(state: &AppState, only_active: bool) -> rusqlite::Result<Vec<LockoutRow>> {
    state
        .database()
        .call(move |conn| -> rusqlite::Result<Vec<LockoutRow>> {
            let sql = if only_active {
                "SELECT id, ip, reason, hit_count, locked_at, expires_at, status
                 FROM firewall_lockout
                 WHERE status = 'active'
                 ORDER BY locked_at DESC LIMIT 200"
            } else {
                "SELECT id, ip, reason, hit_count, locked_at, expires_at, status
                 FROM firewall_lockout
                 ORDER BY locked_at DESC LIMIT 500"
            };
            let mut stmt = conn.prepare_cached(sql)?;
            let rows: rusqlite::Result<Vec<_>> = stmt.query_map([], LockoutRow::from_row)?.collect();
            rows
        })
        .await
}

// Only the monolith's audit-driven auto-lockout (dropped here — Vantage has no
// `audit_log` table; see `lockout.rs`) called this. Kept so the storage layer is
// a faithful port and the helper is ready when an auto-block path returns.
#[allow(dead_code)]
pub async fn find_active_lockout(state: &AppState, ip: &str) -> rusqlite::Result<Option<LockoutRow>> {
    let ip = ip.to_string();
    state
        .database()
        .call(move |conn| -> rusqlite::Result<Option<LockoutRow>> {
            let mut stmt = conn.prepare_cached(
                "SELECT id, ip, reason, hit_count, locked_at, expires_at, status
                 FROM firewall_lockout
                 WHERE ip = ? AND status = 'active'",
            )?;
            match stmt.query_row([ip], LockoutRow::from_row) {
                Ok(v) => Ok(Some(v)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await
}

pub async fn add_lockout(
    state: &AppState,
    ip: &str,
    reason: &str,
    duration_secs: Option<i64>,
) -> rusqlite::Result<i64> {
    let ip = ip.to_string();
    let reason = reason.to_string();
    state
        .database()
        .call(move |conn| -> rusqlite::Result<i64> {
            // Upsert: if there's already an active lockout for this IP,
            // just bump hit_count + extend.
            let existing: Option<i64> = conn
                .prepare_cached("SELECT id FROM firewall_lockout WHERE ip = ? AND status = 'active'")?
                .query_row([&ip], |r| r.get(0))
                .ok();
            if let Some(id) = existing {
                conn.execute(
                    "UPDATE firewall_lockout
                       SET hit_count = hit_count + 1,
                           expires_at = CASE WHEN ?1 IS NULL THEN expires_at
                                             ELSE datetime('now', ?2) END,
                           reason = ?3
                     WHERE id = ?4",
                    rusqlite::params![
                        duration_secs,
                        duration_secs.map(|s| format!("+{s} seconds")).unwrap_or_default(),
                        reason,
                        id,
                    ],
                )?;
                return Ok(id);
            }
            conn.execute(
                "INSERT INTO firewall_lockout(ip, reason, expires_at)
                 VALUES (?, ?, CASE WHEN ?3 IS NULL THEN NULL
                                    ELSE datetime('now', ?4) END)",
                rusqlite::params![
                    ip,
                    reason,
                    duration_secs,
                    duration_secs.map(|s| format!("+{s} seconds")).unwrap_or_default(),
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
}

pub async fn release_lockout(state: &AppState, id: i64) -> rusqlite::Result<usize> {
    state
        .database()
        .call(move |conn| conn.execute("UPDATE firewall_lockout SET status = 'released' WHERE id = ?", [id]))
        .await
}

pub async fn release_expired(state: &AppState) -> rusqlite::Result<Vec<String>> {
    state
        .database()
        .call(|conn| -> rusqlite::Result<Vec<String>> {
            let ips: Vec<String> = {
                let mut stmt = conn.prepare_cached(
                    "SELECT ip FROM firewall_lockout
                     WHERE status = 'active'
                       AND expires_at IS NOT NULL
                       AND expires_at <= CURRENT_TIMESTAMP",
                )?;
                let rows: Result<Vec<String>, _> = stmt.query_map([], |r| r.get::<_, String>(0))?.collect();
                rows?
            };
            conn.execute(
                "UPDATE firewall_lockout
                   SET status = 'released'
                 WHERE status = 'active'
                   AND expires_at IS NOT NULL
                   AND expires_at <= CURRENT_TIMESTAMP",
                [],
            )?;
            Ok(ips)
        })
        .await
}
