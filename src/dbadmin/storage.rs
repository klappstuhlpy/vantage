//! Query history and saved queries — DB Studio Phase 3 persistence.
//!
//! Both tables are per-account and live in `admin.db`. History is a bounded
//! recent-buffer (pruned to [`HISTORY_RETAINED`] on every insert), not a
//! durable archive — the audit log remains the real record of what ran. Saved
//! queries are named bookmarks of SQL the operator wants to keep.

use anyhow::Context;
use kls_web_core::Database;
use serde::Serialize;

const HISTORY_RETAINED: i64 = 200;

// ─── Row types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub id: i64,
    pub source: String,
    pub sql_text: String,
    pub ok: bool,
    pub row_count: i64,
    pub elapsed_ms: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SavedQuery {
    pub id: i64,
    pub name: String,
    pub source: String,
    pub sql_text: String,
    pub created_at: String,
    pub updated_at: String,
}

// ─── History ────────────────────────────────────────────────────────

/// Records a query and prunes to the per-account bound. Best-effort: a
/// recording failure must never block or fail the query response.
pub async fn record_history(
    db: &Database,
    account_id: i64,
    source: &str,
    sql_text: &str,
    ok: bool,
    row_count: i64,
    elapsed_ms: i64,
) {
    let source = source.to_string();
    let sql_text = sql_text.to_string();
    let ok_int: i64 = if ok { 1 } else { 0 };

    let result = db
        .call(move |conn| -> rusqlite::Result<()> {
            conn.execute(
                "INSERT INTO query_history (account_id, source, sql_text, ok, row_count, elapsed_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![account_id, source, sql_text, ok_int, row_count, elapsed_ms],
            )?;
            conn.execute(
                "DELETE FROM query_history WHERE account_id = ?1 AND id <= \
                 (SELECT id FROM query_history WHERE account_id = ?1 ORDER BY id DESC LIMIT 1 OFFSET ?2)",
                rusqlite::params![account_id, HISTORY_RETAINED],
            )?;
            Ok(())
        })
        .await;

    if let Err(e) = result {
        tracing::warn!(error = %e, "could not record query history");
    }
}

/// The most recent history entries for one account, newest first.
pub async fn list_history(db: &Database, account_id: i64, limit: i64) -> anyhow::Result<Vec<HistoryEntry>> {
    db.call(move |conn| -> rusqlite::Result<Vec<HistoryEntry>> {
        let mut stmt = conn.prepare_cached(
            "SELECT id, source, sql_text, ok, row_count, elapsed_ms, created_at \
             FROM query_history WHERE account_id = ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![account_id, limit], |row| {
            Ok(HistoryEntry {
                id: row.get(0)?,
                source: row.get(1)?,
                sql_text: row.get(2)?,
                ok: row.get::<_, i64>(3)? != 0,
                row_count: row.get(4)?,
                elapsed_ms: row.get(5)?,
                created_at: row.get(6)?,
            })
        })?;
        rows.collect()
    })
    .await
    .context("could not read query history")
}

/// Deletes all history for one account. The audit log remains the real record.
pub async fn clear_history(db: &Database, account_id: i64) -> anyhow::Result<()> {
    db.call(move |conn| -> rusqlite::Result<()> {
        conn.execute(
            "DELETE FROM query_history WHERE account_id = ?1",
            rusqlite::params![account_id],
        )?;
        Ok(())
    })
    .await
    .context("could not clear query history")
}

// ─── Saved queries ──────────────────────────────────────────────────

/// All saved queries for one account, alphabetical by name.
pub async fn list_saved(db: &Database, account_id: i64) -> anyhow::Result<Vec<SavedQuery>> {
    db.call(move |conn| -> rusqlite::Result<Vec<SavedQuery>> {
        let mut stmt = conn.prepare_cached(
            "SELECT id, name, source, sql_text, created_at, updated_at \
             FROM saved_query WHERE account_id = ?1 ORDER BY name COLLATE NOCASE",
        )?;
        let rows = stmt.query_map(rusqlite::params![account_id], |row| {
            Ok(SavedQuery {
                id: row.get(0)?,
                name: row.get(1)?,
                source: row.get(2)?,
                sql_text: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })?;
        rows.collect()
    })
    .await
    .context("could not list saved queries")
}

/// Creates or updates a saved query (upsert on account_id + name).
pub async fn save_query(
    db: &Database,
    account_id: i64,
    name: &str,
    source: &str,
    sql_text: &str,
) -> anyhow::Result<SavedQuery> {
    let name = name.to_string();
    let source = source.to_string();
    let sql_text = sql_text.to_string();

    db.call(move |conn| -> rusqlite::Result<SavedQuery> {
        conn.execute(
            "INSERT INTO saved_query (account_id, name, source, sql_text) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(account_id, name) DO UPDATE SET \
             sql_text = excluded.sql_text, source = excluded.source, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
            rusqlite::params![account_id, name, source, sql_text],
        )?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, name, source, sql_text, created_at, updated_at \
             FROM saved_query WHERE account_id = ?1 AND name = ?2",
        )?;
        stmt.query_row(rusqlite::params![account_id, name], |row| {
            Ok(SavedQuery {
                id: row.get(0)?,
                name: row.get(1)?,
                source: row.get(2)?,
                sql_text: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })
    })
    .await
    .context("could not save query")
}

/// Deletes one saved query by id, only if owned by the account.
pub async fn delete_saved(db: &Database, account_id: i64, id: i64) -> anyhow::Result<bool> {
    let changed = db
        .call(move |conn| -> rusqlite::Result<usize> {
            conn.execute(
                "DELETE FROM saved_query WHERE id = ?1 AND account_id = ?2",
                rusqlite::params![id, account_id],
            )
        })
        .await
        .context("could not delete saved query")?;
    Ok(changed > 0)
}
