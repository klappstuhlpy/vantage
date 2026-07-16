//! Database console for the `/database` page — the second feature slice
//! moved into Vantage (ADMIN_SEPARATION_PLAN Phase 4, Step C2).
//!
//! Vantage owns a single SQLite database, its own `admin.db`, so this is a
//! deliberately simplified port of the monolith's multi-backend console: no
//! `requests.db`, no external PostgreSQL, no roles tab — one source, one page.
//! (Percy's PostgreSQL is off-limits by the workspace's DB-isolation rule and
//! was never reachable from the admin console anyway.)
//!
//! Safety mirrors the monolith exactly:
//! - Safe-mode is the default. The query is first screened by the text-level
//!   [`is_safe_query`] prefilter (rejects obvious writes with a friendly
//!   message), then the engine enforces read-only-ness via `PRAGMA
//!   query_only = ON` on the connection.
//! - Danger-mode skips both layers and is only reachable through an admin-only
//!   checkbox plus an explicit confirmation in the UI.
//!
//! Rather than borrow a connection from the live pool (which would contend with
//! the running app, and where a per-connection `query_only` pragma would leak
//! into other pooled connections), each request opens a fresh short-lived
//! `rusqlite::Connection` to the db file and drops it when done.

pub mod routes;
mod safety;

pub use safety::is_safe_query;

use std::path::{Path, PathBuf};
use std::time::Instant;

use rusqlite::{types::ValueRef, Connection};
use serde::Serialize;

/// Hard cap on the number of rows returned by the query runner so a
/// `SELECT * FROM big_table` doesn't OOM the browser tab.
pub const ROW_LIMIT: usize = 1000;

/// Metadata for the single browsable database.
#[derive(Debug, Serialize)]
pub struct DatabaseInfo {
    pub name: String,
    pub kind: &'static str,
    /// On-disk size as a human string (`"42 MB"`).
    pub size_pretty: String,
}

#[derive(Debug, Serialize)]
pub struct TableInfo {
    pub name: String,
    pub row_estimate: i64,
}

#[derive(Debug, Serialize)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub row_count: usize,
    pub elapsed_ms: u64,
    /// `true` when we capped the result set at [`ROW_LIMIT`]; the UI shows a
    /// banner so the operator knows results are partial.
    pub truncated: bool,
}

/// Opens a fresh connection to `path`. When `read_only` is set, `query_only` is
/// engaged so the engine rejects any write on this connection — the connection
/// is short-lived and dropped after the request, so there is nothing to reset.
fn open(path: &Path, read_only: bool) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)?;
    if read_only {
        conn.execute_batch("PRAGMA query_only = ON;")?;
    }
    Ok(conn)
}

/// Describes `admin.db` for the page header (name + on-disk size).
pub fn database_info(path: &Path) -> DatabaseInfo {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    DatabaseInfo {
        name: "admin".into(),
        kind: "sqlite",
        size_pretty: human_size(size),
    }
}

/// Lists the user tables in `admin.db` with an exact row count (the admin
/// database is small enough that `COUNT(*)` is cheap). Runs on a blocking
/// thread since `rusqlite` is synchronous.
pub async fn list_tables(path: PathBuf) -> anyhow::Result<Vec<TableInfo>> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<TableInfo>> {
        let conn = open(&path, true)?;
        let names: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };

        let mut out = Vec::with_capacity(names.len());
        for name in names {
            // The identifier is double-quoted (and inner quotes doubled) so an
            // unusual table name can't break out of the quoting.
            let quoted = name.replace('"', "\"\"");
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM \"{quoted}\""), [], |r| r.get(0))
                .unwrap_or(0);
            out.push(TableInfo {
                name,
                row_estimate: count,
            });
        }
        Ok(out)
    })
    .await?
}

/// Runs `sql` against `admin.db`. In safe mode the connection is opened with
/// `query_only`, so any write is rejected by the engine before rows are touched.
pub async fn run_query(path: PathBuf, sql: &str, safe: bool) -> anyhow::Result<QueryResult> {
    let sql = sql.to_string();
    tokio::task::spawn_blocking(move || -> anyhow::Result<QueryResult> {
        let conn = open(&path, safe)?;
        let started = Instant::now();

        let mut stmt = conn.prepare(&sql)?;
        let col_count = stmt.column_count();

        // A statement with no result columns (INSERT/UPDATE/DELETE/DDL/…) must
        // be run with `execute`, not `query`. In safe mode `query_only` makes
        // the engine reject it before any rows are touched.
        if col_count == 0 {
            let affected = stmt.execute([])?;
            return Ok(QueryResult {
                columns: Vec::new(),
                rows: Vec::new(),
                row_count: affected,
                elapsed_ms: started.elapsed().as_millis() as u64,
                truncated: false,
            });
        }

        let columns: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();

        let mut rows_iter = stmt.query([])?;
        let mut cells: Vec<Vec<String>> = Vec::new();
        let mut total = 0usize;
        while let Some(row) = rows_iter.next()? {
            total += 1;
            if cells.len() < ROW_LIMIT {
                cells.push((0..col_count).map(|i| value_to_string(row, i)).collect());
            }
        }

        Ok(QueryResult {
            columns,
            rows: cells,
            row_count: total,
            elapsed_ms: started.elapsed().as_millis() as u64,
            truncated: total > ROW_LIMIT,
        })
    })
    .await?
}

/// Coerces one SQLite cell to a display string. Blobs are summarised by length
/// rather than dumped, so a `SELECT *` over a table with binary columns stays
/// readable.
fn value_to_string(row: &rusqlite::Row, idx: usize) -> String {
    match row.get_ref(idx) {
        Ok(ValueRef::Null) => "NULL".into(),
        Ok(ValueRef::Integer(i)) => i.to_string(),
        Ok(ValueRef::Real(f)) => f.to_string(),
        Ok(ValueRef::Text(t)) => String::from_utf8_lossy(t).into_owned(),
        Ok(ValueRef::Blob(b)) => format!("<blob: {} bytes>", b.len()),
        Err(_) => "<error>".into(),
    }
}

/// Formats a byte count as a short human string (`"42 MB"`). Self-contained —
/// the monolith's shared `backup::human_size` arrives with the backup slice.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".into();
    }
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes a small SQLite database to a throwaway temp file and returns its
    /// path (its own file — the query runner opens fresh connections to it, so a
    /// shared `:memory:` handle would not work here).
    fn seed_db() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir();
        let path = dir.join(format!("vantage-dbadmin-test-{}-{n}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE widget(id INTEGER PRIMARY KEY, label TEXT, blob BLOB);
             INSERT INTO widget(label, blob) VALUES ('one', x'0011'), ('two', NULL);",
        )
        .unwrap();
        path
    }

    #[tokio::test]
    async fn lists_tables_with_counts() {
        let path = seed_db();
        let tables = list_tables(path.clone()).await.unwrap();
        std::fs::remove_file(&path).ok();

        let widget = tables.iter().find(|t| t.name == "widget").expect("widget table listed");
        assert_eq!(widget.row_estimate, 2);
    }

    #[tokio::test]
    async fn read_query_returns_rows_and_stringifies_cells() {
        let path = seed_db();
        let result = run_query(path.clone(), "SELECT id, label, blob FROM widget ORDER BY id", true)
            .await
            .unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(result.columns, vec!["id", "label", "blob"]);
        assert_eq!(result.row_count, 2);
        assert_eq!(result.rows[0], vec!["1", "one", "<blob: 2 bytes>"]);
        assert_eq!(result.rows[1], vec!["2", "two", "NULL"]);
        assert!(!result.truncated);
    }

    /// Safe-mode opens the connection with `query_only`, so even a write that
    /// slips past the text prefilter is refused by the engine.
    #[tokio::test]
    async fn safe_mode_blocks_writes_at_the_engine() {
        let path = seed_db();
        let err = run_query(path.clone(), "DELETE FROM widget", true).await;
        std::fs::remove_file(&path).ok();
        assert!(err.is_err(), "query_only must reject the write");
    }

    /// Danger-mode (safe = false) actually mutates the database.
    #[tokio::test]
    async fn danger_mode_permits_writes() {
        let path = seed_db();
        let write = run_query(path.clone(), "DELETE FROM widget WHERE id = 1", false)
            .await
            .unwrap();
        assert_eq!(write.row_count, 1, "one row affected");

        let remaining = run_query(path.clone(), "SELECT COUNT(*) FROM widget", true)
            .await
            .unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(remaining.rows[0][0], "1");
    }

    #[test]
    fn human_size_reads_naturally() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1024 * 1024 * 3), "3.0 MB");
    }
}
