//! SQLite backend for the database console.
//!
//! Browses on-disk SQLite files the operator has named: Vantage's own
//! `admin.db`, the site's `requests.db` (`requests_db_path`), and any extra
//! entries in `sqlite_sources`.
//!
//! Rather than borrow a connection from the live pool — which would contend
//! with the running app, and where a per-connection `query_only` pragma would
//! leak into other pooled connections — each request opens a fresh short-lived
//! `rusqlite::Connection` and drops it when done. That is also what makes
//! browsing a *foreign* database file (one Vantage has no pool for) the same
//! code path as browsing its own.

use std::path::{Path, PathBuf};
use std::time::Instant;

use rusqlite::{types::ValueRef, Connection};

use super::{human_size, DatabaseInfo, QueryResult, TableInfo, ROW_LIMIT};
use crate::AppState;

/// One resolved SQLite source: a display name and the file behind it.
struct Entry {
    name: String,
    path: PathBuf,
}

/// Builds the SQLite half of the catalog from config.
///
/// This function is the *only* place a name becomes a path. Everything else
/// takes a name and looks it up here, so a request can never address a file the
/// operator did not put in `config.json`.
///
/// A `:memory:` path (the test posture, and what `requests_db_path` is set to in
/// tests) is skipped: there is no file to open a second connection to, and
/// listing it would offer the operator a source that always errors.
fn entries(state: &AppState) -> Vec<Entry> {
    let mut out = vec![Entry {
        name: "admin".into(),
        path: state.db_path.as_ref().clone(),
    }];

    if let Some(path) = &state.config.requests_db_path {
        if path.as_os_str() != ":memory:" {
            out.push(Entry {
                name: "requests".into(),
                path: path.clone(),
            });
        }
    }

    for src in &state.config.sqlite_sources {
        // A configured name that collides with a built-in would make the picker
        // ambiguous and the lookup below pick whichever came first. Drop it and
        // say so, rather than silently shadowing `admin`.
        if out.iter().any(|e| e.name == src.name) {
            tracing::warn!(name = %src.name, "ignoring sqlite_sources entry: name is already taken");
            continue;
        }
        out.push(Entry {
            name: src.name.clone(),
            path: src.path.clone(),
        });
    }

    out
}

/// Resolves a source name to its configured path, or errors. The error text
/// deliberately does not echo back a path.
fn resolve(state: &AppState, name: &str) -> anyhow::Result<PathBuf> {
    entries(state)
        .into_iter()
        .find(|e| e.name == name)
        .map(|e| e.path)
        .ok_or_else(|| anyhow::anyhow!("unknown database: {name}"))
}

/// Opens a fresh connection to a database file. When `read_only` is set,
/// `query_only` is engaged so the engine rejects any write on this connection —
/// the connection is short-lived and dropped after the request, so there is
/// nothing to reset.
fn open(path: &Path, read_only: bool) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)?;
    if read_only {
        conn.execute_batch("PRAGMA query_only = ON;")?;
    }
    Ok(conn)
}

// ─── Catalog reads ───────────────────────────────────────────────────

/// Describes every configured SQLite source. A file that is missing or
/// unreadable still lists (at size 0) rather than vanishing: an operator looking
/// for a database they configured needs to see that it is *there and broken*,
/// not that it is absent.
pub fn list_databases(state: &AppState) -> Vec<DatabaseInfo> {
    entries(state)
        .into_iter()
        .map(|e| {
            let size = std::fs::metadata(&e.path).map(|m| m.len()).unwrap_or(0);
            DatabaseInfo {
                id: format!("sqlite:{}", e.name),
                name: e.name,
                kind: "sqlite",
                owner: "—".into(),
                encoding: "UTF-8".into(),
                size_pretty: human_size(size),
            }
        })
        .collect()
}

pub async fn list_tables(state: &AppState, name: &str) -> anyhow::Result<Vec<TableInfo>> {
    let path = resolve(state, name)?;
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
            // These databases are small enough that an exact COUNT(*) is cheap.
            // The identifier is double-quoted (and inner quotes doubled) so an
            // unusual table name can't break out of the quoting.
            let quoted = name.replace('"', "\"\"");
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM \"{quoted}\""), [], |r| r.get(0))
                .unwrap_or(0);
            out.push(TableInfo {
                schema: "main".into(),
                name,
                owner: "—".into(),
                row_estimate: count,
                size_pretty: "—".into(),
            });
        }
        Ok(out)
    })
    .await?
}

// ─── Query runner ────────────────────────────────────────────────────

pub async fn run_query(state: &AppState, name: &str, sql: &str, safe: bool) -> anyhow::Result<QueryResult> {
    let path = resolve(state, name)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, SqliteSource};

    /// Writes a small SQLite database to a throwaway temp file and returns its
    /// path (its own file — the query runner opens fresh connections to it, so a
    /// shared `:memory:` handle would not work here).
    fn seed_db() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("vantage-dbadmin-test-{}-{n}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE widget(id INTEGER PRIMARY KEY, label TEXT, blob BLOB);
             INSERT INTO widget(label, blob) VALUES ('one', x'0011'), ('two', NULL);",
        )
        .unwrap();
        path
    }

    /// Hermetic state: `admin` stays in memory (so the migrations don't land in
    /// the seed file and skew the table assertions) and the seeded file is
    /// reached through a configured `extra` source — which is also the case
    /// worth testing, since it is the one that goes through `resolve`.
    async fn state_with(path: &Path) -> AppState {
        let mut config = Config::test_default();
        config.sqlite_sources = vec![SqliteSource {
            name: "extra".into(),
            path: path.to_path_buf(),
        }];
        crate::build_state_with(config, Path::new(":memory:"))
            .await
            .expect("build state")
    }

    #[tokio::test]
    async fn catalog_lists_builtin_and_configured_sources() {
        let path = seed_db();
        let state = state_with(&path).await;
        let dbs = list_databases(&state);
        std::fs::remove_file(&path).ok();

        let ids: Vec<&str> = dbs.iter().map(|d| d.id.as_str()).collect();
        assert!(ids.contains(&"sqlite:admin"));
        assert!(ids.contains(&"sqlite:extra"));
        assert!(dbs.iter().all(|d| d.kind == "sqlite"));
    }

    /// The catalog is the allowlist: a name nobody configured never becomes a
    /// path, so there is nothing to traverse out of.
    #[tokio::test]
    async fn an_unconfigured_name_never_resolves_to_a_path() {
        let path = seed_db();
        let state = state_with(&path).await;
        let direct = resolve(&state, "nope").is_err();
        let traversal = resolve(&state, "../../etc/passwd").is_err();
        let query = run_query(&state, "../../etc/passwd", "SELECT 1", true).await.is_err();
        std::fs::remove_file(&path).ok();

        assert!(direct, "an unknown name is refused");
        assert!(traversal, "a path-shaped name is refused, not joined");
        assert!(query, "the query runner refuses it too, not just the resolver");
    }

    #[tokio::test]
    async fn lists_tables_with_counts() {
        let path = seed_db();
        let state = state_with(&path).await;
        let tables = list_tables(&state, "extra").await.unwrap();
        std::fs::remove_file(&path).ok();

        let widget = tables.iter().find(|t| t.name == "widget").expect("widget table listed");
        assert_eq!(widget.row_estimate, 2);
        assert_eq!(widget.schema, "main");
    }

    #[tokio::test]
    async fn read_query_returns_rows_and_stringifies_cells() {
        let path = seed_db();
        let state = state_with(&path).await;
        let result = run_query(&state, "extra", "SELECT id, label, blob FROM widget ORDER BY id", true)
            .await
            .unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(result.columns, vec!["id", "label", "blob"]);
        assert_eq!(result.row_count, 2);
        assert_eq!(result.rows[0], vec!["1", "one", "<blob: 2 bytes>"]);
        assert_eq!(result.rows[1], vec!["2", "two", "NULL"]);
        assert!(!result.truncated);
    }

    /// Safe mode opens the connection with `query_only`, so even a write that
    /// slips past the text prefilter is refused by the engine.
    #[tokio::test]
    async fn safe_mode_blocks_writes_at_the_engine() {
        let path = seed_db();
        let state = state_with(&path).await;
        let err = run_query(&state, "extra", "DELETE FROM widget", true).await;
        std::fs::remove_file(&path).ok();
        assert!(err.is_err(), "query_only must reject the write");
    }

    /// Danger mode (safe = false) actually mutates the database.
    #[tokio::test]
    async fn danger_mode_permits_writes() {
        let path = seed_db();
        let state = state_with(&path).await;
        let write = run_query(&state, "extra", "DELETE FROM widget WHERE id = 1", false)
            .await
            .unwrap();
        assert_eq!(write.row_count, 1, "one row affected");

        let remaining = run_query(&state, "extra", "SELECT COUNT(*) FROM widget", true)
            .await
            .unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(remaining.rows[0][0], "1");
    }
}
