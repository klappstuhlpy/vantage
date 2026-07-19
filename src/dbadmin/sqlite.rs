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

use rusqlite::{types::ValueRef, Connection, OptionalExtension};

use super::browse::{self, BrowsePlan, CountResult, ExportFormat, RowsPage};
use super::edit::{self, AppliedStatement, ApplyReport, EditPlan};
use super::schema::{Column, Fk, Index, SchemaOverview, TableDetail, ViewInfo};
use super::{human_size, quote_ident, DatabaseInfo, QueryResult, TableInfo, ROW_LIMIT};
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

fn tables_on(conn: &Connection) -> anyhow::Result<Vec<TableInfo>> {
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
        // The identifier is quoted so an unusual table name can't break out
        // of the quoting (D6) — and it came from sqlite_master, not a request.
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {}", quote_ident(&name)), [], |r| {
                r.get(0)
            })
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
}

// ─── Introspection (DB Studio P1) ────────────────────────────────────

/// Tables and views in one call — what the schema tree renders.
pub async fn schema_overview(state: &AppState, name: &str) -> anyhow::Result<SchemaOverview> {
    let path = resolve(state, name)?;
    tokio::task::spawn_blocking(move || -> anyhow::Result<SchemaOverview> {
        let conn = open(&path, true)?;
        let tables = tables_on(&conn)?;
        let views = {
            let mut stmt = conn.prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'view' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(ViewInfo {
                    schema: "main".into(),
                    name: r.get(0)?,
                })
            })?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        Ok(SchemaOverview { tables, views })
    })
    .await?
}

/// Columns, PK, foreign keys and indexes of one table (or view).
///
/// The request's table name is validated against `sqlite_master` *before* it
/// goes anywhere near a PRAGMA — introspection is the allowlist, quoting is the
/// backstop (D6).
pub async fn table_detail(state: &AppState, name: &str, table: &str) -> anyhow::Result<TableDetail> {
    let path = resolve(state, name)?;
    let table = table.to_string();
    tokio::task::spawn_blocking(move || -> anyhow::Result<TableDetail> {
        let conn = open(&path, true)?;

        let kind: Option<String> = conn
            .query_row(
                "SELECT type FROM sqlite_master
                 WHERE name = ?1 AND type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'",
                [&table],
                |r| r.get(0),
            )
            .optional()?;
        let kind = match kind.as_deref() {
            Some("table") => "table",
            Some("view") => "view",
            _ => anyhow::bail!("unknown table: {table}"),
        };

        let quoted = quote_ident(&table);

        // `table_xinfo` (not `table_info`) so generated columns list too; the
        // `hidden` flag tells virtual-table internals (1) apart from generated
        // columns (2/3), and only the former are noise.
        let columns: Vec<Column> = {
            let mut stmt = conn.prepare(&format!("PRAGMA table_xinfo({quoted})"))?;
            let rows = stmt.query_map([], |r| {
                let hidden: i64 = r.get("hidden")?;
                let notnull: i64 = r.get("notnull")?;
                let pk: i64 = r.get("pk")?;
                Ok((
                    hidden,
                    Column {
                        name: r.get("name")?,
                        data_type: r.get("type")?,
                        nullable: notnull == 0,
                        default: r.get("dflt_value")?,
                        pk_ordinal: (pk > 0).then_some(pk as u32),
                    },
                ))
            })?;
            rows.filter_map(|r| match r {
                Ok((1, _)) => None,
                Ok((_, c)) => Some(Ok(c)),
                Err(e) => Some(Err(e)),
            })
            .collect::<rusqlite::Result<_>>()?
        };

        // `foreign_key_list` emits one row per column pair, grouped by `id` —
        // rebuild composite FKs from consecutive (id, seq) rows. A missing "to"
        // column is SQLite's implicit reference to the target's PK.
        let foreign_keys: Vec<Fk> = {
            let mut stmt = conn.prepare(&format!("PRAGMA foreign_key_list({quoted})"))?;
            let rows: Vec<(i64, String, String, Option<String>)> = stmt
                .query_map([], |r| {
                    Ok((r.get("id")?, r.get("table")?, r.get("from")?, r.get("to")?))
                })?
                .collect::<rusqlite::Result<_>>()?;

            let mut fks: Vec<(i64, Fk)> = Vec::new();
            for (id, ref_table, from, to) in rows {
                if fks.last().map(|(last_id, _)| *last_id) != Some(id) {
                    fks.push((
                        id,
                        Fk {
                            columns: Vec::new(),
                            ref_schema: "main".into(),
                            ref_table,
                            ref_columns: Vec::new(),
                        },
                    ));
                }
                let fk = &mut fks.last_mut().expect("just pushed").1;
                fk.columns.push(from);
                if let Some(to) = to {
                    fk.ref_columns.push(to);
                }
            }
            fks.into_iter().map(|(_, fk)| fk).collect()
        };

        let indexes: Vec<Index> = {
            let mut stmt = conn.prepare(&format!("PRAGMA index_list({quoted})"))?;
            let list: Vec<(String, bool)> = stmt
                .query_map([], |r| Ok((r.get("name")?, r.get::<_, i64>("unique")? != 0)))?
                .collect::<rusqlite::Result<_>>()?;

            let mut out = Vec::with_capacity(list.len());
            for (idx_name, unique) in list {
                let mut stmt = conn.prepare(&format!("PRAGMA index_info({})", quote_ident(&idx_name)))?;
                // A NULL name is an expression member (cid -2) or the rowid
                // (cid -1); render the fact rather than dropping the member.
                let columns: Vec<String> = stmt
                    .query_map([], |r| {
                        Ok(r.get::<_, Option<String>>("name")?.unwrap_or_else(|| "<expr>".into()))
                    })?
                    .collect::<rusqlite::Result<_>>()?;
                out.push(Index {
                    name: idx_name,
                    columns,
                    unique,
                });
            }
            out
        };

        Ok(TableDetail {
            schema: "main".into(),
            name: table,
            kind,
            columns,
            foreign_keys,
            indexes,
        })
    })
    .await?
}

// ─── Table browser (DB Studio P2) ────────────────────────────────────

/// One page of rows under a validated [`BrowsePlan`]. Always read-only — the
/// browser composes SELECTs, and `query_only` makes the engine hold it to that.
pub async fn browse_rows(state: &AppState, name: &str, table: &str, plan: BrowsePlan) -> anyhow::Result<RowsPage> {
    let path = resolve(state, name)?;
    let table = table.to_string();
    tokio::task::spawn_blocking(move || -> anyhow::Result<RowsPage> {
        let conn = open(&path, true)?;
        let started = Instant::now();
        let (sql, params) = browse::sqlite_query(&plan, &table);
        let columns: Vec<String> = plan.columns.iter().map(|c| c.name.clone()).collect();

        let mut stmt = conn.prepare(&sql)?;
        let mut rows_iter = stmt.query(rusqlite::params_from_iter(params.iter()))?;
        let mut cells: Vec<Vec<Option<String>>> = Vec::new();
        while let Some(row) = rows_iter.next()? {
            cells.push((0..columns.len()).map(|i| value_to_cell(row, i)).collect());
        }

        let has_more = cells.len() == plan.limit;
        Ok(RowsPage {
            columns,
            rows: cells,
            offset: plan.offset,
            has_more,
            elapsed_ms: started.elapsed().as_millis() as u64,
        })
    })
    .await?
}

/// Exact `COUNT(*)` under the same filters.
pub async fn browse_count(state: &AppState, name: &str, table: &str, plan: BrowsePlan) -> anyhow::Result<CountResult> {
    let path = resolve(state, name)?;
    let table = table.to_string();
    tokio::task::spawn_blocking(move || -> anyhow::Result<CountResult> {
        let conn = open(&path, true)?;
        let started = Instant::now();
        let (sql, params) = browse::sqlite_count(&plan, &table);
        let count: i64 = conn.query_row(&sql, rusqlite::params_from_iter(params.iter()), |r| r.get(0))?;
        Ok(CountResult {
            count,
            elapsed_ms: started.elapsed().as_millis() as u64,
        })
    })
    .await?
}

/// Streams the filtered table through `tx` as encoded chunks (D13), returning
/// the number of rows streamed. The bounded channel is the backpressure: the
/// reader blocks when the client reads slowly, and stops when the client goes
/// away (a closed channel is a finished export, not an error).
pub async fn export(
    state: &AppState,
    name: &str,
    table: &str,
    plan: BrowsePlan,
    format: ExportFormat,
    tx: tokio::sync::mpsc::Sender<Result<String, std::io::Error>>,
) -> anyhow::Result<u64> {
    /// Rows are batched into chunks of roughly this size before hitting the
    /// channel, so the stream isn't a syscall per row.
    const CHUNK: usize = 64 * 1024;

    let path = resolve(state, name)?;
    let table = table.to_string();
    tokio::task::spawn_blocking(move || -> anyhow::Result<u64> {
        let run = || -> anyhow::Result<u64> {
            let conn = open(&path, true)?;
            let (sql, params) = browse::sqlite_export_query(&plan, &table);
            let columns: Vec<String> = plan.columns.iter().map(|c| c.name.clone()).collect();

            let mut stmt = conn.prepare(&sql)?;
            let mut rows_iter = stmt.query(rusqlite::params_from_iter(params.iter()))?;
            let mut buf = format.header(&columns);
            let mut count = 0u64;
            while let Some(row) = rows_iter.next()? {
                let cells: Vec<Option<String>> = (0..columns.len()).map(|i| value_to_cell(row, i)).collect();
                buf.push_str(&format.line(&columns, &cells));
                count += 1;
                if buf.len() >= CHUNK && tx.blocking_send(Ok(std::mem::take(&mut buf))).is_err() {
                    return Ok(count);
                }
            }
            if !buf.is_empty() {
                let _ = tx.blocking_send(Ok(buf));
            }
            Ok(count)
        };
        let out = run();
        if let Err(e) = &out {
            // Truncate the body with an error rather than ending it cleanly —
            // a partial file that looks complete is worse than a broken one.
            let _ = tx.blocking_send(Err(std::io::Error::other(e.to_string())));
        }
        out
    })
    .await?
}

// ─── Staged edits (P5) ───────────────────────────────────────────────

/// Applies a validated batch in one transaction, verifying that every statement
/// affected exactly one row.
///
/// The verification is the feature. Each statement is generated to address a
/// single row by full primary key, so "affected 0" means the row moved or went
/// away between the grid loading it and the operator submitting — and "affected
/// 2" would mean the addressing assumption is broken outright. Either way the
/// batch is abandoned whole: a partially applied set of edits is the one outcome
/// that leaves the operator unable to say what the database now contains.
///
/// Rollback is by drop — rusqlite's `Transaction` rolls back unless committed —
/// so every early return here, including a mid-batch engine error, unwinds the
/// whole batch.
pub async fn apply(state: &AppState, name: &str, plan: EditPlan) -> anyhow::Result<ApplyReport> {
    let path = resolve(state, name)?;
    tokio::task::spawn_blocking(move || -> anyhow::Result<ApplyReport> {
        // The one place this module opens a source writable.
        let mut conn = open(&path, false)?;
        let started = Instant::now();
        let tx = conn.transaction()?;

        let mut statements = Vec::with_capacity(plan.statements.len());
        for (i, st) in plan.statements.iter().enumerate() {
            let affected = tx.execute(&st.sql, rusqlite::params_from_iter(st.params.iter()))? as u64;
            if affected != 1 {
                return Err(edit::row_count_mismatch(i + 1, affected));
            }
            statements.push(AppliedStatement {
                kind: st.kind,
                preview: st.preview.clone(),
                affected,
            });
        }

        tx.commit()?;
        Ok(ApplyReport {
            applied: statements.len(),
            statements,
            elapsed_ms: started.elapsed().as_millis() as u64,
        })
    })
    .await?
}

// ─── Query runner ────────────────────────────────────────────────────

pub async fn run_query(
    state: &AppState,
    name: &str,
    sql: &str,
    safe: bool,
    run_id: Option<&str>,
    account_id: i64,
) -> anyhow::Result<QueryResult> {
    let path = resolve(state, name)?;
    let sql = sql.to_string();
    let registry = state.run_registry.clone();
    let run_id = run_id.map(str::to_string);
    tokio::task::spawn_blocking(move || -> anyhow::Result<QueryResult> {
        let conn = open(&path, safe)?;

        if let Some(ref id) = run_id {
            let ih = conn.get_interrupt_handle();
            registry.register(
                id.clone(),
                account_id,
                super::cancel::CancelHandle::Sqlite(std::sync::Arc::new(ih)),
            );
        }

        let result = run_query_inner(&conn, &sql);

        if let Some(ref id) = run_id {
            registry.remove(id);
        }

        result
    })
    .await?
}

fn run_query_inner(conn: &rusqlite::Connection, sql: &str) -> anyhow::Result<QueryResult> {
    let started = Instant::now();

    // `prepare` parses only the first statement and silently ignores the
    // rest of the text — a console that quietly drops the second half of
    // what the operator typed is lying about what ran. Walk the text with
    // `Batch` instead: take the first real statement, and refuse before
    // executing anything if another follows (a broken tail counts — either
    // way there is text we would not run).
    let mut batch = rusqlite::Batch::new(conn, sql);
    let Some(mut stmt) = batch.next()? else {
        return Ok(QueryResult {
            columns: Vec::new(),
            rows: Vec::new(),
            row_count: 0,
            elapsed_ms: started.elapsed().as_millis() as u64,
            truncated: false,
        });
    };
    if !matches!(batch.next(), Ok(None)) {
        anyhow::bail!("multiple statements are not supported here — run them one at a time (everything after the first ';' would otherwise be silently ignored)");
    }
    let col_count = stmt.column_count();

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
    let mut cells: Vec<Vec<Option<String>>> = Vec::new();
    let mut total = 0usize;
    while let Some(row) = rows_iter.next()? {
        total += 1;
        if cells.len() < ROW_LIMIT {
            cells.push((0..col_count).map(|i| value_to_cell(row, i)).collect());
        }
    }

    Ok(QueryResult {
        columns,
        rows: cells,
        row_count: total,
        elapsed_ms: started.elapsed().as_millis() as u64,
        truncated: total > ROW_LIMIT,
    })
}

// ─── EXPLAIN ────────────────────────────────────────────────────────

/// Runs `EXPLAIN QUERY PLAN <sql>` and returns the plan nodes as a flat list.
/// Always opens a safe (query_only) connection — EXPLAIN is read-only by nature.
pub async fn explain_query(state: &AppState, name: &str, sql: &str) -> anyhow::Result<Vec<super::ExplainNode>> {
    let path = resolve(state, name)?;
    let sql = sql.to_string();
    tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<super::ExplainNode>> {
        let conn = open(&path, true)?;
        let explain_sql = format!("EXPLAIN QUERY PLAN {sql}");
        let mut stmt = conn.prepare(&explain_sql)?;
        let mut nodes = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            nodes.push(super::ExplainNode {
                id: row.get::<_, i64>(0)?.to_string(),
                parent: {
                    let p: i64 = row.get(1)?;
                    if p == 0 {
                        None
                    } else {
                        Some(p.to_string())
                    }
                },
                label: row.get::<_, String>(3)?,
                detail: None,
            });
        }
        Ok(nodes)
    })
    .await?
}

/// Returns the verbatim CREATE statement from `sqlite_master`.
pub async fn get_ddl(state: &AppState, name: &str, table: &str) -> anyhow::Result<String> {
    let path = resolve(state, name)?;
    let table = table.to_string();
    tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let conn = open(&path, true)?;
        let sql: Option<String> = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?1",
                [&table],
                |row| row.get(0),
            )
            .optional()?;
        sql.ok_or_else(|| anyhow::anyhow!("no DDL found for '{table}'"))
    })
    .await?
}

/// Coerces one SQLite cell for display. A real NULL is `None` (a JSON `null` on
/// the wire, per D2), so the frontend can mark it apart from a TEXT value that
/// spells "NULL". Blobs are summarised by length rather than dumped, so a
/// `SELECT *` over a table with binary columns stays readable.
fn value_to_cell(row: &rusqlite::Row, idx: usize) -> Option<String> {
    match row.get_ref(idx) {
        Ok(ValueRef::Null) => None,
        Ok(ValueRef::Integer(i)) => Some(i.to_string()),
        Ok(ValueRef::Real(f)) => Some(f.to_string()),
        Ok(ValueRef::Text(t)) => Some(String::from_utf8_lossy(t).into_owned()),
        Ok(ValueRef::Blob(b)) => Some(format!("<blob: {} bytes>", b.len())),
        Err(_) => Some("<error>".into()),
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
        let query = run_query(&state, "../../etc/passwd", "SELECT 1", true, None, 0)
            .await
            .is_err();
        let schema = schema_overview(&state, "../../etc/passwd").await.is_err();
        let detail = table_detail(&state, "../../etc/passwd", "x").await.is_err();
        std::fs::remove_file(&path).ok();

        assert!(direct, "an unknown name is refused");
        assert!(traversal, "a path-shaped name is refused, not joined");
        assert!(query, "the query runner refuses it too, not just the resolver");
        assert!(schema, "introspection goes through the same catalog");
        assert!(detail, "table detail goes through the same catalog");
    }

    #[tokio::test]
    async fn lists_tables_with_counts() {
        let path = seed_db();
        let state = state_with(&path).await;
        let overview = schema_overview(&state, "extra").await.unwrap();
        std::fs::remove_file(&path).ok();

        let widget = overview
            .tables
            .iter()
            .find(|t| t.name == "widget")
            .expect("widget table listed");
        assert_eq!(widget.row_estimate, 2);
        assert_eq!(widget.schema, "main");
    }

    #[tokio::test]
    async fn read_query_returns_rows_and_stringifies_cells() {
        let path = seed_db();
        let state = state_with(&path).await;
        let result = run_query(
            &state,
            "extra",
            "SELECT id, label, blob FROM widget ORDER BY id",
            true,
            None,
            0,
        )
        .await
        .unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(result.columns, vec!["id", "label", "blob"]);
        assert_eq!(result.row_count, 2);
        assert_eq!(
            result.rows[0],
            vec![Some("1".into()), Some("one".into()), Some("<blob: 2 bytes>".into())]
        );
        assert_eq!(result.rows[1], vec![Some("2".into()), Some("two".into()), None]);
        assert!(!result.truncated);
    }

    /// The test the old stringly encoding made impossible: a real NULL and a
    /// TEXT value spelling 'NULL' are different cells, and stay different all
    /// the way out (D2).
    #[tokio::test]
    async fn a_real_null_is_distinguishable_from_the_string_null() {
        let path = seed_db();
        let state = state_with(&path).await;
        let result = run_query(&state, "extra", "SELECT 'NULL' AS s, NULL AS n", true, None, 0)
            .await
            .unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(result.rows[0], vec![Some("NULL".into()), None]);
    }

    /// rusqlite's `prepare` silently ignores everything after the first
    /// statement. The runner refuses that outright — before executing anything —
    /// rather than reporting a result for half of what was typed.
    #[tokio::test]
    async fn a_second_statement_is_refused_before_anything_runs() {
        let path = seed_db();
        let state = state_with(&path).await;

        let err = run_query(&state, "extra", "SELECT 1; DELETE FROM widget", false, None, 0)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("one at a time"), "got: {err}");

        // Refused means refused: the DELETE in the tail never executed, even
        // though danger mode would have allowed it.
        let count = run_query(&state, "extra", "SELECT COUNT(*) FROM widget", true, None, 0)
            .await
            .unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(count.rows[0][0], Some("2".into()));
    }

    /// A trailing semicolon or a trailing comment is not a second statement —
    /// only real trailing SQL is refused. Comment-only input "runs" and
    /// produces nothing, which is a result, not an error.
    #[tokio::test]
    async fn trailing_semicolons_and_comments_are_not_second_statements() {
        let path = seed_db();
        let state = state_with(&path).await;

        let simple = run_query(&state, "extra", "SELECT 1;", true, None, 0).await;
        let commented = run_query(&state, "extra", "SELECT 1; -- trailing note", true, None, 0).await;
        let comment_only = run_query(&state, "extra", "-- nothing to run", true, None, 0).await;
        std::fs::remove_file(&path).ok();

        assert_eq!(simple.unwrap().row_count, 1);
        assert_eq!(commented.unwrap().row_count, 1);
        let empty = comment_only.unwrap();
        assert_eq!(empty.row_count, 0);
        assert!(empty.columns.is_empty());
    }

    /// Seeds the introspection menagerie: composite PK, composite FK, plain and
    /// unique indexes, a view, and a table whose name carries a quote and a dot.
    fn seed_schema_db() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("vantage-dbschema-test-{}-{n}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"CREATE TABLE parent(
                   a TEXT NOT NULL,
                   b INTEGER NOT NULL,
                   note TEXT DEFAULT 'x',
                   PRIMARY KEY (a, b)
               );
               CREATE TABLE child(
                   id INTEGER PRIMARY KEY,
                   pa TEXT,
                   pb INTEGER,
                   FOREIGN KEY (pa, pb) REFERENCES parent(a, b)
               );
               CREATE INDEX child_pa ON child(pa);
               CREATE UNIQUE INDEX child_pa_pb ON child(pa, pb);
               CREATE VIEW child_view AS SELECT id, pa FROM child;
               CREATE TABLE "we""ird t.able"(x TEXT);
            "#,
        )
        .unwrap();
        path
    }

    #[tokio::test]
    async fn schema_overview_lists_tables_and_views() {
        let path = seed_schema_db();
        let state = state_with(&path).await;
        let overview = schema_overview(&state, "extra").await.unwrap();
        std::fs::remove_file(&path).ok();

        let table_names: Vec<&str> = overview.tables.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(table_names, vec!["child", "parent", "we\"ird t.able"]);
        assert_eq!(overview.views.len(), 1);
        assert_eq!(overview.views[0].name, "child_view");
        assert_eq!(overview.views[0].schema, "main");
    }

    #[tokio::test]
    async fn table_detail_reports_composite_pk_fk_and_indexes() {
        let path = seed_schema_db();
        let state = state_with(&path).await;
        let parent = table_detail(&state, "extra", "parent").await.unwrap();
        let child = table_detail(&state, "extra", "child").await.unwrap();
        std::fs::remove_file(&path).ok();

        // Composite PK: the ordinal, not just a flag, so position survives.
        assert_eq!(parent.kind, "table");
        let a = parent.columns.iter().find(|c| c.name == "a").unwrap();
        let b = parent.columns.iter().find(|c| c.name == "b").unwrap();
        let note = parent.columns.iter().find(|c| c.name == "note").unwrap();
        assert_eq!(a.pk_ordinal, Some(1));
        assert_eq!(b.pk_ordinal, Some(2));
        assert!(!a.nullable, "declared NOT NULL");
        assert_eq!(note.pk_ordinal, None);
        assert!(note.nullable);
        assert_eq!(note.default.as_deref(), Some("'x'"));
        assert_eq!(note.data_type, "TEXT");

        // Composite FK rebuilt from foreign_key_list's per-column rows.
        assert_eq!(child.foreign_keys.len(), 1);
        let fk = &child.foreign_keys[0];
        assert_eq!(fk.columns, vec!["pa", "pb"]);
        assert_eq!(fk.ref_table, "parent");
        assert_eq!(fk.ref_columns, vec!["a", "b"]);

        let id = child.columns.iter().find(|c| c.name == "id").unwrap();
        assert_eq!(id.pk_ordinal, Some(1));

        let plain = child.indexes.iter().find(|i| i.name == "child_pa").unwrap();
        assert!(!plain.unique);
        assert_eq!(plain.columns, vec!["pa"]);
        let unique = child.indexes.iter().find(|i| i.name == "child_pa_pb").unwrap();
        assert!(unique.unique);
        assert_eq!(unique.columns, vec!["pa", "pb"]);
    }

    /// Views introspect too (read-only in the UI), a quote-and-dot table name
    /// survives the round trip, and a name that is not in `sqlite_master` is
    /// refused before it reaches a PRAGMA.
    #[tokio::test]
    async fn table_detail_handles_views_weird_names_and_unknowns() {
        let path = seed_schema_db();
        let state = state_with(&path).await;
        let view = table_detail(&state, "extra", "child_view").await.unwrap();
        let weird = table_detail(&state, "extra", "we\"ird t.able").await.unwrap();
        let unknown = table_detail(&state, "extra", "nope").await;
        let internal = table_detail(&state, "extra", "sqlite_master").await;
        std::fs::remove_file(&path).ok();

        assert_eq!(view.kind, "view");
        let view_cols: Vec<&str> = view.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(view_cols, vec!["id", "pa"]);
        assert!(view.foreign_keys.is_empty());

        assert_eq!(weird.kind, "table");
        assert_eq!(weird.columns[0].name, "x");

        assert!(unknown.is_err(), "an unknown name is refused");
        assert!(internal.is_err(), "sqlite_% internals are not browsable");
    }

    /// End-to-end browse on a seeded file: filters bind, sorts apply, NULLs
    /// stay NULL, blobs summarise, and the count honours the filters.
    #[tokio::test]
    async fn browse_rows_filters_sorts_and_counts() {
        let path = seed_db();
        let state = state_with(&path).await;
        let detail = table_detail(&state, "extra", "widget").await.unwrap();

        let mk_plan = |filters, sort| browse::plan(&detail, filters, sort, None, 0).unwrap();
        let filter = |column: &str, op: &str, value: Option<&str>| browse::FilterSpec {
            column: column.into(),
            op: op.into(),
            value: value.map(String::from),
        };

        // Unfiltered, sorted descending: blob renders as a summary, NULL is None.
        let page = browse_rows(&state, "extra", "widget", mk_plan(vec![], Some(("id".into(), true))))
            .await
            .unwrap();
        assert_eq!(page.columns, vec!["id", "label", "blob"]);
        assert_eq!(page.rows.len(), 2);
        assert_eq!(page.rows[0], vec![Some("2".into()), Some("two".into()), None]);
        assert_eq!(
            page.rows[1],
            vec![Some("1".into()), Some("one".into()), Some("<blob: 2 bytes>".into())]
        );
        assert!(!page.has_more);

        // A bound equality filter narrows to one row.
        let page = browse_rows(
            &state,
            "extra",
            "widget",
            mk_plan(vec![filter("label", "=", Some("two"))], None),
        )
        .await
        .unwrap();
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0][0], Some("2".into()));

        // `contains` LIKE-matches both, `is-null` matches the NULL blob only.
        let both = browse_rows(
            &state,
            "extra",
            "widget",
            mk_plan(vec![filter("label", "contains", Some("o"))], None),
        )
        .await
        .unwrap();
        assert_eq!(both.rows.len(), 2);
        let nulls = browse_rows(
            &state,
            "extra",
            "widget",
            mk_plan(vec![filter("blob", "is-null", None)], None),
        )
        .await
        .unwrap();
        assert_eq!(nulls.rows.len(), 1);
        assert_eq!(nulls.rows[0][1], Some("two".into()));

        // The count honours the same filters.
        let count = browse_count(
            &state,
            "extra",
            "widget",
            mk_plan(vec![filter("label", "=", Some("one"))], None),
        )
        .await
        .unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(count.count, 1);
    }

    /// A quote-and-dot table name browses fine: identifiers travel quoted
    /// per-part from introspection to SQL (D6).
    #[tokio::test]
    async fn browse_survives_a_weird_table_name() {
        let path = seed_schema_db();
        let state = state_with(&path).await;
        let detail = table_detail(&state, "extra", "we\"ird t.able").await.unwrap();
        let plan = browse::plan(&detail, vec![], None, None, 0).unwrap();
        let page = browse_rows(&state, "extra", "we\"ird t.able", plan).await.unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(page.columns, vec!["x"]);
        assert!(page.rows.is_empty());
    }

    /// The export streams the whole filtered set through the channel — header
    /// first, then every row — and reports how many rows left.
    #[tokio::test]
    async fn export_streams_csv_with_all_rows() {
        let path = seed_db();
        let state = state_with(&path).await;
        let detail = table_detail(&state, "extra", "widget").await.unwrap();
        let plan = browse::plan(&detail, vec![], Some(("id".into(), false)), None, 0).unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let rows = export(&state, "extra", "widget", plan, ExportFormat::Csv, tx)
            .await
            .unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(rows, 2);
        let mut body = String::new();
        while let Some(chunk) = rx.recv().await {
            body.push_str(&chunk.unwrap());
        }
        assert_eq!(body, "id,label,blob\n1,one,<blob: 2 bytes>\n2,two,\n");
    }

    /// Safe mode opens the connection with `query_only`, so even a write that
    /// slips past the text prefilter is refused by the engine.
    #[tokio::test]
    async fn safe_mode_blocks_writes_at_the_engine() {
        let path = seed_db();
        let state = state_with(&path).await;
        let err = run_query(&state, "extra", "DELETE FROM widget", true, None, 0).await;
        std::fs::remove_file(&path).ok();
        assert!(err.is_err(), "query_only must reject the write");
    }

    /// Danger mode (safe = false) actually mutates the database.
    #[tokio::test]
    async fn danger_mode_permits_writes() {
        let path = seed_db();
        let state = state_with(&path).await;
        let write = run_query(&state, "extra", "DELETE FROM widget WHERE id = 1", false, None, 0)
            .await
            .unwrap();
        assert_eq!(write.row_count, 1, "one row affected");

        let remaining = run_query(&state, "extra", "SELECT COUNT(*) FROM widget", true, None, 0)
            .await
            .unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(remaining.rows[0][0], Some("1".into()));
    }
}
