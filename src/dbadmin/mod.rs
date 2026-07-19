//! Database console for the `/database` page.
//!
//! The page browses two kinds of database behind a single UI:
//! - **SQLite** — Vantage's own `admin.db`, the site's `requests.db` when
//!   `requests_db_path` is set, and anything else named in `sqlite_sources`.
//! - **PostgreSQL** — the optional instance pointed at by `postgres_url`. Only
//!   listed when that key is set.
//!
//! Each database is addressed by an opaque *source id* of the form
//! `sqlite:<name>` or `pg:<dbname>` (see [`Source`]). The dispatch helpers below
//! parse that id and forward to the right backend submodule, so the route layer
//! and the frontend never special-case a backend.
//!
//! ## Where a database can come from
//!
//! Only from `config.json`. A SQLite source id is resolved by *looking its name
//! up in the catalog the config produced* — never by joining the caller's string
//! onto a directory — so no request can address a file the operator did not
//! name, and there is no path to traverse. This is the same rule the alert sinks
//! and `spotlight_scripts` follow, and for the same reason: the address is the
//! credential. A console that let an admin type a path would be a file-read
//! primitive for anything the process can open.
//!
//! ## Safety
//!
//! - Safe mode is the default. A query is first screened by the text-level
//!   [`is_safe_query`] prefilter (rejects obvious writes with a friendly
//!   message), then the engine enforces read-only-ness for real: Postgres via
//!   `BEGIN TRANSACTION READ ONLY`, SQLite via `PRAGMA query_only = ON`. The
//!   prefilter is the error message; the engine is the guarantee.
//! - Danger mode skips both layers on both backends and is only reachable
//!   through an explicit confirmation in the UI. On Postgres that means a
//!   `DROP TABLE` against a database Vantage does not own, so the confirmation
//!   names the source.
//! - Every query is audited, including the ones safe mode refused.

pub mod browse;
pub mod cancel;
pub mod edit;
pub mod postgres;
pub mod routes;
mod safety;
pub mod schema;
pub mod sqlite;
pub mod storage;

pub use safety::is_safe_query;

use serde::Serialize;

use crate::AppState;

/// Hard cap on the number of rows returned by the query runner so a
/// `SELECT * FROM big_table` doesn't OOM the browser tab. Shared by both
/// backends.
pub const ROW_LIMIT: usize = 1000;

// ─── Shared catalog/result shapes ────────────────────────────────────

/// One entry in the database picker.
#[derive(Debug, Serialize)]
pub struct DatabaseInfo {
    /// Opaque source id (`"sqlite:admin"`, `"pg:postgres"`, …). This is what the
    /// frontend sends back to the table/query endpoints.
    pub id: String,
    /// Display name (`"admin"`, `"requests"`, or the Postgres database name).
    pub name: String,
    /// Backend kind — `"sqlite"` or `"postgres"`. The UI uses this to hide
    /// Postgres-only features (the Roles tab) for SQLite sources.
    pub kind: &'static str,
    pub owner: String,
    pub encoding: String,
    /// On-disk size as a human string (`"42 MB"`).
    pub size_pretty: String,
}

#[derive(Debug, Serialize)]
pub struct TableInfo {
    pub schema: String,
    pub name: String,
    pub owner: String,
    pub row_estimate: i64,
    pub size_pretty: String,
}

#[derive(Debug, Serialize)]
pub struct RoleInfo {
    pub name: String,
    pub superuser: bool,
    pub can_login: bool,
    pub can_create_db: bool,
    pub can_create_role: bool,
}

#[derive(Debug, Serialize)]
pub struct QueryResult {
    pub columns: Vec<String>,
    /// `None` is SQL NULL — serde emits a real JSON `null`, which is what lets
    /// the frontend tell it apart from a TEXT value that happens to spell
    /// "NULL" (D2). Everything else arrives already rendered as text.
    pub rows: Vec<Vec<Option<String>>>,
    pub row_count: usize,
    pub elapsed_ms: u64,
    /// `true` when we capped the result set at [`ROW_LIMIT`]; the UI shows a
    /// banner so the operator knows results are partial.
    pub truncated: bool,
}

// ─── Source addressing ───────────────────────────────────────────────

/// A parsed database source id.
#[derive(Debug)]
pub enum Source {
    /// One of the configured SQLite databases, by name.
    Sqlite(String),
    /// A database on the configured Postgres instance, by name.
    Postgres(String),
}

/// Parses an opaque source id (`"sqlite:admin"`, `"pg:foo"`) into a [`Source`].
///
/// This only splits the string. Whether the name *resolves* is the backend's
/// question — for SQLite that is a catalog lookup, which is what keeps an
/// arbitrary name from reaching the filesystem.
pub fn parse_source(id: &str) -> anyhow::Result<Source> {
    if let Some(name) = id.strip_prefix("sqlite:") {
        if name.is_empty() {
            anyhow::bail!("missing database name in source id");
        }
        Ok(Source::Sqlite(name.to_string()))
    } else if let Some(db) = id.strip_prefix("pg:") {
        if db.is_empty() {
            anyhow::bail!("missing Postgres database name in source id");
        }
        Ok(Source::Postgres(db.to_string()))
    } else {
        anyhow::bail!("unknown database source: {id}")
    }
}

// ─── Dispatch ────────────────────────────────────────────────────────

/// Lists every browsable database: the SQLite ones first, then the Postgres
/// databases when `postgres_url` is configured.
///
/// A failure reaching Postgres is logged and swallowed. The SQLite sources are
/// always available, so a down or misconfigured Postgres must not take the whole
/// page with it — losing the console is exactly the wrong thing to happen while
/// you are trying to work out why a database is unreachable.
pub async fn list_databases(state: &AppState) -> anyhow::Result<Vec<DatabaseInfo>> {
    let mut out = sqlite::list_databases(state);
    if state.config.postgres_url.is_some() {
        match postgres::list_databases(state).await {
            Ok(dbs) => out.extend(dbs),
            Err(e) => tracing::warn!(error = %e, "could not list Postgres databases"),
        }
    }
    Ok(out)
}

/// One-call schema tree for the database identified by `source`: tables (with
/// counts) and views.
pub async fn schema_overview(state: &AppState, source: &str) -> anyhow::Result<schema::SchemaOverview> {
    match parse_source(source)? {
        Source::Sqlite(name) => sqlite::schema_overview(state, &name).await,
        Source::Postgres(db) => postgres::schema_overview(state, &db).await,
    }
}

/// Full description of one table in the database identified by `source`.
/// `schema` is Postgres-only; SQLite has a single namespace and ignores it.
pub async fn table_detail(
    state: &AppState,
    source: &str,
    schema: Option<&str>,
    table: &str,
) -> anyhow::Result<schema::TableDetail> {
    match parse_source(source)? {
        Source::Sqlite(name) => sqlite::table_detail(state, &name, table).await,
        Source::Postgres(db) => postgres::table_detail(state, &db, schema.unwrap_or("public"), table).await,
    }
}

/// One page of a table's rows under a validated browse plan (P2). The table
/// identity comes from the *introspected* detail, not the request — by the
/// time this runs, every identifier in play is introspection output.
pub async fn browse_rows(
    state: &AppState,
    source: &str,
    detail: &schema::TableDetail,
    plan: browse::BrowsePlan,
) -> anyhow::Result<browse::RowsPage> {
    match parse_source(source)? {
        Source::Sqlite(name) => sqlite::browse_rows(state, &name, &detail.name, plan).await,
        Source::Postgres(db) => postgres::browse_rows(state, &db, &detail.schema, &detail.name, plan).await,
    }
}

/// Which SQL dialect a source speaks — the only thing the edit planner needs to
/// know about the backend.
pub fn dialect_of(source: &str) -> anyhow::Result<edit::Dialect> {
    Ok(match parse_source(source)? {
        Source::Sqlite(_) => edit::Dialect::Sqlite,
        Source::Postgres(_) => edit::Dialect::Postgres,
    })
}

/// Applies a validated batch of staged edits (P5). The plan was generated for
/// *this* source's dialect; the backend only executes and verifies it.
pub async fn apply_edits(state: &AppState, source: &str, plan: edit::EditPlan) -> anyhow::Result<edit::ApplyReport> {
    match parse_source(source)? {
        Source::Sqlite(name) => sqlite::apply(state, &name, plan).await,
        Source::Postgres(db) => postgres::apply(state, &db, plan).await,
    }
}

/// The exact row count under the same filters (D8's "count exactly").
pub async fn browse_count(
    state: &AppState,
    source: &str,
    detail: &schema::TableDetail,
    plan: browse::BrowsePlan,
) -> anyhow::Result<browse::CountResult> {
    match parse_source(source)? {
        Source::Sqlite(name) => sqlite::browse_count(state, &name, &detail.name, plan).await,
        Source::Postgres(db) => postgres::browse_count(state, &db, &detail.schema, &detail.name, plan).await,
    }
}

/// Streams the filtered table through `tx` (D13), returning the rows streamed.
pub async fn export_stream(
    state: &AppState,
    source: &str,
    detail: &schema::TableDetail,
    plan: browse::BrowsePlan,
    format: browse::ExportFormat,
    tx: tokio::sync::mpsc::Sender<Result<String, std::io::Error>>,
) -> anyhow::Result<u64> {
    match parse_source(source)? {
        Source::Sqlite(name) => sqlite::export(state, &name, &detail.name, plan, format, tx).await,
        Source::Postgres(db) => postgres::export(state, &db, &detail.schema, &detail.name, plan, format, tx).await,
    }
}

/// Lists Postgres roles. SQLite has no role system, so this is only meaningful
/// for Postgres sources and the UI hides the tab for the others.
pub async fn list_roles(state: &AppState) -> anyhow::Result<Vec<RoleInfo>> {
    postgres::list_roles(state).await
}

/// Runs `sql` against the database identified by `source`. When `safe` is true
/// the backend enforces read-only execution at the engine level.
///
/// `run_id` and `account_id` enable cancellation (D12): the backend registers
/// the cancel handle before execution so `POST /database/query/cancel` can
/// fire it. Both are `Option`/defaulted so internal callers that don't need
/// cancellation can skip them.
pub async fn run_query(
    state: &AppState,
    source: &str,
    sql: &str,
    safe: bool,
    run_id: Option<&str>,
    account_id: i64,
) -> anyhow::Result<QueryResult> {
    match parse_source(source)? {
        Source::Sqlite(name) => sqlite::run_query(state, &name, sql, safe, run_id, account_id).await,
        Source::Postgres(db) => postgres::run_query(state, &db, sql, safe, run_id, account_id).await,
    }
}

// ─── EXPLAIN ────────────────────────────────────────────────────────

/// One node in an EXPLAIN plan tree. Both backends produce a flat list of these;
/// the frontend assembles the tree via `parent` references.
#[derive(Debug, Serialize)]
pub struct ExplainNode {
    pub id: String,
    pub parent: Option<String>,
    pub label: String,
    /// Extra detail (Postgres: cost/rows/width; SQLite: just the detail text).
    pub detail: Option<String>,
}

/// Runs EXPLAIN on the given SQL: `EXPLAIN QUERY PLAN` for SQLite,
/// `EXPLAIN (FORMAT JSON)` for Postgres. Always safe-mode.
pub async fn explain_query(state: &AppState, source: &str, sql: &str) -> anyhow::Result<Vec<ExplainNode>> {
    match parse_source(source)? {
        Source::Sqlite(name) => sqlite::explain_query(state, &name, sql).await,
        Source::Postgres(db) => postgres::explain_query(state, &db, sql).await,
    }
}

/// Returns the DDL (CREATE statement) for a table. SQLite: verbatim from
/// `sqlite_master.sql`; Postgres: reconstructed from introspection.
pub async fn get_ddl(state: &AppState, source: &str, schema: Option<&str>, table: &str) -> anyhow::Result<String> {
    match parse_source(source)? {
        Source::Sqlite(name) => sqlite::get_ddl(state, &name, table).await,
        Source::Postgres(db) => postgres::get_ddl(state, &db, schema.unwrap_or("public"), table).await,
    }
}

/// Quotes one SQL identifier part: doubles embedded double-quotes and wraps the
/// whole part. Both engines this console speaks share the `"…"` doubling rule.
///
/// Qualified names must be quoted per-part — `quote_ident(schema)` `.`
/// `quote_ident(table)` — so a dot *inside* a name can never be read as a
/// separator. Identifiers should only ever come from introspection output, not
/// from a request; this helper is defence in depth, not the defence (D6).
pub fn quote_ident(part: &str) -> String {
    format!("\"{}\"", part.replace('"', "\"\""))
}

/// Formats a byte count as a short human string (`"42 MB"`).
pub fn human_size(bytes: u64) -> String {
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

    #[test]
    fn source_ids_round_trip() {
        assert!(matches!(parse_source("sqlite:admin").unwrap(), Source::Sqlite(n) if n == "admin"));
        assert!(matches!(parse_source("pg:percy").unwrap(), Source::Postgres(d) if d == "percy"));
    }

    /// A malformed or unprefixed id is refused rather than guessed at — the id
    /// is the only thing standing between the caller and a backend.
    #[test]
    fn unknown_or_empty_sources_are_refused() {
        assert!(parse_source("admin").is_err());
        assert!(parse_source("mysql:foo").is_err());
        assert!(parse_source("sqlite:").is_err());
        assert!(parse_source("pg:").is_err());
    }

    /// Per-part quoting means neither a quote nor a dot in an identifier can
    /// change the shape of the SQL it lands in.
    #[test]
    fn quote_ident_neutralises_quotes_and_dots() {
        assert_eq!(quote_ident("account"), "\"account\"");
        assert_eq!(quote_ident("we\"ird"), "\"we\"\"ird\"");
        // A dot stays inside the quotes — it is part of the name, not a
        // schema separator.
        assert_eq!(quote_ident("a.b"), "\"a.b\"");
    }

    #[test]
    fn human_size_reads_naturally() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1024 * 1024 * 3), "3.0 MB");
    }
}
