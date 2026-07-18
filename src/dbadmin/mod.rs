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

pub mod postgres;
pub mod routes;
mod safety;
pub mod sqlite;

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
    pub rows: Vec<Vec<String>>,
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

/// Lists the tables in the database identified by `source`.
pub async fn list_tables(state: &AppState, source: &str) -> anyhow::Result<Vec<TableInfo>> {
    match parse_source(source)? {
        Source::Sqlite(name) => sqlite::list_tables(state, &name).await,
        Source::Postgres(db) => postgres::list_tables(state, &db).await,
    }
}

/// Lists Postgres roles. SQLite has no role system, so this is only meaningful
/// for Postgres sources and the UI hides the tab for the others.
pub async fn list_roles(state: &AppState) -> anyhow::Result<Vec<RoleInfo>> {
    postgres::list_roles(state).await
}

/// Runs `sql` against the database identified by `source`. When `safe` is true
/// the backend enforces read-only execution at the engine level.
pub async fn run_query(state: &AppState, source: &str, sql: &str, safe: bool) -> anyhow::Result<QueryResult> {
    match parse_source(source)? {
        Source::Sqlite(name) => sqlite::run_query(state, &name, sql, safe).await,
        Source::Postgres(db) => postgres::run_query(state, &db, sql, safe).await,
    }
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

    #[test]
    fn human_size_reads_naturally() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1024 * 1024 * 3), "3.0 MB");
    }
}
