//! PostgreSQL backend for the database console.
//!
//! `tokio-postgres` is connected per-request — the console doesn't see enough
//! traffic to warrant a pool, and per-request connections also give a clean way
//! to switch databases (Postgres has no `USE database`; a client must reconnect
//! to target a different one).
//!
//! ## Why the simple query protocol
//!
//! Every query here goes through `simple_query`, not `query`. The extended
//! protocol hands back binary values that have to be decoded per type OID, which
//! means a hand-written dispatch table over `Type::INT4`, `Type::UUID`,
//! `Type::TIMESTAMPTZ` and so on — and anything not in the table renders as
//! `<unsupported: …>`. That is a bad trade for a console whose entire job is to
//! stringify values for display: the server already knows how to render every
//! type it has, including the ones we have never heard of (extensions, domains,
//! arrays, `citext`, enums), and the simple protocol asks it to. It also reports
//! affected-row counts for writes, which the extended protocol's `query` silently
//! returns as an empty row set.
//!
//! ## Safety
//!
//! Safe mode runs inside `BEGIN TRANSACTION READ ONLY`, so the *server* refuses
//! writes no matter what rights the connecting role has — that holds against
//! parser-bypass tricks (comments, quoted identifiers, stacked statements) in a
//! way the text prefilter never could. Danger mode drops the transaction and
//! runs the statement as-is, which on a Postgres instance Vantage does not own
//! is genuinely destructive; that is why the UI names the source in its
//! confirmation and why every run is audited with the source id.

use std::time::{Duration, Instant};

use tokio_postgres::{config::Config as PgConfig, NoTls, SimpleQueryMessage};

use super::{DatabaseInfo, QueryResult, RoleInfo, TableInfo, ROW_LIMIT};
use crate::AppState;

/// Connection + statement deadline for one request. A console query that hangs
/// must not hold a connection (or an Axum handler) open indefinitely.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Parses the configured `postgres_url`, overriding the target database when
/// one is named. Errors when no URL is configured at all.
fn parse_url(url: &str, override_db: Option<&str>) -> anyhow::Result<PgConfig> {
    let mut cfg: PgConfig = url.parse()?;
    cfg.connect_timeout(QUERY_TIMEOUT);
    if let Some(db) = override_db {
        cfg.dbname(db);
    }
    Ok(cfg)
}

/// Opens a single short-lived connection, optionally targeting a database.
///
/// The spawned `connection` task drives the protocol; we await `client` for
/// queries. When the client is dropped at the end of the request, that task
/// exits on its own.
async fn connect(state: &AppState, db: Option<&str>) -> anyhow::Result<tokio_postgres::Client> {
    let url = state
        .config
        .postgres_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("postgres_url is not configured"))?;
    let cfg = parse_url(url, db)?;

    let (client, connection) = cfg.connect(NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::warn!(error = %e, "postgres connection task ended");
        }
    });
    Ok(client)
}

// ─── Catalog reads ───────────────────────────────────────────────────

pub async fn list_databases(state: &AppState) -> anyhow::Result<Vec<DatabaseInfo>> {
    let client = connect(state, None).await?;
    let rows = client
        .query(
            "SELECT d.datname AS name,
                    pg_get_userbyid(d.datdba) AS owner,
                    pg_encoding_to_char(d.encoding) AS encoding,
                    pg_size_pretty(pg_database_size(d.datname)) AS size_pretty
             FROM pg_database d
             WHERE d.datistemplate = false
             ORDER BY d.datname",
            &[],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let name: String = r.get("name");
            DatabaseInfo {
                id: format!("pg:{name}"),
                name,
                kind: "postgres",
                owner: r.get("owner"),
                encoding: r.get("encoding"),
                size_pretty: r.get("size_pretty"),
            }
        })
        .collect())
}

pub async fn list_tables(state: &AppState, db: &str) -> anyhow::Result<Vec<TableInfo>> {
    let client = connect(state, Some(db)).await?;
    let rows = client
        .query(
            "SELECT
                c.relnamespace::regnamespace::text             AS schema,
                c.relname                                      AS name,
                pg_get_userbyid(c.relowner)                    AS owner,
                COALESCE(s.n_live_tup, 0)::bigint              AS row_estimate,
                pg_size_pretty(pg_total_relation_size(c.oid))  AS size_pretty
             FROM pg_class c
             LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
             WHERE c.relkind = 'r'
               AND c.relnamespace::regnamespace::text NOT IN ('pg_catalog', 'information_schema')
             ORDER BY schema, name",
            &[],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| TableInfo {
            schema: r.get("schema"),
            name: r.get("name"),
            owner: r.get("owner"),
            row_estimate: r.get("row_estimate"),
            size_pretty: r.get("size_pretty"),
        })
        .collect())
}

pub async fn list_roles(state: &AppState) -> anyhow::Result<Vec<RoleInfo>> {
    let client = connect(state, None).await?;
    let rows = client
        .query(
            "SELECT rolname, rolsuper, rolcanlogin, rolcreatedb, rolcreaterole
             FROM pg_roles
             WHERE rolname NOT LIKE 'pg\\_%' ESCAPE '\\'
             ORDER BY rolname",
            &[],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| RoleInfo {
            name: r.get("rolname"),
            superuser: r.get("rolsuper"),
            can_login: r.get("rolcanlogin"),
            can_create_db: r.get("rolcreatedb"),
            can_create_role: r.get("rolcreaterole"),
        })
        .collect())
}

// ─── Query runner ────────────────────────────────────────────────────

/// Runs `sql` against `db`. When `safe` is true the statement executes inside a
/// read-only transaction, so the server rejects any write regardless of the
/// connecting role's privileges.
pub async fn run_query(state: &AppState, db: &str, sql: &str, safe: bool) -> anyhow::Result<QueryResult> {
    let mut client = connect(state, Some(db)).await?;
    let started = Instant::now();

    let messages = tokio::time::timeout(QUERY_TIMEOUT, async {
        if safe {
            let tx = client.build_transaction().read_only(true).start().await?;
            let out = tx.simple_query(sql).await?;
            tx.commit().await?;
            Ok::<_, tokio_postgres::Error>(out)
        } else {
            client.simple_query(sql).await
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "query exceeded the {}s limit and was abandoned",
            QUERY_TIMEOUT.as_secs()
        )
    })??;

    Ok(collect(messages, started.elapsed().as_millis() as u64))
}

/// Folds the simple-protocol message stream into a [`QueryResult`].
///
/// A batch can contain several statements' worth of messages. We report the
/// rows of the last statement that produced any, and for a batch that produced
/// none (a write, a DDL) we report the affected count from `CommandComplete` —
/// so `DELETE FROM …` in danger mode says "3 rows" rather than looking like it
/// did nothing.
fn collect(messages: Vec<SimpleQueryMessage>, elapsed_ms: u64) -> QueryResult {
    let mut columns: Vec<String> = Vec::new();
    let mut cells: Vec<Vec<String>> = Vec::new();
    let mut total = 0usize;
    let mut affected = 0u64;

    for msg in messages {
        match msg {
            SimpleQueryMessage::Row(row) => {
                if columns.is_empty() {
                    columns = row.columns().iter().map(|c| c.name().to_string()).collect();
                }
                total += 1;
                if cells.len() < ROW_LIMIT {
                    // A NULL arrives as `None`. Rendering it as the text "NULL"
                    // matches the SQLite backend, and the frontend documents
                    // that it cannot distinguish that from a literal 'NULL'.
                    cells.push(
                        (0..row.columns().len())
                            .map(|i| row.get(i).unwrap_or("NULL").to_string())
                            .collect(),
                    );
                }
            }
            SimpleQueryMessage::CommandComplete(n) => affected += n,
            // `SimpleQueryMessage` is `#[non_exhaustive]`: a future variant
            // (row descriptions for an empty result, say) must not break the
            // build, and carries nothing we render.
            _ => {}
        }
    }

    QueryResult {
        columns,
        rows: cells,
        // A statement that returned rows reports rows; one that returned none
        // reports what it changed.
        row_count: if total > 0 { total } else { affected as usize },
        elapsed_ms,
        truncated: total > ROW_LIMIT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::Path;

    /// The URL is config-only, so an unconfigured instance must be a clean
    /// "not configured" error rather than a panic or a hang.
    #[tokio::test]
    async fn an_unconfigured_instance_reports_rather_than_panics() {
        let state = crate::build_state_with(Config::test_default(), Path::new(":memory:"))
            .await
            .unwrap();
        let err = list_databases(&state).await.unwrap_err().to_string();
        assert!(err.contains("postgres_url"), "got: {err}");
    }

    #[test]
    fn url_parses_and_the_database_can_be_overridden() {
        let cfg = parse_url("postgres://admin:pw@10.0.0.5:5432/appdb", None).unwrap();
        assert_eq!(cfg.get_dbname(), Some("appdb"));

        let switched = parse_url("postgres://admin:pw@10.0.0.5:5432/appdb", Some("other")).unwrap();
        assert_eq!(switched.get_dbname(), Some("other"));
    }

    #[test]
    fn a_malformed_url_is_an_error_not_a_panic() {
        assert!(parse_url("not a dsn", None).is_err());
    }

    /// A write reports what it changed. Without this the simple protocol's
    /// empty row set would render as "0 rows" for a successful DELETE.
    #[test]
    fn a_write_reports_its_affected_count() {
        let r = collect(vec![SimpleQueryMessage::CommandComplete(3)], 5);
        assert_eq!(r.row_count, 3);
        assert!(r.columns.is_empty());
        assert!(!r.truncated);
    }

    #[test]
    fn an_empty_batch_is_a_zero_row_result_not_an_error() {
        let r = collect(Vec::new(), 1);
        assert_eq!(r.row_count, 0);
        assert!(r.rows.is_empty());
    }
}
