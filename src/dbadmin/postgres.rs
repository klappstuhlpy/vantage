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

use futures_util::TryStreamExt;
use tokio_postgres::types::ToSql;
use tokio_postgres::{config::Config as PgConfig, NoTls, SimpleQueryMessage};

use super::browse::{self, BrowsePlan, CountResult, ExportFormat, RowsPage};
use super::edit::{self, AppliedStatement, ApplyReport, EditPlan};
use super::schema::{Column, Fk, Index, SchemaOverview, TableDetail, ViewInfo};
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

async fn list_tables_on(client: &tokio_postgres::Client) -> anyhow::Result<Vec<TableInfo>> {
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

// ─── Introspection (DB Studio P1) ────────────────────────────────────

/// Tables and views in one call — what the schema tree renders.
pub async fn schema_overview(state: &AppState, db: &str) -> anyhow::Result<SchemaOverview> {
    let client = connect(state, Some(db)).await?;

    let tables = list_tables_on(&client).await?;
    let views = client
        .query(
            "SELECT c.relnamespace::regnamespace::text AS schema,
                    c.relname                          AS name
             FROM pg_class c
             WHERE c.relkind = 'v'
               AND c.relnamespace::regnamespace::text NOT IN ('pg_catalog', 'information_schema')
             ORDER BY schema, name",
            &[],
        )
        .await?
        .into_iter()
        .map(|r| ViewInfo {
            schema: r.get("schema"),
            name: r.get("name"),
        })
        .collect();

    Ok(SchemaOverview { tables, views })
}

/// Columns, PK, foreign keys and indexes of one table (or view), from the
/// `pg_catalog` tables. Schema and table travel as bound parameters — no
/// request string is ever spliced into these queries.
pub async fn table_detail(state: &AppState, db: &str, schema: &str, table: &str) -> anyhow::Result<TableDetail> {
    let client = connect(state, Some(db)).await?;

    // Resolve the relation first: the request's names either match a real
    // table/view or the whole call is refused — nothing downstream ever sees
    // an unresolved name.
    let relkind: Option<String> = client
        .query_opt(
            "SELECT c.relkind::text AS relkind
             FROM pg_class c
             JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = $1 AND c.relname = $2",
            &[&schema, &table],
        )
        .await?
        .map(|r| r.get("relkind"));
    let kind = match relkind.as_deref() {
        // 'r' plain table, 'p' partitioned table — both browse as tables.
        Some("r") | Some("p") => "table",
        // 'v' view, 'm' materialized view — both read-only in the UI.
        Some("v") | Some("m") => "view",
        _ => anyhow::bail!("unknown table: {schema}.{table}"),
    };

    let columns = client
        .query(
            "SELECT a.attname                                AS name,
                    format_type(a.atttypid, a.atttypmod)     AS data_type,
                    NOT a.attnotnull                         AS nullable,
                    pg_get_expr(ad.adbin, ad.adrelid)        AS default_expr,
                    pk.ordinal                               AS pk_ordinal
             FROM pg_attribute a
             JOIN pg_class c ON c.oid = a.attrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
             LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
             LEFT JOIN LATERAL (
                 SELECT k.ord AS ordinal
                 FROM pg_constraint con,
                      unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord)
                 WHERE con.conrelid = c.oid AND con.contype = 'p' AND k.attnum = a.attnum
             ) pk ON true
             WHERE n.nspname = $1 AND c.relname = $2
               AND a.attnum > 0 AND NOT a.attisdropped
             ORDER BY a.attnum",
            &[&schema, &table],
        )
        .await?
        .into_iter()
        .map(|r| Column {
            name: r.get("name"),
            data_type: r.get("data_type"),
            nullable: r.get("nullable"),
            default: r.get("default_expr"),
            pk_ordinal: r.get::<_, Option<i64>>("pk_ordinal").map(|o| o as u32),
        })
        .collect();

    let foreign_keys = client
        .query(
            "SELECT (SELECT array_agg(a.attname ORDER BY k.ord)
                     FROM unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord)
                     JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum) AS columns,
                    fn.nspname AS ref_schema,
                    fc.relname AS ref_table,
                    (SELECT array_agg(a.attname ORDER BY k.ord)
                     FROM unnest(con.confkey) WITH ORDINALITY AS k(attnum, ord)
                     JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = k.attnum) AS ref_columns
             FROM pg_constraint con
             JOIN pg_class c ON c.oid = con.conrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
             JOIN pg_class fc ON fc.oid = con.confrelid
             JOIN pg_namespace fn ON fn.oid = fc.relnamespace
             WHERE con.contype = 'f' AND n.nspname = $1 AND c.relname = $2
             ORDER BY con.conname",
            &[&schema, &table],
        )
        .await?
        .into_iter()
        .map(|r| Fk {
            columns: r.get("columns"),
            ref_schema: r.get("ref_schema"),
            ref_table: r.get("ref_table"),
            ref_columns: r.get("ref_columns"),
        })
        .collect();

    let indexes = client
        .query(
            // `pg_get_indexdef(oid, n, true)` renders member n as a column name
            // or expression — the server's own rendering, not a reconstruction.
            "SELECT ci.relname     AS name,
                    ix.indisunique AS is_unique,
                    (SELECT array_agg(pg_get_indexdef(ix.indexrelid, s.i::int, true) ORDER BY s.i)
                     FROM generate_series(1, ix.indnatts) AS s(i)) AS columns
             FROM pg_index ix
             JOIN pg_class ci ON ci.oid = ix.indexrelid
             JOIN pg_class c ON c.oid = ix.indrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = $1 AND c.relname = $2
             ORDER BY ci.relname",
            &[&schema, &table],
        )
        .await?
        .into_iter()
        .map(|r| Index {
            name: r.get("name"),
            columns: r.get("columns"),
            unique: r.get("is_unique"),
        })
        .collect();

    Ok(TableDetail {
        schema: schema.to_string(),
        name: table.to_string(),
        kind,
        columns,
        foreign_keys,
        indexes,
    })
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

// ─── Table browser (DB Studio P2) ────────────────────────────────────

/// One page of rows under a validated [`BrowsePlan`], over the extended
/// protocol: the SELECT list casts every column to text (D4), so binding works
/// and every cell decodes as `Option<String>` — no per-OID table. Runs inside
/// a read-only transaction like every other browse read.
pub async fn browse_rows(
    state: &AppState,
    db: &str,
    schema: &str,
    table: &str,
    plan: BrowsePlan,
) -> anyhow::Result<RowsPage> {
    let mut client = connect(state, Some(db)).await?;
    let started = Instant::now();
    let (sql, params) = browse::pg_query(&plan, schema, table);
    let refs: Vec<&(dyn ToSql + Sync)> = params.iter().map(|p| p as &(dyn ToSql + Sync)).collect();

    let rows = tokio::time::timeout(QUERY_TIMEOUT, async {
        let tx = client.build_transaction().read_only(true).start().await?;
        let rows = tx.query(&sql, &refs).await?;
        tx.commit().await?;
        Ok::<_, tokio_postgres::Error>(rows)
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "query exceeded the {}s limit and was abandoned",
            QUERY_TIMEOUT.as_secs()
        )
    })??;

    let columns: Vec<String> = plan.columns.iter().map(|c| c.name.clone()).collect();
    let cells: Vec<Vec<Option<String>>> = rows
        .iter()
        .map(|r| (0..r.len()).map(|i| r.get::<_, Option<String>>(i)).collect())
        .collect();
    let has_more = cells.len() == plan.limit;

    Ok(RowsPage {
        columns,
        rows: cells,
        offset: plan.offset,
        has_more,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

/// Exact `COUNT(*)` under the same filters — D8's "count exactly" affordance.
pub async fn browse_count(
    state: &AppState,
    db: &str,
    schema: &str,
    table: &str,
    plan: BrowsePlan,
) -> anyhow::Result<CountResult> {
    let mut client = connect(state, Some(db)).await?;
    let started = Instant::now();
    let (sql, params) = browse::pg_count(&plan, schema, table);
    let refs: Vec<&(dyn ToSql + Sync)> = params.iter().map(|p| p as &(dyn ToSql + Sync)).collect();

    let row = tokio::time::timeout(QUERY_TIMEOUT, async {
        let tx = client.build_transaction().read_only(true).start().await?;
        let row = tx.query_one(&sql, &refs).await?;
        tx.commit().await?;
        Ok::<_, tokio_postgres::Error>(row)
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "count exceeded the {}s limit and was abandoned",
            QUERY_TIMEOUT.as_secs()
        )
    })??;

    let count: i64 = row.get::<_, String>(0).parse()?;
    Ok(CountResult {
        count,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

/// Streams the filtered table through `tx` as encoded chunks (D13), returning
/// the number of rows streamed. Deliberately not under [`QUERY_TIMEOUT`]: a
/// large export legitimately outlives 30s, the row stream applies its own
/// backpressure, and the audit entry records what actually left.
pub async fn export(
    state: &AppState,
    db: &str,
    schema: &str,
    table: &str,
    plan: BrowsePlan,
    format: ExportFormat,
    out: tokio::sync::mpsc::Sender<Result<String, std::io::Error>>,
) -> anyhow::Result<u64> {
    const CHUNK: usize = 64 * 1024;

    let run = async {
        let mut client = connect(state, Some(db)).await?;
        let (sql, params) = browse::pg_export_query(&plan, schema, table);
        let columns: Vec<String> = plan.columns.iter().map(|c| c.name.clone()).collect();

        let tx = client.build_transaction().read_only(true).start().await?;
        let stream = tx
            .query_raw(&sql, params.iter().map(|p| p as &(dyn ToSql + Sync)))
            .await?;
        futures_util::pin_mut!(stream);

        let mut buf = format.header(&columns);
        let mut count = 0u64;
        while let Some(row) = stream.try_next().await? {
            let cells: Vec<Option<String>> = (0..row.len()).map(|i| row.get(i)).collect();
            buf.push_str(&format.line(&columns, &cells));
            count += 1;
            if buf.len() >= CHUNK && out.send(Ok(std::mem::take(&mut buf))).await.is_err() {
                return Ok(count);
            }
        }
        if !buf.is_empty() {
            let _ = out.send(Ok(buf)).await;
        }
        Ok(count)
    };

    let result: anyhow::Result<u64> = run.await;
    if let Err(e) = &result {
        // Truncate the body with an error rather than ending it cleanly — a
        // partial file that looks complete is worse than a broken one.
        let _ = out.send(Err(std::io::Error::other(e.to_string()))).await;
    }
    result
}

// ─── Staged edits (P5) ───────────────────────────────────────────────

/// Applies a validated batch in one transaction, verifying that every statement
/// affected exactly one row. See the SQLite twin for why the verification is the
/// feature rather than a formality.
///
/// Unlike the console runner this uses the **extended** protocol: the statements
/// carry bound parameters, which the simple protocol cannot express. That is the
/// same split the grid makes (D4) — the console renders arbitrary results as
/// text, the generated paths bind values.
///
/// Rollback is explicit. `tokio_postgres`'s transaction also rolls back on drop,
/// but an awaited `rollback()` is a completed round trip rather than a best
/// effort at drop time, and this is the path where "did it definitely not
/// apply?" has to have a definite answer.
pub async fn apply(state: &AppState, db: &str, plan: EditPlan) -> anyhow::Result<ApplyReport> {
    let mut client = connect(state, Some(db)).await?;
    let started = Instant::now();

    let report = tokio::time::timeout(QUERY_TIMEOUT, async {
        let tx = client.transaction().await?;

        let mut statements = Vec::with_capacity(plan.statements.len());
        for (i, st) in plan.statements.iter().enumerate() {
            let refs: Vec<&(dyn ToSql + Sync)> = st.params.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
            let affected = match tx.execute(st.sql.as_str(), &refs).await {
                Ok(n) => n,
                Err(e) => {
                    tx.rollback().await.ok();
                    return Err(anyhow::anyhow!("statement {}: {e}", i + 1));
                }
            };
            if affected != 1 {
                tx.rollback().await.ok();
                return Err(edit::row_count_mismatch(i + 1, affected));
            }
            statements.push(AppliedStatement {
                kind: st.kind,
                preview: st.preview.clone(),
                affected,
            });
        }

        tx.commit().await?;
        Ok::<_, anyhow::Error>(statements)
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "the batch exceeded the {}s limit and was abandoned — nothing was committed",
            QUERY_TIMEOUT.as_secs()
        )
    })??;

    Ok(ApplyReport {
        applied: report.len(),
        statements: report,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

// ─── Query runner ────────────────────────────────────────────────────

/// Runs `sql` against `db`. When `safe` is true the statement executes inside a
/// read-only transaction, so the server rejects any write regardless of the
/// connecting role's privileges.
pub async fn run_query(
    state: &AppState,
    db: &str,
    sql: &str,
    safe: bool,
    run_id: Option<&str>,
    account_id: i64,
) -> anyhow::Result<QueryResult> {
    let mut client = connect(state, Some(db)).await?;

    if let Some(id) = run_id {
        let token = client.cancel_token();
        state
            .run_registry
            .register(id.to_string(), account_id, super::cancel::CancelHandle::Postgres(token));
    }

    let started = Instant::now();

    let result = tokio::time::timeout(QUERY_TIMEOUT, async {
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
    })?;

    if let Some(id) = run_id {
        state.run_registry.remove(id);
    }

    Ok(collect(result?, started.elapsed().as_millis() as u64))
}

// ─── EXPLAIN ────────────────────────────────────────────────────────

/// Runs `EXPLAIN (FORMAT JSON) <sql>` and flattens the Postgres plan tree
/// into a list of nodes the frontend can render.
pub async fn explain_query(state: &AppState, db: &str, sql: &str) -> anyhow::Result<Vec<super::ExplainNode>> {
    let mut client = connect(state, Some(db)).await?;
    let explain_sql = format!("EXPLAIN (FORMAT JSON) {sql}");

    let tx = client.build_transaction().read_only(true).start().await?;
    let messages = tx.simple_query(&explain_sql).await?;
    tx.commit().await?;

    // Postgres returns one row with one column containing the JSON plan.
    let mut json_text = String::new();
    for msg in &messages {
        if let SimpleQueryMessage::Row(row) = msg {
            if let Some(s) = row.get(0) {
                json_text.push_str(s);
            }
        }
    }

    if json_text.is_empty() {
        return Ok(Vec::new());
    }

    // Parse the JSON array and flatten the nested plan tree into ExplainNodes.
    let plans: serde_json::Value = serde_json::from_str(&json_text)?;
    let mut nodes = Vec::new();
    let mut next_id: u64 = 0;

    fn walk(plan: &serde_json::Value, parent: Option<String>, nodes: &mut Vec<super::ExplainNode>, next_id: &mut u64) {
        let id = next_id.to_string();
        *next_id += 1;

        let node_type = plan.get("Node Type").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let relation = plan.get("Relation Name").and_then(|v| v.as_str());
        let alias = plan.get("Alias").and_then(|v| v.as_str());
        let total_cost = plan.get("Total Cost").and_then(|v| v.as_f64());
        let plan_rows = plan.get("Plan Rows").and_then(|v| v.as_u64());
        let plan_width = plan.get("Plan Width").and_then(|v| v.as_u64());

        let mut label = node_type.to_string();
        if let Some(rel) = relation {
            label.push_str(&format!(" on {rel}"));
            if let Some(a) = alias {
                if a != rel {
                    label.push_str(&format!(" ({a})"));
                }
            }
        }

        let detail = match (total_cost, plan_rows, plan_width) {
            (Some(cost), Some(rows), Some(width)) => Some(format!("cost={cost:.2} rows={rows} width={width}")),
            _ => None,
        };

        nodes.push(super::ExplainNode {
            id: id.clone(),
            parent,
            label,
            detail,
        });

        if let Some(plans) = plan.get("Plans").and_then(|v| v.as_array()) {
            for child in plans {
                walk(child, Some(id.clone()), nodes, next_id);
            }
        }
    }

    if let Some(arr) = plans.as_array() {
        for entry in arr {
            if let Some(plan) = entry.get("Plan") {
                walk(plan, None, &mut nodes, &mut next_id);
            }
        }
    }

    Ok(nodes)
}

// ─── DDL reconstruction ─────────────────────────────────────────────

/// Reconstructs a CREATE TABLE statement from Postgres introspection.
/// Not `pg_dump` fidelity — comments, GRANTs, tablespaces are omitted — but
/// shows columns, types, defaults, NOT NULL, primary key, and foreign keys.
pub async fn get_ddl(state: &AppState, db: &str, schema: &str, table: &str) -> anyhow::Result<String> {
    let detail = super::table_detail(state, &format!("pg:{db}"), Some(schema), table).await?;
    let mut out = String::new();

    let qualified = if schema == "public" {
        super::quote_ident(table)
    } else {
        format!("{}.{}", super::quote_ident(schema), super::quote_ident(table))
    };

    out.push_str(&format!("CREATE TABLE {} (\n", qualified));

    let col_lines: Vec<String> = detail
        .columns
        .iter()
        .map(|col| {
            let mut line = format!("  {} {}", super::quote_ident(&col.name), col.data_type);
            if !col.nullable {
                line.push_str(" NOT NULL");
            }
            if let Some(ref def) = col.default {
                line.push_str(&format!(" DEFAULT {def}"));
            }
            line
        })
        .collect();

    // Primary key: columns that have a pk_ordinal, sorted by ordinal.
    let mut pk_cols: Vec<(&str, u32)> = detail
        .columns
        .iter()
        .filter_map(|c| c.pk_ordinal.map(|o| (c.name.as_str(), o)))
        .collect();
    pk_cols.sort_by_key(|(_, o)| *o);

    let mut constraints = Vec::new();
    if !pk_cols.is_empty() {
        constraints.push(format!(
            "  PRIMARY KEY ({})",
            pk_cols
                .iter()
                .map(|(c, _)| super::quote_ident(c))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    // Foreign keys
    for fk in &detail.foreign_keys {
        constraints.push(format!(
            "  FOREIGN KEY ({}) REFERENCES {}.{} ({})",
            fk.columns
                .iter()
                .map(|c| super::quote_ident(c))
                .collect::<Vec<_>>()
                .join(", "),
            super::quote_ident(&fk.ref_schema),
            super::quote_ident(&fk.ref_table),
            fk.ref_columns
                .iter()
                .map(|c| super::quote_ident(c))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let mut all_lines = col_lines;
    all_lines.extend(constraints);
    out.push_str(&all_lines.join(",\n"));
    out.push_str("\n);\n");

    // Indexes (skip the implicit PK index)
    let pk_names: Vec<&str> = pk_cols.iter().map(|(n, _)| *n).collect();
    for idx in &detail.indexes {
        // Skip if this index covers exactly the PK columns
        if idx.unique && idx.columns.iter().map(|s| s.as_str()).collect::<Vec<_>>() == pk_names {
            continue;
        }
        let unique = if idx.unique { "UNIQUE " } else { "" };
        out.push_str(&format!(
            "\nCREATE {}INDEX {} ON {} ({});",
            unique,
            super::quote_ident(&idx.name),
            qualified,
            idx.columns
                .iter()
                .map(|c| super::quote_ident(c))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    Ok(out)
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
    let mut cells: Vec<Vec<Option<String>>> = Vec::new();
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
                    // A NULL arrives as `None` and stays `None` (D2): serde
                    // emits a real JSON `null`, so the frontend can mark it
                    // apart from a text value that happens to spell "NULL".
                    cells.push(
                        (0..row.columns().len())
                            .map(|i| row.get(i).map(str::to_string))
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
