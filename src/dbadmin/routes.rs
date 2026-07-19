//! `/database` routes — browse the configured SQLite and PostgreSQL sources and
//! run ad-hoc queries against them behind a safe-mode gate.
//!
//! Every query is recorded to the audit log with the acting admin, their
//! address, the source it ran against, and a bounded snippet of the SQL —
//! including the ones safe mode refused, which are the interesting ones. The
//! source id is part of every entry because "an admin ran a DELETE" and "an
//! admin ran a DELETE against the production Postgres" are different events.
//!
//! Danger mode is additionally sudo-gated: a query that runs without the
//! read-only guard requires a re-authentication inside the sudo window, same
//! as every other destructive action in the app (D3 in `DB_STUDIO_PLAN.md`).
//!
//! ## Where global safe mode sits (and where it does not)
//!
//! `POST /database/apply` — the staged-edit batch (P5) — is on
//! [`crate::safemode`]'s destructive list, so engaging global safe mode turns
//! the whole editing capability off at the middleware, before any handler runs.
//! Preview stays reachable: reading what a batch *would* run changes nothing.
//!
//! `POST /database/query` in danger mode is **not** on that list, and so a
//! hand-written `DELETE` still runs while safe mode is engaged. That is a real
//! asymmetry, not an oversight to be discovered later: safe mode's job is to
//! freeze the *host* — containers, firewall, proxy, scripts — and the console
//! is also the tool you diagnose with while everything else is frozen. Adding
//! `/database/query` to the list would take reads with it (they share a route
//! and the flag lives in the body, where the path-based guard cannot see it),
//! so the honest options are "danger queries stay reachable" or "the console
//! goes dark under safe mode". This picks the first, and the second is a
//! deliberate decision for whoever wants it, not a bug fix.

use std::sync::OnceLock;

use askama::Template;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Extension, Form, Router,
};
use cookie::Cookie;
use serde::{Deserialize, Serialize};

use crate::account::routes::{Sudo, SudoRejection};
use crate::audit;
use crate::dbadmin;
use crate::session::{self, Account};
use crate::AppState;

#[derive(Template)]
#[template(path = "database.html")]
struct AdminDatabaseTemplate {
    account: Option<Account>,
    active_page: &'static str,
    /// Whether an external Postgres instance is configured. Drives the page's
    /// subtitle and whether the Roles tab can ever appear.
    has_postgres: bool,
}

async fn database_page(State(state): State<AppState>, account: Account) -> Result<AdminDatabaseTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(AdminDatabaseTemplate {
        account: Some(account),
        active_page: "database",
        has_postgres: state.config.postgres_url.is_some(),
    })
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

fn forbidden() -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::FORBIDDEN,
        Json(ApiError {
            error: "forbidden".into(),
        }),
    )
}

/// A failed query (bad SQL, missing table, unreachable source, …) is the
/// caller's problem, not an outage — surface it as a 400 with the engine's
/// message so the UI can show exactly what went wrong.
fn query_error(e: impl ToString) -> (StatusCode, Json<ApiError>) {
    (StatusCode::BAD_REQUEST, Json(ApiError { error: e.to_string() }))
}

// ─── Catalog ─────────────────────────────────────────────────────────

/// Which source a catalog call is about.
#[derive(Deserialize)]
struct SourceQuery {
    /// Source id (`sqlite:admin`, `pg:appdb`). Defaults to Vantage's own
    /// database so a client that has not picked yet still gets something.
    #[serde(default = "default_source")]
    source: String,
}

fn default_source() -> String {
    "sqlite:admin".into()
}

async fn list_databases(
    State(state): State<AppState>,
    account: Account,
) -> Result<Json<Vec<dbadmin::DatabaseInfo>>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    dbadmin::list_databases(&state).await.map(Json).map_err(query_error)
}

/// Postgres roles. Reading the role table tells you who can log in and who is a
/// superuser, which is privileged reconnaissance in its own right — so it is
/// audited even though it changes nothing.
async fn list_roles(
    State(state): State<AppState>,
    account: Account,
) -> Result<Json<Vec<dbadmin::RoleInfo>>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    let out = dbadmin::list_roles(&state).await;
    audit::event("database.roles.read", &account)
        .ok(out.is_ok())
        .record(&state.db)
        .await;
    out.map(Json).map_err(query_error)
}

// ─── Introspection (DB Studio P1) ────────────────────────────────────

/// Sessions × sources whose introspection has already been audited. Bounded
/// LRU; a process restart forgetting it means at worst one extra audit row.
static INTROSPECTED: OnceLock<quick_cache::sync::Cache<(String, String), ()>> = OnceLock::new();

/// Records the privileged read that introspection is — once per (session,
/// source), not per click. The signal is "this admin looked at the shape of
/// this database"; a row for every expanded table in the tree would drown it.
/// Both introspection endpoints call this, so a caller that skips `/schema`
/// and goes straight to `/table` is still on the record.
async fn audit_introspection(state: &AppState, account: &Account, cookies: &[Cookie<'static>], source: &str) {
    let session_id = session::session_id_from(cookies, state.config.session_cookie_name()).unwrap_or_default();
    let cache = INTROSPECTED.get_or_init(|| quick_cache::sync::Cache::new(4096));
    let key = (session_id, source.to_string());
    if cache.get(&key).is_some() {
        return;
    }
    cache.insert(key.clone(), ());
    audit::event("database.schema.read", account)
        .target(source)
        .record(&state.db)
        .await;
}

/// The schema tree: tables and views of one source, in one call.
async fn schema_overview(
    State(state): State<AppState>,
    account: Account,
    Extension(cookies): Extension<Vec<Cookie<'static>>>,
    Query(q): Query<SourceQuery>,
) -> Result<Json<dbadmin::schema::SchemaOverview>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    let out = dbadmin::schema_overview(&state, &q.source).await;
    if out.is_ok() {
        audit_introspection(&state, &account, &cookies, &q.source).await;
    }
    out.map(Json).map_err(query_error)
}

/// Which table a detail call is about. `schema` is Postgres-only.
#[derive(Deserialize)]
struct TableQuery {
    #[serde(default = "default_source")]
    source: String,
    schema: Option<String>,
    table: String,
}

/// One table's columns, primary key, foreign keys and indexes.
async fn table_detail(
    State(state): State<AppState>,
    account: Account,
    Extension(cookies): Extension<Vec<Cookie<'static>>>,
    Query(q): Query<TableQuery>,
) -> Result<Json<dbadmin::schema::TableDetail>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    let out = dbadmin::table_detail(&state, &q.source, q.schema.as_deref(), &q.table).await;
    if out.is_ok() {
        audit_introspection(&state, &account, &cookies, &q.source).await;
    }
    out.map(Json).map_err(query_error)
}

// ─── Table browser (DB Studio P2) ────────────────────────────────────

/// A browse request as it arrives on the query string. Filters are structured
/// JSON — `[{column, op, value}]` — never SQL (D5); everything is validated
/// against the introspected table before any SQL is assembled.
#[derive(Deserialize)]
struct BrowseQuery {
    #[serde(default = "default_source")]
    source: String,
    schema: Option<String>,
    table: String,
    /// JSON-encoded `Vec<FilterSpec>`.
    filters: Option<String>,
    /// Sort column; `desc` flips it.
    sort: Option<String>,
    #[serde(default)]
    desc: bool,
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
    /// Export only: `csv` (default) or `ndjson`.
    format: Option<String>,
}

impl BrowseQuery {
    /// Introspects the table and validates the request into a plan. The two
    /// steps are one function because the order is the point: identifiers are
    /// checked against introspection output before SQL assembly ever sees them.
    async fn resolve(
        &self,
        state: &AppState,
    ) -> anyhow::Result<(dbadmin::schema::TableDetail, dbadmin::browse::BrowsePlan)> {
        let detail = dbadmin::table_detail(state, &self.source, self.schema.as_deref(), &self.table).await?;
        let filters: Vec<dbadmin::browse::FilterSpec> = match self.filters.as_deref() {
            Some(s) if !s.is_empty() => {
                serde_json::from_str(s).map_err(|e| anyhow::anyhow!("malformed filters: {e}"))?
            }
            _ => Vec::new(),
        };
        let sort = self.sort.clone().map(|c| (c, self.desc));
        let plan = dbadmin::browse::plan(&detail, filters, sort, self.limit, self.offset)?;
        Ok((detail, plan))
    }

    /// A compact description of the filters for the audit log — what was
    /// exported matters as much as that an export happened.
    fn filter_summary(&self) -> serde_json::Value {
        match self.filters.as_deref() {
            Some(s) if !s.is_empty() => serde_json::from_str(s).unwrap_or_else(|_| serde_json::Value::String(s.into())),
            _ => serde_json::Value::Array(Vec::new()),
        }
    }
}

/// One page of rows for the grid. Not audited: paging is the same privilege as
/// the schema read that already was, and a row per scroll would bury the log.
async fn browse_rows(
    State(state): State<AppState>,
    account: Account,
    Query(q): Query<BrowseQuery>,
) -> Result<Json<dbadmin::browse::RowsPage>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    let (detail, plan) = q.resolve(&state).await.map_err(query_error)?;
    dbadmin::browse_rows(&state, &q.source, &detail, plan)
        .await
        .map(Json)
        .map_err(query_error)
}

/// Exact count under the current filters (D8's "count exactly").
async fn browse_count(
    State(state): State<AppState>,
    account: Account,
    Query(q): Query<BrowseQuery>,
) -> Result<Json<dbadmin::browse::CountResult>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    let (detail, plan) = q.resolve(&state).await.map_err(query_error)?;
    dbadmin::browse_count(&state, &q.source, &detail, plan)
        .await
        .map(Json)
        .map_err(query_error)
}

/// Streams the filtered table as CSV/NDJSON (D13). An export is exfiltration
/// with a smile, and it must look that way in the log: every one is audited
/// with source, table, filters, format and the row count actually streamed —
/// recorded when the stream finishes, by the task that fed it.
async fn export(
    State(state): State<AppState>,
    account: Account,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    use axum::http::header;

    if !account.is_admin() {
        return Err(forbidden());
    }
    let format = dbadmin::browse::ExportFormat::parse(q.format.as_deref().unwrap_or("csv")).map_err(query_error)?;
    let (detail, plan) = q.resolve(&state).await.map_err(query_error)?;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<String, std::io::Error>>(16);
    let body = axum::body::Body::from_stream(futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx)));

    // The filename says which table this was; anything shell-hostile in the
    // name flattens to '_' rather than escaping into the header.
    let safe_name: String = detail
        .name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let disposition = format!("attachment; filename=\"{}.{}\"", safe_name, format.extension());

    let source = q.source.clone();
    let summary = q.filter_summary();
    let table_label = format!("{}.{}", detail.schema, detail.name);
    let state_task = state.clone();
    tokio::spawn(async move {
        let outcome = dbadmin::export_stream(&state_task, &source, &detail, plan, format, tx).await;
        let mut event = audit::event("database.export", &account).target(&source);
        match &outcome {
            Ok(rows) => {
                event = event.detail(serde_json::json!({
                    "table": table_label,
                    "format": format.extension(),
                    "filters": summary,
                    "rows": rows,
                }));
            }
            Err(e) => {
                event = event
                    .detail(serde_json::json!({
                        "table": table_label,
                        "format": format.extension(),
                        "filters": summary,
                        "error": e.to_string(),
                    }))
                    .failed();
            }
        }
        event.record(&state_task.db).await;
    });

    Ok((
        [
            (header::CONTENT_TYPE, format.content_type().to_string()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        body,
    )
        .into_response())
}

// ─── Staged edits (P5) ───────────────────────────────────────────────

/// A batch of staged edits. `schema` is Postgres-only; SQLite sources are
/// single-schema and ignore it.
#[derive(Deserialize)]
struct EditBatch {
    #[serde(default = "default_source")]
    source: String,
    schema: Option<String>,
    table: String,
    changes: Vec<dbadmin::edit::ChangeSpec>,
    /// Apply only. Mirrors the console's flag: the client states its intent to
    /// write, and the server still demands the sudo window on top of it.
    #[serde(default)]
    danger_mode: bool,
}

impl EditBatch {
    /// Introspects the table and validates the batch into statements.
    ///
    /// Both routes go through this, so preview and apply cannot diverge: what
    /// the review drawer shows is produced by the same call that produces what
    /// runs. A preview generated any other way would be a preview of something
    /// else.
    async fn resolve(&self, state: &AppState) -> anyhow::Result<dbadmin::edit::EditPlan> {
        let detail = dbadmin::table_detail(state, &self.source, self.schema.as_deref(), &self.table).await?;
        let dialect = dbadmin::dialect_of(&self.source)?;
        dbadmin::edit::plan(&detail, dialect, self.changes.clone())
    }
}

/// Generates the statements a batch *would* run, without running them.
///
/// Deliberately a separate route from `/database/apply` rather than a `dry_run`
/// flag on it: the apply path is on safe mode's destructive list, and a preview
/// has to stay reachable while safe mode is engaged. Reading what you would run
/// is not a host change, and an operator who cannot inspect a pending batch
/// until they disarm the safety has the incentive exactly backwards.
async fn preview_edits(
    State(state): State<AppState>,
    account: Account,
    Json(batch): Json<EditBatch>,
) -> Result<Json<dbadmin::edit::EditPlan>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    batch.resolve(&state).await.map(Json).map_err(query_error)
}

/// Applies a batch of staged edits (D15).
///
/// The gates, in the order they are checked — every one of them server-side,
/// because the buttons that enforce them in the UI are the courtesy, not the
/// guarantee:
///
/// 1. Admin.
/// 2. Global safe mode — enforced by the `safemode::guard` middleware, which
///    has `/database/apply` on its destructive list. It never reaches here.
/// 3. `danger_mode`, the client's explicit statement of intent (the UI collects
///    a confirmation naming the source).
/// 4. A `Sudo` window: a re-authentication in the last 10 minutes.
///
/// The write itself is one transaction that verifies every statement affected
/// exactly one row and abandons the whole batch otherwise (see the backends).
async fn apply_edits(
    State(state): State<AppState>,
    account: Account,
    sudo: Option<Sudo>,
    Json(batch): Json<EditBatch>,
) -> Result<Json<dbadmin::edit::ApplyReport>, Response> {
    if !account.is_admin() {
        return Err(forbidden().into_response());
    }

    if !batch.danger_mode {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError {
                error: "Applying staged edits writes to the database — turn off safe mode for this source first."
                    .into(),
            }),
        )
            .into_response());
    }

    if sudo.is_none() {
        return Err(SudoRejection::ReauthRequired.into_response());
    }

    let plan = match batch.resolve(&state).await {
        Ok(plan) => plan,
        Err(e) => {
            // A refused batch is a refusal worth keeping: it is an attempt to
            // write that the validator stopped.
            audit::event("database.edit.blocked", &account)
                .target(&batch.source)
                .detail(serde_json::json!({ "table": batch.table, "reason": e.to_string() }))
                .failed()
                .record(&state.db)
                .await;
            let (status, body) = query_error(e);
            return Err((status, body).into_response());
        }
    };

    let (updates, deletes, inserts) = plan.counts();
    let statements: Vec<String> = plan.statements.iter().map(|s| snippet(&s.preview)).collect();

    match dbadmin::apply_edits(&state, &batch.source, plan).await {
        Ok(report) => {
            audit::event("database.edit.apply", &account)
                .target(&batch.source)
                .detail(serde_json::json!({
                    "table": batch.table,
                    "updates": updates,
                    "deletes": deletes,
                    "inserts": inserts,
                    "applied": report.applied,
                    "elapsed_ms": report.elapsed_ms,
                    "statements": statements,
                }))
                .record(&state.db)
                .await;
            Ok(Json(report))
        }
        Err(e) => {
            // The rollback path. Recorded with the statements that were *going*
            // to run: "nothing changed" is only trustworthy if the attempt is
            // in the log too.
            audit::event("database.edit.apply", &account)
                .target(&batch.source)
                .detail(serde_json::json!({
                    "table": batch.table,
                    "updates": updates,
                    "deletes": deletes,
                    "inserts": inserts,
                    "rolled_back": true,
                    "error": e.to_string(),
                    "statements": statements,
                }))
                .failed()
                .record(&state.db)
                .await;
            let (status, body) = query_error(e);
            Err((status, body).into_response())
        }
    }
}

// ─── Query runner ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RunQuery {
    sql: String,
    #[serde(default = "default_source")]
    source: String,
    /// When true, bypass safe mode and run without the read-only guard. Admins
    /// only, *and* the session must have re-authenticated recently (the [`Sudo`]
    /// window) — the UI also requires an explicit confirmation click naming the
    /// source.
    #[serde(default)]
    danger_mode: bool,
    /// Client-generated id for this run, enabling cancellation (D12).
    run_id: Option<String>,
}

async fn run_query(
    State(state): State<AppState>,
    account: Account,
    // Extracted as `Option` because only danger mode needs it: `danger_mode`
    // lives in the body, which no request-parts extractor can see.
    sudo: Option<Sudo>,
    Form(payload): Form<RunQuery>,
) -> Result<Json<dbadmin::QueryResult>, Response> {
    if !account.is_admin() {
        return Err(forbidden().into_response());
    }

    let safe = !payload.danger_mode;

    // Danger mode demands a fresh reauth (D3). Every other destructive action
    // in Vantage sits behind the sudo window, and an unguarded DROP against a
    // production Postgres deserves no less. The machine-readable rejection is
    // the one `core/api.js` turns into the reauth modal + transparent retry.
    if !safe && sudo.is_none() {
        return Err(SudoRejection::ReauthRequired.into_response());
    }

    if safe && !dbadmin::is_safe_query(&payload.sql) {
        audit::event("database.query.blocked", &account)
            .target(&payload.source)
            .detail(serde_json::json!({ "sql": snippet(&payload.sql) }))
            .failed()
            .record(&state.db)
            .await;
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError {
                error: "Blocked by safe-mode: only SELECT / EXPLAIN / SHOW / WITH / VALUES / TABLE / FETCH / PRAGMA allowed."
                    .into(),
            }),
        )
            .into_response());
    }

    let outcome = dbadmin::run_query(
        &state,
        &payload.source,
        &payload.sql,
        safe,
        payload.run_id.as_deref(),
        account.id,
    )
    .await;

    let (ok, row_count, elapsed_ms) = match &outcome {
        Ok(qr) => (true, qr.row_count as i64, qr.elapsed_ms as i64),
        Err(_) => (false, 0, 0),
    };

    match &outcome {
        Ok(qr) => {
            audit::event("database.query", &account)
                .target(&payload.source)
                .detail(serde_json::json!({
                    "danger_mode": payload.danger_mode,
                    "rows": qr.row_count,
                    "elapsed_ms": qr.elapsed_ms,
                    "sql": snippet(&payload.sql),
                }))
                .record(&state.db)
                .await
        }
        Err(e) => {
            audit::event("database.query.error", &account)
                .target(&payload.source)
                .detail(serde_json::json!({
                    "danger_mode": payload.danger_mode,
                    "error": e.to_string(),
                    "sql": snippet(&payload.sql),
                }))
                .failed()
                .record(&state.db)
                .await
        }
    }

    // Record to history (fire-and-forget — never fails the response).
    {
        let db = state.db.clone();
        let source = payload.source.clone();
        let sql_text = payload.sql.clone();
        let aid = account.id;
        tokio::spawn(async move {
            dbadmin::storage::record_history(&db, aid, &source, &sql_text, ok, row_count, elapsed_ms).await;
        });
    }

    outcome.map(Json).map_err(|e| query_error(e).into_response())
}

/// Truncates `sql` so the log line stays small. Newlines collapsed to spaces.
fn snippet(sql: &str) -> String {
    let collapsed: String = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > 200 {
        // Cut on a character boundary — a byte slice through a multi-byte
        // character panics, and SQL carries user data.
        let cut: String = collapsed.chars().take(200).collect();
        format!("{cut}…")
    } else {
        collapsed
    }
}

// ─── EXPLAIN (DB Studio P4) ─────────────────────────────────────────

#[derive(Deserialize)]
struct ExplainQuery {
    sql: String,
    #[serde(default = "default_source")]
    source: String,
}

async fn explain_query(
    State(state): State<AppState>,
    account: Account,
    Form(payload): Form<ExplainQuery>,
) -> Result<Json<Vec<dbadmin::ExplainNode>>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    dbadmin::explain_query(&state, &payload.source, &payload.sql)
        .await
        .map(Json)
        .map_err(query_error)
}

// ─── DDL view (DB Studio P4) ────────────────────────────────────────

#[derive(Deserialize)]
struct DdlQuery {
    #[serde(default = "default_source")]
    source: String,
    schema: Option<String>,
    table: String,
}

#[derive(Serialize)]
struct DdlResult {
    ddl: String,
}

async fn get_ddl(
    State(state): State<AppState>,
    account: Account,
    Query(q): Query<DdlQuery>,
) -> Result<Json<DdlResult>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    let ddl = dbadmin::get_ddl(&state, &q.source, q.schema.as_deref(), &q.table)
        .await
        .map_err(query_error)?;
    Ok(Json(DdlResult { ddl }))
}

// ─── History & saved queries (DB Studio P3) ─────────────────────────

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default = "default_history_limit")]
    limit: Option<i64>,
}

fn default_history_limit() -> Option<i64> {
    Some(100)
}

async fn list_history(
    State(state): State<AppState>,
    account: Account,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Vec<dbadmin::storage::HistoryEntry>>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    dbadmin::storage::list_history(&state.db, account.id, q.limit.unwrap_or(100))
        .await
        .map(Json)
        .map_err(query_error)
}

async fn delete_history(
    State(state): State<AppState>,
    account: Account,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    dbadmin::storage::clear_history(&state.db, account.id)
        .await
        .map_err(query_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_saved(
    State(state): State<AppState>,
    account: Account,
) -> Result<Json<Vec<dbadmin::storage::SavedQuery>>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    dbadmin::storage::list_saved(&state.db, account.id)
        .await
        .map(Json)
        .map_err(query_error)
}

#[derive(Deserialize)]
struct SaveBody {
    name: String,
    source: String,
    sql_text: String,
}

async fn save_query_handler(
    State(state): State<AppState>,
    account: Account,
    Json(body): Json<SaveBody>,
) -> Result<Json<dbadmin::storage::SavedQuery>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    if body.name.trim().is_empty() {
        return Err(query_error("name cannot be empty"));
    }
    dbadmin::storage::save_query(&state.db, account.id, body.name.trim(), &body.source, &body.sql_text)
        .await
        .map(Json)
        .map_err(query_error)
}

#[derive(Deserialize)]
struct DeleteSavedQuery {
    id: i64,
}

async fn delete_saved(
    State(state): State<AppState>,
    account: Account,
    Query(q): Query<DeleteSavedQuery>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    dbadmin::storage::delete_saved(&state.db, account.id, q.id)
        .await
        .map_err(query_error)?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Cancellation (D12) ─────────────────────────────────────────────

#[derive(Deserialize)]
struct CancelBody {
    run_id: String,
}

async fn cancel_query(
    State(state): State<AppState>,
    account: Account,
    Json(body): Json<CancelBody>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    let handle = state.run_registry.cancel(&body.run_id, account.id);
    match handle {
        Some(dbadmin::cancel::CancelHandle::Sqlite(ih)) => {
            ih.interrupt();
            Ok(StatusCode::NO_CONTENT)
        }
        Some(dbadmin::cancel::CancelHandle::Postgres(token)) => {
            let _ = token.cancel_query(tokio_postgres::NoTls).await;
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(query_error("no such running query (it may have already finished)")),
    }
}

/// The admin sub-router for the database console.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/database", get(database_page))
        .route("/database/sources", get(list_databases))
        .route("/database/schema", get(schema_overview))
        .route("/database/table", get(table_detail))
        .route("/database/rows", get(browse_rows))
        .route("/database/count", get(browse_count))
        .route("/database/export", get(export))
        .route("/database/roles", get(list_roles))
        .route("/database/query", post(run_query))
        .route("/database/query/cancel", post(cancel_query))
        .route("/database/preview", post(preview_edits))
        .route("/database/apply", post(apply_edits))
        .route("/database/explain", post(explain_query))
        .route("/database/ddl", get(get_ddl))
        .route("/database/history", get(list_history).delete(delete_history))
        .route(
            "/database/saved",
            get(list_saved).post(save_query_handler).delete(delete_saved),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The snippet cut is by character, not byte. A 200-byte slice through
    /// multi-byte text panics, and SQL routinely carries non-ASCII literals.
    #[test]
    fn snippet_truncates_on_a_character_boundary() {
        let sql = format!("SELECT '{}'", "é".repeat(300));
        let out = snippet(&sql);
        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), 201);
    }

    #[test]
    fn snippet_collapses_whitespace_and_leaves_short_sql_alone() {
        assert_eq!(snippet("SELECT\n  1\n  FROM t"), "SELECT 1 FROM t");
    }
}
