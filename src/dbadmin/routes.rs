//! `/database` routes — browse Vantage's own `admin.db` and run
//! ad-hoc queries against it behind a safe-mode gate.
//!
//! Every query is recorded to the audit log with the acting admin, their
//! address, and a bounded snippet of the SQL — including the ones safe-mode
//! refused, which are the interesting ones.

use askama::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Form, Router,
};
use serde::{Deserialize, Serialize};

use crate::audit;
use crate::dbadmin;
use crate::session::Account;
use crate::AppState;

#[derive(Template)]
#[template(path = "database.html")]
struct AdminDatabaseTemplate {
    account: Option<Account>,
    active_page: &'static str,
    /// The database name + size, rendered into the page header.
    db_name: String,
    db_size: String,
}

async fn database_page(State(state): State<AppState>, account: Account) -> Result<AdminDatabaseTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let info = dbadmin::database_info(&state.db_path);
    Ok(AdminDatabaseTemplate {
        account: Some(account),
        active_page: "database",
        db_name: info.name,
        db_size: info.size_pretty,
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

/// A failed query (bad SQL, missing table, type error, …) is the caller's fault,
/// not an outage — surface it as a 400 with the engine's message so the UI can
/// show exactly what went wrong.
fn query_error(e: impl ToString) -> (StatusCode, Json<ApiError>) {
    (StatusCode::BAD_REQUEST, Json(ApiError { error: e.to_string() }))
}

// ─── Catalog ─────────────────────────────────────────────────────────

async fn list_tables(
    State(state): State<AppState>,
    account: Account,
) -> Result<Json<Vec<dbadmin::TableInfo>>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    dbadmin::list_tables(state.db_path.as_ref().clone())
        .await
        .map(Json)
        .map_err(query_error)
}

// ─── Query runner ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RunQuery {
    sql: String,
    /// When true, bypass safe-mode and run in a normal read/write connection.
    /// Only honoured for admins (already gated) — the UI also requires an
    /// explicit confirmation click.
    #[serde(default)]
    danger_mode: bool,
}

async fn run_query(
    State(state): State<AppState>,
    account: Account,
    Form(payload): Form<RunQuery>,
) -> Result<Json<dbadmin::QueryResult>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }

    let safe = !payload.danger_mode;
    if safe && !dbadmin::is_safe_query(&payload.sql) {
        audit::event("database.query.blocked", &account)
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
        ));
    }

    let outcome = dbadmin::run_query(state.db_path.as_ref().clone(), &payload.sql, safe).await;
    match &outcome {
        Ok(qr) => {
            audit::event("database.query", &account)
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

    outcome.map(Json).map_err(query_error)
}

/// Truncates `sql` so the log line stays small. Newlines collapsed to spaces.
fn snippet(sql: &str) -> String {
    let collapsed: String = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.len() > 200 {
        format!("{}…", &collapsed[..200])
    } else {
        collapsed
    }
}

/// The admin sub-router for the database console.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/database", get(database_page))
        .route("/database/tables", get(list_tables))
        .route("/database/query", post(run_query))
}
