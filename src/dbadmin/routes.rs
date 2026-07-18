//! `/database` routes — browse the configured SQLite and PostgreSQL sources and
//! run ad-hoc queries against them behind a safe-mode gate.
//!
//! Every query is recorded to the audit log with the acting admin, their
//! address, the source it ran against, and a bounded snippet of the SQL —
//! including the ones safe mode refused, which are the interesting ones. The
//! source id is part of every entry because "an admin ran a DELETE" and "an
//! admin ran a DELETE against the production Postgres" are different events.

use askama::Template;
use axum::{
    extract::{Query, State},
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

async fn list_tables(
    State(state): State<AppState>,
    account: Account,
    Query(q): Query<SourceQuery>,
) -> Result<Json<Vec<dbadmin::TableInfo>>, (StatusCode, Json<ApiError>)> {
    if !account.is_admin() {
        return Err(forbidden());
    }
    dbadmin::list_tables(&state, &q.source)
        .await
        .map(Json)
        .map_err(query_error)
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

// ─── Query runner ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RunQuery {
    sql: String,
    #[serde(default = "default_source")]
    source: String,
    /// When true, bypass safe mode and run without the read-only guard. Only
    /// honoured for admins (already gated) — the UI also requires an explicit
    /// confirmation click naming the source.
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
        ));
    }

    let outcome = dbadmin::run_query(&state, &payload.source, &payload.sql, safe).await;
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

    outcome.map(Json).map_err(query_error)
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

/// The admin sub-router for the database console.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/database", get(database_page))
        .route("/database/sources", get(list_databases))
        .route("/database/tables", get(list_tables))
        .route("/database/roles", get(list_roles))
        .route("/database/query", post(run_query))
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
