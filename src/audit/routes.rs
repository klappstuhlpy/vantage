//! Audit log routes.
//!
//! GET /audit       — the audit page
//! GET /audit/data  — JSON entries + filter vocabulary + coverage
//!
//! Read-only, and there is deliberately no route that deletes an entry. An audit
//! log with a delete button is a log that answers "who did this?" with "someone
//! who could also press that button" — retention is a config decision, applied
//! uniformly by the pruner, not an action anyone takes against a row.

use askama::Template;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};

use crate::{audit, session::Account, AppState};

/// Rows per page. Enough that the common question ("what happened today?") is
/// answered without paging, small enough to render instantly.
const PAGE_SIZE: i64 = 100;
const MAX_PAGE_SIZE: i64 = 500;

pub fn routes() -> Router<AppState> {
    Router::new().route("/audit", get(page)).route("/audit/data", get(data))
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditTemplate {
    account: Option<Account>,
    active_page: &'static str,
    retention_days: u32,
}

async fn page(State(state): State<AppState>, account: Account) -> Result<AuditTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(AuditTemplate {
        account: Some(account),
        active_page: "audit",
        retention_days: audit::retention_days(&state),
    })
}

#[derive(Deserialize)]
struct DataQuery {
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    failures: bool,
    #[serde(default)]
    before: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Serialize)]
struct Coverage {
    /// How many entries are held right now.
    rows: i64,
    /// The oldest entry still held. The page shows this rather than the
    /// configured window, because "90 days" is the policy and this is the fact —
    /// on a young install, or one that hit the row cap, they differ.
    oldest: Option<String>,
    retention_days: u32,
}

#[derive(Serialize)]
struct AuditData {
    entries: Vec<audit::Entry>,
    /// Distinct action names present, for the filter menu.
    actions: Vec<String>,
    coverage: Coverage,
    /// Whether another page exists below this one.
    more: bool,
}

/// Normalises an empty query-string value to `None`.
///
/// `?actor=` is what a cleared filter box sends, and treating it as "actor is
/// the empty string" would silently return nothing at all.
fn some_if_filled(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

async fn data(State(state): State<AppState>, account: Account, Query(params): Query<DataQuery>) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }

    let limit = params.limit.unwrap_or(PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
    let filter = audit::Filter {
        action: some_if_filled(params.action),
        actor: some_if_filled(params.actor),
        query: some_if_filled(params.q),
        failures_only: params.failures,
        // One more than asked for, so "is there another page?" is answered by
        // the same query rather than by a second COUNT over the same filter.
        limit: limit + 1,
        before: params.before,
    };

    let mut entries = match audit::entries(&state.db, filter).await {
        Ok(entries) => entries,
        Err(e) => {
            tracing::error!(error = ?e, "could not read the audit log");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Could not read the audit log." })),
            )
                .into_response();
        }
    };
    let more = entries.len() as i64 > limit;
    entries.truncate(limit as usize);

    let (rows, oldest) = audit::coverage(&state.db).await;

    Json(AuditData {
        entries,
        actions: audit::known_actions(&state.db).await.unwrap_or_default(),
        coverage: Coverage {
            rows,
            oldest,
            retention_days: audit::retention_days(&state),
        },
        more,
    })
    .into_response()
}
