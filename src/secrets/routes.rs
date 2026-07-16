use crate::session::Account;
use crate::AppState;
use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Form, Router,
};
use serde::{Deserialize, Serialize};

use super::storage::{FindingRow, LastScan, StatusCounts};

#[derive(Template)]
#[template(path = "secrets.html")]
struct SecretsTemplate {
    account: Option<Account>,
    active_page: &'static str,
    scanner_enabled: bool,
}

async fn secrets_page(State(state): State<AppState>, account: Account) -> SecretsTemplate {
    SecretsTemplate {
        account: Some(account),
        active_page: "secrets",
        scanner_enabled: !state.config.secret_scan_paths.is_empty(),
    }
}

#[derive(Deserialize)]
struct DataQuery {
    #[serde(default)]
    status: Option<String>,
}

#[derive(Serialize)]
struct SecretsData {
    counts: StatusCounts,
    last_scan: Option<LastScan>,
    findings: Vec<FindingRow>,
    scanner_enabled: bool,
}

async fn secrets_data(
    State(state): State<AppState>,
    _account: Account,
    Query(query): Query<DataQuery>,
) -> Result<Json<SecretsData>, StatusCode> {
    let filter = match query.status.as_deref() {
        Some("all") | None => None,
        Some(s) if matches!(s, "open" | "dismissed" | "resolved") => Some(s),
        Some(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let counts = super::storage::status_counts(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let last_scan = super::storage::last_scan(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let findings = super::storage::list_findings(&state.db, filter, 200)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SecretsData {
        counts,
        last_scan,
        findings,
        scanner_enabled: !state.config.secret_scan_paths.is_empty(),
    }))
}

#[derive(Serialize)]
struct TriggerResponse {
    started: bool,
    detail: String,
}

async fn trigger_scan(State(state): State<AppState>, _account: Account) -> Json<TriggerResponse> {
    if state.config.secret_scan_paths.is_empty() {
        return Json(TriggerResponse {
            started: false,
            detail: "No scan paths configured. Add secret_scan_paths to config.json.".into(),
        });
    }
    tracing::info!("secrets.scan.trigger: manual scan initiated");
    let db = state.db.clone();
    let paths = state.config.secret_scan_paths.clone();
    tokio::spawn(async move {
        if let Err(e) = super::run_scan(&db, &paths).await {
            tracing::error!(error = %e, "manual secret scan failed");
        }
    });
    Json(TriggerResponse {
        started: true,
        detail: "Scan queued — refresh in a moment.".into(),
    })
}

#[derive(Deserialize)]
struct StatusUpdate {
    status: String,
}

async fn update_status(
    State(state): State<AppState>,
    _account: Account,
    Path(id): Path<i64>,
    Form(payload): Form<StatusUpdate>,
) -> Result<StatusCode, StatusCode> {
    if !matches!(payload.status.as_str(), "open" | "dismissed" | "resolved") {
        return Err(StatusCode::BAD_REQUEST);
    }
    super::storage::set_status(&state.db, id, &payload.status)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tracing::info!(
        finding_id = id,
        status = %payload.status,
        "secrets.status.change"
    );
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/secrets", get(secrets_page))
        .route("/secrets/data", get(secrets_data))
        .route("/secrets/scan", post(trigger_scan))
        .route("/secrets/:id/status", post(update_status))
}
