//! The live metrics dashboard — page + JSON feeds.
//!
//! - `GET /metrics`               — the dashboard page (tiles + uPlot charts)
//! - `GET /metrics/current`       — latest sample + live container list
//! - `GET /metrics/history?range` — time-series for charts
//!
//! `range` is one of `1h`, `6h`, `24h`, `7d`, `30d` (default `1h`). The page
//! polls `/current` every 5s and refetches `/history` on range change, while
//! the `/ws` `metrics` topic pushes tile updates in real time (polling is the
//! fallback when the socket is down).

use askama::Template;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};

use crate::metrics::{self, DockerStat};
use crate::session::Account;
use crate::AppState;

#[derive(Template)]
#[template(path = "metrics.html")]
struct AdminMetricsTemplate {
    account: Option<Account>,
    active_page: &'static str,
    initial_json: String,
}

async fn metrics_page(State(state): State<AppState>, account: Account) -> Result<AdminMetricsTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let host = metrics::fetch_current(&state.db).await;
    let containers = metrics::docker::collect_cached().await;
    let initial = CurrentResponse { host, containers };
    Ok(AdminMetricsTemplate {
        account: Some(account),
        active_page: "metrics",
        initial_json: serde_json::to_string(&initial).unwrap_or_default(),
    })
}

#[derive(Serialize)]
struct CurrentResponse {
    /// `None` if no scrape has completed yet (just-started server).
    host: Option<metrics::CurrentView>,
    containers: Vec<DockerStat>,
}

async fn current_metrics(State(state): State<AppState>, account: Account) -> Result<Json<CurrentResponse>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let host = metrics::fetch_current(&state.db).await;
    let containers = metrics::docker::collect_cached().await;
    Ok(Json(CurrentResponse { host, containers }))
}

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default = "default_range")]
    range: String,
}

fn default_range() -> String {
    "1h".to_string()
}

fn range_to_seconds(range: &str) -> i64 {
    match range {
        "1h" => 3600,
        "6h" => 6 * 3600,
        "24h" => 24 * 3600,
        "7d" => 7 * 24 * 3600,
        "30d" => 30 * 24 * 3600,
        _ => 3600,
    }
}

#[derive(Serialize)]
struct HistoryResponse {
    points: Vec<metrics::HistoryPoint>,
    containers: std::collections::BTreeMap<String, Vec<metrics::DockerHistoryPoint>>,
}

async fn history_metrics(
    State(state): State<AppState>,
    account: Account,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<HistoryResponse>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let secs = range_to_seconds(&query.range);
    let points = metrics::fetch_history(&state.db, secs)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let containers = metrics::fetch_docker_history(&state.db, secs)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(HistoryResponse { points, containers }))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/metrics", get(metrics_page))
        .route("/metrics/current", get(current_metrics))
        .route("/metrics/history", get(history_metrics))
}
