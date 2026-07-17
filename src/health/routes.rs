//! Health checks / uptime monitoring — pages + JSON data + CRUD endpoints.
//!
//! - `GET    /monitors`                       the admin dashboard page
//! - `GET    /status`                         the public, unauthenticated status page
//! - `GET    /monitors/data`                  JSON: target list with summary
//! - `GET    /monitors/incidents`             JSON: recent incidents (timeline)
//! - `GET    /monitors/:id/history`           JSON: samples + stats for one target
//! - `POST   /monitors`                       create a new target
//! - `POST   /monitors/:id`                   update target
//! - `POST   /monitors/:id/toggle`            enable/disable a target
//! - `POST   /monitors/:id/check`             run a probe immediately
//! - `DELETE /monitors/:id`                   delete a target
//!
//! The uptime-monitor config lives at `/monitors` (not `/health`) so it does not
//! collide with the `/health` liveness probe; the public view stays at `/status`.
//!
//! State-changing handlers log to `tracing` (`health.target.*`) rather than the
//! audit log — audit rows arrive with the audit slice, keeping the action names
//! stable for that later wiring.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Form, Router,
};
use serde::{Deserialize, Serialize};

use crate::audit;
use crate::health::{self, checker::CheckKind, storage::NewTarget};
use crate::session::Account;
use crate::AppState;

// ─── Admin dashboard page ────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "health.html")]
struct AdminHealthTemplate {
    account: Option<Account>,
    active_page: &'static str,
}

async fn page(account: Account) -> Result<AdminHealthTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(AdminHealthTemplate {
        account: Some(account),
        active_page: "health",
    })
}

// ─── Public status page ──────────────────────────────────────────────────────

/// A monitor as shown on the public status page. Deliberately omits the raw
/// target address, kind config, and any internal detail — only the display
/// name and a coarse status/uptime are exposed.
struct PublicService {
    name: String,
    /// Machine status used as a CSS class: `up`, `down`, `degraded`, `unknown`.
    status: String,
    status_label: &'static str,
    uptime: String,
    last_check: String,
}

#[derive(Template)]
#[template(path = "status.html")]
struct StatusTemplate {
    services: Vec<PublicService>,
    overall: &'static str,
    overall_label: &'static str,
    up: usize,
    total: usize,
}

fn status_label(status: &str) -> &'static str {
    match status {
        "up" => "Operational",
        "degraded" => "Degraded",
        "down" => "Down",
        _ => "Unknown",
    }
}

/// Public, unauthenticated uptime status page built from the health monitors.
/// Takes `Option<Account>` so it renders for logged-out visitors too.
async fn status_page(State(state): State<AppState>, _account: Option<Account>) -> Result<StatusTemplate, StatusCode> {
    let summaries = health::storage::list_summaries(&state)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut services = Vec::new();
    let (mut up, mut down, mut degraded) = (0usize, 0usize, 0usize);
    for s in summaries.into_iter().filter(|s| s.target.enabled) {
        let status = s.last_status.clone().unwrap_or_else(|| "unknown".to_string());
        match status.as_str() {
            "up" => up += 1,
            "down" => down += 1,
            "degraded" => degraded += 1,
            _ => {}
        }
        let last_check = s
            .last_check
            .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
            .unwrap_or_else(|| "—".to_string());
        services.push(PublicService {
            name: s.target.name,
            status_label: status_label(&status),
            status,
            // uptime_24h is a FRACTION (0.0–1.0), not a percentage — see
            // storage::uptime_stats, where it comes straight out of
            // `SUM(up) * 1.0 / COUNT(*)`. This used to render it as
            // `{:.2}%` with no conversion, so a service with flawless uptime
            // advertised "1.00%" on the public status page.
            uptime: format!("{:.2}%", s.uptime_24h * 100.0),
            last_check,
        });
    }

    let total = services.len();
    let (overall, overall_label) = if total == 0 {
        ("unknown", "No monitors configured")
    } else if down > 0 {
        ("down", "Major outage")
    } else if degraded > 0 {
        ("degraded", "Degraded performance")
    } else if up == total {
        ("up", "All systems operational")
    } else {
        ("unknown", "Status unknown")
    };

    Ok(StatusTemplate {
        services,
        overall,
        overall_label,
        up,
        total,
    })
}

#[derive(Serialize)]
struct DashboardData {
    summaries: Vec<health::TargetSummary>,
    open_incidents: Vec<health::IncidentRow>,
    total_targets: i64,
    up_count: i64,
    down_count: i64,
    degraded_count: i64,
}

async fn data(State(state): State<AppState>, account: Account) -> Result<Json<DashboardData>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let summaries = health::storage::list_summaries(&state)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let open_incidents = health::storage::list_incidents(&state, None, 50)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .filter(|i| i.ended_at.is_none())
        .collect::<Vec<_>>();

    let total_targets = summaries.len() as i64;
    let mut up = 0i64;
    let mut down = 0i64;
    let mut degraded = 0i64;
    for s in &summaries {
        match s.last_status.as_deref() {
            Some("up") => up += 1,
            Some("degraded") => degraded += 1,
            Some("down") => down += 1,
            _ => {}
        }
    }

    Ok(Json(DashboardData {
        summaries,
        open_incidents,
        total_targets,
        up_count: up,
        down_count: down,
        degraded_count: degraded,
    }))
}

#[derive(Deserialize)]
struct IncidentsQuery {
    #[serde(default)]
    target_id: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

async fn incidents(
    State(state): State<AppState>,
    account: Account,
    Query(query): Query<IncidentsQuery>,
) -> Result<Json<Vec<health::IncidentRow>>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let rows = health::storage::list_incidents(&state, query.target_id, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}

#[derive(Serialize)]
struct HistoryResponse {
    target: health::HealthTarget,
    stats: health::UptimeStats,
    samples: Vec<health::SampleRow>,
    incidents: Vec<health::IncidentRow>,
}

async fn history(
    State(state): State<AppState>,
    account: Account,
    Path(id): Path<i64>,
) -> Result<Json<HistoryResponse>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let target = health::storage::get_target(&state, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let stats = health::storage::uptime_stats(&state, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let samples = health::storage::list_samples(&state, id, 500)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let incidents = health::storage::list_incidents(&state, Some(id), 50)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(HistoryResponse {
        target,
        stats,
        samples,
        incidents,
    }))
}

#[derive(Deserialize)]
struct UpsertForm {
    name: String,
    kind: String,
    target: String,
    #[serde(default)]
    interval_seconds: Option<i64>,
    #[serde(default)]
    timeout_ms: Option<i64>,
    #[serde(default)]
    degraded_ms: Option<i64>,
    #[serde(default)]
    enabled: Option<String>,
    /// Free-form per-kind config — keyword, expected_status, warn_days, etc.
    #[serde(default)]
    config_json: Option<String>,
}

impl UpsertForm {
    fn validate(self) -> Result<NewTarget, StatusCode> {
        let kind = self.kind.trim().to_string();
        if CheckKind::from_str(&kind).is_none() {
            return Err(StatusCode::BAD_REQUEST);
        }
        let name = self.name.trim().to_string();
        let target = self.target.trim().to_string();
        if name.is_empty() || target.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        let config_json = self
            .config_json
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "{}".to_string());
        // Validate JSON shape so we don't store garbage that breaks the checker.
        if serde_json::from_str::<serde_json::Value>(&config_json).is_err() {
            return Err(StatusCode::BAD_REQUEST);
        }
        let enabled = matches!(self.enabled.as_deref(), Some("on" | "true" | "1"));
        Ok(NewTarget {
            name,
            kind,
            target,
            config_json,
            interval_seconds: self.interval_seconds.unwrap_or(60).clamp(10, 86_400),
            timeout_ms: self.timeout_ms.unwrap_or(5_000).clamp(500, 60_000),
            degraded_ms: self.degraded_ms.unwrap_or(1_000).clamp(50, 60_000),
            enabled,
        })
    }
}

async fn create(
    State(state): State<AppState>,
    account: Account,
    Form(form): Form<UpsertForm>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let new = form.validate()?;
    let name = new.name.clone();
    let id = health::storage::create_target(&state, new)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    audit::event("health.target.create", &account)
        .target(format!("health:{id}"))
        .detail(serde_json::json!({ "name": name }))
        .record(&state.db)
        .await;
    Ok(Json(serde_json::json!({ "id": id })))
}

async fn update(
    State(state): State<AppState>,
    account: Account,
    Path(id): Path<i64>,
    Form(form): Form<UpsertForm>,
) -> Result<StatusCode, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let new = form.validate()?;
    let name = new.name.clone();
    health::storage::update_target(&state, id, new)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    audit::event("health.target.update", &account)
        .target(format!("health:{id}"))
        .detail(serde_json::json!({ "name": name }))
        .record(&state.db)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove(
    State(state): State<AppState>,
    account: Account,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    health::storage::delete_target(&state, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    audit::event("health.target.delete", &account)
        .target(format!("health:{id}"))
        .record(&state.db)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ToggleForm {
    enabled: String,
}

async fn toggle(
    State(state): State<AppState>,
    account: Account,
    Path(id): Path<i64>,
    Form(form): Form<ToggleForm>,
) -> Result<StatusCode, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let enabled = matches!(form.enabled.as_str(), "on" | "true" | "1");
    health::storage::set_enabled(&state, id, enabled)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    audit::event("health.target.toggle", &account)
        .target(format!("health:{id}"))
        .detail(serde_json::json!({ "enabled": enabled }))
        .record(&state.db)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn check_now(
    State(state): State<AppState>,
    account: Account,
    Path(id): Path<i64>,
) -> Result<Json<health::CheckOutcome>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let outcome = health::run_check_now(&state, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    audit::event("health.target.probe", &account)
        .target(format!("health:{id}"))
        .detail(serde_json::json!({ "status": outcome.status_str() }))
        .record(&state.db)
        .await;
    Ok(Json(outcome))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/status", get(status_page))
        .route("/monitors", get(page).post(create))
        .route("/monitors/data", get(data))
        .route("/monitors/incidents", get(incidents))
        .route("/monitors/:id/history", get(history))
        .route("/monitors/:id", post(update).delete(remove))
        .route("/monitors/:id/toggle", post(toggle))
        .route("/monitors/:id/check", post(check_now))
}
