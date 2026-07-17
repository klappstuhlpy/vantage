//! Reverse proxy / domain manager dashboard.
//!
//! - `GET    /proxy`                 page
//! - `GET    /proxy/data`            routes + proxy kind + container list
//! - `GET    /proxy/:id/preview`     rendered config for one route
//! - `POST   /proxy`                 create a route
//! - `POST   /proxy/:id`             update a route
//! - `POST   /proxy/:id/toggle`      enable/disable a route
//! - `POST   /proxy/apply`           regenerate all config + reload
//! - `DELETE /proxy/:id`             remove a route
//! - `POST   /proxy/import`          import from Cloudflare tunnel

use std::sync::Arc;
use std::time::Duration;

use crate::audit;
use crate::proxy::{self, storage::NewRoute};
use crate::session::Account;
use crate::{revert, AppState};
use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Form, Router,
};
use serde::{Deserialize, Serialize};

#[derive(Template)]
#[template(path = "proxy.html")]
struct ProxyTemplate {
    account: Option<Account>,
    active_page: &'static str,
    proxy_kind: &'static str,
}

async fn page(State(state): State<AppState>, account: Account) -> Result<ProxyTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(ProxyTemplate {
        account: Some(account),
        active_page: "proxy",
        proxy_kind: proxy::configured_kind(&state).label(),
    })
}

#[derive(Serialize)]
struct ContainerOption {
    name: String,
    identifier: String,
}

#[derive(Serialize)]
struct DashboardData {
    proxy_kind: &'static str,
    config_dir: Option<String>,
    cloudflared_api: bool,
    routes: Vec<proxy::RouteView>,
    containers: Vec<ContainerOption>,
    total: i64,
    enabled_count: i64,
}

async fn data(State(state): State<AppState>, account: Account) -> Result<Json<DashboardData>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let routes = proxy::storage::list_routes(&state)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let enabled_count = routes.iter().filter(|r| r.enabled).count() as i64;
    let total = routes.len() as i64;
    let routes: Vec<proxy::RouteView> = routes.into_iter().map(Into::into).collect();

    let containers = state
        .config
        .services
        .iter()
        .map(|s| ContainerOption {
            name: s.name.clone(),
            identifier: s.identifier.clone(),
        })
        .collect();

    Ok(Json(DashboardData {
        proxy_kind: proxy::configured_kind(&state).label(),
        config_dir: proxy::config_dir(&state).map(|p| p.display().to_string()),
        cloudflared_api: proxy::cloudflared::api_mode(&state),
        routes,
        containers,
        total,
        enabled_count,
    }))
}

async fn preview(
    State(state): State<AppState>,
    account: Account,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let route = proxy::storage::get_route(&state, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let kind = proxy::configured_kind(&state);
    let dir = proxy::config_dir(&state);
    let config = proxy::render::render(kind, &route, dir.as_deref());
    Ok(Json(serde_json::json!({
        "kind": kind.label(),
        "file": kind.file_name(&route.subdomain),
        "config": config,
    })))
}

/// `GET /proxy/preview` — the dry-run diff of what Apply would write, across
/// every config file (§11.2). Read-only: it renders and diffs, it never touches
/// disk or reloads.
async fn preview_all(State(state): State<AppState>, account: Account) -> Result<Json<serde_json::Value>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let changes = proxy::preview_changes(&state)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let changed = changes.iter().filter(|c| c.status != "unchanged").count();
    Ok(Json(serde_json::json!({
        "config_dir": proxy::config_dir(&state).map(|p| p.display().to_string()),
        "changed": changed,
        "files": changes,
    })))
}

#[derive(Deserialize)]
struct UpsertForm {
    subdomain: String,
    target_host: String,
    target_port: i64,
    #[serde(default)]
    target_scheme: Option<String>,
    #[serde(default)]
    container: Option<String>,
    #[serde(default)]
    ssl_managed: Option<String>,
    #[serde(default)]
    cloudflare_proxied: Option<String>,
    #[serde(default)]
    http_auth_user: Option<String>,
    #[serde(default)]
    http_auth_password: Option<String>,
    #[serde(default)]
    rate_limit_rps: Option<i64>,
    #[serde(default)]
    access_rules_json: Option<String>,
    #[serde(default)]
    extra_config: Option<String>,
    #[serde(default)]
    enabled: Option<String>,
}

fn checkbox(v: &Option<String>) -> bool {
    matches!(v.as_deref(), Some("on" | "true" | "1"))
}

impl UpsertForm {
    fn validate(self) -> Result<NewRoute, StatusCode> {
        let subdomain = self.subdomain.trim().to_ascii_lowercase();
        let target_host = self.target_host.trim().to_string();
        if subdomain.is_empty() || target_host.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if subdomain.contains("://") || subdomain.contains('/') || subdomain.contains(' ') {
            return Err(StatusCode::BAD_REQUEST);
        }
        if !(1..=65535).contains(&self.target_port) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let target_scheme = match self.target_scheme.as_deref() {
            Some("https") => "https".to_string(),
            _ => "http".to_string(),
        };
        let container = self.container.filter(|c| !c.trim().is_empty());
        let http_auth_user = self
            .http_auth_user
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty());
        let http_auth_pass_hash = match self
            .http_auth_password
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            Some(pw) => Some(bcrypt::hash(pw, bcrypt::DEFAULT_COST).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?),
            None => None,
        };
        let access_rules_json = self
            .access_rules_json
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                serde_json::from_str::<serde_json::Value>(&s)
                    .map(|_| s)
                    .map_err(|_| StatusCode::BAD_REQUEST)
            })
            .transpose()?;
        let rate_limit_rps = self.rate_limit_rps.filter(|r| *r > 0);
        let extra_config = self.extra_config.filter(|s| !s.trim().is_empty());

        Ok(NewRoute {
            subdomain,
            target_host,
            target_port: self.target_port,
            target_scheme,
            container,
            ssl_managed: checkbox(&self.ssl_managed),
            cloudflare_proxied: checkbox(&self.cloudflare_proxied),
            http_auth_user,
            http_auth_pass_hash,
            rate_limit_rps,
            access_rules_json,
            extra_config,
            enabled: self.enabled.is_none() || checkbox(&self.enabled),
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
    let route = form.validate()?;
    let subdomain = route.subdomain.clone();
    let id = proxy::storage::create_route(&state, route)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    let report = proxy::regenerate_all(&state).await.ok();
    audit::event("proxy.route.create", &account)
        .target(format!("proxy:{id}"))
        // `regenerate_all` is best-effort here (the row is the source of truth),
        // so the report is an Option and "did the config actually get written?"
        // is a fact the audit row should carry rather than assume.
        .detail(serde_json::json!({ "subdomain": subdomain, "written": report.as_ref().map(|r| r.written) }))
        .record(&state.db)
        .await;
    Ok(Json(serde_json::json!({ "id": id, "apply": report })))
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
    let route = form.validate()?;
    let subdomain = route.subdomain.clone();
    proxy::storage::update_route(&state, id, route)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;
    let _ = proxy::regenerate_all(&state).await;
    audit::event("proxy.route.update", &account)
        .target(format!("proxy:{id}"))
        .detail(serde_json::json!({ "subdomain": subdomain }))
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
    proxy::storage::delete_route(&state, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = proxy::regenerate_all(&state).await;
    audit::event("proxy.route.delete", &account)
        .target(format!("proxy:{id}"))
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
    proxy::storage::set_enabled(&state, id, enabled)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = proxy::regenerate_all(&state).await;
    audit::event("proxy.route.toggle", &account)
        .target(format!("proxy:{id}"))
        .detail(serde_json::json!({ "enabled": enabled }))
        .record(&state.db)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `?revert=<secs>` arms a self-revert (§11.1). Absent / 0 = fire-and-keep.
#[derive(Deserialize)]
struct ApplyQuery {
    #[serde(default)]
    revert: Option<u64>,
}

const REVERT_MIN_SECS: u64 = 5;
const REVERT_MAX_SECS: u64 = 600;

async fn apply(
    State(state): State<AppState>,
    Query(query): Query<ApplyQuery>,
    account: Account,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }

    // Snapshot the current on-disk config *before* regenerating, so an armed
    // apply has something to roll back to. `None` when the config can't be
    // snapshotted (no config dir, or Cloudflare API mode) — then no timer is armed.
    let snapshot = match query.revert {
        Some(secs) if secs > 0 => proxy::snapshot_config(&state).await,
        _ => None,
    };

    let report = proxy::regenerate_all(&state)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    audit::event("proxy.apply", &account)
        .detail(serde_json::json!({ "written": report.written, "errors": report.errors.len() }))
        // Applying a config that half-wrote is not a success, and an audit log
        // that records it as one is worse than no entry at all.
        .ok(report.errors.is_empty())
        .record(&state.db)
        .await;

    // Arm the revert only on a clean apply with a snapshot behind it. A partial
    // apply (errors present) is left for the operator to see and fix, not silently
    // rolled back over.
    let revert_info = match (snapshot, query.revert) {
        (Some(snapshot), Some(secs)) if report.errors.is_empty() => {
            let window = Duration::from_secs(secs.clamp(REVERT_MIN_SECS, REVERT_MAX_SECS));
            let revert_state = state.clone();
            let rollback: revert::RevertFn = Arc::new(move || {
                let state = revert_state.clone();
                let snapshot = snapshot.clone();
                Box::pin(async move { proxy::restore_snapshot(&state, snapshot).await })
            });
            Some(state.reverts.arm("proxy", window, rollback))
        }
        _ => None,
    };

    // The frontend reads the ApplyReport fields (written/reload/errors) flat, so
    // the revert descriptor is added alongside them rather than nesting the report.
    let mut body = serde_json::to_value(&report).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "revert".to_string(),
            serde_json::to_value(revert_info).unwrap_or(serde_json::Value::Null),
        );
    }
    Ok(Json(body))
}

/// The token an armed apply hands back, sent to confirm or revert it.
#[derive(Deserialize)]
struct RevertToken {
    token: String,
}

/// `POST /proxy/apply/confirm` — keep an armed apply (cancel its revert timer).
async fn confirm_apply(
    State(state): State<AppState>,
    account: Account,
    Json(body): Json<RevertToken>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let kept = state.reverts.confirm("proxy", &body.token);
    audit::event("proxy.apply.confirmed", &account)
        .ok(kept)
        .record(&state.db)
        .await;
    Ok(Json(serde_json::json!({ "kept": kept })))
}

/// `POST /proxy/apply/revert` — roll an armed apply back now.
async fn revert_apply_now(
    State(state): State<AppState>,
    account: Account,
    Json(body): Json<RevertToken>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let reverted = match state.reverts.take_for_revert("proxy", &body.token) {
        Some(rollback) => {
            rollback().await;
            true
        }
        None => false,
    };
    audit::event("proxy.apply.revert_now", &account)
        .ok(reverted)
        .record(&state.db)
        .await;
    Ok(Json(serde_json::json!({ "reverted": reverted })))
}

async fn import_cloudflare(State(state): State<AppState>, account: Account) -> axum::response::Response {
    use axum::response::IntoResponse;
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !proxy::cloudflared::api_mode(&state) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Cloudflare tunnel API is not configured (need cloudflare api_token, account_id, tunnel_id, and proxy kind = \"cloudflared\")."
            })),
        )
            .into_response();
    }
    match proxy::cloudflared::import(&state).await {
        Ok((imported, updated, skipped)) => {
            audit::event("proxy.import", &account)
                .detail(serde_json::json!({ "imported": imported, "updated": updated, "skipped": skipped }))
                .record(&state.db)
                .await;
            Json(serde_json::json!({ "imported": imported, "updated": updated, "skipped": skipped })).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "Cloudflare tunnel import failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/proxy", get(page).post(create))
        .route("/proxy/data", get(data))
        .route("/proxy/apply", post(apply))
        .route("/proxy/apply/confirm", post(confirm_apply))
        .route("/proxy/apply/revert", post(revert_apply_now))
        .route("/proxy/preview", get(preview_all))
        .route("/proxy/import", post(import_cloudflare))
        .route("/proxy/:id", post(update).delete(remove))
        .route("/proxy/:id/preview", get(preview))
        .route("/proxy/:id/toggle", post(toggle))
}
