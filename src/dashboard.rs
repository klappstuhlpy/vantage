//! Admin dashboard landing page (`GET /`).
//!
//! A glanceable overview: summary tiles (services, monitors, firewall rules,
//! secret findings), recent Docker events, and quick-nav to each section.

use crate::{health, proxy, session::Account, AppState};
use askama::Template;
use axum::{extract::State, routing::get, Router};

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    account: Option<Account>,
    active_page: &'static str,
    service_count: usize,
    monitor_count: usize,
    monitors_up: usize,
    monitors_down: usize,
    proxy_route_count: usize,
    docker_available: bool,
}

async fn page(State(state): State<AppState>, account: Account) -> DashboardTemplate {
    let monitors = health::storage::list_summaries(&state).await.unwrap_or_default();
    let monitors_up = monitors
        .iter()
        .filter(|m| m.last_status.as_deref() == Some("up"))
        .count();
    let monitors_down = monitors
        .iter()
        .filter(|m| m.last_status.as_deref() == Some("down"))
        .count();
    let proxy_routes = proxy::storage::list_routes(&state).await.unwrap_or_default();

    DashboardTemplate {
        account: Some(account),
        active_page: "home",
        service_count: state.config.services.len(),
        monitor_count: monitors.len(),
        monitors_up,
        monitors_down,
        proxy_route_count: proxy_routes.len(),
        docker_available: state.docker().is_some(),
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(page))
}
