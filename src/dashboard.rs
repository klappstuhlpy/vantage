//! The home page (`GET /`) — a customisable widget dashboard.
//!
//! The page itself is deliberately thin. It renders the frame, a set of
//! capability flags, and an empty grid; every widget then fetches its own slice
//! from that slice's existing `/data` endpoint (see `static/js/pages/dashboard.js`).
//! Nothing here aggregates other slices' data, which is what lets a widget be
//! added or removed without touching this file.
//!
//! The counts below are the exception: they are cheap, they come from slices
//! this handler already had to touch, and rendering them server-side means the
//! page has real content in its first paint rather than a grid of spinners.

use crate::{health, metrics, proxy, session::Account, AppState};
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
    /// Capability flags. The frontend reads these off the grid element and
    /// renders a widget's degraded state *without* a request, so a host with no
    /// Docker socket doesn't fire a round of doomed fetches on every load.
    docker_available: bool,
    firewall_available: bool,
    cloudflare_available: bool,
    initial_metrics: String,
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

    let host = metrics::fetch_current(&state.db).await;
    let initial_metrics = serde_json::json!({ "host": host }).to_string();

    DashboardTemplate {
        account: Some(account),
        active_page: "home",
        service_count: state.config.services.len(),
        monitor_count: monitors.len(),
        monitors_up,
        monitors_down,
        proxy_route_count: proxy_routes.len(),
        docker_available: state.docker().is_some(),
        firewall_available: state.firewall_backend().is_some(),
        cloudflare_available: state.cloudflare.is_some(),
        initial_metrics,
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(page))
}
