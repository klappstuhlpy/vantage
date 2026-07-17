//! Cert & domain overview — a read-only page that joins managed reverse-proxy
//! routes with the SSL health monitors, so every domain the box serves is
//! visible in one place alongside its certificate expiry.
//!
//! It owns no state of its own: routes come from `/proxy` and cert data from the
//! `ssl` health monitors on `/monitors`. This is purely a convenience
//! aggregation view (`GET /certs`).

use crate::{health, proxy, session::Account, AppState};
use askama::Template;
use axum::{extract::State, http::StatusCode, routing::get, Router};

struct RouteCertView {
    subdomain: String,
    upstream: String,
    container: Option<String>,
    ssl_managed: bool,
    cloudflare_proxied: bool,
    has_auth: bool,
    enabled: bool,
    edge_tls: bool,
    ssl_days_left: Option<i64>,
    monitor_name: Option<String>,
}

struct StandaloneCertView {
    name: String,
    host: String,
    ssl_days_left: Option<i64>,
    status: Option<String>,
    uptime_24h: f64,
}

#[derive(Template)]
#[template(path = "certs.html")]
struct CertsTemplate {
    account: Option<Account>,
    active_page: &'static str,
    routes: Vec<RouteCertView>,
    standalone: Vec<StandaloneCertView>,
}

fn host_of(target: &str) -> String {
    let t = target.trim();
    let t = t.split("://").nth(1).unwrap_or(t);
    let t = t.split('/').next().unwrap_or(t);
    let t = t.split('@').next_back().unwrap_or(t);
    t.split(':').next().unwrap_or(t).trim().to_ascii_lowercase()
}

/// Maps days-to-expiry onto a design-system pill tone (see components.css).
///
/// These are pill tone names, not free-form words: the template drops the
/// return value straight into `class="pill {…}"`, so "danger"/"unknown" styled
/// nothing at all.
fn cert_class(days: Option<i64>) -> &'static str {
    match days {
        // Expired, or expiring inside a week: nobody is renewing this by hand
        // over a weekend, so it is already an incident.
        Some(d) if d <= 7 => "down",
        Some(d) if d <= 21 => "warn",
        Some(_) => "ok",
        None => "idle",
    }
}

async fn page(State(state): State<AppState>, account: Account) -> Result<CertsTemplate, StatusCode> {
    let proxy_routes = proxy::storage::list_routes(&state).await.unwrap_or_default();
    let summaries = health::storage::list_summaries(&state).await.unwrap_or_default();

    let backend_is_edge = proxy::configured_kind(&state).label() == "cloudflared";

    let ssl_monitors: Vec<&_> = summaries
        .iter()
        .filter(|s| s.target.kind.eq_ignore_ascii_case("ssl"))
        .collect();

    let mut matched_monitor_ids: std::collections::HashSet<i64> = std::collections::HashSet::new();
    let mut routes = Vec::with_capacity(proxy_routes.len());
    for r in &proxy_routes {
        let want = r.subdomain.to_ascii_lowercase();
        let monitor = ssl_monitors.iter().find(|m| host_of(&m.target.target) == want);
        if let Some(m) = monitor {
            matched_monitor_ids.insert(m.target.id);
        }
        routes.push(RouteCertView {
            subdomain: r.subdomain.clone(),
            upstream: format!("{}://{}:{}", r.target_scheme, r.target_host, r.target_port),
            container: r.container.clone(),
            ssl_managed: r.ssl_managed,
            cloudflare_proxied: r.cloudflare_proxied,
            has_auth: r.has_auth(),
            enabled: r.enabled,
            edge_tls: backend_is_edge || r.cloudflare_proxied,
            ssl_days_left: monitor.and_then(|m| m.last_ssl_days_left),
            monitor_name: monitor.map(|m| m.target.name.clone()),
        });
    }

    let standalone = ssl_monitors
        .iter()
        .filter(|m| !matched_monitor_ids.contains(&m.target.id))
        .map(|m| StandaloneCertView {
            name: m.target.name.clone(),
            host: host_of(&m.target.target),
            ssl_days_left: m.last_ssl_days_left,
            status: m.last_status.clone(),
            uptime_24h: m.uptime_24h,
        })
        .collect();

    Ok(CertsTemplate {
        account: Some(account),
        active_page: "certs",
        routes,
        standalone,
    })
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/certs", get(page))
}

/// The countdown as an operator would say it.
///
/// Lives here rather than in the template because a negative day count is not
/// a formatting detail: the page used to render `{{ days }} days` verbatim, so
/// a certificate that lapsed five days ago read "-5 days" — the one state on
/// this page that most needs to be unmissable, written as a typo.
fn cert_label(days: Option<i64>) -> String {
    match days {
        None => "—".to_owned(),
        Some(d) if d < 0 => format!("expired {} days ago", -d),
        Some(0) => "expires today".to_owned(),
        Some(1) => "1 day left".to_owned(),
        Some(d) => format!("{d} days left"),
    }
}

impl RouteCertView {
    fn cert_class(&self) -> &'static str {
        cert_class(self.ssl_days_left)
    }
    fn cert_label(&self) -> String {
        cert_label(self.ssl_days_left)
    }
}
/// Maps a health probe's status onto a pill tone. `up` and `degraded` are not
/// tone names — only `down` coincidentally is — so the mapping has to be
/// explicit or two of the three states render unstyled.
fn status_class(status: Option<&str>) -> &'static str {
    match status {
        Some("up") => "ok",
        Some("degraded") => "warn",
        Some("down") => "down",
        _ => "idle",
    }
}

impl StandaloneCertView {
    fn cert_class(&self) -> &'static str {
        cert_class(self.ssl_days_left)
    }
    fn cert_label(&self) -> String {
        cert_label(self.ssl_days_left)
    }
    fn status_class(&self) -> &'static str {
        status_class(self.status.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_handles_url_port_and_plain() {
        assert_eq!(host_of("https://jellyfin.example.com/health"), "jellyfin.example.com");
        assert_eq!(host_of("jellyfin.example.com:8920"), "jellyfin.example.com");
        assert_eq!(host_of("EXAMPLE.com"), "example.com");
    }

    #[test]
    fn cert_class_thresholds() {
        assert_eq!(cert_class(Some(3)), "down");
        assert_eq!(cert_class(Some(14)), "warn");
        assert_eq!(cert_class(Some(60)), "ok");
        assert_eq!(cert_class(None), "idle");
        // An expired certificate is past due, not fine.
        assert_eq!(cert_class(Some(0)), "down");
        assert_eq!(cert_class(Some(-5)), "down");
    }

    #[test]
    fn cert_label_reads_as_a_countdown() {
        assert_eq!(cert_label(Some(60)), "60 days left");
        assert_eq!(cert_label(Some(1)), "1 day left");
        assert_eq!(cert_label(Some(0)), "expires today");
        // The regression this exists for: never render "-5 days".
        assert_eq!(cert_label(Some(-5)), "expired 5 days ago");
        assert_eq!(cert_label(None), "—");
    }

    #[test]
    fn status_class_maps_every_probe_state_to_a_pill_tone() {
        assert_eq!(status_class(Some("up")), "ok");
        assert_eq!(status_class(Some("degraded")), "warn");
        assert_eq!(status_class(Some("down")), "down");
        assert_eq!(status_class(None), "idle");
        assert_eq!(status_class(Some("nonsense")), "idle");
    }
}
