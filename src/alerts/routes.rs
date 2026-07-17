//! Alert settings routes.
//!
//! GET  /alerts                  — the alerts page
//! GET  /alerts/data             — JSON sinks + recent deliveries
//! POST /alerts/sinks/:sink      — enable/disable a sink (sudo)
//! POST /alerts/test/:sink       — fire a test alert at one sink
//! POST /alerts/on-admin-login   — toggle the sign-in alert (sudo)
//!
//! There is deliberately **no route that edits a sink's URL**. Sinks are
//! configured in `config.json` and nowhere else — see the module docs on why an
//! endpoint that rewrites the alert destination is a liability rather than a
//! convenience.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};

use crate::{account::routes::Sudo, alerts, audit, session::Account, AppState};

/// How many delivery rows the page asks for.
const FEED_LIMIT: i64 = 50;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/alerts", get(page))
        .route("/alerts/data", get(data))
        .route("/alerts/sinks/:sink", post(set_sink))
        .route("/alerts/test/:sink", post(test_sink))
        .route("/alerts/on-admin-login", post(set_admin_login_alert))
}

// ─── Page ────────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "alerts.html")]
struct AlertsTemplate {
    account: Option<Account>,
    active_page: &'static str,
    any_configured: bool,
}

async fn page(State(state): State<AppState>, account: Account) -> Result<AlertsTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(AlertsTemplate {
        account: Some(account),
        active_page: "alerts",
        any_configured: state.has_any_alert_sink(),
    })
}

// ─── Data ────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct SinkView {
    /// The storage/delivery-log key — also what the routes address it by.
    name: &'static str,
    label: &'static str,
    /// What this sink is, in one line, for an operator who has not configured it.
    blurb: &'static str,
    /// The `config.json` key that turns it on, so the page can say *how* to
    /// configure a sink rather than just noting that it isn't.
    config_key: &'static str,
    configured: bool,
    enabled: bool,
    /// Masked destination — host only. `None` when not configured.
    target: Option<String>,
    /// A second line of non-secret detail (email recipients).
    detail: Option<String>,
}

#[derive(Serialize)]
struct AlertsData {
    sinks: Vec<SinkView>,
    deliveries: Vec<alerts::Delivery>,
    on_admin_login: bool,
}

fn label_of(sink: &str) -> &'static str {
    match sink {
        "discord" => "Discord",
        "ntfy" => "ntfy",
        "webhook" => "Webhook",
        "email" => "Email",
        _ => "Unknown",
    }
}

async fn data(State(state): State<AppState>, account: Account) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let cfg = &state.config.alerts;

    let mut sinks = Vec::new();
    for name in alerts::SINKS {
        let (configured, target, detail) = match name {
            "discord" => (
                cfg.discord_webhook_url.is_some(),
                cfg.discord_webhook_url.as_deref().map(alerts::mask_url),
                None,
            ),
            "ntfy" => (
                cfg.ntfy_url.is_some(),
                cfg.ntfy_url.as_deref().map(alerts::mask_url),
                None,
            ),
            "webhook" => (
                cfg.webhook_url.is_some(),
                cfg.webhook_url.as_deref().map(alerts::mask_url),
                None,
            ),
            "email" => match &cfg.email {
                // Host and recipients are not secrets — they are how you tell
                // one relay from another. The password never leaves config.json.
                Some(email) => (
                    true,
                    Some(format!("{}:{}", email.host, email.port)),
                    Some(format!("to {}", email.to.join(", "))),
                ),
                None => (false, None, None),
            },
            _ => (false, None, None),
        };
        sinks.push(SinkView {
            name,
            label: label_of(name),
            blurb: match name {
                "discord" => "Rich embeds posted to a channel webhook.",
                "ntfy" => "Push notification to a phone, via a topic URL.",
                "webhook" => "The alert as JSON, POSTed to any endpoint you run.",
                "email" => "Plain-text mail over SMTP with TLS.",
                _ => "",
            },
            config_key: match name {
                "discord" => "alerts.discord_webhook_url",
                "ntfy" => "alerts.ntfy_url",
                "webhook" => "alerts.webhook_url",
                "email" => "alerts.email",
                _ => "",
            },
            configured,
            enabled: alerts::sink_enabled(&state.db, name).await,
            target,
            detail,
        });
    }

    let deliveries = alerts::recent_deliveries(&state.db, FEED_LIMIT)
        .await
        .unwrap_or_default();

    Json(AlertsData {
        sinks,
        deliveries,
        on_admin_login: alerts::alert_on_admin_login(&state.db).await,
    })
    .into_response()
}

// ─── Mutations ───────────────────────────────────────────────────────────────

fn fail(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

#[derive(Deserialize)]
struct EnabledBody {
    enabled: bool,
}

/// Switches a sink on or off.
///
/// Sudo-gated. Turning an alarm off is not an ordinary preference change — it is
/// the single most useful thing to do to a box you have just broken into, and
/// the cost of asking is one password prompt every ten minutes.
async fn set_sink(
    State(state): State<AppState>,
    sudo: Sudo,
    Path(sink): Path<String>,
    Json(body): Json<EnabledBody>,
) -> Response {
    if !sudo.account.is_admin() {
        return fail(StatusCode::FORBIDDEN, "You don't have permission to do that.");
    }
    if !alerts::SINKS.contains(&sink.as_str()) {
        return fail(StatusCode::NOT_FOUND, "No such alert sink.");
    }
    if let Err(e) = alerts::set_sink_enabled(&state.db, &sink, body.enabled).await {
        tracing::error!(error = ?e, "could not set sink state");
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "The server could not save that.");
    }
    audit::event("alerts.sink.toggle", &sudo.account)
        .target(&sink)
        .detail(serde_json::json!({ "enabled": body.enabled }))
        .record(&state.db)
        .await;
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Serialize)]
struct TestResult {
    ok: bool,
    error: Option<String>,
}

/// Fires a test alert at one sink and reports what happened.
///
/// Not sudo-gated: it sends a message you already configured to an address you
/// already chose, and nothing about the host changes. Making it destructive-
/// grade would just teach people to skip testing.
async fn test_sink(State(state): State<AppState>, account: Account, Path(sink): Path<String>) -> Response {
    if !account.is_admin() {
        return fail(StatusCode::FORBIDDEN, "You don't have permission to do that.");
    }
    if !alerts::SINKS.contains(&sink.as_str()) {
        return fail(StatusCode::NOT_FOUND, "No such alert sink.");
    }

    let payload = serde_json::json!({
        "username": "Vantage",
        "embeds": [{
            "title": "Test alert",
            "description": format!(
                "{} sent this from the Alerts page. If you are reading it, this sink works.",
                account.name
            ),
            // The info blue every non-event alert uses — a test that arrived
            // looking like an outage is a test that costs someone their evening.
            "color": 0x3b82f6,
            "fields": [
                { "name": "Sink", "value": label_of(&sink), "inline": true },
                { "name": "Host", "value": state.config.base_url.clone(), "inline": true },
            ]
        }]
    });

    let outcomes = state.deliver_alert(&payload, Some(&sink), true).await;
    match outcomes.into_iter().next() {
        Some((_, Ok(()))) => Json(TestResult { ok: true, error: None }).into_response(),
        Some((_, Err(reason))) => Json(TestResult {
            ok: false,
            error: Some(reason),
        })
        .into_response(),
        // `deliver_alert` returns nothing when the sink is not configured, which
        // the page's disabled button should already have prevented.
        None => fail(StatusCode::CONFLICT, "That sink isn't configured in config.json."),
    }
}

async fn set_admin_login_alert(State(state): State<AppState>, sudo: Sudo, Json(body): Json<EnabledBody>) -> Response {
    if !sudo.account.is_admin() {
        return fail(StatusCode::FORBIDDEN, "You don't have permission to do that.");
    }
    if let Err(e) = alerts::set_alert_on_admin_login(&state.db, body.enabled).await {
        tracing::error!(error = ?e, "could not set the sign-in alert");
        return fail(StatusCode::INTERNAL_SERVER_ERROR, "The server could not save that.");
    }
    audit::event("alerts.on_admin_login", &sudo.account)
        .detail(serde_json::json!({ "enabled": body.enabled }))
        .record(&state.db)
        .await;
    StatusCode::NO_CONTENT.into_response()
}
