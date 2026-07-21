//! systemd unit status and control.
//!
//! **Which units are reachable is configuration, not request input.** The
//! `systemd_units` list in `config.json` names them; a route resolves the unit
//! in a request by *looking that string up in the list* and passing the
//! configured value to `systemctl` — never the request's own string. That is the
//! same rule the database console applies to its sources and `cron` applies to
//! its scripts: there is no route that accepts a unit name, so there is nothing
//! to aim at `sshd`, at the firewall, or at Vantage itself.
//!
//! The unit name reaches the host as an argv element through
//! [`kls_agent::HostCommand`], so it is data either way — the allowlist is about
//! *which* units an authenticated admin may restart, which is a separate
//! question from shell safety.

use crate::{account::routes::Sudo, audit, session::Account, AppState};
use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use kls_agent::{HostCommand, Tool};
use serde::Serialize;

/// The unit operations reachable over HTTP.
///
/// Deliberately short. `start`/`stop`/`restart` are what an operator reaches for
/// when something is wrong now. `enable`/`disable`/`mask` change what the box
/// does on its *next boot* — that is a config change whose evidence should live
/// in config management, not behind a button whose effect stays invisible until
/// a reboot nobody connects to it.
const ACTIONS: [&str; 3] = ["start", "stop", "restart"];

/// Properties fetched in one `systemctl show` call per unit.
const PROPERTIES: &str = "Id,Description,ActiveState,SubState,UnitFileState,ExecMainStartTimestamp";

/// One unit as the page renders it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnitStatus {
    pub unit: String,
    pub description: String,
    /// `active`, `inactive`, `failed`, `activating`, … — or `unknown` when
    /// `systemctl` could not be reached at all.
    pub active_state: String,
    pub sub_state: String,
    /// `enabled`, `disabled`, `static`, … Empty for a unit with no unit file.
    pub file_state: String,
    pub since: String,
    /// Design-system pill tone for `active_state` (see components.css), computed
    /// server-side so the page has one source of truth instead of a JS copy that
    /// can drift from this table's rules.
    pub tone: &'static str,
}

/// Maps a unit's `ActiveState` onto a pill tone.
///
/// `activating`/`deactivating` are transient rather than good, so they take the
/// warn tone: a unit stuck in `activating` is a unit that is not up.
fn tone_for(active_state: &str) -> &'static str {
    match active_state {
        "active" => "ok",
        "failed" => "down",
        "activating" | "deactivating" | "reloading" => "warn",
        _ => "idle",
    }
}

/// Parses `systemctl show`'s `KEY=VALUE` output for one unit.
///
/// Values routinely contain `=` (most `Description`s on a real box do), so each
/// line splits on the *first* `=` only. Keys absent from the output — which is
/// how systemd reports "this unit has no unit file" — become empty strings
/// rather than an error: a unit that exists but is not enabled is a normal thing
/// to show, not a failure to read it.
fn parse_show(unit: &str, out: &str) -> UnitStatus {
    let mut description = String::new();
    let mut active_state = String::new();
    let mut sub_state = String::new();
    let mut file_state = String::new();
    let mut since = String::new();

    for line in out.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().to_string();
        match key {
            "Description" => description = value,
            "ActiveState" => active_state = value,
            "SubState" => sub_state = value,
            "UnitFileState" => file_state = value,
            "ExecMainStartTimestamp" => since = value,
            _ => {}
        }
    }

    // A unit with no ActiveState line was unreadable; systemd would always emit
    // one, so its absence means the call itself failed.
    let active_state = if active_state.is_empty() {
        "unknown".to_string()
    } else {
        active_state
    };
    let tone = tone_for(&active_state);

    UnitStatus {
        unit: unit.to_string(),
        // A unit with no unit file has no Description either; showing the unit
        // name twice reads better than showing an empty cell.
        description: if description.is_empty() {
            unit.to_string()
        } else {
            description
        },
        active_state,
        sub_state,
        file_state,
        since,
        tone,
    }
}

/// Reads one configured unit's current state.
///
/// A `systemctl` that is missing or refuses is reported as `unknown` rather than
/// propagated: this page's job is to show what the box thinks, and one
/// unreadable unit must not blank the other nine.
async fn status_of(unit: &str) -> UnitStatus {
    let result = HostCommand::new(Tool::Systemctl)
        .args(["show", "--no-pager", "--property", PROPERTIES, unit])
        .output()
        .await;

    match result {
        Ok(out) => parse_show(unit, &String::from_utf8_lossy(&out.stdout)),
        Err(e) => {
            tracing::warn!(unit, error = %e, "systemd: could not read unit state");
            parse_show(unit, "")
        }
    }
}

/// Every configured unit's state, read concurrently.
pub async fn statuses(state: &AppState) -> Vec<UnitStatus> {
    futures_util::future::join_all(state.config.systemd_units.iter().map(|u| status_of(u))).await
}

// ─── Page ────────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "systemd.html")]
struct SystemdTemplate {
    account: Option<Account>,
    active_page: &'static str,
    any_units: bool,
}

async fn page(State(state): State<AppState>, account: Account) -> SystemdTemplate {
    SystemdTemplate {
        account: Some(account),
        active_page: "systemd",
        any_units: !state.config.systemd_units.is_empty(),
    }
}

async fn data(State(state): State<AppState>, _account: Account) -> Response {
    Json(serde_json::json!({ "units": statuses(&state).await })).into_response()
}

// ─── Actions ─────────────────────────────────────────────────────────────────

fn fail(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

/// Runs one `systemctl` verb against one configured unit.
///
/// Sudo-gated: restarting a unit is how an operator takes a service down, and a
/// stolen session cookie should not be able to do that without the password the
/// re-auth prompt asks for.
async fn action(State(state): State<AppState>, sudo: Sudo, Path((unit, verb)): Path<(String, String)>) -> Response {
    if !sudo.account.is_admin() {
        return fail(StatusCode::FORBIDDEN, "You don't have permission to do that.");
    }
    if !ACTIONS.contains(&verb.as_str()) {
        return fail(StatusCode::BAD_REQUEST, "Unsupported unit action.");
    }
    // The configured string is what runs — the request only *selects* it. A unit
    // that is not on the list has no representation here at all.
    let Some(configured) = state.config.systemd_units.iter().find(|u| **u == unit) else {
        // Recorded, because "someone asked this box to restart a unit its
        // operator never listed" is exactly the line worth having afterwards.
        audit::event("systemd.unit.action", &sudo.account)
            .target(&unit)
            .detail(serde_json::json!({ "action": verb }))
            .failed()
            .record(&state.db)
            .await;
        return fail(StatusCode::NOT_FOUND, "No such unit.");
    };

    let output = HostCommand::new(Tool::Systemctl)
        .args([verb.as_str(), configured.as_str()])
        .output()
        .await;

    let (ok, message) = match &output {
        Ok(out) if out.status.success() => (true, String::new()),
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let err = if err.is_empty() {
                "systemctl reported a failure.".to_string()
            } else {
                err
            };
            (false, err)
        }
        Err(e) => (false, e.to_string()),
    };

    audit::event("systemd.unit.action", &sudo.account)
        .target(configured)
        .detail(serde_json::json!({ "action": verb, "error": message }))
        .ok(ok)
        .record(&state.db)
        .await;

    if !ok {
        return fail(StatusCode::BAD_GATEWAY, &message);
    }
    Json(serde_json::json!({ "ok": true, "unit": status_of(configured).await })).into_response()
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/systemd", get(page))
        .route("/systemd/data", get(data))
        .route("/systemd/:unit/:verb", post(action))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_show_reads_the_properties_it_asked_for() {
        let out = "Id=nginx.service\n\
                   Description=A high performance web server\n\
                   ActiveState=active\n\
                   SubState=running\n\
                   UnitFileState=enabled\n\
                   ExecMainStartTimestamp=Mon 2026-07-20 09:14:02 UTC\n";
        let s = parse_show("nginx.service", out);
        assert_eq!(s.unit, "nginx.service");
        assert_eq!(s.description, "A high performance web server");
        assert_eq!(s.active_state, "active");
        assert_eq!(s.sub_state, "running");
        assert_eq!(s.file_state, "enabled");
        assert_eq!(s.tone, "ok");
    }

    #[test]
    fn parse_show_keeps_equals_signs_inside_a_value() {
        // The regression this guards: splitting on every `=` truncated any
        // description containing one, which is most of them on a real box.
        let s = parse_show("x.service", "Description=Runs foo --flag=bar\nActiveState=active\n");
        assert_eq!(s.description, "Runs foo --flag=bar");
    }

    #[test]
    fn parse_show_survives_missing_properties() {
        // How systemd answers for a unit with no unit file — not an error.
        let s = parse_show("ghost.service", "");
        assert_eq!(s.active_state, "unknown");
        assert_eq!(s.file_state, "");
        // Falls back to the unit name rather than rendering a blank cell.
        assert_eq!(s.description, "ghost.service");
        assert_eq!(s.tone, "idle");
    }

    #[test]
    fn tone_separates_transient_states_from_healthy_ones() {
        assert_eq!(tone_for("active"), "ok");
        assert_eq!(tone_for("failed"), "down");
        // Stuck in `activating` is not up.
        assert_eq!(tone_for("activating"), "warn");
        assert_eq!(tone_for("deactivating"), "warn");
        assert_eq!(tone_for("inactive"), "idle");
        // The unreadable-unit fallback lands on idle, not a crash.
        assert_eq!(tone_for("unknown"), "idle");
    }

    #[test]
    fn only_three_verbs_are_reachable() {
        // Boot-time state changes stay off the HTTP surface.
        for verb in ["enable", "disable", "mask", "daemon-reload", "poweroff"] {
            assert!(!ACTIONS.contains(&verb), "{verb} must not be reachable over HTTP");
        }
        for verb in ["start", "stop", "restart"] {
            assert!(ACTIONS.contains(&verb));
        }
    }
}
