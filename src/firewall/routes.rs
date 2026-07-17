//! Firewall management dashboard.
//!
//! - `GET    /firewall`                 page
//! - `GET    /firewall/data`            rules + lockouts + backend status
//! - `POST   /firewall/rule`            create a rule
//! - `POST   /firewall/rule/:id/toggle` enable/disable a rule
//! - `DELETE /firewall/rule/:id`        remove a rule
//! - `POST   /firewall/lockout`         manually block an IP
//! - `POST   /firewall/lockout/:id/release` release an active lockout
//! - `POST   /firewall/apply`           re-apply all rules to the backend
//!
//! State-changing actions are `tracing`-logged with stable `firewall.*` names
//! (the audit slice wires these into the audit trail later); every handler is
//! `is_admin()`-gated, and backend exec is a no-op when no backend is detected
//! (the DB mirror is still the source of truth, so the UI keeps working).

use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Form, Router,
};
use serde::{Deserialize, Serialize};

use crate::account::routes::Sudo;
use crate::audit;
use crate::firewall::{self, backend::Backend, storage::NewRule};
use crate::session::Account;
use crate::{revert, AppState};

#[derive(Template)]
#[template(path = "firewall.html")]
struct AdminFirewallTemplate {
    account: Option<Account>,
    active_page: &'static str,
    backend_label: &'static str,
}

async fn page(State(state): State<AppState>, account: Account) -> Result<AdminFirewallTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let backend_label = state.firewall_backend().map(|b| b.kind.label()).unwrap_or("disabled");
    Ok(AdminFirewallTemplate {
        account: Some(account),
        active_page: "firewall",
        backend_label,
    })
}

#[derive(Serialize)]
struct DashboardData {
    backend: &'static str,
    rules: Vec<firewall::FirewallRule>,
    lockouts: Vec<firewall::LockoutRow>,
    auto_threshold: i64,
    auto_window_secs: i64,
    auto_lockout_secs: i64,
}

async fn data(State(state): State<AppState>, account: Account) -> Result<Json<DashboardData>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let backend = state.firewall_backend().map(|b| b.kind.label()).unwrap_or("disabled");
    // Reconcile the live ufw ruleset into the mirror so rules created
    // out-of-band still show up. Best-effort; never blocks the dashboard.
    firewall::sync::sync_live(&state).await;
    let rules = firewall::storage::list_rules(&state)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let lockouts = firewall::storage::list_lockouts(&state, false)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(DashboardData {
        backend,
        rules,
        lockouts,
        auto_threshold: firewall::lockout::DEFAULT_THRESHOLD,
        auto_window_secs: firewall::lockout::DEFAULT_WINDOW_SECS,
        auto_lockout_secs: firewall::lockout::DEFAULT_LOCKOUT_SECS,
    }))
}

/// `GET /firewall/preview` — the dry-run of Apply (§11.2): the exact commands it
/// would run against the live backend, each tagged with whether it is already on
/// the host (`ctx`) or would be added (`add`). Read-only; runs nothing.
///
/// This is what makes "a ruleset that would cut you off" visible *before* it is
/// live rather than after — the operator reads the drops and rate-limits about to
/// be inserted, in the backend's own syntax, and decides.
async fn preview(State(state): State<AppState>, account: Account) -> Result<Json<serde_json::Value>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let rules = firewall::storage::list_rules(&state)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let backend = state.firewall_backend();
    // What is already live, asked once. `None` = the backend can't tell us, and an
    // unknown must read as "would apply" (an `add`), exactly as Apply itself treats it.
    let live = match backend {
        Some(b) => b.live_tags().await,
        None => None,
    };

    let mut lines: Vec<crate::diffutil::DiffLine> = Vec::new();
    let mut to_apply = 0usize;
    let mut already = 0usize;
    for rule in rules.iter().filter(|r| r.enabled) {
        let Some(argv) = backend.and_then(|b| b.apply_command(rule)) else {
            continue; // disabled backend — nothing to render
        };
        let text = Backend::render(&argv);
        let is_live = live.as_ref().is_some_and(|tags| tags.contains(&Backend::tag(rule)));
        if is_live {
            already += 1;
            lines.push(crate::diffutil::DiffLine { tag: "ctx", text });
        } else {
            to_apply += 1;
            lines.push(crate::diffutil::DiffLine { tag: "add", text });
        }
    }

    Ok(Json(serde_json::json!({
        "backend": backend.map(|b| b.kind.label()).unwrap_or("disabled"),
        "to_apply": to_apply,
        "already_live": already,
        "lines": lines,
    })))
}

#[derive(Deserialize)]
struct RuleForm {
    action: String,
    #[serde(default)]
    direction: Option<String>,
    #[serde(default)]
    proto: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    port: Option<i64>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    rate_per_s: Option<i64>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    enabled: Option<String>,
}

impl RuleForm {
    fn validate(self) -> Result<NewRule, StatusCode> {
        let action = self.action.trim().to_string();
        if !matches!(action.as_str(), "allow" | "deny" | "rate_limit" | "geo_block") {
            return Err(StatusCode::BAD_REQUEST);
        }
        let direction = self.direction.unwrap_or_else(|| "in".to_string());
        if !matches!(direction.as_str(), "in" | "out" | "any") {
            return Err(StatusCode::BAD_REQUEST);
        }
        let proto = self.proto.unwrap_or_else(|| "any".to_string());
        if !matches!(proto.as_str(), "tcp" | "udp" | "icmp" | "any") {
            return Err(StatusCode::BAD_REQUEST);
        }
        let source = self.source.filter(|s| !s.trim().is_empty());
        let country = self
            .country
            .map(|c| c.trim().to_ascii_uppercase())
            .filter(|c| !c.is_empty());
        if action == "geo_block" && country.is_none() {
            return Err(StatusCode::BAD_REQUEST);
        }
        let enabled = !matches!(self.enabled.as_deref(), Some("false" | "0" | "off"));
        Ok(NewRule {
            action,
            direction,
            proto,
            source,
            port: self.port,
            country,
            rate_per_s: self.rate_per_s,
            note: self.note,
            enabled,
        })
    }
}

async fn create_rule(
    State(state): State<AppState>,
    account: Account,
    Form(form): Form<RuleForm>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let rule = form.validate()?;
    let action = rule.action.clone();
    let source = rule.source.clone();
    let id = firewall::storage::create_rule(&state, rule)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Best-effort apply. Failures are logged but don't block the response
    // because the DB row is still the source of truth and the admin can
    // re-apply manually.
    let mut apply_output: Option<String> = None;
    if let Some(rule) = firewall::storage::get_rule(&state, id).await.ok().flatten() {
        if rule.enabled {
            if let Some(backend) = state.firewall_backend() {
                if let Some(argv) = backend.apply_command(&rule) {
                    let preview = Backend::render(&argv);
                    match backend.exec(argv).await {
                        Ok(o) if o.status.success() => apply_output = Some(preview),
                        Ok(o) => {
                            apply_output = Some(format!(
                                "{preview} → exit {} :: {}",
                                o.status,
                                String::from_utf8_lossy(&o.stderr)
                            ));
                        }
                        Err(e) => apply_output = Some(format!("{preview} → {e}")),
                    }
                }
            }
        }
    }
    audit::event("firewall.rule.create", &account)
        .target(id)
        .detail(serde_json::json!({ "action": action, "source": source, "apply": &apply_output }))
        .record(&state.db)
        .await;
    Ok(Json(serde_json::json!({ "id": id, "apply": apply_output })))
}

#[derive(Deserialize)]
struct TogglePayload {
    enabled: String,
}

/// The response for "the host would not do what you asked".
///
/// A 409 rather than a 500: nothing is broken, the packet filter simply still
/// holds the rule, and the operator needs to know that in those words — the row
/// is deliberately still there, still saying "enabled", because that is the truth.
fn still_live(what: &str, reason: &str) -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": format!("{what} is still live on the host: {reason}"),
        })),
    )
        .into_response()
}

async fn toggle_rule(
    State(state): State<AppState>,
    account: Account,
    Path(id): Path<i64>,
    Form(form): Form<TogglePayload>,
) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let enabled = matches!(form.enabled.as_str(), "true" | "1" | "on");
    let Ok(Some(rule)) = firewall::storage::get_rule(&state, id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };

    // Host first, mirror second. The old order wrote the row and then tried the
    // host, discarding the result — so a failed disable left a row that said
    // "off" over a rule that was still dropping packets.
    if let Some(backend) = state.firewall_backend() {
        let outcome = if enabled {
            match backend.apply_command(&rule) {
                Some(argv) => backend.exec(argv).await.map(|o| o.status.success()).unwrap_or(false),
                None => true,
            }
        } else {
            match backend.remove(&rule).await {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!(error = %e, id, "could not remove the rule from the host");
                    return still_live("That rule", &e.to_string());
                }
            }
        };
        if !outcome && enabled {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": "The host refused that rule; it has not been enabled." })),
            )
                .into_response();
        }
    }

    if firewall::storage::toggle_rule(&state, id, enabled).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    audit::event("firewall.rule.toggle", &account)
        .target(id)
        .detail(serde_json::json!({ "enabled": enabled }))
        .record(&state.db)
        .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn delete_rule(State(state): State<AppState>, account: Account, Path(id): Path<i64>) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    // The row is the *only* handle back to the live rule: the host rule carries
    // `vantage:<id>` and nothing else identifies it. Dropping the row after a
    // failed removal would leave a rule on the host that Vantage can no longer
    // name, let alone remove — permanent, and invisible. So the row stays until
    // the host says the rule is gone.
    if let Some(rule) = firewall::storage::get_rule(&state, id).await.ok().flatten() {
        if let Some(backend) = state.firewall_backend() {
            if let Err(e) = backend.remove(&rule).await {
                tracing::warn!(error = %e, id, "could not remove the rule from the host");
                audit::event("firewall.rule.delete", &account)
                    .target(id)
                    .detail(serde_json::json!({ "error": e.to_string() }))
                    .failed()
                    .record(&state.db)
                    .await;
                return still_live("That rule", &e.to_string());
            }
        }
    }
    if firewall::storage::delete_rule(&state, id).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    audit::event("firewall.rule.delete", &account)
        .target(id)
        .record(&state.db)
        .await;
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
struct LockoutForm {
    ip: String,
    #[serde(default)]
    reason: Option<String>,
    /// Lockout length in seconds. Empty / 0 = indefinite.
    #[serde(default)]
    duration_secs: Option<i64>,
}

async fn add_lockout(
    State(state): State<AppState>,
    account: Account,
    Form(form): Form<LockoutForm>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    if form.ip.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let duration = form.duration_secs.filter(|s| *s > 0);
    let reason = form.reason.unwrap_or_else(|| "manual".to_string());
    let id = firewall::storage::add_lockout(&state, form.ip.trim(), &reason, duration)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Whether the kernel block actually went on. A lockout row without a kernel
    // rule behind it is a list of addresses you believe are blocked, which is
    // worse than knowing they are not.
    let blocked = firewall::lockout::apply_backend_block(&state, form.ip.trim(), true).await;
    audit::event("firewall.lockout.add", &account)
        .target(form.ip.trim())
        .detail(serde_json::json!({ "reason": reason, "duration_secs": duration, "blocked": blocked }))
        .ok(blocked || state.firewall_backend().is_none())
        .record(&state.db)
        .await;
    Ok(Json(serde_json::json!({ "id": id, "blocked": blocked })))
}

async fn release_lockout(
    State(state): State<AppState>,
    account: Account,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    // Look up the IP first so we can remove the kernel rule.
    let target_ip = firewall::storage::list_lockouts(&state, false)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .find(|l| l.id == id)
        .map(|l| l.ip);
    firewall::storage::release_lockout(&state, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(ip) = target_ip.as_deref() {
        firewall::lockout::apply_backend_block(&state, ip, false).await;
    }
    audit::event("firewall.lockout.release", &account)
        .target(target_ip.unwrap_or_else(|| format!("lockout:{id}")))
        .record(&state.db)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `?revert=<secs>` on apply arms a self-revert (§11.1): the apply rolls itself
/// back after `secs` unless a confirm arrives. Absent / 0 = the old fire-and-keep.
#[derive(Deserialize)]
struct ApplyQuery {
    #[serde(default)]
    revert: Option<u64>,
}

/// The window is operator-supplied, so it is clamped: too short and a slow link
/// can't confirm in time; too long and a lock-out sits for minutes.
const REVERT_MIN_SECS: u64 = 5;
const REVERT_MAX_SECS: u64 = 600;

/// Pushes every enabled rule at the live backend.
///
/// Sudo-gated: this is the one action in Vantage that can lock you out of the
/// box it runs on. A stale session tab left open on the firewall page should not
/// be one misclick away from applying a ruleset to a remote host — so it asks who
/// you are first (the prompt and retry are handled by `core/api.js`).
///
/// With `?revert=<secs>` the apply arms a rollback: the exact rules it pushed are
/// removed after the window unless a `/firewall/apply/confirm` lands first. A
/// ruleset that cuts off the operator's own session reverts itself.
async fn reapply_all(
    State(state): State<AppState>,
    Query(query): Query<ApplyQuery>,
    sudo: Sudo,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let account = sudo.account;
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let backend = match state.firewall_backend() {
        Some(b) => b,
        None => {
            return Ok(Json(serde_json::json!({
                "applied": 0,
                "skipped": "no backend configured",
            })));
        }
    };
    let rules = firewall::storage::list_rules(&state)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // What is already on the host, asked once rather than once per rule. `None`
    // means the backend cannot tell us, and an unknown must not be treated as a
    // "no" — so those backends apply everything, exactly as before.
    let live = backend.live_tags().await;

    let mut applied = 0usize;
    let mut already = 0usize;
    let mut errors: Vec<String> = Vec::new();
    // The rules this apply actually pushed — the exact set an armed revert removes.
    let mut applied_rules: Vec<firewall::FirewallRule> = Vec::new();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        // Apply appends. Without this check, pressing Apply twice put a second
        // copy of every rule in the chain, and the tenth press a tenth — an
        // ever-growing chain that says the same thing ten times.
        if live.as_ref().is_some_and(|tags| tags.contains(&Backend::tag(&rule))) {
            already += 1;
            continue;
        }
        let Some(argv) = backend.apply_command(&rule) else {
            continue;
        };
        let preview = Backend::render(&argv);
        match backend.exec(argv).await {
            Ok(o) if o.status.success() => {
                applied += 1;
                applied_rules.push(rule);
            }
            Ok(o) => errors.push(format!(
                "{preview} → exit {} :: {}",
                o.status,
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => errors.push(format!("{preview} → {e}")),
        }
    }
    audit::event("firewall.apply_all", &account)
        .detail(serde_json::json!({ "applied": applied, "already_live": already, "errors": &errors }))
        // A partial apply is not a success: some of the ruleset is live and some
        // is not, which is the state an operator most needs to be able to find.
        .ok(errors.is_empty())
        .record(&state.db)
        .await;

    // Arm the self-revert, but only when there is something to undo — arming a
    // countdown over an apply that changed nothing would ask the operator to
    // confirm a no-op.
    let revert_info = match query.revert {
        Some(secs) if secs > 0 && !applied_rules.is_empty() => {
            let window = Duration::from_secs(secs.clamp(REVERT_MIN_SECS, REVERT_MAX_SECS));
            let revert_state = state.clone();
            let armed_rules = applied_rules.clone();
            let rollback: revert::RevertFn = Arc::new(move || {
                let state = revert_state.clone();
                let rules = armed_rules.clone();
                Box::pin(async move { firewall::revert_applied(&state, &rules).await })
            });
            Some(state.reverts.arm("firewall", window, rollback))
        }
        _ => None,
    };

    Ok(Json(serde_json::json!({
        "applied": applied,
        "already_live": already,
        "errors": errors,
        "revert": revert_info,
    })))
}

/// The token an armed apply hands back, sent to confirm or revert it.
#[derive(Deserialize)]
struct RevertToken {
    token: String,
}

/// `POST /firewall/apply/confirm` — keep an armed apply: cancel its revert timer.
/// Plain admin, not sudo: the destructive step already happened under sudo, and
/// this only *keeps* it — the safe direction is confirm, so it must not be harder
/// than doing nothing (which would auto-revert).
async fn confirm_apply(
    State(state): State<AppState>,
    account: Account,
    Json(body): Json<RevertToken>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let kept = state.reverts.confirm("firewall", &body.token);
    audit::event("firewall.apply.confirmed", &account)
        .ok(kept)
        .record(&state.db)
        .await;
    Ok(Json(serde_json::json!({ "kept": kept })))
}

/// `POST /firewall/apply/revert` — roll an armed apply back now, without waiting
/// for the window. Undo is always safe, so this is plain admin too.
async fn revert_apply_now(
    State(state): State<AppState>,
    account: Account,
    Json(body): Json<RevertToken>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let reverted = match state.reverts.take_for_revert("firewall", &body.token) {
        Some(rollback) => {
            rollback().await;
            true
        }
        None => false,
    };
    audit::event("firewall.apply.revert_now", &account)
        .ok(reverted)
        .record(&state.db)
        .await;
    Ok(Json(serde_json::json!({ "reverted": reverted })))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/firewall", get(page))
        .route("/firewall/data", get(data))
        .route("/firewall/preview", get(preview))
        .route("/firewall/rule", post(create_rule))
        .route("/firewall/rule/:id", axum::routing::delete(delete_rule))
        .route("/firewall/rule/:id/toggle", post(toggle_rule))
        .route("/firewall/lockout", post(add_lockout))
        .route("/firewall/lockout/:id/release", post(release_lockout))
        .route("/firewall/apply", post(reapply_all))
        .route("/firewall/apply/confirm", post(confirm_apply))
        .route("/firewall/apply/revert", post(revert_apply_now))
}
