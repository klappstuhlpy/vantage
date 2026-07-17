//! Script routes.
//!
//! GET  /scripts            — the scripts page
//! GET  /scripts/data       — JSON scripts + recent runs
//! POST /scripts/:id/run    — run one script now (sudo)
//! GET  /scripts/:id/runs   — one script's run history
//!
//! There is deliberately **no route that creates or edits a script**. The list
//! comes from `config.json` and nowhere else; an endpoint that could add a
//! command line would be a remote shell with extra steps, and no amount of
//! gating makes that a feature worth having on a control plane.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::Serialize;
use time::OffsetDateTime;

use crate::{account::routes::Sudo, config::SpotlightScript, cron, session::Account, AppState};

/// How many runs the page's history table asks for.
const FEED_LIMIT: i64 = 50;
/// How many runs one script's drawer asks for.
const SCRIPT_FEED_LIMIT: i64 = 20;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/scripts", get(page))
        .route("/scripts/data", get(data))
        .route("/scripts/:id/run", post(run))
        .route("/scripts/:id/runs", get(script_runs))
}

// ─── Page ────────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "scripts.html")]
struct ScriptsTemplate {
    account: Option<Account>,
    active_page: &'static str,
    any_scripts: bool,
}

async fn page(State(state): State<AppState>, account: Account) -> Result<ScriptsTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(ScriptsTemplate {
        account: Some(account),
        active_page: "scripts",
        any_scripts: !state.config.spotlight_scripts.is_empty(),
    })
}

// ─── Data ────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ScriptView {
    id: String,
    name: String,
    description: Option<String>,
    command: String,
    cwd: Option<String>,
    /// The raw cron expression, exactly as written in config.json.
    schedule: Option<String>,
    /// Why the schedule will never fire. `Some` means the script is configured
    /// to run automatically and never will — the one thing this page must not
    /// let an operator keep believing.
    schedule_error: Option<String>,
    /// Next fire time (RFC 3339, UTC). `None` when unscheduled, invalid, or
    /// impossible.
    next_run: Option<String>,
    running: bool,
    last_run: Option<cron::ScriptRun>,
}

#[derive(Serialize)]
struct ScriptsData {
    scripts: Vec<ScriptView>,
    runs: Vec<cron::ScriptRun>,
    timeout_seconds: u64,
}

fn view_of(script: &SpotlightScript, last_run: Option<cron::ScriptRun>) -> ScriptView {
    let parsed = script.schedule.as_ref().map(|expr| cron::CronSchedule::parse(expr));
    let schedule_error = match &parsed {
        Some(Err(e)) => Some(e.clone()),
        _ => None,
    };
    let next_run = match &parsed {
        Some(Ok(sched)) => sched
            .next_after(OffsetDateTime::now_utc())
            .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok()),
        _ => None,
    };
    ScriptView {
        id: script.id.clone(),
        name: script.name.clone(),
        description: script.description.clone(),
        command: script.command.clone(),
        cwd: script.cwd.clone(),
        schedule: script.schedule.clone(),
        schedule_error,
        next_run,
        running: cron::is_running(&script.id),
        last_run,
    }
}

async fn data(State(state): State<AppState>, account: Account) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }

    let runs = cron::recent_runs(&state.db, None, FEED_LIMIT).await.unwrap_or_default();

    let scripts = state
        .config
        .spotlight_scripts
        .iter()
        .map(|script| {
            // The newest run of this script that the feed already fetched. Not a
            // per-script query: with the history bounded at 200 rows, a linear
            // scan of what we hold beats N round trips to SQLite.
            let last = runs.iter().find(|r| r.script_id == script.id).cloned();
            view_of(script, last)
        })
        .collect();

    Json(ScriptsData {
        scripts,
        runs,
        timeout_seconds: cron::SCRIPT_TIMEOUT.as_secs(),
    })
    .into_response()
}

async fn script_runs(State(state): State<AppState>, account: Account, Path(id): Path<String>) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    match cron::recent_runs(&state.db, Some(id), SCRIPT_FEED_LIMIT).await {
        Ok(runs) => Json(serde_json::json!({ "runs": runs })).into_response(),
        Err(e) => {
            tracing::error!(error = ?e, "could not read the run history");
            fail(StatusCode::INTERNAL_SERVER_ERROR, "Could not read the run history.")
        }
    }
}

// ─── Run ─────────────────────────────────────────────────────────────────────

fn fail(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

/// Runs one script now, and answers with what it did.
///
/// Sudo-gated, and the only route in Vantage that is gated purely on what it
/// *could* be rather than what it is: the script itself may be harmless, but
/// this is the app's one arbitrary-command path, so the prompt is priced against
/// the worst line an operator ever puts in `spotlight_scripts`.
///
/// Synchronous — the caller waits out the run (bounded by `SCRIPT_TIMEOUT`) and
/// gets the output back. Anything longer than half a minute belongs on a
/// schedule, not on a button someone is watching.
async fn run(State(state): State<AppState>, sudo: Sudo, Path(id): Path<String>) -> Response {
    if !sudo.account.is_admin() {
        return fail(StatusCode::FORBIDDEN, "You don't have permission to do that.");
    }
    let Some(script) = state.config.spotlight_scripts.iter().find(|s| s.id == id) else {
        return fail(StatusCode::NOT_FOUND, "No such script.");
    };

    match cron::run_script(&state, script, "manual", Some(&sudo.account)).await {
        Some(outcome) => Json(serde_json::json!({
            "ok": outcome.ok,
            "exit_code": outcome.exit_code,
            "output": outcome.output,
            "duration_ms": outcome.duration_ms,
        }))
        .into_response(),
        // 409 rather than a queue: two copies of a backup script over one
        // repository is the failure this exists to prevent, and "it's already
        // running" is a complete answer.
        None => fail(StatusCode::CONFLICT, "That script is already running."),
    }
}
