//! Global safe mode — the shell-level "touch nothing on the host" switch
//! (FRONTEND_MIGRATION_PLAN §11.3, the §7.5 never-lock-yourself-out invariants).
//!
//! When engaged, every destructive host operation is refused *before* it reaches
//! its handler. The point is a single, obvious, one-click way to freeze the
//! machine's mutable surface — during an incident, a migration, or while someone
//! else is holding a wrench inside the box — without hunting through fifteen
//! pages disabling things one at a time.
//!
//! ## Two enforcements, one truth
//!
//! * **Server (authoritative):** the [`guard`] middleware sits on the outermost
//!   layer and answers `423 Locked` to any mutating request whose path is on the
//!   destructive list. This is the backstop that a stale browser tab, a scripted
//!   client, or a race against the toggle cannot get around.
//! * **Browser (cosmetic):** `body.is-safe-mode` (set by `core/safemode.js`) dims
//!   and disables every destructive control via CSS, and the topbar carries a
//!   persistent amber banner. This is courtesy — it stops the operator *trying* —
//!   but it is never trusted; the 423 above is what actually holds.
//!
//! ## Why an atomic, not a DB read per request
//!
//! The gate is consulted on every request. Reading a `storage` row each time
//! would put a DB round-trip in front of the whole app to answer a question that
//! changes maybe twice a year. So the live answer is an [`AtomicBool`] in
//! [`AppState`](crate::AppState); the `storage` row is only its durable shadow,
//! read once at startup ([`load_initial`]) and rewritten on toggle ([`persist`]).
//!
//! ## The list is an allowlist of *destructive* prefixes, deliberately
//!
//! [`is_destructive`] blocks only paths it names, rather than blocking everything
//! and carving out exceptions. The failure mode of the strict form is a locked
//! box you cannot unlock — the safe-mode toggle itself, `/login`, `/account`
//! reauth would all have to be remembered as exceptions, and forgetting one is
//! how safe mode becomes a foot-gun instead of a safety catch. Naming the
//! dangerous routes is the honest direction: a new destructive slice is off the
//! list until someone adds it, which is visible and reviewable, where a silently
//! un-exempted unlock route is neither.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use axum::{
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};

use crate::account::routes::Sudo;
use crate::audit;
use crate::AppState;

/// The `storage` key holding safe mode's durable state. Absent = off, which is
/// the posture every existing install already runs in.
const KEY: &str = "safe_mode.enabled";

/// The destructive path prefixes safe mode freezes. A request is blocked when its
/// method mutates *and* its path is (or is under) one of these.
///
/// Reads (`GET`) are never touched — safe mode stops you changing the host, not
/// looking at it — and neither is anything not named here (auth, the account
/// page, alert test-fires, and, crucially, the safe-mode toggle itself).
const DESTRUCTIVE_PREFIXES: &[&str] = &[
    "/firewall/rule",
    "/firewall/lockout",
    "/firewall/apply",
    "/proxy",
    "/docker",
    "/scripts",
    "/backups",
    // The database console's staged edits (DB Studio P5). Deliberately the
    // apply path alone, not `/database`: browsing and running a read query are
    // not host changes, and freezing the whole console would take the tool you
    // diagnose with along with the tool you break things with. `/database/query`
    // in danger mode is *not* covered here — see the note in dbadmin/routes.rs.
    "/database/apply",
];

/// Whether a request would change host state, and so must be refused while safe
/// mode is engaged.
///
/// Split out and pure so the interesting cases — a destructive POST is blocked, a
/// read to the same path is not, a lookalike path (`/proxyfoo`) is not — are
/// testable without standing up a router.
fn is_destructive(method: &Method, path: &str) -> bool {
    if !matches!(*method, Method::POST | Method::PUT | Method::PATCH | Method::DELETE) {
        return false;
    }
    // Confirming or reverting an already-armed apply (§11.1) is a de-escalation,
    // never a new host change — and it must stay reachable even after safe mode is
    // flipped on mid-window, or the operator is stranded unable to keep or undo the
    // change they just made. These are the endings the revert flow uses.
    if path.ends_with("/confirm") || path.ends_with("/revert") {
        return false;
    }
    DESTRUCTIVE_PREFIXES.iter().any(|prefix| {
        // Segment-boundary match: `/proxy` covers `/proxy` and `/proxy/…` but not
        // a different route that merely starts with the same letters.
        path == *prefix || path.starts_with(&format!("{prefix}/"))
    })
}

/// The outermost gate. Reads the live flag (an atomic, no DB hit) and refuses a
/// destructive request with `423 Locked` and a machine-readable marker the
/// frontend turns into a toast.
pub async fn guard(State(engaged): State<Arc<AtomicBool>>, request: Request, next: Next) -> Response {
    if engaged.load(Ordering::Relaxed) && is_destructive(request.method(), request.uri().path()) {
        tracing::info!(
            method = %request.method(),
            path = request.uri().path(),
            "safe mode: refused a destructive request"
        );
        return (
            StatusCode::LOCKED,
            Json(serde_json::json!({
                "error": "Safe mode is on — host changes are frozen. Turn it off to make changes.",
                "safe_mode": true,
            })),
        )
            .into_response();
    }
    next.run(request).await
}

/// Reads the durable flag at startup so the atomic starts where the operator left
/// it. Any read error resolves to *off*: the fail-safe direction for a switch
/// that freezes the machine is to leave it usable, not to strand it locked
/// because a query hiccupped.
pub async fn load_initial(db: &kls_web_core::Database) -> bool {
    db.get_row("SELECT value FROM storage WHERE name = ?", (KEY.to_string(),), |row| {
        row.get::<_, String>(0)
    })
    .await
    .map(|value| value == "1")
    .unwrap_or(false)
}

/// Writes the durable shadow of the flag.
async fn persist(db: &kls_web_core::Database, engaged: bool) -> anyhow::Result<()> {
    use anyhow::Context;
    db.execute(
        "INSERT INTO storage(name, value) VALUES (?, ?) \
         ON CONFLICT(name) DO UPDATE SET value = excluded.value",
        (KEY.to_string(), if engaged { "1" } else { "0" }),
    )
    .await
    .context("could not save the safe-mode state")?;
    Ok(())
}

// ─── Routes ──────────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct Status {
    engaged: bool,
}

/// `GET /safe-mode` — the live state, for the shell to render the banner and
/// disable controls. Deliberately available to any signed-in session (no admin
/// gate): a non-admin still benefits from being told the box is frozen, and this
/// leaks nothing an admin-only page would not.
async fn status(State(state): State<AppState>, _account: crate::session::Account) -> Json<Status> {
    Json(Status {
        engaged: state.safe_mode.load(Ordering::Relaxed),
    })
}

#[derive(serde::Deserialize)]
struct ToggleBody {
    engaged: bool,
}

/// `POST /safe-mode` — flip safe mode on or off. Sudo-gated: freezing (or, more
/// to the point, *un*freezing) the machine's whole mutable surface is exactly the
/// kind of action a 12-hour-old session should have to prove itself for.
///
/// Note the toggle route is not itself on the destructive list, so turning safe
/// mode *off* is never blocked by safe mode — the one exemption that has to hold
/// or the switch becomes a trap.
async fn toggle(
    State(state): State<AppState>,
    sudo: Sudo,
    Json(body): Json<ToggleBody>,
) -> Result<Json<Status>, StatusCode> {
    let account = sudo.account;
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    // Persist first: the durable row is the one that must not be lost. If it
    // fails we have not lied to the operator about a state that would evaporate
    // on restart.
    if persist(&state.db, body.engaged).await.is_err() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    state.safe_mode.store(body.engaged, Ordering::Relaxed);
    audit::event("safe_mode.toggle", &account)
        .detail(serde_json::json!({ "engaged": body.engaged }))
        .record(&state.db)
        .await;
    Ok(Json(Status { engaged: body.engaged }))
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/safe-mode", get(status).post(toggle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_never_destructive() {
        assert!(!is_destructive(&Method::GET, "/firewall/apply"));
        assert!(!is_destructive(&Method::GET, "/proxy/1/preview"));
    }

    #[test]
    fn mutations_to_named_prefixes_are_destructive() {
        assert!(is_destructive(&Method::POST, "/firewall/apply"));
        assert!(is_destructive(&Method::POST, "/firewall/rule"));
        assert!(is_destructive(&Method::DELETE, "/firewall/rule/7"));
        assert!(is_destructive(&Method::POST, "/proxy"));
        assert!(is_destructive(&Method::POST, "/proxy/3/toggle"));
        assert!(is_destructive(&Method::DELETE, "/proxy/3"));
        assert!(is_destructive(&Method::POST, "/docker/snapshots/2/restore"));
        assert!(is_destructive(&Method::POST, "/scripts/nightly/run"));
    }

    /// The database console's split (DB Studio P5): applying staged edits is a
    /// host change and freezes; browsing, previewing a batch and running a query
    /// do not. The last one is the deliberate asymmetry documented in
    /// `dbadmin/routes.rs` — pinned here so changing it has to be a decision.
    #[test]
    fn safe_mode_freezes_applying_edits_but_not_the_rest_of_the_console() {
        assert!(is_destructive(&Method::POST, "/database/apply"));

        assert!(!is_destructive(&Method::POST, "/database/preview"));
        assert!(!is_destructive(&Method::POST, "/database/query"));
        assert!(!is_destructive(&Method::GET, "/database/rows"));
        assert!(!is_destructive(&Method::GET, "/database/apply"));
        // A lookalike route must not inherit the freeze.
        assert!(!is_destructive(&Method::POST, "/database/applyfoo"));
    }

    #[test]
    fn confirming_or_reverting_an_armed_apply_is_never_blocked() {
        // The revert flow (§11.1) must complete even if safe mode is toggled on
        // during the window — otherwise applying then freezing strands the change.
        assert!(!is_destructive(&Method::POST, "/firewall/apply/confirm"));
        assert!(!is_destructive(&Method::POST, "/firewall/apply/revert"));
        assert!(!is_destructive(&Method::POST, "/proxy/apply/confirm"));
        assert!(!is_destructive(&Method::POST, "/proxy/apply/revert"));
        // …but the arming apply itself is still frozen.
        assert!(is_destructive(&Method::POST, "/firewall/apply"));
        assert!(is_destructive(&Method::POST, "/proxy/apply"));
    }

    #[test]
    fn the_safe_mode_toggle_is_never_blocked_by_safe_mode() {
        // The one exemption that has to hold: you must always be able to turn it
        // back off, or the switch is a trap.
        assert!(!is_destructive(&Method::POST, "/safe-mode"));
    }

    #[test]
    fn a_lookalike_path_is_not_swept_up() {
        // Segment-boundary matching: a different route that merely shares a prefix
        // must not be frozen.
        assert!(!is_destructive(&Method::POST, "/proxyfoo"));
        assert!(!is_destructive(&Method::POST, "/firewall-settings"));
    }

    #[tokio::test]
    async fn persisted_state_survives_a_reload() {
        let state = crate::build_state_with(crate::config::Config::test_default(), std::path::Path::new(":memory:"))
            .await
            .expect("build state");
        assert!(!load_initial(&state.db).await, "safe mode is off by default");
        persist(&state.db, true).await.unwrap();
        assert!(load_initial(&state.db).await, "an engaged flag is read back on reload");
        persist(&state.db, false).await.unwrap();
        assert!(!load_initial(&state.db).await);
    }
}
