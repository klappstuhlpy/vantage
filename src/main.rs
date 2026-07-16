//! Vantage — the standalone, security-first VPS/homelab control plane.
//!
//! Stood up in-tree as a workspace binary (ADMIN_SEPARATION_PLAN Phase 4) before
//! it graduates to its own repo (Phase 6). It links only the shared kernel —
//! [`kls_web_core`] (async SQLite + crypto + migrations), [`kls_ui`] (the design
//! system at `/kls/*`), and [`kls_agent`] (the typed privileged-host-op boundary)
//! — with **no dependency on the `klappstuhl_me` app crate**: its own DB, config,
//! auth and release cadence (locked decision 9, standalone-first).
//!
//! This is the skeleton. The admin **feature slices** (metrics, docker, firewall,
//! health, proxy, backup, ssh, secrets, …) move in one at a time in the following
//! Phase-4 steps while the monolith keeps serving them, so both stay green.
//!
//! Structure so far:
//! - [`config`] — `config.json`, including the fail-closed [`config::Exposure`]
//!   policy (§7.1) evaluated at startup,
//! - [`migrations`] — the embedded `admin.db` schema, applied via the shared runner,
//! - the entry point below: the `admin` bootstrap CLI + the multi-listener server.

use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use axum::{
    extract::{ConnectInfo, State},
    http::{header::SET_COOKIE, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Extension, Form, Json, Router,
};
use cookie::Cookie;
use kls_web_core::{token::Token, Database};
use time::OffsetDateTime;
use tokio::sync::broadcast;

use crate::config::{Config, GuardProfile, Listener};
use crate::session::Account;
use crate::ws::LiveEvent;

mod alerts;
mod backup;
mod cached;
mod certs;
mod cloudflare;
mod config;
mod cron;
mod dashboard;
mod dbadmin;
mod docker;
mod firewall;
mod geoip;
mod guard;
mod health;
mod lockout;
mod logs;
mod metrics;
mod migrations;
mod proxy;
mod sanitizer;
mod secrets;
mod security;
mod session;
mod spotlight;
mod ssh;
mod totp;
mod updates;
mod ws;

/// Shared application state, threaded through every handler.
///
/// Deliberately minimal for the skeleton: the config, the database handle, and a
/// throwaway password hash to compare against on unknown users (constant-time
/// login). The admin runtime handles that live in the monolith's `AppState` today
/// — `docker`, `firewall_backend`, the live-event hub, the alert senders (Seam A)
/// — arrive here as their slices move in.
#[derive(Clone)]
struct AppState {
    pub(crate) config: Arc<Config>,
    pub(crate) db: Arc<Database>,
    /// The on-disk path of `admin.db`. The database console (`dbadmin`) opens
    /// its own short-lived connections to this file rather than borrowing from
    /// the pool, so its per-connection `query_only` pragma can't leak.
    pub(crate) db_path: Arc<PathBuf>,
    /// Broadcast hub for the live-update WebSocket (`/ws`). Feature slices call
    /// [`AppState::live_publish`] as they move in; the `/ws` handler fans events
    /// out to subscribers. Empty until the first publisher slice arrives.
    live_tx: broadcast::Sender<LiveEvent>,
    /// Outbound HTTP client for the health monitor's http/keyword probes (the
    /// SSL-expiry probe does its own raw TLS handshake). Deliberately a plain
    /// client — health checks reach arbitrary operator-configured URLs, so the
    /// SSRF guard the site applies to user-supplied fetches does not apply here.
    pub(crate) client: reqwest::Client,
    /// The read-only Docker introspection handle (Seam A). `None` when the
    /// Docker socket isn't reachable (dev box, or the socket path is absent);
    /// Docker-backed endpoints degrade to 503 rather than 500 in that case.
    /// Reads flow through bollard here; state-changing operations route through
    /// the `kls-agent` host boundary, not this handle.
    pub(crate) docker: Option<Arc<docker::DockerClient>>,
    /// The detected firewall backend (Seam A). `None` when no packet-filter
    /// binary (nft/ufw/iptables) responded at startup — the DB rule mirror still
    /// works, but `apply`/`lockout` exec is a no-op so the UI keeps rendering.
    pub(crate) firewall_backend: Option<Arc<firewall::Backend>>,
    /// GeoIP database for IP→country/city lookups (security dashboard).
    pub(crate) geoip: Arc<geoip::GeoIp>,
    /// Read-only handle to the site's `requests.db` (HTTP access log database).
    /// `None` when not configured or when the path is `:memory:` (test posture).
    pub(crate) requests: Option<Arc<Database>>,
    /// Cloudflare Analytics API client (security dashboard Cloudflare panels).
    /// `None` when `api_token` or `zone_id` is missing.
    pub(crate) cloudflare: Option<Arc<cloudflare::Cloudflare>>,
    /// A valid Argon2 hash of a fixed string, verified against when the username
    /// is unknown so login timing does not reveal account existence.
    pub(crate) incorrect_password_hash: Arc<String>,
}

impl AppState {
    /// The kernel database handle. An accessor (not just the field) so ported
    /// service code that reads `state.database()` — e.g. the health storage
    /// layer — works unchanged.
    pub(crate) fn database(&self) -> &Database {
        &self.db
    }

    /// The read-only Docker handle, if the socket was reachable at startup.
    /// Docker-backed handlers call this and 503 when it returns `None`.
    pub(crate) fn docker(&self) -> Option<&Arc<docker::DockerClient>> {
        self.docker.as_ref()
    }

    /// The detected firewall backend, if any responded at startup. `None` means
    /// no packet-filter binary is usable here — callers skip the kernel exec.
    pub(crate) fn firewall_backend(&self) -> Option<&Arc<firewall::Backend>> {
        self.firewall_backend.as_ref()
    }

    /// Subscribes to the live-event hub (used by each `/ws` connection).
    pub(crate) fn live_subscribe(&self) -> broadcast::Receiver<LiveEvent> {
        self.live_tx.subscribe()
    }

    /// Publishes a live event to every `/ws` subscriber of `topic`. A send error
    /// (no subscribers) is ignored — the hub is fire-and-forget.
    pub(crate) fn live_publish(&self, topic: &'static str, data: serde_json::Value) {
        let _ = self.live_tx.send(LiveEvent { topic, data });
    }

    /// Whether any alert sink (Discord webhook, ntfy, generic webhook, email) is configured.
    pub(crate) fn has_any_alert_sink(&self) -> bool {
        self.config.alerts.discord_webhook_url.is_some()
            || self.config.alerts.ntfy_url.is_some()
            || self.config.alerts.webhook_url.is_some()
            || self.config.alerts.email.is_some()
    }

    /// Fans an alert out to every configured sink. The payload uses the Discord
    /// webhook JSON shape; a neutral notification is derived for non-Discord sinks.
    pub(crate) fn send_alert(&self, value: serde_json::Value) {
        let cfg = &self.config.alerts;
        if let Some(url) = cfg.discord_webhook_url.clone() {
            let client = self.client.clone();
            let v = value.clone();
            tokio::spawn(async move {
                let _ = client.post(&url).json(&v).send().await;
            });
        }
        let note = alerts::AlertNotification::from_discord_value(&value);
        if let Some(url) = cfg.ntfy_url.clone() {
            let client = self.client.clone();
            let n = note.clone();
            tokio::spawn(async move { alerts::send_ntfy(&client, &url, &n).await });
        }
        if let Some(url) = cfg.webhook_url.clone() {
            let client = self.client.clone();
            let n = note.clone();
            tokio::spawn(async move { alerts::send_webhook(&client, &url, &n).await });
        }
        if let Some(email_cfg) = cfg.email.clone() {
            let n = note.clone();
            tokio::spawn(async move {
                if let Err(e) = alerts::send_email(&email_cfg, &n).await {
                    tracing::warn!(error = %e, "email alert delivery failed");
                }
            });
        }
    }
}

/// `account.flags` bit 0 — the admin flag, wire-compatible with the site's
/// `AccountFlags::ADMIN` so the shared token/session machinery maps over unchanged.
pub(crate) const FLAG_ADMIN: i64 = 1 << 0;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("vantage: {e:?}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    // Held for the process lifetime so the non-blocking log writer flushes.
    let _log_guard = setup_logging()?;

    let config = Config::load()?;
    let state = build_state(config).await?;

    // A tiny hand-rolled CLI (no clap dependency): the only non-default verb so
    // far is `admin`, which bootstraps the first host-admin account — mirroring
    // the monolith's `cargo run -- admin`.
    match std::env::args().nth(1).as_deref() {
        None | Some("run") => run_server(state).await,
        Some("admin") => bootstrap_admin(&state).await,
        Some(other) => Err(anyhow::anyhow!("unknown command {other:?} (expected `run` or `admin`)")),
    }
}

/// Sets up logging: a rolling JSON file log under [`logs::logs_directory`] (what
/// the admin log viewer reads) plus a compact stdout layer for the console.
/// Returns the non-blocking writer's guard, which must outlive the process.
fn setup_logging() -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard> {
    use std::str::FromStr;
    use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt, Layer};

    let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let filter = Targets::from_str(&rust_log)?;

    let dir = logs::logs_directory();
    std::fs::create_dir_all(&dir).ok();
    let file_appender = tracing_appender::rolling::Builder::new()
        .max_log_files(30)
        .symlink("today.log")
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_suffix("log")
        .build(&dir)
        .context("could not build the rolling log appender")?;
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(non_blocking)
                .with_filter(filter.clone()),
        )
        .with(tracing_subscriber::fmt::layer().with_target(false).with_filter(filter))
        .init();
    Ok(guard)
}

/// Binds every listener the exposure policy resolves to (fail-closed validation
/// happens here, in [`config::Exposure::listeners`]) and serves the router on each,
/// wrapping the public listener in the guard stack its [`GuardProfile`] selects.
///
/// The public guard applies the fail-closed IP allowlist today (aggressive per-IP
/// login lockout runs in the login handlers, every mode); mTLS
/// (`require_client_cert`), GeoIP country gating, and public-mode TLS/ACME are the
/// remaining Step B2 items — until then every listener serves plain HTTP, correct
/// for the default `vpn`/loopback posture (the tunnel provides transport crypto).
async fn run_server(state: AppState) -> anyhow::Result<()> {
    let listeners = state.config.exposure.listeners()?;
    // Parsed once (already validated by `listeners()`); the public listener's guard
    // enforces it fail-closed.
    let allowlist = Arc::new(state.config.exposure.parsed_allowlist());

    // Background workers. Each feature slice spawns its own as it moves in; a
    // spawn is unconditional (host-metric scrape errors are logged and skipped,
    // so it is a no-op on a box without /proc). More join as later slices arrive.
    spawn_background(&state);

    let base = build_router(state);

    let mut set = tokio::task::JoinSet::new();
    for listener in listeners {
        // Each listener serves the same routes but carries the guard stack its
        // profile selects: the public listener adds the fail-closed IP allowlist.
        let router = match listener.profile {
            GuardProfile::Vpn => base.clone(),
            GuardProfile::Public => base.clone().layer(axum::middleware::from_fn_with_state(
                allowlist.clone(),
                guard::public_ip_allowlist,
            )),
        };
        set.spawn(async move { serve_listener(listener, router).await });
    }
    // If any listener task ends (error or graceful shutdown), stop the process.
    while let Some(joined) = set.join_next().await {
        joined.context("listener task panicked")??;
    }
    Ok(())
}

/// Spawns the always-on background workers. Grows as feature slices move in; each
/// `spawn_*` runs forever and logs-and-continues on error, so a missing host
/// integration (no `/proc`, no Docker) never takes the server down.
fn spawn_background(state: &AppState) {
    metrics::spawn_collector(state.clone());
    metrics::spawn_pruner(state.clone());
    // The health monitor: a reconciler that runs one probe loop per enabled
    // target + an hourly sample pruner. No-op until a target exists.
    health::spawn_monitor(state.clone());
    // The Docker event watcher: streams daemon events onto the `docker` live
    // topic and invalidates the list caches on state changes. No-op when the
    // Docker socket isn't reachable.
    docker::spawn_event_watcher(state.clone());
    // The firewall lockout reaper: releases expired IP blocks every minute.
    firewall::spawn_workers(state.clone());
    // The secret scanner: periodic filesystem scan for leaked credentials.
    secrets::spawn_scheduler(state.clone());
    // The image-update checker: compares local Docker image digests against
    // the registry to detect available updates. No-op without Docker.
    updates::spawn_update_checker(state.clone());
    // The cron scheduler: runs operator scripts on their configured schedule.
    // No-op when no script carries a `schedule` field.
    cron::spawn_scheduler(state.clone());
    // The backup scheduler: takes a backup every backup.interval_hours and
    // prunes to backup.keep. No-op when interval_hours = 0.
    backup::spawn_scheduler(state.clone());
    // SSH token sweeper: marks expired tokens as revoked every hour.
    ssh::spawn_token_sweeper(state.clone());
    // SSH auth log watcher: tails sshd auth.log and updates last_used_at for
    // keys matching successful publickey auth events. No-op when
    // sshd_auth_log_path is not configured.
    ssh::spawn_auth_log_watcher(state.clone());
}

async fn serve_listener(listener: Listener, router: Router) -> anyhow::Result<()> {
    let tcp = tokio::net::TcpListener::bind(listener.addr)
        .await
        .with_context(|| format!("could not bind {} ({:?})", listener.addr, listener.profile))?;
    tracing::info!(
        "vantage listening on http://{} [{:?} profile]",
        listener.addr,
        listener.profile
    );
    // `into_make_service_with_connect_info` exposes the peer address as
    // `ConnectInfo<SocketAddr>` — the public guard's source of truth (direct bind,
    // no proxy, so it cannot be spoofed via a forwarded header).
    axum::serve(tcp, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    Ok(())
}

/// Returns (and creates) the path to the admin database, `<data>/vantage/admin.db`.
/// Overridable with `VANTAGE_CONFIG` (`:memory:` for an ephemeral database).
fn database_path() -> anyhow::Result<PathBuf> {
    if let Ok(explicit) = std::env::var("VANTAGE_CONFIG") {
        return Ok(PathBuf::from(explicit));
    }
    let mut path = dirs::data_dir().context("could not find a data directory for the current user")?;
    path.push("vantage");
    std::fs::create_dir_all(&path).context("could not create the vantage data directory")?;
    path.push("admin.db");
    Ok(path)
}

/// Builds application state against the admin's own on-disk `admin.db`.
async fn build_state(config: Config) -> anyhow::Result<AppState> {
    build_state_with(config, &database_path()?).await
}

/// Opens `admin.db` at `path`, applying the embedded migrations on every
/// connection via the shared runner. Split out so tests can drive a hermetic
/// `:memory:` database.
async fn build_state_with(config: Config, path: &Path) -> anyhow::Result<AppState> {
    // A small pool suits the admin's light, read-mostly workload. `:memory:` must
    // use a single connection — each in-memory connection is its own separate
    // database, so a multi-connection pool would split reads and writes across
    // different DBs (the rule the site's `AppState::for_tests` relies on).
    let connections = if path.to_str() == Some(":memory:") { 1 } else { 4 };
    let db = Database::file(path)
        .connections(connections)
        .with_init(migrations::migrate)
        .open()
        .await
        .context("could not open admin.db")?;
    let incorrect_password_hash = hash_password("incorrect-default-password")?;
    // Seam A: probe the host for a firewall backend once at startup. Skipped for
    // `:memory:` (the test posture) so unit tests never shell out to nft/ufw/
    // iptables — and a `Disabled` result collapses to `None` so every kernel-exec
    // path is naturally a no-op on a box without a packet filter.
    let firewall_backend = if path.to_str() == Some(":memory:") {
        None
    } else {
        let backend = firewall::Backend::detect(config.firewall_backend.as_deref().filter(|s| !s.is_empty())).await;
        (backend.kind != firewall::BackendKind::Disabled).then(|| Arc::new(backend))
    };
    // The live-update hub. 64 slots matches the monolith; a lagging WS consumer
    // gets a `_meta.lagged` notice and falls back to polling.
    let (live_tx, _) = broadcast::channel(64);

    // GeoIP database for the security dashboard (loads the mmdb file if configured).
    let geoip = geoip::GeoIp::open(config.geoip_path.as_deref());

    // requests.db read-only connection for security analytics. Skip `:memory:`
    // (test posture) and open with a read-only pragma on each connection.
    let requests = if let Some(req_path) = &config.requests_db_path {
        if req_path.to_str() != Some(":memory:") && req_path.exists() {
            // Open read-only via `with_init` setting PRAGMA query_only = ON.
            let req_path_owned = req_path.clone();
            match Database::file(&req_path_owned)
                .connections(2)
                .with_init(|conn| {
                    conn.execute_batch("PRAGMA query_only = ON;")?;
                    Ok(())
                })
                .open()
                .await
            {
                Ok(db) => {
                    tracing::info!(path = %req_path.display(), "opened requests.db read-only");
                    Some(Arc::new(db))
                }
                Err(e) => {
                    tracing::warn!(error = %e, path = %req_path.display(), "could not open requests.db; security analytics disabled");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    // Cloudflare analytics client for the security dashboard's CF panels.
    let cloudflare = match (&config.cloudflare.api_token, &config.cloudflare.zone_id) {
        (Some(token), Some(zone)) if !token.is_empty() && !zone.is_empty() => Some(Arc::new(
            cloudflare::Cloudflare::new(reqwest::Client::new(), token.clone(), zone.clone()),
        )),
        _ => None,
    };

    Ok(AppState {
        config: Arc::new(config),
        db: Arc::new(db),
        db_path: Arc::new(path.to_path_buf()),
        live_tx,
        client: reqwest::Client::new(),
        // Seam A: probe the Docker socket once at startup. `None` on a box
        // without Docker — every Docker-backed endpoint degrades gracefully.
        docker: docker::DockerClient::connect(),
        firewall_backend,
        geoip: Arc::new(geoip),
        requests,
        cloudflare,
        incorrect_password_hash: Arc::new(incorrect_password_hash),
    })
}

/// Builds the router. Split out so a test can assert it composes without route
/// conflicts (mirrors klappstuhl_me's `full_router_builds`).
fn build_router(state: AppState) -> Router {
    Router::new()
        .merge(dashboard::routes())
        .route("/login", get(login_page).post(login_submit))
        .route("/login/2fa", get(login_2fa_page).post(login_2fa_submit))
        .route("/logout", get(logout))
        .route("/health", get(health))
        // Admin feature slices (grow as each moves in — Phase 4 Steps C+).
        .merge(logs::routes())
        .merge(dbadmin::routes::routes())
        .merge(metrics::routes::routes())
        .merge(health::routes::routes())
        .merge(docker::routes::routes())
        .merge(firewall::routes::routes())
        .merge(secrets::routes::routes())
        .merge(sanitizer::routes::routes())
        .merge(certs::routes())
        .merge(backup::routes::routes())
        .merge(ssh::routes::routes())
        .merge(proxy::routes::routes())
        .merge(spotlight::routes())
        .merge(security::routes())
        // Admin API endpoints (token-scoped in the monolith; session-gated here).
        .route("/api/updates", get(api_updates))
        // The live-update WebSocket hub; slices publish into it as they arrive.
        .merge(ws::routes())
        .nest("/kls", kls_ui::routes())
        // Vantage's own assets (admin CSS/JS/img), shipped as a `static/` dir
        // next to the binary; the shared design system lives at /kls.
        .nest_service("/static", tower_http::services::ServeDir::new("static"))
        // Parse the Cookie header into a `Vec<Cookie>` extension the `Account`
        // extractor reads. Must wrap the routes (added last = outermost).
        .layer(axum::middleware::from_fn(parse_cookies))
        .with_state(state)
}

/// Middleware that parses the `Cookie` header into a `Vec<Cookie>` request
/// extension (what the [`session`] auth extractor reads). Ported from the site.
pub(crate) async fn parse_cookies(mut req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let cookies = req
        .headers()
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| Cookie::parse_encoded(cookie.trim().to_owned()).ok())
        .collect::<Vec<_>>();
    req.extensions_mut().insert(cookies);
    next.run(req).await
}

/// `GET /api/updates` — image-update status for every configured Docker service.
async fn api_updates(account: Account) -> Result<Json<Vec<updates::ImageUpdate>>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let mut updates: Vec<updates::ImageUpdate> = updates::image_updates_map().into_values().collect();
    updates.sort_by(|a, b| a.service.cmp(&b.service));
    Ok(Json(updates))
}

/// The login page. Redirects to `/` when already signed in.
async fn login_page(account: Option<Account>) -> Response {
    if account.is_some() {
        return Redirect::to("/").into_response();
    }
    render_login(None).into_response()
}

/// Renders the minimal login form (no inline JS, so a strict CSP holds later).
fn render_login(error: Option<&str>) -> Html<String> {
    let error_html = error
        .map(|e| format!("<p style=\"color:#d97757\">{}</p>", html_escape(e)))
        .unwrap_or_default();
    Html(format!(
        "<!doctype html><meta charset=utf-8><link rel=stylesheet href=/kls/base.css>\
         <title>Vantage — sign in</title>\
         <main style=\"max-width:22rem;margin:5rem auto;font-family:monospace\">\
         <h1>Vantage</h1>{error_html}\
         <form method=post action=/login>\
         <p><label>username<br><input name=username autocomplete=username autofocus></label></p>\
         <p><label>password<br><input name=password type=password autocomplete=current-password></label></p>\
         <p><button type=submit>Sign in</button></p>\
         </form></main>"
    ))
}

#[derive(serde::Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

/// A signed, short-lived vouch that the password step succeeded, carried in the
/// `2fa` cookie between the password form and the TOTP form so the password is
/// never re-submitted.
#[derive(serde::Serialize, serde::Deserialize)]
struct PendingTotp {
    account_id: i64,
    /// Unix-timestamp expiry (5 minutes out).
    exp: i64,
}

/// Handles a login POST: aggressive per-IP lockout, constant-time password check,
/// then either a 2FA challenge (TOTP accounts) or a completed session.
async fn login_submit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Form(credentials): Form<Credentials>,
) -> Response {
    let ip = peer.ip();
    if lockout::is_locked(ip) {
        return locked_response();
    }

    let username = credentials.username.trim();
    let account = session::account_by_name(&state.db, username).await;

    // Always verify a hash (the account's, or a throwaway) so timing does not
    // reveal whether the username exists.
    let hash = account
        .as_ref()
        .map(|a| a.password.as_str())
        .unwrap_or(state.incorrect_password_hash.as_str());
    if !verify_password(&credentials.password, hash) {
        lockout::register_failure(ip);
        return (
            StatusCode::UNAUTHORIZED,
            render_login(Some("Incorrect username or password.")),
        )
            .into_response();
    }

    let account = account.expect("password verified, so the account exists");
    if account.has_totp() {
        // Defer the session until the second factor is checked.
        let pending = PendingTotp {
            account_id: account.id,
            exp: OffsetDateTime::now_utc().unix_timestamp() + 300,
        };
        let Ok(signed) = state.config.secret_key.sign(&pending) else {
            return internal_error("could not start the 2FA challenge");
        };
        let cookie = challenge_cookie(state.config.twofa_cookie_name(), signed, state.config.secure_cookies());
        return with_cookie(Redirect::to("/login/2fa").into_response(), &cookie);
    }

    complete_login(&state, account.id, ip).await
}

/// The 2FA code page. Redirects to `/login` without a live pending challenge.
async fn login_2fa_page(
    State(state): State<AppState>,
    Extension(cookies): Extension<Vec<Cookie<'static>>>,
) -> Response {
    if valid_pending(&state, &cookies).is_none() {
        return Redirect::to("/login").into_response();
    }
    render_2fa(None).into_response()
}

#[derive(serde::Deserialize)]
struct TotpForm {
    code: String,
}

/// Verifies the TOTP code against the pending challenge and, on success, mints
/// the session and clears the challenge cookie.
async fn login_2fa_submit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Extension(cookies): Extension<Vec<Cookie<'static>>>,
    Form(form): Form<TotpForm>,
) -> Response {
    let ip = peer.ip();
    if lockout::is_locked(ip) {
        return locked_response();
    }
    let Some(pending) = valid_pending(&state, &cookies) else {
        return Redirect::to("/login").into_response();
    };
    let Some(account) = session::account_by_id(&state.db, pending.account_id).await else {
        return Redirect::to("/login").into_response();
    };

    let ok = account
        .totp_secret
        .as_deref()
        .and_then(|enc| totp::decrypt_secret(&state.config.secret_key, enc))
        .map(|secret| totp::verify(&secret, &form.code))
        .unwrap_or(false);
    if !ok {
        lockout::register_failure(ip);
        return (StatusCode::UNAUTHORIZED, render_2fa(Some("Invalid code."))).into_response();
    }

    // Success: complete the login, then also clear the challenge cookie.
    let response = complete_login(&state, account.id, ip).await;
    let clear = session::clear_cookie(state.config.twofa_cookie_name(), state.config.secure_cookies());
    with_cookie(response, &clear)
}

/// Verifies and decodes the pending-2FA challenge from the cookie jar, enforcing
/// the signature and the 5-minute expiry.
fn valid_pending(state: &AppState, cookies: &[Cookie<'static>]) -> Option<PendingTotp> {
    let name = state.config.twofa_cookie_name();
    let cookie = cookies.iter().find(|c| c.name() == name)?;
    let pending: PendingTotp = state.config.secret_key.verify(cookie.value())?;
    (OffsetDateTime::now_utc().unix_timestamp() <= pending.exp).then_some(pending)
}

/// Mints, persists and sets a session for `account_id`, clearing the IP's
/// failure counter.
async fn complete_login(state: &AppState, account_id: i64, ip: IpAddr) -> Response {
    let Ok(token) = Token::new(account_id) else {
        return internal_error("could not mint a session token");
    };
    if session::save_session(&state.db, &token, Some("Vantage web session".to_string()))
        .await
        .is_err()
    {
        return internal_error("could not persist the session");
    }
    lockout::clear(ip);
    let cookie = session::session_cookie(
        state.config.session_cookie_name(),
        token.signed(&state.config.secret_key),
        state.config.secure_cookies(),
    );
    with_cookie(Redirect::to("/").into_response(), &cookie)
}

/// The short-lived challenge cookie carrying the signed [`PendingTotp`].
fn challenge_cookie(name: &'static str, value: String, secure: bool) -> Cookie<'static> {
    let mut builder = Cookie::build((name, value))
        .path("/")
        .http_only(true)
        .same_site(cookie::SameSite::Strict)
        .max_age(cookie::time::Duration::minutes(5));
    if secure {
        builder = builder.secure(true);
    }
    builder.build()
}

fn locked_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        render_login(Some("Too many failed attempts — try again later.")),
    )
        .into_response()
}

/// Renders the minimal TOTP-code form (no inline JS, for a strict CSP later).
fn render_2fa(error: Option<&str>) -> Html<String> {
    let error_html = error
        .map(|e| format!("<p style=\"color:#d97757\">{}</p>", html_escape(e)))
        .unwrap_or_default();
    Html(format!(
        "<!doctype html><meta charset=utf-8><link rel=stylesheet href=/kls/base.css>\
         <title>Vantage — two-factor</title>\
         <main style=\"max-width:22rem;margin:5rem auto;font-family:monospace\">\
         <h1>Two-factor</h1>{error_html}\
         <form method=post action=/login/2fa>\
         <p><label>authenticator code<br>\
         <input name=code inputmode=numeric autocomplete=one-time-code autofocus></label></p>\
         <p><button type=submit>Verify</button></p>\
         </form></main>"
    ))
}

/// Signs the current session out: deletes the DB row and clears the cookie.
async fn logout(State(state): State<AppState>, Extension(cookies): Extension<Vec<Cookie<'static>>>) -> Response {
    let name = state.config.session_cookie_name();
    if let Some(cookie) = cookies.iter().find(|c| c.name() == name) {
        if let Some((session_id, _)) = cookie.value().split_once('.') {
            session::delete_session(&state.db, session_id).await;
        }
    }
    let clear = session::clear_cookie(name, state.config.secure_cookies());
    with_cookie(Redirect::to("/login").into_response(), &clear)
}

/// Appends a `Set-Cookie` header to a response (never replaces existing ones).
fn with_cookie(mut response: Response, cookie: &Cookie<'static>) -> Response {
    if let Ok(value) = HeaderValue::from_str(&cookie.to_string()) {
        response.headers_mut().append(SET_COOKIE, value);
    }
    response
}

fn internal_error(msg: &'static str) -> Response {
    tracing::error!("{msg}");
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response()
}

/// Minimal HTML-escaping for the few user-controlled strings rendered inline.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Liveness probe that also confirms the kernel database is serving queries.
async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db_ok = state.db.execute_batch("SELECT 1;").await.is_ok();
    Json(serde_json::json!({
        "status": "ok",
        "database": db_ok,
        "exposure": state.config.exposure.mode.as_str(),
    }))
}

/// Bootstraps the first host-admin account (or any additional one) interactively.
async fn bootstrap_admin(state: &AppState) -> anyhow::Result<()> {
    use std::io::Write;

    print!("username: ");
    std::io::stdout().flush().ok();
    let mut username = String::new();
    std::io::stdin()
        .read_line(&mut username)
        .context("could not read username")?;
    let username = username.trim().to_string();
    if username.is_empty() {
        anyhow::bail!("username must not be empty");
    }

    let password = rpassword::prompt_password("password: ").context("could not read password")?;
    let confirm = rpassword::prompt_password("confirm password: ").context("could not read password")?;
    if password != confirm {
        anyhow::bail!("passwords did not match");
    }
    if password.len() < 8 {
        anyhow::bail!("password must be at least 8 characters");
    }

    create_admin_account(&state.db, &username, &password).await?;
    tracing::info!("created host-admin account {username}");
    println!("created host-admin account {username}");
    Ok(())
}

/// Inserts an admin account (Argon2-hashed password, admin flag set). Fails if the
/// username is already taken. Split out so it can be exercised in tests.
async fn create_admin_account(db: &Database, username: &str, password: &str) -> anyhow::Result<()> {
    let hash = hash_password(password)?;
    let username = username.to_string();
    db.execute(
        "INSERT INTO account(name, password, flags) VALUES (?, ?, ?)",
        (username, hash, FLAG_ADMIN),
    )
    .await
    .context("could not insert admin account (is the username already taken?)")?;
    Ok(())
}

/// Hashes a plaintext password using Argon2 with a random salt (same construction
/// as the site's `crate::auth::hash_password`).
fn hash_password(password: &str) -> anyhow::Result<String> {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {e}"))?
        .to_string())
}

/// Verifies a plaintext password against an Argon2 PHC hash (constant-time within
/// Argon2's verifier). A malformed stored hash verifies as `false`.
fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// Waits for Ctrl-C so `axum::serve` can drain in-flight requests on shutdown.
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hermetic in-memory state for tests — never touches the real `admin.db`
    /// on disk or the operator's `config.json`.
    async fn test_state() -> AppState {
        build_state_with(Config::test_default(), Path::new(":memory:"))
            .await
            .expect("build state")
    }

    /// The router must compose without panicking (route/state conflicts).
    #[tokio::test]
    async fn router_builds() {
        let _ = build_router(test_state().await);
    }

    /// The database is live and its migrated account/session schema is present.
    #[tokio::test]
    async fn migrated_schema_is_live() {
        let state = test_state().await;
        assert!(state.db.execute_batch("SELECT id FROM account LIMIT 0;").await.is_ok());
    }

    /// Bootstrapping an admin stores an Argon2 hash with the admin flag set, and a
    /// duplicate username is refused by the UNIQUE index.
    #[tokio::test]
    async fn bootstrap_admin_sets_admin_flag_and_is_unique() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();

        let (password, flags): (String, i64) = state
            .db
            .get_row(
                "SELECT password, flags FROM account WHERE name = ?",
                ("root".to_string(),),
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .await
            .unwrap();
        assert!(password.starts_with("$argon2"), "password is not an Argon2 hash");
        assert_eq!(flags & FLAG_ADMIN, FLAG_ADMIN, "admin flag not set");

        assert!(
            create_admin_account(&state.db, "root", "another!").await.is_err(),
            "duplicate username must be refused"
        );
    }

    // --- End-to-end auth flow (driven through the real router) ---

    use axum::body::Body;
    use axum::http::{
        header::{CONTENT_TYPE, COOKIE},
        Request as HttpRequest, StatusCode,
    };
    use tower::ServiceExt; // oneshot

    fn get(uri: &str) -> HttpRequest<Body> {
        HttpRequest::builder().uri(uri).body(Body::empty()).unwrap()
    }

    /// A form POST carrying a `ConnectInfo` peer (the login handlers require it
    /// for the per-IP lockout; the router only injects it when served over TCP).
    fn form_post(uri: &str, body: &'static str) -> HttpRequest<Body> {
        form_post_from(uri, body, "203.0.113.7:5555")
    }

    fn form_post_from(uri: &str, body: &'static str, peer: &str) -> HttpRequest<Body> {
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri(uri)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        req
    }

    /// A GET carrying a session cookie (drives an authenticated request).
    fn get_with_cookie(uri: &str, cookie_pair: &str) -> HttpRequest<Body> {
        let mut req = get(uri);
        req.headers_mut()
            .insert(COOKIE, HeaderValue::from_str(cookie_pair).unwrap());
        req
    }

    /// Extracts the `name=value` head of the first `Set-Cookie` on a response.
    fn set_cookie_pair(res: &axum::response::Response) -> String {
        res.headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    /// The login gate: `/` redirects logged-out visitors; a good password sets a
    /// session cookie that then admits `/`; a bad password is rejected.
    #[tokio::test]
    async fn login_flow_gates_the_landing_page() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        // Unauthenticated `/` bounces to the login page.
        let res = app.clone().oneshot(get("/")).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get("location").unwrap(), "/login");

        // A bad password is refused (and sets no cookie).
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=wrong"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(res.headers().get(SET_COOKIE).is_none());

        // A good password mints a session cookie.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let cookie_pair = set_cookie_pair(&res);
        assert!(
            cookie_pair.starts_with("vantage_session="),
            "unexpected cookie: {cookie_pair}"
        );

        // Presenting that cookie admits `/`.
        let res = app.oneshot(get_with_cookie("/", &cookie_pair)).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// A TOTP-enabled account cannot log in with the password alone: it is
    /// bounced to the 2FA challenge, and only a valid code completes the session.
    #[tokio::test]
    async fn totp_account_requires_the_second_factor() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        // Enrol a TOTP secret directly (enrollment UI is a later step).
        let secret = b"an-admin-totp-secret";
        let enc = totp::encrypt_secret(&state.config.secret_key, secret).unwrap();
        state
            .db
            .execute(
                "UPDATE account SET totp_secret = ?, totp_enabled = 1 WHERE name = 'root'",
                (enc,),
            )
            .await
            .unwrap();
        let app = build_router(state.clone());

        // Password step → redirect to /login/2fa with a challenge cookie (NOT a session).
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get("location").unwrap(), "/login/2fa");
        let challenge = set_cookie_pair(&res);
        assert!(
            challenge.starts_with("vantage_2fa="),
            "expected a 2fa cookie: {challenge}"
        );

        // A wrong code is rejected.
        let mut req = form_post("/login/2fa", "code=000000");
        req.headers_mut()
            .insert(COOKIE, HeaderValue::from_str(&challenge).unwrap());
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // The correct current code completes the login (mints a session cookie).
        let code = totp::current_code(secret);
        let mut req = form_post("/login/2fa", Box::leak(format!("code={code}").into_boxed_str()));
        req.headers_mut()
            .insert(COOKIE, HeaderValue::from_str(&challenge).unwrap());
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get("location").unwrap(), "/");
        assert!(
            set_cookie_pair(&res).starts_with("vantage_session="),
            "2FA success must mint a session"
        );
    }

    /// After enough bad passwords from one IP, further attempts are throttled
    /// (429) even with the right password.
    #[tokio::test]
    async fn repeated_failures_lock_out_the_source_ip() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);
        let peer = "203.0.113.200:4444";

        for _ in 0..lockout::THRESHOLD {
            let res = app
                .clone()
                .oneshot(form_post_from("/login", "username=root&password=wrong", peer))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        }
        // Now even the correct password is throttled.
        let res = app
            .oneshot(form_post_from("/login", "username=root&password=hunter2!", peer))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// The moved logs slice is auth-gated and renders through the admin layout.
    #[tokio::test]
    async fn logs_page_is_gated_and_renders() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        // Logged-out → redirect to /login.
        let res = app.clone().oneshot(get("/logs/view")).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get("location").unwrap(), "/login");

        // Log in, then the page renders with the layout + page copy.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);
        let res = app
            .clone()
            .oneshot(get_with_cookie("/logs/view", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Vantage"), "layout chrome missing");
        assert!(html.contains("Tail and filter"), "logs page copy missing");

        // The JSON data endpoint answers (empty in a hermetic test — no log dir).
        let res = app.oneshot(get_with_cookie("/logs/data", &cookie_pair)).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// The database console is auth-gated, renders through the admin layout, and
    /// its safe-mode query endpoint runs a read against the live `admin.db`.
    ///
    /// Unlike the other tests this uses a temp *file* database, not `:memory:` —
    /// the console opens its own fresh connection to `db_path`, and every
    /// `:memory:` connection is a separate empty database, so it must share an
    /// on-disk file with the pool to see the migrated schema.
    #[tokio::test]
    async fn database_console_is_gated_and_queries() {
        let db_file = std::env::temp_dir().join(format!("vantage-console-test-{}.db", std::process::id()));
        std::fs::remove_file(&db_file).ok();
        let state = build_state_with(Config::test_default(), &db_file)
            .await
            .expect("build state");
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        // Logged-out → redirect to /login.
        let res = app.clone().oneshot(get("/database")).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get("location").unwrap(), "/login");

        // Log in, then the page renders with the layout + page copy.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);
        let res = app
            .clone()
            .oneshot(get_with_cookie("/database", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Browse and query"), "database page copy missing");

        // A safe-mode read against the migrated admin.db returns the account row.
        let mut req = form_post("/database/query", "sql=SELECT+name+FROM+account&danger_mode=false");
        req.headers_mut()
            .insert(COOKIE, HeaderValue::from_str(&cookie_pair).unwrap());
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("root"),
            "query result missing the row"
        );

        // Safe-mode refuses a write with 403 (the text prefilter).
        let mut req = form_post("/database/query", "sql=DELETE+FROM+account&danger_mode=false");
        req.headers_mut()
            .insert(COOKIE, HeaderValue::from_str(&cookie_pair).unwrap());
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        std::fs::remove_file(&db_file).ok();
    }

    /// The live WebSocket is auth-gated: an unauthenticated upgrade is bounced to
    /// `/login` by the `Account` extractor before the upgrade is attempted.
    #[tokio::test]
    async fn live_ws_requires_a_session() {
        let state = test_state().await;
        let app = build_router(state);
        let res = app.oneshot(get("/ws")).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get("location").unwrap(), "/login");
    }

    /// A published live event reaches a subscriber of the hub with its topic and
    /// payload intact (what each `/ws` connection consumes).
    #[tokio::test]
    async fn live_publish_reaches_subscribers() {
        let state = test_state().await;
        let mut rx = state.live_subscribe();
        state.live_publish("metrics", serde_json::json!({ "cpu": 42 }));
        let event = rx.recv().await.expect("event delivered");
        assert_eq!(event.topic, "metrics");
        assert_eq!(event.data["cpu"], 42);
    }

    /// The metrics JSON endpoints are auth-gated. (The authenticated `/current`
    /// path shells out to `docker stats`, a real host dependency, so it is
    /// exercised by the live smoke test rather than here — the storage layer's
    /// own `#[tokio::test]`s cover the DB reads hermetically.)
    #[tokio::test]
    async fn metrics_endpoints_require_a_session() {
        let state = test_state().await;
        let app = build_router(state);
        for path in ["/metrics/current", "/metrics/history"] {
            let res = app.clone().oneshot(get(path)).await.unwrap();
            assert_eq!(res.status(), StatusCode::SEE_OTHER, "{path} should gate");
            assert_eq!(res.headers().get("location").unwrap(), "/login");
        }
    }

    /// The metrics **page** is auth-gated and renders through the admin layout.
    /// (The page handler only builds a template — it never shells out to Docker
    /// or `/proc`, unlike `/current` — so it is safe to render in a unit test.)
    #[tokio::test]
    async fn metrics_page_is_gated_and_renders() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        // Logged-out → redirect to /login.
        let res = app.clone().oneshot(get("/metrics")).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get("location").unwrap(), "/login");

        // Log in, then the page renders with the layout + page chrome.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);
        let res = app.oneshot(get_with_cookie("/metrics", &cookie_pair)).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Vantage"), "layout chrome missing");
        assert!(html.contains("range-picker"), "metrics page body missing");
        assert!(html.contains("metrics.js"), "metrics script missing");
    }

    /// The health data endpoints gate to `/login`, and once authenticated a
    /// target can be created and read back through the JSON dashboard endpoint.
    /// (Creating + listing never probe the network — only `check_now` does, so
    /// it is left to the live smoke test, like the metrics `/current` path.)
    #[tokio::test]
    async fn health_endpoints_gate_and_crud_roundtrips() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        // Logged-out data endpoints bounce to /login.
        for path in ["/monitors/data", "/monitors/incidents"] {
            let res = app.clone().oneshot(get(path)).await.unwrap();
            assert_eq!(res.status(), StatusCode::SEE_OTHER, "{path} should gate");
            assert_eq!(res.headers().get("location").unwrap(), "/login");
        }

        // Log in.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);

        // Empty dashboard first.
        let res = app
            .clone()
            .oneshot(get_with_cookie("/monitors/data", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("\"total_targets\":0"));

        // Create a TCP target (no probe fired by the create handler).
        let mut req = form_post(
            "/monitors",
            "name=DB&kind=tcp&target=127.0.0.1%3A5432&interval_seconds=60",
        );
        req.headers_mut()
            .insert(COOKIE, HeaderValue::from_str(&cookie_pair).unwrap());
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // The dashboard now reports one target named "DB".
        let res = app
            .oneshot(get_with_cookie("/monitors/data", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json = String::from_utf8_lossy(&body);
        assert!(json.contains("\"total_targets\":1"), "target count wrong: {json}");
        assert!(json.contains("\"name\":\"DB\""), "target name missing: {json}");
    }

    /// The health admin page gates to `/login`, and the public `/status` page
    /// renders for a logged-out visitor (it takes `Option<Account>`).
    #[tokio::test]
    async fn health_admin_page_gates_and_status_page_is_public() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        // The admin page is gated.
        let res = app.clone().oneshot(get("/monitors")).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get("location").unwrap(), "/login");

        // The public status page renders WITHOUT auth (empty monitor list).
        let res = app.clone().oneshot(get("/status")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(
            html.contains("No public monitors are configured yet"),
            "status page body missing"
        );

        // Log in → the admin page renders with the layout + monitor chrome.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);
        let res = app.oneshot(get_with_cookie("/monitors", &cookie_pair)).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Vantage"), "layout chrome missing");
        assert!(html.contains("New monitor"), "health page body missing");
        assert!(html.contains("health.js"), "health script missing");
    }

    /// The Docker read endpoints gate to `/login`, and — with no Docker handle
    /// present — an authenticated request degrades to 503 rather than 500. This
    /// pins the Seam A handle's graceful-degradation contract. The handle is
    /// forced off so the test is hermetic on any host (a dev box running Docker
    /// Desktop would otherwise connect for real).
    #[tokio::test]
    async fn docker_read_endpoints_gate_and_degrade_without_socket() {
        let mut state = test_state().await;
        state.docker = None;
        assert!(state.docker().is_none(), "Docker handle should be forced off");
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        // Logged-out endpoints bounce to /login.
        for path in ["/docker/graph", "/docker/inspect/abc123"] {
            let res = app.clone().oneshot(get(path)).await.unwrap();
            assert_eq!(res.status(), StatusCode::SEE_OTHER, "{path} should gate");
            assert_eq!(res.headers().get("location").unwrap(), "/login");
        }

        // Log in.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);

        // Authenticated, but no Docker → 503 (graceful), never 500.
        for path in ["/docker/graph", "/docker/inspect/abc123"] {
            let res = app.clone().oneshot(get_with_cookie(path, &cookie_pair)).await.unwrap();
            assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE, "{path} should 503");
        }
    }

    /// The services dashboard gates every surface, renders the empty-state page
    /// once authenticated, serves an empty action log, and 404s an action on an
    /// unknown service — all without shelling out to Docker (empty `services`).
    #[tokio::test]
    async fn docker_dashboard_gates_and_serves() {
        let mut state = test_state().await;
        state.docker = None; // force the graceful "Docker not available" render path
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        // Logged-out: page, JSON, and the action POST all bounce to /login.
        for path in ["/docker", "/docker/services/data", "/docker/actions/log"] {
            let res = app.clone().oneshot(get(path)).await.unwrap();
            assert_eq!(res.status(), StatusCode::SEE_OTHER, "{path} should gate");
            assert_eq!(res.headers().get("location").unwrap(), "/login");
        }
        let res = app
            .clone()
            .oneshot(form_post("/docker/action", "name=whatever&action=start"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "action POST should gate");

        // Log in.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);

        // The page renders its empty state (no services configured → no shell-out).
        let res = app
            .clone()
            .oneshot(get_with_cookie("/docker", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("No services configured"), "empty-state copy missing");
        assert!(
            html.contains("Docker not available"),
            "unavailable graph notice missing"
        );
        assert!(html.contains("/static/js/services.js"), "services script not linked");

        // The in-memory action log starts empty.
        let res = app
            .clone()
            .oneshot(get_with_cookie("/docker/actions/log", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], br#"{"actions":[]}"#);

        // An action on an unknown service is a clean 404, not a shell-out or 500.
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/docker/action")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(COOKIE, cookie_pair.as_str())
            .body(Body::from("name=does-not-exist&action=start"))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "unknown service should 404");
    }

    /// The snapshots surface gates, renders its empty state, serves an empty JSON
    /// list from the real `docker_snapshot` table (proving `sql/3.sql` applied),
    /// 503s a create when Docker is absent, and 404s a delete of a missing row —
    /// all hermetic (`docker=None`, no snapshot rows).
    #[tokio::test]
    async fn docker_snapshots_gate_serve_and_degrade() {
        let mut state = test_state().await;
        state.docker = None;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        // Logged-out: page + JSON both bounce to /login.
        for path in ["/docker/snapshots", "/docker/snapshots/data"] {
            let res = app.clone().oneshot(get(path)).await.unwrap();
            assert_eq!(res.status(), StatusCode::SEE_OTHER, "{path} should gate");
            assert_eq!(res.headers().get("location").unwrap(), "/login");
        }

        // Log in.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);

        // The page renders its empty/unavailable state.
        let res = app
            .clone()
            .oneshot(get_with_cookie("/docker/snapshots", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Container Snapshots"), "page heading missing");
        assert!(html.contains("Docker not available"), "unavailable notice missing");

        // The list is empty and served from the migrated table (not a 500).
        let res = app
            .clone()
            .oneshot(get_with_cookie("/docker/snapshots/data", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], br#"{"snapshots":[]}"#);

        // Create with no Docker → 503 (graceful), never 500.
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/docker/snapshots")
            .header(CONTENT_TYPE, "application/json")
            .header(COOKIE, cookie_pair.as_str())
            .body(Body::from(
                r#"{"container_id":"abc","container_name":"c","image":"nginx"}"#,
            ))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "create should 503 with no socket"
        );

        // Delete of a non-existent snapshot is a clean 404.
        let req = HttpRequest::builder()
            .method("DELETE")
            .uri("/docker/snapshots/999")
            .header(COOKIE, cookie_pair.as_str())
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "missing snapshot should 404");
    }

    /// The secrets dashboard gates to `/login`, renders the page once
    /// authenticated, and the data endpoint returns an empty findings list from
    /// the real `secret_finding` table (proving `sql/5.sql` applied). Trigger
    /// with no paths configured returns `started: false`. Status updates work.
    #[tokio::test]
    async fn secrets_gates_serves_and_status_lifecycle() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state.clone());

        // Logged-out: page + data bounce to /login.
        for path in ["/secrets", "/secrets/data"] {
            let res = app.clone().oneshot(get(path)).await.unwrap();
            assert_eq!(res.status(), StatusCode::SEE_OTHER, "{path} should gate");
            assert_eq!(res.headers().get("location").unwrap(), "/login");
        }

        // Log in.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);

        // The page renders with the empty-state / scanner-disabled chrome.
        let res = app
            .clone()
            .oneshot(get_with_cookie("/secrets", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Secret scanner"), "heading missing");
        assert!(html.contains("/static/js/secrets.js"), "script not linked");

        // The data endpoint returns empty findings from the migrated tables.
        let res = app
            .clone()
            .oneshot(get_with_cookie("/secrets/data", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["counts"]["open"], 0);
        assert_eq!(json["findings"].as_array().unwrap().len(), 0);
        assert_eq!(json["scanner_enabled"], false);

        // Trigger with no paths → started: false.
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/secrets/scan")
            .header(COOKIE, cookie_pair.as_str())
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["started"], false);

        // Insert a finding directly and test the status update endpoint.
        state
            .db
            .execute(
                "INSERT INTO secret_finding(rule, severity, file_path, line, snippet, finding_hash)
                 VALUES ('Test Rule', 'high', '/test/file', 1, 'snip', 'testhash')",
                (),
            )
            .await
            .unwrap();
        let id: i64 = state
            .db
            .get_row(
                "SELECT id FROM secret_finding WHERE finding_hash = 'testhash'",
                (),
                |r| r.get(0),
            )
            .await
            .unwrap();

        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("/secrets/{id}/status"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(COOKIE, cookie_pair.as_str())
            .body(Body::from("status=dismissed"))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // Invalid status is 400.
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("/secrets/{id}/status"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(COOKIE, cookie_pair.as_str())
            .body(Body::from("status=bogus"))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    /// The firewall dashboard gates, renders the disabled-backend page, and runs
    /// the full rule + lockout lifecycle against the real tables — hermetic
    /// because `:memory:` skips backend detection (`firewall_backend = None`), so
    /// no handler ever shells out to nft/ufw/iptables.
    #[tokio::test]
    async fn firewall_gates_serves_and_rule_lifecycle() {
        let state = test_state().await;
        assert!(
            state.firewall_backend().is_none(),
            ":memory: must skip backend detection"
        );
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        // Logged-out: page, JSON, and a rule POST all bounce to /login.
        for path in ["/firewall", "/firewall/data"] {
            let res = app.clone().oneshot(get(path)).await.unwrap();
            assert_eq!(res.status(), StatusCode::SEE_OTHER, "{path} should gate");
        }
        let res = app
            .clone()
            .oneshot(form_post("/firewall/rule", "action=deny"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "rule POST should gate");

        // Log in.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);

        // Small helper: an authenticated form POST.
        let form_auth = |uri: &str, body: &'static str| {
            HttpRequest::builder()
                .method("POST")
                .uri(uri)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(COOKIE, cookie_pair.as_str())
                .body(Body::from(body))
                .unwrap()
        };

        // The page renders with the disabled-backend chrome.
        let res = app
            .clone()
            .oneshot(get_with_cookie("/firewall", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Firewall"), "heading missing");
        assert!(html.contains("disabled"), "backend label missing");
        assert!(html.contains("/static/js/firewall.js"), "script not linked");

        // Empty data with the disabled backend + auto-lockout policy numbers.
        let res = app
            .clone()
            .oneshot(get_with_cookie("/firewall/data", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["backend"], "disabled");
        assert_eq!(json["rules"].as_array().unwrap().len(), 0);
        assert_eq!(json["auto_threshold"], 8);

        // Create a rule → returns its id (no backend, so `apply` is null).
        let res = app
            .clone()
            .oneshot(form_auth("/firewall/rule", "action=deny&source=203.0.113.9&port=22"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let rule_id = created["id"].as_i64().expect("rule id");
        assert!(created["apply"].is_null(), "no backend → no apply output");

        // An invalid action is a clean 400.
        let res = app
            .clone()
            .oneshot(form_auth("/firewall/rule", "action=bogus"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // The rule now shows in the data feed.
        let res = app
            .clone()
            .oneshot(get_with_cookie("/firewall/data", &cookie_pair))
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["rules"].as_array().unwrap().len(), 1);

        // Toggle it off, block an IP, release it, delete the rule — all 2xx.
        let res = app
            .clone()
            .oneshot(form_auth(&format!("/firewall/rule/{rule_id}/toggle"), "enabled=false"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let res = app
            .clone()
            .oneshot(form_auth("/firewall/lockout", "ip=203.0.113.5&reason=test"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let lock: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let lock_id = lock["id"].as_i64().expect("lockout id");

        let res = app
            .clone()
            .oneshot(form_auth(&format!("/firewall/lockout/{lock_id}/release"), ""))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let req = HttpRequest::builder()
            .method("DELETE")
            .uri(format!("/firewall/rule/{rule_id}"))
            .header(COOKIE, cookie_pair.as_str())
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
    }

    /// The certs page gates to `/login` and, once authenticated, renders the
    /// layout with empty proxy-route and standalone-monitor tables.
    #[tokio::test]
    async fn certs_page_gates_and_renders_empty() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        // Logged-out → redirect to /login.
        let res = app.clone().oneshot(get("/certs")).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get("location").unwrap(), "/login");

        // Log in, then the page renders.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);
        let res = app.oneshot(get_with_cookie("/certs", &cookie_pair)).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Vantage"), "layout chrome missing");
        assert!(html.contains("Certs"), "page heading missing");
        assert!(
            html.contains("No proxy routes configured"),
            "empty-state proxy copy missing"
        );
        assert!(html.contains("No SSL monitors"), "empty-state monitor copy missing");
    }
}
