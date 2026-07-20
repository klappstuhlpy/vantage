//! Vantage — the standalone, security-first VPS/homelab control plane.
//!
//! Stood up in-tree as a workspace binary (ADMIN_SEPARATION_PLAN Phase 4) before
//! it graduates to its own repo (Phase 6). It links only the shared kernel —
//! [`kls_web_core`] (async SQLite + crypto + migrations) and [`kls_agent`] (the
//! typed privileged-host-op boundary) — with **no dependency on the
//! `klappstuhl_me` app crate**: its own DB, config, auth and release cadence
//! (locked decision 9, standalone-first). The frontend is likewise its own: the
//! `kls-ui` design system was dropped in the frontend rewrite, so `static/`
//! carries the whole UI with zero runtime egress.
//!
//! This is the skeleton. The admin **feature slices** (metrics, docker, firewall,
//! health, proxy, backup, ssh, secrets, …) move in one at a time in the following
//! Phase-4 steps while the monolith keeps serving them, so both stay green.
//!
//! Structure so far:
//! - [`config`] — `config.json`, including the fail-closed [`config::Exposure`]
//!   policy (§7.1) evaluated at startup,
//! - [`migrations`] — the embedded `db` schema, applied via the shared runner,
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
use askama::Template;
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

/// The running build's version, from `Cargo.toml`. The single source of truth —
/// the sidebar, the update checker, and the audit trail all read this rather
/// than carrying their own string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

mod account;
mod alerts;
mod audit;
mod backup;
mod cached;
mod certs;
mod cloudflare;
mod config;
mod cron;
mod dashboard;
mod dbadmin;
mod diffutil;
mod docker;
mod firewall;
mod geoip;
mod guard;
mod headers;
mod health;
mod lockout;
mod logs;
mod metrics;
mod migrations;
mod proxy;
mod revert;
mod safemode;
mod sanitizer;
mod secrets;
mod security;
mod session;
mod settings;
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
    /// Global safe mode (`safemode`): the live "freeze all host changes" flag.
    /// An atomic, not a DB read, because the safe-mode middleware consults it on
    /// every request; the `storage` row is its durable shadow, loaded once at
    /// startup and rewritten on toggle.
    pub(crate) safe_mode: Arc<std::sync::atomic::AtomicBool>,
    /// Runtime-adjustable operational settings (`settings`): the dashboard-editable
    /// overlay on `config.json`'s retention/cadence knobs. An in-memory snapshot,
    /// not a DB read, because background loops consult it every tick; the
    /// `storage` rows are its durable shadow, loaded once at startup and
    /// rewritten on save.
    pub(crate) settings: Arc<settings::Settings>,
    /// In-flight revert timers keyed by domain (`"firewall"`, `"proxy"`). An
    /// arming apply parks a rollback here; a background task fires it unless a
    /// confirm request removes it first (§11.1).
    pub(crate) reverts: revert::Registry,
    /// In-flight console queries, keyed by client-generated run_id. The cancel
    /// endpoint looks here, verifies ownership, and fires the handle (D12).
    pub(crate) run_registry: dbadmin::cancel::RunRegistry,
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

    /// Fans an alert out to every configured, enabled sink. The payload uses the
    /// Discord webhook JSON shape; a neutral notification is derived for
    /// non-Discord sinks.
    ///
    /// Fire-and-forget, as every call site expects — an alert must never be able
    /// to slow down or fail the thing it is reporting on. The outcome is not
    /// discarded any more, though: [`AppState::deliver_alert`] writes each
    /// attempt to the delivery log, which is the only reason the Alerts page can
    /// answer "did it actually go out?".
    pub(crate) fn send_alert(&self, value: serde_json::Value) {
        let state = self.clone();
        tokio::spawn(async move {
            state.deliver_alert(&value, None, false).await;
        });
    }

    /// Delivers to every configured sink and records each attempt.
    ///
    /// `only` restricts delivery to a single sink and **bypasses its enabled
    /// toggle** — that is the Test button, where you have explicitly pointed at
    /// one sink and want to know whether its configuration works, which is a
    /// different question from whether it is currently switched on.
    ///
    /// Returns one entry per sink attempted, so the test route can report the
    /// reason rather than a bare failure.
    pub(crate) async fn deliver_alert(
        &self,
        value: &serde_json::Value,
        only: Option<&str>,
        test: bool,
    ) -> Vec<(&'static str, Result<(), String>)> {
        let cfg = &self.config.alerts;
        let note = alerts::AlertNotification::from_discord_value(value);

        // Resolved up front so the sends below can run concurrently: a sink that
        // is slow (SMTP against a distant relay) must not hold up one that isn't.
        let mut wanted = Vec::new();
        for sink in alerts::SINKS {
            let configured = match sink {
                "discord" => cfg.discord_webhook_url.is_some(),
                "ntfy" => cfg.ntfy_url.is_some(),
                "webhook" => cfg.webhook_url.is_some(),
                "email" => cfg.email.is_some(),
                _ => false,
            };
            let want = match only {
                Some(target) => target == sink,
                None => alerts::sink_enabled(&self.db, sink).await,
            };
            if configured && want {
                wanted.push(sink);
            }
        }

        let outcomes =
            futures_util::future::join_all(wanted.into_iter().map(|sink| attempt_sink(self, &note, value, sink))).await;

        for (sink, result) in &outcomes {
            if let Err(reason) = result {
                tracing::warn!(sink, error = %reason, "alert delivery failed");
            }
            alerts::record_delivery(&self.db, sink, &note, result, test).await;
        }
        outcomes
    }
}

/// Hands one alert to one sink.
///
/// A free function rather than a closure inside [`AppState::deliver_alert`]
/// because `join_all` needs one future type: an `async` closure would produce a
/// distinct opaque type per call site *and* would have to move `note` into the
/// first future it built, leaving nothing for the second.
async fn attempt_sink(
    state: &AppState,
    note: &alerts::AlertNotification,
    value: &serde_json::Value,
    sink: &'static str,
) -> (&'static str, Result<(), String>) {
    let cfg = &state.config.alerts;
    // Every arm is reached only for a sink `deliver_alert` already confirmed is
    // configured, so the `unwrap_or_default` fallbacks are unreachable rather
    // than lenient — an empty URL would fail the send and be logged as such.
    let result = match sink {
        "discord" => {
            alerts::send_discord(
                &state.client,
                cfg.discord_webhook_url.as_deref().unwrap_or_default(),
                value,
            )
            .await
        }
        "ntfy" => alerts::send_ntfy(&state.client, cfg.ntfy_url.as_deref().unwrap_or_default(), note).await,
        "webhook" => alerts::send_webhook(&state.client, cfg.webhook_url.as_deref().unwrap_or_default(), note).await,
        "email" => match &cfg.email {
            Some(email) => alerts::send_email(email, note).await.map_err(|e| e.to_string()),
            None => Err("no email sink configured".to_string()),
        },
        _ => Err("unknown sink".to_string()),
    };
    (sink, result)
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
    // Audit pruner: drops entries past the retention window (and enforces the
    // hard row cap) every six hours.
    audit::spawn_pruner(state.clone());
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

    // Global safe mode: start the live atomic where the operator last left it.
    let safe_mode = Arc::new(std::sync::atomic::AtomicBool::new(safemode::load_initial(&db).await));

    // Runtime settings overlay: start the in-memory snapshot from the durable
    // overrides, so a dashboard-adjusted retention/cadence survives a restart.
    let settings = Arc::new(settings::Settings::load_initial(&db).await);

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
        safe_mode,
        settings,
        reverts: revert::Registry::new(),
        run_registry: dbadmin::cancel::RunRegistry::new(),
    })
}

/// Builds the router. Split out so a test can assert it composes without route
/// conflicts (mirrors klappstuhl_me's `full_router_builds`).
fn build_router(state: AppState) -> Router {
    let report_only = state.config.csp_report_only;
    Router::new()
        .merge(dashboard::routes())
        .route("/login", get(login_page).post(login_submit))
        .route("/login/2fa", get(login_2fa_page).post(login_2fa_submit))
        .route("/logout", get(logout))
        .route("/health", get(health))
        .merge(account::routes::routes())
        .merge(alerts::routes::routes())
        .merge(audit::routes::routes())
        .merge(cron::routes::routes())
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
        .merge(safemode::routes())
        .merge(settings::routes())
        // Admin API endpoints (token-scoped in the monolith; session-gated here).
        .route("/api/updates", get(api_updates))
        // The live-update WebSocket hub; slices publish into it as they arrive.
        .merge(ws::routes())
        // Vantage's own frontend: design system, page CSS/JS, vendored fonts,
        // icon sprite and chart libs. Shipped as a `static/` dir next to the
        // binary. Vantage owns its design system outright — nothing is fetched
        // from a CDN or a shared crate at runtime, so a VPN-only box with no
        // egress renders identically to one with internet access.
        .nest_service("/static", tower_http::services::ServeDir::new("static"))
        // Cache-Control: a short private window on the data endpoints the
        // frontend polls, and a longer public one on `/static` — which had no
        // caching at all, so a hard refresh re-fetched the whole 1.5 MB asset
        // tree. See `headers::cache_control`.
        .layer(axum::middleware::from_fn(headers::cache_control))
        // Compression. The two vendored bundles (`codemirror` 430 KB,
        // `cytoscape` 372 KB) go out at roughly a quarter of the bytes, and the
        // JSON endpoints benefit too. `CompressionLayer::new()` keeps
        // tower-http's default predicate, which already declines to compress
        // Server-Sent Events — the container-log stream must not be buffered.
        .layer(tower_http::compression::CompressionLayer::new())
        // Global safe mode: refuse destructive host mutations while engaged, on
        // the outermost layer so a frozen box turns them away before any handler
        // (or the DB) sees them. Reads the atomic only — no per-request DB hit.
        .layer(axum::middleware::from_fn_with_state(
            state.safe_mode.clone(),
            safemode::guard,
        ))
        // Parse the Cookie header into a `Vec<Cookie>` extension the `Account`
        // extractor reads. Must wrap the routes (added last = outermost).
        .layer(axum::middleware::from_fn(parse_cookies))
        // Security headers (CSP et al) on the very outside, so they also reach
        // static assets and the responses produced by the middleware *below*
        // this line — safe mode's 423 and the public guard's 403 are exactly the
        // responses a per-handler approach forgets.
        .layer(axum::middleware::from_fn(move |req, next| {
            headers::security_headers(report_only, req, next)
        }))
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

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "login_2fa.html")]
struct Login2faTemplate {
    error: Option<String>,
}

/// Renders the login form.
///
/// This was a `format!` of a hand-written HTML string that linked
/// `/kls/base.css` — a stylesheet that no longer exists, so the page had been
/// rendering unstyled. It also hand-escaped its own error message, which is a
/// bug waiting to happen every time someone adds a second interpolation.
/// Askama escapes `{{ }}` for us and the template is checked at compile time.
fn render_login(error: Option<&str>) -> Html<String> {
    Html(
        LoginTemplate {
            error: error.map(str::to_owned),
        }
        .render()
        .unwrap_or_else(|e| {
            // A template that fails to render is a bug, not a runtime
            // condition — but the login page is the one door into the app, so
            // it degrades to something usable rather than a 500.
            tracing::error!(error = %e, "login template failed to render");
            "<!doctype html><title>Vantage</title><h1>Vantage</h1>\
             <form method=post action=/login>\
             <p><label>username <input name=username></label></p>\
             <p><label>password <input name=password type=password></label></p>\
             <button type=submit>Sign in</button></form>"
                .to_owned()
        }),
    )
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
    headers: axum::http::HeaderMap,
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
        // The row an audit log exists for. `actor` is the username that was
        // *typed*, which may name no account at all — that is the fact worth
        // keeping, and it is why this is recorded here rather than after the
        // constant-time check resolves it into an identity.
        //
        // Truncated because this is the one audit call on an unauthenticated
        // path: the typed username is a stranger's input, and a table row is not
        // the place to find out how long they made it. The write rate is bounded
        // by the per-IP lockout above (five tries, then this line is never
        // reached), and by the log's own row cap.
        let typed: String = username.chars().take(64).collect();
        audit::system_event("account.login.failed", &typed)
            .ip(ip)
            .failed()
            .record(&state.db)
            .await;
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

    complete_login(&state, account.id, ip, &headers).await
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
    headers: axum::http::HeaderMap,
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
    // A recovery code is accepted in the same field. Recovery codes exist for
    // exactly this moment — the authenticator is lost, wiped or on a phone in
    // another country — so demanding a separate form to use one would mean the
    // codes only work when you least need them. They are 10 characters and a TOTP
    // code is 6 digits, so there is no ambiguity about which was typed, and
    // redemption is single-use.
    let ok = ok || account::redeem_recovery_code(&state.db, account.id, &form.code).await;
    if !ok {
        lockout::register_failure(ip);
        // Distinct from `account.login.failed`: this one got the password right.
        // Someone holding valid credentials and failing only the second factor is
        // the single most interesting row this log can contain.
        audit::system_event("account.login.2fa_failed", &account.name)
            .ip(ip)
            .failed()
            .record(&state.db)
            .await;
        return (StatusCode::UNAUTHORIZED, render_2fa(Some("Invalid code."))).into_response();
    }

    // Success: complete the login, then also clear the challenge cookie.
    let response = complete_login(&state, account.id, ip, &headers).await;
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
async fn complete_login(state: &AppState, account_id: i64, ip: IpAddr, headers: &axum::http::HeaderMap) -> Response {
    let Ok(token) = Token::new(account_id) else {
        return internal_error("could not mint a session token");
    };
    if session::save_session(&state.db, &token, Some("Vantage web session".to_string()))
        .await
        .is_err()
    {
        return internal_error("could not persist the session");
    }
    // Where this session came from, for the account page's session list. Written
    // after the row exists and best-effort by design: a login must not fail
    // because a User-Agent header was strange.
    account::stamp_provenance(
        &state.db,
        &token.base64(),
        Some(ip.to_string()),
        account::routes::user_agent_of(headers),
    )
    .await;
    lockout::clear(ip);
    // A `system_event` rather than `audit::event`: there is no extracted
    // `Account` here — the session this login is creating is the first one — so
    // the address is passed explicitly instead of riding along on one.
    let name = session::account_by_id(&state.db, account_id)
        .await
        .map(|a| a.name)
        .unwrap_or_else(|| format!("account:{account_id}"));
    audit::system_event("account.login", &name)
        .ip(ip)
        .detail(serde_json::json!({ "user_agent": account::routes::user_agent_of(headers) }))
        .record(&state.db)
        .await;
    alert_on_login(state, account_id, ip, headers).await;
    let cookie = session::session_cookie(
        state.config.session_cookie_name(),
        token.signed(&state.config.secret_key),
        state.config.secure_cookies(),
    );
    with_cookie(Redirect::to("/").into_response(), &cookie)
}

/// Raises an alert for a successful sign-in, when the operator has asked for one.
///
/// Off by default (see `alerts::alert_on_admin_login`) — on a homelab you sign in
/// daily, and an alarm that fires on every ordinary action is one you train
/// yourself to ignore, which is worse than not having it. The operators who want
/// it are the ones who sign in twice a month and would like to know about the
/// third time.
async fn alert_on_login(state: &AppState, account_id: i64, ip: IpAddr, headers: &axum::http::HeaderMap) {
    if !state.has_any_alert_sink() || !alerts::alert_on_admin_login(&state.db).await {
        return;
    }
    let name = session::account_by_id(&state.db, account_id)
        .await
        .map(|a| a.name)
        .unwrap_or_else(|| "unknown".to_string());
    let agent = account::routes::user_agent_of(headers).unwrap_or_else(|| "unknown device".to_string());

    state.send_alert(serde_json::json!({
        "username": "Vantage",
        "embeds": [{
            "title": "Sign-in to Vantage",
            "description": format!("**{name}** signed in from `{ip}`."),
            "color": 0x3b82f6,
            "fields": [
                { "name": "Address", "value": ip.to_string(), "inline": true },
                { "name": "Device", "value": agent, "inline": false },
            ]
        }]
    }));
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

/// Renders the TOTP-code form. See [`render_login`] on why this is a template.
fn render_2fa(error: Option<&str>) -> Html<String> {
    Html(
        Login2faTemplate {
            error: error.map(str::to_owned),
        }
        .render()
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "2FA template failed to render");
            "<!doctype html><title>Vantage</title><h1>Two-factor</h1>\
             <form method=post action=/login/2fa>\
             <p><label>code <input name=code inputmode=numeric></label></p>\
             <button type=submit>Verify</button></form>"
                .to_owned()
        }),
    )
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
    // The same policy the account page enforces — one rule, in one place. This
    // used to be its own `< 8` check, so the CLI would happily bootstrap a
    // password the web UI would then refuse to let you change it to.
    if let Err(message) = account::validate_password(&password) {
        anyhow::bail!("{message}");
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
pub(crate) fn hash_password(password: &str) -> anyhow::Result<String> {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {e}"))?
        .to_string())
}

/// Verifies a plaintext password against an Argon2 PHC hash (constant-time within
/// Argon2's verifier). A malformed stored hash verifies as `false`.
pub(crate) fn verify_password(password: &str, hash: &str) -> bool {
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

    #[test]
    fn version_is_the_crate_version() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected a semver triple, got {VERSION}");
    }

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
    fn form_post(uri: &str, body: impl Into<Body>) -> HttpRequest<Body> {
        form_post_from(uri, body, "203.0.113.7:5555")
    }

    fn form_post_from(uri: &str, body: impl Into<Body>, peer: &str) -> HttpRequest<Body> {
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri(uri)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.into())
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

        // The sidebar reads `crate::VERSION` directly rather than taking it from
        // each page's context struct. That resolves at compile time, so a typo
        // would be a build error — but a *silently empty* render would not be,
        // and the version is what an operator quotes in a bug report.
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(
            html.contains(&format!("v{VERSION}")),
            "the sidebar did not render the version"
        );
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
        let res = app
            .clone()
            .oneshot(form_post_with_cookie("/login/2fa", "code=000000", &challenge))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // The correct current code completes the login (mints a session cookie).
        let code = totp::current_code(secret);
        let res = app
            .oneshot(form_post_with_cookie("/login/2fa", format!("code={code}"), &challenge))
            .await
            .unwrap();
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
        let app = build_router(state.clone());

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
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // The schema explorer sees the migrated schema over the same session…
        let res = app
            .clone()
            .oneshot(get_with_cookie("/database/schema?source=sqlite:admin", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let schema = json_body(res).await;
        let names: Vec<&str> = schema["tables"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"account"), "got: {names:?}");

        // …and a table detail resolves columns + PK.
        let res = app
            .clone()
            .oneshot(get_with_cookie(
                "/database/table?source=sqlite:admin&table=account",
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let detail = json_body(res).await;
        assert!(detail["columns"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "id" && c["pk_ordinal"] == 1));

        // Introspection is audited once per source per session, not per click:
        // two introspection calls above, one row.
        let entries = audit::entries(
            &state.db,
            audit::Filter {
                limit: 50,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let reads = entries.iter().filter(|e| e.action == "database.schema.read").count();
        assert_eq!(reads, 1, "expected exactly one schema-read audit row");

        std::fs::remove_file(&db_file).ok();
    }

    /// The P2 table browser over HTTP: rows page with validated filters, an
    /// unknown filter column is refused by name, and an export streams CSV and
    /// lands in the audit log with the row count that actually left.
    #[tokio::test]
    async fn the_table_browser_pages_filters_and_exports() {
        let db_file = std::env::temp_dir().join(format!("vantage-browse-test-{}.db", std::process::id()));
        std::fs::remove_file(&db_file).ok();
        let state = build_state_with(Config::test_default(), &db_file)
            .await
            .expect("build state");
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state.clone());
        let cookie_pair = login_as_root(&app).await;

        // A page of the account table contains the admin we just created.
        let res = app
            .clone()
            .oneshot(get_with_cookie(
                "/database/rows?source=sqlite:admin&table=account",
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let page = json_body(res).await;
        assert_eq!(page["offset"], 0);
        assert!(page["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_array().unwrap().iter().any(|c| c == "root")));

        // A validated filter narrows it: name = "root" (URL-encoded JSON).
        let filters = "%5B%7B%22column%22%3A%22name%22%2C%22op%22%3A%22%3D%22%2C%22value%22%3A%22root%22%7D%5D";
        let res = app
            .clone()
            .oneshot(get_with_cookie(
                &format!("/database/rows?source=sqlite:admin&table=account&filters={filters}"),
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let page = json_body(res).await;
        assert_eq!(page["rows"].as_array().unwrap().len(), 1);

        // The count honours the same filters.
        let res = app
            .clone()
            .oneshot(get_with_cookie(
                &format!("/database/count?source=sqlite:admin&table=account&filters={filters}"),
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(json_body(res).await["count"], 1);

        // An unknown filter column is a 400 naming the column — never a
        // silently dropped clause (D5).
        let bad = "%5B%7B%22column%22%3A%22nope%22%2C%22op%22%3A%22%3D%22%2C%22value%22%3A%221%22%7D%5D";
        let res = app
            .clone()
            .oneshot(get_with_cookie(
                &format!("/database/rows?source=sqlite:admin&table=account&filters={bad}"),
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let err = json_body(res).await;
        assert!(err["error"].as_str().unwrap().contains("nope"), "got: {err}");

        // The export streams CSV with the attachment headers…
        let res = app
            .clone()
            .oneshot(get_with_cookie(
                "/database/export?source=sqlite:admin&table=account",
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get("content-type").unwrap(), "text/csv; charset=utf-8");
        assert!(res
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("account.csv"));
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let csv = String::from_utf8_lossy(&body);
        assert!(csv.lines().count() >= 2, "header + at least one row, got: {csv}");
        assert!(csv.contains("root"));

        // …and is audited with the row count, recorded by the streaming task
        // once the body has fully left (hence the short poll).
        let mut audited = false;
        for _ in 0..40 {
            let entries = audit::entries(
                &state.db,
                audit::Filter {
                    limit: 50,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            if let Some(e) = entries.iter().find(|e| e.action == "database.export") {
                assert_eq!(e.target.as_deref(), Some("sqlite:admin"));
                assert_eq!(e.detail["table"], "main.account");
                assert_eq!(e.detail["rows"], 1);
                assert!(e.ok);
                audited = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(audited, "the export must land in the audit log");

        std::fs::remove_file(&db_file).ok();
    }

    /// Staged edits (DB Studio P5/D15) end to end against a real SQLite file:
    /// the gates refuse before anything is written, preview never writes, an
    /// applied batch actually changes the row, and a stale primary key rolls the
    /// whole batch back rather than half-applying it.
    #[tokio::test]
    async fn staged_edits_are_gated_previewable_transactional_and_audited() {
        let db_file = std::env::temp_dir().join(format!("vantage-edit-test-{}.db", std::process::id()));
        std::fs::remove_file(&db_file).ok();
        let state = build_state_with(Config::test_default(), &db_file)
            .await
            .expect("build state");
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state.clone());
        let cookie_pair = login_as_root(&app).await;
        let peer = "203.0.113.77:5555";

        let account_id: i64 = state
            .db
            .get_row("SELECT id FROM account WHERE name = ?", ("root".to_string(),), |r| {
                r.get(0)
            })
            .await
            .unwrap();

        let batch = |changes: &str, danger: bool| {
            format!(r#"{{"source":"sqlite:admin","table":"account","danger_mode":{danger},"changes":{changes}}}"#)
        };
        let rename = format!(r#"[{{"kind":"update","pk":{{"id":"{account_id}"}},"set":{{"name":"renamed"}}}}]"#);

        // ── Gate 1: without danger mode, refused outright.
        let res = app
            .clone()
            .oneshot(json_post_with_cookie(
                "/database/apply",
                batch(&rename, false),
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // ── Gate 2: with danger mode but a stale session, the reauth marker.
        let res = app
            .clone()
            .oneshot(json_post_with_cookie(
                "/database/apply",
                batch(&rename, true),
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(res).await["reauth_required"], true);

        // Nothing has been written by either refusal.
        let name: String = state
            .db
            .get_row("SELECT name FROM account WHERE id = ?", (account_id,), |r| r.get(0))
            .await
            .unwrap();
        assert_eq!(name, "root", "a refused batch must not write");

        // ── Preview needs no sudo and writes nothing, but shows the statement
        // with its values inlined for reading.
        let res = app
            .clone()
            .oneshot(json_post_with_cookie(
                "/database/preview",
                batch(&rename, false),
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let plan = json_body(res).await;
        let preview = plan["statements"][0]["preview"].as_str().unwrap().to_string();
        assert!(preview.starts_with("UPDATE"), "got: {preview}");
        assert!(
            preview.contains("'renamed'"),
            "values are inlined for reading: {preview}"
        );
        // The parameterised SQL is what runs, and it carries no value.
        assert!(!plan["statements"][0]["sql"].as_str().unwrap().contains("renamed"));

        let name: String = state
            .db
            .get_row("SELECT name FROM account WHERE id = ?", (account_id,), |r| r.get(0))
            .await
            .unwrap();
        assert_eq!(name, "root", "preview must not write");

        // ── Reauth opens the sudo window; the batch then applies for real.
        let res = app
            .clone()
            .oneshot(json_post_from(
                "/account/reauth",
                r#"{"password":"hunter2!"}"#,
                &cookie_pair,
                peer,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let res = app
            .clone()
            .oneshot(json_post_with_cookie(
                "/database/apply",
                batch(&rename, true),
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let report = json_body(res).await;
        assert_eq!(report["applied"], 1);
        assert_eq!(report["statements"][0]["affected"], 1);

        let name: String = state
            .db
            .get_row("SELECT name FROM account WHERE id = ?", (account_id,), |r| r.get(0))
            .await
            .unwrap();
        assert_eq!(name, "renamed", "the applied batch must actually write");

        // ── A batch whose second statement addresses a row that does not exist
        // must roll the *first* one back too. This is the whole point of D15.
        let mixed = format!(
            r#"[{{"kind":"update","pk":{{"id":"{account_id}"}},"set":{{"name":"first"}}}},
                {{"kind":"update","pk":{{"id":"999999"}},"set":{{"name":"ghost"}}}}]"#
        );
        let res = app
            .clone()
            .oneshot(json_post_with_cookie(
                "/database/apply",
                batch(&mixed, true),
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let err = json_body(res).await["error"].as_str().unwrap().to_string();
        assert!(err.contains("affected 0 rows"), "got: {err}");
        assert!(err.contains("rolled back"), "got: {err}");

        let name: String = state
            .db
            .get_row("SELECT name FROM account WHERE id = ?", (account_id,), |r| r.get(0))
            .await
            .unwrap();
        assert_eq!(name, "renamed", "the good statement in a failed batch must not survive");

        // ── A refusal the validator raises is audited as a blocked attempt, and
        // the successful apply is on the record with its statements.
        let applied: i64 = state
            .db
            .get_row(
                "SELECT COUNT(*) FROM audit_log WHERE action = ? AND ok = 1",
                ("database.edit.apply".to_string(),),
                |r| r.get(0),
            )
            .await
            .unwrap();
        assert_eq!(applied, 1, "the successful apply is on the record");

        let rolled_back: i64 = state
            .db
            .get_row(
                "SELECT COUNT(*) FROM audit_log WHERE action = ? AND ok = 0",
                ("database.edit.apply".to_string(),),
                |r| r.get(0),
            )
            .await
            .unwrap();
        assert_eq!(rolled_back, 1, "so is the batch that rolled back");

        std::fs::remove_file(&db_file).ok();
    }

    /// Danger mode is sudo-gated (DB Studio D3): being a signed-in admin is not
    /// enough to drop the read-only guard. The refusal is the machine-readable
    /// reauth marker — before the SQL is even looked at — and a fresh reauth
    /// opens the window. Safe-mode reads never need it.
    #[tokio::test]
    async fn danger_mode_queries_demand_a_fresh_reauth() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);
        let cookie_pair = login_as_root(&app).await;
        let peer = "203.0.113.61:5555";

        // Signed in, but not recently re-authenticated.
        let mut req = form_post("/database/query", "sql=SELECT+1&danger_mode=true");
        req.headers_mut()
            .insert(COOKIE, HeaderValue::from_str(&cookie_pair).unwrap());
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let json = json_body(res).await;
        assert_eq!(json["reauth_required"], true, "the reauth marker is the API contract");

        // A safe-mode read from the same stale session is untouched.
        let mut req = form_post("/database/query", "sql=SELECT+1&danger_mode=false");
        req.headers_mut()
            .insert(COOKIE, HeaderValue::from_str(&cookie_pair).unwrap());
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Reauth, and the danger query runs.
        let res = app
            .clone()
            .oneshot(json_post_from(
                "/account/reauth",
                r#"{"password":"hunter2!"}"#,
                &cookie_pair,
                peer,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let mut req = form_post("/database/query", "sql=SELECT+1&danger_mode=true");
        req.headers_mut()
            .insert(COOKIE, HeaderValue::from_str(&cookie_pair).unwrap());
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// Safe mode, engaged, turns a destructive host mutation away with 423 at the
    /// middleware — before the handler (or the DB) is reached — while a read of the
    /// same slice still answers. The gate is off by default, so every other test in
    /// the suite is unaffected.
    #[tokio::test]
    async fn safe_mode_freezes_destructive_requests_but_not_reads() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        // Engage safe mode directly on the live atomic (the toggle route is sudo-
        // gated; this test is about the gate, not the toggle).
        state.safe_mode.store(true, std::sync::atomic::Ordering::Relaxed);
        let app = build_router(state);

        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);

        // A destructive POST is refused with 423 Locked and the machine-readable
        // marker the frontend keys off.
        let mut req = form_post("/firewall/apply", "");
        req.headers_mut()
            .insert(COOKIE, HeaderValue::from_str(&cookie_pair).unwrap());
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::LOCKED);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("safe_mode"),
            "missing the marker"
        );

        // A read of the same slice is untouched — safe mode stops changes, not sight.
        let res = app
            .oneshot(get_with_cookie("/firewall/data", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// Confirming (or reverting) an armed apply stays reachable even with safe
    /// mode engaged — the §11.1 exemption that keeps an operator from being
    /// stranded mid-flow. An unknown token simply reports nothing was kept.
    #[tokio::test]
    async fn confirming_an_apply_is_reachable_under_safe_mode() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        state.safe_mode.store(true, std::sync::atomic::Ordering::Relaxed);
        let app = build_router(state);

        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let cookie_pair = set_cookie_pair(&res);

        // The arming apply itself is frozen…
        let mut apply = form_post("/firewall/apply", "");
        apply
            .headers_mut()
            .insert(COOKIE, HeaderValue::from_str(&cookie_pair).unwrap());
        assert_eq!(app.clone().oneshot(apply).await.unwrap().status(), StatusCode::LOCKED);

        // …but confirming an armed apply is not — it must always be able to complete.
        let mut confirm = HttpRequest::builder()
            .method("POST")
            .uri("/firewall/apply/confirm")
            .header(CONTENT_TYPE, "application/json")
            .header(COOKIE, &cookie_pair)
            .body(Body::from(r#"{"token":"nonexistent"}"#))
            .unwrap();
        confirm
            .extensions_mut()
            .insert(ConnectInfo("203.0.113.7:5555".parse::<SocketAddr>().unwrap()));
        let res = app.oneshot(confirm).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "confirm must not be frozen by safe mode");
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("\"kept\":false"));
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
            html.contains("Docker isn't reachable"),
            "unavailable graph notice missing"
        );
        assert!(html.contains("/static/js/pages/docker.js"), "docker script not linked");

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
        assert!(html.contains("Snapshots"), "page heading missing");
        assert!(html.contains("Docker isn't reachable"), "unavailable notice missing");

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

    /// The database console's source catalog: `sqlite:admin` is always there,
    /// Postgres is absent until configured, and a source id nobody configured is
    /// refused rather than resolved — the catalog is the allowlist, so this is
    /// the boundary that keeps a console query off an arbitrary file.
    #[tokio::test]
    async fn the_database_console_only_addresses_configured_sources() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state.clone());
        let cookie_pair = login_as_root(&app).await;

        // The page renders, and it renders the picker. Askama catches a bad
        // field at compile time but not a block that stopped being emitted.
        let res = app
            .clone()
            .oneshot(get_with_cookie("/database", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let html = String::from_utf8(
            axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains(r#"id="source""#), "the source picker must render");
        assert!(
            !html.contains(r#"id="roles-panel""#),
            "no postgres_url means the Roles tab has nothing to show and must not render"
        );

        let res = app
            .clone()
            .oneshot(get_with_cookie("/database/sources", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let sources = json_body(res).await;
        let ids: Vec<&str> = sources
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"sqlite:admin"), "got: {ids:?}");
        assert!(
            !ids.iter().any(|id| id.starts_with("pg:")),
            "no postgres_url is configured, so no Postgres source may be offered"
        );

        // An unknown source is a 400 with a message, not a 500 and not a read.
        for bad in ["sqlite:nope", "pg:anything", "/etc/passwd"] {
            let res = app
                .clone()
                .oneshot(form_post_with_cookie(
                    "/database/query",
                    format!("sql=SELECT+1&source={bad}"),
                    &cookie_pair,
                ))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::BAD_REQUEST, "source {bad} should be refused");

            // The P1 introspection endpoints resolve through the same catalog.
            for uri in [
                format!("/database/schema?source={bad}"),
                format!("/database/table?source={bad}&table=x"),
            ] {
                let res = app.clone().oneshot(get_with_cookie(&uri, &cookie_pair)).await.unwrap();
                assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{uri} should be refused");
            }
        }
    }

    /// The CSP has to be on *every* response, which is why it is a layer rather
    /// than a handler concern. The three checked here are the ones a
    /// per-handler approach would each miss for a different reason: a page
    /// (remembered), a static asset (served by `ServeDir`, no handler of ours),
    /// and a redirect from an unauthenticated request (produced before any
    /// handler runs).
    #[tokio::test]
    async fn security_headers_reach_every_response_including_assets_and_redirects() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state.clone());
        let cookie_pair = login_as_root(&app).await;

        for (label, request) in [
            ("a page", get_with_cookie("/", &cookie_pair)),
            (
                "a static asset",
                HttpRequest::builder()
                    .uri("/static/css/base.css")
                    .body(Body::empty())
                    .unwrap(),
            ),
            // No cookie: this is refused before it reaches a handler.
            (
                "an unauthenticated request",
                HttpRequest::builder().uri("/").body(Body::empty()).unwrap(),
            ),
        ] {
            let res = app.clone().oneshot(request).await.unwrap();
            let headers = res.headers();
            let csp = headers
                .get("content-security-policy")
                .unwrap_or_else(|| panic!("{label} carried no CSP"))
                .to_str()
                .unwrap();
            assert!(csp.contains("default-src 'self'"), "{label} has a weakened CSP: {csp}");
            // Only `style-src` carries the inline escape (CodeMirror and
            // Cytoscape inject their own `<style>`); scripts stay strict.
            assert!(
                csp.contains("script-src 'self';"),
                "{label} allows inline script: {csp}"
            );
            assert_eq!(headers.get("x-frame-options").unwrap(), "DENY", "{label}");
            assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff", "{label}");
        }
    }

    /// Report-only is the escape hatch for a first rollout, so it has to
    /// actually swap the header — and must never send both, which would enforce
    /// the policy while looking like it was only observing.
    #[tokio::test]
    async fn report_only_mode_swaps_the_header_rather_than_adding_one() {
        let mut config = Config::test_default();
        config.csp_report_only = true;
        let state = build_state_with(config, std::path::Path::new(":memory:"))
            .await
            .unwrap();
        let app = build_router(state);

        let res = app
            .oneshot(HttpRequest::builder().uri("/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(
            res.headers().get("content-security-policy-report-only").is_some(),
            "report-only mode must send the report-only header"
        );
        assert!(
            res.headers().get("content-security-policy").is_none(),
            "report-only mode must not also enforce"
        );
    }

    /// The command palette offers each configured database as a deep link into
    /// the console. Two things are pinned: the link carries the *source id* (a
    /// palette entry that dumped you on the page with the wrong database
    /// selected would be worse than no entry), and the id is percent-encoded,
    /// because it lands in a query string and a source name is config text, not
    /// a known-safe token.
    #[tokio::test]
    async fn the_palette_deep_links_to_a_database_source() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state.clone());
        let cookie_pair = login_as_root(&app).await;

        let res = app
            .clone()
            .oneshot(get_with_cookie("/spotlight/search?q=admin", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = json_body(res).await;
        let items = body["items"].as_array().unwrap();

        let db_item = items
            .iter()
            .find(|i| i["kind"] == "database")
            .unwrap_or_else(|| panic!("no database entry in: {items:?}"));
        assert_eq!(
            db_item["url"].as_str().unwrap(),
            "/database?source=sqlite%3Aadmin",
            "the entry must select the source, and the id must be encoded"
        );

        // A query matching no source name offers no database entry — the
        // palette must not list every database for every search.
        let res = app
            .clone()
            .oneshot(get_with_cookie("/spotlight/search?q=zzzznope", &cookie_pair))
            .await
            .unwrap();
        let body = json_body(res).await;
        assert!(
            !body["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["kind"] == "database"),
            "a non-matching query must not offer database entries"
        );
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
        assert!(html.contains("<h1>Secrets</h1>"), "heading missing");
        assert!(html.contains("/static/js/pages/secrets.js"), "script not linked");
        // No paths are configured in the test config, so the page must say the
        // scanner is idle rather than implying it is watching something.
        assert!(html.contains("The scanner is idle"), "scanner-disabled callout missing");

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
        assert!(html.contains("/static/js/pages/firewall.js"), "script not linked");

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
        assert!(html.contains("<h1>Certificates</h1>"), "page heading missing");
        assert!(html.contains("No proxy routes"), "empty-state proxy copy missing");
        assert!(
            html.contains("Nothing else is being watched"),
            "empty-state monitor copy missing"
        );
    }

    // --- Account & security (Phase 9) ---

    /// A JSON POST carrying a session cookie and a peer address.
    fn json_post_with_cookie(uri: &str, body: impl Into<Body>, cookie_pair: &str) -> HttpRequest<Body> {
        json_post_from(uri, body, cookie_pair, "203.0.113.7:5555")
    }

    fn json_post_from(uri: &str, body: impl Into<Body>, cookie_pair: &str, peer: &str) -> HttpRequest<Body> {
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header(COOKIE, cookie_pair)
            .body(body.into())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        req
    }

    /// A form POST carrying both a cookie and a peer (the 2FA challenge needs both).
    fn form_post_with_cookie(uri: &str, body: impl Into<Body>, cookie_pair: &str) -> HttpRequest<Body> {
        let mut req = form_post(uri, body);
        req.headers_mut()
            .insert(COOKIE, HeaderValue::from_str(cookie_pair).unwrap());
        req
    }

    /// Logs `root` in and returns the session cookie pair.
    async fn login_as_root(app: &Router) -> String {
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "login did not succeed");
        set_cookie_pair(&res)
    }

    async fn json_body(res: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).expect("response was not JSON")
    }

    /// The account page is gated, renders through the layout, and its session
    /// list reports the browser making the request as the current session —
    /// with the provenance the login path recorded.
    #[tokio::test]
    async fn account_page_gates_and_lists_the_current_session() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        let res = app.clone().oneshot(get("/account")).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get("location").unwrap(), "/login");

        let cookie_pair = login_as_root(&app).await;

        let res = app
            .clone()
            .oneshot(get_with_cookie("/account", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Two-factor authentication"), "page copy missing");
        // A fresh account has no second factor: the page must offer to set one
        // up rather than to turn one off.
        assert!(html.contains(r#"id="totp-enable""#), "enroll control missing");
        assert!(
            !html.contains(r#"id="totp-disable""#),
            "offered to disable an absent factor"
        );

        let res = app
            .clone()
            .oneshot(get_with_cookie("/account/sessions", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json = json_body(res).await;
        let sessions = json["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 1, "expected exactly the session we just made");
        assert_eq!(sessions[0]["current"], true, "the requesting session must be flagged");
        assert_eq!(
            sessions[0]["ip"], "203.0.113.7",
            "login did not record the source address"
        );
    }

    /// The sudo gate: being signed in is not enough to change a credential, and
    /// the refusal is the machine-readable one the frontend turns into a prompt.
    /// Re-authenticating opens the window, and the password change then lands.
    #[tokio::test]
    async fn changing_a_password_requires_a_fresh_reauth() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);
        let cookie_pair = login_as_root(&app).await;
        // Its own source address: this test deliberately fails a password check,
        // and `lockout` is process-global, so sharing an IP with another test
        // would make both of them depend on the order they ran in.
        let peer = "203.0.113.21:5555";

        // Signed in, but not recently re-authenticated.
        let res = app
            .clone()
            .oneshot(json_post_from(
                "/account/password",
                r#"{"new_password":"a-much-longer-password"}"#,
                &cookie_pair,
                peer,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let json = json_body(res).await;
        assert_eq!(json["reauth_required"], true, "the reauth marker is the API contract");

        // A wrong password does not open the window.
        let res = app
            .clone()
            .oneshot(json_post_from(
                "/account/reauth",
                r#"{"password":"wrong"}"#,
                &cookie_pair,
                peer,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // The right one does.
        let res = app
            .clone()
            .oneshot(json_post_from(
                "/account/reauth",
                r#"{"password":"hunter2!"}"#,
                &cookie_pair,
                peer,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Too short is refused on its own terms — not with the sudo error.
        let res = app
            .clone()
            .oneshot(json_post_from(
                "/account/password",
                r#"{"new_password":"short"}"#,
                &cookie_pair,
                peer,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let res = app
            .clone()
            .oneshot(json_post_from(
                "/account/password",
                r#"{"new_password":"a-much-longer-password"}"#,
                &cookie_pair,
                peer,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // The new password works and the old one does not.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "the old password still works");
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=a-much-longer-password"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
    }

    /// Revoking a session takes effect on that session's next request, and the
    /// session doing the revoking survives.
    #[tokio::test]
    async fn revoking_other_sessions_ends_them_and_spares_this_one() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        let first = login_as_root(&app).await;
        let second = login_as_root(&app).await;
        assert_ne!(first, second, "two logins must mint two sessions");

        let res = app
            .clone()
            .oneshot(json_post_with_cookie("/account/sessions/revoke-all", "{}", &second))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(json_body(res).await["revoked"], 1);

        // The revoked session is bounced; the revoking one still works.
        let res = app.clone().oneshot(get_with_cookie("/account", &first)).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let res = app.clone().oneshot(get_with_cookie("/account", &second)).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    /// The whole enrollment round trip through the router: start, verify the
    /// code the returned secret generates, get recovery codes back — and then a
    /// recovery code signs in at the 2FA challenge exactly once.
    #[tokio::test]
    async fn totp_enrollment_round_trips_and_recovery_codes_are_single_use() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state.clone());
        let cookie_pair = login_as_root(&app).await;

        // Enrollment is destructive-adjacent, so it is sudo-gated like the rest.
        let res = app
            .clone()
            .oneshot(json_post_with_cookie("/account/totp/start", "{}", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let res = app
            .clone()
            .oneshot(json_post_with_cookie(
                "/account/reauth",
                r#"{"password":"hunter2!"}"#,
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let res = app
            .clone()
            .oneshot(json_post_with_cookie("/account/totp/start", "{}", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let start = json_body(res).await;
        let token = start["token"].as_str().unwrap().to_owned();
        assert!(start["uri"].as_str().unwrap().starts_with("otpauth://totp/"));
        assert!(start["qr"]["width"].as_u64().unwrap() > 0);

        // Starting does not enable: an unverified secret must not lock anyone out.
        let enabled: i64 = state
            .db
            .get_row("SELECT totp_enabled FROM account WHERE name = 'root'", (), |r| r.get(0))
            .await
            .unwrap();
        assert_eq!(enabled, 0, "enrollment enabled the factor before it was verified");

        // The secret we were handed must generate a code the server accepts.
        let secret = start["secret"].as_str().unwrap();
        let raw = decode_base32(secret);
        let code = totp::current_code(&raw);
        let res = app
            .clone()
            .oneshot(json_post_with_cookie(
                "/account/totp/enable",
                format!(r#"{{"token":"{token}","code":"{code}"}}"#),
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let codes: Vec<String> = json_body(res).await["recovery_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(codes.len(), 10);

        // Signing in now stops at the 2FA challenge…
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get("location").unwrap(), "/login/2fa");
        let challenge = set_cookie_pair(&res);

        // …and a recovery code gets past it.
        let body = format!("code={}", codes[0]);
        let res = app
            .clone()
            .oneshot(form_post_with_cookie("/login/2fa", body.clone(), &challenge))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(res.headers().get("location").unwrap(), "/");

        // The same code a second time does not: that is what single-use means.
        let res = app
            .clone()
            .oneshot(form_post("/login", "username=root&password=hunter2!"))
            .await
            .unwrap();
        let challenge = set_cookie_pair(&res);
        let res = app
            .oneshot(form_post_with_cookie("/login/2fa", body, &challenge))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    // --- Alerts (Phase 10) ---

    /// The alerts page is gated, and with no sink in `config.json` it reports
    /// all four as absent rather than pretending alerting is live.
    #[tokio::test]
    async fn alerts_page_gates_and_reports_no_sink_configured() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        let res = app.clone().oneshot(get("/alerts")).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let cookie_pair = login_as_root(&app).await;
        let res = app
            .clone()
            .oneshot(get_with_cookie("/alerts", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(
            html.contains("No alert sink is configured"),
            "an unconfigured install must say so"
        );

        let res = app
            .clone()
            .oneshot(get_with_cookie("/alerts/data", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json = json_body(res).await;
        let sinks = json["sinks"].as_array().unwrap();
        assert_eq!(sinks.len(), 4, "every sink is listed, configured or not");
        assert!(
            sinks.iter().all(|s| s["configured"] == false && s["target"].is_null()),
            "test config has no sinks"
        );
        // Absent state means enabled: a fresh install must alert once a sink
        // appears, without anyone finding a switch first.
        assert!(sinks.iter().all(|s| s["enabled"] == true));
        assert_eq!(json["on_admin_login"], false, "sign-in alerts default off");
        assert!(json["deliveries"].as_array().unwrap().is_empty());
    }

    /// Switching an alert sink off is sudo-gated — it is the most useful thing
    /// to do to a box you have just broken into.
    #[tokio::test]
    async fn muting_a_sink_requires_reauth_and_then_sticks() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state.clone());
        let cookie_pair = login_as_root(&app).await;

        let res = app
            .clone()
            .oneshot(json_post_with_cookie(
                "/alerts/sinks/discord",
                r#"{"enabled":false}"#,
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(res).await["reauth_required"], true);

        let res = app
            .clone()
            .oneshot(json_post_with_cookie(
                "/account/reauth",
                r#"{"password":"hunter2!"}"#,
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let res = app
            .clone()
            .oneshot(json_post_with_cookie(
                "/alerts/sinks/discord",
                r#"{"enabled":false}"#,
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(
            !alerts::sink_enabled(&state.db, "discord").await,
            "the mute did not persist"
        );
        // Muting one sink must not mute the others.
        assert!(alerts::sink_enabled(&state.db, "ntfy").await);

        // An unknown sink is a 404, not a silently-created storage row.
        let res = app
            .clone()
            .oneshot(json_post_with_cookie(
                "/alerts/sinks/carrier-pigeon",
                r#"{"enabled":false}"#,
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// Testing a sink that isn't configured says so, rather than reporting a
    /// success for a message that went nowhere.
    #[tokio::test]
    async fn testing_an_unconfigured_sink_is_a_conflict() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);
        let cookie_pair = login_as_root(&app).await;

        let res = app
            .clone()
            .oneshot(json_post_with_cookie("/alerts/test/discord", "", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT);
    }

    // ─── Audit ───────────────────────────────────────────────────────────────

    /// The end-to-end property: an action performed over HTTP shows up on the
    /// audit page. Testing `audit::log` in isolation would prove the table
    /// works, not that anything writes to it.
    #[tokio::test]
    async fn a_real_action_lands_in_the_audit_log() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state.clone());

        let res = app.clone().oneshot(get("/audit")).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let cookie_pair = login_as_root(&app).await;

        // Signing in is itself auditable, and the page must show it — an audit
        // log that cannot tell you someone logged in is not one.
        let res = app
            .clone()
            .oneshot(get_with_cookie("/audit/data", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json = json_body(res).await;
        assert_eq!(json["entries"][0]["action"], "account.login");
        assert_eq!(json["entries"][0]["actor"], "root");

        // Now a real action, through the router, with no audit call in sight.
        let res = app
            .clone()
            .oneshot(form_post_with_cookie(
                "/database/query",
                "sql=DROP+TABLE+account&danger_mode=false",
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "safe mode should refuse that");

        let res = app
            .clone()
            .oneshot(get_with_cookie("/audit/data", &cookie_pair))
            .await
            .unwrap();
        let json = json_body(res).await;
        let top = &json["entries"][0];
        assert_eq!(top["action"], "database.query.blocked");
        // The refused attempt is recorded *as* refused. This is the row the log
        // exists for, and recording it as a success would be worse than nothing.
        assert_eq!(top["ok"], false);
        assert!(top["detail"]["sql"].as_str().unwrap().contains("DROP TABLE"));
        assert!(json["actions"]
            .as_array()
            .unwrap()
            .contains(&"database.query.blocked".into()));
    }

    /// A failed sign-in is recorded against the username that was typed, even
    /// when no such account exists.
    #[tokio::test]
    async fn a_failed_sign_in_is_recorded_against_the_name_that_was_typed() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state.clone());

        // Own peer address: `lockout` is process-global, so a wrong password
        // here must not spend another test's budget.
        let res = app
            .clone()
            .oneshot(form_post_from(
                "/login",
                "username=ghost&password=wrong",
                "203.0.113.44:5555",
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let entries = audit::entries(
            &state.db,
            audit::Filter {
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "account.login.failed");
        assert_eq!(entries[0].actor, "ghost", "the typed name is the fact worth keeping");
        assert!(!entries[0].ok);
        assert_eq!(entries[0].ip.as_deref(), Some("203.0.113.44"));
    }

    /// Filters compose, and the page's paging cursor does not repeat a row.
    #[tokio::test]
    async fn the_audit_page_filters_and_pages() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state.clone());
        let cookie_pair = login_as_root(&app).await;

        for i in 0..4 {
            let res = app
                .clone()
                .oneshot(form_post_with_cookie(
                    "/database/query",
                    format!("sql=SELECT+{i}&danger_mode=false"),
                    &cookie_pair,
                ))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }

        // Area prefix: one filter for "everything the database console did".
        let res = app
            .clone()
            .oneshot(get_with_cookie("/audit/data?action=database.&limit=2", &cookie_pair))
            .await
            .unwrap();
        let json = json_body(res).await;
        let page = json["entries"].as_array().unwrap();
        assert_eq!(page.len(), 2);
        assert!(page.iter().all(|e| e["action"] == "database.query"));
        assert_eq!(json["more"], true, "two of four means there is another page");

        // The next page starts strictly below the last id seen.
        let last = page[1]["id"].as_i64().unwrap();
        let res = app
            .clone()
            .oneshot(get_with_cookie(
                &format!("/audit/data?action=database.&limit=2&before={last}"),
                &cookie_pair,
            ))
            .await
            .unwrap();
        let json = json_body(res).await;
        let next = json["entries"].as_array().unwrap();
        assert!(next.iter().all(|e| e["id"].as_i64().unwrap() < last));

        // An empty filter value is "no filter", not "match the empty string" —
        // which is what a cleared search box sends.
        let res = app
            .clone()
            .oneshot(get_with_cookie("/audit/data?q=&actor=", &cookie_pair))
            .await
            .unwrap();
        let json = json_body(res).await;
        assert!(
            !json["entries"].as_array().unwrap().is_empty(),
            "a cleared filter box must not blank the page"
        );
    }

    // ─── Scripts ─────────────────────────────────────────────────────────────

    /// A state whose config declares `scripts`, since scripts come from
    /// config.json and there is deliberately no route that creates one.
    async fn state_with_scripts(scripts: Vec<config::SpotlightScript>) -> AppState {
        let mut cfg = Config::test_default();
        cfg.spotlight_scripts = scripts;
        build_state_with(cfg, Path::new(":memory:")).await.expect("build state")
    }

    fn script(id: &str, command: &str, schedule: Option<&str>) -> config::SpotlightScript {
        config::SpotlightScript {
            id: id.to_string(),
            name: format!("The {id} script"),
            command: command.to_string(),
            description: None,
            cwd: None,
            schedule: schedule.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn scripts_page_gates_and_says_when_none_are_configured() {
        let state = test_state().await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);

        let res = app.clone().oneshot(get("/scripts")).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);

        let cookie_pair = login_as_root(&app).await;
        let res = app
            .clone()
            .oneshot(get_with_cookie("/scripts", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(
            html.contains("No scripts are configured"),
            "an empty install must say so"
        );

        let res = app
            .clone()
            .oneshot(get_with_cookie("/scripts/data", &cookie_pair))
            .await
            .unwrap();
        let json = json_body(res).await;
        assert!(json["scripts"].as_array().unwrap().is_empty());
        assert!(json["runs"].as_array().unwrap().is_empty());
    }

    /// The app's one arbitrary-command path: sudo-gated, and what it did is
    /// recorded rather than left in the logs.
    #[tokio::test]
    async fn running_a_script_requires_reauth_and_records_what_it_did() {
        let state = state_with_scripts(vec![script("hello", "echo vantage-was-here", None)]).await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state.clone());
        let cookie_pair = login_as_root(&app).await;

        let res = app
            .clone()
            .oneshot(json_post_with_cookie("/scripts/hello/run", "", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(res).await["reauth_required"], true);

        let res = app
            .clone()
            .oneshot(json_post_with_cookie(
                "/account/reauth",
                r#"{"password":"hunter2!"}"#,
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let res = app
            .clone()
            .oneshot(json_post_with_cookie("/scripts/hello/run", "", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let json = json_body(res).await;
        assert_eq!(json["ok"], true);
        assert_eq!(json["exit_code"], 0);
        assert!(
            json["output"].as_str().unwrap().contains("vantage-was-here"),
            "the script's output is the reason the button exists"
        );

        // The run outlives the request: this is the thing that was missing when
        // a scheduled script's only trace was a tracing line.
        let runs = cron::recent_runs(&state.db, None, 10).await.unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].script_id, "hello");
        assert_eq!(runs[0].trigger, "manual");
        assert_eq!(runs[0].actor.as_deref(), Some("root"), "a manual run names who ran it");
        assert!(runs[0].ok);

        // …and the card can show it without a second query.
        let res = app
            .clone()
            .oneshot(get_with_cookie("/scripts/data", &cookie_pair))
            .await
            .unwrap();
        let json = json_body(res).await;
        assert_eq!(json["scripts"][0]["last_run"]["ok"], true);
        assert_eq!(json["scripts"][0]["running"], false);

        // A script that isn't in config.json cannot be conjured by URL.
        let res = app
            .clone()
            .oneshot(json_post_with_cookie("/scripts/rm-rf-slash/run", "", &cookie_pair))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    /// A failing script is reported as failing, with its output — the whole
    /// point being that you can tell *why* from the page.
    #[tokio::test]
    async fn a_failing_script_reports_its_exit_code() {
        let state = state_with_scripts(vec![script("boom", "exit 3", None)]).await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state.clone());
        let cookie_pair = login_as_root(&app).await;
        let res = app
            .clone()
            .oneshot(json_post_with_cookie(
                "/account/reauth",
                r#"{"password":"hunter2!"}"#,
                &cookie_pair,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let res = app
            .clone()
            .oneshot(json_post_with_cookie("/scripts/boom/run", "", &cookie_pair))
            .await
            .unwrap();
        // The *request* succeeded; the script did not. Conflating those would
        // make a failed script look like a broken page.
        assert_eq!(res.status(), StatusCode::OK);
        let json = json_body(res).await;
        assert_eq!(json["ok"], false);
        assert_eq!(json["exit_code"], 3);

        let runs = cron::recent_runs(&state.db, Some("boom".to_string()), 10)
            .await
            .unwrap();
        assert_eq!(runs.len(), 1);
        assert!(!runs[0].ok);
        assert_eq!(runs[0].exit_code, Some(3));
    }

    /// A script configured to run automatically that never will is the worst
    /// state this page can be in, so the schedule is parsed for the page.
    #[tokio::test]
    async fn a_broken_schedule_is_reported_not_silently_ignored() {
        let state = state_with_scripts(vec![
            script("nightly", "echo ok", Some("30 3 * * *")),
            script("typo", "echo ok", Some("30 3 * *")),
        ])
        .await;
        create_admin_account(&state.db, "root", "hunter2!").await.unwrap();
        let app = build_router(state);
        let cookie_pair = login_as_root(&app).await;

        let res = app
            .clone()
            .oneshot(get_with_cookie("/scripts/data", &cookie_pair))
            .await
            .unwrap();
        let json = json_body(res).await;

        let good = &json["scripts"][0];
        assert!(good["schedule_error"].is_null());
        assert!(
            good["next_run"].is_string(),
            "a valid schedule knows when it next fires"
        );

        let bad = &json["scripts"][1];
        assert!(
            bad["schedule_error"].as_str().unwrap().contains("5 fields"),
            "a typo'd schedule must say why it will never fire"
        );
        assert!(bad["next_run"].is_null());
    }

    /// Test-only inverse of `account::base32_encode`, so the enrollment test can
    /// drive the real client's path: scan the secret, generate a code from it.
    fn decode_base32(encoded: &str) -> Vec<u8> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = Vec::new();
        let mut buffer: u32 = 0;
        let mut bits: u32 = 0;
        for c in encoded.bytes() {
            let value = ALPHABET.iter().position(|&a| a == c).expect("not base32") as u32;
            buffer = (buffer << 5) | value;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((buffer >> bits) as u8);
            }
        }
        out
    }
}
