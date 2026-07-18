//! Docker admin routes — services dashboard + service actions + dependency graph.
//!
//! - `GET  /docker`                — services cards + Cytoscape.js graph
//! - `POST /docker/action`         — start / stop / restart / pull / recreate
//! - `GET  /docker/actions/log`    — JSON action-log ring buffer
//! - `GET  /docker/services/data`  — JSON live service status + `docker stats`
//! - `GET  /docker/logs/:name`     — SSE container log stream
//! - `GET  /docker/graph`          — JSON `DockerGraph` (nodes + edges)
//! - `GET  /docker/inspect/:id`    — JSON `ContainerInspectResponse`
//! - `GET  /docker/snapshots`      — snapshots page
//! - `GET  /docker/snapshots/data` — JSON snapshot list
//! - `POST /docker/snapshots`      — commit a container to a snapshot image
//! - `POST /docker/snapshots/:id/restore` — run a new container from a snapshot
//! - `DELETE /docker/snapshots/:id`       — delete a snapshot (image + row)
//!
//! The read layer (graph, inspect) and the three mutating snapshot calls go
//! through the Seam A `DockerClient` bollard handle in `AppState`; the service
//! actions and the `docker stats` / `docker logs` reads shell out through the
//! typed `kls-agent` host boundary ([`HostCommand`]).
//!
//! One thing is deliberately **not** here yet: image-update checking (the "Pull"
//! hint / update badge — it arrives with the updates slice). Container inspect
//! and log-stream opens can expose env vars and secrets, so both are recorded to
//! the audit log rather than swallowed.

use std::convert::Infallible;

use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Json, Response,
    },
    routing::{delete, get, post},
    Form, Router,
};
use futures_util::stream;
use kls_agent::exec::{HostCommand, Tool};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::audit;
use crate::metrics::docker::DockerStat;
use crate::session::Account;
use crate::AppState;

// ─── Service status model ─────────────────────────────────────────────────────

/// Runtime status of a single Docker service from [`crate::config::ServiceConfig`],
/// as rendered into the initial page. `started_at` is pre-formatted to an ISO
/// string here (the page carries no custom Askama filter); the live JSON refresh
/// reformats it client-side moments after load.
pub struct ServiceStatus {
    pub name: String,
    pub running: bool,
    pub started_at: Option<String>,
    pub image: Option<String>,
    pub short_id: Option<String>,
    pub restart_count: Option<u32>,
}

// ─── Docker process helpers ───────────────────────────────────────────────────

fn is_docker_running(identifier: &str) -> bool {
    HostCommand::new(Tool::Docker)
        .args([
            "ps",
            "--filter",
            &format!("name={identifier}"),
            "--format",
            "{{.Names}}",
        ])
        .output_blocking()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(identifier))
        .unwrap_or(false)
}

fn docker_started_at(identifier: &str) -> Option<OffsetDateTime> {
    let out = HostCommand::new(Tool::Docker)
        .args(["inspect", "-f", "{{.State.StartedAt}}", identifier])
        .output_blocking()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() || s.contains("Error") {
        return None;
    }
    OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339).ok()
}

/// Returns `(image, short_id, restart_count)` via `docker inspect`.
fn docker_details(identifier: &str) -> (Option<String>, Option<String>, Option<u32>) {
    let out = HostCommand::new(Tool::Docker)
        .args([
            "inspect",
            "--format",
            "{{.Config.Image}}\t{{slice .Id 0 12}}\t{{.RestartCount}}",
            identifier,
        ])
        .output_blocking()
        .ok();

    let Some(out) = out else {
        return (None, None, None);
    };
    let raw = String::from_utf8_lossy(&out.stdout);
    let s = raw.trim();
    if s.is_empty() || s.starts_with("Error") {
        return (None, None, None);
    }

    let mut parts = s.splitn(3, '\t');
    let image = parts.next().filter(|s| !s.is_empty()).map(str::to_owned);
    let short_id = parts.next().filter(|s| !s.is_empty()).map(str::to_owned);
    let restart_count = parts.next().and_then(|s| s.trim().parse().ok());
    (image, short_id, restart_count)
}

/// Formats an [`OffsetDateTime`] as `YYYY-MM-DD HH:MM:SS+ZZ:ZZ` — the ISO-ish
/// shape the initial page carries in a `<time datetime>` attribute (matching the
/// site's `isoformat` filter). The JS refresh reformats to local time on load.
fn iso(dt: OffsetDateTime) -> String {
    let (hours, minutes, _) = dt.offset().as_hms();
    format!(
        "{}-{:02}-{:02} {:02}:{:02}:{:02}{:+03}:{:02}",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        hours,
        minutes.abs()
    )
}

// ─── Kill-on-drop guard ───────────────────────────────────────────────────────

struct KillOnDrop(tokio::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

// ─── Docker action log ────────────────────────────────────────────────────────
//
// An in-memory ring buffer of the most recent service actions (start / stop /
// restart / pull / recreate) together with the captured command output. This is
// what powers the "Action Log" panel on the Docker page so the operator can
// actually see what happened when they click a button — otherwise stdout goes to
// the server console and the user sees nothing.

/// One recorded service action and its captured command output.
#[derive(Clone, Serialize)]
struct DockerActionLog {
    #[serde(with = "time::serde::rfc3339")]
    ts: OffsetDateTime,
    service: String,
    action: String,
    success: bool,
    actor: String,
    output: String,
}

/// Maximum number of action-log entries kept in memory.
const ACTION_LOG_CAP: usize = 200;

/// Process-wide action-log ring buffer (newest entry at the front).
fn action_log() -> &'static std::sync::Mutex<std::collections::VecDeque<DockerActionLog>> {
    static LOG: std::sync::OnceLock<std::sync::Mutex<std::collections::VecDeque<DockerActionLog>>> =
        std::sync::OnceLock::new();
    LOG.get_or_init(|| std::sync::Mutex::new(std::collections::VecDeque::new()))
}

fn record_action(entry: DockerActionLog) {
    if let Ok(mut log) = action_log().lock() {
        log.push_front(entry);
        log.truncate(ACTION_LOG_CAP);
    }
}

/// Run `docker <args>` (optionally in `cwd`), capturing combined stdout+stderr.
/// Returns `(success, trimmed_output)`. Docker writes pull/compose progress to
/// stderr, so both streams are merged into the returned text.
async fn run_docker(args: &[&str], cwd: Option<&str>) -> (bool, String) {
    let mut cmd = HostCommand::new(Tool::Docker).args(args.iter().copied());
    if let Some(dir) = cwd {
        cmd = cmd.current_dir(dir);
    }
    match cmd.output().await {
        Ok(out) => {
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.trim().is_empty() {
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str(&stderr);
            }
            (out.status.success(), text.trim_end().to_string())
        }
        Err(e) => {
            // `os error 2` here usually means either the `docker` binary isn't on
            // PATH or the working directory doesn't exist — name both so the
            // message isn't misleading.
            let where_ = match cwd {
                Some(dir) => format!(" (cwd: {dir})"),
                None => String::new(),
            };
            (
                false,
                format!("$ docker {}{where_}\nfailed to launch: {e}", args.join(" ")),
            )
        }
    }
}

/// True when `path` is a usable compose project directory — it exists and
/// contains a compose file. When the app runs in a container without the host's
/// compose directory mounted, this is false and callers fall back to
/// bare-container commands over the Docker socket.
fn compose_dir_usable(path: &str) -> bool {
    let dir = std::path::Path::new(path);
    dir.is_dir()
        && [
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ]
        .iter()
        .any(|f| dir.join(f).exists())
}

/// Perform one service action, returning `(success, captured_output)`.
///
/// When the service has a reachable compose `path` we drive `docker compose`;
/// otherwise we operate on the bare container by `identifier`.
async fn perform_action(path: Option<&str>, identifier: &str, action: &str) -> (bool, String) {
    // Only drive `docker compose` when the project directory is actually
    // reachable (it exists and has a compose file). Otherwise fall back to
    // bare-container commands over the Docker socket — this is what happens when
    // the app runs in a container without the host compose dir mounted.
    let compose = path.filter(|p| compose_dir_usable(p));
    let note = match (path, compose) {
        (Some(p), None) => Some(format!(
            "note: compose directory \"{p}\" isn't accessible here — using container commands instead\n"
        )),
        _ => None,
    };

    let (success, output) = match action {
        "start" => match compose {
            Some(p) => run_docker(&["compose", "up", "-d"], Some(p)).await,
            None => run_docker(&["start", identifier], None).await,
        },
        "stop" => match compose {
            Some(p) => run_docker(&["compose", "down"], Some(p)).await,
            None => run_docker(&["stop", identifier], None).await,
        },
        "restart" => match compose {
            Some(p) => run_docker(&["compose", "restart"], Some(p)).await,
            None => run_docker(&["restart", identifier], None).await,
        },
        "pull" => match compose {
            Some(p) => run_docker(&["compose", "pull"], Some(p)).await,
            None => {
                let (_, raw) = run_docker(&["inspect", "-f", "{{.Config.Image}}", identifier], None).await;
                let image = raw.trim();
                if image.is_empty() || image.starts_with("Error") {
                    (false, "could not determine the image to pull".to_string())
                } else {
                    run_docker(&["pull", image], None).await
                }
            }
        },
        "recreate" => match compose {
            Some(p) => run_docker(&["compose", "up", "-d", "--force-recreate"], Some(p)).await,
            None => {
                // No compose file to recreate from — the best we can do for a bare
                // container is stop + start it. Capture both steps.
                let (s1, o1) = run_docker(&["stop", identifier], None).await;
                let (s2, o2) = run_docker(&["start", identifier], None).await;
                (s1 && s2, format!("{o1}\n{o2}").trim().to_string())
            }
        },
        other => return (false, format!("unknown action: {other}")),
    };

    match note {
        Some(note) => (success, format!("{note}{output}")),
        None => (success, output),
    }
}

// ─── Combined Docker page ─────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "docker.html")]
struct AdminDockerTemplate {
    account: Option<Account>,
    active_page: &'static str,
    docker_available: bool,
    services: Vec<ServiceStatus>,
}

async fn docker_page(State(state): State<AppState>, account: Account) -> Result<AdminDockerTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }

    let services = state
        .config
        .services
        .iter()
        .map(|cfg| {
            let running = is_docker_running(&cfg.identifier);
            let started_at = if running {
                docker_started_at(&cfg.identifier).map(iso)
            } else {
                None
            };
            let (image, short_id, restart_count) = docker_details(&cfg.identifier);
            ServiceStatus {
                name: cfg.name.clone(),
                running,
                started_at,
                image,
                short_id,
                restart_count,
            }
        })
        .collect();

    Ok(AdminDockerTemplate {
        docker_available: state.docker().is_some(),
        account: Some(account),
        active_page: "docker",
        services,
    })
}

// ─── Service action (form POST) ───────────────────────────────────────────────

#[derive(Deserialize)]
struct ServiceAction {
    name: String,
    action: String,
}

async fn service_action(State(state): State<AppState>, account: Account, Form(data): Form<ServiceAction>) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }

    let Some(cfg) = state.config.services.iter().find(|s| s.name == data.name).cloned() else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown service" })),
        )
            .into_response();
    };

    if !matches!(data.action.as_str(), "start" | "stop" | "restart" | "pull" | "recreate") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "unknown action" })),
        )
            .into_response();
    }

    let (success, output) = perform_action(cfg.path.as_deref(), &cfg.identifier, &data.action).await;

    // A state-changing privileged host op. Audited *after* the fact, with its
    // outcome: the old line was emitted before the action ran, so the log
    // recorded intent and called it history — a restart that failed left a
    // record indistinguishable from one that worked. The verb is a detail rather
    // than part of the action name so that "what happened to this container?"
    // is one filter instead of five.
    audit::event("docker.service.action", &account)
        .target(&data.name)
        .detail(serde_json::json!({ "action": data.action, "container": cfg.identifier }))
        .ok(success)
        .record(&state.db)
        .await;

    // State changed — drop the cached container/network/volume lists so the graph
    // and live data reflect the new reality immediately.
    if let Some(docker) = state.docker() {
        docker.invalidate().await;
    }

    record_action(DockerActionLog {
        ts: OffsetDateTime::now_utc(),
        service: cfg.name.clone(),
        action: data.action.clone(),
        success,
        actor: account.name.clone(),
        output: output.clone(),
    });

    let status = if success {
        StatusCode::OK
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (
        status,
        Json(serde_json::json!({
            "ok": success,
            "service": cfg.name,
            "action": data.action,
            "output": output,
        })),
    )
        .into_response()
}

// ─── Action log data (JSON) ───────────────────────────────────────────────────

async fn action_log_data(account: Account) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let entries: Vec<DockerActionLog> = action_log()
        .lock()
        .map(|g| g.iter().cloned().collect())
        .unwrap_or_default();
    Json(serde_json::json!({ "actions": entries })).into_response()
}

// ─── Live service data (JSON) ─────────────────────────────────────────────────

#[derive(Serialize)]
struct ServiceView {
    name: String,
    running: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    started_at: Option<OffsetDateTime>,
    image: Option<String>,
    short_id: Option<String>,
    restart_count: Option<u32>,
    cpu_pct: Option<f64>,
    mem_used: Option<u64>,
    mem_limit: Option<u64>,
}

async fn services_data(State(state): State<AppState>, account: Account) -> Result<Json<Vec<ServiceView>>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }

    let stats: Vec<DockerStat> = crate::metrics::docker::collect().await.unwrap_or_default();
    let stats_by_name: std::collections::HashMap<&str, &DockerStat> =
        stats.iter().map(|s| (s.name.as_str(), s)).collect();

    let views = state
        .config
        .services
        .iter()
        .map(|cfg| {
            let running = is_docker_running(&cfg.identifier);
            let started_at = if running {
                docker_started_at(&cfg.identifier)
            } else {
                None
            };
            let (image, short_id, restart_count) = docker_details(&cfg.identifier);
            let stat = stats_by_name.get(cfg.identifier.as_str()).copied();

            ServiceView {
                name: cfg.name.clone(),
                running,
                started_at,
                image,
                short_id,
                restart_count,
                cpu_pct: stat.map(|s| s.cpu_pct),
                mem_used: stat.map(|s| s.mem_used),
                mem_limit: stat.map(|s| s.mem_limit),
            }
        })
        .collect();

    Ok(Json(views))
}

// ─── Container log SSE ────────────────────────────────────────────────────────

async fn container_logs_sse(
    State(state): State<AppState>,
    account: Account,
    Path(name): Path<String>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }

    let cfg = state
        .config
        .services
        .iter()
        .find(|s| s.name == name)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    // Audited once per stream-open. Container logs can include secrets and
    // request bodies, so this is a privileged read — the audit log records the
    // reads that hand someone a credential, not just the writes.
    audit::event("docker.container.logs.open", &account)
        .target(&name)
        .detail(serde_json::json!({ "container": cfg.identifier }))
        .record(&state.db)
        .await;

    type LogStream = std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<Event, Infallible>> + Send>>;

    // `--timestamps` prefixes every line with an RFC3339Nano stamp. The frontend
    // splits it off and renders it as a dim gutter column, so each line — however
    // the container formats its own output — gets one consistent timestamp.
    let mut child = HostCommand::new(Tool::Docker)
        .args(["logs", "--follow", "--timestamps", "--tail", "200", &cfg.identifier])
        .spawn_piped()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let stdout = child.stdout.take().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let stderr = child.stderr.take().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let (tx, rx) = tokio::sync::mpsc::channel::<String>(256);
    let tx2 = tx.clone();

    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if tx.send(line).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if tx2.send(line).await.is_err() {
                break;
            }
        }
    });

    let log_stream: LogStream = Box::pin(stream::unfold((rx, KillOnDrop(child)), |(mut rx, killer)| async move {
        rx.recv()
            .await
            .map(|line| (Ok::<_, Infallible>(Event::default().data(line)), (rx, killer)))
    }));

    Ok(Sse::new(log_stream).keep_alive(KeepAlive::default()))
}

// ─── Graph data ───────────────────────────────────────────────────────────────

async fn graph_data(State(state): State<AppState>, account: Account) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(docker) = state.docker() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Docker socket not available"
            })),
        )
            .into_response();
    };
    match docker.build_graph().await {
        Ok(graph) => Json(graph).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "build_graph failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

// ─── Container inspect ────────────────────────────────────────────────────────

async fn inspect_container(State(state): State<AppState>, account: Account, Path(id): Path<String>) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(docker) = state.docker() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match docker.inspect(&id).await {
        Ok(info) => {
            // Inspect dumps env vars, mounts, and command line — those routinely
            // contain credentials, so the read is audited like any other way of
            // getting a secret out of this host.
            audit::event("docker.container.inspect", &account)
                .target(&id)
                .record(&state.db)
                .await;
            Json(info).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, id, "inspect_container failed");
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

// ─── Snapshot model ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct DockerSnapshot {
    id: i64,
    container_id: String,
    container_name: String,
    original_image: String,
    snapshot_tag: String,
    description: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

impl DockerSnapshot {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            container_id: row.get("container_id")?,
            container_name: row.get("container_name")?,
            original_image: row.get("original_image")?,
            snapshot_tag: row.get("snapshot_tag")?,
            description: row.get("description")?,
            created_at: row.get("created_at")?,
        })
    }
}

const SNAPSHOT_COLUMNS: &str =
    "id, container_id, container_name, original_image, snapshot_tag, description, created_at";

/// A 12-char URL/tag-safe random id for a fresh snapshot image (the monolith
/// used `nanoid`; Vantage has no such dep, so a small `getrandom` draw over an
/// alphanumeric alphabet does the job — this is a label, not a secret). Purely
/// `[a-zA-Z0-9]` so it can never start with `-`/`.` (both illegal in a Docker
/// image tag component).
fn random_tag() -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut bytes = [0u8; 12];
    // Falls back to a fixed seed only if the OS RNG is somehow unavailable; the
    // UNIQUE index on `snapshot_tag` still guards against a collision.
    let _ = getrandom::getrandom(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

// ─── Snapshots page ───────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "docker_snapshots.html")]
struct AdminSnapshotsTemplate {
    account: Option<Account>,
    active_page: &'static str,
    docker_available: bool,
}

async fn snapshots_page(State(state): State<AppState>, account: Account) -> Result<AdminSnapshotsTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(AdminSnapshotsTemplate {
        docker_available: state.docker().is_some(),
        account: Some(account),
        active_page: "snapshots",
    })
}

// ─── Snapshots data (JSON) ────────────────────────────────────────────────────

async fn snapshots_data(State(state): State<AppState>, account: Account) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let sql = format!("SELECT {SNAPSHOT_COLUMNS} FROM docker_snapshot ORDER BY created_at DESC");
    let snaps: rusqlite::Result<Vec<DockerSnapshot>> = state
        .database()
        .call(move |conn| {
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows: rusqlite::Result<Vec<DockerSnapshot>> = stmt.query_map([], DockerSnapshot::from_row)?.collect();
            rows
        })
        .await;
    match snaps {
        Ok(snapshots) => Json(serde_json::json!({ "snapshots": snapshots })).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "snapshots_data query failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ─── Create snapshot ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateSnapshotPayload {
    container_id: String,
    container_name: String,
    image: String,
    #[serde(default)]
    description: Option<String>,
}

async fn create_snapshot(
    State(state): State<AppState>,
    account: Account,
    Json(payload): Json<CreateSnapshotPayload>,
) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(docker) = state.docker() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Docker not available" })),
        )
            .into_response();
    };

    let tag = random_tag();
    let snapshot_tag = match docker.commit_snapshot(&payload.container_id, &tag).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "commit_snapshot failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let desc = payload.description.filter(|s| !s.is_empty());
    let (cid, cname, img, stag) = (
        payload.container_id.clone(),
        payload.container_name.clone(),
        payload.image.clone(),
        snapshot_tag.clone(),
    );
    let insert: rusqlite::Result<usize> = state
        .database()
        .call(move |conn| {
            conn.execute(
                "INSERT INTO docker_snapshot
                   (container_id, container_name, original_image, snapshot_tag, description)
                 VALUES (?, ?, ?, ?, ?)",
                rusqlite::params![cid, cname, img, stag, desc],
            )
        })
        .await;

    match insert {
        Ok(_) => {
            audit::event("docker.snapshot.create", &account)
                .target(&snapshot_tag)
                .detail(serde_json::json!({
                    "container": payload.container_name,
                    "image": payload.image,
                }))
                .record(&state.db)
                .await;
            Json(serde_json::json!({ "snapshot_tag": snapshot_tag })).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "snapshot DB insert failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

// ─── Restore snapshot ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RestorePayload {
    name: String,
}

/// Restores a container from a snapshot.
///
/// Sudo-gated: this replaces a running service with an image captured at some
/// earlier point, and there is no undo — the thing it overwrote is gone. Routine
/// container actions (start, restart, pull) are not gated; being reversible is
/// exactly the difference.
async fn restore_snapshot(
    State(state): State<AppState>,
    sudo: crate::account::routes::Sudo,
    Path(id): Path<i64>,
    Json(payload): Json<RestorePayload>,
) -> Response {
    let account = sudo.account;
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(docker) = state.docker() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };

    let sql = format!("SELECT {SNAPSHOT_COLUMNS} FROM docker_snapshot WHERE id = ?");
    let snap: rusqlite::Result<Option<DockerSnapshot>> = state
        .database()
        .call(move |conn| {
            let mut stmt = conn.prepare_cached(&sql)?;
            match stmt.query_row([id], DockerSnapshot::from_row) {
                Ok(s) => Ok(Some(s)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await;

    let snap = match snap {
        Ok(Some(s)) => s,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    };

    let name = payload.name.trim().to_owned();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "container name required" })),
        )
            .into_response();
    }

    match docker.run_snapshot(&snap.snapshot_tag, &name).await {
        Ok(container_id) => {
            audit::event("docker.snapshot.restore", &account)
                .target(&snap.snapshot_tag)
                .detail(serde_json::json!({ "restored_as": name, "container_id": container_id }))
                .record(&state.db)
                .await;
            Json(serde_json::json!({ "container_id": container_id })).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "run_snapshot failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

// ─── Delete snapshot ──────────────────────────────────────────────────────────

async fn delete_snapshot(State(state): State<AppState>, account: Account, Path(id): Path<i64>) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }

    let tag: rusqlite::Result<Option<String>> = state
        .database()
        .call(move |conn| {
            match conn.query_row("SELECT snapshot_tag FROM docker_snapshot WHERE id = ?", [id], |row| {
                row.get::<_, String>(0)
            }) {
                Ok(t) => Ok(Some(t)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await;

    let tag = match tag {
        Ok(Some(t)) => t,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    };

    // Best-effort image removal — if the image is already gone, still drop the row.
    if let Some(docker) = state.docker() {
        if let Err(e) = docker.delete_image(&tag).await {
            tracing::warn!(error = %e, tag, "rmi failed — removing DB record anyway");
        }
    }

    let del: rusqlite::Result<usize> = state
        .database()
        .call(move |conn| conn.execute("DELETE FROM docker_snapshot WHERE id = ?", [id]))
        .await;

    match del {
        Ok(_) => {
            audit::event("docker.snapshot.delete", &account)
                .target(&tag)
                .record(&state.db)
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/docker", get(docker_page))
        .route("/docker/action", post(service_action))
        .route("/docker/actions/log", get(action_log_data))
        .route("/docker/services/data", get(services_data))
        .route("/docker/logs/:name", get(container_logs_sse))
        .route("/docker/graph", get(graph_data))
        .route("/docker/inspect/:id", get(inspect_container))
        .route("/docker/snapshots", get(snapshots_page).post(create_snapshot))
        .route("/docker/snapshots/data", get(snapshots_data))
        .route("/docker/snapshots/:id/restore", post(restore_snapshot))
        .route("/docker/snapshots/:id", delete(delete_snapshot))
}
