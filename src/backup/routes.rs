//! Admin SQLite backup management.
//!
//! - `GET    /backups`                  list page
//! - `POST   /backups`                  take a backup now (then prune)
//! - `GET    /backups/:name/download`   download a backup file
//! - `POST   /backups/:name/upload`     upload a backup to the off-site store
//! - `POST   /backups/:name/delete`     delete a backup file
//!
//! Restore is deliberately not offered in-app (replacing the live DB under
//! WAL is unsafe); download and swap `admin.db` with the server stopped.

use crate::{audit, backup, session::Account, AppState};
use askama::Template;
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Json, Redirect, Response},
    routing::{get, post},
    Router,
};

/// One backup file as shown in the dashboard table. The off-site state is
/// pre-rendered to a label + CSS class so the template stays declarative.
struct BackupRow {
    name: String,
    size_human: String,
    modified: String,
    off_site_label: &'static str,
    off_site_class: &'static str,
}

#[derive(Template)]
#[template(path = "backups.html")]
struct BackupsTemplate {
    account: Option<Account>,
    active_page: &'static str,
    rows: Vec<BackupRow>,
    count: usize,
    total_size_human: String,
    keep: usize,
    // ── Schedule ──
    schedule_enabled: bool,
    interval_hours: u64,
    last_backup: Option<String>,
    /// Estimated next scheduled run (last backup + interval), UTC.
    next_run: Option<String>,
    // ── Off-site ──
    /// `Some("s3 → bucket/prefix")` when an off-site target is configured.
    remote_label: Option<String>,
    remote_reachable: bool,
    /// Reason the off-site store could not be listed, when applicable.
    remote_error: Option<String>,
    off_site_count: usize,
}

/// Builds the human-readable "s3 → bucket/prefix" label shown in the UI, or
/// `None` when no off-site target is configured.
fn remote_label(state: &AppState) -> Option<String> {
    state.config.backup.remote.as_ref().map(|r| {
        let prefix = r.normalized_prefix();
        format!("{} → {}/{}", r.kind, r.bucket, prefix)
    })
}

/// Formats a UTC unix timestamp as `YYYY-MM-DD HH:MM UTC`, or `None` if invalid.
fn fmt_ts(unix: i64) -> Option<String> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
}

async fn page(State(state): State<AppState>, account: Account) -> Result<BackupsTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let backups = backup::list(&state);
    let total: u64 = backups.iter().map(|b| b.size).sum();

    // Off-site status (best-effort; bounded by the S3 client timeout).
    let remote = backup::remote_status(&state).await;
    let (remote_reachable, remote_error, off_site_names) = match remote {
        backup::RemoteStatus::Disabled => (false, None, None),
        backup::RemoteStatus::Unreachable(e) => (false, Some(e), None),
        backup::RemoteStatus::Reachable(set) => (true, None, Some(set)),
    };

    let off_site_count = off_site_names
        .as_ref()
        .map(|set| backups.iter().filter(|b| set.contains(&b.name)).count())
        .unwrap_or(0);

    let rows: Vec<BackupRow> = backups
        .iter()
        .map(|b| {
            // The class is a design-system pill tone, not an ad-hoc name: these
            // used to be "yes"/"no"/"unknown", which matched no stylesheet rule
            // and rendered as unstyled text. "local only" is a warning rather
            // than a neutral state — an off-site target is configured and this
            // snapshot is not on it, which is precisely the case where a lost
            // host loses the backup too.
            let (off_site_label, off_site_class) = match &off_site_names {
                Some(set) if set.contains(&b.name) => ("stored", "ok"),
                Some(_) => ("local only", "warn"),
                None => ("not configured", "idle"),
            };
            BackupRow {
                name: b.name.clone(),
                size_human: b.size_human.clone(),
                modified: b.modified.clone(),
                off_site_label,
                off_site_class,
            }
        })
        .collect();

    // Schedule summary + a next-run estimate from the newest backup.
    let interval_hours = backup::interval_hours(&state);
    let schedule_enabled = interval_hours > 0;
    let last_unix = backups.first().map(|b| b.modified_unix);
    let last_backup = last_unix.and_then(fmt_ts);
    let next_run = match (schedule_enabled, last_unix) {
        (true, Some(unix)) => fmt_ts(unix + (interval_hours as i64) * 3600),
        _ => None,
    };

    Ok(BackupsTemplate {
        account: Some(account),
        active_page: "backups",
        count: rows.len(),
        total_size_human: backup::human_size(total),
        keep: backup::keep_count(&state),
        schedule_enabled,
        interval_hours,
        last_backup,
        next_run,
        remote_label: remote_label(&state),
        remote_reachable,
        remote_error,
        off_site_count,
        rows,
    })
}

async fn create_now(State(state): State<AppState>, account: Account) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    match backup::create(&state).await {
        Ok(path) => {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            // Push the fresh backup off-site in the background (no-op when
            // unconfigured); the request is never blocked on network I/O.
            backup::spawn_remote_upload(state.clone(), path);
            backup::prune(&state, backup::keep_count(&state));
            audit::event("backup.create", &account)
                .target(&name)
                .record(&state.db)
                .await;
        }
        Err(e) => tracing::warn!(error = %e, "manual backup failed"),
    }
    Redirect::to("/backups").into_response()
}

/// Uploads one existing backup to the off-site store synchronously and returns
/// JSON feedback. Unlike the automatic background push, this gives the operator
/// immediate feedback (useful to validate credentials after configuring).
async fn upload_now(State(state): State<AppState>, account: Account, Path(name): Path<String>) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if state.config.backup.remote.is_none() {
        return Json(serde_json::json!({
            "status": "error",
            "message": "No off-site backup target is configured."
        }))
        .into_response();
    }
    let Some(path) = backup::resolve(&state, &name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match backup::upload_to_remote(&state, &path).await {
        Ok(Some(key)) => {
            audit::event("backup.upload", &account)
                .target(&name)
                .detail(serde_json::json!({ "key": key }))
                .record(&state.db)
                .await;
            Json(serde_json::json!({
                "status": "success",
                "message": format!("Uploaded off-site as {key}.")
            }))
            .into_response()
        }
        Ok(None) => Json(serde_json::json!({
            "status": "error",
            "message": "No remote configured."
        }))
        .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, file = %name, "manual off-site upload failed");
            Json(serde_json::json!({
                "status": "error",
                "message": format!("Off-site upload failed: {e}")
            }))
            .into_response()
        }
    }
}

async fn download(account: Account, State(state): State<AppState>, Path(name): Path<String>) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(path) = backup::resolve(&state, &name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
            ],
            bytes,
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "backup download failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn delete_backup(State(state): State<AppState>, account: Account, Path(name): Path<String>) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(path) = backup::resolve(&state, &name) {
        if std::fs::remove_file(&path).is_ok() {
            audit::event("backup.delete", &account)
                .target(&name)
                .record(&state.db)
                .await;
        }
    }
    Redirect::to("/backups").into_response()
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/backups", get(page).post(create_now))
        .route("/backups/:name/download", get(download))
        .route("/backups/:name/upload", post(upload_now))
        .route("/backups/:name/delete", post(delete_backup))
}
