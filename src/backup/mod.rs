//! On-disk SQLite backups via `VACUUM INTO`, plus a scheduled snapshot task.
//!
//! `VACUUM INTO` writes a consistent, fully-checkpointed copy of the database
//! to a new file without needing an exclusive lock on the live database, so it
//! is safe to run while the server is serving requests. Backups land in
//! `<data>/vantage/backups/` as `backup-<unix-ts>.db`.
//!
//! Restore is intentionally a manual, offline operation: swapping the live
//! database file while the process holds WAL connections is unsafe, so the
//! admin UI offers download (and the operator restores by stopping the server
//! and replacing `admin.db`).

pub mod routes;
pub mod s3;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use serde::Serialize;
use time::OffsetDateTime;

use crate::AppState;

const PREFIX: &str = "backup-";
const SUFFIX: &str = ".db";

/// Default hours between scheduled backups when unconfigured.
const DEFAULT_INTERVAL_HOURS: u64 = 24;
/// Default number of backups to retain when unconfigured.
const DEFAULT_KEEP: usize = 14;

/// Returns (creating if needed) the directory backups are stored in:
/// `<data>/vantage/backups`.
pub fn directory(state: &AppState) -> anyhow::Result<PathBuf> {
    let db = &*state.db_path;
    let dir = db
        .parent()
        .context("database path has no parent directory")?
        .join("backups");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(e).context("could not create backups directory");
        }
    }
    Ok(dir)
}

/// Metadata about a single on-disk backup file.
#[derive(Debug, Clone, Serialize)]
pub struct BackupInfo {
    pub name: String,
    pub size: u64,
    pub size_human: String,
    pub modified_unix: i64,
    pub modified: String,
}

/// Human-readable byte size (B / KB / MB / GB).
pub fn human_size(bytes: u64) -> String {
    if bytes < 1_024 {
        format!("{bytes} B")
    } else if bytes < 1_048_576 {
        format!("{:.1} KB", bytes as f64 / 1_024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    }
}

/// Creates a new backup via `VACUUM INTO`, returning the written file path.
pub async fn create(state: &AppState) -> anyhow::Result<PathBuf> {
    let dir = directory(state)?;
    let ts = OffsetDateTime::now_utc().unix_timestamp();
    let target = dir.join(format!("{PREFIX}{ts}{SUFFIX}"));
    // VACUUM INTO refuses to overwrite an existing file.
    if target.exists() {
        anyhow::bail!("backup target already exists: {}", target.display());
    }
    let path_str = target.to_string_lossy().to_string();
    state
        .db
        .call(move |conn| conn.execute("VACUUM INTO ?1", rusqlite::params![path_str]))
        .await
        .context("VACUUM INTO failed")?;
    Ok(target)
}

/// Lists existing backups, newest first.
pub fn list(state: &AppState) -> Vec<BackupInfo> {
    let Ok(dir) = directory(state) else {
        return Vec::new();
    };
    let Ok(read_dir) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in read_dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.starts_with(PREFIX) && name.ends_with(SUFFIX)) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let size = meta.len();
        let modified_unix = meta
            .modified()
            .ok()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let modified = OffsetDateTime::from_unix_timestamp(modified_unix)
            .ok()
            .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
            .unwrap_or_default();
        out.push(BackupInfo {
            name,
            size,
            size_human: human_size(size),
            modified_unix,
            modified,
        });
    }
    out.sort_by_key(|b| std::cmp::Reverse(b.modified_unix));
    out
}

/// Deletes backups beyond the newest `keep`. `keep == 0` disables pruning.
pub fn prune(state: &AppState, keep: usize) {
    if keep == 0 {
        return;
    }
    for b in list(state).into_iter().skip(keep) {
        if let Some(path) = resolve(state, &b.name) {
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::warn!(error = %e, file = %b.name, "could not prune old backup");
            }
        }
    }
}

/// Resolves a user-supplied backup name to a safe path inside the backups
/// directory, or `None` if the name is unsafe or the file doesn't exist.
pub fn resolve(state: &AppState, name: &str) -> Option<PathBuf> {
    // Reject path separators / traversal — only bare backup file names allowed.
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return None;
    }
    if !(name.starts_with(PREFIX) && name.ends_with(SUFFIX)) {
        return None;
    }
    let path = directory(state).ok()?.join(name);
    path.is_file().then_some(path)
}

/// The configured retention count (number of backups to keep).
pub fn keep_count(state: &AppState) -> usize {
    state.config.backup.keep.unwrap_or(DEFAULT_KEEP)
}

/// The effective scheduled-backup interval in hours (0 = disabled).
pub fn interval_hours(state: &AppState) -> u64 {
    state.config.backup.interval_hours.unwrap_or(DEFAULT_INTERVAL_HOURS)
}

/// Off-site backup status for the data-protection dashboard.
pub enum RemoteStatus {
    /// No off-site target configured.
    Disabled,
    /// Configured but the listing failed (network / credentials) — the string
    /// is a short human-readable reason.
    Unreachable(String),
    /// Reachable; the set holds the **bare file names** present off-site
    /// (prefix stripped) so they can be matched against local backups.
    Reachable(std::collections::HashSet<String>),
}

/// Fetches the set of backup file names present in the off-site store, mapped
/// to the [`RemoteStatus`] the dashboard renders. Best-effort and bounded by
/// the underlying request timeout.
pub async fn remote_status(state: &AppState) -> RemoteStatus {
    let Some(remote) = state.config.backup.remote.clone() else {
        return RemoteStatus::Disabled;
    };
    match s3::list_keys(&state.client, &remote).await {
        Ok(keys) => {
            let prefix = remote.normalized_prefix();
            let names = keys
                .into_iter()
                // Keep only this app's backups, reduced to the bare file name.
                .filter_map(|k| k.strip_prefix(&prefix).map(str::to_string))
                .filter(|n| n.starts_with(PREFIX) && n.ends_with(SUFFIX))
                .collect();
            RemoteStatus::Reachable(names)
        }
        Err(e) => RemoteStatus::Unreachable(e.to_string()),
    }
}

/// Uploads a backup file to the configured off-site object store. Returns
/// `Ok(None)` when no remote is configured (a no-op, not an error), or
/// `Ok(Some(key))` with the remote object key on success.
pub async fn upload_to_remote(state: &AppState, path: &std::path::Path) -> anyhow::Result<Option<String>> {
    let Some(remote) = state.config.backup.remote.clone() else {
        return Ok(None);
    };
    let key = s3::upload_file(&state.client, &remote, path).await?;
    Ok(Some(key))
}

/// Uploads a backup in the background, emitting an alert on failure so a
/// silently broken off-site target doesn't go unnoticed. Used by the
/// scheduler and the manual "backup now" action — the request/scheduler tick
/// is never blocked on network I/O.
pub fn spawn_remote_upload(state: AppState, path: PathBuf) {
    if state.config.backup.remote.is_none() {
        return;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    tokio::spawn(async move {
        match upload_to_remote(&state, &path).await {
            Ok(Some(key)) => tracing::info!(key = %key, "backup uploaded off-site"),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, file = %name, "off-site backup upload failed");
                state.send_alert(serde_json::json!({
                    "username": "vantage",
                    "embeds": [{
                        "title": "⚠️ Off-site backup failed",
                        "description": "A SQLite backup could not be uploaded to the configured remote store.",
                        "color": 0xef4444u32,
                        "fields": [
                            { "name": "File", "value": name, "inline": true },
                            { "name": "Error", "value": e.to_string(), "inline": false },
                        ]
                    }]
                }));
            }
        }
    });
}

/// Minimum delay before the scheduler takes an overdue (or first-ever) backup
/// after start-up. Spaces out catch-up backups so a burst of restarts doesn't
/// each fire one immediately, and paces retries when `create` keeps failing.
const STARTUP_GRACE_SECS: u64 = 300;

/// Background scheduler: takes a backup every `backup.interval_hours` and
/// prunes to `backup.keep`. A value of 0 hours disables the scheduler.
///
/// The schedule is derived from the **newest backup on disk**, not from process
/// start-up, so the cadence survives restarts: a process that restarts more
/// often than the interval would otherwise reset its timer every time and never
/// reach a scheduled backup. If the newest backup is already older than the
/// interval (or none exists), a catch-up backup runs after [`STARTUP_GRACE_SECS`];
/// otherwise the scheduler sleeps until `newest_backup + interval`. This matches
/// the "next run" estimate shown in the admin UI.
pub fn spawn_scheduler(state: AppState) {
    let interval_hours = state.config.backup.interval_hours.unwrap_or(DEFAULT_INTERVAL_HOURS);
    if interval_hours == 0 {
        tracing::info!("scheduled backups disabled (backup.interval_hours = 0)");
        return;
    }
    let keep = keep_count(&state);
    let interval_secs = interval_hours * 3600;
    tokio::spawn(async move {
        loop {
            // Re-read the newest backup each iteration so the next run is always
            // anchored to the last successful backup (restart-durable).
            let now = OffsetDateTime::now_utc().unix_timestamp();
            let due_at = match list(&state).first() {
                Some(b) => b.modified_unix + interval_secs as i64,
                None => now, // never backed up — take one shortly after start-up
            };
            let wait = (due_at - now).max(STARTUP_GRACE_SECS as i64) as u64;
            tracing::info!(wait_secs = wait, "next scheduled backup in ~{wait}s");
            tokio::time::sleep(Duration::from_secs(wait)).await;

            match create(&state).await {
                Ok(path) => {
                    tracing::info!(path = %path.display(), "scheduled backup created");
                    spawn_remote_upload(state.clone(), path);
                    prune(&state, keep);
                }
                Err(e) => tracing::warn!(error = %e, "scheduled backup failed"),
            }
        }
    });
}
