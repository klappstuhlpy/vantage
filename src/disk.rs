//! Disk usage: every mounted filesystem, and the size of the directories the
//! operator asked to watch.
//!
//! The two halves have different trust postures on purpose. `df` needs no
//! allowlist — it takes no path, and reports only mount points and how full they
//! are, never a byte of their contents. `du` does need one: it walks a directory
//! tree, so *which* trees it may walk is `config.disk_paths` and nothing a
//! request carries. There is no route that accepts a path. Same rule as
//! `systemd_units` and the database console's sources: a request selects from a
//! configured list, it never supplies the target.

use crate::{session::Account, AppState};
use askama::Template;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use kls_agent::{HostCommand, Tool};
use serde::Serialize;
use std::time::Duration;

/// A `du` that has not answered by now is abandoned. `du` on a pathological tree
/// (millions of inodes, or a stalled network mount) can take minutes; the page
/// must still render the filesystems and the directories that *did* answer
/// rather than hang on the worst one.
///
/// ponytail: fixed 20s per directory. Make it a per-path config field only if a
/// real deployment has a tree that legitimately needs longer.
const DU_TIMEOUT: Duration = Duration::from_secs(20);

// ─── Filesystems (df) ──────────────────────────────────────────────────────────

/// One mounted filesystem as the page renders it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Filesystem {
    pub source: String,
    pub mount: String,
    pub size: u64,
    pub used: u64,
    pub avail: u64,
    /// Used percent, from `used`/`size`. Zero when `size` is zero (a pseudo
    /// filesystem like `tmpfs` with nothing on it) rather than a divide-by-zero.
    pub use_pct: u8,
    /// Design-system tone for the fill bar (see components.css): a filling disk
    /// is the whole reason to look at this page, so it earns colour before it is
    /// an outage — warn past 80%, down past 95%.
    pub tone: &'static str,
}

fn fs_tone(pct: u8) -> &'static str {
    match pct {
        p if p >= 95 => "down",
        p if p >= 80 => "warn",
        _ => "ok",
    }
}

/// Parses `df -B1 -P` output — one filesystem per line, sizes already in bytes.
///
/// `-P` (POSIX) guarantees one physical line per filesystem, so a long device
/// name never wraps onto its own line and desyncs the columns. The mount point
/// is the last column and a mount path may contain spaces, so it is everything
/// from the sixth field on, not just the sixth.
fn parse_df(out: &str) -> Vec<Filesystem> {
    out.lines()
        .skip(1) // header row
        .filter_map(|line| {
            let t: Vec<&str> = line.split_whitespace().collect();
            if t.len() < 6 {
                return None;
            }
            let size: u64 = t[1].parse().ok()?;
            let used: u64 = t[2].parse().ok()?;
            let avail: u64 = t[3].parse().ok()?;
            let use_pct = if size == 0 {
                0
            } else {
                ((used as u128 * 100) / size as u128).min(100) as u8
            };
            Some(Filesystem {
                source: t[0].to_string(),
                mount: t[5..].join(" "),
                size,
                used,
                avail,
                use_pct,
                tone: fs_tone(use_pct),
            })
        })
        .collect()
}

/// Every mounted filesystem, fullest first.
///
/// A `df` that is missing or fails yields an empty list rather than an error:
/// the directory-sizes half of the page is still worth showing.
pub async fn filesystems() -> Vec<Filesystem> {
    match HostCommand::new(Tool::Df).args(["-B1", "-P"]).output().await {
        Ok(o) => {
            let mut v = parse_df(&String::from_utf8_lossy(&o.stdout));
            v.sort_by_key(|f| std::cmp::Reverse(f.used));
            v
        }
        Err(e) => {
            tracing::warn!(error = %e, "disk: df failed");
            Vec::new()
        }
    }
}

// ─── Directories (du) ──────────────────────────────────────────────────────────

/// One watched directory's measured size.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DirUsage {
    pub path: String,
    /// `None` when `du` could not measure it — missing, unreadable, or timed
    /// out. The row still appears: a watched path that has vanished is exactly
    /// the thing worth seeing, and a silent omission would hide it.
    pub bytes: Option<u64>,
    /// Why `bytes` is `None`, straight from `du`'s stderr where there is one.
    pub note: String,
}

async fn dir_usage(path: &str) -> DirUsage {
    // `-s` one summary line; `-B1` sizes in bytes (allocated blocks, matching how
    // df reports the same disk). The path is an argv element, never a shell word.
    let cmd = HostCommand::new(Tool::Du).args(["-sB1", path]);
    let (bytes, note) = match tokio::time::timeout(DU_TIMEOUT, cmd.output()).await {
        Ok(Ok(o)) if o.status.success() => {
            // `du -s` prints "<bytes>\t<path>"; the size is the first field.
            let out = String::from_utf8_lossy(&o.stdout);
            (out.split_whitespace().next().and_then(|n| n.parse().ok()), String::new())
        }
        Ok(Ok(o)) => {
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            (None, if err.is_empty() { "du reported a failure".into() } else { err })
        }
        Ok(Err(e)) => (None, e.to_string()),
        Err(_) => (None, "timed out".into()),
    };
    DirUsage { path: path.to_string(), bytes, note }
}

/// Every configured directory's size, measured concurrently.
pub async fn directories(state: &AppState) -> Vec<DirUsage> {
    futures_util::future::join_all(state.config.disk_paths.iter().map(|p| dir_usage(p))).await
}

// ─── Page ──────────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "disk.html")]
struct DiskTemplate {
    account: Option<Account>,
    active_page: &'static str,
    any_dirs: bool,
}

async fn page(State(state): State<AppState>, account: Account) -> DiskTemplate {
    DiskTemplate {
        account: Some(account),
        active_page: "disk",
        any_dirs: !state.config.disk_paths.is_empty(),
    }
}

async fn data(State(state): State<AppState>, _account: Account) -> Response {
    let (filesystems, directories) = tokio::join!(filesystems(), directories(&state));
    Json(serde_json::json!({ "filesystems": filesystems, "directories": directories })).into_response()
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/disk", get(page)).route("/disk/data", get(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_df_reads_every_mount_in_bytes() {
        let out = "Filesystem     1B-blocks       Used  Available Capacity Mounted on\n\
                   /dev/sda1     50000000000   40000000000  10000000000     80% /\n\
                   tmpfs          8000000000            0   8000000000      0% /dev/shm\n";
        let v = parse_df(out);
        assert_eq!(v.len(), 2);
        // Sorted by used happens in filesystems(); parse_df keeps input order.
        assert_eq!(v[0].source, "/dev/sda1");
        assert_eq!(v[0].mount, "/");
        assert_eq!(v[0].size, 50_000_000_000);
        assert_eq!(v[0].used, 40_000_000_000);
        assert_eq!(v[0].use_pct, 80);
        assert_eq!(v[0].tone, "warn");
        // A pseudo filesystem with nothing on it does not divide by zero.
        assert_eq!(v[1].use_pct, 0);
        assert_eq!(v[1].tone, "ok");
    }

    #[test]
    fn parse_df_keeps_spaces_in_a_mount_path() {
        // A mount path can contain a space; the mount is the whole tail, not one
        // field, or the used/size columns would shift.
        let out = "Filesystem 1B-blocks Used Available Capacity Mounted on\n\
                   /dev/sdb1 1000 500 500 50% /mnt/my backups\n";
        let v = parse_df(out);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].mount, "/mnt/my backups");
        assert_eq!(v[0].used, 500);
        assert_eq!(v[0].use_pct, 50);
    }

    #[test]
    fn parse_df_skips_short_and_garbage_lines() {
        // A blank tail line and a non-numeric column must not become a row.
        let out = "Filesystem 1B-blocks Used Available Capacity Mounted on\n\
                   udev - - - - /dev\n\
                   \n";
        assert!(parse_df(out).is_empty());
    }

    #[test]
    fn fs_tone_colours_a_filling_disk_before_it_is_an_outage() {
        assert_eq!(fs_tone(0), "ok");
        assert_eq!(fs_tone(79), "ok");
        assert_eq!(fs_tone(80), "warn");
        assert_eq!(fs_tone(94), "warn");
        assert_eq!(fs_tone(95), "down");
        assert_eq!(fs_tone(100), "down");
    }
}
