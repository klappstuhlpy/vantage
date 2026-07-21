//! Disk usage: every mounted filesystem, and a top-level directory breakdown of
//! each real one.
//!
//! Both halves take no path from the request. `df` reports mount points and how
//! full they are, never a byte of their contents. The `du` breakdown walks a
//! tree, but *which* trees is not request input either: it is exactly the set of
//! mount points `df` just reported for real block devices, each scanned with
//! `-x` so the walk stays on that one filesystem. There is no route that accepts
//! a path — the same rule as `systemd_units` and the database console's sources.
//! That is why this page needs no allowlist and no configuration: it lists all
//! by default.

use crate::{session::Account, AppState};
use askama::Template;
use axum::{
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use kls_agent::{HostCommand, Tool};
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;

/// A `du` that has not answered by now is abandoned. `du` on a pathological tree
/// (millions of inodes, or a stalled network mount) can take minutes; the page
/// must still render the filesystems and the mounts that *did* answer rather
/// than hang on the worst one.
///
/// ponytail: fixed 20s per mount, partial output is discarded (du only prints at
/// the end). Stream-parse with a longer budget only if a real deployment has a
/// tree that legitimately needs it.
const DU_TIMEOUT: Duration = Duration::from_secs(20);

/// How many of the largest children of a mount to keep. A root filesystem has a
/// few dozen top-level entries; the long tail of tiny ones is noise on a
/// "what is filling this disk" view.
const TOP_N: usize = 12;

fn tone(pct: u8) -> &'static str {
    match pct {
        p if p >= 95 => "down",
        p if p >= 80 => "warn",
        _ => "ok",
    }
}

// ─── Filesystems (df) ──────────────────────────────────────────────────────────

/// One mounted filesystem as the page renders it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Filesystem {
    pub source: String,
    pub fstype: String,
    pub mount: String,
    pub size: u64,
    pub used: u64,
    pub avail: u64,
    /// Used percent, from `used`/`size`. Zero when `size` is zero (a pseudo
    /// filesystem like `tmpfs` with nothing on it) rather than a divide-by-zero.
    pub use_pct: u8,
    pub tone: &'static str,
    /// Inode-used percent from `df -i`, merged in by mount point. `None` when
    /// that second `df` had no matching row (or failed) — a filesystem can run
    /// out of inodes with space to spare, so it earns its own column.
    pub inode_pct: Option<u8>,
    pub inode_tone: &'static str,
    /// Whether this filesystem is backed by a real block device (`source` is a
    /// path). Only these get a `du` breakdown; scanning `tmpfs`/`overlay` is
    /// either pointless or double-counts a lower layer.
    pub real: bool,
}

/// A real filesystem has a device path for a source; a pseudo one names its kind
/// (`tmpfs`, `overlay`, `proc`). The breakdown is only meaningful for the former.
fn is_real(source: &str) -> bool {
    source.starts_with('/')
}

/// Parses `df -PT -B1` output — one filesystem per line, sizes in bytes, with a
/// filesystem-type column.
///
/// `-P` (POSIX) guarantees one physical line per filesystem, so a long device
/// name never wraps and desyncs the columns. `-T` inserts Type as the second
/// field, pushing size/used/avail to 2/3/4 and the mount to the sixth-onward
/// (a mount path may contain spaces, so it is the whole tail).
fn parse_df(out: &str) -> Vec<Filesystem> {
    out.lines()
        .skip(1) // header row
        .filter_map(|line| {
            let t: Vec<&str> = line.split_whitespace().collect();
            if t.len() < 7 {
                return None;
            }
            let size: u64 = t[2].parse().ok()?;
            let used: u64 = t[3].parse().ok()?;
            let avail: u64 = t[4].parse().ok()?;
            let use_pct = if size == 0 {
                0
            } else {
                ((used as u128 * 100) / size as u128).min(100) as u8
            };
            let source = t[0].to_string();
            Some(Filesystem {
                real: is_real(&source),
                source,
                fstype: t[1].to_string(),
                mount: t[6..].join(" "),
                size,
                used,
                avail,
                use_pct,
                tone: tone(use_pct),
                inode_pct: None,
                inode_tone: "ok",
            })
        })
        .collect()
}

/// Parses `df -Pi` into a mount → inode-used-percent map.
///
/// Columns: Filesystem Inodes IUsed IFree IUse% Mounted-on. The percent carries
/// a trailing `%`, and a filesystem with no inode concept (many `tmpfs`) prints
/// `-`, which simply doesn't parse and is skipped.
fn parse_inodes(out: &str) -> HashMap<String, u8> {
    out.lines()
        .skip(1)
        .filter_map(|line| {
            let t: Vec<&str> = line.split_whitespace().collect();
            if t.len() < 6 {
                return None;
            }
            let pct: u8 = t[4].trim_end_matches('%').parse().ok()?;
            Some((t[5..].join(" "), pct.min(100)))
        })
        .collect()
}

/// Every mounted filesystem, fullest first, with inode usage merged in.
///
/// A `df` that is missing or fails yields an empty list rather than an error:
/// the breakdown half of the page is still worth showing.
pub async fn filesystems() -> Vec<Filesystem> {
    let space_cmd = HostCommand::new(Tool::Df).args(["-PT", "-B1"]);
    let inodes_cmd = HostCommand::new(Tool::Df).args(["-Pi"]);
    let (space, inodes) = tokio::join!(space_cmd.output(), inodes_cmd.output());

    let mut v = match space {
        Ok(o) => parse_df(&String::from_utf8_lossy(&o.stdout)),
        Err(e) => {
            tracing::warn!(error = %e, "disk: df failed");
            return Vec::new();
        }
    };
    if let Ok(o) = inodes {
        let map = parse_inodes(&String::from_utf8_lossy(&o.stdout));
        for f in &mut v {
            if let Some(&pct) = map.get(&f.mount) {
                f.inode_pct = Some(pct);
                f.inode_tone = tone(pct);
            }
        }
    }
    v.sort_by_key(|f| std::cmp::Reverse(f.used));
    v
}

// ─── Directory breakdown (du) ────────────────────────────────────────────────

/// One top-level child of a mount and its size on disk.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DirEntry {
    pub path: String,
    pub bytes: u64,
    /// Width for the bar, as a percent of the largest child in the same mount —
    /// so the biggest fills the track and the rest are comparable to it. This is
    /// deliberately relative-to-max, not to the disk: a truthful "how full" bar
    /// already lives in the filesystem row above.
    pub pct: u8,
}

/// The top-level breakdown of one filesystem.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Breakdown {
    pub mount: String,
    pub entries: Vec<DirEntry>,
    /// Set when `du` could not walk the mount (timed out, unreadable). The card
    /// still renders so a mount that vanished from view is visible, not silently
    /// dropped.
    pub note: String,
}

/// Parses `du -d1 -xB1 <mount>` — "<bytes>\t<path>" per line — into the mount's
/// children, largest first, dropping the summary line for the mount itself.
fn parse_du(out: &str, mount: &str) -> Vec<DirEntry> {
    let mut rows: Vec<(String, u64)> = out
        .lines()
        .filter_map(|line| {
            let (size, path) = line.split_once('\t')?;
            let bytes: u64 = size.trim().parse().ok()?;
            let path = path.trim();
            // The last line du prints is the mount total itself — not a child.
            if path == mount {
                return None;
            }
            Some((path.to_string(), bytes))
        })
        .collect();
    rows.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
    let max = rows.first().map(|(_, b)| *b).unwrap_or(0).max(1);
    rows.into_iter()
        .take(TOP_N)
        .map(|(path, bytes)| DirEntry {
            path,
            bytes,
            pct: ((bytes as u128 * 100) / max as u128).min(100) as u8,
        })
        .collect()
}

async fn breakdown(mount: &str) -> Breakdown {
    // `-d1` one level deep; `-x` stay on this filesystem (never wander into a
    // nested mount and double-count it); `-B1` bytes. The mount is an argv
    // element, never a shell word — and it is a `df` mount point, not request
    // input.
    let cmd = HostCommand::new(Tool::Du).args(["-d1", "-xB1", mount]);
    let (entries, note) = match tokio::time::timeout(DU_TIMEOUT, cmd.output()).await {
        Ok(Ok(o)) if o.status.success() => (parse_du(&String::from_utf8_lossy(&o.stdout), mount), String::new()),
        Ok(Ok(o)) => {
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            (
                Vec::new(),
                if err.is_empty() {
                    "du reported a failure".into()
                } else {
                    err
                },
            )
        }
        Ok(Err(e)) => (Vec::new(), e.to_string()),
        Err(_) => (Vec::new(), "timed out".into()),
    };
    Breakdown {
        mount: mount.to_string(),
        entries,
        note,
    }
}

/// A top-level breakdown of every real filesystem, measured concurrently.
pub async fn breakdowns(filesystems: &[Filesystem]) -> Vec<Breakdown> {
    let real: Vec<&Filesystem> = filesystems.iter().filter(|f| f.real).collect();
    futures_util::future::join_all(real.into_iter().map(|f| breakdown(&f.mount))).await
}

// ─── Page ──────────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "disk.html")]
struct DiskTemplate {
    account: Option<Account>,
    active_page: &'static str,
}

async fn page(account: Account) -> DiskTemplate {
    DiskTemplate {
        account: Some(account),
        active_page: "disk",
    }
}

async fn data(_account: Account) -> Response {
    let filesystems = filesystems().await;
    let breakdowns = breakdowns(&filesystems).await;
    Json(serde_json::json!({ "filesystems": filesystems, "breakdowns": breakdowns })).into_response()
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/disk", get(page)).route("/disk/data", get(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_df_reads_every_mount_with_type_in_bytes() {
        let out = "Filesystem     Type  1B-blocks       Used  Available Capacity Mounted on\n\
                   /dev/sda1      ext4 50000000000 40000000000 10000000000     80% /\n\
                   tmpfs          tmpfs 8000000000           0  8000000000      0% /dev/shm\n";
        let v = parse_df(out);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].source, "/dev/sda1");
        assert_eq!(v[0].fstype, "ext4");
        assert_eq!(v[0].mount, "/");
        assert_eq!(v[0].size, 50_000_000_000);
        assert_eq!(v[0].used, 40_000_000_000);
        assert_eq!(v[0].use_pct, 80);
        assert_eq!(v[0].tone, "warn");
        assert!(v[0].real);
        // A pseudo filesystem: zero size divides safely, and it is not "real".
        assert_eq!(v[1].use_pct, 0);
        assert_eq!(v[1].tone, "ok");
        assert!(!v[1].real);
    }

    #[test]
    fn parse_df_keeps_spaces_in_a_mount_path() {
        let out = "Filesystem Type 1B-blocks Used Available Capacity Mounted on\n\
                   /dev/sdb1 ext4 1000 500 500 50% /mnt/my backups\n";
        let v = parse_df(out);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].mount, "/mnt/my backups");
        assert_eq!(v[0].use_pct, 50);
    }

    #[test]
    fn parse_df_skips_short_and_garbage_lines() {
        let out = "Filesystem Type 1B-blocks Used Available Capacity Mounted on\n\
                   udev devtmpfs - - - - /dev\n\
                   \n";
        assert!(parse_df(out).is_empty());
    }

    #[test]
    fn parse_inodes_maps_percent_by_mount_and_skips_dashes() {
        let out = "Filesystem      Inodes   IUsed   IFree IUse% Mounted on\n\
                   /dev/sda1      3200000  200000 3000000    6% /\n\
                   tmpfs                -       -       -     - /run\n";
        let m = parse_inodes(out);
        assert_eq!(m.get("/"), Some(&6));
        assert_eq!(m.get("/run"), None);
    }

    #[test]
    fn tone_colours_a_filling_disk_before_it_is_an_outage() {
        assert_eq!(tone(79), "ok");
        assert_eq!(tone(80), "warn");
        assert_eq!(tone(95), "down");
    }

    #[test]
    fn parse_du_sorts_children_drops_the_mount_row_and_scales_bars() {
        let out = "4096\t/bin\n\
                   20000000000\t/var\n\
                   10000000000\t/usr\n\
                   50000000000\t/\n";
        let e = parse_du(out, "/");
        // The "/" summary line is not a child.
        assert_eq!(e.len(), 3);
        // Largest first, and the largest fills the bar.
        assert_eq!(e[0].path, "/var");
        assert_eq!(e[0].pct, 100);
        assert_eq!(e[1].path, "/usr");
        assert_eq!(e[1].pct, 50);
        assert_eq!(e[2].path, "/bin");
    }

    #[test]
    fn parse_du_caps_at_top_n() {
        let out: String = (0..40).map(|i| format!("{}\t/d{}\n", (40 - i) * 1000, i)).collect();
        assert_eq!(parse_du(&out, "/").len(), TOP_N);
    }
}
