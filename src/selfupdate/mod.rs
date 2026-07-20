//! Vantage's own update checking.
//!
//! Distinct from [`crate::updates`], which checks the *managed services'*
//! container images against their registries. This module asks GitHub whether a
//! newer Vantage release exists and, when the deployment shape allows it,
//! applies that update.
//!
//! Like `updates`, the result is derived data rebuilt on demand, so it lives in
//! memory and is never persisted.

use std::time::Duration;

use anyhow::{anyhow, Context};
use serde::Serialize;
use time::OffsetDateTime;

use crate::AppState;

pub mod helper;
pub mod routes;

/// Where and what to recreate: the Compose project on disk, the service within
/// it, and the container Vantage is currently running as.
///
/// Lives here rather than in `routes` because both `routes` (which produces it)
/// and `helper` (which consumes it) need it.
#[derive(Debug, Clone)]
pub struct Deployment {
    pub project_dir: String,
    pub service: String,
    pub container: String,
}

/// Where releases are read from. **Compile-time constants, deliberately not
/// configuration**: an update checker whose source can be repointed over HTTP
/// is a one-request supply-chain attack. Same rule as alert sink URLs,
/// `dbadmin` sources, and `spotlight_scripts`.
const RELEASES_URL: &str = "https://api.github.com/repos/klappstuhlpy/vantage/releases/latest";
const USER_AGENT: &str = concat!("vantage/", env!("CARGO_PKG_VERSION"));

/// GitHub is a third party, so the check gets a short leash — a hung poll must
/// not keep a task alive until the next interval.
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfUpdateState {
    UpToDate,
    UpdateAvailable,
    /// The check could not be completed — offline, rate-limited, malformed
    /// response. Never a claim about the version, only about the check.
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReleaseInfo {
    /// The git tag as GitHub reports it, e.g. `v0.5.0`.
    pub tag: String,
    /// The tag with any `v` prefix stripped, e.g. `0.5.0`.
    pub version: String,
    pub published_at: Option<String>,
    /// The release body — rendered as the release notes on the settings page.
    pub notes: String,
    pub url: String,
}

impl ReleaseInfo {
    /// Builds a release from GitHub's JSON. Only `tag_name` is required: a
    /// release with no body or no date is still a release, and refusing to
    /// report an update because its notes are empty would be the wrong failure.
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let tag = v.get("tag_name")?.as_str()?.trim().to_string();
        if tag.is_empty() {
            return None;
        }
        let version = tag.trim_start_matches('v').to_string();
        Some(Self {
            tag,
            version,
            published_at: v.get("published_at").and_then(|d| d.as_str()).map(str::to_owned),
            notes: v.get("body").and_then(|b| b.as_str()).unwrap_or("").trim().to_string(),
            url: v.get("html_url").and_then(|u| u.as_str()).unwrap_or("").to_string(),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SelfUpdateStatus {
    pub current: &'static str,
    pub state: SelfUpdateState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<ReleaseInfo>,
    pub checked_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for SelfUpdateStatus {
    fn default() -> Self {
        Self {
            current: crate::VERSION,
            state: SelfUpdateState::Unknown,
            latest: None,
            checked_at: 0,
            error: None,
        }
    }
}

/// Parses a dotted numeric triple. `None` for anything that is not exactly
/// three numeric components — a tag like `nightly`, `0.4`, or `0.4.2.1` is not
/// a version we will compare against.
fn triple(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.trim().trim_start_matches('v');
    let mut it = v.split('.');
    let (a, b, c) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() {
        return None;
    }
    Some((a.parse().ok()?, b.parse().ok()?, c.parse().ok()?))
}

/// Whether `candidate` is a strictly newer version than `current`.
///
/// Components compare numerically, not lexically — the bug this exists to avoid
/// is `0.10.0` sorting below `0.9.0`. Anything unparseable is never newer: the
/// fail-safe direction is to stay quiet, not to announce an update that may not
/// exist. Prereleases need no handling because `/releases/latest` excludes them.
pub fn is_newer(current: &str, candidate: &str) -> bool {
    match (triple(current), triple(candidate)) {
        (Some(c), Some(n)) => n > c,
        _ => false,
    }
}

// ─── In-memory result store ─────────────────────────────────────────────────

fn store() -> &'static std::sync::Mutex<SelfUpdateStatus> {
    static STORE: std::sync::OnceLock<std::sync::Mutex<SelfUpdateStatus>> = std::sync::OnceLock::new();
    STORE.get_or_init(|| std::sync::Mutex::new(SelfUpdateStatus::default()))
}

pub fn status() -> SelfUpdateStatus {
    store().lock().map(|g| g.clone()).unwrap_or_default()
}

pub fn set_status(s: SelfUpdateStatus) {
    if let Ok(mut guard) = store().lock() {
        *guard = s;
    }
}

// ─── The fetch ──────────────────────────────────────────────────────────────

/// Reads the latest published release. GitHub rejects requests without a
/// `User-Agent`, so one is always sent.
pub async fn fetch_latest(client: &reqwest::Client) -> anyhow::Result<ReleaseInfo> {
    let resp = client
        .get(RELEASES_URL)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .context("release request failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("GitHub returned {}", resp.status());
    }

    let body: serde_json::Value = resp.json().await.context("release response was not JSON")?;
    ReleaseInfo::from_json(&body).ok_or_else(|| anyhow!("release response had no tag_name"))
}

// ─── The background check ───────────────────────────────────────────────────

/// Marks a status as "the check did not complete", preserving whatever the last
/// successful check found. Dropping the known release on a transient network
/// failure would make the card flicker between "update available" and "nothing
/// here", which reads as the release having been withdrawn.
fn degraded(previous: SelfUpdateStatus, error: impl Into<String>) -> SelfUpdateStatus {
    SelfUpdateStatus {
        current: crate::VERSION,
        state: SelfUpdateState::Unknown,
        latest: previous.latest,
        checked_at: OffsetDateTime::now_utc().unix_timestamp(),
        error: Some(error.into()),
    }
}

/// Runs one check, stores the result, and — on a transition into
/// "update available" — fires an alert and a live event.
pub async fn run_check(state: &AppState) {
    let previous = status();
    let was_available = previous.state == SelfUpdateState::UpdateAvailable;

    let release = match fetch_latest(&state.client).await {
        Ok(r) => r,
        Err(e) => {
            set_status(degraded(previous, e.to_string()));
            return;
        }
    };

    let available = is_newer(crate::VERSION, &release.version);
    let version = release.version.clone();
    let url = release.url.clone();

    set_status(SelfUpdateStatus {
        current: crate::VERSION,
        state: if available {
            SelfUpdateState::UpdateAvailable
        } else {
            SelfUpdateState::UpToDate
        },
        latest: Some(release),
        checked_at: OffsetDateTime::now_utc().unix_timestamp(),
        error: None,
    });

    state.live_publish(
        "selfupdate",
        serde_json::json!({ "available": available, "version": version }),
    );

    // Only the *transition* alerts. Re-announcing the same pending update every
    // interval trains the operator to ignore the channel.
    if available && !was_available && state.has_any_alert_sink() {
        state.send_alert(serde_json::json!({
            "username": "vantage",
            "embeds": [{
                "title": format!("\u{2b06} Vantage {version} is available"),
                "description": format!(
                    "You are running {}. Review the release notes and update from the settings page.\n{}",
                    crate::VERSION,
                    url
                ),
                "color": 0x10b981u32,
            }]
        }));
    }
}

/// How long to idle before re-reading the interval while checks are disabled,
/// so the settings page can turn them on without a restart.
const DISABLED_RECHECK_SECS: u64 = 3600;

/// Background task, mirroring [`crate::updates::spawn_update_checker`]: the
/// interval is read live each loop so the settings page can enable or disable
/// checks without a restart, and `0` means disabled.
pub fn spawn_self_update_checker(state: AppState) {
    tokio::spawn(async move {
        // Staggered past the image-update checker so the two do not both fire
        // into the network at boot.
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            let hours = crate::updates::check_interval_hours(&state);
            if hours == 0 {
                tokio::time::sleep(Duration::from_secs(DISABLED_RECHECK_SECS)).await;
                continue;
            }
            run_check(&state).await;
            tokio::time::sleep(Duration::from_secs(hours * 3600)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_patch_minor_and_major_are_newer() {
        assert!(is_newer("0.4.2", "0.4.3"));
        assert!(is_newer("0.4.2", "0.5.0"));
        assert!(is_newer("0.4.2", "1.0.0"));
    }

    #[test]
    fn equal_and_older_are_not_newer() {
        assert!(!is_newer("0.4.2", "0.4.2"));
        assert!(!is_newer("0.4.2", "0.4.1"));
        assert!(!is_newer("1.0.0", "0.9.9"));
    }

    #[test]
    fn a_v_prefix_is_tolerated_on_either_side() {
        assert!(is_newer("0.4.2", "v0.4.3"));
        assert!(!is_newer("v0.4.3", "0.4.2"));
    }

    #[test]
    fn components_compare_as_numbers_not_strings() {
        // The bug this guards: "0.10.0" sorts below "0.9.0" under a string compare.
        assert!(is_newer("0.9.0", "0.10.0"));
        assert!(!is_newer("0.10.0", "0.9.0"));
    }

    #[test]
    fn malformed_versions_are_never_newer() {
        assert!(!is_newer("0.4.2", "not-a-version"));
        assert!(!is_newer("0.4.2", ""));
        assert!(!is_newer("0.4.2", "0.4"));
        assert!(!is_newer("0.4.2", "0.4.2.1"));
    }

    #[test]
    fn parses_a_release_payload() {
        let body = serde_json::json!({
            "tag_name": "v0.5.0",
            "published_at": "2026-07-21T10:00:00Z",
            "body": "### Added\n\n- A thing.",
            "html_url": "https://github.com/klappstuhlpy/vantage/releases/tag/v0.5.0",
        });
        let r = ReleaseInfo::from_json(&body).expect("parses");
        assert_eq!(r.tag, "v0.5.0");
        assert_eq!(r.version, "0.5.0");
        assert_eq!(r.notes, "### Added\n\n- A thing.");
        assert_eq!(r.published_at.as_deref(), Some("2026-07-21T10:00:00Z"));
    }

    #[test]
    fn a_release_without_a_body_or_date_still_parses() {
        // Refusing to report an update because its notes are empty would be the
        // wrong failure — the update is still real.
        let body = serde_json::json!({ "tag_name": "v0.5.0", "html_url": "https://example.invalid" });
        let r = ReleaseInfo::from_json(&body).expect("parses");
        assert_eq!(r.version, "0.5.0");
        assert_eq!(r.notes, "");
        assert!(r.published_at.is_none());
    }

    #[test]
    fn a_release_without_a_tag_is_rejected() {
        let body = serde_json::json!({ "body": "notes" });
        assert!(ReleaseInfo::from_json(&body).is_none());
    }

    #[test]
    fn a_failed_check_keeps_the_last_known_release() {
        // The contract: a check that could not complete reports Unknown but must
        // not erase what the previous successful check learned. An operator who
        // goes offline should still see "0.5.0 is available", not a blank card —
        // and certainly not something that reads as the release being withdrawn.
        let known = ReleaseInfo {
            tag: "v0.5.0".into(),
            version: "0.5.0".into(),
            published_at: None,
            notes: String::new(),
            url: String::new(),
        };
        let previous = SelfUpdateStatus {
            current: "0.4.2",
            state: SelfUpdateState::UpdateAvailable,
            latest: Some(known),
            checked_at: 1,
            error: None,
        };

        let after = degraded(previous, "offline");

        assert_eq!(after.state, SelfUpdateState::Unknown);
        assert_eq!(after.error.as_deref(), Some("offline"));
        assert_eq!(after.latest.expect("release retained").version, "0.5.0");
        assert!(after.checked_at > 1, "the check time should advance");
    }

    #[test]
    fn the_store_round_trips() {
        set_status(SelfUpdateStatus {
            current: crate::VERSION,
            state: SelfUpdateState::UpToDate,
            latest: None,
            checked_at: 42,
            error: None,
        });
        let s = status();
        assert_eq!(s.state, SelfUpdateState::UpToDate);
        assert_eq!(s.checked_at, 42);
    }
}
