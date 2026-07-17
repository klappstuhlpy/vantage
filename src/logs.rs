//! Admin log viewer — the first feature slice moved into Vantage
//! (ADMIN_SEPARATION_PLAN Phase 4, Step C).
//!
//! - `GET /logs/view`   page
//! - `GET /logs/data`   JSON: tailed + filtered log lines
//!
//! Reads the rolling JSON log written by the tracing appender in
//! [`logs_directory`]. Ported from the monolith's `admin/logs.rs`.
//!
//! Vantage runs as its own process, so [`logs_directory`] is *Vantage's* log
//! directory and nothing else. The site it fronts writes its own logs elsewhere;
//! setting `site_logs_path` points the viewer at that directory too, the same
//! way `requests_db_path` points the security page at the site's access log.

use std::path::{Path, PathBuf};

use askama::Template;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};

use crate::session::Account;
use crate::AppState;

/// Vantage's log directory: `<state>/vantage`, falling back to `./logs`.
pub fn logs_directory() -> PathBuf {
    dirs::state_dir()
        .map(|p| p.join("vantage"))
        .unwrap_or_else(|| PathBuf::from("./logs"))
}

/// Which log stream the viewer is reading.
///
/// Vantage writes one JSON application log. The site writes two — the same JSON
/// application log *and* a compact-text bad-request log — in one directory, so
/// picking a site log needs both a path and a discriminator. Without one,
/// [`resolve_log_file`]'s newest-file fallback would cheerfully hand back
/// `bad_requests.log` when asked for the application log.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Source {
    #[default]
    Vantage,
    Site,
    SiteBad,
}

impl Source {
    /// The directory this source reads from, or `None` when it is a site source
    /// and no `site_logs_path` is configured.
    fn directory(self, state: &AppState) -> Option<PathBuf> {
        match self {
            Source::Vantage => Some(logs_directory()),
            Source::Site | Source::SiteBad => state.config.site_logs_path.clone(),
        }
    }

    /// True for the site's bad-request log, which is compact text rather than
    /// the JSON the other two write.
    fn is_bad_requests(self) -> bool {
        self == Source::SiteBad
    }
}

#[derive(Template)]
#[template(path = "logs.html")]
struct AdminLogsTemplate {
    account: Option<Account>,
    active_page: &'static str,
    /// Whether `site_logs_path` is set. The source picker only renders when it
    /// is: with one source there is nothing to pick, and a control that cannot
    /// do anything is worse than no control.
    site_logs_available: bool,
}

async fn page(State(state): State<AppState>, account: Account) -> Result<AdminLogsTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(AdminLogsTemplate {
        account: Some(account),
        active_page: "logs",
        site_logs_available: state.config.site_logs_path.is_some(),
    })
}

/// Resolves the newest log file of one kind in `dir`. Prefers the appender's
/// stable symlink, falling back to the newest matching rotated file (symlinks
/// need privileges on Windows).
///
/// `bad_requests` selects between the two streams the site writes into a single
/// directory — both the symlink name and the rotated-file prefix have to match,
/// or the fallback would cross the streams.
fn resolve_log_file(dir: &Path, bad_requests: bool) -> Option<PathBuf> {
    let direct = dir.join(if bad_requests { "bad_requests.log" } else { "today.log" });
    if direct.exists() {
        return Some(direct);
    }
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".log") {
            continue;
        }
        if name.starts_with("bad_requests") != bad_requests {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let modified = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
        if best.as_ref().map(|(t, _)| modified > *t).unwrap_or(true) {
            best = Some((modified, entry.path()));
        }
    }
    best.map(|(_, p)| p)
}

#[derive(Serialize)]
struct LogLine {
    ts: String,
    level: String,
    target: String,
    message: String,
    raw: String,
}

/// Parses one log line. JSON lines (the appender's format) are decomposed into
/// fields; anything else is treated as a plain message.
fn parse_line(raw: &str) -> LogLine {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        let ts = v.get("timestamp").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let level = v.get("level").and_then(|x| x.as_str()).unwrap_or("INFO").to_string();
        let target = v.get("target").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let message = v
            .get("fields")
            .and_then(|f| f.get("message"))
            .and_then(|m| m.as_str())
            .map(|s| s.to_string())
            .or_else(|| v.get("fields").map(|f| f.to_string()))
            .unwrap_or_default();
        LogLine {
            ts,
            level,
            target,
            message,
            raw: raw.to_string(),
        }
    } else {
        LogLine {
            ts: String::new(),
            level: "INFO".to_string(),
            target: String::new(),
            message: raw.to_string(),
            raw: raw.to_string(),
        }
    }
}

#[derive(Deserialize)]
struct LogQuery {
    #[serde(default)]
    source: Source,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn data(State(state): State<AppState>, account: Account, Query(query): Query<LogQuery>) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    // An unconfigured site source and an empty log directory are the same answer
    // to the operator ("there is nothing to show here"), so they render the same.
    let Some(path) = query
        .source
        .directory(&state)
        .and_then(|dir| resolve_log_file(&dir, query.source.is_bad_requests()))
    else {
        return Json(serde_json::json!({ "file": serde_json::Value::Null, "lines": [] })).into_response();
    };
    let content = tokio::fs::read_to_string(&path).await.unwrap_or_default();

    let limit = query.limit.unwrap_or(500).clamp(1, 5000);
    let needle = query.q.unwrap_or_default().to_lowercase();
    let level = query.level.unwrap_or_default();

    // Walk newest-first, filter, cap, then restore chronological order.
    let mut lines: Vec<LogLine> = content
        .lines()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .map(parse_line)
        .filter(|ll| level.is_empty() || ll.level.eq_ignore_ascii_case(&level))
        .filter(|ll| needle.is_empty() || ll.raw.to_lowercase().contains(&needle))
        .take(limit)
        .collect();
    lines.reverse();

    let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned());
    Json(serde_json::json!({ "file": file_name, "lines": lines })).into_response()
}

/// The admin sub-router. As more slices move in they merge here.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/logs/view", get(page))
        .route("/logs/data", get(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_line_reads_json_and_plaintext() {
        let json =
            r#"{"timestamp":"2026-07-16T00:00:00Z","level":"WARN","target":"vantage","fields":{"message":"hi"}}"#;
        let parsed = parse_line(json);
        assert_eq!(parsed.level, "WARN");
        assert_eq!(parsed.target, "vantage");
        assert_eq!(parsed.message, "hi");

        let plain = parse_line("just a line");
        assert_eq!(plain.level, "INFO");
        assert_eq!(plain.message, "just a line");
    }

    #[test]
    fn logs_directory_is_named_for_the_app() {
        assert!(logs_directory().ends_with("vantage") || logs_directory().ends_with("logs"));
    }

    /// A scratch log directory that cleans itself up.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("vantage-logs-test-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn write(&self, name: &str, body: &str) {
            std::fs::write(self.0.join(name), body).unwrap();
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn resolve_prefers_the_stable_symlink_over_rotated_files() {
        let dir = TempDir::new("symlink");
        dir.write("today.log", "{}");
        dir.write("2026-07-16.log", "{}");

        let found = resolve_log_file(&dir.0, false).unwrap();
        assert_eq!(found.file_name().unwrap(), "today.log");
    }

    /// The regression this whole `bad_requests` flag exists for: the site writes
    /// both logs into one directory, so the newest-file fallback must not answer
    /// a request for the application log with the bad-request log, or vice versa.
    #[test]
    fn the_two_site_streams_never_cross() {
        let dir = TempDir::new("streams");
        // No symlinks — force the fallback, which is where crossing could happen.
        // The bad-request log is written last, so it is the newest `.log` here.
        dir.write("2026-07-16.log", "{}");
        dir.write("bad_requests.2026-07-16.log", "plain text");

        let app = resolve_log_file(&dir.0, false).unwrap();
        assert_eq!(app.file_name().unwrap(), "2026-07-16.log");

        let bad = resolve_log_file(&dir.0, true).unwrap();
        assert_eq!(bad.file_name().unwrap(), "bad_requests.2026-07-16.log");
    }

    #[test]
    fn a_directory_without_the_requested_stream_resolves_to_nothing() {
        let dir = TempDir::new("missing");
        dir.write("today.log", "{}");
        // Vantage's own directory has no bad-request log; asking for one is not
        // an error, there is simply nothing to show.
        assert!(resolve_log_file(&dir.0, true).is_none());
        assert!(resolve_log_file(Path::new("/definitely/not/a/directory"), false).is_none());
    }

    #[test]
    fn source_parses_from_the_query_string_and_defaults_to_vantage() {
        // Through the real extractor, so this pins the wire format the page's
        // `?source=` values have to match — not just serde's view of the enum.
        let parse = |q: &str| {
            let uri: axum::http::Uri = format!("/logs/data?{q}").parse().unwrap();
            Query::<LogQuery>::try_from_uri(&uri).unwrap().0.source
        };
        assert_eq!(parse(""), Source::Vantage);
        assert_eq!(parse("limit=200"), Source::Vantage);
        assert_eq!(parse("source=site"), Source::Site);
        assert_eq!(parse("source=site-bad"), Source::SiteBad);
        assert!(Source::SiteBad.is_bad_requests());
        assert!(!Source::Site.is_bad_requests());
    }

    async fn state_with(site_logs: Option<PathBuf>) -> AppState {
        let mut config = crate::config::Config::test_default();
        config.site_logs_path = site_logs;
        crate::build_state_with(config, Path::new(":memory:")).await.unwrap()
    }

    #[tokio::test]
    async fn site_sources_need_a_configured_path() {
        let unset = state_with(None).await;
        assert!(Source::Site.directory(&unset).is_none());
        assert!(Source::SiteBad.directory(&unset).is_none());
        // Vantage's own log never depends on config.
        assert!(Source::Vantage.directory(&unset).is_some());

        let configured = state_with(Some(PathBuf::from("/var/log/site"))).await;
        assert_eq!(
            Source::Site.directory(&configured),
            Some(PathBuf::from("/var/log/site"))
        );
        assert_eq!(
            Source::SiteBad.directory(&configured),
            Some(PathBuf::from("/var/log/site"))
        );
    }
}
