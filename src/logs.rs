//! Admin log viewer — the first feature slice moved into Vantage
//! (ADMIN_SEPARATION_PLAN Phase 4, Step C).
//!
//! - `GET /logs/view`   page
//! - `GET /logs/data`   JSON: tailed + filtered log lines
//!
//! Reads the rolling JSON log written by the tracing appender in
//! [`logs_directory`]. Ported from the monolith's `admin/logs.rs`, trimmed to
//! Vantage's single application log (the bad-request log arrives with the
//! request-logging/security slice).

use std::path::PathBuf;

use askama::Template;
use axum::{
    extract::Query,
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

#[derive(Template)]
#[template(path = "logs.html")]
struct AdminLogsTemplate {
    account: Option<Account>,
    active_page: &'static str,
}

async fn page(account: Account) -> Result<AdminLogsTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(AdminLogsTemplate {
        account: Some(account),
        active_page: "logs",
    })
}

/// Resolves the newest application log file. Prefers the appender's stable
/// `today.log` symlink, falling back to the newest matching rotated file
/// (symlinks need privileges on Windows).
fn resolve_log_file() -> Option<PathBuf> {
    let dir = logs_directory();
    let direct = dir.join("today.log");
    if direct.exists() {
        return Some(direct);
    }
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(&dir).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".log") {
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
    q: Option<String>,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn data(account: Account, Query(query): Query<LogQuery>) -> Response {
    if !account.is_admin() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(path) = resolve_log_file() else {
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
}
