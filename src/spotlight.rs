//! Spotlight (Ctrl+K) backend — a fuzzy search across all browseable pages,
//! Docker containers, SSH keys, firewall rules, secret findings, and operator
//! scripts.
//!
//! GET /spotlight/search?q= — returns JSON `{ items: [...] }`
//!
//! Navigation only. Every item resolves to a URL, including scripts: running one
//! needs a sudo prompt and produces output worth reading, so the palette takes
//! you to the script's card and the run happens there.

use crate::{session::Account, AppState};
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct SpotlightItem {
    kind: &'static str,
    title: String,
    subtitle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
}

impl SpotlightItem {
    fn nav(title: impl Into<String>, subtitle: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            kind: "navigate",
            title: title.into(),
            subtitle: subtitle.into(),
            url: Some(url.into()),
        }
    }
    fn result(
        kind: &'static str,
        title: impl Into<String>,
        subtitle: impl Into<String>,
        url: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            title: title.into(),
            subtitle: subtitle.into(),
            url: Some(url.into()),
        }
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn static_nav() -> Vec<SpotlightItem> {
    vec![
        SpotlightItem::nav("Metrics", "CPU, memory, network charts", "/metrics"),
        SpotlightItem::nav("Docker", "Services, graph, start/stop/restart", "/docker"),
        SpotlightItem::nav("Snapshots", "Capture and restore containers", "/docker/snapshots"),
        SpotlightItem::nav("Proxy", "Reverse-proxy route mapping", "/proxy"),
        SpotlightItem::nav("Certs", "Domains and certificate expiry", "/certs"),
        SpotlightItem::nav("Health", "Uptime monitors and incidents", "/monitors"),
        SpotlightItem::nav("Firewall", "Packet-filter rules and lockouts", "/firewall"),
        SpotlightItem::nav("Secrets", "Secret scanner findings", "/secrets"),
        SpotlightItem::nav("SSH Keys", "Keys, tokens, session audit", "/ssh"),
        SpotlightItem::nav("Backups", "SQLite snapshots, download/restore", "/backups"),
        SpotlightItem::nav("Database", "Browse and query the database", "/database"),
        SpotlightItem::nav("Logs", "Tail and filter application logs", "/logs/view"),
        SpotlightItem::nav("Scripts", "Operator scripts, schedules, run history", "/scripts"),
        SpotlightItem::nav("Audit log", "Who changed what, and from where", "/audit"),
        SpotlightItem::nav("Alerts", "Notification sinks and delivery log", "/alerts"),
        SpotlightItem::nav("Account", "Password, two-factor, active sessions", "/account"),
    ]
}

#[derive(Deserialize)]
struct SearchQuery {
    #[serde(default)]
    q: String,
}

async fn search(State(state): State<AppState>, _account: Account, Query(params): Query<SearchQuery>) -> Response {
    let q = params.q.trim().to_owned();
    let mut items: Vec<SpotlightItem> = Vec::new();

    for item in static_nav() {
        if q.is_empty() || contains_ci(&item.title, &q) || contains_ci(&item.subtitle, &q) {
            items.push(item);
        }
        if items.len() >= 6 && !q.is_empty() {
            break;
        }
    }

    if q.is_empty() {
        return Json(serde_json::json!({ "items": items })).into_response();
    }

    // Operator scripts. These navigate to the script's card rather than running
    // it: a run needs a sudo prompt and has output worth reading, and neither
    // fits in a palette row that closes the moment you pick it.
    for script in &state.config.spotlight_scripts {
        let description = script.description.clone().unwrap_or_default();
        if contains_ci(&script.name, &q) || contains_ci(&description, &q) || contains_ci(&script.id, &q) {
            items.push(SpotlightItem::result(
                "script",
                script.name.clone(),
                if description.is_empty() {
                    script.command.clone()
                } else {
                    description
                },
                format!("/scripts#{}", script.id),
            ));
        }
    }

    let like = format!("%{q}%");

    // SSH keys
    if let Ok(rows) = state
        .db
        .call({
            let like = like.clone();
            move |conn| -> rusqlite::Result<Vec<(String, String)>> {
                let mut stmt = conn.prepare_cached(
                    "SELECT name, fingerprint FROM ssh_key
                     WHERE name LIKE ?1 OR fingerprint LIKE ?1
                     ORDER BY id DESC LIMIT 3",
                )?;
                let rows = stmt
                    .query_map([&like], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            }
        })
        .await
    {
        for (name, fp) in rows {
            items.push(SpotlightItem::result("ssh", name, fp, "/ssh"));
        }
    }

    // Secret findings
    if let Ok(rows) = state
        .db
        .call({
            let like = like.clone();
            move |conn| -> rusqlite::Result<Vec<(String, String)>> {
                let mut stmt = conn.prepare_cached(
                    "SELECT rule, file_path FROM secret_finding
                     WHERE rule LIKE ?1 OR file_path LIKE ?1
                     ORDER BY id DESC LIMIT 3",
                )?;
                let rows = stmt
                    .query_map([&like], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            }
        })
        .await
    {
        for (rule, path) in rows {
            items.push(SpotlightItem::result("secret", rule, path, "/secrets"));
        }
    }

    // Firewall rules
    if let Ok(rows) = state
        .db
        .call({
            let like = like.clone();
            move |conn| -> rusqlite::Result<Vec<(String, String)>> {
                let mut stmt = conn.prepare_cached(
                    "SELECT action, COALESCE(source, '') FROM firewall_rule
                     WHERE action LIKE ?1 OR source LIKE ?1 OR comment LIKE ?1
                     ORDER BY id DESC LIMIT 3",
                )?;
                let rows = stmt
                    .query_map([&like], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            }
        })
        .await
    {
        for (action, source) in rows {
            let subtitle = if source.is_empty() {
                action.clone()
            } else {
                format!("{action} {source}")
            };
            items.push(SpotlightItem::result("firewall", &action, subtitle, "/firewall"));
        }
    }

    // Database sources. Sources, not tables: a table list means introspecting
    // every configured database, which is a privileged read the audit log
    // records per source — doing that on each palette keystroke would turn a
    // launcher into a stream of audited schema dumps. The console's own Ctrl+P
    // jumps to a table, over schema it has already fetched.
    if let Ok(dbs) = crate::dbadmin::list_databases(&state).await {
        for info in dbs.iter().filter(|d| contains_ci(&d.name, &q)).take(5) {
            items.push(SpotlightItem::result(
                "database",
                format!("Open {}", info.name),
                format!("{} database · {}", info.kind, info.size_pretty),
                // The id is config-derived, but it lands in a query string:
                // encode it rather than trusting that no source name ever
                // contains an `&`.
                format!(
                    "/database?source={}",
                    percent_encoding::utf8_percent_encode(&info.id, percent_encoding::NON_ALPHANUMERIC)
                ),
            ));
        }
    }

    // Docker containers
    if let Some(docker) = state.docker() {
        if let Ok(containers) = docker.containers().await {
            for c in containers.iter().take(5) {
                let cname = c
                    .names
                    .as_ref()
                    .and_then(|n| n.first())
                    .map(|n| n.trim_start_matches('/').to_owned())
                    .unwrap_or_default();
                let image = c.image.clone().unwrap_or_default();
                if contains_ci(&cname, &q) || contains_ci(&image, &q) {
                    let state_str = c.state.clone().unwrap_or_default();
                    items.push(SpotlightItem::result(
                        "container",
                        cname,
                        format!("{image} · {state_str}"),
                        "/docker",
                    ));
                }
            }
        }
    }

    Json(serde_json::json!({ "items": items })).into_response()
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/spotlight/search", get(search))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_ci_is_case_insensitive() {
        assert!(contains_ci("Docker Containers", "docker"));
        assert!(contains_ci("Docker Containers", "CONTAINER"));
        assert!(!contains_ci("Metrics", "docker"));
    }

    #[test]
    fn static_nav_has_entries() {
        assert!(!static_nav().is_empty());
    }
}
