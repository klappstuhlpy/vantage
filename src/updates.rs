//! Container image update detection.
//!
//! For every configured Docker service, we ask the image's registry what
//! digest it currently serves for the running tag (Registry v2 HTTP API) and
//! compare it against the digest the local image was pulled at. A mismatch
//! means `docker pull` would fetch something new — i.e. an update is available.
//! This is the same mechanism diun / What's-Up-Docker use, implemented in a
//! few HTTP calls so no extra binary or SDK is required.
//!
//! Results live in memory (derivable on demand, so nothing is persisted) and
//! are refreshed by a background task. The Docker page renders a badge from
//! them, and a newly-discovered update fans out an alert.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Context};
use serde::Serialize;
use time::OffsetDateTime;

use crate::config::ServiceConfig;
use crate::AppState;

/// Default hours between background update checks when unconfigured.
const DEFAULT_INTERVAL_HOURS: u64 = 12;

/// Media types we accept for a manifest HEAD — manifest lists (multi-arch)
/// first, then single manifests, in both Docker and OCI flavours. The digest
/// the daemon pins on `docker pull` is the one for whichever of these the
/// registry returns, so matching the same set keeps the comparison honest.
const MANIFEST_ACCEPT: &str = "application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.oci.image.index.v1+json, \
     application/vnd.oci.image.manifest.v1+json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    /// Local digest matches the registry — nothing to pull.
    UpToDate,
    /// The registry serves a newer digest for this tag.
    UpdateAvailable,
    /// Couldn't determine (local-only image, private registry, network error).
    Unknown,
}

/// The result of checking one service's image.
#[derive(Debug, Clone, Serialize)]
pub struct ImageUpdate {
    /// Configured service name.
    pub service: String,
    /// Image reference inspected (e.g. `nginx:latest`).
    pub image: String,
    pub state: UpdateState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_digest: Option<String>,
    /// When the check ran (unix seconds).
    pub checked_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ─── In-memory result store ─────────────────────────────────────────────────

/// The latest image-update results, keyed by service name. This is derived data
/// (rebuilt on demand by the background checker), so it lives in memory.
fn store() -> &'static std::sync::Mutex<HashMap<String, ImageUpdate>> {
    static STORE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, ImageUpdate>>> = std::sync::OnceLock::new();
    STORE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Replaces the stored image-update results (called by the background checker
/// after each run).
pub fn set_image_updates(updates: HashMap<String, ImageUpdate>) {
    if let Ok(mut guard) = store().lock() {
        *guard = updates;
    }
}

/// A snapshot clone of the current image-update map, keyed by service name.
pub fn image_updates_map() -> HashMap<String, ImageUpdate> {
    store().lock().map(|g| g.clone()).unwrap_or_default()
}

/// The current image-update status for one service, if checked.
#[allow(dead_code)]
pub fn image_update(service: &str) -> Option<ImageUpdate> {
    store().lock().ok().and_then(|g| g.get(service).cloned())
}

// ─── Image reference parsing ────────────────────────────────────────────────

/// A parsed image reference resolved to a concrete registry host, repository,
/// and tag (digests are ignored — we compare by tag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// Registry host to query, e.g. `registry-1.docker.io`, `ghcr.io`.
    pub registry: String,
    /// Fully-qualified repository, e.g. `library/nginx`, `owner/app`.
    pub repository: String,
    pub tag: String,
}

/// Parses a Docker image reference, applying Docker Hub's defaults
/// (`library/` namespace, `latest` tag, `registry-1.docker.io` host).
///
/// Returns `None` for an empty/malformed reference.
pub fn parse_image_ref(image: &str) -> Option<ImageRef> {
    // Drop any pinned digest — we resolve the tag against the registry.
    let image = image.split('@').next().unwrap_or(image).trim();
    if image.is_empty() {
        return None;
    }

    // A leading path component is a registry host only if it looks like one
    // (contains a dot or port colon, or is localhost). Otherwise it's part of
    // a Docker Hub repository (`owner/app`).
    let (registry_part, remainder) = match image.split_once('/') {
        Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => {
            (Some(first.to_string()), rest)
        }
        _ => (None, image),
    };

    // Split a trailing `:tag` (a colon with no slash after it — otherwise it's
    // part of the path and there is no tag).
    let (repo, tag) = match remainder.rsplit_once(':') {
        Some((r, t)) if !t.contains('/') && !t.is_empty() => (r.to_string(), t.to_string()),
        _ => (remainder.to_string(), "latest".to_string()),
    };
    if repo.is_empty() {
        return None;
    }

    let is_docker_hub = registry_part.is_none();
    let registry = if is_docker_hub {
        "registry-1.docker.io".to_string()
    } else {
        registry_part.unwrap()
    };
    let repository = if is_docker_hub && !repo.contains('/') {
        format!("library/{repo}")
    } else {
        repo
    };

    Some(ImageRef {
        registry,
        repository,
        tag,
    })
}

/// Splits a `WWW-Authenticate` parameter list on top-level commas, respecting
/// quoted values (a Bearer `scope` can itself contain commas, e.g.
/// `repository:foo:pull,push`).
fn split_top_level_commas(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut buf = String::new();
    let mut in_quotes = false;
    for c in input.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                buf.push(c);
            }
            ',' if !in_quotes => {
                parts.push(std::mem::take(&mut buf));
            }
            _ => buf.push(c),
        }
    }
    if !buf.is_empty() {
        parts.push(buf);
    }
    parts
}

/// Parses a `Bearer realm="…",service="…",scope="…"` challenge into a map.
fn parse_www_authenticate(header: &str) -> HashMap<String, String> {
    let header = header.trim();
    let header = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .unwrap_or(header);
    let mut map = HashMap::new();
    for part in split_top_level_commas(header) {
        if let Some((k, v)) = part.split_once('=') {
            let v = v.trim().trim_matches('"');
            map.insert(k.trim().to_ascii_lowercase(), v.to_string());
        }
    }
    map
}

// ─── Registry queries ───────────────────────────────────────────────────────

/// Fetches a bearer token for a registry challenge. The realm + service come
/// from the challenge; the scope falls back to a read-only repository scope if
/// the registry didn't specify one.
async fn fetch_token(client: &reqwest::Client, challenge: &str, image: &ImageRef) -> anyhow::Result<String> {
    let params = parse_www_authenticate(challenge);
    let realm = params.get("realm").context("auth challenge missing realm")?;
    let scope = params
        .get("scope")
        .cloned()
        .unwrap_or_else(|| format!("repository:{}:pull", image.repository));

    let mut query: Vec<(&str, String)> = vec![("scope", scope)];
    if let Some(service) = params.get("service") {
        query.push(("service", service.clone()));
    }

    let body: serde_json::Value = client
        .get(realm.as_str())
        .query(&query)
        .send()
        .await
        .context("token request failed")?
        .error_for_status()
        .context("token endpoint returned an error")?
        .json()
        .await
        .context("token response was not JSON")?;

    body.get("token")
        .or_else(|| body.get("access_token"))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("token response had no token field"))
}

/// Returns the digest the registry currently serves for the image's tag
/// (the `Docker-Content-Digest` of the manifest). Handles anonymous pull
/// auth (Docker Hub, GHCR) transparently.
async fn remote_digest(client: &reqwest::Client, image: &ImageRef) -> anyhow::Result<String> {
    let url = format!(
        "https://{}/v2/{}/manifests/{}",
        image.registry, image.repository, image.tag
    );

    let resp = client
        .head(url.as_str())
        .header(reqwest::header::ACCEPT, MANIFEST_ACCEPT)
        .send()
        .await
        .context("manifest HEAD failed")?;

    let resp = if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        let challenge = resp
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("registry requires auth but sent no challenge"))?;
        let token = fetch_token(client, &challenge, image).await?;
        client
            .head(url.as_str())
            .header(reqwest::header::ACCEPT, MANIFEST_ACCEPT)
            .bearer_auth(token)
            .send()
            .await
            .context("authenticated manifest HEAD failed")?
    } else {
        resp
    };

    if !resp.status().is_success() {
        anyhow::bail!("registry returned {} for {}", resp.status(), url);
    }

    resp.headers()
        .get("docker-content-digest")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("manifest response had no Docker-Content-Digest header"))
}

// ─── Per-service check ──────────────────────────────────────────────────────

/// Builds an `ImageUpdate` in the `Unknown` state with an explanatory message.
fn unknown(service: &str, image: &str, error: impl Into<String>) -> ImageUpdate {
    ImageUpdate {
        service: service.to_string(),
        image: image.to_string(),
        state: UpdateState::Unknown,
        current_digest: None,
        latest_digest: None,
        checked_at: OffsetDateTime::now_utc().unix_timestamp(),
        error: Some(error.into()),
    }
}

/// Checks a single service's running image against its registry.
pub async fn check_service(state: &AppState, service: &ServiceConfig) -> ImageUpdate {
    let Some(docker) = state.docker() else {
        return unknown(&service.name, "", "Docker socket not available");
    };

    // Resolve the image reference the container is actually running.
    let image = match docker.inspect(&service.identifier).await {
        Ok(info) => info.config.and_then(|c| c.image).unwrap_or_default(),
        Err(e) => return unknown(&service.name, "", format!("inspect failed: {e}")),
    };
    if image.is_empty() {
        return unknown(&service.name, "", "container has no image");
    }

    let Some(image_ref) = parse_image_ref(&image) else {
        return unknown(&service.name, &image, "unparseable image reference");
    };

    // Local repo digests (what the image was pulled at).
    let local_digests = match docker.image_repo_digests(&image).await {
        Ok(d) => d,
        Err(e) => return unknown(&service.name, &image, format!("image inspect failed: {e}")),
    };
    if local_digests.is_empty() {
        return unknown(&service.name, &image, "image has no registry digest (built locally?)");
    }

    // Registry's current digest for this tag.
    let latest = match remote_digest(&state.client, &image_ref).await {
        Ok(d) => d,
        Err(e) => return unknown(&service.name, &image, e.to_string()),
    };

    // Local digests look like `repo@sha256:…`; compare the digest portion.
    let current = local_digests
        .iter()
        .find_map(|d| d.rsplit_once('@').map(|(_, dig)| dig.to_string()));
    let up_to_date = local_digests
        .iter()
        .any(|d| d.rsplit_once('@').map(|(_, dig)| dig == latest).unwrap_or(false));

    ImageUpdate {
        service: service.name.clone(),
        image,
        state: if up_to_date {
            UpdateState::UpToDate
        } else {
            UpdateState::UpdateAvailable
        },
        current_digest: current,
        latest_digest: Some(latest),
        checked_at: OffsetDateTime::now_utc().unix_timestamp(),
        error: None,
    }
}

/// Re-checks one configured service's image on demand, updating just its stored
/// entry. Returns the fresh result, or `None` if no service by that name is
/// configured. Unlike [`run_check`], this fires no alert — the operator is
/// looking at the screen that asked for it.
pub async fn check_one(state: &AppState, service_name: &str) -> Option<ImageUpdate> {
    let service = state.config.services.iter().find(|s| s.name == service_name)?.clone();
    let update = check_service(state, &service).await;
    if let Ok(mut guard) = store().lock() {
        guard.insert(update.service.clone(), update.clone());
    }
    Some(update)
}

/// Runs a check across every configured service, stores the result, and fires
/// an alert for any image that went from "no update" to "update available"
/// since the previous run.
pub async fn run_check(state: &AppState) {
    let services = state.config.services.clone();
    if services.is_empty() {
        return;
    }
    let previous = image_updates_map();
    let mut results: HashMap<String, ImageUpdate> = HashMap::new();
    let mut newly_available: Vec<ImageUpdate> = Vec::new();

    for service in &services {
        let update = check_service(state, service).await;
        let was_available = previous
            .get(&service.name)
            .map(|p| p.state == UpdateState::UpdateAvailable)
            .unwrap_or(false);
        if update.state == UpdateState::UpdateAvailable && !was_available {
            newly_available.push(update.clone());
        }
        results.insert(service.name.clone(), update);
    }

    set_image_updates(results);

    if !newly_available.is_empty() && state.has_any_alert_sink() {
        let fields: Vec<serde_json::Value> = newly_available
            .iter()
            .map(|u| {
                serde_json::json!({
                    "name": u.service,
                    "value": format!("`{}`", u.image),
                    "inline": false,
                })
            })
            .collect();
        let count = newly_available.len();
        state.send_alert(serde_json::json!({
            "username": "klappstuhl",
            "embeds": [{
                "title": format!("\u{1f4e6} {count} container image update{} available", if count == 1 { "" } else { "s" }),
                "description": "Newer images are published for these services. Pull + recreate from [/admin/docker](/admin/docker).",
                "color": 0x10b981u32,
                "fields": fields,
            }]
        }));
    }
}

/// Background task: refresh image-update status on an interval. The first
/// check runs shortly after start-up (so the badge appears without waiting a
/// full interval). No-op when Docker is unavailable or checks are disabled
/// (`update_check_interval_hours = 0`).
/// The update-check interval in hours `config.json` (or the default) asks for.
pub fn config_interval_hours(state: &AppState) -> u64 {
    state
        .config
        .update_check_interval_hours
        .unwrap_or(DEFAULT_INTERVAL_HOURS)
}

/// The *effective* update-check interval in hours (0 = disabled): a dashboard
/// override wins over `config.json`, which wins over the built-in default.
pub fn check_interval_hours(state: &AppState) -> u64 {
    state
        .settings
        .get()
        .update_check_interval_hours
        .or(state.config.update_check_interval_hours)
        .unwrap_or(DEFAULT_INTERVAL_HOURS)
}

/// How long to idle before re-checking while update checks are disabled, so the
/// settings page can turn them on without a restart.
const DISABLED_RECHECK_SECS: u64 = 3600;

pub fn spawn_update_checker(state: AppState) {
    // Docker absence is decided at boot and cannot change at runtime, so it is
    // still an early return. The interval, by contrast, is read live each loop.
    if state.docker().is_none() {
        return;
    }
    tokio::spawn(async move {
        // Small initial delay so this doesn't pile onto everything else at boot.
        tokio::time::sleep(Duration::from_secs(45)).await;
        loop {
            let hours = check_interval_hours(&state);
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
    fn parses_docker_hub_official_image() {
        let r = parse_image_ref("nginx").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/nginx");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parses_docker_hub_user_image_with_tag() {
        let r = parse_image_ref("grafana/grafana:10.2.0").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "grafana/grafana");
        assert_eq!(r.tag, "10.2.0");
    }

    #[test]
    fn parses_ghcr_image() {
        let r = parse_image_ref("ghcr.io/owner/app:v1.2.3").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "owner/app");
        assert_eq!(r.tag, "v1.2.3");
    }

    #[test]
    fn parses_registry_with_port() {
        let r = parse_image_ref("registry.example.com:5000/team/svc:dev").unwrap();
        assert_eq!(r.registry, "registry.example.com:5000");
        assert_eq!(r.repository, "team/svc");
        assert_eq!(r.tag, "dev");
    }

    #[test]
    fn strips_pinned_digest() {
        let r = parse_image_ref("nginx@sha256:deadbeef").unwrap();
        assert_eq!(r.repository, "library/nginx");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_image_ref("").is_none());
        assert!(parse_image_ref("   ").is_none());
    }

    #[test]
    fn parses_www_authenticate_with_comma_in_scope() {
        let challenge = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull,push""#;
        let map = parse_www_authenticate(challenge);
        assert_eq!(map.get("realm").unwrap(), "https://auth.docker.io/token");
        assert_eq!(map.get("service").unwrap(), "registry.docker.io");
        assert_eq!(map.get("scope").unwrap(), "repository:library/nginx:pull,push");
    }
}
