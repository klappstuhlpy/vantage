//! Reverse proxy / domain manager.
//!
//! Maps a subdomain to an upstream container/host:port, then renders an nginx
//! `server { … }` block (or a Caddyfile fragment / cloudflared config.yml) and
//! writes it to the configured `proxy.config_dir`. After regenerating, the
//! optional `proxy.reload_command` is run so the proxy picks up the change.

pub mod cf_tunnel;
pub mod cloudflared;
pub mod render;
pub mod routes;
pub mod storage;

pub use render::ProxyKind;
pub use storage::{ProxyRoute, RouteView};

use crate::AppState;
use std::path::PathBuf;

/// Result of regenerating proxy config on disk.
#[derive(Debug, Default, serde::Serialize)]
pub struct ApplyReport {
    pub written: usize,
    pub dir: Option<String>,
    pub reload: Option<String>,
    pub errors: Vec<String>,
}

/// One file's worth of pending change, for the dry-run preview (§11.2). `status`
/// is `added` / `changed` / `removed` / `unchanged`; `diff` is the line-level
/// old→new the client paints.
#[derive(Debug, serde::Serialize)]
pub struct FileChange {
    pub file: String,
    pub status: &'static str,
    pub added: usize,
    pub removed: usize,
    pub diff: Vec<crate::diffutil::DiffLine>,
}

/// What an apply *would* do, computed without touching disk: the old→new diff of
/// every config file this proxy kind would write, plus the managed files it would
/// prune. This is the "Preview changes" step — the operator sees the ruleset
/// change to their reverse proxy before it is live, not after.
pub async fn preview_changes(state: &AppState) -> anyhow::Result<Vec<FileChange>> {
    let kind = configured_kind(state);
    let routes = storage::list_routes(state).await?;

    // API mode has no local file to diff against — the change lands in the
    // Cloudflare tunnel over HTTP. Show the config that would be pushed as a set
    // of additions so the operator can still read it before committing.
    if cloudflared::api_mode(state) {
        let enabled: Vec<&ProxyRoute> = routes.iter().filter(|r| r.enabled).collect();
        let body = render::render_cloudflared_config(
            &enabled,
            state.config.cloudflare.tunnel_name.as_deref(),
            state.config.cloudflare.tunnel_credentials_file.as_deref(),
        );
        let diff = crate::diffutil::diff("", &body);
        let stat = crate::diffutil::stat(&diff);
        return Ok(vec![FileChange {
            file: "Cloudflare tunnel (API)".to_string(),
            status: "changed",
            added: stat.added,
            removed: stat.removed,
            diff,
        }]);
    }

    let Some(dir) = config_dir(state) else {
        // Nothing is written when there is no config dir — so there is nothing to
        // preview, and the page says as much.
        return Ok(Vec::new());
    };

    if kind.is_single_file() {
        let enabled: Vec<&ProxyRoute> = routes.iter().filter(|r| r.enabled).collect();
        let body = render::render_cloudflared_config(
            &enabled,
            state.config.cloudflare.tunnel_name.as_deref(),
            state.config.cloudflare.tunnel_credentials_file.as_deref(),
        );
        let name = render::CLOUDFLARED_FILE;
        let old = tokio::fs::read_to_string(dir.join(name)).await.unwrap_or_default();
        return Ok(vec![change_for(name, &old, &body)]);
    }

    let mut out = Vec::new();
    let mut expected: std::collections::HashSet<String> = std::collections::HashSet::new();

    for route in routes.iter().filter(|r| r.enabled) {
        let file_name = kind.file_name(&route.subdomain);
        let body = render::render(kind, route, Some(&dir));
        let old = tokio::fs::read_to_string(dir.join(&file_name))
            .await
            .unwrap_or_default();
        expected.insert(file_name.clone());
        // htpasswd files are secrets, never their contents in a preview — but a
        // route gaining or losing auth is worth flagging, so note the file's
        // presence in `expected` and leave its body out of the diff.
        if matches!(kind, ProxyKind::Nginx) && route.has_auth() {
            expected.insert(render::htpasswd_file_name(&route.subdomain));
        }
        out.push(change_for(&file_name, &old, &body));
    }

    // Managed files that would be pruned show up as removals — the most important
    // line of a preview is often the route that is about to stop resolving.
    collect_prunes(&dir, kind, &expected, &mut out).await;
    Ok(out)
}

/// A snapshot of the managed proxy config on disk, taken *before* an armed apply
/// so its rollback can put the running proxy back exactly as it was.
///
/// Only the config files Vantage manages are captured — restoring the whole
/// directory would trample files the operator hand-placed. The rollback restores
/// the reachable running state; the DB rows the apply came from are left alone, so
/// after a revert the page correctly shows the routes as saved-but-not-applied
/// again (the pending banner), which is the truthful state.
#[derive(Clone)]
pub struct ConfigSnapshot {
    dir: PathBuf,
    files: std::collections::HashMap<String, String>,
}

/// Reads the managed config on disk into a [`ConfigSnapshot`], or `None` when
/// there is nothing snapshottable — no config dir, or Cloudflare API mode, where
/// the "config" lives in a remote tunnel we cannot capture and restore locally.
/// `None` means the apply arms no revert timer, which the caller surfaces.
pub async fn snapshot_config(state: &AppState) -> Option<ConfigSnapshot> {
    if cloudflared::api_mode(state) {
        return None;
    }
    let dir = config_dir(state)?;
    let kind = configured_kind(state);
    let mut files = std::collections::HashMap::new();
    for name in managed_file_names(&dir, kind).await {
        if let Ok(content) = tokio::fs::read_to_string(dir.join(&name)).await {
            files.insert(name, content);
        }
    }
    Some(ConfigSnapshot { dir, files })
}

/// Restores a [`ConfigSnapshot`] and reloads the proxy — the rollback an armed
/// apply runs when its window closes unconfirmed. Files the apply added (managed,
/// on disk, absent from the snapshot) are removed; snapshotted files are written
/// back verbatim; then the reload command runs so the live proxy follows.
pub async fn restore_snapshot(state: &AppState, snapshot: ConfigSnapshot) {
    let ConfigSnapshot { dir, files } = snapshot;
    let kind = configured_kind(state);
    let mut errors: Vec<String> = Vec::new();

    // Remove managed files the apply created — they were not there when the
    // snapshot was taken, so putting the proxy back means taking them away.
    for name in managed_file_names(&dir, kind).await {
        if !files.contains_key(&name) {
            if let Err(e) = tokio::fs::remove_file(dir.join(&name)).await {
                errors.push(format!("remove {name}: {e}"));
            }
        }
    }
    // Write every snapshotted file back to exactly its prior content.
    for (name, content) in &files {
        if let Err(e) = tokio::fs::write(dir.join(name), content).await {
            errors.push(format!("write {name}: {e}"));
        }
    }

    let reload = run_reload(state).await;
    crate::audit::system_event("proxy.apply.reverted", "revert-timer")
        .detail(serde_json::json!({ "restored": files.len(), "errors": &errors, "reload": reload }))
        .ok(errors.is_empty())
        .record(&state.db)
        .await;
}

/// The names of the config files in `dir` that Vantage considers its own — the
/// set snapshot/restore operate on. For nginx/caddy that is files carrying the
/// `# Managed by Vantage` marker; for cloudflared it is the single config file.
async fn managed_file_names(dir: &std::path::Path, kind: ProxyKind) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    if kind.is_single_file() {
        let name = render::CLOUDFLARED_FILE.to_string();
        if dir.join(&name).exists() {
            out.insert(name);
        }
        return out;
    }
    let ext = match kind {
        ProxyKind::Nginx => "conf",
        ProxyKind::Caddy => "caddy",
        ProxyKind::Cloudflared => return out,
    };
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return out;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(&format!(".{ext}")) {
            continue;
        }
        if let Ok(content) = tokio::fs::read_to_string(entry.path()).await {
            if content.starts_with("# Managed by Vantage") {
                out.insert(name);
            }
        }
    }
    out
}

/// Builds a [`FileChange`] from an old/new pair, classifying the status.
fn change_for(file: &str, old: &str, new: &str) -> FileChange {
    let diff = crate::diffutil::diff(old, new);
    let stat = crate::diffutil::stat(&diff);
    let status = if old.is_empty() {
        "added"
    } else if new.is_empty() {
        "removed"
    } else if stat.is_unchanged() {
        "unchanged"
    } else {
        "changed"
    };
    FileChange {
        file: file.to_string(),
        status,
        added: stat.added,
        removed: stat.removed,
        diff,
    }
}

/// Finds managed files on disk that the next apply would prune, and appends each
/// as a removal. Mirrors [`prune_stale`]'s "# Managed by Vantage" test so the
/// preview and the apply agree on what counts as ours to delete.
async fn collect_prunes(
    dir: &std::path::Path,
    kind: ProxyKind,
    expected: &std::collections::HashSet<String>,
    out: &mut Vec<FileChange>,
) {
    let ext = match kind {
        ProxyKind::Nginx => "conf",
        ProxyKind::Caddy => "caddy",
        ProxyKind::Cloudflared => return,
    };
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(&format!(".{ext}")) || expected.contains(&name) {
            continue;
        }
        if let Ok(contents) = tokio::fs::read_to_string(entry.path()).await {
            if contents.starts_with("# Managed by Vantage") {
                out.push(change_for(&name, &contents, ""));
            }
        }
    }
}

/// The proxy kind configured for this server.
pub fn configured_kind(state: &AppState) -> ProxyKind {
    ProxyKind::parse(state.config.proxy.kind.as_deref())
}

/// The directory proxy config is written to, if any.
pub fn config_dir(state: &AppState) -> Option<PathBuf> {
    state.config.proxy.config_dir.clone()
}

fn log_apply(backend: &str, report: &ApplyReport) {
    if report.errors.is_empty() {
        tracing::info!(
            backend,
            written = report.written,
            reload = report.reload.as_deref().unwrap_or("-"),
            "proxy config regenerated"
        );
    } else {
        tracing::warn!(
            backend,
            written = report.written,
            errors = report.errors.len(),
            detail = %report.errors.join(" | "),
            reload = report.reload.as_deref().unwrap_or("-"),
            "proxy config regenerated with errors"
        );
    }
}

/// Regenerate proxy config for every enabled route and reload the proxy.
pub async fn regenerate_all(state: &AppState) -> anyhow::Result<ApplyReport> {
    let kind = configured_kind(state);

    if cloudflared::api_mode(state) {
        let result = cloudflared::push(state).await;
        match &result {
            Ok(report) => log_apply("cloudflared-api", report),
            Err(e) => tracing::warn!(error = %e, "Cloudflare tunnel API push failed"),
        }
        return result;
    }

    let Some(dir) = config_dir(state) else {
        tracing::debug!("proxy config_dir unset — routes are tracked in the DB only, nothing written");
        return Ok(ApplyReport::default());
    };

    let routes = storage::list_routes(state).await?;

    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        let report = ApplyReport {
            dir: Some(dir.display().to_string()),
            errors: vec![format!("create_dir_all: {e}")],
            ..Default::default()
        };
        tracing::warn!(dir = %dir.display(), error = %e, "could not create proxy config dir");
        return Ok(report);
    }

    if kind.is_single_file() {
        let report = regenerate_cloudflared(state, &dir, &routes).await?;
        log_apply("cloudflared", &report);
        return Ok(report);
    }

    let report = regenerate_files(state, &dir, kind, &routes).await;
    log_apply(kind.label(), &report);
    Ok(report)
}

async fn regenerate_files(
    state: &AppState,
    dir: &std::path::Path,
    kind: ProxyKind,
    routes: &[ProxyRoute],
) -> ApplyReport {
    let mut report = ApplyReport {
        dir: Some(dir.display().to_string()),
        ..Default::default()
    };

    let mut expected: std::collections::HashSet<String> = std::collections::HashSet::new();

    for route in routes {
        if !route.enabled {
            continue;
        }
        let file_name = kind.file_name(&route.subdomain);
        let path = dir.join(&file_name);
        let body = render::render(kind, route, Some(dir));
        match tokio::fs::write(&path, body).await {
            Ok(()) => {
                report.written += 1;
                expected.insert(file_name);
            }
            Err(e) => report.errors.push(format!("{}: {e}", path.display())),
        }

        if matches!(kind, ProxyKind::Nginx) && route.has_auth() {
            if let (Some(user), Some(hash)) = (&route.http_auth_user, &route.http_auth_pass_hash) {
                let ht_name = render::htpasswd_file_name(&route.subdomain);
                let ht_path = dir.join(&ht_name);
                let line = format!("{user}:{hash}\n");
                match tokio::fs::write(&ht_path, line).await {
                    Ok(()) => {
                        expected.insert(ht_name);
                    }
                    Err(e) => report.errors.push(format!("{}: {e}", ht_path.display())),
                }
            }
        }
    }

    prune_stale(dir, kind, &expected, &mut report).await;

    if let Some(out) = run_reload(state).await {
        report.reload = Some(out);
    }
    report
}

async fn regenerate_cloudflared(
    state: &AppState,
    dir: &std::path::Path,
    routes: &[ProxyRoute],
) -> anyhow::Result<ApplyReport> {
    let mut report = ApplyReport {
        dir: Some(dir.display().to_string()),
        ..Default::default()
    };

    let enabled: Vec<&ProxyRoute> = routes.iter().filter(|r| r.enabled).collect();
    let body = render::render_cloudflared_config(
        &enabled,
        state.config.cloudflare.tunnel_name.as_deref(),
        state.config.cloudflare.tunnel_credentials_file.as_deref(),
    );

    let path = dir.join(render::CLOUDFLARED_FILE);
    match tokio::fs::write(&path, body).await {
        Ok(()) => report.written = 1,
        Err(e) => report.errors.push(format!("{}: {e}", path.display())),
    }

    if let Some(out) = run_reload(state).await {
        report.reload = Some(out);
    }
    Ok(report)
}

async fn prune_stale(
    dir: &std::path::Path,
    kind: ProxyKind,
    expected: &std::collections::HashSet<String>,
    report: &mut ApplyReport,
) {
    let ext = match kind {
        ProxyKind::Nginx => "conf",
        ProxyKind::Caddy => "caddy",
        ProxyKind::Cloudflared => return,
    };
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(&format!(".{ext}")) || expected.contains(&name) {
            continue;
        }
        let path = entry.path();
        if let Ok(contents) = tokio::fs::read_to_string(&path).await {
            if contents.starts_with("# Managed by Vantage") {
                if let Err(e) = tokio::fs::remove_file(&path).await {
                    report.errors.push(format!("prune {}: {e}", path.display()));
                }
            }
        }
    }
}

async fn run_reload(state: &AppState) -> Option<String> {
    let cmd = state
        .config
        .proxy
        .reload_command
        .as_deref()
        .filter(|s| !s.trim().is_empty())?;

    let mut command = kls_agent::exec::shell(cmd);

    match command.output().await {
        Ok(o) if o.status.success() => {
            tracing::info!(cmd, "proxy reload command ran");
            Some(format!("{cmd} → ok"))
        }
        Ok(o) => {
            let detail = {
                let err = String::from_utf8_lossy(&o.stderr);
                let err = err.trim();
                if err.is_empty() {
                    String::from_utf8_lossy(&o.stdout).trim().to_string()
                } else {
                    err.to_string()
                }
            };
            tracing::warn!(cmd, status = %o.status, detail = %detail, "proxy reload command failed");
            Some(format!("{cmd} → {} :: {detail}", o.status))
        }
        Err(e) => {
            tracing::warn!(cmd, error = %e, "proxy reload command could not be launched");
            Some(format!("{cmd} → {e}"))
        }
    }
}

#[cfg(test)]
mod preview_tests {
    use super::*;
    use crate::config::Config;

    fn route(subdomain: &str) -> storage::NewRoute {
        storage::NewRoute {
            subdomain: subdomain.to_string(),
            target_host: "app".to_string(),
            target_port: 8080,
            target_scheme: "http".to_string(),
            container: None,
            ssl_managed: false,
            cloudflare_proxied: false,
            http_auth_user: None,
            http_auth_pass_hash: None,
            rate_limit_rps: None,
            access_rules_json: None,
            extra_config: None,
            enabled: true,
        }
    }

    /// The dry-run preview reports an about-to-be-written file as `added`, and the
    /// same file as `unchanged` once it is on disk — the operator sees the change
    /// before Apply, and nothing after it.
    #[tokio::test]
    async fn preview_reports_added_then_unchanged() {
        let dir = std::env::temp_dir().join(format!("vantage-proxy-preview-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = Config::test_default();
        cfg.proxy.config_dir = Some(dir.clone());
        let state = crate::build_state_with(cfg, std::path::Path::new(":memory:"))
            .await
            .expect("state");

        storage::create_route(&state, route("app.example.test")).await.unwrap();

        // Before writing: the route's file does not exist, so it is a pure addition.
        let changes = preview_changes(&state).await.unwrap();
        let file = changes
            .iter()
            .find(|c| c.file.contains("app.example.test"))
            .expect("a file change");
        assert_eq!(file.status, "added");
        assert!(file.added > 0 && file.removed == 0);

        // Apply for real, then the preview shows nothing left to do.
        regenerate_all(&state).await.unwrap();
        let changes = preview_changes(&state).await.unwrap();
        let file = changes
            .iter()
            .find(|c| c.file.contains("app.example.test"))
            .expect("a file change");
        assert_eq!(file.status, "unchanged", "a just-applied route has no pending change");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The revert rollback restores the running config to its pre-apply state:
    /// files the apply *added* are removed and the prior files are put back, so a
    /// proxy change that cut off access can undo itself.
    #[tokio::test]
    async fn a_snapshot_restore_undoes_what_an_apply_added() {
        let dir = std::env::temp_dir().join(format!("vantage-proxy-revert-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = Config::test_default();
        cfg.proxy.config_dir = Some(dir.clone());
        let state = crate::build_state_with(cfg, std::path::Path::new(":memory:"))
            .await
            .expect("state");

        // One route live on disk, then snapshot that state.
        storage::create_route(&state, route("keep.example.test")).await.unwrap();
        regenerate_all(&state).await.unwrap();
        let keep = dir.join("keep.example.test.conf");
        assert!(keep.exists(), "the first route was written");
        let snapshot = snapshot_config(&state).await.expect("a snapshot");

        // Apply a second route — this is the change the timer would roll back.
        storage::create_route(&state, route("added.example.test"))
            .await
            .unwrap();
        regenerate_all(&state).await.unwrap();
        let added = dir.join("added.example.test.conf");
        assert!(added.exists(), "the second route was applied");

        // Restore: the added file goes, the kept file stays exactly as it was.
        restore_snapshot(&state, snapshot).await;
        assert!(!added.exists(), "the applied route's file was rolled back");
        assert!(keep.exists(), "the pre-existing route survived the rollback");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Nothing snapshottable → no timer armed. A config-dir-less install (routes
    /// tracked in the DB only) can't be rolled back, so an armed apply degrades to
    /// a plain one rather than pretending it can undo itself.
    #[tokio::test]
    async fn no_config_dir_means_no_snapshot() {
        let state = crate::build_state_with(Config::test_default(), std::path::Path::new(":memory:"))
            .await
            .expect("state");
        assert!(snapshot_config(&state).await.is_none());
    }

    /// A managed file on disk with no route behind it any more previews as a
    /// removal — the most consequential line of a preview is often the route about
    /// to stop resolving.
    #[tokio::test]
    async fn an_orphaned_managed_file_previews_as_a_removal() {
        let dir = std::env::temp_dir().join(format!("vantage-proxy-prune-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("gone.example.test.conf"), "# Managed by Vantage\nserver {}\n").unwrap();
        let mut cfg = Config::test_default();
        cfg.proxy.config_dir = Some(dir.clone());
        let state = crate::build_state_with(cfg, std::path::Path::new(":memory:"))
            .await
            .expect("state");

        let changes = preview_changes(&state).await.unwrap();
        let removal = changes
            .iter()
            .find(|c| c.file.contains("gone.example.test"))
            .expect("a removal");
        assert_eq!(removal.status, "removed");
        assert!(removal.removed > 0);

        std::fs::remove_dir_all(&dir).ok();
    }
}
