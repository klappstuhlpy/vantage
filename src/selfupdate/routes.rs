//! The self-update surface: read the status, and apply an update.
//!
//! Applying is deliberately narrow. It is offered only for a Compose-managed
//! container running a floating tag, and refuses everything else with the
//! manual command. Recreating a container from `docker inspect` does not
//! faithfully round-trip — capabilities, network aliases, devices, sysctls and
//! restart-policy edges can all be dropped silently — and on a tool that
//! manages a firewall, quietly losing `NET_ADMIN` or the `/etc/ufw` mount
//! produces something that looks healthy and is not. Compose applies a spec
//! declared on disk rather than one guessed from a running object.

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use kls_agent::exec::{HostCommand, Tool};

use crate::account::routes::Sudo;
use crate::audit;
use crate::selfupdate::{helper, status, Deployment, SelfUpdateState, SelfUpdateStatus};
use crate::session::Account;
use crate::AppState;

/// Why an in-place update was refused. Every variant carries the manual path,
/// because a refusal the operator cannot act on is a dead end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyRefusal {
    NotContainerized,
    NoSocket,
    NotIdentified,
    NotCompose,
    PinnedTag,
    NoUpdate,
}

impl ApplyRefusal {
    pub fn message(&self) -> &'static str {
        match self {
            Self::NotContainerized => {
                "Vantage is not running in a container, so it cannot recreate itself. Pull the new release and restart it the way you started it."
            }
            Self::NoSocket => {
                "The Docker socket is not available to Vantage. Run `docker compose pull vantage && docker compose up -d vantage` on the host."
            }
            Self::NotIdentified => {
                "Vantage could not identify its own container to inspect it. Run `docker compose pull vantage && docker compose up -d vantage` on the host."
            }
            Self::NotCompose => {
                "This container was not started by Docker Compose. Recreate it with your usual tooling using the new image."
            }
            Self::PinnedTag => {
                "The compose file pins an exact image tag, so recreating would reinstall the same version. Edit it to the new version, then run `docker compose up -d`."
            }
            Self::NoUpdate => "Vantage is already running the latest release.",
        }
    }

    /// The slug recorded in the audit log, so a refused attempt says why.
    pub fn slug(&self) -> &'static str {
        match self {
            Self::NotContainerized => "not_containerized",
            Self::NoSocket => "no_socket",
            Self::NotIdentified => "not_identified",
            Self::NotCompose => "not_compose",
            Self::PinnedTag => "pinned_tag",
            Self::NoUpdate => "no_update",
        }
    }
}

/// Whether an image reference names an exact version rather than a floating tag.
///
/// `docker compose up` applies whatever the compose file says, so an operator
/// pinned to `:0.4.2` would get a "success" that changed nothing. Detecting the
/// pin and refusing is the honest answer.
///
/// Only the portion after the last `/` is examined, so a registry host's port
/// (`registry:5000/owner/app`) is not mistaken for a tag.
pub fn is_pinned_tag(image: &str) -> bool {
    let after_host = image.rsplit('/').next().unwrap_or(image);
    match after_host.rsplit_once(':') {
        Some((_, tag)) => tag
            .trim_start_matches('v')
            .split('.')
            .next()
            .is_some_and(|first| !first.is_empty() && first.parse::<u64>().is_ok()),
        None => false,
    }
}

/// Docker's Go templates render a missing label as the literal `<no value>`.
fn label_missing(s: &str) -> bool {
    s.is_empty() || s == "<no value>"
}

/// The container id carried by Docker's own per-container bind mounts
/// (`/var/lib/docker/containers/<id>/hosts` and friends appear in
/// `/proc/self/mountinfo` verbatim).
///
/// `$HOSTNAME` is *not* a reliable substitute: Vantage's compose file uses
/// `network_mode: host`, which shares the host's UTS namespace, so the
/// container's hostname is the machine's name and `docker inspect` on it finds
/// nothing.
fn container_id_from_mountinfo(mountinfo: &str) -> Option<String> {
    mountinfo
        .split("/containers/")
        .skip(1)
        .filter_map(|rest| rest.split('/').next())
        .find(|id| id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_string)
}

/// Resolves the running deployment, or the reason it cannot be updated in place.
pub async fn detect_deployment() -> Result<Deployment, ApplyRefusal> {
    if !std::path::Path::new("/.dockerenv").exists() {
        return Err(ApplyRefusal::NotContainerized);
    }
    if !std::path::Path::new("/var/run/docker.sock").exists() {
        return Err(ApplyRefusal::NoSocket);
    }

    // The mount table first; `$HOSTNAME` (the short id, when Docker owns the UTS
    // namespace) only as a fallback.
    let id = std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .as_deref()
        .and_then(container_id_from_mountinfo)
        .or_else(|| std::env::var("HOSTNAME").ok())
        .ok_or(ApplyRefusal::NotIdentified)?;

    let out = HostCommand::new(Tool::Docker)
        .args([
            "inspect",
            "--format",
            "{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}\t{{index .Config.Labels \"com.docker.compose.service\"}}\t{{.Config.Image}}",
            id.as_str(),
        ])
        .output()
        .await
        .map_err(|_| ApplyRefusal::NoSocket)?;

    // The socket answered; it simply did not know this id.
    if !out.status.success() {
        return Err(ApplyRefusal::NotIdentified);
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut parts = text.trim().split('\t');
    let project_dir = parts.next().unwrap_or("").trim().to_string();
    let service = parts.next().unwrap_or("").trim().to_string();
    let image = parts.next().unwrap_or("").trim().to_string();

    if label_missing(&project_dir) || label_missing(&service) {
        return Err(ApplyRefusal::NotCompose);
    }
    if is_pinned_tag(&image) {
        return Err(ApplyRefusal::PinnedTag);
    }

    Ok(Deployment {
        project_dir,
        service,
        container: id,
    })
}

/// The status read. Admin-only, but not sudo — knowing which version is running
/// is not a privileged action.
async fn get_status(account: Account) -> Result<Json<SelfUpdateStatus>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(status()))
}

/// One helper so every refusal is audited identically. A refused self-update
/// attempt is precisely the kind of event the audit log exists for.
async fn refuse(state: &AppState, account: &Account, r: ApplyRefusal) -> (StatusCode, String) {
    audit::event("selfupdate.apply", account)
        .detail(serde_json::json!({ "refused": r.slug() }))
        .failed()
        .record(&state.db)
        .await;
    (StatusCode::CONFLICT, r.message().to_string())
}

async fn apply(State(state): State<AppState>, sudo: Sudo) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let account = sudo.account;

    let current = status();
    if current.state != SelfUpdateState::UpdateAvailable {
        return Err(refuse(&state, &account, ApplyRefusal::NoUpdate).await);
    }

    // Read the target from the same snapshot the availability check used: a
    // background refresh landing between the two reads would otherwise let this
    // apply a version nobody checked.
    let Some(target) = current.latest.map(|r| r.version) else {
        return Err(refuse(&state, &account, ApplyRefusal::NoUpdate).await);
    };

    let deployment = match detect_deployment().await {
        Ok(d) => d,
        Err(r) => return Err(refuse(&state, &account, r).await),
    };

    audit::event("selfupdate.apply", &account)
        .target(&target)
        .detail(serde_json::json!({
            "from": crate::VERSION,
            "service": deployment.service,
            "project_dir": deployment.project_dir,
            "container": deployment.container,
        }))
        .record(&state.db)
        .await;

    // The update did not start: say so plainly rather than reporting a restart
    // that is not happening, because the operator's next move depends on it.
    helper::launch(&deployment, &target)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "started": true,
        "version": target,
        "note": "Vantage is restarting into the new version. This page will reconnect on its own.",
    })))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/updates/self", get(get_status))
        .route("/updates/apply", post(apply))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_refusal_explains_itself() {
        for r in [
            ApplyRefusal::NotContainerized,
            ApplyRefusal::NoSocket,
            ApplyRefusal::NotIdentified,
            ApplyRefusal::NotCompose,
            ApplyRefusal::PinnedTag,
            ApplyRefusal::NoUpdate,
        ] {
            assert!(!r.message().is_empty(), "{r:?} has no message");
            assert!(!r.slug().is_empty(), "{r:?} has no audit slug");
        }
    }

    #[test]
    fn refusal_slugs_are_distinct() {
        // The audit log distinguishes them; two variants sharing a slug would
        // silently merge two different refusals into one story.
        let slugs = [
            ApplyRefusal::NotContainerized.slug(),
            ApplyRefusal::NoSocket.slug(),
            ApplyRefusal::NotIdentified.slug(),
            ApplyRefusal::NotCompose.slug(),
            ApplyRefusal::PinnedTag.slug(),
            ApplyRefusal::NoUpdate.slug(),
        ];
        let mut seen = slugs.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), slugs.len(), "duplicate audit slug");
    }

    #[test]
    fn a_pinned_tag_is_detected() {
        assert!(is_pinned_tag("ghcr.io/klappstuhlpy/vantage:0.4.2"));
        assert!(is_pinned_tag("ghcr.io/klappstuhlpy/vantage:v0.4.2"));
        assert!(!is_pinned_tag("ghcr.io/klappstuhlpy/vantage:latest"));
        assert!(!is_pinned_tag("ghcr.io/klappstuhlpy/vantage:edge"));
        assert!(!is_pinned_tag("ghcr.io/klappstuhlpy/vantage"));
    }

    #[test]
    fn a_registry_port_is_not_mistaken_for_a_tag() {
        // `registry:5000/owner/vantage` has a colon, but no tag.
        assert!(!is_pinned_tag("registry.example.com:5000/owner/vantage"));
        assert!(is_pinned_tag("registry.example.com:5000/owner/vantage:1.2.3"));
    }

    #[test]
    fn the_container_id_is_read_from_the_mount_table() {
        // A real line, as Docker writes it with `network_mode: host` — where
        // $HOSTNAME is the machine's name and would inspect to nothing.
        let id = "a".repeat(64);
        let mountinfo = format!(
            "641 640 0:75 / /proc rw shared:325 - proc proc rw\n\
             650 640 259:2 /var/lib/docker/containers/{id}/hosts /etc/hosts rw - ext4 /dev/nvme0n1p2 rw\n"
        );
        assert_eq!(container_id_from_mountinfo(&mountinfo).as_deref(), Some(id.as_str()));

        // Outside a container there is no such mount: the caller must fall back.
        assert_eq!(
            container_id_from_mountinfo("641 640 0:75 / /proc rw - proc proc rw\n"),
            None
        );
        // A `/containers/` path that is not an id must not be mistaken for one.
        assert_eq!(
            container_id_from_mountinfo("1 2 0:3 / /srv/containers/data rw - ext4 x rw\n"),
            None
        );
    }

    #[test]
    fn a_missing_compose_label_is_recognised() {
        assert!(label_missing(""));
        assert!(label_missing("<no value>"));
        assert!(!label_missing("/srv/vantage"));
    }
}
