//! Read-only Docker introspection layer (Seam A).
//!
//! Wraps the bollard async Docker client with a 60-second TTL cache on the
//! three list calls (containers, networks, volumes) so the graph endpoint
//! doesn't hammer the socket on every request.
//!
//! The client is optional — [`DockerClient::connect`] returns `None` when
//! the Docker socket is unavailable (e.g. dev machine without Docker, or the
//! socket path doesn't exist).  Routes that need Docker gracefully degrade
//! to an empty graph rather than 500-ing.
//!
//! This is the first **Seam A** runtime handle to land in Vantage's
//! `AppState`. Reads (list/inspect/graph/events) go through bollard here, as do
//! the three *mutating* snapshot calls (`commit_snapshot`/`run_snapshot`/
//! `delete_image` — socket-API operations with no compose analogue). The service
//! actions (start/stop/restart/pull/recreate) instead shell out to the `docker`
//! CLI through the `kls-agent` boundary, since they support compose. The
//! image-update digest read (`image_repo_digests`) is still held back — it joins
//! with the updates slice, its only caller.
pub mod routes; // HTTP handlers for this admin feature (see main.rs router)

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use bollard::{
    container::{InspectContainerOptions, ListContainersOptions},
    models::{ContainerInspectResponse, ContainerSummary, Network, PortTypeEnum, Volume},
    network::ListNetworksOptions,
    system::EventsOptions,
    volume::ListVolumesOptions,
    Docker,
};
use futures_util::StreamExt;
use serde::Serialize;

use crate::cached::TimedCachedValue;
use crate::AppState;

// ─── Client ──────────────────────────────────────────────────────────────────

/// Cache TTL for list calls (containers / networks / volumes).
const CACHE_TTL: Duration = Duration::from_secs(60);

pub struct DockerClient {
    docker: Docker,
    cached_containers: TimedCachedValue<Vec<ContainerSummary>>,
    cached_networks: TimedCachedValue<Vec<Network>>,
    cached_volumes: TimedCachedValue<Vec<Volume>>,
}

impl DockerClient {
    /// Attempt to connect to the local Docker socket.
    /// Returns `None` if Docker is not reachable.
    pub fn connect() -> Option<Arc<Self>> {
        let docker = Docker::connect_with_local_defaults()
            .inspect_err(|e| tracing::info!(error = %e, "Docker socket not available — graph disabled"))
            .ok()?;

        Some(Arc::new(Self {
            docker,
            cached_containers: TimedCachedValue::new(CACHE_TTL),
            cached_networks: TimedCachedValue::new(CACHE_TTL),
            cached_volumes: TimedCachedValue::new(CACHE_TTL),
        }))
    }

    // ─── Cached list calls ────────────────────────────────────────────────

    /// All containers (including stopped). 60 s cache.
    pub async fn containers(&self) -> anyhow::Result<Vec<ContainerSummary>> {
        if let Some(guard) = self.cached_containers.get().await {
            return Ok(guard.clone());
        }
        let containers = self
            .docker
            .list_containers(Some(ListContainersOptions::<String> {
                all: true,
                ..Default::default()
            }))
            .await
            .context("list_containers")?;
        let _ = self.cached_containers.set(containers.clone()).await;
        Ok(containers)
    }

    /// All networks. 60 s cache.
    pub async fn networks(&self) -> anyhow::Result<Vec<Network>> {
        if let Some(guard) = self.cached_networks.get().await {
            return Ok(guard.clone());
        }
        let networks = self
            .docker
            .list_networks(None::<ListNetworksOptions<String>>)
            .await
            .context("list_networks")?;
        let _ = self.cached_networks.set(networks.clone()).await;
        Ok(networks)
    }

    /// All volumes. 60 s cache.
    pub async fn volumes(&self) -> anyhow::Result<Vec<Volume>> {
        if let Some(guard) = self.cached_volumes.get().await {
            return Ok(guard.clone());
        }
        let resp = self
            .docker
            .list_volumes(None::<ListVolumesOptions<String>>)
            .await
            .context("list_volumes")?;
        let volumes = resp.volumes.unwrap_or_default();
        let _ = self.cached_volumes.set(volumes.clone()).await;
        Ok(volumes)
    }

    /// Full inspect of a single container. Not cached — used on-demand.
    pub async fn inspect(&self, id: &str) -> anyhow::Result<ContainerInspectResponse> {
        self.docker
            .inspect_container(id, None::<InspectContainerOptions>)
            .await
            .context("inspect_container")
    }

    // ─── Snapshot operations ──────────────────────────────────────────────
    //
    // These are the only *mutating* Docker calls Vantage makes over bollard.
    // (The service actions — start/stop/restart/pull/recreate — shell out to the
    // `docker` CLI through the kls-agent boundary because they support compose;
    // commit/create/remove-image have no compose analogue and are cleanest over
    // the socket API, matching the monolith.)

    /// Commit a container to a new image. Returns the full image reference
    /// `klappstuhl-snapshot:<tag>`.
    pub async fn commit_snapshot(&self, container_id: &str, tag: &str) -> anyhow::Result<String> {
        use bollard::container::Config;
        use bollard::image::CommitContainerOptions;

        let full_ref = format!("klappstuhl-snapshot:{tag}");
        self.docker
            .commit_container(
                CommitContainerOptions {
                    container: container_id.to_owned(),
                    repo: "klappstuhl-snapshot".to_owned(),
                    tag: tag.to_owned(),
                    comment: String::new(),
                    author: String::new(),
                    pause: true,
                    changes: None,
                },
                Config::<String>::default(),
            )
            .await
            .context("commit_container")?;
        Ok(full_ref)
    }

    /// Remove an image by its full reference (e.g. `klappstuhl-snapshot:abc`).
    pub async fn delete_image(&self, name: &str) -> anyhow::Result<()> {
        use bollard::image::RemoveImageOptions;

        self.docker
            .remove_image(
                name,
                Some(RemoveImageOptions {
                    force: true,
                    noprune: false,
                }),
                None,
            )
            .await
            .context("remove_image")?;
        self.invalidate().await;
        Ok(())
    }

    /// Create and immediately start a container from `image` named `name`.
    /// Returns the new container ID.
    pub async fn run_snapshot(&self, image: &str, name: &str) -> anyhow::Result<String> {
        use bollard::container::{Config, CreateContainerOptions, StartContainerOptions};

        let created = self
            .docker
            .create_container(
                Some(CreateContainerOptions {
                    name: name.to_owned(),
                    platform: None,
                }),
                Config {
                    image: Some(image.to_owned()),
                    ..Default::default()
                },
            )
            .await
            .context("create_container")?;
        self.docker
            .start_container(&created.id, None::<StartContainerOptions<String>>)
            .await
            .context("start_container")?;
        self.invalidate().await;
        Ok(created.id)
    }

    /// Returns the list of `RepoDigests` for the named image (e.g.
    /// `["nginx@sha256:abc…"]`). Empty when the image was built locally and
    /// never pulled/pushed (no registry digest to compare against). Used by
    /// the image-update checker to compare the pulled digest against what the
    /// registry currently serves for the same tag.
    pub async fn image_repo_digests(&self, image: &str) -> anyhow::Result<Vec<String>> {
        let info = self.docker.inspect_image(image).await.context("inspect_image")?;
        Ok(info.repo_digests.unwrap_or_default())
    }

    /// Invalidate all three caches (called after any state-changing action).
    pub async fn invalidate(&self) {
        self.cached_containers.invalidate().await;
        self.cached_networks.invalidate().await;
        self.cached_volumes.invalidate().await;
    }
}

// ─── Graph types ─────────────────────────────────────────────────────────────
//
// These are the serialisable types the graph endpoint returns. Defined here so
// the docker module owns the full data model.

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum NodeKind {
    Container,
    Network,
    Volume,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    #[serde(flatten)]
    pub kind: NodeKind,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Container belongs to a network.
    Network,
    /// Container mounts a volume.
    Volume,
    /// compose `depends_on` relationship.
    DependsOn,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    #[serde(rename = "type")]
    pub kind: EdgeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DockerGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

// ─── Graph builder ───────────────────────────────────────────────────────────

impl DockerClient {
    /// Build the full dependency graph from cached list data.
    pub async fn build_graph(&self) -> anyhow::Result<DockerGraph> {
        let containers = self.containers().await?;
        let networks = self.networks().await?;
        let volumes = self.volumes().await?;

        let mut nodes: Vec<GraphNode> = Vec::new();
        let mut edges: Vec<GraphEdge> = Vec::new();

        // Network names referenced by at least one container. The list-networks
        // summary often reports an empty `containers` map, so we can't rely on
        // it to decide whether a built-in network (bridge/host/none) is in use.
        // Tracking references here lets us always emit a node for any network a
        // container is attached to, preventing dangling edges in the graph.
        let referenced_networks: HashSet<String> = containers
            .iter()
            .filter_map(|c| c.network_settings.as_ref())
            .filter_map(|ns| ns.networks.as_ref())
            .flat_map(|nets| nets.keys().cloned())
            .collect();

        // ── Container nodes ───────────────────────────────────────────

        // Map from compose service name → container node id for depends_on edges.
        let mut service_to_node: HashMap<String, String> = HashMap::new();

        for c in &containers {
            let id = c.id.clone().unwrap_or_default();
            let short_id = id.get(..12).unwrap_or(&id).to_owned();

            let name = c
                .names
                .as_ref()
                .and_then(|n| n.first())
                .map(|n| n.trim_start_matches('/').to_owned())
                .unwrap_or_else(|| short_id.clone());

            let labels = c.labels.clone().unwrap_or_default();
            let compose_service = labels.get("com.docker.compose.service").cloned();
            let compose_project = labels.get("com.docker.compose.project").cloned();

            // Exposed ports summary list
            let ports: Vec<String> = c
                .ports
                .as_ref()
                .map(|ps| {
                    ps.iter()
                        .map(|p| {
                            let proto = match p.typ {
                                Some(PortTypeEnum::TCP) => "tcp",
                                Some(PortTypeEnum::UDP) => "udp",
                                Some(PortTypeEnum::SCTP) => "sctp",
                                _ => "tcp",
                            };
                            match (p.public_port, p.private_port) {
                                (Some(pub_port), priv_port) => format!("{}:{}/{}", pub_port, priv_port, proto),
                                (None, priv_port) => format!("{}/{}", priv_port, proto),
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            let node_id = format!("container:{short_id}");

            if let Some(svc) = &compose_service {
                service_to_node.insert(svc.clone(), node_id.clone());
            }

            nodes.push(GraphNode {
                id: node_id.clone(),
                label: name.clone(),
                kind: NodeKind::Container,
                data: serde_json::json!({
                    "full_id":       id,
                    "image":         c.image.clone().unwrap_or_default(),
                    "state":         c.state.clone().unwrap_or_default(),
                    "status":        c.status.clone().unwrap_or_default(),
                    "ports":         ports,
                    "compose_service": compose_service,
                    "compose_project": compose_project,
                    "labels":        labels,
                }),
            });

            // ── Container → network edges ─────────────────────────────

            if let Some(net_settings) = &c.network_settings {
                if let Some(nets) = &net_settings.networks {
                    for net_name in nets.keys() {
                        edges.push(GraphEdge {
                            source: node_id.clone(),
                            target: format!("network:{net_name}"),
                            kind: EdgeKind::Network,
                            label: None,
                        });
                    }
                }
            }
        }

        // ── depends_on edges (from compose label) ─────────────────────

        for c in &containers {
            let id = c.id.clone().unwrap_or_default();
            let short_id = id.get(..12).unwrap_or(&id).to_owned();
            let node_id = format!("container:{short_id}");

            let labels = c.labels.clone().unwrap_or_default();
            if let Some(dep_str) = labels.get("com.docker.compose.depends_on") {
                // The label value is a comma-separated list of service names.
                for dep in dep_str.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    if let Some(target) = service_to_node.get(dep) {
                        edges.push(GraphEdge {
                            source: node_id.clone(),
                            target: target.clone(),
                            kind: EdgeKind::DependsOn,
                            label: Some("depends_on".into()),
                        });
                    }
                }
            }
        }

        // ── Network nodes ─────────────────────────────────────────────

        for net in &networks {
            let id = net.id.clone().unwrap_or_default();
            let name = net
                .name
                .clone()
                .unwrap_or_else(|| id.get(..12).unwrap_or(&id).to_owned());

            // Skip Docker's built-in bridge/host/none for noise reduction,
            // unless they actually have containers attached. `net.containers`
            // is unreliable in the list response, so also keep any network a
            // container references (otherwise its edge would dangle).
            let container_count = net.containers.as_ref().map(|m| m.len()).unwrap_or(0);
            let is_builtin = matches!(name.as_str(), "bridge" | "host" | "none");
            if is_builtin && container_count == 0 && !referenced_networks.contains(&name) {
                continue;
            }

            nodes.push(GraphNode {
                id: format!("network:{name}"),
                label: name.clone(),
                kind: NodeKind::Network,
                data: serde_json::json!({
                    "full_id": id,
                    "driver":  net.driver.clone().unwrap_or_default(),
                    "scope":   net.scope.clone().unwrap_or_default(),
                    "labels":  net.labels.clone().unwrap_or_default(),
                }),
            });
        }

        // ── Volume nodes + container→volume edges ─────────────────────

        for vol in &volumes {
            let name = vol.name.clone();
            nodes.push(GraphNode {
                id: format!("volume:{name}"),
                label: name.clone(),
                kind: NodeKind::Volume,
                data: serde_json::json!({
                    "driver":     vol.driver.clone(),
                    "mountpoint": vol.mountpoint.clone(),
                    "labels":     vol.labels.clone(),
                }),
            });
        }

        // Volume mount edges require per-container inspect data —
        // use the already-fetched ContainerSummary.Mounts field.
        for c in &containers {
            let id = c.id.clone().unwrap_or_default();
            let short_id = id.get(..12).unwrap_or(&id).to_owned();
            let node_id = format!("container:{short_id}");

            if let Some(mounts) = &c.mounts {
                for m in mounts {
                    let vol_name = match m.name.as_deref() {
                        Some(n) if !n.is_empty() => n.to_owned(),
                        _ => continue, // bind mount — not a named volume
                    };
                    edges.push(GraphEdge {
                        source: node_id.clone(),
                        target: format!("volume:{vol_name}"),
                        kind: EdgeKind::Volume,
                        label: m.destination.clone(),
                    });
                }
            }
        }

        Ok(DockerGraph { nodes, edges })
    }

    /// Raw bollard event stream. Each item is one Docker daemon event.
    /// The stream is `'static` — bollard keeps its own internal Arc.
    pub fn events_stream(
        &self,
    ) -> impl futures_util::Stream<Item = Result<bollard::models::EventMessage, bollard::errors::Error>> + Send + 'static
    {
        self.docker.events(None::<EventsOptions<String>>)
    }
}

// ─── Background event watcher ─────────────────────────────────────────────────

/// Spawn a task that streams Docker events and publishes them on the
/// `"docker"` live topic.  Automatically reconnects with exponential
/// back-off on stream errors.  No-op when Docker is not available.
pub fn spawn_event_watcher(state: AppState) {
    let Some(docker) = state.docker().cloned() else {
        return;
    };
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(2);
        loop {
            let mut stream = docker.events_stream();
            loop {
                match stream.next().await {
                    Some(Ok(msg)) => {
                        backoff = Duration::from_secs(2);
                        let action = msg.action.as_deref().unwrap_or("");
                        if matches!(
                            action,
                            "start" | "stop" | "die" | "create" | "destroy" | "rename" | "restart" | "kill"
                        ) {
                            docker.invalidate().await;
                            // The service cards read a separate `docker inspect`
                            // snapshot; a state change invalidates that too, so
                            // the push and the cards can't disagree.
                            routes::invalidate_service_cache().await;
                        }
                        let data = serde_json::to_value(&msg).unwrap_or_default();
                        state.live_publish("docker", data);
                    }
                    Some(Err(e)) => {
                        tracing::warn!(error = %e, "Docker event stream error — reconnecting");
                        break;
                    }
                    None => {
                        tracing::debug!("Docker event stream ended — reconnecting");
                        break;
                    }
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    });
}
