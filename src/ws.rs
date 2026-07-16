//! Single live-update WebSocket endpoint at `/ws` — the live hub (Phase 4,
//! Step C3), foundational infrastructure the later feature slices publish into.
//!
//! Protocol (text frames carrying JSON):
//!
//! Client → server:
//! ```json
//! { "action": "subscribe",   "topics": ["metrics", "docker"] }
//! { "action": "unsubscribe", "topics": ["docker"] }
//! ```
//!
//! Server → client (after a topic event):
//! ```json
//! { "topic": "metrics", "data": { …same payload as the matching HTTP endpoint… } }
//! ```
//!
//! Ported from the monolith's `admin/ws.rs`. The only substantive change is that
//! [`LiveEvent`] and the `live_publish`/`live_subscribe` accessors now live in
//! Vantage's own [`AppState`] (the monolith kept them in `core::state`), and
//! the topic gate is unconditional here since every Vantage account is a host
//! admin. No slice publishes yet — the hub accepts subscriptions and stays
//! silent until metrics/docker/secrets/audit move in and call `live_publish`.

use std::collections::HashSet;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;

use crate::session::Account;
use crate::AppState;

/// One live event pushed to WebSocket subscribers. `topic` is a static tag
/// (`"metrics"`, `"docker"`, `"secrets"`, `"audit"`, …); `data` is whatever JSON
/// the producer chose (typically the same JSON the matching HTTP endpoint
/// returns). Clients say which topics they care about on connect.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LiveEvent {
    pub topic: &'static str,
    pub data: serde_json::Value,
}

/// `subscribe` and `unsubscribe` share the same shape.
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
enum ClientMessage {
    Subscribe { topics: Vec<String> },
    Unsubscribe { topics: Vec<String> },
}

/// Whether a client may subscribe to `topic`. Every live topic is admin-only,
/// and every Vantage account is a host admin — so a valid session (which the
/// [`Account`] extractor already requires) can subscribe to anything. Kept as a
/// seam so a future read-only operator role can be gated per-topic.
fn topic_allowed(_topic: &str, is_admin: bool) -> bool {
    is_admin
}

async fn ws_upgrade(State(state): State<AppState>, account: Account, ws: WebSocketUpgrade) -> Response {
    let is_admin = account.is_admin();
    ws.on_upgrade(move |socket| handle_socket(state, socket, is_admin))
}

async fn handle_socket(state: AppState, socket: WebSocket, is_admin: bool) {
    let (mut sender, mut receiver) = socket.split();
    let mut events = state.live_subscribe();
    let mut subscriptions: HashSet<String> = HashSet::new();

    // Greet so clients can detect a successful upgrade and switch off their
    // polling fallback without waiting for the first event.
    let _ = sender
        .send(Message::Text(r#"{"topic":"_meta","data":{"hello":true}}"#.into()))
        .await;

    loop {
        tokio::select! {
            // ── Outbound: live events from the broadcast hub ──────
            evt = events.recv() => {
                match evt {
                    Ok(event) => {
                        if !subscriptions.contains(event.topic) {
                            continue;
                        }
                        let body = serde_json::json!({
                            "topic": event.topic,
                            "data": event.data,
                        });
                        if sender.send(Message::Text(body.to_string())).await.is_err() {
                            break; // client gone
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        // Slow consumer dropped n messages — surface so the client
                        // can fall back to polling for a catch-up snapshot.
                        let body = serde_json::json!({ "topic": "_meta", "data": { "lagged": n } });
                        let _ = sender.send(Message::Text(body.to_string())).await;
                    }
                    Err(RecvError::Closed) => break,
                }
            }

            // ── Inbound: subscribe / unsubscribe / pings ──────────
            msg = receiver.next() => {
                let Some(Ok(msg)) = msg else { break };
                match msg {
                    Message::Text(text) => {
                        match serde_json::from_str::<ClientMessage>(&text) {
                            Ok(ClientMessage::Subscribe { topics }) => {
                                for t in topics {
                                    if topic_allowed(&t, is_admin) {
                                        subscriptions.insert(t);
                                    }
                                }
                                let body = serde_json::json!({
                                    "topic": "_meta",
                                    "data": { "subscribed": subscriptions.iter().collect::<Vec<_>>() }
                                });
                                let _ = sender.send(Message::Text(body.to_string())).await;
                            }
                            Ok(ClientMessage::Unsubscribe { topics }) => {
                                for t in topics {
                                    subscriptions.remove(&t);
                                }
                            }
                            Err(_) => {
                                // Malformed payload — keep the socket alive but ignore.
                            }
                        }
                    }
                    Message::Ping(payload) => {
                        let _ = sender.send(Message::Pong(payload)).await;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/ws", get(ws_upgrade))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topics_require_admin() {
        assert!(topic_allowed("metrics", true));
        assert!(!topic_allowed("metrics", false));
    }
}
