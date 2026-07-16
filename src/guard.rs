//! Per-listener request guards for the hardened public listener (§7.1).
//!
//! In `both` mode two listeners share one router but carry different guard
//! stacks: the VPN listener trusts its transport, the public one does not. This
//! module holds the gates that only the `GuardProfile::Public` listener applies.
//!
//! Implemented so far: the **fail-closed IP allowlist** (an empty allowlist denies
//! everyone). mTLS (`require_client_cert`), GeoIP country gating, and aggressive
//! per-IP/per-account lockout layer on top of this in Step B2 — each is additive
//! and none relaxes the allowlist.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::config::IpCidr;

/// Fail-closed IP allowlist for the public listener. The peer address is the
/// direct TCP source — Vantage binds directly (never behind a proxy it manages,
/// §7.5), so there is no `X-Forwarded-For` to spoof. A request from an address in
/// no allowlisted CIDR is refused before it reaches auth or any handler.
pub async fn public_ip_allowlist(
    State(allowlist): State<Arc<Vec<IpCidr>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    if allowlist.iter().any(|cidr| cidr.contains(peer.ip())) {
        next.run(request).await
    } else {
        tracing::warn!(peer = %peer.ip(), "public listener: denied — source not in exposure.allowlist");
        (StatusCode::FORBIDDEN, "forbidden\n").into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request as HttpRequest, routing::get, Router};
    use tower::ServiceExt; // oneshot

    fn app(allowlist: Vec<&str>) -> Router {
        let parsed = Arc::new(
            allowlist
                .into_iter()
                .map(|c| IpCidr::parse(c).unwrap())
                .collect::<Vec<_>>(),
        );
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(parsed, public_ip_allowlist))
    }

    /// Drives a request whose `ConnectInfo` peer is `peer`, returning the status.
    async fn status_from(allowlist: Vec<&str>, peer: &str) -> StatusCode {
        let req = HttpRequest::builder().uri("/").body(Body::empty()).unwrap();
        // `from_fn_with_state` reads ConnectInfo from request extensions; inject it
        // directly (what `into_make_service_with_connect_info` does at serve time).
        let mut req = req;
        req.extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        app(allowlist).oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn allowed_source_passes() {
        assert_eq!(status_from(vec!["10.0.0.0/8"], "10.1.2.3:5555").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn disallowed_source_is_forbidden() {
        assert_eq!(
            status_from(vec!["10.0.0.0/8"], "8.8.8.8:5555").await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn empty_allowlist_denies_everyone() {
        assert_eq!(status_from(vec![], "10.1.2.3:5555").await, StatusCode::FORBIDDEN);
    }
}
