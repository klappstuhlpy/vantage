//! Cloudflare Tunnel management via the API (for remotely-managed tunnels).
//!
//! When cloudflare api_token + account_id + tunnel_id are configured, the
//! cloudflared proxy backend manages the tunnel's public-hostname ingress
//! through the Cloudflare API instead of writing a local `config.yml`.

use super::cf_tunnel::{CfTunnel, IngressRule};
use super::storage;
use crate::AppState;

use super::ApplyReport;

/// Builds the tunnel API client when all three required settings are present.
pub fn api_client(state: &AppState) -> Option<CfTunnel> {
    let cfg = &state.config;
    let token = cfg.cloudflare.api_token.as_deref().filter(|s| !s.is_empty())?;
    let account = cfg.cloudflare.account_id.as_deref().filter(|s| !s.is_empty())?;
    let tunnel = cfg.cloudflare.tunnel_id.as_deref().filter(|s| !s.is_empty())?;
    Some(CfTunnel::new(
        state.client.clone(),
        token.to_string(),
        account.to_string(),
        tunnel.to_string(),
        cfg.cloudflare.zone_id.clone().filter(|s| !s.is_empty()),
    ))
}

/// `true` when cloudflared should manage the tunnel through the API rather than
/// a local file.
pub fn api_mode(state: &AppState) -> bool {
    super::configured_kind(state).label() == "cloudflared" && api_client(state).is_some()
}

/// Parses a tunnel `service` URL (`http://host:port`) into scheme/host/port.
pub fn parse_service(service: &str) -> Option<(String, String, i64)> {
    let (scheme, rest) = service.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => match p.parse::<i64>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (authority.to_string(), default_port(&scheme)),
        },
        None => (authority.to_string(), default_port(&scheme)),
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host, port))
}

fn default_port(scheme: &str) -> i64 {
    if scheme == "https" {
        443
    } else {
        80
    }
}

fn build_ingress(routes: &[storage::ProxyRoute]) -> Vec<IngressRule> {
    let mut rules: Vec<IngressRule> = routes
        .iter()
        .filter(|r| r.enabled)
        .map(|r| {
            let service = format!("{}://{}:{}", r.target_scheme, r.target_host, r.target_port);
            let origin_request = if r.target_scheme.eq_ignore_ascii_case("https") {
                Some(serde_json::json!({ "noTLSVerify": true }))
            } else {
                None
            };
            IngressRule {
                hostname: Some(r.subdomain.clone()),
                service,
                path: None,
                origin_request,
            }
        })
        .collect();
    rules.push(IngressRule {
        hostname: None,
        service: "http_status:404".to_string(),
        path: None,
        origin_request: None,
    });
    rules
}

/// Pushes every enabled route to the tunnel as its ingress, then upserts the
/// proxied CNAME for each hostname.
pub async fn push(state: &AppState) -> anyhow::Result<ApplyReport> {
    let api = api_client(state).ok_or_else(|| anyhow::anyhow!("Cloudflare tunnel API not configured"))?;
    let routes = storage::list_routes(state).await?;
    let enabled: Vec<&storage::ProxyRoute> = routes.iter().filter(|r| r.enabled).collect();

    let ingress = build_ingress(&routes);
    let hostname_count = ingress.iter().filter(|r| !r.is_catch_all()).count();

    let mut report = ApplyReport {
        dir: Some(format!("cloudflare tunnel {}", short_tunnel(state))),
        ..Default::default()
    };

    api.put_ingress(&ingress).await?;
    report.written = hostname_count;
    tracing::info!(hostnames = hostname_count, "pushed ingress to Cloudflare tunnel");

    let mut dns_ok = 0usize;
    for route in &enabled {
        match api.upsert_dns(&route.subdomain).await {
            Ok(()) => dns_ok += 1,
            Err(e) => {
                tracing::warn!(hostname = %route.subdomain, error = %e, "DNS upsert failed");
                report.errors.push(format!("DNS {}: {e}", route.subdomain));
            }
        }
    }
    report.reload = Some(format!(
        "Cloudflare API: {hostname_count} ingress rule(s), {dns_ok}/{} DNS record(s) ok",
        enabled.len()
    ));
    Ok(report)
}

/// Pulls the tunnel's current ingress into the route table.
pub async fn import(state: &AppState) -> anyhow::Result<(usize, usize, usize)> {
    let api = api_client(state).ok_or_else(|| anyhow::anyhow!("Cloudflare tunnel API not configured"))?;
    let ingress = api.get_ingress().await?;

    let (mut imported, mut updated, mut skipped) = (0usize, 0usize, 0usize);
    for rule in &ingress {
        let Some(hostname) = rule.hostname.as_deref().filter(|h| !h.is_empty()) else {
            continue;
        };
        let Some((scheme, host, port)) = parse_service(&rule.service) else {
            tracing::info!(hostname, service = %rule.service, "skipping non-HTTP tunnel ingress on import");
            skipped += 1;
            continue;
        };
        match storage::upsert_imported_route(state, hostname.to_string(), host, port, scheme).await {
            Ok(true) => imported += 1,
            Ok(false) => updated += 1,
            Err(e) => {
                tracing::warn!(hostname, error = %e, "failed to upsert imported route");
                skipped += 1;
            }
        }
    }
    tracing::info!(imported, updated, skipped, "imported routes from Cloudflare tunnel");
    Ok((imported, updated, skipped))
}

fn short_tunnel(state: &AppState) -> String {
    state
        .config
        .cloudflare
        .tunnel_id
        .as_deref()
        .map(|t| t.chars().take(8).collect::<String>())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_service() {
        assert_eq!(
            parse_service("http://localhost:8920"),
            Some(("http".into(), "localhost".into(), 8920))
        );
        assert_eq!(
            parse_service("https://10.0.0.5:8443"),
            Some(("https".into(), "10.0.0.5".into(), 8443))
        );
    }

    #[test]
    fn defaults_port_when_absent() {
        assert_eq!(parse_service("http://app"), Some(("http".into(), "app".into(), 80)));
        assert_eq!(parse_service("https://app"), Some(("https".into(), "app".into(), 443)));
    }

    #[test]
    fn skips_non_http_services() {
        assert_eq!(parse_service("ssh://localhost:22"), None);
        assert_eq!(parse_service("http_status:404"), None);
        assert_eq!(parse_service("tcp://localhost:3389"), None);
    }

    #[test]
    fn build_ingress_appends_catch_all() {
        use time::OffsetDateTime;
        let route = storage::ProxyRoute {
            id: 1,
            subdomain: "a.example.com".into(),
            target_host: "localhost".into(),
            target_port: 8920,
            target_scheme: "http".into(),
            container: None,
            ssl_managed: false,
            cloudflare_proxied: true,
            http_auth_user: None,
            http_auth_pass_hash: None,
            rate_limit_rps: None,
            access_rules_json: None,
            extra_config: None,
            enabled: true,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let ingress = build_ingress(&[route]);
        assert_eq!(ingress.len(), 2);
        assert_eq!(ingress[0].hostname.as_deref(), Some("a.example.com"));
        assert!(ingress[1].is_catch_all());
    }
}
