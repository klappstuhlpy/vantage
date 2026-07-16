//! Proxy config generation.
//!
//! Turns a [`ProxyRoute`] into an nginx `server { … }` block or a Caddyfile
//! site entry.  The emitted text is what gets written to
//! `proxy.config_dir/<subdomain>.conf` and (for nginx) reloaded with the
//! configured reload command.

use super::storage::ProxyRoute;

/// Which proxy syntax to emit.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProxyKind {
    Nginx,
    Caddy,
    /// Cloudflare Tunnel. Unlike nginx/caddy this renders a single combined
    /// `config.yml` with one `ingress:` list (not a file per route), and TLS
    /// terminates at Cloudflare's edge, so there are no local certificates.
    Cloudflared,
}

impl ProxyKind {
    pub fn parse(s: Option<&str>) -> Self {
        match s.map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("caddy") => ProxyKind::Caddy,
            Some("cloudflared" | "cloudflare-tunnel" | "tunnel") => ProxyKind::Cloudflared,
            _ => ProxyKind::Nginx,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ProxyKind::Nginx => "nginx",
            ProxyKind::Caddy => "caddy",
            ProxyKind::Cloudflared => "cloudflared",
        }
    }

    /// `true` for proxies whose routes are emitted into a single combined
    /// config file rather than one file per route.
    pub fn is_single_file(self) -> bool {
        matches!(self, ProxyKind::Cloudflared)
    }

    /// File name a route's config lands in. For cloudflared every route shares
    /// the single `config.yml`; for nginx/caddy it's one file per subdomain.
    pub fn file_name(self, subdomain: &str) -> String {
        match self {
            ProxyKind::Nginx => format!("{subdomain}.conf"),
            // Caddy imports *.caddy fragments under one Caddyfile.
            ProxyKind::Caddy => format!("{subdomain}.caddy"),
            ProxyKind::Cloudflared => CLOUDFLARED_FILE.to_string(),
        }
    }
}

/// Combined config file name written for the cloudflared backend.
pub const CLOUDFLARED_FILE: &str = "config.yml";

/// htpasswd file name for a route (nginx basic-auth).
pub fn htpasswd_file_name(subdomain: &str) -> String {
    format!("{subdomain}.htpasswd")
}

/// Access rules parsed from the route's `access_rules_json`.
#[derive(Debug, Default, serde::Deserialize)]
struct AccessRules {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

fn parse_access(route: &ProxyRoute) -> AccessRules {
    route
        .access_rules_json
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

/// Render the config fragment for a single route.
///
/// `dir` is the directory the config (and any htpasswd sidecar) is written
/// to — used to emit an absolute `auth_basic_user_file` path for nginx.
pub fn render(kind: ProxyKind, route: &ProxyRoute, dir: Option<&std::path::Path>) -> String {
    match kind {
        ProxyKind::Nginx => render_nginx(route, dir),
        ProxyKind::Caddy => render_caddy(route),
        // For cloudflared a single route can't be a standalone file, so the
        // "preview" shows just this route's contribution to config.yml.
        ProxyKind::Cloudflared => render_cloudflared_preview(route),
    }
}

fn render_nginx(route: &ProxyRoute, dir: Option<&std::path::Path>) -> String {
    let upstream = format!("{}://{}:{}", route.target_scheme, route.target_host, route.target_port);
    let access = parse_access(route);
    let mut out = String::new();

    out.push_str(&format!(
        "# Managed by Vantage — route #{} ({})\n",
        route.id, route.subdomain
    ));
    out.push_str("server {\n");
    if route.ssl_managed {
        out.push_str("    listen 443 ssl;\n");
        out.push_str("    listen [::]:443 ssl;\n");
    } else {
        out.push_str("    listen 80;\n");
        out.push_str("    listen [::]:80;\n");
    }
    out.push_str(&format!("    server_name {};\n", route.subdomain));

    if route.ssl_managed {
        // Conventional certbot path; admins can override via extra_config.
        out.push_str(&format!(
            "    ssl_certificate     /etc/letsencrypt/live/{}/fullchain.pem;\n",
            route.subdomain
        ));
        out.push_str(&format!(
            "    ssl_certificate_key /etc/letsencrypt/live/{}/privkey.pem;\n",
            route.subdomain
        ));
    }

    if route.cloudflare_proxied {
        out.push_str("    real_ip_header CF-Connecting-IP;\n");
        out.push_str("    # set_real_ip_from <cloudflare-ranges> — configure globally\n");
    }

    if let Some(rps) = route.rate_limit_rps {
        // Requires a matching `limit_req_zone` in the http {} block; we
        // reference a conventional zone name keyed on the route id.
        out.push_str(&format!(
            "    # limit_req_zone $binary_remote_addr zone=route{}:10m rate={}r/s; (add to http{{}})\n",
            route.id, rps
        ));
        out.push_str(&format!(
            "    limit_req zone=route{} burst={} nodelay;\n",
            route.id,
            rps.max(1) * 2
        ));
    }

    out.push_str("    location / {\n");
    for cidr in &access.allow {
        out.push_str(&format!("        allow {};\n", cidr));
    }
    for cidr in &access.deny {
        if cidr == "*" {
            out.push_str("        deny all;\n");
        } else {
            out.push_str(&format!("        deny {};\n", cidr));
        }
    }
    if route.has_auth() {
        let htpasswd = htpasswd_file_name(&route.subdomain);
        let path = match dir {
            Some(d) => d.join(&htpasswd).display().to_string(),
            None => htpasswd,
        };
        out.push_str("        auth_basic \"Restricted\";\n");
        out.push_str(&format!("        auth_basic_user_file {};\n", path));
    }
    out.push_str(&format!("        proxy_pass {};\n", upstream));
    out.push_str("        proxy_set_header Host $host;\n");
    out.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
    out.push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
    out.push_str("        proxy_set_header X-Forwarded-Proto $scheme;\n");
    out.push_str("        proxy_http_version 1.1;\n");
    out.push_str("        proxy_set_header Upgrade $http_upgrade;\n");
    out.push_str("        proxy_set_header Connection \"upgrade\";\n");
    out.push_str("    }\n");

    if let Some(extra) = route.extra_config.as_deref().filter(|s| !s.trim().is_empty()) {
        for line in extra.lines() {
            out.push_str(&format!("    {}\n", line));
        }
    }

    out.push_str("}\n");
    out
}

fn render_caddy(route: &ProxyRoute) -> String {
    let upstream = format!("{}://{}:{}", route.target_scheme, route.target_host, route.target_port);
    let access = parse_access(route);
    let mut out = String::new();

    out.push_str(&format!(
        "# Managed by Vantage — route #{} ({})\n",
        route.id, route.subdomain
    ));
    out.push_str(&format!("{} {{\n", route.subdomain));

    if !route.ssl_managed {
        out.push_str("    tls internal\n");
    }

    if !access.allow.is_empty() || !access.deny.is_empty() {
        out.push_str("    @blocked {\n");
        for cidr in &access.deny {
            if cidr == "*" {
                out.push_str("        not remote_ip 0.0.0.0/0\n");
            } else {
                out.push_str(&format!("        remote_ip {}\n", cidr));
            }
        }
        out.push_str("    }\n");
        if !access.allow.is_empty() {
            out.push_str(&format!("    @allowed remote_ip {}\n", access.allow.join(" ")));
            out.push_str("    handle @allowed {\n");
        }
        out.push_str("    respond @blocked 403\n");
        if !access.allow.is_empty() {
            out.push_str("    }\n");
        }
    }

    if route.has_auth() {
        if let (Some(user), Some(hash)) = (&route.http_auth_user, &route.http_auth_pass_hash) {
            out.push_str("    basic_auth {\n");
            out.push_str(&format!("        {} {}\n", user, hash));
            out.push_str("    }\n");
        }
    }

    if let Some(rps) = route.rate_limit_rps {
        out.push_str(&format!(
            "    # rate_limit: {} r/s — requires the caddy-ratelimit plugin\n",
            rps
        ));
    }

    out.push_str(&format!("    reverse_proxy {}\n", upstream));

    if let Some(extra) = route.extra_config.as_deref().filter(|s| !s.trim().is_empty()) {
        for line in extra.lines() {
            out.push_str(&format!("    {}\n", line));
        }
    }

    out.push_str("}\n");
    out
}

// ─── Cloudflare Tunnel (cloudflared) ────────────────────────────────────────

/// Appends one route's `ingress:` entry (two-space indented, as it sits inside
/// the list). cloudflared ingress can't express HTTP basic-auth, rate limits,
/// or IP allow/deny — those belong in Cloudflare Access/WAF — so those route
/// fields are surfaced as a comment rather than silently dropped.
fn render_cloudflared_entry(route: &ProxyRoute, out: &mut String) {
    let upstream = format!("{}://{}:{}", route.target_scheme, route.target_host, route.target_port);
    out.push_str(&format!("  - hostname: {}\n", route.subdomain));
    out.push_str(&format!("    service: {}\n", upstream));

    // originRequest block for https upstreams (commonly self-signed internally)
    // and any verbatim extra_config the operator added.
    let https = route.target_scheme.eq_ignore_ascii_case("https");
    let extra = route.extra_config.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if https || extra.is_some() {
        out.push_str("    originRequest:\n");
        if https {
            out.push_str("      noTLSVerify: true\n");
        }
        if let Some(extra) = extra {
            for line in extra.lines() {
                out.push_str(&format!("      {}\n", line));
            }
        }
    }

    if route.has_auth() || route.rate_limit_rps.is_some() || route.access_rules_json.is_some() {
        out.push_str(
            "    # note: basic-auth / rate-limit / access rules are not part of a tunnel ingress —\n\
             \x20   # enforce them with Cloudflare Access / WAF on this hostname instead.\n",
        );
    }
}

/// Single-route preview (what this route contributes to `config.yml`).
fn render_cloudflared_preview(route: &ProxyRoute) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# Managed by Vantage — Cloudflare Tunnel ingress (part of {CLOUDFLARED_FILE}), route #{} ({})\n",
        route.id, route.subdomain
    ));
    out.push_str("ingress:\n");
    render_cloudflared_entry(route, &mut out);
    out
}

/// Renders the full combined `config.yml` for the cloudflared backend from
/// every enabled route. `tunnel` and `credentials_file` come from config; when
/// unset, editable placeholders are emitted so the file is still valid to hand
/// off. The required catch-all `http_status:404` ingress rule is always last.
pub fn render_cloudflared_config(
    routes: &[&ProxyRoute],
    tunnel: Option<&str>,
    credentials_file: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push_str("# Managed by Vantage — Cloudflare Tunnel\n");
    out.push_str("# Edits to managed sections are overwritten on the next apply.\n");
    match tunnel {
        Some(t) if !t.trim().is_empty() => out.push_str(&format!("tunnel: {}\n", t.trim())),
        _ => out.push_str("tunnel: REPLACE_WITH_TUNNEL_ID   # set cloudflare.tunnel_name in config.json\n"),
    }
    match credentials_file {
        Some(c) if !c.trim().is_empty() => out.push_str(&format!("credentials-file: {}\n", c.trim())),
        _ => out.push_str(
            "credentials-file: /etc/cloudflared/REPLACE.json   # set cloudflare.tunnel_credentials_file in config.json\n",
        ),
    }
    out.push('\n');
    out.push_str("ingress:\n");
    for route in routes {
        render_cloudflared_entry(route, &mut out);
    }
    // cloudflared requires a catch-all rule as the final ingress entry.
    out.push_str("  - service: http_status:404\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn route(subdomain: &str, scheme: &str, host: &str, port: i64) -> ProxyRoute {
        ProxyRoute {
            id: 1,
            subdomain: subdomain.to_string(),
            target_host: host.to_string(),
            target_port: port,
            target_scheme: scheme.to_string(),
            container: None,
            ssl_managed: true,
            cloudflare_proxied: false,
            http_auth_user: None,
            http_auth_pass_hash: None,
            rate_limit_rps: None,
            access_rules_json: None,
            extra_config: None,
            enabled: true,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn parses_cloudflared_aliases() {
        assert_eq!(ProxyKind::parse(Some("cloudflared")), ProxyKind::Cloudflared);
        assert_eq!(ProxyKind::parse(Some("tunnel")), ProxyKind::Cloudflared);
        assert_eq!(ProxyKind::parse(Some("nginx")), ProxyKind::Nginx);
        assert!(ProxyKind::Cloudflared.is_single_file());
        assert!(!ProxyKind::Nginx.is_single_file());
        assert_eq!(ProxyKind::Cloudflared.file_name("a.example.com"), CLOUDFLARED_FILE);
    }

    #[test]
    fn renders_combined_ingress_with_catch_all() {
        let a = route("a.example.com", "http", "localhost", 8920);
        let b = route("b.example.com", "https", "10.0.0.5", 8443);
        let routes = [&a, &b];
        let cfg = render_cloudflared_config(&routes, Some("my-tunnel"), Some("/etc/cloudflared/x.json"));
        assert!(cfg.contains("tunnel: my-tunnel"));
        assert!(cfg.contains("credentials-file: /etc/cloudflared/x.json"));
        assert!(cfg.contains("- hostname: a.example.com"));
        assert!(cfg.contains("service: http://localhost:8920"));
        assert!(cfg.contains("- hostname: b.example.com"));
        // https upstream gets noTLSVerify.
        assert!(cfg.contains("noTLSVerify: true"));
        // Catch-all must be the final ingress rule.
        assert!(cfg.trim_end().ends_with("- service: http_status:404"));
    }

    #[test]
    fn missing_tunnel_emits_placeholder() {
        let a = route("a.example.com", "http", "localhost", 80);
        let cfg = render_cloudflared_config(&[&a], None, None);
        assert!(cfg.contains("REPLACE_WITH_TUNNEL_ID"));
        assert!(cfg.contains("tunnel_credentials_file"));
    }
}
