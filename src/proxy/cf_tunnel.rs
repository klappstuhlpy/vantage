//! Cloudflare Tunnel (cfd_tunnel) + DNS REST client.
//!
//! For a *remotely-managed* tunnel (created in the dashboard, run with
//! `cloudflared tunnel run --token …`) there is no local `config.yml` or
//! credentials file — the public-hostname ingress lives in Cloudflare and is
//! edited via the API.

use anyhow::Context;
use serde::{Deserialize, Serialize};

const API_BASE: &str = "https://api.cloudflare.com/client/v4";

fn tunnel_cname_target(tunnel_id: &str) -> String {
    format!("{tunnel_id}.cfargotunnel.com")
}

#[derive(Clone)]
pub struct CfTunnel {
    client: reqwest::Client,
    api_token: String,
    account_id: String,
    tunnel_id: String,
    zone_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IngressRule {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hostname: Option<String>,
    pub service: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default, rename = "originRequest")]
    pub origin_request: Option<serde_json::Value>,
}

impl IngressRule {
    pub fn is_catch_all(&self) -> bool {
        self.hostname.as_deref().map(str::is_empty).unwrap_or(true)
    }
}

impl CfTunnel {
    pub fn new(
        client: reqwest::Client,
        api_token: String,
        account_id: String,
        tunnel_id: String,
        zone_id: Option<String>,
    ) -> Self {
        Self {
            client,
            api_token,
            account_id,
            tunnel_id,
            zone_id,
        }
    }

    fn config_url(&self) -> String {
        format!(
            "{API_BASE}/accounts/{}/cfd_tunnel/{}/configurations",
            self.account_id, self.tunnel_id
        )
    }

    pub async fn get_ingress(&self) -> anyhow::Result<Vec<IngressRule>> {
        let url = self.config_url();
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .context("GET tunnel configuration")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let parsed: CfResponse<TunnelConfigResult> =
            serde_json::from_str(&text).with_context(|| format!("parse tunnel config response ({status}): {text}"))?;
        if !parsed.success {
            anyhow::bail!(
                "Cloudflare API error ({status}) reading tunnel config: {}",
                parsed.detail_with_hint()
            );
        }
        Ok(parsed
            .result
            .and_then(|r| r.config)
            .map(|c| c.ingress)
            .unwrap_or_default())
    }

    pub async fn put_ingress(&self, ingress: &[IngressRule]) -> anyhow::Result<()> {
        let url = self.config_url();
        let body = serde_json::json!({ "config": { "ingress": ingress } });
        let resp = self
            .client
            .put(&url)
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await
            .context("PUT tunnel configuration")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let parsed: CfResponse<serde_json::Value> =
            serde_json::from_str(&text).with_context(|| format!("parse PUT response ({status}): {text}"))?;
        if !parsed.success {
            anyhow::bail!(
                "Cloudflare API error ({status}) writing tunnel config: {}",
                parsed.detail_with_hint()
            );
        }
        Ok(())
    }

    pub async fn upsert_dns(&self, hostname: &str) -> anyhow::Result<()> {
        let zone = self
            .zone_id
            .as_deref()
            .context("cloudflare zone_id not set — cannot manage DNS for tunnel hostnames")?;
        let target = tunnel_cname_target(&self.tunnel_id);
        let record = serde_json::json!({
            "type": "CNAME",
            "name": hostname,
            "content": target,
            "proxied": true,
            "comment": "Managed by Vantage",
        });

        let list_url = format!("{API_BASE}/zones/{zone}/dns_records?type=CNAME&name={hostname}");
        let listed: CfResponse<Vec<DnsRecord>> = self
            .client
            .get(&list_url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .context("list DNS records")?
            .json()
            .await
            .context("parse DNS list")?;
        if !listed.success {
            anyhow::bail!(
                "Cloudflare API error listing DNS for {hostname}: {}",
                listed.detail_with_hint()
            );
        }

        let existing = listed.result.unwrap_or_default().into_iter().next();
        let (method_url, is_update) = match &existing {
            Some(rec) => (format!("{API_BASE}/zones/{zone}/dns_records/{}", rec.id), true),
            None => (format!("{API_BASE}/zones/{zone}/dns_records"), false),
        };
        let req = if is_update {
            self.client.put(&method_url)
        } else {
            self.client.post(&method_url)
        };
        let resp = req
            .bearer_auth(&self.api_token)
            .json(&record)
            .send()
            .await
            .context("upsert DNS record")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let parsed: CfResponse<serde_json::Value> =
            serde_json::from_str(&text).with_context(|| format!("parse DNS upsert ({status}): {text}"))?;
        if !parsed.success {
            anyhow::bail!(
                "Cloudflare API error upserting DNS for {hostname}: {}",
                parsed.detail_with_hint()
            );
        }
        Ok(())
    }
}

// ─── Cloudflare REST envelope ───────────────────────────────────────────────

#[derive(Deserialize)]
struct CfResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    result: Option<T>,
}

impl<T> CfResponse<T> {
    fn errors_str(&self) -> String {
        if self.errors.is_empty() {
            "no error detail".to_string()
        } else {
            self.errors
                .iter()
                .map(|e| format!("[{}] {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join("; ")
        }
    }

    fn is_auth_error(&self) -> bool {
        self.errors.iter().any(|e| e.code == 10000)
    }

    fn detail_with_hint(&self) -> String {
        if self.is_auth_error() {
            format!(
                "{} — the API token is missing permissions or the account is wrong. \
                 A tunnel token needs Account › Cloudflare Tunnel › Read (Edit to push) \
                 and Zone › DNS › Edit, with the account added under the token's Account \
                 Resources. Also confirm cloudflare.account_id matches that account.",
                self.errors_str()
            )
        } else {
            self.errors_str()
        }
    }
}

#[derive(Deserialize)]
struct CfError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct TunnelConfigResult {
    #[serde(default)]
    config: Option<IngressConfig>,
}

#[derive(Deserialize)]
struct IngressConfig {
    #[serde(default)]
    ingress: Vec<IngressRule>,
}

#[derive(Deserialize, Default)]
struct DnsRecord {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catch_all_detection() {
        let catch = IngressRule {
            service: "http_status:404".into(),
            ..Default::default()
        };
        assert!(catch.is_catch_all());
        let real = IngressRule {
            hostname: Some("a.example.com".into()),
            service: "http://localhost:80".into(),
            ..Default::default()
        };
        assert!(!real.is_catch_all());
    }

    #[test]
    fn cname_target_format() {
        assert_eq!(tunnel_cname_target("abc-123"), "abc-123.cfargotunnel.com");
    }

    #[test]
    fn auth_error_gets_a_permission_hint() {
        let resp: CfResponse<serde_json::Value> = CfResponse {
            success: false,
            errors: vec![CfError {
                code: 10000,
                message: "Authentication error".into(),
            }],
            result: None,
        };
        assert!(resp.is_auth_error());
        let detail = resp.detail_with_hint();
        assert!(detail.contains("Authentication error"));
        assert!(detail.contains("Cloudflare Tunnel"));
        assert!(detail.contains("account_id"));
    }

    #[test]
    fn non_auth_error_has_no_hint() {
        let resp: CfResponse<serde_json::Value> = CfResponse {
            success: false,
            errors: vec![CfError {
                code: 1003,
                message: "something else".into(),
            }],
            result: None,
        };
        assert!(!resp.is_auth_error());
        let detail = resp.detail_with_hint();
        assert!(detail.contains("something else"));
        assert!(!detail.contains("Account Resources"));
    }

    #[test]
    fn ingress_rule_round_trips_without_nulls() {
        let rule = IngressRule {
            hostname: Some("a.example.com".into()),
            service: "https://10.0.0.1:8443".into(),
            path: None,
            origin_request: Some(serde_json::json!({ "noTLSVerify": true })),
        };
        let json = serde_json::to_string(&rule).unwrap();
        assert!(!json.contains("\"path\""));
        assert!(json.contains("originRequest"));
        assert!(json.contains("a.example.com"));
    }
}
