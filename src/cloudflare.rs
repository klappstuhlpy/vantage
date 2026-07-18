//! Minimal Cloudflare Analytics GraphQL client.
//!
//! Cloudflare exposes an analytics API at `api.cloudflare.com/client/v4/graphql`
//! which we hit with a bearer token + zone ID. This module implements two
//! queries needed by the security dashboard:
//!
//! 1. **Zone traffic over time** — total requests, threats, cached bytes,
//!    bot-detected requests bucketed by 1-minute intervals.
//! 2. **Firewall (WAF) events** — recent events grouped by action, source,
//!    country, and rule.
//!
//! Both queries hit `httpRequests1mGroups` and `firewallEventsAdaptive`
//! respectively, which are the standard datasets exposed to free-tier zones.

use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Clone)]
pub struct Cloudflare {
    client: reqwest::Client,
    api_token: String,
    zone_id: String,
}

const ENDPOINT: &str = "https://api.cloudflare.com/client/v4/graphql";

#[derive(Debug, Default, Serialize)]
pub struct ZoneSummary {
    pub total_requests: u64,
    pub cached_requests: u64,
    pub bytes: u64,
    pub threats: u64,
    pub page_views: u64,
    /// Time-series buckets sorted ascending by `ts`.
    pub series: Vec<TrafficBucket>,
}

#[derive(Debug, Serialize)]
pub struct TrafficBucket {
    /// Bucket start, unix seconds.
    pub ts: i64,
    pub requests: u64,
    pub threats: u64,
    pub bytes: u64,
    pub cached_requests: u64,
}

#[derive(Debug, Serialize)]
pub struct FirewallEvent {
    pub ts: i64,
    pub action: String,
    pub rule_id: String,
    pub source: String,
    pub country: String,
    pub client_ip: String,
    pub uri: String,
}

impl Cloudflare {
    pub fn new(client: reqwest::Client, api_token: String, zone_id: String) -> Self {
        Self {
            client,
            api_token,
            zone_id,
        }
    }

    /// Returns zone traffic totals + per-minute series. `since` is typically
    /// `now - 24h`.
    pub async fn zone_summary(&self, since: OffsetDateTime) -> anyhow::Result<ZoneSummary> {
        let query = r#"
        query ZoneTraffic($zoneTag: String!, $since: Time!, $until: Time!) {
          viewer {
            zones(filter: { zoneTag: $zoneTag }) {
              httpRequests1mGroups(
                limit: 2000
                filter: { datetime_geq: $since, datetime_leq: $until }
                orderBy: [datetimeMinute_ASC]
              ) {
                dimensions { datetimeMinute }
                sum {
                  requests
                  cachedRequests
                  bytes
                  threats
                  pageViews
                }
              }
            }
          }
        }
        "#;
        let until = OffsetDateTime::now_utc();
        let body = json!({
            "query": query,
            "variables": {
                "zoneTag": self.zone_id,
                "since": since.format(&Rfc3339)?,
                "until": until.format(&Rfc3339)?,
            }
        });

        let resp: GraphQlResponse<TrafficData> = self.post_graphql(body).await?;
        let buckets = resp
            .data
            .and_then(|d| d.viewer.zones.into_iter().next())
            .map(|z| z.http_requests_1m_groups)
            .unwrap_or_default();

        let mut summary = ZoneSummary::default();
        for b in buckets {
            summary.total_requests += b.sum.requests;
            summary.cached_requests += b.sum.cached_requests;
            summary.bytes += b.sum.bytes;
            summary.threats += b.sum.threats;
            summary.page_views += b.sum.page_views;
            summary.series.push(TrafficBucket {
                ts: parse_cf_datetime(&b.dimensions.datetime_minute).unwrap_or(0),
                requests: b.sum.requests,
                threats: b.sum.threats,
                bytes: b.sum.bytes,
                cached_requests: b.sum.cached_requests,
            });
        }
        Ok(summary)
    }

    /// Recent firewall events (most recent first).
    pub async fn firewall_events(&self, since: OffsetDateTime, limit: u32) -> anyhow::Result<Vec<FirewallEvent>> {
        let query = r#"
        query FwEvents($zoneTag: String!, $since: Time!, $until: Time!, $limit: Int!) {
          viewer {
            zones(filter: { zoneTag: $zoneTag }) {
              firewallEventsAdaptive(
                limit: $limit
                filter: { datetime_geq: $since, datetime_leq: $until }
                orderBy: [datetime_DESC]
              ) {
                action
                clientIP
                clientCountryName
                clientRequestPath
                source
                ruleId
                datetime
              }
            }
          }
        }
        "#;
        let until = OffsetDateTime::now_utc();
        let body = json!({
            "query": query,
            "variables": {
                "zoneTag": self.zone_id,
                "since": since.format(&Rfc3339)?,
                "until": until.format(&Rfc3339)?,
                "limit": limit,
            }
        });

        let resp: GraphQlResponse<FwData> = self.post_graphql(body).await?;
        let raw = resp
            .data
            .and_then(|d| d.viewer.zones.into_iter().next())
            .map(|z| z.firewall_events_adaptive)
            .unwrap_or_default();

        Ok(raw
            .into_iter()
            .map(|r| FirewallEvent {
                ts: parse_cf_datetime(&r.datetime).unwrap_or(0),
                action: r.action,
                rule_id: r.rule_id,
                source: r.source,
                country: r.client_country_name,
                client_ip: r.client_ip,
                uri: r.client_request_path,
            })
            .collect())
    }

    async fn post_graphql<T>(&self, body: serde_json::Value) -> anyhow::Result<GraphQlResponse<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let res = self
            .client
            .post(ENDPOINT)
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await?;
        if !res.status().is_success() {
            anyhow::bail!("cloudflare returned HTTP {}", res.status());
        }
        let parsed: GraphQlResponse<T> = res.json().await?;
        if let Some(errors) = &parsed.errors {
            if !errors.is_empty() {
                anyhow::bail!("cloudflare graphql error: {}", errors[0].message);
            }
        }
        Ok(parsed)
    }
}

// ─── GraphQL deserialisation types ──────────────────────────────────────

#[derive(Deserialize)]
struct GraphQlResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphQlError>>,
}

#[derive(Deserialize)]
struct GraphQlError {
    message: String,
}

#[derive(Deserialize)]
struct TrafficData {
    viewer: TrafficViewer,
}

#[derive(Deserialize)]
struct TrafficViewer {
    zones: Vec<TrafficZone>,
}

#[derive(Deserialize)]
struct TrafficZone {
    #[serde(rename = "httpRequests1mGroups")]
    http_requests_1m_groups: Vec<TrafficRow>,
}

#[derive(Deserialize)]
struct TrafficRow {
    dimensions: TrafficDims,
    sum: TrafficSum,
}

#[derive(Deserialize)]
struct TrafficDims {
    #[serde(rename = "datetimeMinute")]
    datetime_minute: String,
}

#[derive(Deserialize)]
struct TrafficSum {
    #[serde(default)]
    requests: u64,
    #[serde(default, rename = "cachedRequests")]
    cached_requests: u64,
    #[serde(default)]
    bytes: u64,
    #[serde(default)]
    threats: u64,
    #[serde(default, rename = "pageViews")]
    page_views: u64,
}

#[derive(Deserialize)]
struct FwData {
    viewer: FwViewer,
}

#[derive(Deserialize)]
struct FwViewer {
    zones: Vec<FwZone>,
}

#[derive(Deserialize)]
struct FwZone {
    #[serde(rename = "firewallEventsAdaptive")]
    firewall_events_adaptive: Vec<FwRaw>,
}

#[derive(Deserialize)]
struct FwRaw {
    action: String,
    #[serde(rename = "clientIP")]
    client_ip: String,
    #[serde(rename = "clientCountryName", default)]
    client_country_name: String,
    #[serde(rename = "clientRequestPath", default)]
    client_request_path: String,
    source: String,
    #[serde(rename = "ruleId", default)]
    rule_id: String,
    datetime: String,
}

fn parse_cf_datetime(s: &str) -> Option<i64> {
    OffsetDateTime::parse(s, &Rfc3339).ok().map(|d| d.unix_timestamp())
}
