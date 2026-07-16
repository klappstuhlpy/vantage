//! Security analytics dashboard routes.
//!
//! - `GET /security` — page
//! - `GET /security/data?range=…` — JSON aggregate for charts/tables/feed
//! - `GET /security/cloudflare` — JSON wrapping Cloudflare panels (CF only)

use crate::{
    cloudflare::{FirewallEvent, ZoneSummary},
    session::Account,
    AppState,
};
use askama::Template;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;

#[derive(Template)]
#[template(path = "security.html")]
struct SecurityTemplate {
    account: Option<Account>,
    active_page: &'static str,
    /// True when both a token + zone are configured; UI uses this to decide
    /// whether to render the Cloudflare section.
    cloudflare_enabled: bool,
    /// True when a usable mmdb file is loaded; UI hides the country column
    /// otherwise.
    geoip_enabled: bool,
}

async fn security_page(State(state): State<AppState>, account: Account) -> Result<SecurityTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(SecurityTemplate {
        account: Some(account),
        active_page: "security",
        cloudflare_enabled: state.cloudflare.is_some(),
        geoip_enabled: state.geoip.is_enabled(),
    })
}

#[derive(Deserialize)]
struct RangeQuery {
    #[serde(default = "default_range")]
    range: String,
}
fn default_range() -> String {
    "24h".into()
}

fn range_to_seconds(r: &str) -> i64 {
    match r {
        "1h" => 3_600,
        "6h" => 6 * 3_600,
        "24h" => 24 * 3_600,
        "7d" => 7 * 24 * 3_600,
        "30d" => 30 * 24 * 3_600,
        _ => 24 * 3_600,
    }
}

// ─── Aggregated app-side security data ─────────────────────────────────

#[derive(Serialize)]
struct SecurityData {
    /// Bucketed counts of 4xx responses by reason — series for the area chart.
    timeline: Vec<TimelineBucket>,
    /// Top IPs by 4xx count in the window, enriched with geo info.
    top_ips: Vec<TopIp>,
    /// Distribution of 4xx responses by bad_reason (for the donut).
    reason_breakdown: Vec<ReasonCount>,
    /// Country distribution of *all* traffic (not just 4xx).
    country_distribution: Vec<CountryCount>,
    /// Most recent suspicious events for the activity feed.
    recent: Vec<RecentEvent>,
    /// Headline totals for the tile row.
    totals: Totals,
}

#[derive(Serialize)]
struct Totals {
    failed_logins: u64,
    rate_limited: u64,
    bad_requests: u64,
    unique_ips: u64,
}

#[derive(Serialize)]
struct TimelineBucket {
    ts: i64,
    failed_logins: u64,
    rate_limited: u64,
    bad_requests: u64,
}

#[derive(Serialize)]
struct TopIp {
    ip: String,
    count: u64,
    country_code: String,
    country: String,
    city: String,
}

#[derive(Serialize)]
struct ReasonCount {
    reason: String,
    count: u64,
}

#[derive(Serialize)]
struct CountryCount {
    country_code: String,
    country: String,
    count: u64,
}

#[derive(Serialize)]
struct RecentEvent {
    ts: i64,
    ip: Option<String>,
    country_code: String,
    path: String,
    status_code: u16,
    reason: String,
    user_id: Option<i64>,
}

/// A request log entry from `requests.db`, matching the site's `request` table schema.
#[derive(Debug, Clone)]
struct RequestLogEntry {
    pub ts: i64,
    pub ip: Option<String>,
    pub path: String,
    pub status_code: u16,
    pub bad_reason: Option<String>,
    pub user_id: Option<i64>,
}

impl RequestLogEntry {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            ts: row.get("ts")?,
            ip: row.get("ip")?,
            path: row.get("path")?,
            status_code: row.get("status_code")?,
            bad_reason: row.get("bad_reason")?,
            user_id: row.get("user_id")?,
        })
    }
}

async fn security_data(
    State(state): State<AppState>,
    account: Account,
    Query(query): Query<RangeQuery>,
) -> Result<Json<SecurityData>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }

    // If requests.db is not configured, return empty data.
    let Some(requests_db) = state.requests.as_ref() else {
        tracing::warn!("security_data called but requests.db is not configured");
        return Ok(Json(SecurityData {
            timeline: Vec::new(),
            top_ips: Vec::new(),
            reason_breakdown: Vec::new(),
            country_distribution: Vec::new(),
            recent: Vec::new(),
            totals: Totals {
                failed_logins: 0,
                rate_limited: 0,
                bad_requests: 0,
                unique_ips: 0,
            },
        }));
    };

    let seconds = range_to_seconds(&query.range);
    let since_ms = (OffsetDateTime::now_utc().unix_timestamp() - seconds) * 1_000;

    // All 4xx entries (used by every chart on the page) — cap to 5k to stay
    // responsive on long ranges, sorted newest-first via ts DESC.
    let bad: Vec<RequestLogEntry> = requests_db
        .call(move |conn| -> rusqlite::Result<Vec<RequestLogEntry>> {
            let mut stmt = conn.prepare_cached(
                "SELECT ts, ip, path, status_code, bad_reason, user_id
                 FROM request WHERE ts >= ? AND status_code >= 400 AND status_code < 500
                 ORDER BY ts DESC LIMIT 5000",
            )?;
            let rows = stmt
                .query_map([since_ms], RequestLogEntry::from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to query requests.db for 4xx entries");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Sample for the country-distribution panel. Capped at 5000 newest
    // requests so a 30-day window doesn't load 100k+ rows just to count
    // country codes. Rank order is preserved; absolute counts are
    // representative of the sample, not the entire window.
    let countries_raw: Vec<(Option<String>,)> = requests_db
        .call(move |conn| -> rusqlite::Result<Vec<(Option<String>,)>> {
            let mut stmt = conn.prepare_cached(
                "SELECT ip FROM request WHERE ts >= ? AND ip IS NOT NULL ORDER BY ts DESC LIMIT 5000",
            )?;
            let rows = stmt
                .query_map([since_ms], |row| Ok((row.get(0)?,)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to query requests.db for country distribution");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // ── Totals ────────────────────────────────────────────────────
    let mut totals = Totals {
        failed_logins: 0,
        rate_limited: 0,
        bad_requests: 0,
        unique_ips: 0,
    };
    let mut unique_ip_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in &bad {
        totals.bad_requests += 1;
        match r.bad_reason.as_deref() {
            Some("Incorrect Login") => totals.failed_logins += 1,
            Some("Rate Limited") => totals.rate_limited += 1,
            _ => {}
        }
        if let Some(ip) = &r.ip {
            unique_ip_set.insert(ip.clone());
        }
    }
    totals.unique_ips = unique_ip_set.len() as u64;

    // ── Timeline buckets (split per reason category) ──────────────
    let bucket_secs = pick_bucket(seconds);
    let mut bucket_map: HashMap<i64, TimelineBucket> = HashMap::new();
    for r in &bad {
        let ts_s = r.ts / 1_000;
        let bucket = ts_s - (ts_s % bucket_secs);
        let entry = bucket_map.entry(bucket).or_insert(TimelineBucket {
            ts: bucket,
            failed_logins: 0,
            rate_limited: 0,
            bad_requests: 0,
        });
        entry.bad_requests += 1;
        match r.bad_reason.as_deref() {
            Some("Incorrect Login") => entry.failed_logins += 1,
            Some("Rate Limited") => entry.rate_limited += 1,
            _ => {}
        }
    }
    let mut timeline: Vec<TimelineBucket> = bucket_map.into_values().collect();
    timeline.sort_by_key(|b| b.ts);

    // ── Top offending IPs (top 25 by count) ───────────────────────
    let mut ip_counts: HashMap<String, u64> = HashMap::new();
    for r in &bad {
        if let Some(ip) = &r.ip {
            *ip_counts.entry(ip.clone()).or_default() += 1;
        }
    }
    let mut top_pairs: Vec<(String, u64)> = ip_counts.into_iter().collect();
    top_pairs.sort_by_key(|p| std::cmp::Reverse(p.1));
    top_pairs.truncate(25);
    let geo = &state.geoip;
    let top_ips: Vec<TopIp> = top_pairs
        .into_iter()
        .map(|(ip, count)| {
            let g = geo.lookup_str(&ip).unwrap_or_default();
            TopIp {
                ip,
                count,
                country_code: g.country_code,
                country: g.country,
                city: g.city,
            }
        })
        .collect();

    // ── Reason breakdown ──────────────────────────────────────────
    let mut reason_counts: HashMap<String, u64> = HashMap::new();
    for r in &bad {
        let reason = r.bad_reason.clone().unwrap_or_else(|| "Other".to_string());
        *reason_counts.entry(reason).or_default() += 1;
    }
    let mut reason_breakdown: Vec<ReasonCount> = reason_counts
        .into_iter()
        .map(|(reason, count)| ReasonCount { reason, count })
        .collect();
    reason_breakdown.sort_by_key(|r| std::cmp::Reverse(r.count));

    // ── Country distribution (across all requests, not just 4xx) ──
    let mut country_counts: HashMap<String, (String, u64)> = HashMap::new();
    for (ip,) in &countries_raw {
        let Some(ip) = ip else { continue };
        let g = geo.lookup_str(ip).unwrap_or_default();
        if g.country_code.is_empty() {
            continue;
        }
        let entry = country_counts.entry(g.country_code.clone()).or_insert((g.country, 0));
        entry.1 += 1;
    }
    let mut country_distribution: Vec<CountryCount> = country_counts
        .into_iter()
        .map(|(country_code, (country, count))| CountryCount {
            country_code,
            country,
            count,
        })
        .collect();
    country_distribution.sort_by_key(|c| std::cmp::Reverse(c.count));
    country_distribution.truncate(15);

    // ── Recent feed (newest 50) ───────────────────────────────────
    let recent: Vec<RecentEvent> = bad
        .iter()
        .take(50)
        .map(|r| {
            let g = r.ip.as_deref().and_then(|ip| geo.lookup_str(ip)).unwrap_or_default();
            RecentEvent {
                ts: r.ts / 1_000,
                ip: r.ip.clone(),
                country_code: g.country_code,
                path: r.path.clone(),
                status_code: r.status_code,
                reason: r.bad_reason.clone().unwrap_or_else(|| "Bad Request".to_string()),
                user_id: r.user_id,
            }
        })
        .collect();

    Ok(Json(SecurityData {
        timeline,
        top_ips,
        reason_breakdown,
        country_distribution,
        recent,
        totals,
    }))
}

/// Pick a sensible bucket size so timeline charts have ~40-120 buckets.
fn pick_bucket(window_secs: i64) -> i64 {
    match window_secs {
        n if n <= 3_600 => 60,           // 1h → 1-min buckets
        n if n <= 6 * 3_600 => 5 * 60,   // 6h → 5-min
        n if n <= 24 * 3_600 => 15 * 60, // 24h → 15-min
        n if n <= 7 * 86_400 => 60 * 60, // 7d → 1-hour
        _ => 6 * 60 * 60,                // 30d → 6-hour
    }
}

// ─── Cloudflare panels ─────────────────────────────────────────────────

#[derive(Serialize)]
struct CfData {
    summary: ZoneSummary,
    events: Vec<FirewallEvent>,
}

async fn cloudflare_data(
    State(state): State<AppState>,
    account: Account,
    Query(query): Query<RangeQuery>,
) -> Result<Json<CfData>, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let cf = state.cloudflare.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    let secs = range_to_seconds(&query.range);
    let since = OffsetDateTime::now_utc() - time::Duration::seconds(secs);

    let summary = cf.zone_summary(since).await.map_err(|e| {
        tracing::error!(error = %e, "cloudflare zone_summary failed");
        StatusCode::BAD_GATEWAY
    })?;
    let events = cf.firewall_events(since, 100).await.unwrap_or_default(); // CF may not return WAF events if user has no WAF — non-fatal

    Ok(Json(CfData { summary, events }))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/security", get(security_page))
        .route("/security/data", get(security_data))
        .route("/security/cloudflare", get(cloudflare_data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_to_seconds_handles_all_ranges() {
        assert_eq!(range_to_seconds("1h"), 3_600);
        assert_eq!(range_to_seconds("6h"), 6 * 3_600);
        assert_eq!(range_to_seconds("24h"), 24 * 3_600);
        assert_eq!(range_to_seconds("7d"), 7 * 24 * 3_600);
        assert_eq!(range_to_seconds("30d"), 30 * 24 * 3_600);
        assert_eq!(range_to_seconds("bogus"), 24 * 3_600); // default
    }

    #[test]
    fn pick_bucket_picks_sensible_intervals() {
        assert_eq!(pick_bucket(3_600), 60); // 1h → 1-min
        assert_eq!(pick_bucket(6 * 3_600), 5 * 60); // 6h → 5-min
        assert_eq!(pick_bucket(24 * 3_600), 15 * 60); // 24h → 15-min
        assert_eq!(pick_bucket(7 * 86_400), 60 * 60); // 7d → 1-hour
        assert_eq!(pick_bucket(30 * 86_400), 6 * 60 * 60); // 30d → 6-hour
    }
}
