//! Minimal VirusTotal v3 API client for hash lookups.

use serde::Deserialize;
use std::time::Duration;

#[derive(Debug)]
pub struct VtResult {
    pub status: String,
    pub positives: i64,
    pub total: i64,
    pub url: String,
}

/// Looks up `sha256` on VirusTotal. Returns `None` if the file hasn't been
/// analyzed yet (404), `Some(VtResult)` if found. Timeout: 30 seconds.
pub async fn check_hash(client: &reqwest::Client, api_key: &str, sha256: &str) -> anyhow::Result<Option<VtResult>> {
    tokio::time::timeout(Duration::from_secs(30), check_hash_inner(client, api_key, sha256))
        .await
        .map_err(|_| anyhow::anyhow!("VirusTotal lookup timed out"))?
}

async fn check_hash_inner(client: &reqwest::Client, api_key: &str, sha256: &str) -> anyhow::Result<Option<VtResult>> {
    let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
    let resp = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("VirusTotal request failed: {e}"))?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("VirusTotal API returned {}", resp.status()));
    }

    let json: VtApiResponse = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("VirusTotal response parse failed: {e}"))?;

    let stats = json.data.attributes.last_analysis_stats;
    let malicious = stats.malicious;
    let suspicious = stats.suspicious;
    let harmless = stats.harmless;
    let undetected = stats.undetected;
    let total = malicious + suspicious + harmless + undetected;
    let positives = malicious + suspicious;
    let vt_url = format!("https://www.virustotal.com/gui/file/{sha256}");

    let status = if positives > 0 {
        "detected".to_string()
    } else {
        "clean".to_string()
    };

    Ok(Some(VtResult {
        status,
        positives,
        total,
        url: vt_url,
    }))
}

#[derive(Deserialize)]
struct VtApiResponse {
    data: VtData,
}

#[derive(Deserialize)]
struct VtData {
    attributes: VtAttributes,
}

#[derive(Deserialize)]
struct VtAttributes {
    last_analysis_stats: VtStats,
}

#[derive(Deserialize)]
struct VtStats {
    malicious: i64,
    suspicious: i64,
    harmless: i64,
    undetected: i64,
}
