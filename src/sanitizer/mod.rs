//! File sanitizer: upload a file, scan it with ClamAV + VirusTotal, record history.

mod clamav;
pub mod routes;
mod virustotal;

use crate::AppState;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Combined scan report from ClamAV and VirusTotal.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub sha256: String,
    pub file_size: i64,
    pub clamav_clean: Option<bool>,
    pub clamav_virus: Option<String>,
    pub vt_status: Option<String>,
    pub vt_positives: Option<i64>,
    pub vt_total: Option<i64>,
    pub vt_url: Option<String>,
}

/// Scans `data` with the configured backends (ClamAV + VirusTotal) and returns
/// a combined report. When a backend isn't configured, its fields stay `None`.
pub async fn scan_bytes(state: &AppState, data: &[u8]) -> ScanReport {
    let file_size = data.len() as i64;
    let sha256 = sha256_hex(data);

    // ClamAV scan (if configured)
    let (clamav_clean, clamav_virus) = if let Some(addr) = state.config.clamav_addr.as_deref() {
        match clamav::scan(addr, data).await {
            Ok(result) => {
                if result.clean {
                    (Some(true), None)
                } else {
                    (Some(false), result.virus)
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "ClamAV scan error");
                (None, Some(format!("scan error: {e}")))
            }
        }
    } else {
        (None, None)
    };

    // VirusTotal lookup (if configured)
    let (vt_status, vt_positives, vt_total, vt_url) = if let Some(key) = state.config.virustotal_api_key.as_deref() {
        match virustotal::check_hash(&state.client, key, &sha256).await {
            Ok(Some(result)) => (
                Some(result.status),
                Some(result.positives),
                Some(result.total),
                Some(result.url),
            ),
            Ok(None) => (Some("unknown".to_string()), None, None, None),
            Err(e) => {
                tracing::warn!(error = %e, "VirusTotal lookup error");
                (Some("error".to_string()), None, None, None)
            }
        }
    } else {
        (None, None, None, None)
    };

    ScanReport {
        sha256,
        file_size,
        clamav_clean,
        clamav_virus,
        vt_status,
        vt_positives,
        vt_total,
        vt_url,
    }
}

/// Computes the lowercase hex SHA-256 of `data`.
fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in digest.iter() {
        write!(&mut s, "{b:02x}").unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_computes_correct_digest() {
        let data = b"hello world";
        let hash = sha256_hex(data);
        assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }
}
