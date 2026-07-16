//! Per-container Docker statistics.
//!
//! Shells out to `docker stats --no-stream --format "{{json .}}"` (via the typed
//! [`kls_agent`] boundary) which prints one JSON object per running container.
//! Parsing JSON keeps us independent of the column widths that the
//! human-readable format uses.
//!
//! Ported verbatim from the monolith's `admin/metrics/docker.rs`.

use kls_agent::exec::{HostCommand, Tool};
use serde::{Deserialize, Serialize};

/// One container row from `docker stats`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DockerStat {
    pub name: String,
    pub cpu_pct: f64,
    pub mem_used: u64,
    pub mem_limit: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

/// Raw row as produced by `docker stats --format '{{json .}}'`.
///
/// Numeric fields arrive as human strings ("12.34%", "256MiB / 8GiB", "1.2kB / 850B")
/// — we parse them out below.
#[derive(Deserialize)]
struct RawStat {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "CPUPerc")]
    cpu_perc: String,
    #[serde(rename = "MemUsage")]
    mem_usage: String,
    #[serde(rename = "NetIO")]
    net_io: String,
}

/// Returns one [`DockerStat`] per running container. Returns Err if `docker`
/// isn't available; an empty Vec if it ran but no containers are up.
pub async fn collect() -> anyhow::Result<Vec<DockerStat>> {
    let out = HostCommand::new(Tool::Docker)
        .args(["stats", "--no-stream", "--format", "{{json .}}"])
        .output()
        .await?;
    if !out.status.success() {
        anyhow::bail!("docker stats exited with status {}", out.status);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut result = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let raw: RawStat = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => continue, // malformed line — skip
        };
        let (mem_used, mem_limit) = parse_mem_pair(&raw.mem_usage);
        let (net_rx, net_tx) = parse_io_pair(&raw.net_io);
        result.push(DockerStat {
            name: raw.name,
            cpu_pct: parse_percent(&raw.cpu_perc),
            mem_used,
            mem_limit,
            net_rx_bytes: net_rx,
            net_tx_bytes: net_tx,
        });
    }
    Ok(result)
}

/// "12.34%" → 12.34
fn parse_percent(s: &str) -> f64 {
    s.trim_end_matches('%').trim().parse().unwrap_or(0.0)
}

/// "256MiB / 8GiB" → (256MiB_in_bytes, 8GiB_in_bytes)
fn parse_mem_pair(s: &str) -> (u64, u64) {
    let mut iter = s.split('/').map(str::trim);
    let used = iter.next().map(parse_size).unwrap_or(0);
    let limit = iter.next().map(parse_size).unwrap_or(0);
    (used, limit)
}

/// Same shape as mem: "1.2kB / 850B" → (1200, 850).
fn parse_io_pair(s: &str) -> (u64, u64) {
    parse_mem_pair(s)
}

/// "256MiB" → 268435456.  Accepts the suffixes Docker uses:
/// B, kB, MB, GB, TB (decimal) and KiB, MiB, GiB, TiB (binary).
fn parse_size(s: &str) -> u64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }
    // Find where the unit suffix starts (first non-digit / dot / minus)
    let unit_start = s
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit() && *c != '.' && *c != '-')
        .map(|(i, _)| i)
        .unwrap_or(s.len());

    let (num_str, unit) = s.split_at(unit_start);
    let num: f64 = num_str.parse().unwrap_or(0.0);
    let mult: f64 = match unit.trim() {
        "" | "B" => 1.0,
        "kB" => 1_000.0,
        "MB" => 1_000_000.0,
        "GB" => 1_000_000_000.0,
        "TB" => 1_000_000_000_000.0,
        "KiB" => 1024.0,
        "MiB" => 1024.0 * 1024.0,
        "GiB" => 1024.0 * 1024.0 * 1024.0,
        "TiB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    };
    (num * mult) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_parsing() {
        assert_eq!(parse_size("256MiB"), 256 * 1024 * 1024);
        assert_eq!(parse_size("1.5GiB"), (1.5_f64 * 1024.0 * 1024.0 * 1024.0) as u64);
        assert_eq!(parse_size("100kB"), 100_000);
        assert_eq!(parse_size("850B"), 850);
        assert_eq!(parse_size(""), 0);
    }

    #[test]
    fn pct_parsing() {
        assert!((parse_percent("12.34%") - 12.34).abs() < 1e-9);
        assert_eq!(parse_percent("0.00%"), 0.0);
    }

    #[test]
    fn mem_pair_parsing() {
        let (u, l) = parse_mem_pair("256MiB / 8GiB");
        assert_eq!(u, 256 * 1024 * 1024);
        assert_eq!(l, 8 * 1024 * 1024 * 1024);
    }
}
