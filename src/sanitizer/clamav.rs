//! Minimal ClamAV (clamd) client over the INSTREAM protocol.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
pub struct ClamResult {
    pub clean: bool,
    pub virus: Option<String>,
}

/// Scans `data` via a ClamAV daemon at `addr` over the INSTREAM wire protocol.
/// Returns `Ok(ClamResult)` on success, `Err` on connection/protocol errors.
/// Timeout: 30 seconds.
pub async fn scan(addr: &str, data: &[u8]) -> anyhow::Result<ClamResult> {
    tokio::time::timeout(Duration::from_secs(30), scan_inner(addr, data))
        .await
        .map_err(|_| anyhow::anyhow!("ClamAV scan timed out"))?
}

async fn scan_inner(addr: &str, data: &[u8]) -> anyhow::Result<ClamResult> {
    let mut sock = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| anyhow::anyhow!("connect to clamd ({addr}): {e}"))?;

    // INSTREAM header
    sock.write_all(b"zINSTREAM\0").await?;

    // Send data in 64KB chunks, each prefixed with a 4-byte big-endian length
    const CHUNK: usize = 65536;
    for chunk in data.chunks(CHUNK) {
        let len = chunk.len() as u32;
        sock.write_all(&len.to_be_bytes()).await?;
        sock.write_all(chunk).await?;
    }
    // Terminate with a zero-length chunk
    sock.write_all(&[0u8; 4]).await?;

    // Read the response
    let mut resp = Vec::with_capacity(64);
    sock.read_to_end(&mut resp).await?;

    let resp = std::str::from_utf8(&resp)
        .unwrap_or("")
        .trim_end_matches('\0')
        .trim()
        .to_owned();

    // Parse: either "stream: OK" or "stream: <virus_name> FOUND"
    if resp.ends_with(": OK") {
        Ok(ClamResult {
            clean: true,
            virus: None,
        })
    } else if resp.ends_with(" FOUND") {
        let virus = resp
            .strip_prefix("stream: ")
            .and_then(|s| s.strip_suffix(" FOUND"))
            .unwrap_or(&resp)
            .to_owned();
        Ok(ClamResult {
            clean: false,
            virus: Some(virus),
        })
    } else {
        Err(anyhow::anyhow!("unexpected clamd response: {resp}"))
    }
}
