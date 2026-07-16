//! Minimal S3-compatible PUT-object client using AWS Signature V4.
//!
//! Just enough of the protocol to push a backup file off-site. Path-style
//! addressing (`{endpoint}/{bucket}/{key}`) and SigV4 are accepted by AWS S3,
//! Backblaze B2, Cloudflare R2, MinIO, Wasabi, and friends, so a single code
//! path covers every realistic target. No SDK dependency — signing is a few
//! HMAC-SHA256 chains, which `hmac` + `sha2` (already in the tree) give us.
//!
//! The whole file is read into memory to compute the payload hash that SigV4
//! requires. Backups are small relative to host RAM, so streaming is not worth
//! the extra complexity here.

use anyhow::Context;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use time::macros::format_description;

use crate::config::BackupRemoteConfig;

type HmacSha256 = Hmac<Sha256>;

const SERVICE: &str = "s3";
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    to_hex(&hasher.finalize())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    out
}

/// Percent-encodes a single object-key/path component per RFC 3986
/// "unreserved" rules, which is what SigV4 canonicalisation expects. When
/// `keep_slash` is true, `/` is left intact (object keys are signed with their
/// slashes preserved).
fn uri_encode(input: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(char::from_digit((b >> 4) as u32, 16).unwrap().to_ascii_uppercase());
            out.push(char::from_digit((b & 0xf) as u32, 16).unwrap().to_ascii_uppercase());
        }
    }
    out
}

/// Uploads `path` to the configured bucket, keyed by `prefix + filename`.
/// Returns the object key on success.
pub async fn upload_file(
    client: &reqwest::Client,
    cfg: &BackupRemoteConfig,
    path: &std::path::Path,
) -> anyhow::Result<String> {
    if !cfg.kind.eq_ignore_ascii_case("s3") {
        anyhow::bail!(
            "unsupported backup.remote.kind: {} (only \"s3\" is supported)",
            cfg.kind
        );
    }
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .context("backup path has no file name")?;
    let key = format!("{}{}", cfg.normalized_prefix(), filename);

    let body = tokio::fs::read(path)
        .await
        .with_context(|| format!("could not read backup file {}", path.display()))?;

    let endpoint = cfg.endpoint.trim_end_matches('/');
    // Canonical resource path: /<bucket>/<key>, each component URI-encoded with
    // slashes preserved inside the key.
    let canonical_uri = format!("/{}/{}", uri_encode(&cfg.bucket, false), uri_encode(&key, true));
    let url = format!("{endpoint}{canonical_uri}");
    let parsed = reqwest::Url::parse(&url).with_context(|| format!("invalid remote endpoint URL: {url}"))?;

    // Host header exactly as reqwest will send it (include non-default port).
    let host = match (parsed.host_str(), parsed.port()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_string(),
        (None, _) => anyhow::bail!("remote endpoint URL has no host: {url}"),
    };

    let now = time::OffsetDateTime::now_utc();
    let amz_date = now
        .format(format_description!("[year][month][day]T[hour][minute][second]Z"))
        .context("formatting amz date")?;
    let datestamp = now
        .format(format_description!("[year][month][day]"))
        .context("formatting datestamp")?;

    let payload_hash = sha256_hex(&body);

    // ── Canonical request ──────────────────────────────────────────────────
    let canonical_headers = format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!("PUT\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    // ── String to sign ─────────────────────────────────────────────────────
    let scope = format!("{datestamp}/{}/{SERVICE}/aws4_request", cfg.region);
    let string_to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    // ── Signing key (HMAC chain) ───────────────────────────────────────────
    let k_date = hmac(
        format!("AWS4{}", cfg.secret_access_key).as_bytes(),
        datestamp.as_bytes(),
    );
    let k_region = hmac(&k_date, cfg.region.as_bytes());
    let k_service = hmac(&k_region, SERVICE.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = to_hex(&hmac(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        cfg.access_key_id
    );

    let resp = client
        .put(parsed)
        .header("Authorization", authorization)
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .context("PUT request to remote store failed")?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        let snippet: String = text.chars().take(300).collect();
        anyhow::bail!("remote store rejected upload ({status}): {snippet}");
    }
    Ok(key)
}

/// Pulls `<Key>…</Key>` values out of an S3 `ListObjectsV2` XML response.
/// Hand-rolled (no XML dependency) — the response shape is fixed and the keys
/// never contain `<`, so a literal scan is sufficient and easy to test.
fn extract_keys(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(open) = rest.find("<Key>") {
        let after = &rest[open + "<Key>".len()..];
        let Some(close) = after.find("</Key>") else { break };
        out.push(after[..close].to_string());
        rest = &after[close + "</Key>".len()..];
    }
    out
}

/// Lists object keys under the configured prefix via `ListObjectsV2` (one
/// signed GET). Returns the full keys (prefix included). Best-effort: used to
/// show which local backups also exist off-site, so it carries a short timeout.
pub async fn list_keys(client: &reqwest::Client, cfg: &BackupRemoteConfig) -> anyhow::Result<Vec<String>> {
    if !cfg.kind.eq_ignore_ascii_case("s3") {
        anyhow::bail!(
            "unsupported backup.remote.kind: {} (only \"s3\" is supported)",
            cfg.kind
        );
    }

    let endpoint = cfg.endpoint.trim_end_matches('/');
    let canonical_uri = format!("/{}", uri_encode(&cfg.bucket, false));
    // SigV4 canonical query: keys sorted, values URI-encoded (slashes too).
    let prefix = cfg.normalized_prefix();
    let canonical_query = format!("list-type=2&prefix={}", uri_encode(&prefix, false));
    let url = format!("{endpoint}{canonical_uri}?{canonical_query}");
    let parsed = reqwest::Url::parse(&url).with_context(|| format!("invalid remote endpoint URL: {url}"))?;

    let host = match (parsed.host_str(), parsed.port()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_string(),
        (None, _) => anyhow::bail!("remote endpoint URL has no host: {url}"),
    };

    let now = time::OffsetDateTime::now_utc();
    let amz_date = now
        .format(format_description!("[year][month][day]T[hour][minute][second]Z"))
        .context("formatting amz date")?;
    let datestamp = now
        .format(format_description!("[year][month][day]"))
        .context("formatting datestamp")?;

    // GET with an empty body — the payload hash is SHA-256 of "".
    let payload_hash = sha256_hex(b"");
    let canonical_headers = format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request =
        format!("GET\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let scope = format!("{datestamp}/{}/{SERVICE}/aws4_request", cfg.region);
    let string_to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac(
        format!("AWS4{}", cfg.secret_access_key).as_bytes(),
        datestamp.as_bytes(),
    );
    let k_region = hmac(&k_date, cfg.region.as_bytes());
    let k_service = hmac(&k_region, SERVICE.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = to_hex(&hmac(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        cfg.access_key_id
    );

    let resp = client
        .get(parsed)
        .header("Authorization", authorization)
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .timeout(std::time::Duration::from_secs(8))
        .send()
        .await
        .context("ListObjectsV2 request to remote store failed")?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        let snippet: String = text.chars().take(300).collect();
        anyhow::bail!("remote store rejected list ({status}): {snippet}");
    }
    Ok(extract_keys(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_keys_pulls_all_keys() {
        let xml = "<ListBucketResult><Contents><Key>db/backup-1.db</Key><Size>10</Size></Contents>\
                   <Contents><Key>db/backup-2.db</Key></Contents></ListBucketResult>";
        assert_eq!(extract_keys(xml), vec!["db/backup-1.db", "db/backup-2.db"]);
        assert!(extract_keys("<ListBucketResult></ListBucketResult>").is_empty());
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    #[test]
    fn sha256_known_vector() {
        // SHA-256 of the empty string.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn uri_encode_preserves_unreserved_and_slash() {
        assert_eq!(uri_encode("backup-123.db", true), "backup-123.db");
        assert_eq!(uri_encode("a/b c", true), "a/b%20c");
        assert_eq!(uri_encode("a/b", false), "a%2Fb");
    }

    #[test]
    fn signing_key_matches_aws_reference() {
        // AWS SigV4 documentation worked example (key derivation):
        // secret "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", date 20150830,
        // region us-east-1, service iam.
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let k_date = hmac(format!("AWS4{secret}").as_bytes(), b"20150830");
        let k_region = hmac(&k_date, b"us-east-1");
        let k_service = hmac(&k_region, b"iam");
        let k_signing = hmac(&k_service, b"aws4_request");
        assert_eq!(
            to_hex(&k_signing),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }
}
