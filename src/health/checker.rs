//! Individual probe implementations.

use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

use super::storage::HealthTarget;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Up,
    Degraded,
    Down,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CheckKind {
    Http,
    Tcp,
    Keyword,
    Ssl,
}

impl CheckKind {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "http" => Some(Self::Http),
            "tcp" => Some(Self::Tcp),
            "keyword" => Some(Self::Keyword),
            "ssl" => Some(Self::Ssl),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckOutcome {
    pub status: CheckStatus,
    pub latency_ms: Option<i64>,
    pub status_code: Option<i64>,
    pub error: Option<String>,
    pub ssl_days_left: Option<i64>,
}

impl CheckOutcome {
    pub fn status_str(&self) -> &'static str {
        match self.status {
            CheckStatus::Up => "up",
            CheckStatus::Degraded => "degraded",
            CheckStatus::Down => "down",
        }
    }
}

/// Per-kind options stored in `health_target.config_json`.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct CheckConfig {
    #[serde(default)]
    pub keyword: Option<String>,
    /// Acceptable HTTP status codes.  Empty = accept 2xx + 3xx.
    #[serde(default)]
    pub expected_status: Vec<u16>,
    /// HTTP method to use for http/keyword checks.  Defaults to GET.
    #[serde(default)]
    pub method: Option<String>,
    /// SSL: trigger "degraded" when the cert expires within this many days.
    #[serde(default)]
    pub warn_days: Option<i64>,
    /// Whether to follow HTTP redirects (default: true).
    #[serde(default)]
    pub follow_redirects: Option<bool>,
    /// Treat the absence of the keyword as success instead of failure.
    /// Useful for monitoring that a maintenance string is *gone*.
    #[serde(default)]
    pub invert_keyword: Option<bool>,
}

impl CheckConfig {
    pub fn from_json(s: &str) -> Self {
        serde_json::from_str(s).unwrap_or_default()
    }
}

pub async fn run(target: &HealthTarget, client: &reqwest::Client) -> CheckOutcome {
    let config = CheckConfig::from_json(&target.config_json);
    let timeout = Duration::from_millis(target.timeout_ms.max(500) as u64);
    let degraded_ms = target.degraded_ms.max(50);

    let kind = match CheckKind::from_str(&target.kind) {
        Some(k) => k,
        None => {
            return CheckOutcome {
                status: CheckStatus::Down,
                latency_ms: None,
                status_code: None,
                error: Some(format!("unknown check kind: {}", target.kind)),
                ssl_days_left: None,
            }
        }
    };

    match kind {
        CheckKind::Http | CheckKind::Keyword => http_check(client, target, &config, timeout, degraded_ms, kind).await,
        CheckKind::Tcp => tcp_check(&target.target, timeout, degraded_ms).await,
        CheckKind::Ssl => ssl_check(&target.target, &config, timeout, degraded_ms).await,
    }
}

async fn http_check(
    client: &reqwest::Client,
    target: &HealthTarget,
    config: &CheckConfig,
    timeout: Duration,
    degraded_ms: i64,
    kind: CheckKind,
) -> CheckOutcome {
    let method = config.method.as_deref().unwrap_or("GET").to_ascii_uppercase();
    let method = match method.as_str() {
        "GET" => reqwest::Method::GET,
        "HEAD" => reqwest::Method::HEAD,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "OPTIONS" => reqwest::Method::OPTIONS,
        other => {
            return CheckOutcome {
                status: CheckStatus::Down,
                latency_ms: None,
                status_code: None,
                error: Some(format!("unsupported HTTP method: {other}")),
                ssl_days_left: None,
            };
        }
    };

    let start = Instant::now();
    let req = client
        .request(method, &target.target)
        .timeout(timeout)
        .header("user-agent", "klappstuhl-health/1.0");

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return CheckOutcome {
                status: CheckStatus::Down,
                latency_ms: Some(start.elapsed().as_millis() as i64),
                status_code: None,
                error: Some(short_err(&e.to_string())),
                ssl_days_left: None,
            };
        }
    };

    let status_code = resp.status().as_u16();
    let status_ok = if config.expected_status.is_empty() {
        resp.status().is_success() || resp.status().is_redirection()
    } else {
        config.expected_status.contains(&status_code)
    };

    if !status_ok {
        return CheckOutcome {
            status: CheckStatus::Down,
            latency_ms: Some(start.elapsed().as_millis() as i64),
            status_code: Some(status_code as i64),
            error: Some(format!("unexpected status {status_code}")),
            ssl_days_left: None,
        };
    }

    // Keyword check: read body, look for substring.
    if matches!(kind, CheckKind::Keyword) {
        if let Some(keyword) = config.keyword.as_deref().filter(|s| !s.is_empty()) {
            let body = match resp.text().await {
                Ok(b) => b,
                Err(e) => {
                    return CheckOutcome {
                        status: CheckStatus::Down,
                        latency_ms: Some(start.elapsed().as_millis() as i64),
                        status_code: Some(status_code as i64),
                        error: Some(format!("body read: {}", short_err(&e.to_string()))),
                        ssl_days_left: None,
                    };
                }
            };
            let invert = config.invert_keyword.unwrap_or(false);
            let found = body.contains(keyword);
            if found == invert {
                let msg = if invert {
                    format!("keyword `{keyword}` was present (expected absent)")
                } else {
                    format!("keyword `{keyword}` not found")
                };
                return CheckOutcome {
                    status: CheckStatus::Down,
                    latency_ms: Some(start.elapsed().as_millis() as i64),
                    status_code: Some(status_code as i64),
                    error: Some(msg),
                    ssl_days_left: None,
                };
            }
        }
    }

    let elapsed = start.elapsed().as_millis() as i64;
    let status = if elapsed > degraded_ms {
        CheckStatus::Degraded
    } else {
        CheckStatus::Up
    };

    CheckOutcome {
        status,
        latency_ms: Some(elapsed),
        status_code: Some(status_code as i64),
        error: if matches!(status, CheckStatus::Degraded) {
            Some(format!("slow response ({elapsed} ms > {degraded_ms} ms)"))
        } else {
            None
        },
        ssl_days_left: None,
    }
}

async fn tcp_check(target: &str, timeout: Duration, degraded_ms: i64) -> CheckOutcome {
    let start = Instant::now();
    let target_owned = target.to_string();

    // Resolve in a blocking pool to avoid spending the timeout on a slow DNS lookup.
    let addrs = match tokio::task::spawn_blocking(move || target_owned.to_socket_addrs())
        .await
        .ok()
        .and_then(|r| r.ok())
    {
        Some(addrs) => addrs.collect::<Vec<_>>(),
        None => {
            return CheckOutcome {
                status: CheckStatus::Down,
                latency_ms: Some(start.elapsed().as_millis() as i64),
                status_code: None,
                error: Some("DNS resolution failed".into()),
                ssl_days_left: None,
            }
        }
    };

    let Some(addr) = addrs.into_iter().next() else {
        return CheckOutcome {
            status: CheckStatus::Down,
            latency_ms: Some(start.elapsed().as_millis() as i64),
            status_code: None,
            error: Some("no addresses resolved".into()),
            ssl_days_left: None,
        };
    };

    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => {
            let elapsed = start.elapsed().as_millis() as i64;
            let status = if elapsed > degraded_ms {
                CheckStatus::Degraded
            } else {
                CheckStatus::Up
            };
            CheckOutcome {
                status,
                latency_ms: Some(elapsed),
                status_code: None,
                error: if matches!(status, CheckStatus::Degraded) {
                    Some(format!("slow connect ({elapsed} ms > {degraded_ms} ms)"))
                } else {
                    None
                },
                ssl_days_left: None,
            }
        }
        Ok(Err(e)) => CheckOutcome {
            status: CheckStatus::Down,
            latency_ms: Some(start.elapsed().as_millis() as i64),
            status_code: None,
            error: Some(short_err(&e.to_string())),
            ssl_days_left: None,
        },
        Err(_) => CheckOutcome {
            status: CheckStatus::Down,
            latency_ms: Some(timeout.as_millis() as i64),
            status_code: None,
            error: Some("timeout".into()),
            ssl_days_left: None,
        },
    }
}

async fn ssl_check(target: &str, config: &CheckConfig, timeout: Duration, _degraded_ms: i64) -> CheckOutcome {
    let start = Instant::now();
    let (host, port) = parse_host_port(target);

    let target_owned = format!("{host}:{port}");
    let host_clone = host.clone();
    let addrs = match tokio::task::spawn_blocking(move || target_owned.to_socket_addrs())
        .await
        .ok()
        .and_then(|r| r.ok())
    {
        Some(addrs) => addrs.collect::<Vec<_>>(),
        None => {
            return CheckOutcome {
                status: CheckStatus::Down,
                latency_ms: Some(start.elapsed().as_millis() as i64),
                status_code: None,
                error: Some("DNS resolution failed".into()),
                ssl_days_left: None,
            }
        }
    };

    let Some(addr) = addrs.into_iter().next() else {
        return CheckOutcome {
            status: CheckStatus::Down,
            latency_ms: Some(start.elapsed().as_millis() as i64),
            status_code: None,
            error: Some("no addresses resolved".into()),
            ssl_days_left: None,
        };
    };

    let result = tokio::time::timeout(timeout, async {
        let tcp = TcpStream::connect(addr).await?;

        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertVerifier))
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(host_clone.as_str())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?
            .to_owned();

        let stream = connector.connect(server_name, tcp).await?;
        let (_, conn) = stream.get_ref();
        let certs: Vec<CertificateDer<'static>> = conn
            .peer_certificates()
            .map(|c| c.iter().map(|d| d.clone().into_owned()).collect())
            .unwrap_or_default();
        // Drop the TLS stream — we only wanted the peer cert chain.
        drop(stream);
        Ok::<_, std::io::Error>(certs)
    })
    .await;

    let certs = match result {
        Ok(Ok(c)) if !c.is_empty() => c,
        Ok(Ok(_)) => {
            return CheckOutcome {
                status: CheckStatus::Down,
                latency_ms: Some(start.elapsed().as_millis() as i64),
                status_code: None,
                error: Some("no peer certificate".into()),
                ssl_days_left: None,
            }
        }
        Ok(Err(e)) => {
            return CheckOutcome {
                status: CheckStatus::Down,
                latency_ms: Some(start.elapsed().as_millis() as i64),
                status_code: None,
                error: Some(short_err(&e.to_string())),
                ssl_days_left: None,
            }
        }
        Err(_) => {
            return CheckOutcome {
                status: CheckStatus::Down,
                latency_ms: Some(timeout.as_millis() as i64),
                status_code: None,
                error: Some("TLS handshake timeout".into()),
                ssl_days_left: None,
            }
        }
    };

    let leaf = &certs[0];
    let days_left = match x509_parser::parse_x509_certificate(leaf.as_ref()) {
        Ok((_, parsed)) => {
            let not_after = parsed.validity().not_after.timestamp();
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            (not_after - now) / 86_400
        }
        Err(e) => {
            return CheckOutcome {
                status: CheckStatus::Down,
                latency_ms: Some(start.elapsed().as_millis() as i64),
                status_code: None,
                error: Some(format!("cert parse: {e}")),
                ssl_days_left: None,
            }
        }
    };

    let warn = config.warn_days.unwrap_or(14);
    let elapsed = start.elapsed().as_millis() as i64;
    let (status, error) = if days_left <= 0 {
        (
            CheckStatus::Down,
            Some(format!("certificate expired ({days_left} days)")),
        )
    } else if days_left <= warn {
        (
            CheckStatus::Degraded,
            Some(format!("certificate expires in {days_left} days")),
        )
    } else {
        (CheckStatus::Up, None)
    };

    CheckOutcome {
        status,
        latency_ms: Some(elapsed),
        status_code: None,
        error,
        ssl_days_left: Some(days_left),
    }
}

fn parse_host_port(target: &str) -> (String, u16) {
    // Accept `host:port`, `host`, `https://host[:port]/path`.
    if let Ok(url) = reqwest::Url::parse(target) {
        let host = url.host_str().unwrap_or("").to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        return (host, port);
    }
    if let Some((h, p)) = target.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (target.to_string(), 443)
}

fn short_err(e: &str) -> String {
    let trimmed = e.trim();
    if trimmed.len() > 160 {
        format!("{}…", &trimmed[..160])
    } else {
        trimmed.to_string()
    }
}

// ─── rustls cert verifier that accepts anything ──────────────────────
//
// Safe here because we never trust the certs — we only inspect them for
// the validity period.

#[derive(Debug)]
struct AcceptAnyCertVerifier;

impl ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_kind_parses_known_and_rejects_unknown() {
        assert_eq!(CheckKind::from_str("http"), Some(CheckKind::Http));
        assert_eq!(CheckKind::from_str("tcp"), Some(CheckKind::Tcp));
        assert_eq!(CheckKind::from_str("keyword"), Some(CheckKind::Keyword));
        assert_eq!(CheckKind::from_str("ssl"), Some(CheckKind::Ssl));
        assert_eq!(CheckKind::from_str("ping"), None);
    }

    #[test]
    fn config_json_tolerates_garbage() {
        let cfg = CheckConfig::from_json(r#"{"keyword":"ok","warn_days":7}"#);
        assert_eq!(cfg.keyword.as_deref(), Some("ok"));
        assert_eq!(cfg.warn_days, Some(7));
        // Malformed JSON falls back to defaults rather than panicking.
        let cfg = CheckConfig::from_json("not json");
        assert!(cfg.keyword.is_none());
        assert!(cfg.warn_days.is_none());
    }

    #[test]
    fn parse_host_port_reads_urls_bare_hosts_and_host_port() {
        assert_eq!(
            parse_host_port("https://example.com/path"),
            ("example.com".to_string(), 443)
        );
        // A digit-leading `host:port` can't be a URL scheme, so it hits the
        // `rsplit_once(':')` fallback and keeps the explicit port.
        assert_eq!(parse_host_port("127.0.0.1:9000"), ("127.0.0.1".to_string(), 9000));
        // A bare host with no scheme/port defaults to 443 (the SSL check target).
        assert_eq!(parse_host_port("example.com"), ("example.com".to_string(), 443));
    }

    #[test]
    fn short_err_truncates_long_messages() {
        let long = "x".repeat(300);
        let out = short_err(&long);
        assert!(out.ends_with('…'));
        assert!(out.chars().count() <= 161);
        assert_eq!(short_err("  brief  "), "brief");
    }
}
