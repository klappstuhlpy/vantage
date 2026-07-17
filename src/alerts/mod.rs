//! Multi-sink alert fan-out.
//!
//! All alert payloads in the app share the Discord webhook JSON shape
//! (`{username, embeds: [{title, description, fields, color}]}`), whether they
//! come from a builder or a hand-built `json!`. That lets us derive a neutral
//! [`AlertNotification`] from any of them and deliver it to non-Discord sinks
//! (ntfy, a generic webhook, email) without changing the many call sites.
//!
//! ## Where a sink is configured, and where it is switched off
//!
//! *Where an alert goes* is `config.json` and only `config.json`. The web UI can
//! read the sinks (masked) but cannot edit a URL, and that is a security boundary
//! rather than an omission: an endpoint that rewrites the alert destination is an
//! endpoint that redirects your alarms, which is the first thing worth doing to a
//! box you have just broken into.
//!
//! *Whether a sink is currently firing* is runtime state, kept in the `storage`
//! table (`alerts.sink.<name>.enabled`) so muting a noisy sink at 3am does not
//! mean editing a file on the host and restarting. Absent = enabled, so a fresh
//! install behaves exactly as it did before this existed.

use serde::Serialize;
use serde_json::Value;

use kls_web_core::Database;

pub mod routes;

/// The sinks, in the order the page lists them. `&str` rather than an enum
/// because these strings are also the storage keys and the `alert_delivery.sink`
/// column — one spelling, no mapping table to drift.
pub const SINKS: [&str; 4] = ["discord", "ntfy", "webhook", "email"];

/// How many delivery rows are kept. Enough to answer "did last night's alert go
/// out?" without turning `admin.db` into a log store — that is what `logs/` is.
const ALERT_DELIVERY_RETAINED: i64 = 200;

#[derive(Clone, Serialize)]
pub struct NotificationField {
    pub name: String,
    pub value: String,
}

/// A sink-neutral alert distilled from a Discord-shaped payload.
#[derive(Clone, Serialize)]
pub struct AlertNotification {
    pub title: String,
    /// `"success"`, `"error"`, or `"info"` (mapped from the embed color).
    pub level: String,
    /// Title + description + flattened fields, for plain-text sinks.
    pub body: String,
    pub fields: Vec<NotificationField>,
}

impl AlertNotification {
    /// Extracts a neutral notification from the first embed of a Discord-shaped
    /// payload. Missing pieces degrade to sensible defaults.
    pub fn from_discord_value(value: &Value) -> Self {
        let embed = value.get("embeds").and_then(|e| e.get(0));
        let get_str = |key: &str| -> String {
            embed
                .and_then(|e| e.get(key))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };

        let title = {
            let t = get_str("title");
            if t.is_empty() {
                "Alert".to_string()
            } else {
                t
            }
        };
        let description = get_str("description");
        let color = embed.and_then(|e| e.get("color")).and_then(|c| c.as_u64()).unwrap_or(0);
        // Success greens / error reds used across discord.rs + json! payloads.
        let level = match color {
            0x1c7951 | 0x10b981 => "success",
            0xa4392f | 0xef4444 => "error",
            _ => "info",
        }
        .to_string();

        let fields: Vec<NotificationField> = embed
            .and_then(|e| e.get("fields"))
            .and_then(|f| f.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| {
                        let name = f.get("name")?.as_str()?.to_string();
                        let value = f.get("value")?.as_str()?.to_string();
                        Some(NotificationField { name, value })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut body = description;
        for field in &fields {
            if field.name.is_empty() {
                continue;
            }
            if !body.is_empty() {
                body.push('\n');
            }
            body.push_str(&field.name);
            body.push_str(": ");
            body.push_str(&field.value);
        }

        Self {
            title,
            level,
            body,
            fields,
        }
    }

    /// ASCII-only copy of the title, safe for an HTTP header value (titles can
    /// contain emoji, which are invalid in header values).
    fn ascii_title(&self) -> String {
        let t: String = self
            .title
            .chars()
            .filter(|c| c.is_ascii() && !c.is_ascii_control())
            .collect();
        let t = t.trim().to_string();
        if t.is_empty() {
            "Alert".to_string()
        } else {
            t
        }
    }
}

/// Turns `[label](target)` into plain text. When the label and target are
/// identical (e.g. `[/admin/health](/admin/health)`) only the label is kept;
/// otherwise the target is appended in parentheses so the destination survives.
fn delink(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(open) = rest.find('[') {
        // Look for the `](` separating label from target, then the closing `)`.
        if let Some(sep_rel) = rest[open..].find("](") {
            let sep = open + sep_rel;
            if let Some(close_rel) = rest[sep + 2..].find(')') {
                let close = sep + 2 + close_rel;
                let label = &rest[open + 1..sep];
                let target = &rest[sep + 2..close];
                out.push_str(&rest[..open]);
                out.push_str(label);
                if !target.is_empty() && target != label {
                    out.push_str(" (");
                    out.push_str(target);
                    out.push(')');
                }
                rest = &rest[close + 1..];
                continue;
            }
        }
        // Not a well-formed link: emit through the `[` and keep scanning.
        out.push_str(&rest[..=open]);
        rest = &rest[open + 1..];
    }
    out.push_str(rest);
    out
}

/// Strips the Discord-flavoured markdown that appears in alert payloads
/// (`**bold**`, `__underline__`, `~~strike~~`, `` `code` ``, and `[label](url)`
/// links) so plain-text sinks like ntfy don't render the literal markers.
///
/// Single `*` / `_` / `~` are left alone — Discord only uses them paired for
/// emphasis here, and stripping lone ones would mangle identifiers such as
/// `cpu_percent`.
fn strip_markdown(input: &str) -> String {
    let delinked = delink(input);
    // All markers are ASCII, so a byte scan can't split a multi-byte char.
    let b = delinked.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'`' {
            i += 1;
            continue;
        }
        if (c == b'*' || c == b'_' || c == b'~') && i + 1 < b.len() && b[i + 1] == c {
            i += 2;
            continue;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8(out).unwrap_or(delinked)
}

/// Turns a reqwest outcome into the reason string the delivery log stores.
///
/// A 4xx/5xx is a failure here even though reqwest calls it a success — from the
/// operator's side "Discord answered 401" and "Discord was unreachable" are the
/// same fact: the alert did not arrive.
async fn http_outcome(result: reqwest::Result<reqwest::Response>) -> Result<(), String> {
    match result {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) => Err(format!("the endpoint answered {}", response.status())),
        Err(e) if e.is_timeout() => Err("the endpoint timed out".to_string()),
        Err(e) if e.is_connect() => Err("could not connect to the endpoint".to_string()),
        // Deliberately not `{e}`: reqwest's Display includes the full URL, which
        // for every sink here contains the secret.
        Err(_) => Err("the request failed".to_string()),
    }
}

/// POSTs the raw Discord-shaped payload to a Discord webhook URL.
pub async fn send_discord(client: &reqwest::Client, url: &str, value: &Value) -> Result<(), String> {
    http_outcome(client.post(url).json(value).send().await).await
}

/// POSTs the notification to an ntfy topic URL as a plain-text push.
pub async fn send_ntfy(client: &reqwest::Client, url: &str, note: &AlertNotification) -> Result<(), String> {
    let priority = match note.level.as_str() {
        "error" => "high",
        "success" => "default",
        _ => "low",
    };
    let tags = match note.level.as_str() {
        "error" => "rotating_light",
        "success" => "white_check_mark",
        _ => "information_source",
    };
    // ntfy renders plain text, so strip the Discord markdown from the body and
    // title (the title header is also ASCII-folded for header-value safety).
    let body = if note.body.is_empty() {
        strip_markdown(&note.title)
    } else {
        strip_markdown(&note.body)
    };
    http_outcome(
        client
            .post(url)
            .header("Title", strip_markdown(&note.ascii_title()))
            .header("Priority", priority)
            .header("Tags", tags)
            .body(body)
            .send()
            .await,
    )
    .await
}

/// POSTs the neutral notification as JSON to a generic webhook URL.
pub async fn send_webhook(client: &reqwest::Client, url: &str, note: &AlertNotification) -> Result<(), String> {
    http_outcome(client.post(url).json(note).send().await).await
}

// -- SMTP email sink ----------------------------------------------------------
//
// A minimal async SMTP client built on the `tokio-rustls` stack the app
// already pulls in (matching the hand-rolled SigV4 / TOTP / cron style — no
// new dependency). TLS is mandatory: port 465 is implicit TLS, everything
// else upgrades via STARTTLS. Auth is AUTH LOGIN when credentials are present.

use std::io::{Error, Result as IoResult};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use base64::Engine as _;

use crate::config::EmailConfig;

fn smtp_err(msg: &str) -> Error {
    Error::other(format!("smtp: {msg}"))
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

/// The hostname we announce in EHLO — the domain of the `from` address, or
/// `localhost` if it has no `@`. Purely cosmetic to most servers.
fn ehlo_name(cfg: &EmailConfig) -> &str {
    cfg.from
        .split_once('@')
        .map(|(_, domain)| domain)
        .filter(|d| !d.is_empty())
        .unwrap_or("localhost")
}

/// Reads one (possibly multi-line) SMTP reply and returns its 3-digit code.
/// Continuation lines have a `-` as the 4th byte (`250-...`); the final line
/// uses a space (`250 ...`).
async fn read_reply<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> IoResult<u16> {
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Err(smtp_err("connection closed"));
        }
        let bytes = line.as_bytes();
        if bytes.len() < 3 {
            return Err(smtp_err("truncated reply"));
        }
        let code: u16 = line[..3].parse().map_err(|_| smtp_err("bad reply code"))?;
        // More lines coming if the 4th char is a hyphen.
        if bytes.len() >= 4 && bytes[3] == b'-' {
            continue;
        }
        return Ok(code);
    }
}

/// Sends a single command line (CRLF appended) and asserts the reply code.
async fn command<S>(reader: &mut BufReader<S>, line: &str, expect: u16) -> IoResult<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let w = reader.get_mut();
    w.write_all(line.as_bytes()).await?;
    w.write_all(b"\r\n").await?;
    w.flush().await?;
    let code = read_reply(reader).await?;
    if code != expect {
        return Err(smtp_err(&format!(
            "expected {expect}, got {code} after `{}`",
            line.split(' ').next().unwrap_or(line)
        )));
    }
    Ok(())
}

/// Builds a trusting rustls client config from the bundled webpki roots.
fn tls_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Runs the EHLO -> AUTH -> MAIL -> DATA exchange over an established stream.
/// `expect_greeting` is true for implicit-TLS connects (the server sends a
/// fresh 220 over TLS) and false after a STARTTLS upgrade.
async fn deliver<S>(stream: S, cfg: &EmailConfig, message: &[u8], expect_greeting: bool) -> IoResult<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    if expect_greeting && read_reply(&mut reader).await? != 220 {
        return Err(smtp_err("bad greeting"));
    }
    command(&mut reader, &format!("EHLO {}", ehlo_name(cfg)), 250).await?;

    if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
        command(&mut reader, "AUTH LOGIN", 334).await?;
        command(&mut reader, &b64(user), 334).await?;
        command(&mut reader, &b64(pass), 235).await?;
    }

    command(&mut reader, &format!("MAIL FROM:<{}>", cfg.from), 250).await?;
    for to in &cfg.to {
        command(&mut reader, &format!("RCPT TO:<{to}>"), 250).await?;
    }
    command(&mut reader, "DATA", 354).await?;

    let w = reader.get_mut();
    w.write_all(message).await?;
    w.write_all(b"\r\n.\r\n").await?;
    w.flush().await?;
    if read_reply(&mut reader).await? != 250 {
        return Err(smtp_err("message rejected"));
    }
    let _ = command(&mut reader, "QUIT", 221).await; // best-effort
    Ok(())
}

/// Assembles an RFC 5322 message. The body is base64-encoded (avoids 8bit /
/// line-length / dot-stuffing concerns) and the subject uses the ASCII-folded
/// title (sidestepping encoded-word headers for emoji).
fn build_message(cfg: &EmailConfig, note: &AlertNotification) -> Vec<u8> {
    let subject = strip_markdown(&note.ascii_title());
    let text = if note.body.is_empty() {
        strip_markdown(&note.title)
    } else {
        strip_markdown(&note.body)
    };

    let date = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_default();

    // Wrap the base64 body at 76 columns per MIME.
    let encoded = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    let mut wrapped = String::new();
    for chunk in encoded.as_bytes().chunks(76) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        wrapped.push_str("\r\n");
    }

    let headers = format!(
        "From: {from}\r\n\
         To: {to}\r\n\
         Subject: {subject}\r\n\
         Date: {date}\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n",
        from = cfg.from,
        to = cfg.to.join(", "),
    );

    let mut msg = headers.into_bytes();
    msg.extend_from_slice(wrapped.as_bytes());
    msg
}

/// Delivers the notification as an email via SMTP. Errors are returned so the
/// caller can log/alert; deliveries are spawned in the background by `send_alert`.
pub async fn send_email(cfg: &EmailConfig, note: &AlertNotification) -> IoResult<()> {
    if cfg.to.is_empty() {
        return Err(smtp_err("no recipients configured"));
    }
    let message = build_message(cfg, note);

    let server_name =
        rustls_pki_types::ServerName::try_from(cfg.host.clone()).map_err(|_| smtp_err("invalid host name"))?;
    let connector = tokio_rustls::TlsConnector::from(tls_config());

    let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port)).await?;

    if cfg.port == 465 {
        // Implicit TLS — wrap immediately, then expect the 220 greeting.
        let tls = connector.connect(server_name, tcp).await?;
        deliver(tls, cfg, &message, true).await
    } else {
        // STARTTLS — greet + EHLO + STARTTLS in the clear, then upgrade.
        let mut reader = BufReader::new(tcp);
        if read_reply(&mut reader).await? != 220 {
            return Err(smtp_err("bad greeting"));
        }
        command(&mut reader, &format!("EHLO {}", ehlo_name(cfg)), 250).await?;
        command(&mut reader, "STARTTLS", 220).await?;
        let tcp = reader.into_inner();
        let tls = connector.connect(server_name, tcp).await?;
        deliver(tls, cfg, &message, false).await
    }
}

// ─── Sink state (runtime toggles) ────────────────────────────────────────────

fn sink_key(sink: &str) -> String {
    format!("alerts.sink.{sink}.enabled")
}

/// Whether a sink is currently firing. **Absent means enabled** — a fresh
/// install, and every install that predates this table, behaves as it always
/// has. Any read failure also answers `true`: the fail-safe direction for an
/// alarm is to sound, not to stay quiet because a query broke.
pub async fn sink_enabled(db: &Database, sink: &str) -> bool {
    match db
        .get_row("SELECT value FROM storage WHERE name = ?", (sink_key(sink),), |row| {
            row.get::<_, String>(0)
        })
        .await
    {
        Ok(value) => value != "0",
        Err(_) => true,
    }
}

/// Switches a sink on or off.
pub async fn set_sink_enabled(db: &Database, sink: &str, enabled: bool) -> anyhow::Result<()> {
    use anyhow::Context;
    db.execute(
        "INSERT INTO storage(name, value) VALUES (?, ?) \
         ON CONFLICT(name) DO UPDATE SET value = excluded.value",
        (sink_key(sink), if enabled { "1" } else { "0" }),
    )
    .await
    .context("could not save the sink state")?;
    Ok(())
}

/// Storage key for the "alert when someone signs in" toggle.
const ADMIN_LOGIN_KEY: &str = "alerts.on_admin_login";

/// Whether a successful sign-in should raise an alert. Defaults to **off**: on a
/// homelab you sign in daily, and an alarm that fires on every ordinary action is
/// one you learn to ignore — which is worse than not having it.
pub async fn alert_on_admin_login(db: &Database) -> bool {
    db.get_row(
        "SELECT value FROM storage WHERE name = ?",
        (ADMIN_LOGIN_KEY.to_string(),),
        |row| row.get::<_, String>(0),
    )
    .await
    .map(|value| value == "1")
    .unwrap_or(false)
}

pub async fn set_alert_on_admin_login(db: &Database, enabled: bool) -> anyhow::Result<()> {
    use anyhow::Context;
    db.execute(
        "INSERT INTO storage(name, value) VALUES (?, ?) \
         ON CONFLICT(name) DO UPDATE SET value = excluded.value",
        (ADMIN_LOGIN_KEY.to_string(), if enabled { "1" } else { "0" }),
    )
    .await
    .context("could not save the sign-in alert setting")?;
    Ok(())
}

// ─── Delivery log ────────────────────────────────────────────────────────────

/// One attempt to hand one alert to one sink.
#[derive(Debug, Clone, Serialize)]
pub struct Delivery {
    pub id: i64,
    pub sink: String,
    pub title: String,
    pub level: String,
    pub ok: bool,
    pub error: Option<String>,
    pub test: bool,
    pub sent_at: String,
}

/// Records a delivery attempt and prunes the log back to its bound.
///
/// Best-effort: an alert that reached Discord but whose bookkeeping failed is
/// still a delivered alert, and turning that into a visible error would be
/// reporting a problem the operator does not have.
pub async fn record_delivery(
    db: &Database,
    sink: &str,
    note: &AlertNotification,
    result: &Result<(), String>,
    test: bool,
) {
    let (ok, error) = match result {
        Ok(()) => (1i64, None),
        Err(e) => (0i64, Some(e.clone())),
    };
    let inserted = db
        .execute(
            "INSERT INTO alert_delivery(sink, title, level, ok, error, test) VALUES (?, ?, ?, ?, ?, ?)",
            (
                sink.to_string(),
                note.ascii_title(),
                note.level.clone(),
                ok,
                error,
                test as i64,
            ),
        )
        .await;
    if inserted.is_err() {
        return;
    }
    // Prune here rather than in a background task: the table only grows when an
    // alert fires, so the write path is exactly where the bound belongs, and
    // there is no scheduler to forget to start.
    let _ = db
        .execute(
            "DELETE FROM alert_delivery WHERE id <= (SELECT MAX(id) FROM alert_delivery) - ?",
            (ALERT_DELIVERY_RETAINED,),
        )
        .await;
}

/// The most recent delivery attempts, newest first.
pub async fn recent_deliveries(db: &Database, limit: i64) -> anyhow::Result<Vec<Delivery>> {
    use anyhow::Context;
    db.call(move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT id, sink, title, level, ok, error, test, sent_at \
             FROM alert_delivery ORDER BY id DESC LIMIT ?",
        )?;
        let rows: rusqlite::Result<Vec<Delivery>> = stmt
            .query_map((limit,), |row| {
                Ok(Delivery {
                    id: row.get(0)?,
                    sink: row.get(1)?,
                    title: row.get(2)?,
                    level: row.get(3)?,
                    ok: row.get::<_, i64>(4)? != 0,
                    error: row.get(5)?,
                    test: row.get::<_, i64>(6)? != 0,
                    sent_at: row.get(7)?,
                })
            })?
            .collect();
        rows
    })
    .await
    .context("could not read the delivery log")
}

// ─── Masking ─────────────────────────────────────────────────────────────────

/// Renders a sink URL safe to show on a page.
///
/// Keeps the scheme and host, drops everything after. The host is the part worth
/// checking (is this going to discord.com or to somewhere else?) and everything
/// after it is, for every sink Vantage supports, the secret itself — a Discord
/// webhook's path *is* its token, and an ntfy topic name *is* its address. There
/// is no "last 4 characters" here on purpose: revealing a suffix of a credential
/// helps an operator identify it and helps an attacker confirm it, and only one
/// of those two needs this page.
pub fn mask_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "(malformed URL)".to_string();
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        return "(malformed URL)".to_string();
    }
    let has_more = rest.len() > host.len();
    if has_more {
        format!("{scheme}://{host}/…")
    } else {
        format!("{scheme}://{host}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mask_url_keeps_the_host_and_drops_the_secret() {
        // A Discord webhook's path is its credential.
        assert_eq!(
            mask_url("https://discord.com/api/webhooks/123456789/AbCdEfGhIjKlMnOpQrSt"),
            "https://discord.com/…"
        );
        // An ntfy topic is its address *and* its secret.
        assert_eq!(mask_url("https://ntfy.sh/my-secret-topic"), "https://ntfy.sh/…");
        // No path to hide.
        assert_eq!(mask_url("https://hooks.example.test"), "https://hooks.example.test");
        // A port is part of the host and stays: it is how you tell two sinks apart.
        assert_eq!(mask_url("http://127.0.0.1:8080/hook"), "http://127.0.0.1:8080/…");
        assert_eq!(mask_url("not a url"), "(malformed URL)");
        assert_eq!(mask_url("https://"), "(malformed URL)");
    }

    #[test]
    fn masked_output_never_contains_the_secret() {
        // The property that matters, stated as a property: whatever came after
        // the host must not survive into the string a page renders.
        let secret = "AbCdEfGhIjKlMnOpQrSt";
        let masked = mask_url(&format!("https://discord.com/api/webhooks/123456789/{secret}"));
        assert!(!masked.contains(secret));
        assert!(!masked.contains("123456789"));
    }

    #[test]
    fn extracts_neutral_notification_from_discord_payload() {
        let payload = json!({
            "username": "klappstuhl",
            "embeds": [{
                "title": "🔴 web is down",
                "description": "the site is unreachable",
                "color": 0xef4444u32,
                "fields": [
                    { "name": "Target", "value": "web", "inline": false },
                    { "name": "Error", "value": "timeout", "inline": false }
                ]
            }]
        });
        let note = AlertNotification::from_discord_value(&payload);
        assert_eq!(note.title, "🔴 web is down");
        assert_eq!(note.level, "error");
        assert_eq!(note.fields.len(), 2);
        assert!(note.body.contains("the site is unreachable"));
        assert!(note.body.contains("Target: web"));
        // Header-safe title strips the emoji.
        assert_eq!(note.ascii_title(), "web is down");
    }

    #[test]
    fn defaults_when_fields_absent() {
        let note = AlertNotification::from_discord_value(&json!({}));
        assert_eq!(note.title, "Alert");
        assert_eq!(note.level, "info");
        assert!(note.fields.is_empty());
    }

    #[test]
    fn strips_discord_markdown_for_ntfy() {
        let input = "**Target:** `web`\n**Kind:** http\n\nCheck the [/admin/health](/admin/health) dashboard.";
        let out = strip_markdown(input);
        assert_eq!(out, "Target: web\nKind: http\n\nCheck the /admin/health dashboard.");
    }

    #[test]
    fn delink_keeps_distinct_targets() {
        assert_eq!(
            delink("see [the docs](https://x.test)"),
            "see the docs (https://x.test)"
        );
        // Identical label/target collapses to a single copy.
        assert_eq!(delink("[/admin/health](/admin/health)"), "/admin/health");
    }

    #[test]
    fn strip_leaves_single_markers_and_other_text() {
        // Lone underscores in identifiers must survive.
        assert_eq!(
            strip_markdown("cpu_percent over threshold"),
            "cpu_percent over threshold"
        );
        // Strikethrough + underline pairs are removed.
        assert_eq!(strip_markdown("~~old~~ __new__"), "old new");
    }

    #[test]
    fn strip_handles_multibyte_text() {
        // Emoji / non-ASCII bytes must not be corrupted by the byte scan.
        assert_eq!(strip_markdown("🔴 **web** is down"), "🔴 web is down");
    }

    fn sample_email_cfg() -> crate::config::EmailConfig {
        crate::config::EmailConfig {
            host: "smtp.example.test".into(),
            port: 587,
            username: Some("u".into()),
            password: Some("p".into()),
            from: "alerts@klappstuhl.me".into(),
            to: vec!["ops@klappstuhl.me".into()],
        }
    }

    #[test]
    fn ehlo_name_uses_from_domain() {
        assert_eq!(ehlo_name(&sample_email_cfg()), "klappstuhl.me");
        let mut cfg = sample_email_cfg();
        cfg.from = "noatsign".into();
        assert_eq!(ehlo_name(&cfg), "localhost");
    }

    #[test]
    fn build_message_has_headers_and_base64_body() {
        let note = AlertNotification::from_discord_value(&json!({
            "embeds": [{
                "title": "🔴 web is down",
                "description": "**unreachable**",
                "color": 0xef4444u32,
            }]
        }));
        let msg = String::from_utf8(build_message(&sample_email_cfg(), &note)).unwrap();

        // Subject is ASCII-folded (emoji + markdown stripped).
        assert!(msg.contains("Subject: web is down\r\n"), "got: {msg}");
        assert!(msg.contains("From: alerts@klappstuhl.me\r\n"));
        assert!(msg.contains("To: ops@klappstuhl.me\r\n"));
        assert!(msg.contains("Content-Transfer-Encoding: base64\r\n"));

        // Body sits after the blank header/body separator and decodes back to
        // the markdown-stripped description.
        let body_b64: String = msg.split("\r\n\r\n").nth(1).unwrap().split_whitespace().collect();
        let decoded = base64::engine::general_purpose::STANDARD.decode(body_b64).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "unreachable");
    }
}
