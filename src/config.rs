//! Vantage configuration, loaded from `config.json`.
//!
//! Written with a fresh signing key on first run; the operator then fills in the
//! exposure mode and (for public mode) the IP allowlist. Path is
//! `$VANTAGE_CONFIG`, else `<config-dir>/vantage/config.json`.
//!
//! The security-critical piece here is [`Exposure`] — the switchable, fail-closed
//! bind policy (ADMIN_SEPARATION_PLAN §7.1). Vantage is deliberately a
//! remote-root web app, so the exposure gate is evaluated **at startup** and
//! refuses to come up in an unsafe posture rather than trusting a runtime check.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context};
use kls_web_core::key::SecretKey;
use serde::{Deserialize, Serialize};

/// Email (SMTP) delivery configuration for the alert sink. The SMTP client in
/// `alerts.rs` uses `tokio-rustls` + webpki roots — port 465 is implicit TLS,
/// everything else upgrades via STARTTLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// SMTP server hostname (e.g. `smtp.fastmail.com`).
    pub host: String,
    /// SMTP port. `465` -> implicit TLS, otherwise STARTTLS. Defaults to 587.
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    /// AUTH LOGIN username. Omit (with `password`) for an unauthenticated relay.
    #[serde(default)]
    pub username: Option<String>,
    /// AUTH LOGIN password / app-password.
    #[serde(default)]
    pub password: Option<String>,
    /// Envelope sender / `From:` address.
    pub from: String,
    /// One or more recipient addresses.
    pub to: Vec<String>,
}

fn default_smtp_port() -> u16 {
    587
}

/// Multi-sink alert delivery configuration. All four sinks are optional and
/// fire in parallel; a missing key disables that sink.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertsConfig {
    /// Discord webhook URL (receives the raw Discord-shaped JSON payload).
    #[serde(default)]
    pub discord_webhook_url: Option<String>,
    /// ntfy topic URL (plain-text push with priority/tags).
    #[serde(default)]
    pub ntfy_url: Option<String>,
    /// Generic webhook URL (receives the neutral `AlertNotification` as JSON).
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// SMTP email sink configuration.
    #[serde(default)]
    pub email: Option<EmailConfig>,
}

/// A pre-defined operator script that can be run on demand from the Ctrl+K
/// palette *and* optionally on a cron schedule. The same struct configures both
/// the ad-hoc runner and the background scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpotlightScript {
    pub id: String,
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// A standard 5-field cron expression (`min hour dom month dow`, evaluated in
    /// UTC). When set, the background scheduler runs this script at the matching
    /// minute(s).
    #[serde(default)]
    pub schedule: Option<String>,
}

/// A Docker service the operator manages from the Docker dashboard (start / stop /
/// restart / pull / recreate, live stats, log stream). Configured in `config.json`
/// under `services`; an empty list simply renders an empty dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Human-readable display name (the card title, and the service key the
    /// dashboard addresses actions/logs by).
    pub name: String,
    /// The Docker container name passed to `docker start` / `docker stop` etc.
    pub identifier: String,
    /// Working directory that contains the `docker-compose.yml`.
    ///
    /// When set (and actually reachable — it exists and holds a compose file),
    /// Start/Stop/Restart/Pull/Recreate drive `docker compose` in this directory
    /// instead of the bare `docker start` / `docker stop` / … commands. When the
    /// directory isn't reachable (e.g. the app runs in a container without the
    /// host compose dir mounted) the handlers fall back to bare-container commands
    /// over the Docker socket.
    #[serde(default)]
    pub path: Option<String>,
}

/// SQLite backup configuration (on-disk retention + off-site mirroring).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Hours between automatic `VACUUM INTO` backups. `0` disables; unset
    /// defaults to 24.
    #[serde(default)]
    pub interval_hours: Option<u64>,
    /// Number of automatic backups to retain. Unset defaults to 14.
    #[serde(default)]
    pub keep: Option<usize>,
    /// Off-site backup target. Unset = local-only backups.
    #[serde(default)]
    pub remote: Option<BackupRemoteConfig>,
}

/// S3-compatible off-site backup target configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRemoteConfig {
    /// Storage backend. Currently only `"s3"` is supported.
    pub kind: String,
    /// Endpoint base URL, e.g. `"https://s3.us-west-002.backblazeb2.com"`,
    /// `"https://<account>.r2.cloudflarestorage.com"`, or for AWS
    /// `"https://s3.us-east-1.amazonaws.com"`.
    pub endpoint: String,
    /// Signing region. AWS needs the real region; B2/R2/MinIO accept any value.
    pub region: String,
    /// Destination bucket name.
    pub bucket: String,
    /// Optional key prefix inside the bucket (e.g. `"vantage/"`). A trailing
    /// slash is added automatically if missing and the prefix is non-empty.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Access key id.
    pub access_key_id: String,
    /// Secret access key.
    pub secret_access_key: String,
}

impl BackupRemoteConfig {
    /// The normalized prefix with a trailing slash when non-empty, or an empty
    /// string when unset.
    pub fn normalized_prefix(&self) -> String {
        match &self.prefix {
            Some(p) if !p.is_empty() => {
                if p.ends_with('/') {
                    p.clone()
                } else {
                    format!("{p}/")
                }
            }
            _ => String::new(),
        }
    }
}

/// Reverse proxy config-generation settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Backend kind: `"nginx"`, `"caddy"`, or `"cloudflared"`. Defaults to nginx.
    #[serde(default)]
    pub kind: Option<String>,
    /// Directory to write generated config files into. Unset = routes tracked in
    /// the DB only (no files written, no reload). Ignored in cloudflared API mode.
    #[serde(default)]
    pub config_dir: Option<std::path::PathBuf>,
    /// Shell command to reload the proxy after regenerating config (e.g.
    /// `"nginx -s reload"`, `"systemctl restart cloudflared"`). Runs via
    /// `kls-agent::exec::shell`.
    #[serde(default)]
    pub reload_command: Option<String>,
}

/// One extra SQLite file exposed in the database console (`sqlite_sources`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliteSource {
    /// Display name, and the `sqlite:<name>` half of the source id. Must not
    /// collide with the built-in `admin` or `requests` sources — a duplicate is
    /// dropped with a warning at catalog build time rather than shadowing them.
    pub name: String,
    /// Path to the `.db` file. Opened fresh per request, read-only unless the
    /// operator turns off safe mode.
    pub path: std::path::PathBuf,
}

/// Cloudflare API credentials (for Tunnel API mode and DNS record upserts).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CloudflareConfig {
    #[serde(default)]
    pub api_token: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub tunnel_id: Option<String>,
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default)]
    pub tunnel_name: Option<String>,
    #[serde(default)]
    pub tunnel_credentials_file: Option<String>,
}

/// Top-level Vantage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The exposure policy: which interface(s) the control plane listens on and
    /// what gates the public listener carries. Evaluated at startup (fail closed).
    #[serde(default)]
    pub exposure: Exposure,
    /// Docker services shown on the Docker dashboard. Empty by default; the
    /// operator lists their containers/compose projects here.
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    /// Forces a specific firewall backend at startup: `"nft"`/`"nftables"`,
    /// `"ufw"`, `"iptables"`, or `"disabled"`. When unset (the default) the
    /// firewall page probes each backend in order and uses the first that
    /// responds. An empty string is treated as unset.
    #[serde(default)]
    pub firewall_backend: Option<String>,
    /// Directories the secret scanner walks periodically (every 6 h) looking
    /// for leaked credentials. Empty = scheduler disabled.
    #[serde(default)]
    pub secret_scan_paths: Vec<std::path::PathBuf>,
    /// Pre-defined operator scripts (Spotlight palette + cron scheduler). Empty by
    /// default; scripts without a `schedule` are only runnable on demand.
    #[serde(default)]
    pub spotlight_scripts: Vec<SpotlightScript>,
    /// Public base URL the admin app is served from (absolute asset/redirect URLs).
    /// No trailing slash. In `vpn` mode this is the tunnel address.
    #[serde(default = "default_base_url")]
    pub base_url: String,
    /// Domains to obtain an ACME certificate for in `public`/`both` mode. Unused in
    /// `vpn` mode (the tunnel already provides transport encryption).
    #[serde(default)]
    pub domains: Vec<String>,
    /// Whether this is a production deployment (enables ACME on port 443).
    #[serde(default)]
    pub production: bool,
    /// Hours between background Docker image update checks (registry digest
    /// comparison). Defaults to 12; set to 0 to disable. Requires Docker.
    #[serde(default)]
    pub update_check_interval_hours: Option<u64>,
    /// How many days of audit entries to keep. Defaults to 90
    /// (`audit::DEFAULT_RETENTION_DAYS`). A hard row cap applies on top, so this
    /// is a promise about how far back you can look rather than an unbounded
    /// grant — see `audit::prune`.
    #[serde(default)]
    pub audit_retention_days: Option<u32>,
    /// Send the Content-Security-Policy as `-Report-Only` instead of enforcing
    /// it. Off by default: the policy is enforced.
    ///
    /// This exists for the first run against a real browser on a real host. A
    /// policy that blocks one forgotten asset can render the control plane
    /// unusable, and this control plane may be the only way in to the box —
    /// discovering that in the console beats discovering it as a blank page.
    #[serde(default)]
    pub csp_report_only: bool,
    /// Multi-sink alert delivery (Discord webhook, ntfy, generic webhook, email).
    /// All sinks are optional; absent = no alerts.
    #[serde(default)]
    pub alerts: AlertsConfig,
    /// SQLite backup settings (on-disk retention + off-site mirroring).
    #[serde(default)]
    pub backup: BackupConfig,
    /// Reverse proxy config generation (nginx/caddy/cloudflared).
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// Cloudflare API credentials (Tunnel API mode + DNS upserts).
    #[serde(default)]
    pub cloudflare: CloudflareConfig,
    /// Path to the sshd auth log for monitoring public-key authentications.
    /// When set, the SSH log watcher tails this file and updates last_used_at
    /// for keys matching successful auth events. Typically `/var/log/auth.log`
    /// on Debian/Ubuntu or the path to a journald log export. Unset = disabled.
    #[serde(default)]
    pub sshd_auth_log_path: Option<String>,
    /// Path to the GeoIP database (GeoLite2-City.mmdb). When set, the security
    /// dashboard populates country/city fields for IP-based analytics.
    #[serde(default)]
    pub geoip_path: Option<std::path::PathBuf>,
    /// Path to the site's `requests.db` (the HTTP access log database). The
    /// admin opens it read-only for the security analytics page.
    #[serde(default)]
    pub requests_db_path: Option<std::path::PathBuf>,
    /// Directory holding the site's rolling log files (`today.log` and
    /// `bad_requests.log`). When set, the log viewer can switch between
    /// Vantage's own log and the site's; unset, it shows only Vantage's.
    ///
    /// Vantage runs as its own process and writes its own log, so it cannot
    /// reach the site's without being told where they are — the same reason
    /// `requests_db_path` exists.
    #[serde(default)]
    pub site_logs_path: Option<std::path::PathBuf>,
    /// Extra SQLite files to expose in the database console, beyond Vantage's
    /// own `admin.db` and the `requests_db_path` one. Each entry is a display
    /// name and a path.
    ///
    /// This list *is* the console's allowlist: a source id names an entry here,
    /// and `dbadmin::sqlite` resolves the name against this catalog rather than
    /// joining anything the request supplied onto a directory. Adding a database
    /// is therefore a config edit, the same as adding an alert sink or a
    /// spotlight script — there is deliberately no route that does it, because a
    /// console that accepts a path is a read primitive for every file the
    /// process can open.
    #[serde(default)]
    pub sqlite_sources: Vec<SqliteSource>,
    /// Connection URL for an external PostgreSQL instance
    /// (`postgres://user:pw@host:5432/dbname`), browsable from the database
    /// console. Unset = the console shows only the SQLite sources.
    ///
    /// The console can reach every database on that instance, and in danger mode
    /// it can write to them, so the role in this URL is the real limit on what
    /// an admin can do here. Give it the narrowest rights that make the console
    /// useful to you.
    #[serde(default)]
    pub postgres_url: Option<String>,
    /// ClamAV daemon address for the file sanitizer (e.g. `"127.0.0.1:3310"`).
    /// Unset = ClamAV scan disabled.
    #[serde(default)]
    pub clamav_addr: Option<String>,
    /// VirusTotal API key for the file sanitizer. Unset = VT lookup disabled.
    #[serde(default)]
    pub virustotal_api_key: Option<String>,
    /// HMAC key for signed cookies (sessions, flash). Generated on first run.
    pub secret_key: SecretKey,
}

/// Which exposure mode the control plane runs in (ADMIN_SEPARATION_PLAN §7.1,
/// locked decision 1). All modes share the same auth stack; `public` only *adds*
/// gates on top of `vpn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExposureMode {
    /// VPN-only (default): binds a non-public interface, refuses a public bind.
    #[default]
    Vpn,
    /// Hardened public subdomain: second factor + IP allowlist + aggressive lockout.
    Public,
    /// Both listeners at once — break-glass for when the VPN is down.
    Both,
}

impl ExposureMode {
    /// The lowercase wire name (matches the serde representation).
    pub fn as_str(&self) -> &'static str {
        match self {
            ExposureMode::Vpn => "vpn",
            ExposureMode::Public => "public",
            ExposureMode::Both => "both",
        }
    }
}

/// The exposure policy. `bind` is the primary listener; `public_bind` is the
/// second listener used only in `both` mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exposure {
    #[serde(default)]
    pub mode: ExposureMode,
    /// The primary listener address. In `vpn` mode this must resolve to a
    /// non-public interface (loopback / RFC1918 / CGNAT / ULA / link-local).
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    /// The public listener for `both` mode (the hardened, allowlisted one).
    #[serde(default)]
    pub public_bind: Option<SocketAddr>,
    /// CIDR allowlist for the public listener. **Empty = deny-all** until
    /// configured (fail closed). Ignored by the VPN listener.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Require a client certificate (mTLS) on the public listener. Off by default
    /// (locked decision 6): the strongest posture stays one flag away.
    #[serde(default)]
    pub require_client_cert: bool,
    /// Optional ISO country-code allowlist for the public listener (GeoIP).
    #[serde(default)]
    pub country_allowlist: Option<Vec<String>>,
}

impl Default for Exposure {
    fn default() -> Self {
        Self {
            mode: ExposureMode::default(),
            bind: default_bind(),
            public_bind: None,
            allowlist: Vec::new(),
            require_client_cert: false,
            country_allowlist: None,
        }
    }
}

/// The guard profile a bound listener carries — which §7.1 gates apply to
/// requests arriving on it. A `both`-mode deployment binds one of each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardProfile {
    /// The trusted listener (VPN interface / loopback). Auth still required; no
    /// IP allowlist / mTLS / country gate.
    Vpn,
    /// The hardened public listener: allowlist + optional mTLS + country gate +
    /// aggressive lockout, on top of mandatory second-factor auth.
    Public,
}

/// A resolved listener: an address to bind and the guard profile to enforce on it.
#[derive(Debug, Clone, Copy)]
pub struct Listener {
    pub addr: SocketAddr,
    pub profile: GuardProfile,
}

fn default_bind() -> SocketAddr {
    // Loopback by default: safe for SSH-tunnel use and never a public interface.
    SocketAddr::from(([127, 0, 0, 1], 8092))
}

fn default_base_url() -> String {
    "http://127.0.0.1:8092".to_string()
}

impl Exposure {
    /// Validates the exposure policy at startup and returns the concrete set of
    /// listeners to bind. **Fail closed:** any unsafe posture is an error, not a
    /// warning — Vantage refuses to start rather than come up exposed.
    pub fn listeners(&self) -> anyhow::Result<Vec<Listener>> {
        // Every configured CIDR must parse, in every mode — a typo in the
        // allowlist must never silently widen (or, for public, silently deny) it.
        for entry in &self.allowlist {
            IpCidr::parse(entry).with_context(|| format!("invalid CIDR in exposure.allowlist: {entry:?}"))?;
        }

        match self.mode {
            ExposureMode::Vpn => {
                ensure_non_public(self.bind, "exposure.bind", "vpn")?;
                Ok(vec![Listener {
                    addr: self.bind,
                    profile: GuardProfile::Vpn,
                }])
            }
            ExposureMode::Public => {
                // The public listener may legitimately bind a public interface —
                // that is the point — but its gates must be armed.
                self.check_public_gates("exposure.bind")?;
                Ok(vec![Listener {
                    addr: self.bind,
                    profile: GuardProfile::Public,
                }])
            }
            ExposureMode::Both => {
                let public_bind = self
                    .public_bind
                    .context("exposure.mode is \"both\" but exposure.public_bind is unset")?;
                ensure_non_public(self.bind, "exposure.bind", "both")?;
                self.check_public_gates("exposure.public_bind")?;
                Ok(vec![
                    Listener {
                        addr: self.bind,
                        profile: GuardProfile::Vpn,
                    },
                    Listener {
                        addr: public_bind,
                        profile: GuardProfile::Public,
                    },
                ])
            }
        }
    }

    /// The parsed CIDR allowlist. Callers should have validated via [`Self::listeners`]
    /// first; a malformed entry here is skipped (fail-closed: it never widens the set).
    pub fn parsed_allowlist(&self) -> Vec<IpCidr> {
        self.allowlist.iter().filter_map(|e| IpCidr::parse(e).ok()).collect()
    }

    /// Public-listener sanity: an empty allowlist is deny-all (fail closed) — we
    /// allow it (a locked-down box is safe) but surface it loudly so it is never
    /// an accident. Real enforcement is the per-listener middleware (later phase).
    fn check_public_gates(&self, field: &str) -> anyhow::Result<()> {
        if self.allowlist.is_empty() {
            tracing::warn!(
                "{field}: public exposure with an EMPTY allowlist — every request will be denied until \
                 exposure.allowlist is populated (fail-closed default)"
            );
        }
        Ok(())
    }
}

/// Refuses `addr` if it resolves to a globally-routable (public) interface.
/// Loopback, RFC1918, CGNAT (100.64/10 — where Tailscale allocates), IPv6 ULA and
/// link-local are all accepted as VPN/trusted interfaces.
fn ensure_non_public(addr: SocketAddr, field: &str, mode: &str) -> anyhow::Result<()> {
    if is_globally_routable(addr.ip()) {
        bail!(
            "{field} = {addr} resolves to a public interface, refused in \"{mode}\" mode. \
             Bind the VPN/loopback interface, or switch exposure.mode to \"public\"/\"both\"."
        );
    }
    Ok(())
}

/// Whether an IP is globally routable (i.e. a public address). Conservative by
/// design: anything not clearly private/reserved is treated as public, so a
/// misclassification errs toward *refusing* a bind rather than allowing an
/// exposed one.
fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
    {
        return false;
    }
    // Carrier-grade NAT 100.64.0.0/10 — the range Tailscale hands addresses out of
    // (decision O8), and never publicly routable.
    let o = ip.octets();
    if o[0] == 100 && (o[1] & 0xC0) == 0x40 {
        return false;
    }
    true
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    let seg0 = ip.segments()[0];
    // Link-local fe80::/10 and unique-local fc00::/7 are non-public. (The stable
    // std helpers for these are still unstable, so mask the prefix by hand.)
    // Everything else is treated as global-unicast (public).
    (seg0 & 0xffc0) != 0xfe80 && (seg0 & 0xfe00) != 0xfc00
}

/// A parsed CIDR block (`ip` or `ip/prefix`) supporting membership tests — the
/// fail-closed allowlist primitive the public-mode middleware consumes (§7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    base: IpAddr,
    prefix: u8,
}

impl IpCidr {
    /// Parses `"10.0.0.0/8"`, `"1.2.3.4"` (host → /32 or /128), or an IPv6 form.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let base: IpAddr = addr_part
            .trim()
            .parse()
            .with_context(|| format!("not an IP address: {addr_part:?}"))?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            Some(p) => {
                let n: u8 = p.trim().parse().with_context(|| format!("bad prefix length: {p:?}"))?;
                if n > max {
                    bail!("prefix /{n} exceeds /{max} for {base}");
                }
                n
            }
            None => max,
        };
        Ok(Self { base, prefix })
    }

    /// Whether `ip` falls inside this block. A v4 CIDR never matches a v6 address
    /// and vice versa. Consumed by the public-listener allowlist guard (`guard.rs`).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(base), IpAddr::V4(ip)) => bits_match(&base.octets(), &ip.octets(), self.prefix),
            (IpAddr::V6(base), IpAddr::V6(ip)) => bits_match(&base.octets(), &ip.octets(), self.prefix),
            _ => false,
        }
    }
}

/// Compares the first `prefix` bits of two big-endian byte strings.
fn bits_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// Copies into `raw` (what is on disk) every object key present in `full` (the
/// config re-serialised after loading) and absent from `raw`, recursing into nested
/// objects and through arrays position-wise. Returns whether anything was added.
///
/// This fills gaps rather than replacing the file wholesale so that a value already
/// on disk is never restyled and an unrecognised key — the operator's, not ours to
/// prune — survives the rewrite.
fn json_fill_missing(full: &serde_json::Value, raw: &mut serde_json::Value) -> bool {
    match (full, raw) {
        (serde_json::Value::Object(full), serde_json::Value::Object(raw)) => {
            let mut added = false;
            for (key, value) in full {
                match raw.get_mut(key) {
                    Some(existing) => added |= json_fill_missing(value, existing),
                    None => {
                        raw.insert(key.clone(), value.clone());
                        added = true;
                    }
                }
            }
            added
        }
        (serde_json::Value::Array(full), serde_json::Value::Array(raw)) if full.len() == raw.len() => full
            .iter()
            .zip(raw)
            .fold(false, |added, (f, r)| added | json_fill_missing(f, r)),
        _ => false,
    }
}

impl Config {
    /// Loads the config, creating a default (with a fresh signing key) on first
    /// run. `VANTAGE_PORT` overrides the primary bind port after loading.
    pub fn load() -> anyhow::Result<Self> {
        let path = config_path()?;
        let mut config = if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("could not read config file at {}", path.display()))?;
            let mut raw: serde_json::Value = serde_json::from_str(&raw)
                .with_context(|| format!("could not parse config file at {}", path.display()))?;
            let config: Self = serde_json::from_value(raw.clone())
                .with_context(|| format!("could not parse config file at {}", path.display()))?;

            // A field added since the file was written is filled in by its serde
            // default and then silently absent from disk, so the operator never sees
            // that it exists. Write those keys back whenever that happened; anything
            // already in the file is left exactly as it was.
            let full = serde_json::to_value(&config).context("could not serialise the config")?;
            if json_fill_missing(&full, &mut raw) {
                write_json_to(&raw, &path)?;
                tracing::info!(
                    "config at {} was missing fields — wrote them back with defaults",
                    path.display()
                );
            }
            config
        } else {
            let config = Self::default_with_generated_key()?;
            config.write_to(&path)?;
            tracing::warn!(
                "no config found — wrote a default (vpn/loopback exposure, generated signing key) to {}",
                path.display()
            );
            config
        };

        if let Ok(port) = std::env::var("VANTAGE_PORT") {
            if let Ok(port) = port.parse::<u16>() {
                config.exposure.bind.set_port(port);
            }
        }
        Ok(config)
    }

    /// Whether the session cookie is set `Secure` (and `__Host-`-prefixed): true
    /// in production or whenever a public listener is present. In the plain-HTTP
    /// vpn/loopback dev posture it is false so the browser will actually send it.
    pub fn secure_cookies(&self) -> bool {
        self.production || matches!(self.exposure.mode, ExposureMode::Public | ExposureMode::Both)
    }

    /// The session cookie name. `__Host-`-prefixed when `Secure` (§7.3: never
    /// domain-scoped, path `/`); a plain host-only name for plain-HTTP dev, where
    /// a `Secure` `__Host-` cookie would never be sent.
    pub fn session_cookie_name(&self) -> &'static str {
        if self.secure_cookies() {
            "__Host-vantage"
        } else {
            "vantage_session"
        }
    }

    /// The short-lived cookie name carrying a signed pending-2FA challenge between
    /// the password step and the TOTP step. Same `__Host-`/dev split as the session.
    pub fn twofa_cookie_name(&self) -> &'static str {
        if self.secure_cookies() {
            "__Host-vantage_2fa"
        } else {
            "vantage_2fa"
        }
    }

    fn default_with_generated_key() -> anyhow::Result<Self> {
        Ok(Self {
            exposure: Exposure::default(),
            services: Vec::new(),
            firewall_backend: None,
            secret_scan_paths: Vec::new(),
            spotlight_scripts: Vec::new(),
            base_url: default_base_url(),
            domains: Vec::new(),
            production: false,
            update_check_interval_hours: None,
            audit_retention_days: None,
            csp_report_only: false,
            alerts: AlertsConfig::default(),
            backup: BackupConfig::default(),
            proxy: ProxyConfig::default(),
            cloudflare: CloudflareConfig::default(),
            sshd_auth_log_path: None,
            geoip_path: None,
            requests_db_path: None,
            sqlite_sources: Vec::new(),
            postgres_url: None,
            site_logs_path: None,
            clamav_addr: None,
            virustotal_api_key: None,
            secret_key: SecretKey::random().context("could not generate a signing key")?,
        })
    }

    fn write_to(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_value(self).context("could not serialise the default config")?;
        write_json_to(&json, path)
    }
}

fn write_json_to(json: &serde_json::Value, path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create config directory {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(json).context("could not serialise the config")?;
    std::fs::write(path, json).with_context(|| format!("could not write config to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
impl Config {
    /// A minimal in-memory config for tests (random key, default vpn exposure).
    pub fn test_default() -> Self {
        Self {
            exposure: Exposure::default(),
            services: Vec::new(),
            firewall_backend: None,
            secret_scan_paths: Vec::new(),
            spotlight_scripts: Vec::new(),
            base_url: "http://localhost".to_string(),
            domains: Vec::new(),
            production: false,
            update_check_interval_hours: None,
            audit_retention_days: None,
            csp_report_only: false,
            alerts: AlertsConfig::default(),
            backup: BackupConfig::default(),
            proxy: ProxyConfig::default(),
            cloudflare: CloudflareConfig::default(),
            sshd_auth_log_path: None,
            geoip_path: None,
            requests_db_path: None,
            sqlite_sources: Vec::new(),
            postgres_url: None,
            site_logs_path: None,
            clamav_addr: None,
            virustotal_api_key: None,
            secret_key: SecretKey::random().expect("generate test key"),
        }
    }
}

/// Resolves the config file path: `$VANTAGE_CONFIG`, else
/// `<config-dir>/vantage/config.json`.
fn config_path() -> anyhow::Result<PathBuf> {
    if let Ok(explicit) = std::env::var("VANTAGE_CONFIG") {
        return Ok(PathBuf::from(explicit));
    }
    let mut path = dirs::config_dir().context("could not find a config directory for the current user")?;
    path.push("vantage");
    path.push("config.json");
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fill(full: serde_json::Value, mut raw: serde_json::Value) -> (bool, serde_json::Value) {
        let added = json_fill_missing(&full, &mut raw);
        (added, raw)
    }

    #[test]
    fn a_missing_field_is_written_back_with_its_default() {
        use serde_json::json;

        // Top level, nested, and inside an array element.
        assert_eq!(
            fill(json!({"sqlite_sources": []}), json!({})),
            (true, json!({"sqlite_sources": []}))
        );
        assert_eq!(
            fill(json!({"alerts": {"ntfy_url": null}}), json!({"alerts": {}})),
            (true, json!({"alerts": {"ntfy_url": null}}))
        );
        assert_eq!(
            fill(
                json!({"s": [{"name": "a", "path": "b"}]}),
                json!({"s": [{"name": "a"}]})
            ),
            (true, json!({"s": [{"name": "a", "path": "b"}]}))
        );
    }

    #[test]
    fn an_existing_config_is_left_alone() {
        use serde_json::json;

        // Nothing missing — an untouched file must not be rewritten.
        assert_eq!(
            fill(json!({"port": 8092}), json!({"port": 8092})),
            (false, json!({"port": 8092}))
        );
        // A value that differs from the default is a value, not a gap: keep it.
        assert_eq!(
            fill(json!({"port": 8092}), json!({"port": 9000})),
            (false, json!({"port": 9000}))
        );
        // An unrecognised key on disk is the operator's — never pruned.
        let operator = json!({"port": 8092, "mystery": true});
        assert_eq!(fill(json!({"port": 8092}), operator.clone()), (false, operator));
    }

    #[test]
    fn config_round_trips_without_wanting_a_rewrite() {
        // The invariant that matters: a config we just wrote must load clean.
        let full = serde_json::to_value(Config::test_default()).unwrap();
        assert_eq!(fill(full.clone(), full.clone()), (false, full.clone()));

        // ...and stripping a field must be detected and restored.
        let mut stripped = full.clone();
        stripped.as_object_mut().unwrap().remove("sqlite_sources").unwrap();
        assert_eq!(fill(full.clone(), stripped), (true, full));
    }

    fn exposure(mode: ExposureMode, bind: &str) -> Exposure {
        Exposure {
            mode,
            bind: bind.parse().unwrap(),
            ..Exposure::default()
        }
    }

    #[test]
    fn vpn_mode_accepts_loopback_and_private_and_cgnat() {
        for addr in ["127.0.0.1:8092", "10.0.0.5:8092", "192.168.1.2:8092", "100.64.0.1:8092"] {
            let listeners = exposure(ExposureMode::Vpn, addr).listeners().expect(addr);
            assert_eq!(listeners.len(), 1);
            assert_eq!(listeners[0].profile, GuardProfile::Vpn);
        }
    }

    #[test]
    fn vpn_mode_refuses_a_public_bind() {
        // A globally-routable address in vpn mode is fail-closed refused.
        let err = exposure(ExposureMode::Vpn, "8.8.8.8:8092").listeners().unwrap_err();
        assert!(err.to_string().contains("public interface"), "{err}");
    }

    #[test]
    fn public_mode_allows_a_public_bind() {
        let listeners = exposure(ExposureMode::Public, "8.8.8.8:443").listeners().unwrap();
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].profile, GuardProfile::Public);
    }

    #[test]
    fn both_mode_requires_public_bind_and_binds_two_listeners() {
        let mut e = exposure(ExposureMode::Both, "127.0.0.1:8092");
        assert!(e.listeners().is_err(), "both mode without public_bind must fail");
        e.public_bind = Some("0.0.0.0:443".parse().unwrap());
        let listeners = e.listeners().unwrap();
        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0].profile, GuardProfile::Vpn);
        assert_eq!(listeners[1].profile, GuardProfile::Public);
    }

    #[test]
    fn both_mode_refuses_public_address_on_the_vpn_listener() {
        let mut e = exposure(ExposureMode::Both, "8.8.8.8:8092");
        e.public_bind = Some("0.0.0.0:443".parse().unwrap());
        assert!(e.listeners().unwrap_err().to_string().contains("public interface"));
    }

    #[test]
    fn a_malformed_allowlist_entry_is_rejected() {
        let mut e = exposure(ExposureMode::Public, "8.8.8.8:443");
        e.allowlist = vec!["10.0.0.0/8".into(), "not-a-cidr".into()];
        assert!(e.listeners().unwrap_err().to_string().contains("allowlist"));
    }

    #[test]
    fn ipv6_ula_and_link_local_are_non_public() {
        // Unique-local fd00::/8 and link-local fe80::/10 are accepted in vpn mode.
        for addr in ["[fd00::1]:8092", "[fe80::1]:8092", "[::1]:8092"] {
            assert!(exposure(ExposureMode::Vpn, addr).listeners().is_ok(), "{addr}");
        }
        // A global-unicast v6 address is refused in vpn mode.
        assert!(exposure(ExposureMode::Vpn, "[2606:4700::1]:8092").listeners().is_err());
    }

    #[test]
    fn cidr_membership() {
        let block = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(block.contains("10.9.9.9".parse().unwrap()));
        assert!(!block.contains("11.0.0.1".parse().unwrap()));
        // A bare host parses to /32 and matches only itself.
        let host = IpCidr::parse("1.2.3.4").unwrap();
        assert!(host.contains("1.2.3.4".parse().unwrap()));
        assert!(!host.contains("1.2.3.5".parse().unwrap()));
        // Cross-family never matches.
        assert!(!block.contains("::1".parse().unwrap()));
        // /0 matches everything of its family.
        assert!(IpCidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn cidr_rejects_oversized_prefix() {
        assert!(IpCidr::parse("10.0.0.0/33").is_err());
        assert!(IpCidr::parse("::/129").is_err());
    }
}
