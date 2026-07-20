# Vantage

A security-first VPS/homelab control plane. Manage your server through a terminal-aesthetic web UI, backed by a CLI.

Vantage gives you a single pane of glass over Docker containers, firewall rules, uptime probes, host metrics, SSL certificates, secrets scanning, SSH keys, scheduled scripts, reverse proxy config, and database backups — all behind a hardened auth stack with fail-closed network exposure.

## Features

- **Docker management** — container/network/volume dependency graph, live events, start/stop/restart/pull/recreate, per-service stats and log streaming
- **Firewall** — nftables/ufw/iptables rule mirror with auto-lockout on brute-force
- **Uptime monitoring** — HTTP, TCP, keyword, and SSL probes with incident tracking and alerting
- **Host metrics** — CPU, memory, disk, network from `/proc`+`/sys`; Docker container stats; live WebSocket tiles
- **SSL certificate monitoring** — expiry tracking across all your domains
- **Secrets scanning** — periodic filesystem scan for leaked credentials (via [secretshape](https://crates.io/crates/secretshape))
- **File sanitizer** — ClamAV + VirusTotal integration for uploaded/suspicious files
- **Reverse proxy** — config generation for nginx, Caddy, and Cloudflare Tunnels; DNS upserts via Cloudflare API
- **SSH key management** — authorized_keys CRUD, temporary access tokens, audit log
- **Database console** — browse and query SQLite databases + external PostgreSQL with a two-layer safety guard (prefilter + engine-enforced read-only); schema browser, table paging, CSV export
- **Backups** — automatic SQLite `VACUUM INTO` with retention + S3-compatible off-site mirroring
- **Scheduled scripts** — cron-driven operator scripts runnable from the Ctrl+K spotlight palette
- **Docker image updates** — periodic registry digest comparison with dashboard notifications
- **Multi-sink alerting** — Discord webhook, ntfy, generic webhook, SMTP email (all optional, fire in parallel)
- **Security analytics** — request stats, GeoIP lookups, Cloudflare panels, login attempt tracking
- **Audit log** — every privileged action recorded (who, when, from where, what), time-based retention, refused attempts included
- **Safe mode** — global kill switch that freezes all destructive host mutations (middleware-enforced)
- **Revert-timer apply** — firewall/proxy changes auto-roll-back unless confirmed within a timeout window; dry-run diff preview before apply
- **Security headers** — strict CSP (`'self'` only, no inline/eval), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy on every response
- **Live updates** — WebSocket hub with subscribe/unsubscribe protocol for real-time dashboard tiles

## Security Model

Vantage is deliberately a remote-root web app and takes an aggressive defensive posture:

| Layer       | Mechanism                                                                                                                                                 |
|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| Network     | Fail-closed exposure policy evaluated at startup (`vpn`/`public`/`both`); refuses to bind a public interface in VPN mode; empty CIDR allowlist = deny all |
| Auth        | Argon2 passwords, HMAC-signed `__Host-` cookies (SameSite=Strict, HttpOnly, 12h), TOTP 2FA (ChaCha20-Poly1305 at rest)                                    |
| Brute-force | Per-IP login lockout (5 failures / 15 min, bounded LRU); constant-time verification even for unknown usernames                                            |
| Privilege   | All host mutations route through a typed boundary (`kls-agent`) — not raw shell; reads go through bollard/procfs                                          |
| Sudo        | Destructive actions require re-authentication within 10 min (`Sudo` extractor); transparent reauth modal + retry in the browser                           |
| Headers     | Strict CSP (`default-src 'self'`; no inline/eval/wildcard), X-Frame-Options DENY, nosniff, no-referrer — on every response including static assets        |
| Database    | WAL-mode SQLite; DB console enforces `PRAGMA query_only` / Postgres `READ ONLY`; safe-mode prefilter rejects writes                                       |

An authenticated session can manage containers, firewall rules, SSH keys, and cron
scripts — it is root on the host by design. Run it in the default `vpn` mode behind a
private network or VPN; only use `public` mode with a tight CIDR allowlist and TOTP on
every account. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Requirements

- Docker with the Compose v2 plugin — the supported deployment. Images are published for amd64 and arm64
- Linux recommended for full functionality (Docker socket, `/proc`/`/sys`, firewall binaries)
- Optional: GeoLite2-City.mmdb for GeoIP lookups
- Optional: ClamAV daemon for file scanning
- Optional: VirusTotal API key

## Quick Start

Vantage is published at `ghcr.io/klappstuhlpy/vantage` — no clone, no build.

```bash
# Grab the compose file
curl -O https://raw.githubusercontent.com/klappstuhlpy/vantage/master/docker-compose.yml

# First run — generates a default config.json, then stop again
docker compose up -d && docker compose down

# Edit the generated config (exposure mode, services, alert sinks, integrations)
vim ./data/config/vantage/config.json

# Bootstrap the first admin account (interactive)
docker compose run --rm vantage ./vantage admin

# Start permanently
docker compose up -d
```

On first run, a `config.json` is generated with a fresh signing key.

To build from source instead, see [Development](#development).

## Configuration

Vantage loads its configuration from `config.json`. The path is determined by:
1. `$VANTAGE_CONFIG` environment variable (if set)
2. Platform config directory (`~/.config/vantage/config.json` on Linux)

### Minimal config (VPN mode)

```json
{
  "exposure": {
    "mode": "vpn",
    "bind": "127.0.0.1:8443"
  },
  "secret_key": "<auto-generated on first run>",
  "services": []
}
```

<details>
<summary><strong>Full <code>config.json</code> reference (every field, described, with examples)</strong></summary>

Every field is optional unless marked **required**. Omitted fields fall back to the
default shown. `secret_key` is generated for you on first run — never set it by hand.
All paths may be absolute or relative to the process working directory.

#### Top-level fields

| Field                         | Type             | Default                                       | Description                                                                                                                                                         |
|-------------------------------|------------------|-----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `exposure`                    | object           | `{ "mode": "vpn", "bind": "127.0.0.1:8092" }` | Network exposure policy — which interface(s) the control plane binds and what gates guard them. Evaluated at startup, fail-closed. See [Exposure](#exposure) below. |
| `services`                    | array            | `[]`                                          | Docker services shown on the Docker dashboard. See [Services](#services).                                                                                           |
| `firewall_backend`            | string \| null   | `null` (auto-probe)                           | Force a firewall backend: `"nft"`/`"nftables"`, `"ufw"`, `"iptables"`, or `"disabled"`. Unset/empty = probe each in order and use the first that responds.          |
| `secret_scan_paths`           | array of paths   | `[]`                                          | Directories the secret scanner walks every 6 h for leaked credentials. Empty = scheduler disabled.                                                                  |
| `spotlight_scripts`           | array            | `[]`                                          | Pre-defined operator scripts (Ctrl+K palette + optional cron). See [Spotlight scripts](#spotlight-scripts).                                                         |
| `base_url`                    | string           | `"http://127.0.0.1:8092"`                     | Public base URL the admin app is served from (absolute assets/redirects). No trailing slash. In `vpn` mode this is the tunnel address.                              |
| `domains`                     | array of strings | `[]`                                          | Domains to obtain an ACME certificate for in `public`/`both` mode. Unused in `vpn` mode.                                                                            |
| `production`                  | bool             | `false`                                       | Production deployment: enables ACME on port 443 and forces `Secure`/`__Host-` cookies.                                                                              |
| `update_check_interval_hours` | number \| null   | `12`                                          | Hours between background Docker image update checks (registry digest compare). `0` disables. Requires Docker.                                                       |
| `audit_retention_days`        | number \| null   | `90`                                          | Days of audit-log entries to keep (a hard row cap also applies).                                                                                                    |
| `csp_report_only`            | bool             | `false`                                       | Send `Content-Security-Policy-Report-Only` instead of enforcing. Use for first-rollout discovery — a wrong policy can lock you out of the only way into the box.    |
| `sqlite_sources`             | array            | `[]`                                          | Extra SQLite files to expose in the database console (beyond `admin.db` and `requests_db_path`). See [SQLite sources](#sqlite-sources).                             |
| `postgres_url`               | string \| null   | `null`                                        | PostgreSQL connection URL (`postgres://user:pw@host:5432/db`) for the database console. The role's privileges are the real limit — use the narrowest that's useful. |
| `alerts`                      | object           | `{}`                                          | Multi-sink alert delivery. All sinks optional; absent = no alerts. See [Alerts](#alerts).                                                                           |
| `backup`                      | object           | `{}`                                          | SQLite backup settings (retention + off-site mirror). See [Backup](#backup).                                                                                        |
| `proxy`                       | object           | `{}`                                          | Reverse-proxy config generation. See [Proxy](#proxy).                                                                                                               |
| `cloudflare`                  | object           | `{}`                                          | Cloudflare API credentials (Tunnel API mode + DNS upserts). See [Cloudflare](#cloudflare).                                                                          |
| `sshd_auth_log_path`          | string \| null   | `null`                                        | Path to the sshd auth log (e.g. `/var/log/auth.log`). When set, the SSH log watcher updates `last_used_at` for keys on successful auth.                             |
| `geoip_path`                  | path \| null     | `null`                                        | Path to `GeoLite2-City.mmdb`. Enables country/city fields on the security dashboard.                                                                                |
| `requests_db_path`            | path \| null     | `null`                                        | Path to the site's `requests.db` (HTTP access log). Opened read-only for security analytics.                                                                        |
| `site_logs_path`              | path \| null     | `null`                                        | Directory holding the site's rolling logs (`today.log`, `bad_requests.log`). Lets the log viewer switch between Vantage's log and the site's.                       |
| `clamav_addr`                 | string \| null   | `null`                                        | ClamAV daemon address for the file sanitizer, e.g. `"127.0.0.1:3310"`. Unset = ClamAV scan disabled.                                                                |
| `virustotal_api_key`          | string \| null   | `null`                                        | VirusTotal API key for the file sanitizer. Unset = VT lookup disabled.                                                                                              |
| `secret_key`                  | string           | generated                                     | HMAC key for signed cookies. **Written for you on first run — do not edit.**                                                                                        |

#### Exposure

The security-critical block. `mode` selects the posture; the other fields arm the gates.

| Field                 | Type                              | Default            | Description                                                                                                                                                                                   |
|-----------------------|-----------------------------------|--------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `mode`                | `"vpn"` \| `"public"` \| `"both"` | `"vpn"`            | `vpn`: bind a non-public interface only (refuses a public bind). `public`: hardened public listener with an IP allowlist. `both`: a VPN listener **and** a hardened public one (break-glass). |
| `bind`                | socket addr                       | `"127.0.0.1:8092"` | Primary listener. In `vpn`/`both` mode must resolve to a non-public interface (loopback / RFC1918 / CGNAT 100.64/10 / IPv6 ULA / link-local).                                                 |
| `public_bind`         | socket addr \| null               | `null`             | The public listener for `both` mode (**required** when `mode` is `"both"`).                                                                                                                   |
| `allowlist`           | array of CIDRs                    | `[]`               | CIDR allowlist for the public listener. **Empty = deny-all** (fail closed). Accepts `"1.2.3.4"` (host), `"10.0.0.0/8"`, or IPv6. Ignored by the VPN listener.                                 |
| `require_client_cert` | bool                              | `false`            | Require a client certificate (mTLS) on the public listener.                                                                                                                                   |
| `country_allowlist`   | array of strings \| null          | `null`             | Optional ISO country-code allowlist for the public listener (needs `geoip_path`), e.g. `["DE", "AT"]`.                                                                                        |

```json
"exposure": {
  "mode": "both",
  "bind": "100.64.0.1:8092",
  "public_bind": "0.0.0.0:443",
  "allowlist": ["203.0.113.0/24", "198.51.100.7"],
  "require_client_cert": true,
  "country_allowlist": ["DE"]
}
```

#### Services

Each entry is one Docker service on the Docker dashboard.

| Field        | Type           | Required  | Description                                                                                                                                                                          |
|--------------|----------------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `name`       | string         | yes       | Display name / the key the dashboard addresses actions and logs by.                                                                                                                  |
| `identifier` | string         | yes       | The Docker container name passed to `docker start`/`stop`/etc.                                                                                                                       |
| `path`       | string \| null | no        | Directory holding the `docker-compose.yml`. When set and reachable, actions drive `docker compose` here; otherwise they fall back to bare-container commands over the Docker socket. |

```json
"services": [
  { "name": "Web", "identifier": "web", "path": "/opt/stacks/web" },
  { "name": "Redis", "identifier": "redis" }
]
```

#### Spotlight scripts

Operator scripts runnable from the Ctrl+K palette and, when `schedule` is set, on cron.

| Field         | Type           | Required  | Description                                                                                                |
|---------------|----------------|-----------|------------------------------------------------------------------------------------------------------------|
| `id`          | string         | yes       | Stable identifier (used by the run endpoint and the per-id run lock).                                      |
| `name`        | string         | yes       | Display name in the palette.                                                                               |
| `command`     | string         | yes       | The shell command to run (bounded by a timeout, output tail-truncated).                                    |
| `description` | string \| null | no        | Short description shown in the palette.                                                                    |
| `cwd`         | string \| null | no        | Working directory to run the command in.                                                                   |
| `schedule`    | string \| null | no        | 5-field cron expression (`min hour dom month dow`, UTC). When set, runs automatically at matching minutes. |

```json
"spotlight_scripts": [
  {
    "id": "nightly-prune",
    "name": "Prune Docker",
    "command": "docker system prune -af",
    "description": "Reclaim disk from unused images",
    "cwd": "/root",
    "schedule": "0 4 * * *"
  }
]
```

#### Alerts

All four sinks are optional and fire in parallel; a missing key disables that sink. Sink
**addresses live only here** (the URL is the credential) — there is no route to edit them.

| Field                 | Type           | Description                                                      |
|-----------------------|----------------|------------------------------------------------------------------|
| `discord_webhook_url` | string \| null | Discord webhook (receives the raw Discord-shaped JSON).          |
| `ntfy_url`            | string \| null | ntfy topic URL (plain-text push with priority/tags).             |
| `webhook_url`         | string \| null | Generic webhook (receives the neutral `AlertNotification` JSON). |
| `email`               | object \| null | SMTP email sink (see below).                                     |

**`alerts.email`** — SMTP delivery. Port `465` uses implicit TLS; anything else upgrades via STARTTLS.

| Field      | Type             | Required  | Default  | Description                                                              |
|------------|------------------|-----------|----------|--------------------------------------------------------------------------|
| `host`     | string           | yes       | —        | SMTP hostname, e.g. `smtp.fastmail.com`.                                 |
| `port`     | number           | no        | `587`    | SMTP port. `465` = implicit TLS, else STARTTLS.                          |
| `username` | string \| null   | no        | —        | AUTH LOGIN username (omit with `password` for an unauthenticated relay). |
| `password` | string \| null   | no        | —        | AUTH LOGIN password / app-password.                                      |
| `from`     | string           | yes       | —        | Envelope sender / `From:` address.                                       |
| `to`       | array of strings | yes       | —        | One or more recipient addresses.                                         |

```json
"alerts": {
  "discord_webhook_url": "https://discord.com/api/webhooks/123/abc",
  "ntfy_url": "https://ntfy.sh/my-private-topic",
  "webhook_url": "https://example.com/hooks/vantage",
  "email": {
    "host": "smtp.fastmail.com",
    "port": 465,
    "username": "alerts@example.com",
    "password": "app-password",
    "from": "alerts@example.com",
    "to": ["ops@example.com"]
  }
}
```

#### Backup

SQLite backup (on-disk retention + optional off-site mirror).

| Field            | Type           | Default  | Description                                                  |
|------------------|----------------|----------|--------------------------------------------------------------|
| `interval_hours` | number \| null | `24`     | Hours between automatic `VACUUM INTO` backups. `0` disables. |
| `keep`           | number \| null | `14`     | Number of automatic backups to retain.                       |
| `remote`         | object \| null | `null`   | Off-site target. Unset = local-only.                         |

**`backup.remote`** — S3-compatible target (`kind` is currently `"s3"` only).

| Field               | Type           | Required  | Description                                                                             |
|---------------------|----------------|-----------|-----------------------------------------------------------------------------------------|
| `kind`              | string         | yes       | Backend kind. Currently only `"s3"`.                                                    |
| `endpoint`          | string         | yes       | Endpoint base URL (AWS `https://s3.us-east-1.amazonaws.com`, B2, R2, MinIO, …).         |
| `region`            | string         | yes       | Signing region. AWS needs the real region; B2/R2/MinIO accept any value.                |
| `bucket`            | string         | yes       | Destination bucket.                                                                     |
| `prefix`            | string \| null | no        | Key prefix inside the bucket (e.g. `"vantage/"`; a trailing slash is added if missing). |
| `access_key_id`     | string         | yes       | Access key id.                                                                          |
| `secret_access_key` | string         | yes       | Secret access key.                                                                      |

```json
"backup": {
  "interval_hours": 12,
  "keep": 30,
  "remote": {
    "kind": "s3",
    "endpoint": "https://s3.us-west-002.backblazeb2.com",
    "region": "us-west-002",
    "bucket": "my-backups",
    "prefix": "vantage/",
    "access_key_id": "0026...",
    "secret_access_key": "K002..."
  }
}
```

#### Proxy

Reverse-proxy config generation.

| Field            | Type           | Default   | Description                                                                                                                             |
|------------------|----------------|-----------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `kind`           | string \| null | `"nginx"` | Backend: `"nginx"`, `"caddy"`, or `"cloudflared"`.                                                                                      |
| `config_dir`     | path \| null   | `null`    | Directory to write generated config into. Unset = routes tracked in the DB only (no files, no reload). Ignored in cloudflared API mode. |
| `reload_command` | string \| null | `null`    | Shell command to reload the proxy after regeneration, e.g. `"nginx -s reload"`.                                                         |

```json
"proxy": {
  "kind": "nginx",
  "config_dir": "/etc/nginx/conf.d",
  "reload_command": "nginx -s reload"
}
```

#### Cloudflare

Cloudflare API credentials (Tunnel API mode + DNS record upserts). All fields optional; supply what your setup uses.

| Field                     | Type           | Description                             |
|---------------------------|----------------|-----------------------------------------|
| `api_token`               | string \| null | Cloudflare API token.                   |
| `account_id`              | string \| null | Account id.                             |
| `tunnel_id`               | string \| null | Tunnel id (for API-managed tunnels).    |
| `zone_id`                 | string \| null | DNS zone id (for record upserts).       |
| `tunnel_name`             | string \| null | Tunnel name.                            |
| `tunnel_credentials_file` | string \| null | Path to a tunnel credentials JSON file. |

```json
"cloudflare": {
  "api_token": "cf-token",
  "account_id": "abc123",
  "tunnel_id": "def456",
  "zone_id": "ghi789",
  "tunnel_name": "vantage",
  "tunnel_credentials_file": "/etc/cloudflared/creds.json"
}
```

#### SQLite sources

Extra SQLite databases exposed in the database console. Each entry's `name` becomes a source
id (`sqlite:<name>`) — the console resolves it from this catalog, never from the request URL.

| Field  | Type | Required | Description                                                                     |
|--------|------|----------|---------------------------------------------------------------------------------|
| `name` | string | yes    | Display name and the lookup key (must not collide with the built-in `admin` or `requests` sources). |
| `path` | path   | yes    | Path to the `.db` file. Opened fresh per request, read-only unless danger mode is active.           |

```json
"sqlite_sources": [
  { "name": "percy", "path": "/var/lib/percy/percy.db" },
  { "name": "analytics", "path": "/opt/data/analytics.db" }
]
```

#### Complete example

A public-mode deployment exercising most fields:

```json
{
  "exposure": {
    "mode": "public",
    "bind": "0.0.0.0:443",
    "allowlist": ["203.0.113.0/24"],
    "require_client_cert": false,
    "country_allowlist": ["DE", "AT"]
  },
  "services": [
    { "name": "Web", "identifier": "web", "path": "/opt/stacks/web" }
  ],
  "firewall_backend": "nft",
  "secret_scan_paths": ["/opt", "/srv"],
  "spotlight_scripts": [
    { "id": "prune", "name": "Prune Docker", "command": "docker system prune -af", "schedule": "0 4 * * *" }
  ],
  "base_url": "https://vantage.example.com",
  "domains": ["vantage.example.com"],
  "production": true,
  "update_check_interval_hours": 12,
  "audit_retention_days": 90,
  "csp_report_only": false,
  "sqlite_sources": [
    { "name": "percy", "path": "/var/lib/percy/percy.db" }
  ],
  "postgres_url": "postgres://user:password@localhost:5432",
  "alerts": {
    "discord_webhook_url": "https://discord.com/api/webhooks/123/abc",
    "email": {
      "host": "smtp.fastmail.com", "port": 465,
      "username": "alerts@example.com", "password": "app-password",
      "from": "alerts@example.com", "to": ["ops@example.com"]
    }
  },
  "backup": {
    "interval_hours": 12, "keep": 30,
    "remote": {
      "kind": "s3", "endpoint": "https://s3.us-east-1.amazonaws.com",
      "region": "us-east-1", "bucket": "my-backups", "prefix": "vantage/",
      "access_key_id": "AKIA...", "secret_access_key": "..."
    }
  },
  "proxy": { "kind": "nginx", "config_dir": "/etc/nginx/conf.d", "reload_command": "nginx -s reload" },
  "cloudflare": { "api_token": "cf-token", "zone_id": "ghi789" },
  "sshd_auth_log_path": "/var/log/auth.log",
  "geoip_path": "/var/lib/geoip/GeoLite2-City.mmdb",
  "requests_db_path": "/var/lib/site/requests.db",
  "site_logs_path": "/var/log/site",
  "clamav_addr": "127.0.0.1:3310",
  "virustotal_api_key": "vt-key",
  "secret_key": "<auto-generated on first run>"
}
```

</details>

### Environment Variables

| Variable         | Purpose                                              |
|------------------|------------------------------------------------------|
| `VANTAGE_CONFIG` | Override config file path                            |
| `VANTAGE_PORT`   | Override bind port after config load                 |
| `RUST_LOG`       | Log level filter (default: `info`)                   |
| `HOST_PROC`      | Override `/proc` path (for containerized deployment) |
| `HOST_SYS`       | Override `/sys` path (for containerized deployment)  |

## Docker

The install flow is under [Quick Start](#quick-start). The container uses **host networking** so the firewall backend operates on real host rules. Key volume mounts:

| Mount                           | Purpose                    |
|---------------------------------|----------------------------|
| `./data:/data`                  | Config, database, logs     |
| `/var/run/docker.sock`          | Container dashboard        |
| `/etc/ufw`, `/var/lib/ufw`      | Firewall rule database     |
| `/proc`, `/sys` (read-only)     | Host metrics               |
| `/home`, `/root`                | SSH authorized_keys sync   |
| `/var/log/auth.log` (read-only) | SSH key last-used tracking |

Capabilities granted: `NET_ADMIN` (firewall rule modification) and `NET_BIND_SERVICE` (port <1024 binding).

## Updating

Vantage checks the project's GitHub releases on the same schedule as the container
image checks (`update_check_interval_hours`; `0` disables both), shows the new version
and its release notes on the settings page, and alerts your configured sinks the first
time a release appears. Nothing ever applies itself.

The settings page can apply the update for you when all three hold:

- Vantage runs in a container started by Docker Compose
- its image tag floats (`:latest`) rather than pinning an exact version
- `/var/run/docker.sock` is mounted into the container

It asks for your password again first and records the attempt in the audit log. Any
other setup is refused with the command to run by hand:

```bash
docker compose pull vantage && docker compose up -d vantage
```

## Development

Building from source needs Rust 1.74+ (2021 edition), and optionally the `mold` linker
(configured automatically on Linux builds). To build the container instead of pulling
it, uncomment the `build:` block in `docker-compose.yml`.

```bash
cargo build                     # compile
cargo run                       # run server (uses config.json)
cargo run -- admin              # bootstrap admin account
cargo test                      # run all tests (hermetic, in-memory DB)
cargo test <test_name>          # single test
cargo fmt                       # format (max_width=120)
cargo clippy                    # lint
```

Tests use `Config::test_default()` and `:memory:` SQLite — no external dependencies needed.

## Architecture

Vantage is structured as independent **feature slices** sharing a common `AppState`:

```
src/
  main.rs          -- entry point, AppState, router, auth
  config.rs        -- config.json loading, exposure policy
  session.rs       -- auth extractor, account model
  migrations.rs    -- compile-time embedded schema
  <feature>/       -- self-contained domain slice
    mod.rs         -- logic + background workers
    routes.rs      -- HTTP handlers
    storage.rs     -- SQLite persistence
```

Feature slices: account, audit, metrics, docker, firewall, health, secrets, sanitizer, proxy, backup, ssh, certs, security, logs, dbadmin, spotlight, cron, updates, alerts.

The server-side rendered frontend uses Askama templates (`templates/`) with per-page JS/CSS (`static/`). The UI is fully standalone — no external CDN or runtime dependency; fonts, icons, and chart libraries are vendored under `static/`.

Release history is in [CHANGELOG.md](CHANGELOG.md). Vantage is pre-1.0: the config
format and the exposure policy may still change between minor versions.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). A clean checkout builds with nothing but a
Rust toolchain — the shared kernel crates live in the public
[kls-core](https://github.com/klappstuhlpy/kls-core) repository.

## License

Vantage is licensed under the [GNU Affero General Public License v3.0](LICENSE).

Because the AGPL's network clause (section 13) applies, if you modify Vantage and let
others use it over a network, you must offer those users the source of your modified
version.
