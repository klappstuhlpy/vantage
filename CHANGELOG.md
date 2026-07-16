# Changelog

All notable, user-visible changes to Vantage are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
as interpreted for an operator-facing control plane: MAJOR for a breaking change
to the config file or a removed feature, MINOR for a new capability, PATCH for
fixes and polish.

Vantage is pre-1.0 — the config format and the exposure policy may still change
between minor versions.

## [Unreleased]

## [0.1.0] - 2026-07-16

### Added

- Initial release: a security-first control plane for a VPS or homelab, served as a terminal-styled web UI with a CLI for bootstrapping the first admin account.
- Docker management: browse containers, networks, and volumes as a dependency graph, follow live events, start/stop/restart/pull/recreate a service, and watch per-service stats and logs.
- A firewall view that mirrors your existing nftables, ufw, or iptables rules and can lock out an address automatically after repeated failed logins.
- Uptime monitoring with HTTP, TCP, keyword, and SSL probes, incident tracking, and alerts when a probe changes state.
- Live host metrics — CPU, memory, disk, and network — alongside per-container stats, updating in place without a refresh.
- SSL certificate monitoring that tracks expiry across your domains and warns before one lapses.
- A periodic secret scan of the filesystem that reports credentials committed or left where they shouldn't be.
- A file sanitizer that checks suspicious files against ClamAV and VirusTotal.
- Reverse proxy configuration for nginx, Caddy, and Cloudflare Tunnels, including DNS record upserts through the Cloudflare API.
- SSH key management: review and edit authorized keys, issue temporary access tokens for automation, and audit what was used.
- A read-only database console for inspecting the application's own database, guarded so a query cannot write.
- Automatic database backups with a retention policy and optional off-site mirroring to any S3-compatible bucket.
- Scheduled operator scripts, runnable on a cron schedule or on demand from the Ctrl+K palette.
- Docker image update checks that compare your running images against the registry and surface what is out of date.
- Alerting to Discord, ntfy, a generic webhook, or email — any combination, all optional.
- A security overview with request statistics, GeoIP lookups, Cloudflare panels, and a record of login attempts.

### Security

- Network exposure is fail-closed and decided at startup: the default VPN mode refuses to start on a public interface, and public mode requires an explicit address allowlist — an empty allowlist denies everyone rather than admitting everyone.
- Accounts are protected by Argon2 password hashing, signed session cookies scoped to the host, and optional TOTP two-factor authentication with the shared secret encrypted at rest.
- Repeated failed logins from the same address are throttled independently of any firewall configuration, and login timing does not reveal whether a username exists.
- Changes to the host are made through a typed, audited boundary rather than by shelling out.

[Unreleased]: https://github.com/klappstuhlpy/vantage/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/klappstuhlpy/vantage/releases/tag/v0.1.0
