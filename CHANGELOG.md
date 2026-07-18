# Changelog

All notable, user-visible changes to Vantage are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
as interpreted for an operator-facing control plane: MAJOR for a breaking change
to the config file or a removed feature, MINOR for a new capability, PATCH for
fixes and polish.

## [Unreleased]

### Fixed
- **Cloudflare analytics work again.** The deprecated `httpRequests1mGroups` dataset has been retired — the security page now queries `httpRequestsOverviewAdaptiveGroups` (hourly buckets) and derives threat counts from `firewallEventsAdaptiveGroups`, restoring the traffic chart and threat totals.
- Added more margin to the flag item in security recent events table for better readability.

## [0.3.0] - 2026-07-18

### Added

- **The database console browses more than Vantage's own database again.** A picker at the top of `/database` lists every SQLite file you have configured — `admin.db`, the site's `requests.db`, and anything you add under `sqlite_sources` — plus every database on an external PostgreSQL instance once you set `postgres_url`. Postgres sources also get a Roles tab showing who can log in and who is a superuser. Databases can only be added in `config.json`: there is deliberately no way to point the console at a path from the browser.
- Safe mode now names what it is protecting. Turning it off asks about *that* database specifically, the warning banner says which one is unguarded, and switching database turns safe mode back on rather than carrying an unguarded console over to a new target. Every query is recorded in the audit log with the database it ran against.
- **Vantage can now be run as a container.** A published image and a `docker-compose.yml` mean you no longer have to build from source to try it on a host — the README walks through the mounts it needs to see the host it is managing.

### Changed

- **The container log console reads far better and remembers its size.** Every line is now split into a timestamp, a colour-coded level, and the message — with warning and error lines tinted so they stand out while scrolling — instead of one flat grey stream, and a chatty container no longer makes the window stutter as lines pour in. You can drag the window to whatever size suits, and it reopens the way you left it.

### Fixed

- **The Metrics page drew no charts**, failing with "Couldn't load history" — the CPU, memory, network and disk history were all unavailable rather than plotting. The charts render again.
- **The page behind an open dialog could still be scrolled**, sliding the content out from under the dialog and exposing the blank space below it. Modals, drawers and the `Ctrl`+`K` palette now hold the page still while they are open.
- Dashboard widgets sharing a row are now the same height, so a short widget beside a tall one no longer leaves a blank gap beneath it.
- **Dragging a dashboard widget got stuck.** Cards could jitter in place, drift away from the slot they were heading for, or leave the whole grid frozen and refusing every later drag until the page was reloaded. Dragging is now steady from pick-up to drop, and a drag that ends in an unusual way — the pointer leaving the window, the browser taking the drag back — releases the grid properly instead of stranding it. Rearranging is also markedly smoother on a busy dashboard.
- **A second scrollbar sat beside the page**, showing a blank band under the interface and scrolling the frame out of view when dragged. The page frame is exactly one screen tall and now says so, so only the content area scrolls.
- Modals on the sign-in and public status pages let the page behind them scroll — those pages had never been covered by the scroll lock the rest of the interface uses.
- On the Firewall page, the block form's fields and its submit button sat on different lines, because only one field carried a hint beneath it. The row lines up whatever the fields contain.

## [0.2.0] - 2026-07-17

### Changed

- The minimum password length is now 12 characters, and `vantage admin` enforces the same rule the interface does — it used to accept 8, so the CLI could create a password the web UI would refuse to let you change it to. Existing passwords keep working; the rule applies when you set one.
- The interface has been rebuilt from the ground up around a new design system — a new palette, typography, icon set, and component library, with a light theme alongside the dark one, five accent colours, and a compact density option. Your preferences are remembered in your browser.
- Every page now sits in a new frame: grouped navigation that collapses to an icon rail, one honest live-connection indicator (the radar mark sweeps only while Vantage is genuinely connected to the host), and a layout that works down to a phone.

- The home page is now a dashboard you arrange yourself: add, remove, resize and drag widgets covering CPU, memory, disk, network, services, monitors, incidents, firewall and secret findings. Your layout is remembered in your browser.

### Added

- **Added a wiggle animation for dashboard widgets while in edit mode.**
- **Introduced a dynamic Settings page:** (under System) to manage operational configurations like audit retention, backup intervals, and update checks directly from the UI.

- **Applying firewall rules or a proxy configuration now reverts itself unless you confirm.** Apply first shows a dry-run — the exact commands about to hit the packet filter, or an old→new diff of every proxy config file — so nothing goes live unseen. Once applied, a countdown runs: confirm within the window to keep the change, or it rolls back on its own. A ruleset that cut off your own session undoes itself instead of locking you out of the box you were configuring. You can also revert immediately without waiting.
- **A global safe mode.** One switch in the top bar freezes every host change at once — firewall, proxy, containers, scripts and backups all go read-only, an amber banner says so on every page, and destructive controls disable themselves. Reads keep working. It is enforced on the server, not just hidden in the interface, so a stale tab or a script cannot slip a change past it. Turning it on and off asks for your password.
- **The log viewer can read the site's logs, not just Vantage's own.** Point `site_logs_path` at the site's log directory and the Logs page gains a source switch covering Vantage's log, the site's application log, and the site's bad-request log. Vantage is its own process and writes its own log, so it cannot find the site's without being told where they are — the same arrangement as `requests_db_path`. Leave the key unset and nothing changes: the page shows Vantage's log and no switch appears.

- **An Account page**, under System. Change your password, see every browser signed in as you — with the device and address it signed in from, and when it was last active — and cut any of them off. Until now the only way to change a Vantage password was to bootstrap a second account from the CLI.
- **Two-factor authentication can be turned on from the interface.** Vantage has always *checked* a TOTP code at sign-in, but there was no way to enrol one: the column existed and nothing could fill it. Scan the QR, confirm a code, and you get ten single-use recovery codes for the day your authenticator isn't there. A recovery code works at the sign-in prompt in place of a code, and each one works exactly once.
- **Changing a credential now asks for your password again**, even though you're already signed in — sessions last 12 hours, and an unlocked laptop should not be a standing licence to rewrite the credentials for a machine. The confirmation lasts 10 minutes and covers that browser only.

- **An Alerts page**, under System. See every notification sink, whether it's configured, and — for the first time — whether your alerts are actually arriving. Every delivery is now recorded with its result, so a webhook that has been quietly rejecting alerts for months no longer looks exactly like a quiet month. You can test a sink, mute a noisy one without editing a file on the host, and turn on an alert for sign-ins. Sink addresses stay in `config.json`: the page shows them masked and cannot change them, because an endpoint that redirects your alarms is the first thing worth having on a machine someone has just broken into.
- **An Audit log**, under System — every change made through Vantage, with who made it, the address they made it from, what they changed, and whether it worked. Refused attempts are kept too: a query safe-mode blocked, a sign-in that failed, a second factor that didn't check out. Search it, filter it by area or by person, and send someone the link — the filters live in the URL. Entries are kept for 90 days (`audit_retention_days` in `config.json`). Actions used to leave nothing but a line in the application log, in two different shapes, which meant no page could show them and no search could find them all.
- **A Scripts page**, under System. Your configured scripts, what they run, when they next fire, and the last 50 runs — scheduled and manual alike — each with its exit code and output. Press Run to run one now (it asks for your password first, and shows you the exact command before it runs). Scheduled scripts used to leave nothing behind but a log line, so "did last night's backup run?" was a question only the logs could answer.

- **Search anything with `Ctrl`+`K`** (or `/`): jump to any container, proxy route, firewall rule, SSH key, secret finding, script, or page. The search backend already existed but had never been reachable from the interface.
- Secret findings now stay **masked until you ask to see them**. A finding is a live credential; the old page printed it into the table for anyone glancing at the screen — or reading a screenshot pasted into a ticket. Reveal and copy are per-finding.
- The Logs page shows **which file it is reading**, follows the log without yanking you back to the bottom while you're reading further up, and highlights your search term in place.
- Deleting a backup now asks first, and says whether an off-site copy exists — deleting your only remaining copy reads differently to deleting one of two.
- Docker services now show an **update badge** when the registry has a newer image than the one you're running. Vantage has been checking for these all along without ever showing you the answer.
- Metrics, Docker, Health and Firewall gained real loading, empty and unavailable states, so a page tells you whether it's still fetching, has nothing to show, or can't reach the host — instead of showing "Loading…" forever.

### Fixed

- **The public status page reported "1.00%" uptime for a service with perfect uptime.** The figure is stored as a fraction and was printed as a percentage without converting it, so every service on the one page you'd show the public understated its uptime by a factor of a hundred.
- The sign-in and two-factor pages had been rendering completely unstyled: they linked a stylesheet that the rewrite removed. They are now proper pages — and, like every other page, they follow your light/dark preference.
- The accent picker showed all five swatches in the same colour, so you couldn't see what you were choosing.
- **The Proxy page now works.** It had never worked: the script that draws the route manager did not exist, so the page rendered a heading and two dead buttons over an empty box. Adding, editing, previewing the generated config, enabling, deleting and applying routes — all of it was implemented on the server and unreachable from the interface.
- **The SSH pages now work.** Both said "Loading…" forever, for the same reason: the script they referenced was never written. Keys, tokens, revocation and the audit log are all reachable for the first time.
- **Deleting or disabling a firewall rule did not remove it from the host** — on nftables, which is the backend Vantage picks by default. `nft delete rule` only accepts a rule *handle*, and Vantage was asking it to delete by matching the rule text, which is not valid syntax; the command failed every time and the error was discarded. The rule disappeared from the dashboard and kept filtering packets. Vantage now tags every rule it applies with its own id and deletes by the handle that tag resolves to — and if the host will not remove a rule, the rule **stays listed**, with the reason, instead of vanishing from the page while still live.
- **Releasing a lockout did not unblock the address** on nftables, for the same reason, and **an nft lockout may never have blocked anything**: the block was appended to the end of the filter chain, so any earlier "accept" rule won. Blocks are now inserted at the top, the way the ufw and iptables paths always did it.
- **The firewall's enable/disable switch didn't work at all** — the request was sent without the field naming the state to switch to, and the server rejected every one. (Introduced by the interface rewrite; the old page sent it correctly.)
- **Pressing Apply repeatedly stacked duplicate rules.** Every apply re-added every enabled rule, so a chain accumulated a fresh copy of the whole ruleset each time. Apply now skips what is already live, and removing a rule removes every copy of it rather than one.
- **Alerts were sent and forgotten.** Every alert Vantage raised — a monitor going down, a backup failing, a certificate expiring — was dispatched without ever looking at whether the sink accepted it. A rejected webhook was indistinguishable from a healthy one, and there was nowhere to find out. Failures are now recorded, reported on the Alerts page, and logged.
- **Scripts were never runnable on demand**, despite being described that way since 0.1.0: nothing but the cron scheduler could reach them, so a script without a `schedule` could not run at all. `Ctrl`+`K` now finds them and the Scripts page runs them.
- **A Docker service action was recorded before it ran**, so the record said what someone intended rather than what happened — a restart that failed left a trace indistinguishable from one that worked. Service actions, snapshot restores and proxy/firewall applies now record their outcome, and a partial apply is recorded as the failure it is.
- **A script that hit its 30-second timeout was abandoned, not stopped.** Vantage stopped waiting and reported a timeout while the command kept running on the host indefinitely, with nothing left holding a handle to it. Timed-out scripts are now killed.
- The `Ctrl`+`K` palette grouped SSH keys, secret findings and firewall rules under a generic "Results" heading with a placeholder icon, because the groups it knew about didn't match the ones the server actually sends.
- The Security page's styles and scripts never loaded at all — it referenced layout sections that didn't exist, so the page had been shipping inert. The layout now defines one documented set of sections, making the whole class of mistake impossible.
- Snapshots recorded an empty source image for every capture: the container picker read the image from the wrong place and silently stored nothing. New snapshots record it correctly, and existing rows now say "not recorded" rather than showing a blank.
- Network and disk figures on the Metrics page were reported as raw counters since boot, labelled as if they were current activity. They are now true per-second rates, and say so while waiting for a second sample rather than showing a misleading zero.
- Vantage no longer requests fonts or charting libraries from a CDN. Everything the interface needs is served by Vantage itself, so a host with no outbound internet access renders exactly like one that has it.
- Text throughout the interface now meets WCAG AA contrast in both themes and every accent colour, and all interface text scales and reflows properly on small screens.
- The Sanitizer's "Max 16 MB" was never true: uploads above 2 MB were rejected with an error the page reported as a generic failure. The 16 MB limit is now actually enforced, and a file over it is refused immediately with the reason, rather than after a pointless upload.
- The Sanitizer no longer implies a file is safe when nothing checked it. "VirusTotal has never seen this file" and "no scanner was configured" are now stated as themselves, rather than being reported the same way as a clean result.
- An expired certificate showed its countdown as a negative number ("-5 days"). It now reads "expired 5 days ago", and the certificate, TLS and off-site status labels throughout render with their intended colours — several had been emitting style names that no stylesheet defined, so they appeared as plain text.
- The Backups page's off-site status now distinguishes "no off-site target is configured" from "this snapshot is missing from the one you configured" — the second is a warning, and it used to look identical to the first.

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

[Unreleased]: https://github.com/klappstuhlpy/vantage/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/klappstuhlpy/vantage/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/klappstuhlpy/vantage/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/klappstuhlpy/vantage/releases/tag/v0.1.0
