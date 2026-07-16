# Security Policy

Vantage is deliberately a remote-root web application: an authenticated session can
manage containers, firewall rules, SSH keys, and scheduled scripts on the host. A
vulnerability here is a host compromise, so security reports are treated as the
highest-priority class of issue.

## Supported versions

Vantage is pre-1.0. Only the latest release receives security fixes; there are no
backports to earlier 0.x versions.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report it through
[GitHub private vulnerability reporting](https://github.com/klappstuhlpy/vantage/security/advisories/new),
which keeps the discussion private until a fix is released.

Please include what you need to make the issue reproducible: affected version, the
exposure mode in use, the steps, and what an attacker gains. A proof of concept is
welcome but never required — a clear description of the flaw is enough.

You will get an acknowledgement of the report, and a fix will be released before the
report is made public. Please give the fix a chance to ship before disclosing publicly.

## Scope

In scope — anything that lets someone:

- reach an authenticated surface without valid credentials, or bypass the second factor
- escape the read-only guards (the database console, Docker introspection)
- issue a privileged host operation that the session should not be allowed to make
- bind or reach a listener that the configured exposure mode should have refused
- recover a secret at rest (session key, TOTP secret, stored credentials)

Out of scope:

- Findings that require an attacker who already has root or an admin session — that
  is the intended power of an admin session, not a privilege escalation.
- A deployment configured to be reachable publicly with a permissive allowlist. That
  is a supported mode, but exposing it is your decision and its consequences are yours.
- Vulnerabilities in Docker, your firewall backend, or another dependency, unless
  Vantage's use of it is what makes it exploitable. Report those upstream.
- Missing hardening with no demonstrated impact.

## Deployment guidance

The safest posture is the default: run in `vpn` mode, reachable only over a private
network or a VPN, and never expose it directly to the internet. If you do use
`public` mode, treat the CIDR allowlist as the primary control and enable the second
factor on every account.
