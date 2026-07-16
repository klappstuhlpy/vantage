-- Vantage's own database (admin.db) — the auth foundation the admin shell owns.
--
-- Vantage has its own identities by design (ADMIN_SEPARATION_PLAN §4, §7.3):
-- no shared table, no SSO with the site. Expect 1-2 rows in `account`. Passwords
-- are Argon2 (bootstrap via `vantage admin`); `flags` bit 0 is the admin flag,
-- kept wire-compatible with the site's AccountFlags so the shared token/session
-- machinery maps over unchanged. TOTP columns are present now (passkeys land in
-- Phase 7); recovery codes and API keys arrive with their slices.
--
-- The admin **feature** tables (firewall_rule, proxy_route, health_target,
-- ssh_key, metric_sample, …) are NOT here: each moves in with its slice as a
-- later numbered migration (sql/1.sql onward), so this file stays the stable
-- account/session core. See ADMIN_SEPARATION_PLAN §9.1 for the table disposition.

CREATE TABLE IF NOT EXISTS account
(
    id           INTEGER PRIMARY KEY,
    name         TEXT UNIQUE NOT NULL,
    password     TEXT        NOT NULL,
    created_at   TEXT        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    flags        INTEGER     NOT NULL DEFAULT 0,
    totp_secret  TEXT,
    totp_enabled INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS account_name_idx ON account (name);

CREATE TABLE IF NOT EXISTS session
(
    id          TEXT PRIMARY KEY,
    account_id  INTEGER REFERENCES account (id) ON DELETE CASCADE,
    created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description TEXT,
    api_key     INTEGER NOT NULL DEFAULT 0,
    -- Comma-separated granted scopes for API keys (empty = browser session /
    -- full access), mirroring the site's session table so the shared scope
    -- extractor pattern ports over when the API slice arrives.
    scopes      TEXT    NOT NULL DEFAULT ''
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS session_account_id_idx ON session (account_id);
CREATE INDEX IF NOT EXISTS session_api_key_idx ON session (api_key);

-- Generic key/value store (runtime toggles, checker caches). Admin-owned keys
-- only — the site keeps its own `storage` (ADMIN_SEPARATION_PLAN §9.1 note).
CREATE TABLE IF NOT EXISTS storage
(
    name  TEXT PRIMARY KEY,
    value TEXT
) WITHOUT ROWID;
