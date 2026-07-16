-- Firewall UI — rule definitions + automatic-lockout block list (schema
-- byte-identical to the monolith's sql/10.sql, so the firewall storage layer
-- ports over unchanged).

-- Persistent rule store. The actual firewall (nftables/ufw/iptables) is the
-- source of truth at packet-filter level, but we keep a mirror in SQLite so the
-- UI can list, edit, and re-apply rules on demand.
CREATE TABLE IF NOT EXISTS firewall_rule
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    -- "allow" | "deny" | "rate_limit" | "geo_block"
    action      TEXT    NOT NULL,
    -- "in" | "out" | "any"
    direction   TEXT    NOT NULL DEFAULT 'in',
    -- "tcp" | "udp" | "icmp" | "any"
    proto       TEXT    NOT NULL DEFAULT 'any',
    -- Source CIDR or single IP.  NULL = any.
    source      TEXT,
    -- Destination port (NULL = any).
    port        INTEGER,
    -- Two-letter country code for geo rules.
    country     TEXT,
    -- Rate limit: requests-per-second cap (action='rate_limit' only).
    rate_per_s  INTEGER,
    note        TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Free-form metadata: backend used, raw nft handle, import marker, etc.
    meta_json   TEXT
);

CREATE INDEX IF NOT EXISTS firewall_rule_action_idx ON firewall_rule (action);
CREATE INDEX IF NOT EXISTS firewall_rule_source_idx ON firewall_rule (source);

-- Block list driven by automatic/manual lockout.  Separate from `firewall_rule`
-- because these are transient and self-expire.
CREATE TABLE IF NOT EXISTS firewall_lockout
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT    NOT NULL,
    reason       TEXT    NOT NULL,
    -- Number of triggering events seen (e.g. failed logins).
    hit_count    INTEGER NOT NULL DEFAULT 1,
    locked_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- NULL = no expiry, otherwise auto-unlock time.
    expires_at   TEXT,
    -- "active" | "released"
    status       TEXT    NOT NULL DEFAULT 'active'
);

CREATE INDEX IF NOT EXISTS firewall_lockout_ip_idx     ON firewall_lockout (ip);
CREATE INDEX IF NOT EXISTS firewall_lockout_status_idx ON firewall_lockout (status);

CREATE UNIQUE INDEX IF NOT EXISTS firewall_lockout_active_ip_idx
    ON firewall_lockout (ip) WHERE status = 'active';
