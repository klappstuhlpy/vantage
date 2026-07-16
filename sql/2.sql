-- Health checks / uptime monitoring (Uptime-Kuma-style internal monitor).
--
-- Three tables (schema byte-identical to the monolith's sql/9.sql, so the
-- health storage layer ports over unchanged):
--   * health_target        — what we monitor (URL/host/cert + check params)
--   * health_check_sample  — every probe result (status, latency, error)
--   * health_incident      — open + closed downtime windows derived from samples

CREATE TABLE IF NOT EXISTS health_target
(
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL,
    -- "http" | "tcp" | "keyword" | "ssl"
    kind             TEXT    NOT NULL,
    -- For http/keyword/ssl: URL.  For tcp: host:port.
    target           TEXT    NOT NULL,
    -- Per-kind options stored as JSON: keyword, expected_status,
    -- expected_response, follow_redirects, http_method, http_headers,
    -- warn_days (SSL only), etc.
    config_json      TEXT    NOT NULL DEFAULT '{}',
    interval_seconds INTEGER NOT NULL DEFAULT 60,
    timeout_ms       INTEGER NOT NULL DEFAULT 5000,
    -- Latency threshold for "degraded" classification.  When the probe
    -- succeeds but takes longer than this, status becomes "degraded"
    -- instead of "up".
    degraded_ms      INTEGER NOT NULL DEFAULT 1000,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS health_target_enabled_idx ON health_target (enabled);

CREATE TABLE IF NOT EXISTS health_check_sample
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id     INTEGER NOT NULL REFERENCES health_target (id) ON DELETE CASCADE,
    ts            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- "up" | "down" | "degraded"
    status        TEXT    NOT NULL,
    latency_ms    INTEGER,
    -- HTTP status code (for http/keyword checks)
    status_code   INTEGER,
    -- Free-form failure reason ("connection refused", "keyword not found", …)
    error         TEXT,
    -- For SSL checks: days remaining until cert expiry.
    ssl_days_left INTEGER
);

CREATE INDEX IF NOT EXISTS health_sample_target_ts_idx
    ON health_check_sample (target_id, ts DESC);

CREATE TABLE IF NOT EXISTS health_incident
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER NOT NULL REFERENCES health_target (id) ON DELETE CASCADE,
    -- "down" | "degraded"
    status       TEXT    NOT NULL,
    started_at   TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- NULL while the incident is ongoing.
    ended_at     TEXT,
    -- Snapshot of the most recent error reason for fast listing.
    last_error   TEXT,
    -- Count of consecutive failing samples that built this incident.
    sample_count INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS health_incident_target_idx   ON health_incident (target_id);
CREATE INDEX IF NOT EXISTS health_incident_started_idx  ON health_incident (started_at DESC);
CREATE INDEX IF NOT EXISTS health_incident_open_idx     ON health_incident (target_id, ended_at);
