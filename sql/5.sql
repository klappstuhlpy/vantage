-- Revises: V4
-- Creation Date: 2026-07-16
-- Reason: Secret scanner — track leaked-credential findings discovered by
--         the periodic filesystem scan at /secrets.

CREATE TABLE IF NOT EXISTS secret_finding
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    rule          TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    file_path     TEXT    NOT NULL,
    line          INTEGER NOT NULL,
    snippet       TEXT    NOT NULL,
    finding_hash  TEXT    NOT NULL UNIQUE,
    status        TEXT    NOT NULL DEFAULT 'open',
    first_seen    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen     TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS secret_finding_status_idx   ON secret_finding (status);
CREATE INDEX IF NOT EXISTS secret_finding_severity_idx ON secret_finding (severity);
CREATE INDEX IF NOT EXISTS secret_finding_last_seen    ON secret_finding (last_seen);

CREATE TABLE IF NOT EXISTS scan_run
(
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at     TEXT,
    files_scanned   INTEGER NOT NULL DEFAULT 0,
    bytes_scanned   INTEGER NOT NULL DEFAULT 0,
    findings_new    INTEGER NOT NULL DEFAULT 0,
    findings_total  INTEGER NOT NULL DEFAULT 0,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS scan_run_started_idx ON scan_run (started_at);
