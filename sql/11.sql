-- Script run history.
--
-- Every run of a `spotlight_scripts` entry — scheduled or pressed by hand —
-- lands here. Until now a scheduled script's only trace was a `tracing` line,
-- so "did last night's backup script actually run?" was answerable only by an
-- operator who still had the logs and knew to grep them.
--
-- `output` is bounded by the writer (tail-truncated), and the table is pruned to
-- a fixed row count on insert: this is a recent-history buffer, not a log store.
CREATE TABLE IF NOT EXISTS script_run
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    -- The config `id` of the script. Not a foreign key: scripts live in
    -- config.json, so a run must outlive the removal of the script it ran.
    script_id   TEXT    NOT NULL,
    -- Denormalised on purpose, for the same reason: the name at run time is a
    -- fact about the run, and renaming a script must not rewrite its history.
    script_name TEXT    NOT NULL,
    -- 'schedule' or 'manual'.
    trigger     TEXT    NOT NULL,
    -- Who pressed Run. NULL for scheduled runs, which nobody pressed.
    actor       TEXT,
    ok          INTEGER NOT NULL,
    exit_code   INTEGER,
    output      TEXT,
    duration_ms INTEGER NOT NULL,
    started_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS script_run_script_idx ON script_run (script_id, id DESC);
