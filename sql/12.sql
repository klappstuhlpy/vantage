-- The audit log: who did what to this host, through Vantage.
--
-- Distinct from `logs/` (the app's tracing output, a file that rotates) and from
-- the count-bounded buffers next to it (`alert_delivery`, `script_run`, which
-- answer "is this feature working?"). This answers "who changed the firewall on
-- the 3rd?", so it is retained by *time* rather than by row count — a busy
-- afternoon must not silently push last week off the end of the evidence.
--
-- A hard row cap still applies on top of the time window (see `audit::prune`):
-- retention is a promise about how far back you can look, not a licence for a
-- runaway loop to fill the disk.
CREATE TABLE IF NOT EXISTS audit_log
(
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    -- A stable dotted name: `firewall.rule.create`, `ssh.key.revoke`. Stable is
    -- the point — these are what a filter, and any future alert, match on.
    action TEXT    NOT NULL,
    -- The account name at the time of the action. Denormalised deliberately: an
    -- audit row must not change meaning because an account was later renamed or
    -- deleted, and it must survive that deletion.
    actor  TEXT    NOT NULL,
    -- The address the request came from — the socket peer, stamped onto the
    -- Account by the session extractor. NULL for actions no request asked for
    -- (a scheduled script run).
    ip     TEXT,
    -- What the action was done to (a rule id, a key fingerprint, a container).
    target TEXT,
    -- A JSON object of action-specific context. Free-form on purpose: the shape
    -- of "what else mattered" differs per action, and a column per fact would be
    -- a migration every time a handler learns a new one.
    detail TEXT,
    -- 0 when the action was attempted and refused or failed. A log of only the
    -- successes is the wrong half: `database.query.blocked` is the interesting row.
    ok     INTEGER NOT NULL DEFAULT 1,
    at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- The two reads the page makes: the newest N, and the newest N of one action.
CREATE INDEX IF NOT EXISTS audit_log_at_idx ON audit_log (id DESC);
CREATE INDEX IF NOT EXISTS audit_log_action_idx ON audit_log (action, id DESC);
CREATE INDEX IF NOT EXISTS audit_log_actor_idx ON audit_log (actor, id DESC);
