-- Failed SSH auth attempts, aggregated one row per source IP.
--
-- The sshd auth-log watcher (src/ssh/mod.rs) already tails the log for
-- successful publickey logins; this table is the failure side of the same
-- stream. Aggregate-per-IP rather than one row per event so the table stays
-- bounded (one row per attacker) without a pruner — a brute-force run is
-- thousands of lines but a handful of IPs.
CREATE TABLE ssh_auth_failure (
    ip         TEXT PRIMARY KEY,
    attempts   INTEGER NOT NULL DEFAULT 1,
    last_user  TEXT,
    first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ssh_auth_failure_last_seen ON ssh_auth_failure(last_seen);
