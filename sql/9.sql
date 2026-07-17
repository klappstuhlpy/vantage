-- Account & security shell (FRONTEND_MIGRATION_PLAN §14, Phase 9).
--
-- Two additions, both in service of the /account page.
--
-- 1. Session provenance. `session` has carried a free-text `description` since
--    sql/0.sql, and every browser login writes the same string into it
--    ("Vantage web session"), which cannot answer the one question a session
--    list exists to answer: is that row me, or someone else? The columns below
--    record where a session came from and when it was last seen. They are
--    nullable on purpose — sessions minted before this migration genuinely have
--    no provenance, and the UI says "unknown" rather than inventing it.
--
-- 2. Sudo stamps. `sudo_at` is when this session last re-authenticated. A
--    destructive action requires a stamp inside the sudo window (see
--    `account::sudo`); NULL means "never", which is both the correct default for
--    a pre-existing session and the fail-closed one.

ALTER TABLE session ADD COLUMN last_seen_at TEXT;
ALTER TABLE session ADD COLUMN user_agent TEXT;
ALTER TABLE session ADD COLUMN ip TEXT;
ALTER TABLE session ADD COLUMN sudo_at TEXT;

-- Recovery codes — the way back in when the authenticator app is gone.
--
-- Hashed with SHA-256 rather than Argon2, and that is deliberate: Argon2 exists
-- to make a *low*-entropy secret (a password a human chose) expensive to guess
-- at scale. These codes are 50 bits of getrandom output, so there is nothing to
-- guess; the only property needed is that a leaked admin.db or backup does not
-- hand over usable codes, which a plain digest of a high-entropy input already
-- gives. Same reasoning as `ssh::hash_token`, which treats its generated tokens
-- exactly this way.
--
-- A code is single-use: `used_at` is stamped on redemption and the row is kept,
-- so the account page can show how many codes are spent without keeping the code.
CREATE TABLE IF NOT EXISTS recovery_code
(
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    code_hash  TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    used_at    TEXT
);

CREATE INDEX IF NOT EXISTS recovery_code_account_idx ON recovery_code (account_id);
