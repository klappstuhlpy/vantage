-- SSH key management tables: authorized keys, temporary access tokens, and session audit.

CREATE TABLE IF NOT EXISTS ssh_key (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES account(id),
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    algo TEXT NOT NULL,
    comment TEXT,
    target_user TEXT,
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT,
    revoked_at TEXT,
    UNIQUE(account_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS ssh_token (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES account(id),
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '',
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    used_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS ssh_session_audit (
    id INTEGER PRIMARY KEY,
    account_id INTEGER,
    key_id INTEGER,
    action TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
