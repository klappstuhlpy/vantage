-- Query history and saved queries for DB Studio (Phase 3).
--
-- History records every query the console ran, per account, bounded to a
-- recent-history buffer (200 rows per account, pruned on insert). Saved queries
-- are named bookmarks of SQL the operator wants to keep.
--
-- Both tables hold SQL text that may contain secrets (connection strings in
-- comments, passwords in INSERT literals). They live in admin.db — the same
-- database as the audit log, with the same access posture: admin-only data in
-- an admin-only store.

CREATE TABLE IF NOT EXISTS query_history
(
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    source     TEXT    NOT NULL,
    sql_text   TEXT    NOT NULL,
    ok         INTEGER NOT NULL DEFAULT 1,
    row_count  INTEGER NOT NULL DEFAULT 0,
    elapsed_ms INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS query_history_account_idx ON query_history (account_id, id DESC);

CREATE TABLE IF NOT EXISTS saved_query
(
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    source     TEXT    NOT NULL,
    sql_text   TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(account_id, name)
);

CREATE INDEX IF NOT EXISTS saved_query_account_idx ON saved_query (account_id, id DESC);
