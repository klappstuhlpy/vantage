-- Per-account UI preferences (theme, accent, density, sidebar, widget layout).
--
-- Stored as a JSON blob so adding a new preference key never requires a
-- migration. The frontend writes the full state on every save; the server
-- does no validation beyond "it parses as JSON" — the browser owns the schema.

CREATE TABLE IF NOT EXISTS user_prefs
(
    account_id INTEGER PRIMARY KEY REFERENCES account(id) ON DELETE CASCADE,
    prefs      TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
