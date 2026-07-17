-- Alert delivery log (FRONTEND_MIGRATION_PLAN §14, Phase 10).
--
-- Vantage has fanned alerts out to Discord/ntfy/webhook/email since 0.1.0, and
-- every one of those sends was a `let _ = ...`: the result was dropped on the
-- floor. So the one question an operator actually has about alerting — "did the
-- alert I never received get sent?" — had no answer anywhere in the product. A
-- silent alerting path is worse than none, because you believe it works.
--
-- One row per sink per attempt. `ok = 0` rows carry the reason in `error`.
-- `test = 1` marks a delivery fired by the Test button rather than by a real
-- event, so a test does not masquerade as evidence that alerting works for
-- events (it isn't — it proves the sink accepts a POST, which is still worth
-- knowing).
--
-- Bounded to the most recent ALERT_DELIVERY_RETAINED rows by the writer (see
-- `alerts::record_delivery`) rather than by a background task: the table only
-- grows on an alert, so pruning where the growth happens keeps it honest with
-- no scheduler to forget.
CREATE TABLE IF NOT EXISTS alert_delivery
(
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    sink    TEXT    NOT NULL,
    title   TEXT    NOT NULL,
    level   TEXT    NOT NULL,
    ok      INTEGER NOT NULL,
    error   TEXT,
    test    INTEGER NOT NULL DEFAULT 0,
    sent_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS alert_delivery_sent_at_idx ON alert_delivery (sent_at);
