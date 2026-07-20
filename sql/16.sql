-- Certificate-expiry alert state — one row per SSL monitor that has already
-- crossed an expiry milestone, holding the tightest threshold notified so far.
--
-- The table exists purely to make the alert fire once per milestone instead of
-- once per probe. An `ssl` monitor on a 60-second interval sitting six days from
-- expiry is 1440 notifications a day for a fact the operator learned the first
-- time, and an alert channel that cries that often is one nobody reads when the
-- next thing actually breaks.
--
-- The row is deleted once the certificate is renewed (days-left back outside the
-- widest threshold), which re-arms the whole ladder for the next cycle. The
-- cascade drops it with the monitor.

CREATE TABLE IF NOT EXISTS cert_alert_state (
    target_id   INTEGER PRIMARY KEY REFERENCES health_target (id) ON DELETE CASCADE,
    threshold   INTEGER NOT NULL,
    notified_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
