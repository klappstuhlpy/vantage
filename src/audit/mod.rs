//! The audit log — who did what to this host, through Vantage.
//!
//! ## One call, not two conventions
//!
//! Before this slice, admin actions were recorded by hand-written `tracing`
//! events in two mutually incompatible shapes: half the app emitted
//! `tracing::info!(action = "ssh.key.revoke", account = %name, …)` and the other
//! half emitted `tracing::info!(actor = %name, target = id, "firewall.rule.create")`
//! — the action name as a *message*. Anything that read one shape silently
//! missed the other, which is the specific way an audit log betrays you: it
//! looks complete.
//!
//! So the audit event is not scraped from the log. [`log`] is a typed call that
//! writes the row **and** emits the tracing event, and the call sites use it
//! instead of a hand-rolled `tracing::info!`. Forgetting to audit a new action
//! is still possible — nothing can fix that but review — but *mis-shaping* one
//! no longer is, and there is exactly one thing to grep for.
//!
//! ## The address
//!
//! Audited actions carry the address they came from, taken from
//! [`Account::ip`](crate::session::Account::ip) — stamped once by the session
//! extractor from the socket peer, which is the same source of truth the public
//! guard uses. The alternative was thirty handlers each remembering to ask for a
//! `ConnectInfo`, which is thirty chances to produce an audit row that cannot say
//! where it came from.
//!
//! ## Retention
//!
//! Time-based (`audit_retention_days`, default 90) with a hard row cap on top.
//! Deliberately unlike the count-bounded buffers beside it (`alert_delivery`,
//! `script_run`): those answer "is this feature working?", where only the recent
//! rows matter. This one answers "who changed the firewall on the 3rd?", and a
//! busy afternoon must not push last week off the end of the evidence.

use serde::Serialize;
use serde_json::Value;

use kls_web_core::Database;

pub mod routes;

/// The ceiling regardless of the retention window. Roughly a decade of ordinary
/// use, and a bound on the worst case: a loop that audits in anger cannot fill
/// the disk, it can only shorten the window.
const MAX_ROWS: i64 = 100_000;

/// How long entries are kept when `config.audit_retention_days` is unset.
pub const DEFAULT_RETENTION_DAYS: u32 = 90;

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub id: i64,
    pub action: String,
    pub actor: String,
    pub target: Option<String>,
    pub ip: Option<String>,
    /// The stored JSON object, re-parsed. `Null` when the action had no context.
    pub detail: Value,
    pub ok: bool,
    pub at: String,
}

/// One action, being described before it is recorded.
///
/// A builder rather than a six-argument function: most actions need three of the
/// fields and a positional `None, None, true` at every call site is how the wrong
/// `None` ends up in the wrong slot.
#[must_use = "an audit event does nothing until .record() is awaited"]
pub struct Event {
    action: &'static str,
    actor: String,
    ip: Option<String>,
    target: Option<String>,
    detail: Option<Value>,
    ok: bool,
}

/// Begins an audit event for `action`, performed by `account`.
///
/// Takes the whole account rather than a name so the address comes along without
/// the call site thinking about it.
pub fn event(action: &'static str, account: &crate::session::Account) -> Event {
    Event {
        action,
        actor: account.name.clone(),
        ip: account.ip.clone(),
        target: None,
        detail: None,
        ok: true,
    }
}

/// Begins an audit event for something no signed-in account did — a scheduled
/// run, a background sweep. `actor` names the mechanism ("scheduler").
pub fn system_event(action: &'static str, actor: &str) -> Event {
    Event {
        action,
        actor: actor.to_string(),
        ip: None,
        target: None,
        detail: None,
        ok: true,
    }
}

impl Event {
    /// What the action was done to.
    pub fn target(mut self, target: impl std::fmt::Display) -> Self {
        self.target = Some(target.to_string());
        self
    }

    /// The address behind the action, for the one case that has no extracted
    /// `Account` to take it from: a sign-in, which is the request that *creates*
    /// the session everything else reads it off.
    pub fn ip(mut self, ip: impl std::fmt::Display) -> Self {
        self.ip = Some(ip.to_string());
        self
    }

    /// Action-specific context, as a JSON object.
    pub fn detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }

    /// Marks an attempt that was refused or failed. These rows are the
    /// interesting half — `database.query.blocked` matters more than the queries
    /// that ran — so they are recorded, not skipped.
    pub fn failed(mut self) -> Self {
        self.ok = false;
        self
    }

    /// Sets `ok` from a result-shaped boolean.
    pub fn ok(mut self, ok: bool) -> Self {
        self.ok = ok;
        self
    }

    /// Writes the row and emits the matching tracing event.
    ///
    /// Best-effort by design: an audit write that fails must not fail the action
    /// the operator asked for. It is logged loudly instead — and because the
    /// tracing event is emitted here too, the fact survives even when the row
    /// does not.
    pub async fn record(self, db: &Database) {
        let Event {
            action,
            actor,
            ip,
            target,
            detail,
            ok,
        } = self;

        // Emitted here rather than at the call site so the log file and the audit
        // table cannot disagree about what happened — they are one statement.
        if ok {
            tracing::info!(action, actor, ip = ?ip, target = ?target, detail = ?detail, "audit");
        } else {
            tracing::warn!(action, actor, ip = ?ip, target = ?target, detail = ?detail, "audit: refused or failed");
        }

        let detail = detail.map(|d| d.to_string());
        if let Err(e) = db
            .execute(
                "INSERT INTO audit_log(action, actor, ip, target, detail, ok) VALUES (?, ?, ?, ?, ?, ?)",
                (action, actor, ip, target, detail, ok as i64),
            )
            .await
        {
            tracing::error!(action, error = ?e, "AUDIT WRITE FAILED — this action is not in the audit log");
        }
    }
}

// ─── Reading ────────────────────────────────────────────────────────────────

/// Filters for the audit page. Every field is optional and they `AND` together.
#[derive(Debug, Default, Clone)]
pub struct Filter {
    /// Exact action name, or a `prefix.` — `firewall.` matches every firewall
    /// action, which is how anyone actually reads this: by area, not by verb.
    pub action: Option<String>,
    pub actor: Option<String>,
    /// Substring across action/target/detail.
    pub query: Option<String>,
    /// Only failed/refused attempts.
    pub failures_only: bool,
    pub limit: i64,
    /// Keyset pagination: return rows with `id` below this. Not OFFSET, which
    /// skips or repeats rows when a new action lands mid-read.
    pub before: Option<i64>,
}

pub async fn entries(db: &Database, filter: Filter) -> anyhow::Result<Vec<Entry>> {
    use anyhow::Context;
    db.call(move |conn| {
        // `?N IS NULL OR …` keeps one prepared statement for every filter
        // combination, rather than concatenating SQL per request.
        let mut stmt = conn.prepare_cached(
            "SELECT id, action, actor, ip, target, detail, ok, at FROM audit_log \
             WHERE (?1 IS NULL OR action = ?1 OR action LIKE ?1 || '%') \
               AND (?2 IS NULL OR actor = ?2) \
               AND (?3 IS NULL OR action LIKE '%' || ?3 || '%' \
                              OR IFNULL(ip, '') LIKE '%' || ?3 || '%' \
                              OR IFNULL(target, '') LIKE '%' || ?3 || '%' \
                              OR IFNULL(detail, '') LIKE '%' || ?3 || '%') \
               AND (?4 = 0 OR ok = 0) \
               AND (?5 IS NULL OR id < ?5) \
             ORDER BY id DESC LIMIT ?6",
        )?;
        let rows: rusqlite::Result<Vec<Entry>> = stmt
            .query_map(
                (
                    filter.action,
                    filter.actor,
                    filter.query,
                    filter.failures_only as i64,
                    filter.before,
                    filter.limit,
                ),
                |row| {
                    let detail: Option<String> = row.get(5)?;
                    Ok(Entry {
                        id: row.get(0)?,
                        action: row.get(1)?,
                        actor: row.get(2)?,
                        ip: row.get(3)?,
                        target: row.get(4)?,
                        // A detail that will not parse is shown as the string it
                        // is rather than dropped: it is still evidence.
                        detail: detail
                            .map(|d| serde_json::from_str(&d).unwrap_or(Value::String(d)))
                            .unwrap_or(Value::Null),
                        ok: row.get::<_, i64>(6)? != 0,
                        at: row.get(7)?,
                    })
                },
            )?
            .collect();
        rows
    })
    .await
    .context("could not read the audit log")
}

/// The distinct action names present, for the filter menu.
///
/// Read from the data rather than from a hardcoded list: a list would drift the
/// moment someone adds an action, and drift *quietly* — the filter would simply
/// never offer the new one.
pub async fn known_actions(db: &Database) -> anyhow::Result<Vec<String>> {
    use anyhow::Context;
    db.call(|conn| {
        let mut stmt = conn.prepare_cached("SELECT DISTINCT action FROM audit_log ORDER BY action")?;
        let rows: rusqlite::Result<Vec<String>> = stmt.query_map([], |row| row.get(0))?.collect();
        rows
    })
    .await
    .context("could not read the audit actions")
}

/// Total rows and the oldest timestamp still held — what the page needs to say
/// how far back the evidence actually goes, rather than quoting the configured
/// window and hoping.
pub async fn coverage(db: &Database) -> (i64, Option<String>) {
    db.get_row("SELECT COUNT(*), MIN(at) FROM audit_log", (), |row| {
        Ok((row.get(0)?, row.get(1)?))
    })
    .await
    .unwrap_or((0, None))
}

// ─── Retention ──────────────────────────────────────────────────────────────

/// Deletes entries outside the retention window, then enforces the hard cap.
pub async fn prune(db: &Database, retention_days: u32) -> anyhow::Result<usize> {
    use anyhow::Context;
    let window = format!("-{retention_days} days");
    let by_age = db
        .execute(
            "DELETE FROM audit_log WHERE at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)",
            (window,),
        )
        .await
        .context("could not prune the audit log")?;
    let by_cap = db
        .execute(
            "DELETE FROM audit_log WHERE id <= (SELECT MAX(id) FROM audit_log) - ?",
            (MAX_ROWS,),
        )
        .await
        .context("could not cap the audit log")?;
    if by_cap > 0 {
        // The window is the promise; the cap breaking it is worth saying out loud.
        tracing::warn!(
            rows = by_cap,
            "audit log hit its {MAX_ROWS}-row cap — entries younger than the retention window were dropped"
        );
    }
    Ok(by_age + by_cap)
}

/// The audit retention window in days that `config.json` (or the built-in
/// default) asks for — the base before any runtime override.
pub fn config_retention_days(state: &crate::AppState) -> u32 {
    state.config.audit_retention_days.unwrap_or(DEFAULT_RETENTION_DAYS)
}

/// The *effective* retention window: a dashboard override wins over `config.json`,
/// which wins over the built-in default. This is what the pruner and the UI read.
pub fn retention_days(state: &crate::AppState) -> u32 {
    state
        .settings
        .get()
        .audit_retention_days
        .or(state.config.audit_retention_days)
        .unwrap_or(DEFAULT_RETENTION_DAYS)
}

/// Spawns the daily audit pruner.
pub fn spawn_pruner(state: crate::AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
        loop {
            tick.tick().await;
            // Re-read every tick so a retention change from the settings page
            // takes effect on the next prune, no restart needed.
            let days = retention_days(&state);
            match prune(&state.db, days).await {
                Ok(n) if n > 0 => tracing::info!(rows = n, days, "pruned audit entries"),
                Err(e) => tracing::warn!(error = ?e, "could not prune the audit log"),
                _ => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::session::Account;
    use std::sync::Arc;

    /// The migrated schema, in memory. `Database` itself is not `Clone` — the
    /// pool is shared through the `Arc` the state already holds.
    async fn db() -> Arc<Database> {
        let state = crate::build_state_with(Config::test_default(), std::path::Path::new(":memory:"))
            .await
            .expect("build state");
        state.db.clone()
    }

    /// An account as the session extractor would hand it over: with an address.
    fn root() -> Account {
        Account {
            id: 1,
            name: "root".into(),
            password: String::new(),
            flags: crate::FLAG_ADMIN,
            totp_enabled: false,
            totp_secret: None,
            avatar_type: None,
            ip: Some("203.0.113.7".into()),
        }
    }

    #[tokio::test]
    async fn records_and_reads_back_an_action() {
        let db = db().await;
        event("firewall.rule.create", &root())
            .target(42)
            .detail(serde_json::json!({ "action": "drop", "source": "198.51.100.4" }))
            .record(&db)
            .await;

        let rows = entries(
            &db,
            Filter {
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "firewall.rule.create");
        assert_eq!(rows[0].actor, "root");
        assert_eq!(rows[0].target.as_deref(), Some("42"));
        assert_eq!(rows[0].detail["source"], "198.51.100.4");
        assert!(rows[0].ok);
        // The address rides along from the extractor without the call site
        // asking for it — that is the whole point of taking the account.
        assert_eq!(rows[0].ip.as_deref(), Some("203.0.113.7"));
    }

    /// An action nobody performed still names something as the actor.
    #[tokio::test]
    async fn a_system_action_has_no_address_and_says_who_it_was() {
        let db = db().await;
        system_event("script.run", "scheduler")
            .target("nightly-restic")
            .record(&db)
            .await;

        let rows = entries(
            &db,
            Filter {
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(rows[0].actor, "scheduler");
        assert!(rows[0].ip.is_none(), "a scheduled run came from no address");
    }

    /// The refused half is the half worth having.
    #[tokio::test]
    async fn a_refused_action_is_recorded_as_a_failure() {
        let db = db().await;
        event("database.query.blocked", &root())
            .detail(serde_json::json!({ "sql": "DROP TABLE account" }))
            .failed()
            .record(&db)
            .await;

        let failures = || {
            let db = db.clone();
            async move {
                entries(
                    &db,
                    Filter {
                        failures_only: true,
                        limit: 10,
                        ..Default::default()
                    },
                )
                .await
                .unwrap()
            }
        };
        let rows = failures().await;
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].ok);

        // …and a successful action must not show up under that filter.
        event("ssh.key.add", &root()).record(&db).await;
        assert_eq!(failures().await.len(), 1, "a success leaked into the failures filter");
    }

    /// Nobody reads an audit log by verb; they read it by area.
    #[tokio::test]
    async fn an_action_prefix_matches_the_whole_area() {
        let db = db().await;
        event("firewall.rule.create", &root()).record(&db).await;
        event("firewall.rule.delete", &root()).record(&db).await;
        event("ssh.key.add", &root()).record(&db).await;

        let rows = entries(
            &db,
            Filter {
                action: Some("firewall.".into()),
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.action.starts_with("firewall.")));

        // An exact name still selects exactly one.
        let rows = entries(
            &db,
            Filter {
                action: Some("ssh.key.add".into()),
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn search_covers_the_target_the_address_and_the_detail() {
        let db = db().await;
        event("ssh.key.revoke", &root()).target("SHA256:abc").record(&db).await;
        event("proxy.route.create", &root())
            .detail(serde_json::json!({ "host": "vpn.example.test" }))
            .record(&db)
            .await;

        let hit = |q: &str| {
            let db = db.clone();
            let q = q.to_string();
            async move {
                entries(
                    &db,
                    Filter {
                        query: Some(q),
                        limit: 10,
                        ..Default::default()
                    },
                )
                .await
                .unwrap()
            }
        };
        assert_eq!(hit("SHA256:abc").await.len(), 1, "target is searchable");
        assert_eq!(hit("vpn.example.test").await.len(), 1, "detail is searchable");
        // "What else did that address do?" is the question an incident starts with.
        assert_eq!(hit("203.0.113.7").await.len(), 2, "address is searchable");
        assert_eq!(hit("nothing-like-this").await.len(), 0);
    }

    #[tokio::test]
    async fn paging_walks_backwards_without_repeating_a_row() {
        let db = db().await;
        for i in 0..5 {
            event("ssh.key.add", &root()).target(i).record(&db).await;
        }
        let first = entries(
            &db,
            Filter {
                limit: 2,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(first.len(), 2);
        let second = entries(
            &db,
            Filter {
                limit: 2,
                before: Some(first[1].id),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(second.len(), 2);
        assert!(
            second[0].id < first[1].id,
            "a page must not repeat the row it started from"
        );
    }

    #[tokio::test]
    async fn retention_drops_the_old_and_keeps_the_recent() {
        let db = db().await;
        event("ssh.key.add", &root()).target("today").record(&db).await;
        // Backdate one row past a 90-day window.
        db.execute(
            "INSERT INTO audit_log(action, actor, target, ok, at) \
             VALUES ('ssh.key.add', 'root', 'ancient', 1, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-200 days'))",
            (),
        )
        .await
        .unwrap();

        assert_eq!(prune(&db, DEFAULT_RETENTION_DAYS).await.unwrap(), 1);
        let rows = entries(
            &db,
            Filter {
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target.as_deref(), Some("today"));
    }

    #[tokio::test]
    async fn known_actions_come_from_the_data() {
        let db = db().await;
        event("ssh.key.add", &root()).record(&db).await;
        event("ssh.key.add", &root()).record(&db).await;
        event("firewall.apply", &root()).record(&db).await;
        assert_eq!(known_actions(&db).await.unwrap(), vec!["firewall.apply", "ssh.key.add"]);
    }
}
