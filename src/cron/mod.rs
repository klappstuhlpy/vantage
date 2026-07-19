//! Operator scripts: a small 5-field cron scheduler, an on-demand runner, and
//! the history of both.
//!
//! Scripts are declared in `config.json` under `spotlight_scripts`. Each can
//! carry a `schedule` (standard `min hour dom month dow` cron expression,
//! evaluated in UTC); a background task wakes at the top of every minute and
//! runs any script whose schedule matches — turning the script list into real
//! homelab automation (nightly restic, cert renew, log rotation, …) without a
//! separate cron daemon or a new config concept. Every script, scheduled or not,
//! can also be run on demand from the Scripts page.
//!
//! The parser supports `*`, single values, comma lists, `a-b` ranges, and
//! `*/step` / `a-b/step` steps. Day-of-month and day-of-week follow the classic
//! Vixie-cron rule: when both are restricted, a match on *either* fires.
//!
//! ## Why runs are recorded
//!
//! A scheduled script used to leave nothing behind but a `tracing` line, which
//! made the only question anyone asks about automation — *did last night's run
//! work?* — answerable only by someone who still had the logs and knew to grep
//! them. Both paths now go through [`run_script`], which captures the exit code
//! and a bounded tail of the output into `script_run`.
//!
//! ## The trust boundary
//!
//! A script is an arbitrary operator-authored command line executed as the
//! Vantage user. Vantage does not let the web UI *write* one — the list is
//! config-file-only, exactly like alert sinks — because an endpoint that could
//! add a script would be a remote shell with extra steps. The UI runs what is
//! already there, and nothing else.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use time::OffsetDateTime;

use kls_web_core::Database;

use crate::config::SpotlightScript;
use crate::AppState;

pub mod routes;

/// One parsed cron field, expanded into the concrete set of values it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Field {
    /// `true` when the field was `*` (matches anything within range).
    star: bool,
    /// Sorted, de-duplicated set of matching values.
    values: Vec<u8>,
}

impl Field {
    fn matches(&self, value: u8) -> bool {
        self.star || self.values.binary_search(&value).is_ok()
    }
}

/// Parses a single cron field given the inclusive `[min, max]` range it lives
/// in (e.g. minutes are 0–59). Returns `Err` with a human-readable reason on
/// malformed input.
fn parse_field(spec: &str, min: u8, max: u8) -> Result<Field, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("empty field".to_string());
    }
    let mut values: Vec<u8> = Vec::new();
    let mut star = false;

    for part in spec.split(',') {
        let part = part.trim();
        // Split off an optional `/step`.
        let (range_part, step) = match part.split_once('/') {
            Some((r, s)) => {
                let step: u8 = s.parse().map_err(|_| format!("invalid step `{s}`"))?;
                if step == 0 {
                    return Err("step cannot be zero".to_string());
                }
                (r, step)
            }
            None => (part, 1),
        };

        let (lo, hi) = if range_part == "*" {
            if step == 1 {
                star = true;
            }
            (min, max)
        } else if let Some((a, b)) = range_part.split_once('-') {
            let a: u8 = a.parse().map_err(|_| format!("invalid range start `{a}`"))?;
            let b: u8 = b.parse().map_err(|_| format!("invalid range end `{b}`"))?;
            (a, b)
        } else {
            let v: u8 = range_part
                .parse()
                .map_err(|_| format!("invalid value `{range_part}`"))?;
            (v, v)
        };

        if lo < min || hi > max || lo > hi {
            return Err(format!("value out of range {min}-{max}: `{part}`"));
        }
        let mut v = lo;
        while v <= hi {
            values.push(v);
            v += step;
        }
    }

    values.sort_unstable();
    values.dedup();
    Ok(Field { star, values })
}

/// A parsed 5-field cron schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronSchedule {
    minute: Field,
    hour: Field,
    dom: Field,
    month: Field,
    dow: Field,
}

impl CronSchedule {
    /// Parses a standard 5-field cron expression (`min hour dom month dow`).
    pub fn parse(expr: &str) -> Result<Self, String> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(format!("expected 5 fields, got {}", fields.len()));
        }
        Ok(Self {
            minute: parse_field(fields[0], 0, 59)?,
            hour: parse_field(fields[1], 0, 23)?,
            dom: parse_field(fields[2], 1, 31)?,
            // Day-of-week uses 0-7 (0 and 7 both = Sunday); normalise 7 → 0.
            month: parse_field(fields[3], 1, 12)?,
            dow: {
                let mut f = parse_field(fields[4], 0, 7)?;
                if f.values.contains(&7) {
                    f.values.retain(|&v| v != 7);
                    if !f.values.contains(&0) {
                        f.values.push(0);
                    }
                    f.values.sort_unstable();
                }
                f
            },
        })
    }

    /// Returns `true` when `dt` (interpreted in UTC) falls on this schedule.
    pub fn matches(&self, dt: OffsetDateTime) -> bool {
        let minute = dt.minute();
        let hour = dt.hour();
        let dom = dt.day();
        let month: u8 = dt.month() as u8;
        // time's Sunday-based index matches cron's 0=Sunday convention.
        let dow = dt.weekday().number_days_from_sunday();

        if !self.minute.matches(minute) || !self.hour.matches(hour) || !self.month.matches(month) {
            return false;
        }

        // Classic cron day rule: if both DOM and DOW are restricted, either may
        // match; if only one is restricted, it alone gates; if neither, both
        // are `*` and pass.
        match (self.dom.star, self.dow.star) {
            (true, true) => true,
            (false, true) => self.dom.matches(dom),
            (true, false) => self.dow.matches(dow),
            (false, false) => self.dom.matches(dom) || self.dow.matches(dow),
        }
    }

    /// The first minute strictly after `after` that this schedule fires on.
    ///
    /// Brute-forced a minute at a time rather than solved field by field: the
    /// search is bounded at a year (~527k cheap checks, microseconds), it runs
    /// once per scheduled script per page load, and the field-wise version has
    /// to get the DOM/DOW `or` rule and month lengths right to be worth its own
    /// bugs. Returns `None` for a schedule that cannot fire within a year, which
    /// in practice means an impossible date like `0 0 30 2 *` — and telling the
    /// operator "never" is exactly the useful answer there.
    pub fn next_after(&self, after: OffsetDateTime) -> Option<OffsetDateTime> {
        let start = after.replace_second(0).ok()?.replace_nanosecond(0).ok()?;
        let horizon = start + time::Duration::days(366);
        let mut t = start + time::Duration::minutes(1);
        while t <= horizon {
            if self.matches(t) {
                return Some(t);
            }
            t += time::Duration::minutes(1);
        }
        None
    }
}

// ─── Command execution ──────────────────────────────────────────────────────

/// How long a scripted command may run before it's killed.
pub const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

/// How much captured output is kept per run.
///
/// The **tail** is kept rather than the head: when a script fails, the reason is
/// almost always the last thing it said.
const OUTPUT_LIMIT: usize = 16 * 1024;

/// Builds the shell command for a script string.
///
/// Cron scripts are arbitrary operator-authored command lines, so they go
/// through kls-agent's named shell escape hatch (`sh -c` / `cmd /C`, with the
/// standard system `bin` directories appended to `PATH` on Unix) rather than the
/// typed allowlist — the one deliberately-unconstrained execution path, kept
/// visible and admin-only. See [`kls_agent::exec::shell`].
pub fn build_command(command: &str) -> tokio::process::Command {
    let mut cmd = kls_agent::exec::shell(command);
    // Without this, hitting SCRIPT_TIMEOUT only abandons *our* side: the future
    // is dropped, we log "timed out", and the child keeps running on the host
    // forever with nothing left holding a handle to it. A timeout that leaks the
    // process it was meant to bound is not a timeout.
    cmd.kill_on_drop(true);
    cmd
}

/// Trims captured output to [`OUTPUT_LIMIT`], keeping the end.
fn tail(text: &str) -> String {
    if text.len() <= OUTPUT_LIMIT {
        return text.to_string();
    }
    // Cut on a char boundary, then forward to the next line break so the first
    // visible line is a whole line rather than the back half of one.
    let mut start = text.len() - OUTPUT_LIMIT;
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    let rest = &text[start..];
    let rest = rest.find('\n').map_or(rest, |i| &rest[i + 1..]);
    format!(
        "[… earlier output dropped — showing the last {} KB]\n{rest}",
        OUTPUT_LIMIT / 1024
    )
}

/// What one run of a script did.
pub struct RunOutcome {
    pub ok: bool,
    /// `None` when the process was killed (timeout) or never launched.
    pub exit_code: Option<i32>,
    /// Captured stdout, then stderr — tail-truncated. Empty when the script was
    /// silent, which is the normal case for a script that worked.
    pub output: String,
    pub duration_ms: i64,
}

/// Scripts currently executing, by config id.
///
/// A nightly restic run and an operator pressing Run at the wrong moment are two
/// resticks over one repository. Refusing the second is cheaper than explaining
/// the lock file it leaves behind.
fn running() -> &'static Mutex<HashSet<String>> {
    static RUNNING: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    RUNNING.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Claims the run slot for `id`, releasing it on drop.
struct RunSlot(String);

impl RunSlot {
    fn claim(id: &str) -> Option<Self> {
        let mut set = running().lock().unwrap_or_else(|e| e.into_inner());
        set.insert(id.to_string()).then(|| Self(id.to_string()))
    }
}

impl Drop for RunSlot {
    fn drop(&mut self) {
        running().lock().unwrap_or_else(|e| e.into_inner()).remove(&self.0);
    }
}

/// Whether a script is executing right now.
pub fn is_running(id: &str) -> bool {
    running().lock().unwrap_or_else(|e| e.into_inner()).contains(id)
}

/// Runs one script to completion and records the result.
///
/// Shared by the scheduler and the Run button, so a scheduled run and a manual
/// one are the same event with a different `trigger` — there is no second code
/// path that could drift, and the history shows both.
///
/// `actor` is the account that pressed Run, or `None` for the scheduler — which
/// is also what tells the audit event whether there is an address behind it.
///
/// Returns `None` when the script is already running.
pub async fn run_script(
    state: &AppState,
    script: &SpotlightScript,
    trigger: &'static str,
    actor: Option<&crate::session::Account>,
) -> Option<RunOutcome> {
    let _slot = RunSlot::claim(&script.id)?;

    let mut cmd = build_command(&script.command);
    if let Some(cwd) = &script.cwd {
        cmd.current_dir(cwd);
    }

    let started = std::time::Instant::now();
    let result = tokio::time::timeout(SCRIPT_TIMEOUT, cmd.output()).await;
    let duration_ms = started.elapsed().as_millis() as i64;

    let outcome = match result {
        Ok(Ok(output)) => {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.trim().is_empty() {
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str(&stderr);
            }
            RunOutcome {
                ok: output.status.success(),
                exit_code: output.status.code(),
                output: tail(text.trim_end()),
                duration_ms,
            }
        }
        // Failed to launch: the message ("No such file or directory") is the
        // whole diagnosis, so it goes where the operator will look — the output.
        Ok(Err(e)) => RunOutcome {
            ok: false,
            exit_code: None,
            output: format!("could not start the command: {e}"),
            duration_ms,
        },
        Err(_) => RunOutcome {
            ok: false,
            exit_code: None,
            output: format!("timed out after {}s and was killed", SCRIPT_TIMEOUT.as_secs()),
            duration_ms,
        },
    };

    // Audited from the runner rather than the route, so a *scheduled* run is in
    // the audit log too. An audit trail that only knows about the actions someone
    // clicked would answer "what ran on this host?" with half the truth.
    let event = match actor {
        Some(account) => crate::audit::event("script.run", account),
        None => crate::audit::system_event("script.run", "scheduler"),
    };
    event
        .target(&script.id)
        .detail(serde_json::json!({
            "trigger": trigger,
            "exit_code": outcome.exit_code,
            "duration_ms": duration_ms,
        }))
        .ok(outcome.ok)
        .record(&state.db)
        .await;

    record_run(&state.db, script, trigger, actor.map(|a| a.name.as_str()), &outcome).await;
    Some(outcome)
}

// ─── History ────────────────────────────────────────────────────────────────

/// How many runs are kept across all scripts.
const RUNS_RETAINED: i64 = 200;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScriptRun {
    pub id: i64,
    pub script_id: String,
    pub script_name: String,
    pub trigger: String,
    pub actor: Option<String>,
    pub ok: bool,
    pub exit_code: Option<i32>,
    pub output: Option<String>,
    pub duration_ms: i64,
    pub started_at: String,
}

/// Records one run and prunes the history to its bound.
///
/// Best-effort: a script that ran is a script that ran, and failing the request
/// because the bookkeeping failed would report a problem the operator does not
/// have.
async fn record_run(db: &Database, script: &SpotlightScript, trigger: &str, actor: Option<&str>, outcome: &RunOutcome) {
    let inserted = db
        .execute(
            "INSERT INTO script_run(script_id, script_name, trigger, actor, ok, exit_code, output, duration_ms) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                script.id.clone(),
                script.name.clone(),
                trigger.to_string(),
                actor.map(str::to_string),
                outcome.ok as i64,
                outcome.exit_code,
                (!outcome.output.is_empty()).then(|| outcome.output.clone()),
                outcome.duration_ms,
            ),
        )
        .await;
    if inserted.is_err() {
        tracing::warn!(script = %script.id, "could not record the script run");
        return;
    }
    // Pruned on the write path, where the table grows — no scheduler to forget.
    let _ = db
        .execute(
            "DELETE FROM script_run WHERE id <= (SELECT MAX(id) FROM script_run) - ?",
            (RUNS_RETAINED,),
        )
        .await;
}

/// The most recent runs, newest first. `script` narrows to one script's history.
pub async fn recent_runs(db: &Database, script: Option<String>, limit: i64) -> anyhow::Result<Vec<ScriptRun>> {
    use anyhow::Context;
    db.call(move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT id, script_id, script_name, trigger, actor, ok, exit_code, output, duration_ms, started_at \
             FROM script_run WHERE (?1 IS NULL OR script_id = ?1) ORDER BY id DESC LIMIT ?2",
        )?;
        let rows: rusqlite::Result<Vec<ScriptRun>> = stmt
            .query_map((script, limit), |row| {
                Ok(ScriptRun {
                    id: row.get(0)?,
                    script_id: row.get(1)?,
                    script_name: row.get(2)?,
                    trigger: row.get(3)?,
                    actor: row.get(4)?,
                    ok: row.get::<_, i64>(5)? != 0,
                    exit_code: row.get(6)?,
                    output: row.get(7)?,
                    duration_ms: row.get(8)?,
                    started_at: row.get(9)?,
                })
            })?
            .collect();
        rows
    })
    .await
    .context("could not read the run history")
}

// ─── Background scheduler ───────────────────────────────────────────────────

/// Spawns the cron scheduler. No-op when no script carries a `schedule`.
/// Wakes at the top of each minute and runs every script whose schedule
/// matches the current UTC minute.
pub fn spawn_scheduler(state: AppState) {
    let scheduled = state
        .config
        .spotlight_scripts
        .iter()
        .filter(|s| s.schedule.is_some())
        .count();
    if scheduled == 0 {
        return;
    }

    // Validate schedules once at start-up so typos surface in the log rather
    // than silently never firing.
    for script in &state.config.spotlight_scripts {
        if let Some(expr) = &script.schedule {
            if let Err(e) = CronSchedule::parse(expr) {
                tracing::warn!(script = %script.name, schedule = %expr, error = %e, "invalid cron schedule — script will not run");
            }
        }
    }
    tracing::info!(count = scheduled, "spotlight script scheduler started");

    tokio::spawn(async move {
        loop {
            // Sleep until the next minute boundary so each minute is evaluated
            // exactly once.
            let now = OffsetDateTime::now_utc();
            let wait = 60 - now.second() as u64;
            tokio::time::sleep(Duration::from_secs(wait.max(1))).await;

            let now = OffsetDateTime::now_utc();
            for script in &state.config.spotlight_scripts {
                let Some(expr) = &script.schedule else { continue };
                // An unparseable expression was already reported at startup (the
                // loop above); here it just means "never due".
                let Ok(sched) = CronSchedule::parse(expr) else { continue };
                if !sched.matches(now) {
                    continue;
                }
                if run_script(&state, script, "schedule", None).await.is_none() {
                    // The previous run of this script is still going. A schedule
                    // tighter than the script is long is an operator error, but
                    // the fix is to say so, not to pile a second copy on top of
                    // the first.
                    tracing::warn!(script = %script.name, "skipped — the previous run is still going");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn parses_and_matches_every_minute() {
        let s = CronSchedule::parse("* * * * *").unwrap();
        assert!(s.matches(datetime!(2026-05-31 12:34:00 UTC)));
    }

    #[test]
    fn matches_specific_minute_and_hour() {
        let s = CronSchedule::parse("30 3 * * *").unwrap();
        assert!(s.matches(datetime!(2026-05-31 03:30:00 UTC)));
        assert!(!s.matches(datetime!(2026-05-31 03:31:00 UTC)));
        assert!(!s.matches(datetime!(2026-05-31 04:30:00 UTC)));
    }

    #[test]
    fn step_and_list_and_range() {
        let s = CronSchedule::parse("*/15 0-6 * * *").unwrap();
        assert!(s.matches(datetime!(2026-05-31 00:00:00 UTC)));
        assert!(s.matches(datetime!(2026-05-31 06:45:00 UTC)));
        assert!(!s.matches(datetime!(2026-05-31 07:00:00 UTC)));
        assert!(!s.matches(datetime!(2026-05-31 00:10:00 UTC)));
    }

    #[test]
    fn day_of_week_sunday_is_zero_or_seven() {
        // 2026-05-31 is a Sunday.
        let zero = CronSchedule::parse("0 0 * * 0").unwrap();
        let seven = CronSchedule::parse("0 0 * * 7").unwrap();
        assert!(zero.matches(datetime!(2026-05-31 00:00:00 UTC)));
        assert!(seven.matches(datetime!(2026-05-31 00:00:00 UTC)));
        // Monday should not match.
        assert!(!zero.matches(datetime!(2026-06-01 00:00:00 UTC)));
    }

    #[test]
    fn dom_dow_or_semantics_when_both_restricted() {
        // Fires on the 1st of the month OR on any Monday.
        let s = CronSchedule::parse("0 0 1 * 1").unwrap();
        // 2026-06-01 is a Monday → matches both.
        assert!(s.matches(datetime!(2026-06-01 00:00:00 UTC)));
        // 2026-05-04 is a Monday, not the 1st → still matches (DOW).
        assert!(s.matches(datetime!(2026-05-04 00:00:00 UTC)));
        // 2026-07-01 is a Wednesday → matches (DOM).
        assert!(s.matches(datetime!(2026-07-01 00:00:00 UTC)));
        // 2026-05-05 is a Tuesday, not the 1st → no match.
        assert!(!s.matches(datetime!(2026-05-05 00:00:00 UTC)));
    }

    #[test]
    fn rejects_malformed() {
        assert!(CronSchedule::parse("* * * *").is_err()); // 4 fields
        assert!(CronSchedule::parse("60 * * * *").is_err()); // minute out of range
        assert!(CronSchedule::parse("*/0 * * * *").is_err()); // zero step
        assert!(CronSchedule::parse("abc * * * *").is_err());
    }

    #[test]
    fn next_after_finds_the_following_fire_time() {
        let s = CronSchedule::parse("30 3 * * *").unwrap();
        // Later the same day.
        assert_eq!(
            s.next_after(datetime!(2026-05-31 01:00:00 UTC)),
            Some(datetime!(2026-05-31 03:30:00 UTC))
        );
        // Already past today → tomorrow.
        assert_eq!(
            s.next_after(datetime!(2026-05-31 03:30:00 UTC)),
            Some(datetime!(2026-06-01 03:30:00 UTC))
        );
        // Strictly after: standing exactly on a fire time must not return it,
        // or the scheduler's own minute would read as its next run.
        assert_ne!(
            s.next_after(datetime!(2026-05-31 03:30:00 UTC)),
            Some(datetime!(2026-05-31 03:30:00 UTC))
        );
    }

    #[test]
    fn next_after_crosses_a_year_boundary_and_gives_up_on_the_impossible() {
        let newyear = CronSchedule::parse("0 0 1 1 *").unwrap();
        assert_eq!(
            newyear.next_after(datetime!(2026-12-31 23:00:00 UTC)),
            Some(datetime!(2027-01-01 00:00:00 UTC))
        );
        // February 30th never comes.
        let never = CronSchedule::parse("0 0 30 2 *").unwrap();
        assert_eq!(never.next_after(datetime!(2026-05-31 00:00:00 UTC)), None);
    }

    #[test]
    fn tail_keeps_the_end_and_whole_lines() {
        let short = "all done\n";
        assert_eq!(tail(short), short);

        let long = "x".repeat(OUTPUT_LIMIT) + "\nthe error is here";
        let cut = tail(&long);
        assert!(cut.len() < long.len());
        // The end — where a failing script says why — survives.
        assert!(cut.ends_with("the error is here"));
        assert!(cut.starts_with("[… earlier output dropped"));
        // No half-line left over from the cut.
        assert!(!cut.contains("xxxx"));
    }

    #[test]
    fn tail_cuts_on_a_char_boundary() {
        // A multi-byte run means the naive `len - LIMIT` index lands mid-char;
        // slicing there would panic rather than truncate.
        let long = "é".repeat(OUTPUT_LIMIT);
        let cut = tail(&long);
        assert!(cut.len() <= long.len());
    }

    #[test]
    fn a_script_can_only_run_once_at_a_time() {
        let first = RunSlot::claim("nightly-restic").expect("the slot is free");
        assert!(is_running("nightly-restic"));
        // The scheduler firing while a manual run is in flight must not start a
        // second copy over the same repository.
        assert!(RunSlot::claim("nightly-restic").is_none());
        // A different script is unaffected.
        let other = RunSlot::claim("rotate-logs").expect("a different script is free");
        drop(first);
        assert!(!is_running("nightly-restic"));
        assert!(RunSlot::claim("nightly-restic").is_some());
        drop(other);
    }
}
