//! A small 5-field cron scheduler for the pre-defined Spotlight scripts.
//!
//! The same scripts that can be run on demand from the Ctrl+K palette can also
//! carry a `schedule` (standard `min hour dom month dow` cron expression,
//! evaluated in UTC). A background task wakes at the top of every minute and
//! runs any script whose schedule matches — turning the script list into real
//! homelab automation (nightly restic, cert renew, log rotation, …) without a
//! separate cron daemon or a new config concept.
//!
//! The parser supports `*`, single values, comma lists, `a-b` ranges, and
//! `*/step` / `a-b/step` steps. Day-of-month and day-of-week follow the classic
//! Vixie-cron rule: when both are restricted, a match on *either* fires.

use std::time::Duration;

use time::OffsetDateTime;

use crate::config::SpotlightScript;
use crate::AppState;

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
}

// ─── Command execution (shared with the Spotlight HTTP runner) ──────────────

/// How long a scripted command may run before it's killed.
pub const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds the shell command for a scheduled script string.
///
/// Cron scripts are arbitrary operator-authored command lines, so they go
/// through kls-agent's named shell escape hatch (`sh -c` / `cmd /C`, with the
/// standard system `bin` directories appended to `PATH` on Unix) rather than the
/// typed allowlist — the one deliberately-unconstrained execution path, kept
/// visible and admin-only. See [`kls_agent::exec::shell`].
pub fn build_command(command: &str) -> tokio::process::Command {
    kls_agent::exec::shell(command)
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
                match CronSchedule::parse(expr) {
                    Ok(sched) if sched.matches(now) => run_scheduled(script).await,
                    _ => {}
                }
            }
        }
    });
}

/// Runs one scheduled script, logging the outcome via structured tracing.
async fn run_scheduled(script: &SpotlightScript) {
    let mut cmd = build_command(&script.command);
    if let Some(cwd) = &script.cwd {
        cmd.current_dir(cwd);
    }

    let outcome = tokio::time::timeout(SCRIPT_TIMEOUT, cmd.output()).await;
    match outcome {
        Ok(Ok(output)) => {
            let code = output.status.code();
            if output.status.success() {
                tracing::info!(script = %script.name, exit = ?code, "scheduled script ran");
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!(script = %script.name, exit = ?code, stderr = %stderr.trim(), "scheduled script exited non-zero");
            }
            tracing::info!(
                script = %script.name,
                action = "spotlight.script.scheduled",
                exit = ?code,
                success = output.status.success(),
                "scheduled script completed"
            );
        }
        Ok(Err(e)) => tracing::warn!(script = %script.name, error = %e, "scheduled script failed to launch"),
        Err(_) => tracing::warn!(script = %script.name, "scheduled script timed out"),
    }
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
}
