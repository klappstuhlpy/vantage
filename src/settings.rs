//! Runtime-adjustable operational settings — the handful of `config.json`
//! knobs that are safe to change from the dashboard without shell access.
//!
//! ## What lives here, and what deliberately does not
//!
//! Only *operational parameters* are here: retention windows and background-job
//! cadences. Nothing that hands over a capability or a credential is — scripts
//! (arbitrary command execution), the exposure/bind model, alert sink URLs, S3
//! and Cloudflare tokens, and the signing key all stay file-only, on purpose.
//! Those are the root of trust for "who can reach this box and what it can run",
//! and a web request must never be able to rewrite them (see `cron/routes.rs`
//! for the same reasoning applied to scripts). This module is the safe tier and
//! nothing tempts it wider.
//!
//! ## The overlay model (why not move config to the DB)
//!
//! `config.json` stays authoritative: it is read before the DB pool or auth
//! even exist, and it is the operator-owned file. This module is an *overlay* on
//! top of it — a DB row *overrides* the file's value for one whitelisted key,
//! and absence means "use the file". Precedence is always:
//!
//! ```text
//!   DB override  →  config.json  →  built-in default constant
//! ```
//!
//! The live answer is an in-memory [`Overrides`] snapshot (cheap `Copy`), read
//! once at startup ([`load_initial`]) and rewritten on save — the same shape as
//! [`safe_mode`](crate::safemode): the `storage` rows are only its durable
//! shadow, so a background loop reading the value every tick never touches the
//! DB. Each domain module folds the precedence in its own effective-value helper
//! (e.g. [`audit::retention_days`](crate::audit::retention_days)) so the default
//! constant stays where it belongs.

use std::sync::RwLock;

use anyhow::Context;
use axum::{extract::State, http::StatusCode, response::Json, routing::get, Router};
use kls_web_core::Database;

use crate::account::routes::Sudo;
use crate::session::Account;
use crate::{audit, backup, selfupdate, updates, AppState};

/// `storage` keys holding the durable overrides. Absent = no override.
const K_AUDIT_RETENTION: &str = "settings.audit_retention_days";
const K_UPDATE_INTERVAL: &str = "settings.update_check_interval_hours";
const K_BACKUP_INTERVAL: &str = "settings.backup_interval_hours";
const K_BACKUP_KEEP: &str = "settings.backup_keep";

// Bounds that keep a saved value sane — a retention of 0 would prune the whole
// log, a keep of 0 would delete every backup, and an unbounded interval would
// overflow when multiplied out to seconds. These are the guard rails the file
// never had.
const RETENTION_MAX_DAYS: u32 = 3650;
const INTERVAL_MAX_HOURS: u64 = 8760;
const KEEP_MAX: usize = 1000;

/// The live override snapshot. Every field is `Option`: `None` means "defer to
/// `config.json`". `Copy`, so a reader takes a snapshot and drops the lock
/// before it ever awaits.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Overrides {
    pub audit_retention_days: Option<u32>,
    pub update_check_interval_hours: Option<u64>,
    pub backup_interval_hours: Option<u64>,
    pub backup_keep: Option<usize>,
}

/// Holds the live overrides. One instance in [`AppState`]; the `storage` rows
/// are its durable shadow.
pub struct Settings {
    inner: RwLock<Overrides>,
}

impl Settings {
    /// Reads the durable overrides at startup so the live snapshot starts where
    /// the operator left it. A read hiccup on any key resolves that key to "no
    /// override" — the fail-safe direction is to fall back to the file, never to
    /// invent a value.
    pub async fn load_initial(db: &Database) -> Self {
        let inner = Overrides {
            audit_retention_days: read(db, K_AUDIT_RETENTION).await,
            update_check_interval_hours: read(db, K_UPDATE_INTERVAL).await,
            backup_interval_hours: read(db, K_BACKUP_INTERVAL).await,
            backup_keep: read(db, K_BACKUP_KEEP).await,
        };
        Self {
            inner: RwLock::new(inner),
        }
    }

    /// A snapshot of the current overrides. Cheap and lock-free-ish: takes the
    /// read lock, copies, releases — safe to call from a hot background loop.
    pub fn get(&self) -> Overrides {
        *self.inner.read().expect("settings lock poisoned")
    }

    /// Persists a new override set (durable shadow first, then the live
    /// snapshot) so a failed write never leaves the in-memory value lying about
    /// a state that would evaporate on restart.
    async fn apply(&self, db: &Database, new: Overrides) -> anyhow::Result<()> {
        write(db, K_AUDIT_RETENTION, new.audit_retention_days.map(|v| v as i64)).await?;
        write(db, K_UPDATE_INTERVAL, new.update_check_interval_hours.map(|v| v as i64)).await?;
        write(db, K_BACKUP_INTERVAL, new.backup_interval_hours.map(|v| v as i64)).await?;
        write(db, K_BACKUP_KEEP, new.backup_keep.map(|v| v as i64)).await?;
        *self.inner.write().expect("settings lock poisoned") = new;
        Ok(())
    }
}

/// Reads one optional, parsed value from the `storage` KV table.
async fn read<T: std::str::FromStr>(db: &Database, key: &str) -> Option<T> {
    db.get_row("SELECT value FROM storage WHERE name = ?", (key.to_string(),), |row| {
        row.get::<_, String>(0)
    })
    .await
    .ok()
    .and_then(|s| s.parse::<T>().ok())
}

/// Upserts (or, for `None`, deletes) one durable override row.
async fn write(db: &Database, key: &str, val: Option<i64>) -> anyhow::Result<()> {
    match val {
        Some(v) => {
            db.execute(
                "INSERT INTO storage(name, value) VALUES (?, ?) \
                 ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                (key.to_string(), v.to_string()),
            )
            .await
            .with_context(|| format!("could not save setting {key}"))?;
        }
        None => {
            db.execute("DELETE FROM storage WHERE name = ?", (key.to_string(),))
                .await
                .with_context(|| format!("could not clear setting {key}"))?;
        }
    }
    Ok(())
}

// ─── Page ────────────────────────────────────────────────────────────────────

#[derive(askama::Template)]
#[template(path = "settings.html")]
struct SettingsTemplate {
    account: Option<Account>,
    active_page: &'static str,
    /// For each knob: the override as an input string (blank when there is no
    /// override) and the effective default from `config.json`/the built-in
    /// constant (shown as placeholder + hint, and what a cleared field falls
    /// back to).
    audit_retention_days: String,
    audit_retention_default: u32,
    update_interval_hours: String,
    update_interval_default: u64,
    backup_interval_hours: String,
    backup_interval_default: u64,
    /// The self-update card. `update_notes` is the release body as markdown;
    /// Askama escapes it into the page and settings.js renders a safe subset
    /// (escape-first, our tags only) — no server-side parser for one card.
    current_version: &'static str,
    update_available: bool,
    update_version: String,
    update_published: String,
    update_notes: String,
    update_url: String,
    backup_keep: String,
    backup_keep_default: usize,
}

/// An override rendered for an `<input value=…>`: the number, or `""` for "no
/// override, using the default".
fn field<T: ToString>(v: Option<T>) -> String {
    v.map(|n| n.to_string()).unwrap_or_default()
}

async fn page(State(state): State<AppState>, account: Account) -> Result<SettingsTemplate, StatusCode> {
    if !account.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let o = state.settings.get();
    let su = selfupdate::status();
    let latest = su.latest;
    Ok(SettingsTemplate {
        account: Some(account),
        active_page: "settings",
        audit_retention_days: field(o.audit_retention_days),
        audit_retention_default: audit::config_retention_days(&state),
        update_interval_hours: field(o.update_check_interval_hours),
        update_interval_default: updates::config_interval_hours(&state),
        backup_interval_hours: field(o.backup_interval_hours),
        backup_interval_default: backup::config_interval_hours(&state),
        backup_keep: field(o.backup_keep),
        backup_keep_default: backup::config_keep(&state),
        current_version: crate::VERSION,
        update_available: su.state == selfupdate::SelfUpdateState::UpdateAvailable,
        update_version: latest.as_ref().map(|r| r.version.clone()).unwrap_or_default(),
        update_published: latest.as_ref().and_then(|r| r.published_at.clone()).unwrap_or_default(),
        update_notes: latest.as_ref().map(|r| r.notes.clone()).unwrap_or_default(),
        update_url: latest.as_ref().map(|r| r.url.clone()).unwrap_or_default(),
    })
}

// ─── Save ────────────────────────────────────────────────────────────────────

/// The save body. Every field is optional; a `null`/absent field clears that
/// override (reverting the knob to `config.json`). The form always sends all
/// four, so a save is a full replace of the override set.
#[derive(serde::Deserialize)]
struct SaveBody {
    audit_retention_days: Option<u32>,
    update_check_interval_hours: Option<u64>,
    backup_interval_hours: Option<u64>,
    backup_keep: Option<usize>,
}

/// `POST /settings` — save the operational overrides. Sudo-gated and admin-only:
/// these change how long the audit trail lives and how often the box backs
/// itself up, which is exactly what a 12-hour-old session should re-prove for.
async fn save(
    State(state): State<AppState>,
    sudo: Sudo,
    Json(body): Json<SaveBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let account = sudo.account;
    if !account.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Admins only." })),
        ));
    }

    let bad = |msg: &str| (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg })));

    // Range-check before anything is written. A retention or keep of zero is a
    // data-loss foot-gun, not a valid setting, so it is refused rather than
    // silently clamped.
    if let Some(v) = body.audit_retention_days {
        if !(1..=RETENTION_MAX_DAYS).contains(&v) {
            return Err(bad("Audit retention must be between 1 and 3650 days."));
        }
    }
    if let Some(v) = body.update_check_interval_hours {
        if v > INTERVAL_MAX_HOURS {
            return Err(bad(
                "Update-check interval must be 8760 hours or fewer (0 disables it).",
            ));
        }
    }
    if let Some(v) = body.backup_interval_hours {
        if v > INTERVAL_MAX_HOURS {
            return Err(bad("Backup interval must be 8760 hours or fewer (0 disables it)."));
        }
    }
    if let Some(v) = body.backup_keep {
        if !(1..=KEEP_MAX).contains(&v) {
            return Err(bad("Backups to keep must be between 1 and 1000."));
        }
    }

    let new = Overrides {
        audit_retention_days: body.audit_retention_days,
        update_check_interval_hours: body.update_check_interval_hours,
        backup_interval_hours: body.backup_interval_hours,
        backup_keep: body.backup_keep,
    };

    if let Err(e) = state.settings.apply(&state.db, new).await {
        tracing::warn!(error = ?e, "could not save settings");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Could not save settings." })),
        ));
    }

    audit::event("settings.update", &account)
        .detail(serde_json::json!({
            "audit_retention_days": new.audit_retention_days,
            "update_check_interval_hours": new.update_check_interval_hours,
            "backup_interval_hours": new.backup_interval_hours,
            "backup_keep": new.backup_keep,
        }))
        .record(&state.db)
        .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/settings", get(page).post(save))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn state() -> AppState {
        crate::build_state_with(crate::config::Config::test_default(), std::path::Path::new(":memory:"))
            .await
            .expect("build state")
    }

    #[tokio::test]
    async fn overrides_default_to_none() {
        let s = state().await;
        assert_eq!(s.settings.get(), Overrides::default());
    }

    #[tokio::test]
    async fn overrides_round_trip_through_storage() {
        let s = state().await;
        let new = Overrides {
            audit_retention_days: Some(30),
            update_check_interval_hours: Some(0),
            backup_interval_hours: Some(6),
            backup_keep: Some(20),
        };
        s.settings.apply(&s.db, new).await.unwrap();
        assert_eq!(s.settings.get(), new, "live snapshot updates immediately");

        // A fresh store reading the same DB sees the persisted overrides.
        let reloaded = Settings::load_initial(&s.db).await;
        assert_eq!(reloaded.get(), new, "overrides survive a reload");
    }

    #[tokio::test]
    async fn clearing_an_override_deletes_its_row() {
        let s = state().await;
        s.settings
            .apply(
                &s.db,
                Overrides {
                    audit_retention_days: Some(30),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // Clear everything: the row must be gone, not lingering at its old value.
        s.settings.apply(&s.db, Overrides::default()).await.unwrap();
        let reloaded = Settings::load_initial(&s.db).await;
        assert_eq!(reloaded.get(), Overrides::default());
    }
}
