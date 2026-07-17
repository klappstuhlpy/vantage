//! Armed, self-reverting applies (FRONTEND_MIGRATION_PLAN §11.1).
//!
//! The most dangerous thing Vantage does is change the packet filter or the
//! reverse proxy on the box it is served through: a bad rule can cut off the very
//! connection the operator is holding, and then they cannot undo it — they are
//! locked out of the machine they just locked themselves out of.
//!
//! A revert timer closes that trap. An *arming* apply does the change and then
//! parks a rollback here with a deadline. If a second request confirms inside the
//! window, the change stays. If nothing confirms — because the operator lost
//! access, or walked away — a background task rolls it back. A ruleset that cuts
//! you off reverts itself.
//!
//! This module is only the timing and the bookkeeping; it knows nothing about
//! firewalls or proxies. The *rollback* is a closure the caller hands over
//! ([`RevertFn`]), which captures whatever it needs and does its own auditing.
//! That keeps the dangerous, host-specific logic in the slice that owns it.
//!
//! ## The one race that matters
//!
//! The timer firing and a confirm arriving at the same instant must not both act.
//! The registry mutex is the arbiter: whoever removes the domain's entry first
//! wins, and the loser sees it gone and does nothing. The timer *claims* the
//! entry (removes it) before it reverts; confirm removes it before it returns
//! success. There is no window where a change is both kept and reverted.
//!
//! ## Not durable, on purpose
//!
//! The registry is in memory. If the Vantage process dies mid-window the change
//! simply stays — there is no persisted rollback to replay against a host whose
//! state we can no longer be sure of. That is the safe failure: a surprise
//! rollback on restart, against a firewall an admin may have since fixed by hand,
//! is more dangerous than an un-reverted change the dashboard still shows as
//! pending.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use argon2::password_hash::rand_core::{OsRng, RngCore};
use time::OffsetDateTime;

/// The rollback the timer (or a manual "revert now") runs. Boxed so different
/// slices can hand over different concrete futures through one type.
pub type RevertFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A cloneable factory for the rollback future. Cloneable because two callers can
/// need it — the timer task and a manual revert-now — and only one will run it.
pub type RevertFn = Arc<dyn Fn() -> RevertFuture + Send + Sync>;

/// One armed, not-yet-confirmed apply.
struct Armed {
    token: String,
    abort: tokio::task::AbortHandle,
    revert: RevertFn,
}

/// The set of in-flight reverts, at most one per domain (`"firewall"`,
/// `"proxy"`). Keyed by domain so a fresh apply naturally supersedes an
/// unconfirmed older one for the same slice rather than stacking.
#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<Mutex<HashMap<&'static str, Armed>>>,
}

/// What an arming apply hands back to the client so it can run the countdown and
/// send the confirm.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ArmResult {
    pub token: String,
    pub revert_secs: u64,
    pub expires_unix: i64,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Arms a revert for `domain`, superseding any unconfirmed one already there
    /// (the older change is *kept* — a new apply is the operator's newer intent).
    ///
    /// Returns the token the client must confirm with and when the window closes.
    pub fn arm(&self, domain: &'static str, window: Duration, revert: RevertFn) -> ArmResult {
        let token = new_token();
        let deadline = OffsetDateTime::now_utc() + window;
        let deadline_unix = deadline.unix_timestamp();

        // The timer. It claims the entry before reverting, so a confirm that
        // already removed it makes this a no-op — the race resolved by the lock.
        let inner = self.inner.clone();
        let revert_for_timer = revert.clone();
        let token_for_timer = token.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(window).await;
            let claimed = {
                let mut guard = inner.lock().unwrap();
                match guard.get(domain) {
                    Some(a) if a.token == token_for_timer => guard.remove(domain).is_some(),
                    _ => false,
                }
            };
            if claimed {
                tracing::warn!(domain, "revert timer elapsed — rolling back an unconfirmed apply");
                revert_for_timer().await;
            }
        })
        .abort_handle();

        let mut guard = self.inner.lock().unwrap();
        if let Some(old) = guard.remove(domain) {
            // Cancel the superseded timer; its change stays (the new apply is
            // built on top of it).
            old.abort.abort();
        }
        guard.insert(
            domain,
            Armed {
                token: token.clone(),
                abort: handle,
                revert,
            },
        );

        ArmResult {
            token,
            revert_secs: window.as_secs(),
            expires_unix: deadline_unix,
        }
    }

    /// Confirms an armed apply: cancels the timer and keeps the change. `true` if
    /// the token matched a live entry; `false` if it had already fired or been
    /// superseded — in which case there is nothing to keep, and the caller says so.
    pub fn confirm(&self, domain: &'static str, token: &str) -> bool {
        let mut guard = self.inner.lock().unwrap();
        match guard.get(domain) {
            Some(a) if a.token == token => {
                let armed = guard.remove(domain).unwrap();
                armed.abort.abort();
                true
            }
            _ => false,
        }
    }

    /// Claims an armed apply for an immediate rollback, returning its [`RevertFn`]
    /// for the caller to await. The rollback is not run here — it cannot be, the
    /// registry lock is held and rollbacks are async — so the caller does
    /// `if let Some(f) = registry.take_for_revert(..) { f().await }`.
    pub fn take_for_revert(&self, domain: &'static str, token: &str) -> Option<RevertFn> {
        let mut guard = self.inner.lock().unwrap();
        match guard.get(domain) {
            Some(a) if a.token == token => {
                let armed = guard.remove(domain).unwrap();
                armed.abort.abort();
                Some(armed.revert)
            }
            _ => None,
        }
    }
}

/// A 128-bit hex token from the OS RNG — unguessable, so a stale tab cannot
/// confirm or revert an apply it never saw.
fn new_token() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A revert closure that bumps a shared counter, so a test can see whether it
    /// ran.
    fn counting_revert(counter: &Arc<AtomicUsize>) -> RevertFn {
        let counter = counter.clone();
        Arc::new(move || {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
            })
        })
    }

    #[tokio::test]
    async fn a_confirmed_apply_never_reverts() {
        let reg = Registry::new();
        let ran = Arc::new(AtomicUsize::new(0));
        let armed = reg.arm("firewall", Duration::from_millis(80), counting_revert(&ran));

        assert!(reg.confirm("firewall", &armed.token), "the live token confirms");
        // Wait past the window; the timer must have been cancelled.
        tokio::time::sleep(Duration::from_millis(160)).await;
        assert_eq!(ran.load(Ordering::SeqCst), 0, "a confirmed apply must not roll back");
    }

    #[tokio::test]
    async fn an_unconfirmed_apply_reverts_itself() {
        let reg = Registry::new();
        let ran = Arc::new(AtomicUsize::new(0));
        reg.arm("firewall", Duration::from_millis(40), counting_revert(&ran));

        tokio::time::sleep(Duration::from_millis(140)).await;
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "the window closed unconfirmed — it must revert"
        );
        // …and the entry is gone, so a late confirm finds nothing.
        assert!(!reg.confirm("firewall", "whatever"));
    }

    #[tokio::test]
    async fn a_stale_token_neither_confirms_nor_reverts() {
        let reg = Registry::new();
        let ran = Arc::new(AtomicUsize::new(0));
        let armed = reg.arm("proxy", Duration::from_millis(200), counting_revert(&ran));

        assert!(!reg.confirm("proxy", "not-the-token"), "a wrong token confirms nothing");
        assert!(reg.take_for_revert("proxy", "not-the-token").is_none());
        // The real token still works.
        assert!(reg.confirm("proxy", &armed.token));
    }

    #[tokio::test]
    async fn revert_now_runs_the_rollback_and_disarms_the_timer() {
        let reg = Registry::new();
        let ran = Arc::new(AtomicUsize::new(0));
        let armed = reg.arm("proxy", Duration::from_millis(120), counting_revert(&ran));

        let f = reg
            .take_for_revert("proxy", &armed.token)
            .expect("the live token claims it");
        f().await;
        assert_eq!(ran.load(Ordering::SeqCst), 1, "revert-now ran the rollback once");

        // The timer was disarmed, so it must not run it a second time.
        tokio::time::sleep(Duration::from_millis(180)).await;
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "the superseded timer must not double-revert"
        );
    }

    #[tokio::test]
    async fn a_new_apply_supersedes_the_previous_unconfirmed_one() {
        let reg = Registry::new();
        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));

        let a = reg.arm("firewall", Duration::from_millis(60), counting_revert(&first));
        let b = reg.arm("firewall", Duration::from_millis(60), counting_revert(&second));
        assert_ne!(a.token, b.token);

        // The first timer was cancelled (its change kept); confirming the second
        // keeps it too. Neither rolls back.
        assert!(
            !reg.confirm("firewall", &a.token),
            "the superseded token is no longer live"
        );
        assert!(reg.confirm("firewall", &b.token));
        tokio::time::sleep(Duration::from_millis(140)).await;
        assert_eq!(first.load(Ordering::SeqCst), 0, "a superseded apply must not revert");
        assert_eq!(second.load(Ordering::SeqCst), 0);
    }
}
