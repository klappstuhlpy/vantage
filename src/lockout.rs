//! In-process login lockout for Vantage — a decaying per-IP counter.
//!
//! After [`THRESHOLD`] failed credential attempts from one IP within [`WINDOW`],
//! further attempts from that IP are refused until the window elapses. Because
//! Vantage is a remote-root surface (§7.1), the threshold is tighter than the
//! site's soft-lockout and it applies in *every* exposure mode, not just public.
//!
//! Held in process memory (bounded, LRU-evicted); state is lost on restart,
//! which is fine for a short-window throttle. A *firewall-level* ban driven by
//! these events is a later, additive capability (§8-B) — this app-layer throttle
//! does not depend on it.

use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use quick_cache::sync::Cache;

/// Failed attempts from one IP within [`WINDOW`] that trip the lockout.
pub const THRESHOLD: u32 = 5;
/// Sliding window over which failures accumulate. Once the threshold is reached
/// the IP stays locked until `WINDOW` has passed since its *first* failure.
pub const WINDOW: Duration = Duration::from_secs(900);
/// Maximum distinct IPs tracked at once (bounds memory; LRU-evicted).
const CAPACITY: usize = 10_000;

#[derive(Clone, Copy)]
struct AttemptWindow {
    count: u32,
    /// When the current window started (the first failure in it).
    started: Instant,
}

fn table() -> &'static Cache<IpAddr, AttemptWindow> {
    static TABLE: OnceLock<Cache<IpAddr, AttemptWindow>> = OnceLock::new();
    TABLE.get_or_init(|| Cache::new(CAPACITY))
}

/// Record one failed authentication attempt from `ip`. Called only on genuine
/// credential failures (bad password / bad 2FA code), never on validation
/// refusals.
pub fn register_failure(ip: IpAddr) {
    let now = Instant::now();
    let next = match table().get(&ip) {
        Some(w) if now.duration_since(w.started) < WINDOW => AttemptWindow {
            count: w.count.saturating_add(1),
            started: w.started,
        },
        _ => AttemptWindow { count: 1, started: now },
    };
    table().insert(ip, next);
}

/// Clears an IP's failure counter — called on a successful login so a user who
/// eventually authenticates is not left throttled by their earlier typos.
pub fn clear(ip: IpAddr) {
    table().remove(&ip);
}

/// True when `ip` is currently locked out: at or over [`THRESHOLD`] within a
/// still-live [`WINDOW`].
pub fn is_locked(ip: IpAddr) -> bool {
    match table().get(&ip) {
        Some(w) => Instant::now().duration_since(w.started) < WINDOW && w.count >= THRESHOLD,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, n))
    }

    #[test]
    fn locks_only_after_threshold_then_clears() {
        let addr = ip(1);
        for _ in 0..THRESHOLD - 1 {
            register_failure(addr);
        }
        assert!(!is_locked(addr), "below threshold must not lock");
        register_failure(addr);
        assert!(is_locked(addr), "reaching threshold must lock");
        clear(addr);
        assert!(!is_locked(addr), "clear() must reset the counter");
    }

    #[test]
    fn distinct_ips_are_independent() {
        let a = ip(2);
        let b = ip(3);
        for _ in 0..THRESHOLD {
            register_failure(a);
        }
        assert!(is_locked(a));
        assert!(!is_locked(b), "one IP's failures must not lock another");
    }
}
