//! Small in-process caching primitives.
//!
//! Only [`TimedCachedValue`] lives here — a single value with a TTL, used by the
//! Docker layer to avoid hammering the socket on every graph request. The site's
//! `platform/cached.rs` also carries a response-body cache; that isn't needed
//! here yet, so this is the minimal, self-contained subset (no crate-internal
//! deps beyond `tokio`).

use std::time::{Duration, Instant};

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// A timed cache value that only lasts for a specified duration before expiring.
#[derive(Debug)]
pub struct TimedCachedValue<T> {
    value: RwLock<Option<(T, Instant)>>,
    ttl: Duration,
}

impl<T> TimedCachedValue<T> {
    pub fn new(ttl: Duration) -> Self {
        Self {
            value: RwLock::new(None),
            ttl,
        }
    }

    /// Returns the cached value, or [`None`] if it cannot be found or is expired.
    pub async fn get(&self) -> Option<RwLockReadGuard<'_, T>> {
        let guard = self.value.read().await;
        RwLockReadGuard::try_map(guard, |f| {
            if let Some((value, exp)) = f {
                if exp.elapsed() >= self.ttl {
                    None
                } else {
                    Some(value)
                }
            } else {
                None
            }
        })
        .ok()
    }

    /// Sets the value in the cache and returns a read guard to the value.
    pub async fn set(&self, value: T) -> RwLockReadGuard<'_, T> {
        let mut guard = self.value.write().await;
        *guard = Some((value, Instant::now()));
        RwLockWriteGuard::downgrade_map(guard, |f| &f.as_ref().unwrap().0)
    }

    /// Invalidates the cache.
    pub async fn invalidate(&self) {
        let mut guard = self.value.write().await;
        *guard = None;
    }
}
