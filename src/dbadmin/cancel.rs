//! In-flight query cancellation registry (DB Studio D12).
//!
//! The client generates a `run_id` (UUID) per query and passes it alongside the
//! SQL. Before execution begins, the backend registers a cancel handle keyed by
//! that id. `POST /database/query/cancel` looks the handle up, verifies ownership
//! (account A cannot cancel account B's query), and fires it.
//!
//! The handle lives only as long as the query is executing — it is removed on
//! completion (success or error), so a cancel of an already-finished query is a
//! no-op reported as such. The registry is in-memory and intentionally not
//! durable: a process restart simply drops all running queries (the connections
//! close, the queries stop).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A handle that can cancel an in-flight query. Thread-safe.
pub enum CancelHandle {
    /// SQLite: `rusqlite::InterruptHandle` calls `sqlite3_interrupt` on the
    /// connection, causing the active query to return `SQLITE_INTERRUPT`.
    Sqlite(Arc<rusqlite::InterruptHandle>),
    /// Postgres: `tokio_postgres::CancelToken` sends an out-of-band cancel
    /// request to the server.
    Postgres(tokio_postgres::CancelToken),
}

struct RunEntry {
    account_id: i64,
    handle: CancelHandle,
}

/// Global registry of in-flight console queries, keyed by client-generated
/// run_id. A thin wrapper around a mutex-guarded map — designed to be cheap and
/// correct, not clever.
#[derive(Clone, Default)]
pub struct RunRegistry {
    inner: Arc<Mutex<HashMap<String, RunEntry>>>,
}

impl RunRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a run just before execution begins.
    pub fn register(&self, run_id: String, account_id: i64, handle: CancelHandle) {
        self.inner
            .lock()
            .unwrap()
            .insert(run_id, RunEntry { account_id, handle });
    }

    /// Removes a run when execution completes (success or error).
    pub fn remove(&self, run_id: &str) {
        self.inner.lock().unwrap().remove(run_id);
    }

    /// Attempts to cancel a run. Returns the handle only if the run_id exists
    /// *and* is owned by the given account. The entry is removed on success —
    /// whoever claims it first wins (identical race semantics to
    /// `revert::Registry`).
    pub fn cancel(&self, run_id: &str, account_id: i64) -> Option<CancelHandle> {
        let mut guard = self.inner.lock().unwrap();
        if guard.get(run_id).map(|e| e.account_id) == Some(account_id) {
            guard.remove(run_id).map(|e| e.handle)
        } else {
            None
        }
    }
}
