//! Backend state — connection, bearer token, and the tokio runtime handle.
//!
//! This is the single mutable state held behind the Tauri `State<>` manager.
//! All network IO happens on the tokio runtime; UI commands are thin wrappers.

use std::sync::Arc;
use tokio::sync::RwLock;

/// Connection target + bearer token. `None` when disconnected.
#[derive(Clone, Debug)]
pub struct Connection {
    /// Base URL, e.g. `http://127.0.0.1:8443` (no trailing slash).
    pub server: String,
    /// Bearer token: `name:secret` (operator) or bare token (legacy).
    pub bearer: String,
}

/// Pending task we've enqueued and are awaiting results for.
/// Used to correlate drained results back to the issuing command + emit to UI.
#[derive(Clone, Debug)]
pub struct PendingTask {
    pub task_id: u64,
    pub session: String,
    /// Human-readable command string for display.
    pub command_label: String,
    /// Consecutive EMPTY `/api/results` drains since a result last arrived.
    /// The poll loop increments this on empty drains and resets it when any
    /// result drains; at `MAX_EMPTY_DRAINS` the task is expired and the
    /// console block is resolved with a synthetic error result (dead beacon).
    pub empty_drains: u32,
}

/// The full backend state. Held in an `Arc<RwLock<>>` so the poll loop and
/// command handlers can share it.
#[derive(Default)]
pub struct BackendState {
    pub connection: Arc<RwLock<Option<Connection>>>,
    pub pending: Arc<RwLock<Vec<PendingTask>>>,
    /// Last EDR pid supplied to Settings Open/Close; reused by auto-open on
    /// inject/hashdump. Not the inject target pid.
    pub kernel_pid: Arc<RwLock<Option<u32>>>,
}

impl BackendState {
    pub fn new() -> Self {
        Self::default()
    }
}
