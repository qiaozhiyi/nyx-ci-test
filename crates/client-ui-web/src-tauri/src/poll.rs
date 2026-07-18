//! Background poll loop — the C2 heartbeat.
//!
//! Every 2s: refresh `GET /api/sessions` (with signature-based change detection)
//! and drain `GET /api/results` for each active session. Results are emitted to
//! the frontend via Tauri events.
//!
//! This mirrors the proven design from the old Makepad bridge (single worker
//! thread, per-session drain) but uses Tauri's `Window::emit` instead of
//! Makepad's private channel API.

use std::sync::Arc;
use tauri::async_runtime;
use tauri::{AppHandle, Emitter};
use tokio::time::{interval, Duration};

use crate::rest;
use crate::state::{BackendState, Connection};

/// Poll interval for `/api/sessions`. Matches the old bridge.
const SESSION_POLL: Duration = Duration::from_secs(2);

/// Consecutive `/api/sessions` failures tolerated before emitting `nyx://error`.
/// The frontend treats any such error as a dropped connection and logs the
/// operator out, so a single transient blip must not trigger it — only a
/// sustained outage (3 consecutive misses ≈ 6s) is surfaced.
const MAX_SESSION_FETCH_FAILURES: u32 = 3;

/// Spawn the background poll loop on Tauri's async runtime.
/// Must use `tauri::async_runtime::spawn` (not bare `tokio::spawn`) because
/// Tauri 2's setup callback runs outside a tokio runtime context.
pub fn spawn(app: AppHandle, state: Arc<BackendState>) {
    async_runtime::spawn(async move {
        let client = rest::http_client();
        let mut tick = interval(SESSION_POLL);
        let mut last_sig: Option<String> = None;
        let mut fail_count: u32 = 0;

        loop {
            tick.tick().await;

            let conn = state.connection.read().await.clone();
            let Some(Connection { server, bearer }) = conn else {
                // Disconnected — reset signature so next connect re-emits full list.
                last_sig = None;
                continue;
            };

            // 1. Refresh sessions (with change detection via signature).
            // Tolerate up to MAX_SESSION_FETCH_FAILURES consecutive failures
            // before emitting `nyx://error` (frontend treats it as fatal).
            match rest::fetch_sessions(&client, &server, &bearer).await {
                Ok(sessions) => {
                    fail_count = 0;
                    let sig = nyx_rest::session_signature(&sessions);
                    if last_sig.as_deref() != Some(sig.as_str()) {
                        last_sig = Some(sig);
                        let _ = app.emit("nyx://sessions", &sessions);
                    }
                }
                Err(e) => {
                    fail_count += 1;
                    eprintln!(
                        "[poll] fetch_sessions failed ({fail_count}/{MAX_SESSION_FETCH_FAILURES}): {e}"
                    );
                    if fail_count >= MAX_SESSION_FETCH_FAILURES {
                        let _ = app.emit("nyx://error", e.to_string());
                    }
                }
            }

            // 2. Drain results for each session with pending tasks.
            drain_pending_results(&app, &state, &client, &server, &bearer).await;
        }
    });
}

/// Drain `/api/results` for each session that has pending tasks.
/// Server clears the queue on GET, so we aggregate per-session.
async fn drain_pending_results(
    app: &AppHandle,
    state: &Arc<BackendState>,
    client: &reqwest::Client,
    server: &str,
    bearer: &str,
) {
    let pending = state.pending.read().await.clone();
    if pending.is_empty() {
        return;
    }

    // Unique sessions with pending tasks.
    let sessions: Vec<String> = {
        let mut s: Vec<String> = pending.iter().map(|t| t.session.clone()).collect();
        s.sort();
        s.dedup();
        s
    };

    for session in sessions {
        match rest::drain_results(client, server, bearer, &session).await {
            Ok(results) => {
                for r in &results {
                    let _ = app.emit("nyx://result", r);
                }
                // Remove completed/errored tasks from pending.
                let done_ids: std::collections::HashSet<u64> =
                    results.iter().map(|r| r.task_id).collect();
                if !done_ids.is_empty() {
                    let mut p = state.pending.write().await;
                    p.retain(|t| !done_ids.contains(&t.task_id));
                }
            }
            Err(_) => {
                // Transient network error — leave pending, retry next tick.
            }
        }
    }
}
