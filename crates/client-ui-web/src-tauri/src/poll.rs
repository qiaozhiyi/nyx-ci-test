//! Background poll loop — the C2 heartbeat.
//!
//! Every 2s: refresh `GET /api/sessions` (with signature-based change detection)
//! and drain `GET /api/results` for each active session. Results are emitted to
//! the frontend via Tauri events.
//!
//! This mirrors the proven design from the old Makepad bridge (single worker
//! thread, per-session drain) but uses Tauri's `Window::emit` instead of
//! Makepad's private channel API.
//!
//! Pending-task hygiene: a task whose session vanishes from `/api/sessions`
//! can never drain, and a task in a live session that produces no result after
//! `MAX_EMPTY_DRAINS` consecutive empty drains belongs to a dead beacon. Both
//! are expired here and the console block is resolved with a synthetic
//! `nyx://result` error so the UI never shows a stuck `queued`/`processing`
//! entry.

use std::sync::Arc;
use tauri::async_runtime;
use tauri::{AppHandle, Emitter};
use tokio::time::{interval, Duration};

use nyx_rest::{ResultView, SessionView};

use crate::rest;
use crate::state::{BackendState, Connection, PendingTask};

/// Poll interval for `/api/sessions`. Matches the old bridge.
const SESSION_POLL: Duration = Duration::from_secs(2);

/// Consecutive `/api/sessions` failures tolerated before emitting `nyx://error`.
/// The frontend treats any such error as a dropped connection and logs the
/// operator out, so a single transient blip must not trigger it — only a
/// sustained outage (3 consecutive misses ≈ 6s) is surfaced.
const MAX_SESSION_FETCH_FAILURES: u32 = 3;

/// Consecutive EMPTY `/api/results` drains tolerated for a pending task before
/// it is expired and the console block resolved with a synthetic error result.
/// 90 drains × 2s poll ≈ 3 minutes of beacon silence. This must exceed the
/// worst-case command round trip of a default-profile implant (sleep 60s +
/// 20% jitter → up to ~72s to pick the task up + ~72s for the result to come
/// back ≈ 144s); anything tighter false-expires healthy beacons.
const MAX_EMPTY_DRAINS: u32 = 90;

/// `nyx://result` payload: a `ResultView` plus the session it belongs to.
/// Every result (real drain or synthetic expiry error) carries `session_id`
/// so the frontend can route it into the right per-session task flow by
/// `(session_id, task_id)` instead of matching task ids across all sessions.
#[derive(Debug, Clone, serde::Serialize)]
struct ResultEvent {
    session_id: String,
    #[serde(flatten)]
    result: ResultView,
}

/// Spawn the background poll loop on Tauri's async runtime.
/// Must use `tauri::async_runtime::spawn` (not bare `tokio::spawn`) because
/// Tauri 2's setup callback runs outside a tokio runtime context.
pub fn spawn(app: AppHandle, state: Arc<BackendState>) {
    async_runtime::spawn(async move {
        let client = rest::http_client();
        let mut tick = interval(SESSION_POLL);
        let mut last_sig: Option<String> = None;
        let mut fail_count: u32 = 0;
        // Emit `nyx://error` at most once per outage: the frontend treats it as
        // fatal and tears the connection down (see App.tsx onError), so
        // re-emitting on every subsequent failed tick would just spam while the
        // poll loop winds down. Reset when a fetch succeeds again.
        let mut error_reported = false;

        loop {
            tick.tick().await;

            let conn = state.connection.read().await.clone();
            let Some(Connection { server, bearer }) = conn else {
                // Disconnected — reset signature so next connect re-emits full list.
                last_sig = None;
                error_reported = false;
                continue;
            };

            // 1. Refresh sessions (with change detection via signature).
            // Tolerate up to MAX_SESSION_FETCH_FAILURES consecutive failures
            // before emitting `nyx://error` (frontend treats it as fatal).
            match rest::fetch_sessions(&client, &server, &bearer).await {
                Ok(sessions) => {
                    fail_count = 0;
                    error_reported = false;
                    // Expire pending tasks for sessions that vanished from the
                    // server: their results will never drain, so resolve the
                    // console blocks with a synthetic error instead of hanging.
                    // Only runs on a SUCCESSFUL fetch — a failed fetch means
                    // the list is stale and must not trigger expiry.
                    expire_absent_sessions(&app, &state, &sessions).await;
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
                    if fail_count >= MAX_SESSION_FETCH_FAILURES && !error_reported {
                        error_reported = true;
                        let _ = app.emit("nyx://error", e.to_string());
                    }
                }
            }

            // 2. Drain results for each session with pending tasks.
            drain_pending_results(&app, &state, &client, &server, &bearer).await;
        }
    });
}

/// Drop pending tasks whose session is absent from the latest `/api/sessions`
/// snapshot, emitting a synthetic `nyx://result` error per task so the console
/// resolves the stuck block.
async fn expire_absent_sessions(
    app: &AppHandle,
    state: &Arc<BackendState>,
    sessions: &[SessionView],
) {
    let live: std::collections::HashSet<&str> = sessions.iter().map(|s| s.id.as_str()).collect();

    // Snapshot the expired tasks under the read lock, then remove under the
    // write lock (emit happens outside any lock).
    let expired: Vec<PendingTask> = {
        let p = state.pending.read().await;
        p.iter()
            .filter(|t| !live.contains(t.session.as_str()))
            .cloned()
            .collect()
    };
    if expired.is_empty() {
        return;
    }

    {
        let mut p = state.pending.write().await;
        p.retain(|t| live.contains(t.session.as_str()));
    }

    for t in &expired {
        emit_error_result(
            app,
            &t.session,
            t.task_id,
            format!("命令超时：session 已不在线（{}），任务未回流。", t.session),
        );
    }
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
                    let _ = app.emit(
                        "nyx://result",
                        ResultEvent {
                            session_id: session.clone(),
                            result: r.clone(),
                        },
                    );
                }
                // Remove completed/errored tasks from pending. Server task
                // ids are PER-SESSION counters (Session.next_task_id), so the
                // retain must be scoped to this session — an unscoped match
                // would silently delete another session's pending task that
                // happens to share the id, hanging its console block forever.
                let done_ids: std::collections::HashSet<u64> =
                    results.iter().map(|r| r.task_id).collect();
                let mut p = state.pending.write().await;
                if done_ids.is_empty() {
                    // Empty drain: nothing completed this tick. Advance the
                    // consecutive-empty counter; tasks that still produce no
                    // result after MAX_EMPTY_DRAINS are expired (dead beacon).
                    drop(p);
                    register_empty_drain(app, state, &session).await;
                } else {
                    // Drain produced results — the session is alive; reset the
                    // empty-drain counters of its remaining pending tasks, then
                    // drop the completed ones.
                    for t in p.iter_mut().filter(|t| t.session == session) {
                        t.empty_drains = 0;
                    }
                    p.retain(|t| !(t.session == session && done_ids.contains(&t.task_id)));
                }
            }
            Err(e) => {
                // Failed drains must count toward expiry too: a session whose
                // results endpoint persistently errors (RBAC 403, flaky link
                // where /api/sessions still succeeds) would otherwise keep
                // tasks pending FOREVER with zero UI feedback.
                eprintln!("[poll] drain_results failed for {session}: {e}");
                register_empty_drain(app, state, &session).await;
            }
        }
    }
}

/// Advance the consecutive-empty counter for every pending task of `session`
/// and expire those past `MAX_EMPTY_DRAINS`, resolving their console blocks
/// with a synthetic error result. Shared by the empty-drain and failed-drain
/// branches. Lock is never held across the emit.
async fn register_empty_drain(app: &AppHandle, state: &Arc<BackendState>, session: &str) {
    let expired: Vec<PendingTask> = {
        let mut p = state.pending.write().await;
        for t in p.iter_mut().filter(|t| t.session == session) {
            t.empty_drains = t.empty_drains.saturating_add(1);
        }
        let expired: Vec<PendingTask> = p
            .iter()
            .filter(|t| t.session == session && t.empty_drains >= MAX_EMPTY_DRAINS)
            .cloned()
            .collect();
        if !expired.is_empty() {
            p.retain(|t| !(t.session == session && t.empty_drains >= MAX_EMPTY_DRAINS));
        }
        expired
    };
    for t in &expired {
        emit_error_result(
            app,
            &t.session,
            t.task_id,
            format!(
                "命令超时：连续 {} 次检查未回流结果，beacon 可能已失联。",
                MAX_EMPTY_DRAINS
            ),
        );
    }
}

/// Emit a synthetic `nyx://result` error for a task, stamped with its session.
/// Lets the console resolve a block whose result will never drain (expired).
fn emit_error_result(app: &AppHandle, session: &str, task_id: u64, text: String) {
    let _ = app.emit(
        "nyx://result",
        ResultEvent {
            session_id: session.to_string(),
            result: ResultView {
                task_id,
                kind: "error".into(),
                text,
                data_hex: None,
                seq: None,
                eof: None,
            },
        },
    );
}
