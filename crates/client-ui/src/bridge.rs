//! Data bridge: the ONLY place that touches the network or blocks.
//!
//! Architecture (validated against Makepad 2.0's `automate` example):
//!
//! ```text
//!   UI thread (Makepad main)            IO worker (std::thread + tokio)
//!   ┌──────────────────────┐            ┌───────────────────────────┐
//!   │ App                  │            │ reqwest async client      │
//!   │  state_updates:      │  Snapshot  │  - GET /api/sessions 2s  │
//!   │    ToUIReceiver <────├────────────┤  - per-task result poll   │
//!   │  ui_controls:        │  Cmd       │    (exponential backoff)  │
//!   │    FromUISender ────>├────────────>│ send() = set_ui_signal() │
//!   └──────────────────────┘            └───────────────────────────┘
//! ```
//!
//! `ToUISender::send()` calls `SignalToUI::set_ui_signal()`, which wakes the
//! Makepad event loop; `App::handle_signal` (via `MatchEvent`) drains the
//! channel and refreshes. The UI thread NEVER blocks on IO — it only ever
//! copies cheap `Vec`s out of the channel. This is what makes the client
//! "fast + low-resource": the GPU renders at the monitor's native rate, IO is
//! off-thread, and the UI redraws only when a snapshot changes.

use std::time::{Duration, Instant};

use makepad_widgets::log;
// `ToUIReceiver`/`FromUISender` come from makepad-network, which platform
// re-exports as `makepad_platform::makepad_network` (platform/src/lib.rs:90).
// widgets → draw → platform, so we reach it via makepad_widgets.
use makepad_widgets::makepad_platform::makepad_network::ui_signal::{
    FromUIReceiver, FromUISender, ToUIReceiver, ToUISender,
};
use serde::Deserialize;

// ---- wire types (mirror the REST API; same shapes as the egui client) ----

/// One beacon session, as returned by `GET /api/sessions`.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionView {
    pub id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    #[serde(default)]
    pub is_admin: u8,
    #[serde(default)]
    pub pending: usize,
    #[serde(default)]
    pub beacon_id: u32,
    #[serde(default)]
    pub arch: u8,
    #[serde(default)]
    pub pid: u32,
}

/// A full UI snapshot pushed worker→UI. Coarse-grained on purpose: the worker
/// owns the polling cadence and only sends when something changed, so the UI
/// redraws at most once per poll interval (default 2s), not per byte of shell
/// output.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Most recent session list (empty until the first successful fetch).
    pub sessions: Vec<SessionView>,
    /// Log lines accumulated since the last snapshot. The UI appends these to
    /// its event log; the worker trims its own buffer so this channel can't
    /// grow unbounded (H2-style memory-DoS guard).
    pub log_lines: Vec<String>,
    /// Connection state — drives the top status bar.
    pub connected: bool,
    /// BOF execution updates since the last snapshot. Each entry is appended to
    /// the BOF history UI global by the App. Empty unless a BOF task changed
    /// state (enqueued / completed / errored).
    pub bof_updates: Vec<BofUpdate>,
    /// Per-session shell output lines: (session_id, line). Drained into
    /// `CONSOLE` in `apply_snapshot` so the per-beacon console widget can
    /// render them without touching the global event log.
    pub console_lines: Vec<(String, String)>,
}

/// One BOF lifecycle event, pushed worker→UI and routed into the BOFS global.
#[derive(Debug, Clone)]
pub struct BofUpdate {
    pub name: String,
    pub args: String,
    pub status: BofState,
}

/// Lifecycle of a BOF task. Mirrors the widget's display status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BofState {
    Pending,
    Done,
    Error,
}

/// UI→worker command. Enum keeps the channel message type closed and explicit.
#[derive(Debug, Clone)]
pub enum Cmd {
    /// Target team server base URL + optional API bearer token.
    /// `password` is the operator-typed token sent as `Authorization: Bearer`.
    /// `None` when the server has no `NYX_TOKEN` configured (local dev).
    Connect { server: String, password: Option<String> },
    /// Enqueue a shell task on the given session.
    Shell { session: String, args: String },
    /// Enqueue a BOF (Beacon Object File) task on the given session. `name` is
    /// the COFF entry label shown in the BOF history; `args` the space-separated
    /// arg string (split here to match the server's `Vec<String>`); `data_hex`
    /// the hex-encoded COFF bytes. The result (`kind == "bof"`) is routed into
    /// the BOFS UI global.
    Bof { session: String, name: String, args: String, data_hex: String },
    /// Stop the worker loop (app shutdown).
    Shutdown,
}

/// Default poll interval for the session list. Short enough to feel live,
/// long enough to not hammer the team server. Tunable later via profile.
const SESSION_POLL: Duration = Duration::from_secs(2);

/// Bound on the worker's pending log buffer — if the UI hasn't drained this
/// many lines we drop oldest. Prevents a slow UI from OOMing the worker if
/// the server floods events (mirrors the server's own H2 memory-DoS bound).
const LOG_BUFFER_CAP: usize = 1024;

/// Channels the `App` holds. Returned by [`spawn`].
pub struct Bridge {
    /// Worker→UI snapshots. Drain in `handle_signal`.
    pub to_ui: ToUIReceiver<Snapshot>,
    /// UI→worker commands. Send on button clicks.
    pub from_ui: FromUISender<Cmd>,
}

/// Spin up the IO worker and return the channel ends the App holds.
///
/// The worker owns its own tokio runtime so the rest of the crate stays
/// sync-friendly (Makepad's event loop is sync). One thread, one runtime —
/// `current_thread` keeps it to a single OS thread: minimal footprint, fits
/// "low-resource". No thread-pool proliferation.
pub fn spawn() -> Bridge {
    let to_ui: ToUIReceiver<Snapshot> = ToUIReceiver::default();
    let sender = to_ui.sender();
    let mut from_ui: FromUISender<Cmd> = FromUISender::default();
    // receiver() consumes &mut self and can only be called once — do it here,
    // before handing the sender end to the App.
    let cmd_rx = from_ui.receiver();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                log!("nyx bridge: tokio runtime build failed: {e}");
                return;
            }
        };
        rt.block_on(worker_loop(cmd_rx, sender));
    });

    Bridge { to_ui, from_ui }
}

// ---- worker loop -----------------------------------------------------------

/// What kind of task a pending entry is, so its result can be routed to the
/// right UI surface (shell output → event log; BOF output → BOF history).
#[derive(Clone)]
enum TaskKind {
    Shell,
    /// BOF, carrying its display name + args for the history row.
    Bof { name: String, args: String },
}

/// A task whose result the worker is still polling.
struct PendingTask {
    session: String,
    task_id: u64,
    kind: TaskKind,
    backoff: Duration,
    last_poll: Instant,
}

async fn worker_loop(cmd_rx: FromUIReceiver<Cmd>, to_ui: ToUISender<Snapshot>) {
    // (server_url, optional bearer token). None until first Connect.
    let mut server: Option<(String, Option<String>)> = None;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .expect("reqwest client build");

    // Pending tasks whose result we're still polling. Each gets an exponential
    // backoff so a slow task doesn't spin.
    let mut pending: Vec<PendingTask> = Vec::new();
    let mut log_buf: Vec<String> = Vec::new();
    let mut bof_updates: Vec<BofUpdate> = Vec::new();
    let mut console_lines: Vec<(String, String)> = Vec::new();
    let mut last_session_sig = String::new();
    // Tracks the connection state last REPORTED to the UI. A connect→disconnect
    // (or vice-versa) transition must always push a snapshot even if nothing
    // else changed — otherwise the UI never learns it connected (e.g. fetching
    // an empty session list on first connect yields no signature change, so the
    // old `changed || log_buf || bof` guard silently swallowed the only
    // `connected=true` the UI ever needed).
    let mut was_connected = false;

    loop {
        // 1. Drain any UI→worker commands (non-blocking).
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                Cmd::Shutdown => return,
                Cmd::Connect { server: s, password } => {
                    log_push(&mut log_buf, &format!("connecting to {s} …"));
                    server = Some((s, password));
                    let _ = to_ui.send(take_snapshot(&mut log_buf, false, &[], &mut bof_updates, &mut console_lines));
                }
                Cmd::Shell { session, args } => {
                    let Some((ref srv, ref token)) = server else {
                        log_push(&mut log_buf, "! not connected");
                        continue;
                    };
                    match enqueue_shell(&client, srv, &session, &args, token).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] $ {} → task {}", short(&session), args, tid),
                            );
                            pending.push(PendingTask {
                                session, task_id: tid, kind: TaskKind::Shell,
                                backoff: Duration::from_millis(500), last_poll: Instant::now(),
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! enqueue: {e}")),
                    }
                }
                Cmd::Bof { session, name, args, data_hex } => {
                    let Some((ref srv, ref token)) = server else {
                        log_push(&mut log_buf, "! not connected");
                        continue;
                    };
                    match enqueue_bof(&client, srv, &session, &name, &args, &data_hex, token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] bof {} → task {}", short(&session), name, tid));
                            // Show as pending immediately so the panel isn't empty while polling.
                            bof_updates.push(BofUpdate {
                                name: name.clone(), args: args.clone(), status: BofState::Pending,
                            });
                            pending.push(PendingTask {
                                session, task_id: tid,
                                kind: TaskKind::Bof { name, args },
                                backoff: Duration::from_millis(500), last_poll: Instant::now(),
                            });
                        }
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! bof enqueue: {e}"));
                            bof_updates.push(BofUpdate {
                                name, args, status: BofState::Error,
                            });
                        }
                    }
                }
            }
        }

        let Some((ref srv, ref token)) = server else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };

        // 2. Refresh session list (throttled to SESSION_POLL).
        match fetch_sessions(&client, srv, token).await {
            Ok(list) => {
                let sig = session_signature(&list);
                let changed = sig != last_session_sig;
                // A successful fetch means we ARE connected. If that differs
                // from what we last told the UI, we must push a snapshot even
                // when nothing else changed — otherwise an empty initial
                // session list (sig "" == initial "") leaves the UI stuck on
                // "Disconnected" forever, because the `changed || log || bof`
                // guard below would all be false.
                let connected_changed = !was_connected;
                was_connected = true;
                if changed {
                    last_session_sig = sig;
                }
                if changed || connected_changed || !log_buf.is_empty() || !bof_updates.is_empty() || !console_lines.is_empty() {
                    let _ = to_ui.send(take_snapshot(&mut log_buf, true, &list, &mut bof_updates, &mut console_lines));
                }
            }
            Err(e) => {
                // A failed fetch means we are NOT connected. Mirror the
                // connected_changed logic so a drop is always reported too.
                was_connected = false;
                log_push(&mut log_buf, &format!("! sessions: {e}"));
                let _ = to_ui.send(take_snapshot(&mut log_buf, false, &[], &mut bof_updates, &mut console_lines));
            }
        }

        // 3. Poll pending task results (with per-task backoff).
        let mut still_pending = Vec::new();
        for t in pending.drain(..) {
            if t.last_poll.elapsed() < t.backoff {
                still_pending.push(t);
                continue;
            }
            let PendingTask { session, task_id, kind, backoff, .. } = t;
            match poll_result(&client, srv, &session, task_id, token).await {
                Ok(Some(out)) => match kind {
                    TaskKind::Shell => {
                        if !out.is_empty() {
                            log_push(&mut log_buf, &format!("[{}] {}", short(&session), out));
                            console_lines.push((session.clone(), out));
                        }
                    }
                    TaskKind::Bof { name, args } => {
                        let status = if out.starts_with("[error]") { BofState::Error } else { BofState::Done };
                        if !out.is_empty() {
                            log_push(&mut log_buf, &format!("[{}] bof {}: {}", short(&session), name, out));
                        }
                        bof_updates.push(BofUpdate { name, args, status });
                    }
                },
                Ok(None) => {
                    let next = backoff.saturating_mul(2).min(Duration::from_secs(4));
                    still_pending.push(PendingTask {
                        session, task_id, kind, backoff: next, last_poll: Instant::now(),
                    });
                }
                Err(e) => {
                    log_push(&mut log_buf, &format!("[{}] ! {}", short(&session), e));
                    if let TaskKind::Bof { name, args } = kind {
                        bof_updates.push(BofUpdate { name, args, status: BofState::Error });
                    }
                }
            }
        }
        pending = still_pending;

        // Flush any task-result log lines / BOF updates / console lines accumulated this cycle.
        if !log_buf.is_empty() || !bof_updates.is_empty() || !console_lines.is_empty() {
            let _ = to_ui.send(Snapshot {
                log_lines: std::mem::take(&mut log_buf),
                connected: true,
                sessions: Vec::new(),
                bof_updates: std::mem::take(&mut bof_updates),
                console_lines: std::mem::take(&mut console_lines),
            });
        }

        tokio::time::sleep(SESSION_POLL).await;
    }
}

/// Truncate a session id to 8 chars for log lines (matches the UI's `{:.8}`).
fn short(s: &str) -> &str {
    &s[..s.len().min(8)]
}

fn take_snapshot(
    log_buf: &mut Vec<String>,
    connected: bool,
    sessions: &[SessionView],
    bof_updates: &mut Vec<BofUpdate>,
    console_lines: &mut Vec<(String, String)>,
) -> Snapshot {
    Snapshot {
        sessions: sessions.to_vec(),
        log_lines: std::mem::take(log_buf),
        connected,
        bof_updates: std::mem::take(bof_updates),
        console_lines: std::mem::take(console_lines),
    }
}

// ---- REST helpers (all async, all on the worker) ---------------------------

/// Attach the bearer token (if any) to a request builder. `None` token is a
/// no-op (local dev server with no `NYX_TOKEN`); `Some` sets
/// `Authorization: Bearer <token>` — exactly what the server's `require_auth`
/// gate expects on `/api/*`.
fn authed(req: reqwest::RequestBuilder, token: &Option<String>) -> reqwest::RequestBuilder {
    match token {
        Some(t) => req.bearer_auth(t),
        None => req,
    }
}

async fn fetch_sessions(
    c: &reqwest::Client,
    server: &str,
    token: &Option<String>,
) -> anyhow::Result<Vec<SessionView>> {
    Ok(authed(c.get(format!("{server}/api/sessions")), token)
        .send()
        .await?
        .json()
        .await?)
}

#[derive(Deserialize)]
struct TaskAck {
    task_id: u64,
}

#[derive(Deserialize)]
struct ResultView {
    task_id: u64,
    kind: String,
    text: String,
}

async fn enqueue_shell(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    args: &str,
    token: &Option<String>,
) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "shell", "args": args }
    });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(ack.task_id)
}

async fn enqueue_bof(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    name: &str,
    args: &str,
    data_hex: &str,
    token: &Option<String>,
) -> anyhow::Result<u64> {
    // The server's `JsonCommand::Bof` wants `args: Vec<String>` — split the
    // operator-typed space-separated string. Empty arg string → empty vec.
    let args_vec: Vec<&str> = if args.trim().is_empty() {
        Vec::new()
    } else {
        args.split_whitespace().collect()
    };
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "bof", "name": name, "args": args_vec, "data_hex": data_hex }
    });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(ack.task_id)
}

async fn poll_result(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    task_id: u64,
    token: &Option<String>,
) -> anyhow::Result<Option<String>> {
    let rs: Vec<ResultView> = authed(
        c.get(format!("{server}/api/results")).query(&[("session", session)]),
        token,
    )
    .send()
    .await?
    .json()
    .await?;
    Ok(rs.into_iter().find(|r| r.task_id == task_id).map(|r| match r.kind.as_str() {
        "output" => r.text,
        "ok" => String::new(),
        "error" => format!("[error] {}", r.text),
        other => format!("[{other}] {}", r.text),
    }))
}

/// A cheap signature of the session list so the worker only pushes a snapshot
/// when the set actually changed (id/host/user/admin/pending), avoiding a
/// redraw storm on every 2s poll when nothing moved.
fn session_signature(list: &[SessionView]) -> String {
    let mut s = String::new();
    for v in list {
        s.push_str(&v.id);
        s.push('|');
        s.push_str(&v.hostname);
        s.push('|');
        s.push_str(&v.username);
        s.push('|');
        s.push_str(&format!("{}|{}", v.is_admin, v.pending));
        s.push(';');
    }
    s
}

/// `pub(crate)` so the unit test in `#[cfg(test)] mod tests` (and any future
/// integration test) can exercise the cap behaviour directly.
pub(crate) fn log_push(buf: &mut Vec<String>, line: impl Into<String>) {
    buf.push(line.into());
    if buf.len() > LOG_BUFFER_CAP {
        let drop = buf.len() - LOG_BUFFER_CAP;
        buf.drain(..drop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(id: &str, host: &str, user: &str, admin: u8, pend: usize) -> SessionView {
        SessionView {
            id: id.into(),
            hostname: host.into(),
            username: user.into(),
            os: String::new(),
            is_admin: admin,
            pending: pend,
            beacon_id: 0,
            arch: 0,
            pid: 0,
        }
    }

    #[test]
    fn connect_cmd_carries_password() {
        // Cmd::Connect now carries an optional bearer token. This pins the
        // signature so a future refactor can't silently drop it (the original
        // auth-header bug was exactly this: the field didn't exist).
        let c = Cmd::Connect { server: "http://x".into(), password: Some("sekret".into()) };
        match c {
            Cmd::Connect { password: Some(p), .. } => assert_eq!(p, "sekret"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn connect_cmd_allows_no_token() {
        // Local dev server (no NYX_TOKEN) → password is None; must not error.
        let c = Cmd::Connect { server: "http://x".into(), password: None };
        match c {
            Cmd::Connect { password: None, .. } => {}
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn signature_stable_order() {
        // Same list → same signature (so the worker doesn't spam snapshots).
        let a = vec![sv("s1", "h", "u", 0, 1), sv("s2", "h2", "u2", 1, 0)];
        let b = a.clone();
        assert_eq!(session_signature(&a), session_signature(&b));
    }

    #[test]
    fn signature_detects_change() {
        // A changed field (pending count, admin flag, user, host, id) must
        // change the signature — otherwise stale UI.
        let base = vec![sv("s1", "h", "u", 0, 1)];
        let sig0 = session_signature(&base);
        assert_ne!(sig0, session_signature(&vec![sv("s1", "h", "u", 0, 2)]), "pending change");
        assert_ne!(sig0, session_signature(&vec![sv("s1", "h", "u", 1, 1)]), "admin change");
        assert_ne!(sig0, session_signature(&vec![sv("s1", "h2", "u", 0, 1)]), "host change");
        assert_ne!(sig0, session_signature(&vec![sv("s2", "h", "u", 0, 1)]), "id change");
    }

    #[test]
    fn signature_empty_is_empty_string() {
        assert_eq!(session_signature(&[]), "");
    }

    #[test]
    fn log_push_appends() {
        let mut buf = Vec::new();
        log_push(&mut buf, "a");
        log_push(&mut buf, "b");
        assert_eq!(buf, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn log_push_caps_and_drops_oldest() {
        // Fill past the cap; oldest entries are dropped, newest kept.
        let mut buf = Vec::new();
        for i in 0..(LOG_BUFFER_CAP + 50) {
            log_push(&mut buf, i.to_string());
        }
        assert_eq!(buf.len(), LOG_BUFFER_CAP, "buffer must be capped exactly");
        // The first surviving entry should be the one at offset 50 (we dropped 50).
        assert_eq!(buf[0], "50", "oldest surviving line must be index 50");
        assert_eq!(buf.last().unwrap(), &(LOG_BUFFER_CAP + 50 - 1).to_string());
    }
}
