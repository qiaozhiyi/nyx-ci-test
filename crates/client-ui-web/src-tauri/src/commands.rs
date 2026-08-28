//! Tauri commands — the UI→Rust IPC boundary.
//!
//! These are thin: they read/write BackendState and call into `rest`.
//! The big simplification vs the old bridge: `send_command` is GENERIC.
//! The frontend constructs any `JsonCommand` as a `serde_json::Value` and
//! this layer forwards it to `POST /api/task` verbatim. No 28-arm match.

use serde_json::Value;
use std::sync::Arc;
use tauri::{Emitter, State};

use crate::rest;
use crate::state::{BackendState, Connection, PendingTask};

/// Connect to a team server. Stores the connection; the poll loop picks it up.
#[tauri::command]
pub async fn connect(
    state: State<'_, Arc<BackendState>>,
    server: String,
    bearer: String,
) -> Result<(), String> {
    // Validate by attempting an immediate sessions fetch.
    let client = rest::http_client();
    rest::fetch_sessions(&client, &server, &bearer)
        .await
        .map_err(|e| e.to_string())?;
    // Clear leftover pending from a PREVIOUS connection: the frontend can
    // connect without an explicit disconnect (Settings reconnect path used
    // to), and stale entries would be expired against the new server's
    // session ids — emitting bogus timeout errors into fresh consoles.
    state.pending.write().await.clear();
    *state.connection.write().await = Some(Connection { server, bearer });
    Ok(())
}

/// Disconnect from the team server.
#[tauri::command]
pub async fn disconnect(state: State<'_, Arc<BackendState>>) -> Result<(), String> {
    *state.connection.write().await = None;
    state.pending.write().await.clear();
    Ok(())
}

/// Send a command to a session. The frontend builds the `JsonCommand` JSON;
/// this layer forwards it to the server. Returns the assigned task_id.
#[tauri::command]
pub async fn send_command(
    state: State<'_, Arc<BackendState>>,
    app: tauri::AppHandle,
    session: String,
    command: Value,
    command_label: String,
) -> Result<u64, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };

    let client = rest::http_client();
    let kernel_pid = *state.kernel_pid.read().await;
    maybe_auto_open_kernel_window(&app, &client, &server, &bearer, &command, kernel_pid).await;

    let ack = rest::enqueue_task(&client, &server, &bearer, &session, command)
        .await
        .map_err(|e| e.to_string())?;

    // Track as pending so the poll loop drains its results.
    state.pending.write().await.push(PendingTask {
        task_id: ack.task_id,
        session: session.clone(),
        command_label,
        empty_drains: 0,
    });

    // Emit a "task submitted" event so the UI can show the queued block immediately.
    let _ = app.emit(
        "nyx://task-submitted",
        serde_json::json!({
            "task_id": ack.task_id,
            "session": session,
            "chan": ack.chan,
        }),
    );

    Ok(ack.task_id)
}

// ===== Credentials =====

#[tauri::command]
pub async fn list_creds(
    state: State<'_, Arc<BackendState>>,
    reveal: Option<bool>,
    kind: Option<String>,
) -> Result<Vec<serde_json::Value>, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };
    let client = rest::http_client();
    rest::list_creds(
        &client,
        &server,
        &bearer,
        reveal.unwrap_or(false),
        kind.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn add_cred(state: State<'_, Arc<BackendState>>, cred: Value) -> Result<Value, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };
    let client = rest::http_client();
    rest::add_cred(&client, &server, &bearer, cred)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_cred(
    state: State<'_, Arc<BackendState>>,
    realm: String,
    user: String,
    kind: String,
) -> Result<Value, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };
    let client = rest::http_client();
    rest::delete_cred(&client, &server, &bearer, &realm, &user, &kind)
        .await
        .map_err(|e| e.to_string())
}

// ===== Audit =====

#[tauri::command]
pub async fn fetch_audit(
    state: State<'_, Arc<BackendState>>,
    params: Option<Value>,
) -> Result<Vec<serde_json::Value>, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };
    let client = rest::http_client();
    let p = params.unwrap_or(serde_json::json!({}));
    rest::fetch_audit(&client, &server, &bearer, &p)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn verify_audit(state: State<'_, Arc<BackendState>>) -> Result<Value, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };
    let client = rest::http_client();
    rest::verify_audit(&client, &server, &bearer)
        .await
        .map_err(|e| e.to_string())
}

// ===== Implant =====

#[tauri::command]
pub async fn generate_implant(
    state: State<'_, Arc<BackendState>>,
    req: Value,
) -> Result<Value, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };
    let client = rest::http_client();
    rest::generate_implant(&client, &server, &bearer, req)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_implants(state: State<'_, Arc<BackendState>>) -> Result<Value, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };
    let client = rest::http_client();
    rest::list_implants(&client, &server, &bearer)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn revoke_implant(
    state: State<'_, Arc<BackendState>>,
    implant_pub: String,
) -> Result<Value, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };
    let client = rest::http_client();
    rest::revoke_implant(&client, &server, &bearer, &implant_pub)
        .await
        .map_err(|e| e.to_string())
}

// ===== Collaboration (M3) =====

#[tauri::command]
pub async fn fetch_report(state: State<'_, Arc<BackendState>>) -> Result<String, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };
    let client = rest::http_client();
    rest::fetch_report(&client, &server, &bearer)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_session_owner(
    state: State<'_, Arc<BackendState>>,
    session: String,
    owner: Option<String>,
) -> Result<Value, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };
    let client = rest::http_client();
    rest::set_session_owner(&client, &server, &bearer, &session, owner.as_deref())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn fetch_operators(state: State<'_, Arc<BackendState>>) -> Result<Value, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };
    let client = rest::http_client();
    rest::fetch_operators(&client, &server, &bearer)
        .await
        .map_err(|e| e.to_string())
}

// ===== Profile =====

#[tauri::command]
pub async fn fetch_profile(state: State<'_, Arc<BackendState>>) -> Result<Value, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };
    let client = rest::http_client();
    rest::fetch_profile(&client, &server, &bearer)
        .await
        .map_err(|e| e.to_string())
}

// ===== 文件选择 / 读取(BOF / upload 用)=====

/// 文件读取上限:64 MB。二进制走 hex 过 IPC 已经不轻,再大直接防呆拒绝。
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// 打开系统文件选择对话框,返回选中文件的绝对路径;用户取消返回 None。
/// filters 为扩展名列表(不含点,如 ["o", "obj"]),空列表表示不过滤。
#[tauri::command]
pub fn pick_file(app: tauri::AppHandle, title: String, filters: Vec<String>) -> Option<String> {
    use tauri_plugin_dialog::DialogExt;
    let mut dlg = app.dialog().file().set_title(title);
    let exts: Vec<&str> = filters.iter().map(|s| s.as_str()).collect();
    if !exts.is_empty() {
        dlg = dlg.add_filter("files", &exts);
    }
    dlg.blocking_pick_file()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.to_string_lossy().into_owned())
}

/// 读取本地文件并返回小写 hex 串(前端 bof / upload 的 data_hex)。
#[tauri::command]
pub async fn read_file_hex(path: String) -> Result<String, String> {
    use std::fmt::Write;
    let meta = std::fs::metadata(&path).map_err(|e| format!("无法访问文件 {path}: {e}"))?;
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!("文件过大({} 字节),超过 64MB 上限", meta.len()));
    }
    let data = std::fs::read(&path).map_err(|e| format!("无法读取文件 {path}: {e}"))?;
    let mut hex = String::with_capacity(data.len() * 2);
    for b in &data {
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

// ===== Kernel time-window (T2) =====

/// Best-effort `phase=open` before inject/hashdump. 404 / network errors are
/// silent; 502 `failed_step` is a notice. The implant task is always sent.
async fn maybe_auto_open_kernel_window(
    app: &tauri::AppHandle,
    client: &reqwest::Client,
    server: &str,
    bearer: &str,
    command: &Value,
    pid: Option<u32>,
) {
    if !rest::command_wants_kernel_open(command) {
        return;
    }
    if let Ok(reply) = rest::kernel_window(client, server, bearer, "open", pid).await {
        if let Some(msg) = rest::kernel_open_notice(reply.status, &reply.body) {
            let _ = app.emit("nyx://notice", msg);
        }
    }
}

/// `POST /api/kernel/window`. Always returns `{status, body}` on HTTP
/// (including 404/502 and close `restored: false`); only transport/auth is Err.
#[tauri::command]
pub async fn kernel_window(
    state: State<'_, Arc<BackendState>>,
    phase: String,
    pid: Option<u32>,
) -> Result<Value, String> {
    let conn = state.connection.read().await.clone();
    let Some(Connection { server, bearer }) = conn else {
        return Err("not connected".into());
    };
    if let Some(p) = pid.filter(|p| *p > 0) {
        *state.kernel_pid.write().await = Some(p);
    }
    let client = rest::http_client();
    let reply = rest::kernel_window(&client, &server, &bearer, &phase, pid)
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "status": reply.status, "body": reply.body }))
}
