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
    let ack = rest::enqueue_task(&client, &server, &bearer, &session, command)
        .await
        .map_err(|e| e.to_string())?;

    // Track as pending so the poll loop drains its results.
    state.pending.write().await.push(PendingTask {
        task_id: ack.task_id,
        session: session.clone(),
        command_label,
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
