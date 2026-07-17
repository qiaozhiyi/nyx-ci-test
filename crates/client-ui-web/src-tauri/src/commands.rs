//! Tauri commands — the UI→Rust IPC boundary.
//!
//! These are thin: they read/write BackendState and call into `rest`.
//! The big simplification vs the old bridge: `send_command` is GENERIC.
//! The frontend constructs any `JsonCommand` as a `serde_json::Value` and
//! this layer forwards it to `POST /api/task` verbatim. No 28-arm match.

use std::sync::Arc;
use serde_json::Value;
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
