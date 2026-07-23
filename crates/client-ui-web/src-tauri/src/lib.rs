//! Nyx operator GUI — Tauri 2 backend.
//!
//! Architecture:
//!   - `state`  — BackendState (connection, bearer, pending tasks)
//!   - `rest`   — HTTP helpers (the ONLY network layer; reuses nyx_rest types)
//!   - `poll`   — 2s background poll loop (sessions + per-session results drain)
//!   - `commands` — #[tauri::command] entry points (thin, generic send_command)
//!
//! The old Makepad bridge had a 912-line dispatch.rs match. It's gone:
//! `send_command` accepts any `JsonCommand` as JSON and forwards it verbatim.

pub mod commands;
pub mod poll;
pub mod rest;
pub mod state;

use state::BackendState;
use std::sync::Arc;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Arc::new(BackendState::new()))
        .setup(|app| {
            // Spawn the background poll loop with access to the app handle (for emit).
            let handle = app.handle().clone();
            let state: tauri::State<Arc<BackendState>> = app.state();
            poll::spawn(handle, state.inner().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::connect,
            commands::disconnect,
            commands::send_command,
            commands::list_creds,
            commands::add_cred,
            commands::delete_cred,
            commands::fetch_audit,
            commands::verify_audit,
            commands::generate_implant,
            commands::list_implants,
            commands::revoke_implant,
            commands::fetch_profile,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
