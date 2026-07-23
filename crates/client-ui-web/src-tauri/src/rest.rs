//! Thin HTTP helpers — the ONLY layer that touches the network.
//!
//! All wire types (`SessionView`, `TaskAck`, `ResultView`) come from `nyx_rest`,
//! so the client can never drift from the server's actual response shapes.
//! Binary payloads (upload data, shellcode) are hex-encoded strings in JSON,
//! matching the server's `JsonCommand` convention.

use anyhow::{anyhow, Result};
use nyx_rest::{authed, ResultView, SessionView, TaskAck};
use reqwest::Client;

/// Build a reqwest client with sane timeouts for an operator console.
pub fn http_client() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("reqwest client build")
}

/// `GET /api/sessions` — list all active sessions.
pub async fn fetch_sessions(
    client: &Client,
    server: &str,
    bearer: &str,
) -> Result<Vec<SessionView>> {
    let url = format!("{}/api/sessions", server.trim_end_matches('/'));
    let resp = authed(client.get(&url), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "sessions: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
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
    let resp = authed(client.post(&url).json(&body), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "task: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
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
    let resp = authed(client.get(&url), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "results: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.json().await?)
}

// ===== Credentials =====

/// `GET /api/creds?reveal=&kind=` — list credentials.
/// `reveal=true` shows plaintext secrets (requires non-Viewer role server-side).
/// `kind` filters by hash/password/ticket/key.
pub async fn list_creds(
    client: &Client,
    server: &str,
    bearer: &str,
    reveal: bool,
    kind: Option<&str>,
) -> Result<Vec<serde_json::Value>> {
    let mut url = format!("{}/api/creds", server.trim_end_matches('/'));
    let mut params: Vec<String> = Vec::new();
    if reveal {
        params.push("reveal=1".into());
    }
    if let Some(k) = kind {
        params.push(format!("kind={}", k));
    }
    if !params.is_empty() {
        url.push('?');
        url.push_str(&params.join("&"));
    }
    let resp = authed(client.get(&url), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "creds: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.json().await?)
}

/// `POST /api/creds` — upsert a credential by (realm, user, kind).
pub async fn add_cred(
    client: &Client,
    server: &str,
    bearer: &str,
    cred: serde_json::Value,
) -> Result<serde_json::Value> {
    let url = format!("{}/api/creds", server.trim_end_matches('/'));
    let resp = authed(client.post(&url).json(&cred), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "creds add: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.json().await?)
}

/// `POST /api/creds/delete` — delete by composite key.
pub async fn delete_cred(
    client: &Client,
    server: &str,
    bearer: &str,
    realm: &str,
    user: &str,
    kind: &str,
) -> Result<serde_json::Value> {
    let url = format!("{}/api/creds/delete", server.trim_end_matches('/'));
    let body = serde_json::json!({ "realm": realm, "user": user, "kind": kind });
    let resp = authed(client.post(&url).json(&body), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "creds delete: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.json().await?)
}

// ===== Audit =====

/// `GET /api/audit` — query the hash-chained audit log.
pub async fn fetch_audit(
    client: &Client,
    server: &str,
    bearer: &str,
    params: &serde_json::Value,
) -> Result<Vec<serde_json::Value>> {
    let base = format!("{}/api/audit", server.trim_end_matches('/'));
    let mut url = base;
    let mut qs: Vec<String> = Vec::new();
    if let Some(obj) = params.as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                qs.push(format!("{}={}", k, s));
            } else if let Some(n) = v.as_u64() {
                qs.push(format!("{}={}", k, n));
            }
        }
    }
    if !qs.is_empty() {
        url.push('?');
        url.push_str(&qs.join("&"));
    }
    let resp = authed(client.get(&url), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "audit: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.json().await?)
}

/// `GET /api/audit/verify` — verify the hash-chain integrity.
pub async fn verify_audit(
    client: &Client,
    server: &str,
    bearer: &str,
) -> Result<serde_json::Value> {
    let url = format!("{}/api/audit/verify", server.trim_end_matches('/'));
    let resp = authed(client.get(&url), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "audit verify: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.json().await?)
}

// ===== Implant generation =====

/// `POST /api/generate-implant` — build a per-implant binary.
pub async fn generate_implant(
    client: &Client,
    server: &str,
    bearer: &str,
    req: serde_json::Value,
) -> Result<serde_json::Value> {
    let url = format!("{}/api/generate-implant", server.trim_end_matches('/'));
    let resp = authed(client.post(&url).json(&req), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "generate: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.json().await?)
}

/// `GET /api/implants` — list all generated implants.
pub async fn list_implants(
    client: &Client,
    server: &str,
    bearer: &str,
) -> Result<serde_json::Value> {
    let url = format!("{}/api/implants", server.trim_end_matches('/'));
    let resp = authed(client.get(&url), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "implants: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.json().await?)
}

/// `POST /api/implant/revoke` — revoke an implant by pubkey.
pub async fn revoke_implant(
    client: &Client,
    server: &str,
    bearer: &str,
    implant_pub: &str,
) -> Result<serde_json::Value> {
    let url = format!("{}/api/implant/revoke", server.trim_end_matches('/'));
    let body = serde_json::json!({ "implant_pub": implant_pub });
    let resp = authed(client.post(&url).json(&body), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "revoke: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.json().await?)
}

// ===== Profile =====

/// `GET /api/profile` — current Malleable C2 profile summary.
pub async fn fetch_profile(
    client: &Client,
    server: &str,
    bearer: &str,
) -> Result<serde_json::Value> {
    let url = format!("{}/api/profile", server.trim_end_matches('/'));
    let resp = authed(client.get(&url), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "profile: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.json().await?)
}
