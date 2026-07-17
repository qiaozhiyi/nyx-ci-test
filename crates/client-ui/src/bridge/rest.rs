//! REST helpers (all async, all on the worker thread).
//!
//! `authed` is imported from `nyx_rest` — shared with client-cli so the
//! bearer-token logic can't diverge between clients.

use serde::Deserialize;

use super::{authed, SessionView};

/// Fetch the session list as a single round-trip. The caller drives real
/// connect-stage progress around this (see the `match` at the call site): the
/// stage advances to `Connecting` conceptually when the request flies, but since
/// reqwest's send+decode is one awaited future we surface the granular stages
/// from the Ok/Err branches. Keeping the network call in one helper avoids
/// re-plumbing the authed/get chain.
pub(crate) async fn fetch_sessions(
    c: &reqwest::Client,
    server: &str,
    token: &Option<String>,
) -> anyhow::Result<Vec<SessionView>> {
    Ok(authed(c.get(format!("{server}/api/sessions")), token)
        .send()
        .await?
        .json()
        .await?)
}

#[derive(Deserialize)]
struct TaskAck {
    task_id: u64,
}

#[derive(Deserialize)]
pub(crate) struct ResultView {
    pub task_id: u64,
    pub kind: String,
    pub text: String,
}

pub(crate) async fn enqueue_task(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    command: serde_json::Value,
    token: &Option<String>,
) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "session": session,
        "command": command
    });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(ack.task_id)
}

/// `GET /api/results?session=<hex>` — DRAINS the session's entire result
/// queue server-side and returns every row. Must be called at most once per
/// session per worker tick, and every returned row must be routed (see the
/// worker loop): calling it per-task and keeping only the matching row is
/// exactly the lost-result bug this replaced.
pub(crate) async fn drain_results(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    token: &Option<String>,
) -> anyhow::Result<Vec<ResultView>> {
    let rs: Vec<ResultView> = authed(
        c.get(format!("{server}/api/results"))
            .query(&[("session", session)]),
        token,
    )
    .send()
    .await?
    .json()
    .await?;
    Ok(rs)
}

/// Map a result row to display text. `ok` maps to empty so the structured
/// arms (Ls/Ps/Hashdump/…) keep their skip-on-empty semantics; the Generic
/// arm checks `r.kind == "ok"` itself to give no-output commands feedback.
pub(crate) fn result_text(r: &ResultView) -> String {
    match r.kind.as_str() {
        "output" => r.text.clone(),
        "ok" => String::new(),
        "error" => format!("[error] {}", r.text),
        other => format!("[{other}] {}", r.text),
    }
}

#[derive(Deserialize)]
pub(crate) struct TaskRow {
    pub task_id: u64,
    pub command: String,
}

/// `GET /api/tasks?session=<hex>` — list the queued task batch for a session.
/// Used by `/tasks` and the live queue overlay. Mirrors the TUI's behavior.
pub(crate) async fn fetch_tasks(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    token: &Option<String>,
) -> anyhow::Result<Vec<TaskRow>> {
    let rs: Vec<TaskRow> = authed(
        c.get(format!("{server}/api/tasks"))
            .query(&[("session", session)]),
        token,
    )
    .send()
    .await?
    .json()
    .await?;
    Ok(rs)
}

/// Best-effort view of the malleable-C2 profile response. The server may return
/// any subset of fields depending on the loaded profile (`loaded=false` when
/// none); we deserialize permissively so a sparse response still surfaces the
/// `loaded` flag without forcing every other field to be Option<Vec<...>>.
#[derive(Deserialize)]
pub(crate) struct ProfileView {
    #[serde(default)]
    pub loaded: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub samples: Option<Vec<String>>,
    #[serde(default)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// `GET /api/profile` — fetch the loaded profile metadata. Used by `/profile`.
pub(crate) async fn fetch_profile(
    c: &reqwest::Client,
    server: &str,
    token: &Option<String>,
) -> anyhow::Result<ProfileView> {
    Ok(authed(c.get(format!("{server}/api/profile")), token)
        .send()
        .await?
        .json()
        .await?)
}

/// `GET /api/audit/verify` — verify the audit hash chain. Returns the `ok`
/// boolean so the UI can surface pass/fail. The server may also attach a count
/// of records verified; we ignore the rest.
#[derive(Deserialize)]
struct AuditVerifyView {
    ok: bool,
}

/// `GET /api/audit/verify`.
pub(crate) async fn audit_verify(
    c: &reqwest::Client,
    server: &str,
    token: &Option<String>,
) -> anyhow::Result<bool> {
    let v: AuditVerifyView = authed(c.get(format!("{server}/api/audit/verify")), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(v.ok)
}

/// `POST /api/creds` — add a credential. Server returns `{ "ok": true, "key":
/// [realm, user, kind] }`; we ignore the key on success.
pub(crate) async fn cred_add(
    c: &reqwest::Client,
    server: &str,
    realm: &str,
    user: &str,
    kind: &str,
    secret: &str,
    token: &Option<String>,
) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "realm": realm,
        "user": user,
        "kind": kind,
        "secret": secret,
    });
    let _ack: serde_json::Value = authed(c.post(format!("{server}/api/creds")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(())
}

/// `POST /api/creds/delete` — delete by composite key. Returns whether the
/// row was actually deleted (false on no-match, true on hit).
pub(crate) async fn cred_delete(
    c: &reqwest::Client,
    server: &str,
    realm: &str,
    user: &str,
    kind: &str,
    token: &Option<String>,
) -> anyhow::Result<bool> {
    let body = serde_json::json!({
        "realm": realm,
        "user": user,
        "kind": kind,
    });
    let ack: serde_json::Value = authed(
        c.post(format!("{server}/api/creds/delete")).json(&body),
        token,
    )
    .send()
    .await?
    .json()
    .await?;
    Ok(ack
        .get("deleted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}
