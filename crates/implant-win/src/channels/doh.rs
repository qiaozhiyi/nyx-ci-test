//! DoH (DNS-over-HTTPS) channel — STUB (spec-2 will implement).
//!
//! spec-2 plan: WinHTTP POST to the DoH resolver (cloudflare/google), tunnel
//! frame bytes through DNS A/TXT queries. Server-side `/doh` endpoint extracts
//! the frame from DNS-wire format and feeds it to `handle_frame()`.

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use super::ChannelCtx;

/// STUB: returns None + diagnostic marker. spec-2 fills this in.
pub unsafe fn send_recv(_ctx: &ChannelCtx, _frame: &[u8]) -> Option<Vec<u8>> {
    crate::entry::diag_mark(b"ERR_CH_DOH_UNIMPL");
    None
}
