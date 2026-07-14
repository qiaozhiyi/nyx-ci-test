//! SMB Named Pipe channel — STUB (spec-2 will implement).
//!
//! spec-2 plan: FFI CreateFileW/WriteFile/ReadFile on `\\.\pipe\<name>`.
//! Server-side SMB pipe listener (Windows only). Supports P2P pivot and
//! Everyone-ACL mode (unauthenticated pipe for IIS exploit scenarios).

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use super::ChannelCtx;

/// STUB: returns None + diagnostic marker. spec-2 fills this in.
pub unsafe fn send_recv(_ctx: &ChannelCtx, _frame: &[u8]) -> Option<Vec<u8>> {
    crate::entry::diag_mark(b"ERR_CH_SMB_UNIMPL");
    None
}
