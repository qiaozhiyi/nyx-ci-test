//! T-REX scanner backends — PEB-walk-resolved Win32 API calls.
//!
//! Every function here resolves its API via `crate::resolve::export_addr`,
//! caches the result in a static atomic, and calls it directly. No IAT,
//! no static linking — PIC-clean.

#![cfg(target_os = "windows")]
use crate::heap::{String, Vec};
use crate::resolve::export_addr;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

// ---- Helpers ---------------------------------------------------------------

/// Resolve a kernel32 export, cache in static, return fn pointer (or null).
macro_rules! resolve_kernel32 {
    ($name:expr, $static:ident) => {{
        static $static: AtomicUsize = AtomicUsize::new(0);
        let cached = $static.load(Ordering::Relaxed);
        if cached != 0 {
            cached
        } else {
            match unsafe { export_addr(b"kernel32.dll", $name) } {
                Some(a) => {
                    $static.store(a, Ordering::Relaxed);
                    a
                }
                None => 0,
            }
        }
    }};
}

macro_rules! resolve_advapi32 {
    ($name:expr, $static:ident) => {{
        static $static: AtomicUsize = AtomicUsize::new(0);
        let cached = $static.load(Ordering::Relaxed);
        if cached != 0 {
            cached
        } else {
            match unsafe { export_addr(b"advapi32.dll", $name) } {
                Some(a) => {
                    $static.store(a, Ordering::Relaxed);
                    a
                }
                None => 0,
            }
        }
    }};
}

/// Simple wcslen for null-terminated UTF-16.
pub unsafe fn wcslen(mut s: *const u16) -> usize {
    let mut n = 0;
    while *s.add(n) != 0 {
        n += 1;
    }
    n
}

/// Convert a null-terminated UTF-16 string to a heap-allocated String.
/// Non-ASCII chars are replaced with '?'.
pub unsafe fn wide_to_utf8(w: *const u16) -> String {
    if w.is_null() {
        return String::new();
    }
    let len = wcslen(w);
    let slice = core::slice::from_raw_parts(w, len);
    wide_slice_to_utf8(slice)
}

/// Convert a UTF-16 slice to a heap-allocated String.
pub unsafe fn wide_slice_to_utf8(w: &[u16]) -> String {
    let mut s = String::with_capacity(w.len());
    for &c in w {
        if c == 0 {
            break;
        }
        if c < 0x80 {
            s.push(c as u8 as char);
        } else {
            s.push('?');
        }
    }
    s
}

// ---- T0: Process Enumeration ------------------------------------------------


pub unsafe fn create_toolhelp_snapshot() -> *mut c_void {
    let addr = resolve_kernel32!(b"CreateToolhelp32Snapshot", CT32S);
    if addr == 0 {
        return core::ptr::null_mut();
    }
    type Fn = unsafe extern "system" fn(u32, u32) -> *mut c_void;
    let f: Fn = core::mem::transmute(addr);
    // TH32CS_SNAPPROCESS = 2
    f(2, 0)
}

pub unsafe fn process32_first(h: *mut c_void, pe: *mut core::ffi::c_void) -> i32 {
    let addr = resolve_kernel32!(b"Process32FirstW", P32F);
    if addr == 0 {
        return 0;
    }
    type Fn = unsafe extern "system" fn(*mut c_void, *mut core::ffi::c_void) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(h, pe)
}

pub unsafe fn process32_next(h: *mut c_void, pe: *mut core::ffi::c_void) -> i32 {
    let addr = resolve_kernel32!(b"Process32NextW", P32N);
    if addr == 0 {
        return 0;
    }
    type Fn = unsafe extern "system" fn(*mut c_void, *mut core::ffi::c_void) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(h, pe)
}

pub unsafe fn close_handle(h: *mut c_void) {
    let addr = resolve_kernel32!(b"CloseHandle", CH);
    if addr == 0 {
        return;
    }
    type Fn = unsafe extern "system" fn(*mut c_void) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(h);
}

// ---- T3: Service Manager Enumeration ----------------------------------------



pub unsafe fn open_sc_manager() -> *mut c_void {
    let addr = resolve_advapi32!(b"OpenSCManagerW", OSM);
    if addr == 0 {
        return core::ptr::null_mut();
    }
    type Fn = unsafe extern "system" fn(*const u16, *const u16, u32) -> *mut c_void;
    let f: Fn = core::mem::transmute(addr);
    // SC_MANAGER_ENUMERATE_SERVICE = 0x0004
    f(core::ptr::null(), core::ptr::null(), 0x0004)
}

pub unsafe fn close_sc_manager(h: *mut c_void) {
    let addr = resolve_advapi32!(b"CloseServiceHandle", CSH);
    if addr == 0 {
        return;
    }
    type Fn = unsafe extern "system" fn(*mut c_void) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(h);
}

pub unsafe fn enum_services_status_ex(
    scm: *mut c_void,
    level: u32,
    svc_type: u32,
    state: u32,
    buf: *mut u8,
    buf_sz: u32,
    needed: *mut u32,
    returned: *mut u32,
    resume: *mut u32,
    _group: *const u16,
) -> i32 {
    let addr = resolve_advapi32!(b"EnumServicesStatusExW", ESSE);
    if addr == 0 {
        return 0;
    }
    type Fn = unsafe extern "system" fn(
        *mut c_void, u32, u32, u32, *mut u8, u32, *mut u32, *mut u32, *mut u32, *const u16,
    ) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(scm, level, svc_type, state, buf, buf_sz, needed, returned, resume, core::ptr::null())
}

// ---- Mitigation Queries -----------------------------------------------------

pub unsafe fn get_process_mitigation_policy(
    h: *mut c_void,
    policy: u32,
    buf: *mut c_void,
    len: u32,
) -> i32 {
    let addr = resolve_kernel32!(b"GetProcessMitigationPolicy", GPMP);
    if addr == 0 {
        return 0;
    }
    type Fn = unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32) -> i32;
    let f: Fn = core::mem::transmute(addr);
    f(h, policy, buf, len)
}

// ---- Memory Helpers ---------------------------------------------------------

/// Allocate `sz` bytes of zeroed RW memory via VirtualAlloc.
pub unsafe fn alloc(sz: usize) -> *mut u8 {
    let addr = resolve_kernel32!(b"VirtualAlloc", VA);
    if addr == 0 {
        return core::ptr::null_mut();
    }
    type Fn = unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut u8;
    let f: Fn = core::mem::transmute(addr);
    // MEM_COMMIT | MEM_RESERVE = 0x3000, PAGE_READWRITE = 0x04
    f(core::ptr::null_mut(), sz, 0x3000, 0x04)
}

/// Free memory allocated by `alloc`.
pub unsafe fn free(p: *mut u8) {
    let addr = resolve_kernel32!(b"VirtualFree", VF);
    if addr == 0 {
        return;
    }
    type Fn = unsafe extern "system" fn(*mut u8, usize, u32) -> i32;
    let f: Fn = core::mem::transmute(addr);
    // MEM_RELEASE = 0x8000
    f(p, 0, 0x8000);
}
