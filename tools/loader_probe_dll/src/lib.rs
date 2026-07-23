//! Host-side harness that injects + invokes the reflective PIC blob.
//!
//! This is NOT part of the implant — it is the verifiable delivery channel
//! the release pipeline (`scripts/loader_probe.ps1` + `scripts/release/
//! loader_probe_gate.ps1`) uses to prove the blob actually reflective-loads
//! + executes DllMain on a real Windows kernel.
//!
//! # Why a harness DLL (not a standalone exe)
//!
//! `rundll32` gives us a stable invocation surface (`rundll32 loader_probe.dll,
//! nyx_probe_run <blob_path>`) and lets us execute in a fresh process isolated
//! from the runner agent — a crash here is caught by Windows Error Reporting,
//! not by the GH Actions runner.
//!
//! # What it does
//!
//! 1. Parse the blob path from the rundll32 command tail.
//! 2. Read the blob into heap memory.
//! 3. `VirtualAlloc(NULL, blob.len(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)`
//!    — RWX is intentional for the probe (the production implant uses its own
//!    allocator with W^X transitions; we are verifying the *content*, not the
//!    allocation policy).
//! 4. `memcpy` the blob into the executable page.
//! 5. `FlushInstructionCache` so the CPU doesn't execute stale I-cache lines.
//! 6. Jump to the page base (= PIC stub entry). Wrap the jump in a Vectored
//!    Exception Handler so a crash produces `FAIL stage=invoke` with the
//!    exception code, not a WER dialog + bluescreen cascade.
//! 7. If the stub returns (it shouldn't — it calls DllMain then the loader
//!    blob's last act is to return from the original trampoline), write
//!    `OK rv=<N>` to the result file. If it crashes, the VEH writes
//!    `FAIL stage=invoke code=0x<N>`.
//!
//! # Result file contract
//!
//! Written to the path in `NYX_PROBE_RESULT` (env), or
//! `C:\nyx\loader_probe_result.txt` as fallback (single ASCII line):
//!   * `OK rv=0x<HEX>`               — stub returned, N = its return value
//!   * `FAIL stage=read <msg>`       — could not read blob file
//!   * `FAIL stage=alloc GLE=<N>`    — VirtualAlloc failed
//!   * `FAIL stage=veh <msg>`        — VEH registration failed
//!   * `FAIL stage=invoke code=0x<N> addr=0x<N>` — stub crashed
//!
//! `scripts/loader_probe.ps1` polls for this file and parses the line.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::RawHandle;

// ── Win32 FFI (no windows-sys dep; raw extern "system") ─────────────────────

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(
        lp_address: *const c_void,
        dw_size: usize,
        fl_allocation_type: u32,
        fl_protect: u32,
    ) -> *mut c_void;
    fn VirtualFree(lp_address: *const c_void, dw_size: usize, dw_free_type: u32) -> i32;
    fn FlushInstructionCache(
        h_process: RawHandle,
        lp_base_address: *const c_void,
        dw_size: usize,
    ) -> i32;
    fn GetCurrentProcess() -> RawHandle;
    fn CreateFileW(
        lp_file_name: *const u16,
        dw_desired_access: u32,
        dw_share_mode: u32,
        lp_security_attributes: *const c_void,
        dw_creation_disposition: u32,
        dw_flags_and_attributes: u32,
        h_template_file: RawHandle,
    ) -> RawHandle;
    fn ReadFile(
        h_file: RawHandle,
        lp_buffer: *mut u8,
        n_number_of_bytes_to_read: u32,
        lp_number_of_bytes_read: *mut u32,
        lp_overlapped: *const c_void,
    ) -> i32;
    fn CloseHandle(hObject: RawHandle) -> i32;
    fn GetFileSize(h_file: RawHandle, lp_file_size_high: *mut u32) -> u32;
    fn CreateFileA(
        lp_file_name: *const u8,
        dw_desired_access: u32,
        dw_share_mode: u32,
        lp_security_attributes: *const c_void,
        dw_creation_disposition: u32,
        dw_flags_and_attributes: u32,
        h_template_file: RawHandle,
    ) -> RawHandle;
    fn WriteFile(
        h_file: RawHandle,
        lp_buffer: *const u8,
        n_number_of_bytes_to_write: u32,
        lp_number_of_bytes_written: *mut u32,
        lp_overlapped: *const c_void,
    ) -> i32;
    fn GetLastError() -> u32;
    fn AddVectoredExceptionHandler(
        first: u32,
        handler: unsafe extern "system" fn(*mut c_void) -> u32,
    ) -> *mut c_void;
    fn RemoveVectoredExceptionHandler(handle: *mut c_void) -> u32;
}

// ── Constants ────────────────────────────────────────────────────────────────

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const OPEN_EXISTING: u32 = 3;
const CREATE_ALWAYS: u32 = 2;
const INVALID_HANDLE_VALUE: RawHandle = -1isize as RawHandle;

const DEFAULT_RESULT_PATH: &[u8] = b"C:\\nyx\\loader_probe_result.txt\0";

/// Resolve the result-file path as a static slice (no allocation).
///
/// Historically this returned `Vec<u8>` and honored `NYX_PROBE_RESULT`, but
/// both `Vec::new()` (heap alloc) and `std::env::var` (std runtime) require
/// the Rust runtime to be fully initialized — which is NOT guaranteed when
/// `nyx_probe_run` is invoked by rundll32 immediately after `DllMain`. Both
/// paths silently abort. Returning a `&'static [u8]` avoids the dependency.
///
/// To change the result path, edit `DEFAULT_RESULT_PATH` above and rebuild.
fn resolve_result_path() -> &'static [u8] {
    DEFAULT_RESULT_PATH
}

// ── SEH (vectored exception handler) ─────────────────────────────────────────

const EXCEPTION_CONTINUE_SEARCH: u32 = 0;

const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
const EXCEPTION_PRIV_INSTRUCTION: u32 = 0xC000_0096;
const EXCEPTION_STACK_OVERFLOW: u32 = 0xC000_00FD;
const EXCEPTION_IN_PAGE_ERROR: u32 = 0xC000_0006;
const EXCEPTION_ARRAY_BOUNDS_EXCEEDED: u32 = 0xC000_008C;

#[repr(C)]
#[allow(non_camel_case_types)]
struct EXCEPTION_RECORD {
    exception_code: u32,
    exception_flags: u32,
    exception_record: *mut EXCEPTION_RECORD,
    exception_address: *mut c_void,
    number_parameters: u32,
    _reserved: u64,
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct EXCEPTION_POINTERS {
    exception_record: *mut EXCEPTION_RECORD,
    context_record: *mut c_void,
}

// Module-global so the VEH can record the crash and the outer code can read it.
static mut LAST_EXC_CODE: u32 = 0;
static mut LAST_EXC_ADDR: usize = 0;

unsafe extern "system" fn veh_handler(ptrs: *mut c_void) -> u32 {
    if ptrs.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let ep = &*(ptrs as *const EXCEPTION_POINTERS);
    if ep.exception_record.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let er = &*ep.exception_record;
    let code = er.exception_code;
    // Only trap the "real crash" codes — ignore breakpoint/single-step which
    // a debugger might inject.
    let catches = matches!(
        code,
        EXCEPTION_ACCESS_VIOLATION
            | EXCEPTION_ILLEGAL_INSTRUCTION
            | EXCEPTION_PRIV_INSTRUCTION
            | EXCEPTION_STACK_OVERFLOW
            | EXCEPTION_IN_PAGE_ERROR
            | EXCEPTION_ARRAY_BOUNDS_EXCEEDED
    );
    if !catches {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    LAST_EXC_CODE = code;
    LAST_EXC_ADDR = er.exception_address as usize;
    // Write the FAIL line *before* continuing the search. If WER then kills
    // the process, the file is already on disk for the outer driver to read.
    let msg = format!(
        "FAIL stage=invoke code=0x{:08X} addr=0x{:016X}\n",
        code, LAST_EXC_ADDR
    );
    write_result_raw(msg.as_bytes());
    EXCEPTION_CONTINUE_SEARCH
}

// ── Result file I/O ──────────────────────────────────────────────────────────

fn write_result_raw(bytes: &[u8]) {
    let path = resolve_result_path();
    unsafe {
        let h = CreateFileA(
            path.as_ptr(),
            GENERIC_WRITE,
            0,
            core::ptr::null(),
            CREATE_ALWAYS,
            0,
            core::ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return;
        }
        let mut written: u32 = 0;
        let _ = WriteFile(
            h,
            bytes.as_ptr(),
            bytes.len() as u32,
            &mut written,
            core::ptr::null(),
        );
        let _ = CloseHandle(h);
    }
}

fn write_result_ok(rv: usize) {
    let msg = format!("OK rv=0x{:016X}\n", rv);
    write_result_raw(msg.as_bytes());
}

// ── File read ────────────────────────────────────────────────────────────────

fn read_blob(path_wide: &[u16]) -> Result<Vec<u8>, String> {
    unsafe {
        let h = CreateFileW(
            path_wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            core::ptr::null(),
            OPEN_EXISTING,
            0,
            core::ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return Err(format!("CreateFileW failed: GLE={}", GetLastError()));
        }
        let mut high: u32 = 0;
        let low = GetFileSize(h, &mut high);
        if low == 0xFFFF_FFFF {
            let gle = GetLastError();
            CloseHandle(h);
            return Err(format!("GetFileSize failed: GLE={gle}"));
        }
        let size = ((high as u64) << 32) | (low as u64);
        if size > 64 * 1024 * 1024 {
            CloseHandle(h);
            return Err(format!("blob too large: {size} bytes (max 64 MiB)"));
        }
        let mut buf = vec![0u8; size as usize];
        let mut total: u32 = 0;
        while (total as usize) < buf.len() {
            let mut got: u32 = 0;
            let want = (buf.len() - total as usize).min(0x7FFF_FFFF) as u32;
            let ok = ReadFile(
                h,
                buf.as_mut_ptr().add(total as usize),
                want,
                &mut got,
                core::ptr::null(),
            );
            if ok == 0 {
                let gle = GetLastError();
                CloseHandle(h);
                return Err(format!("ReadFile failed at offset {total}: GLE={gle}"));
            }
            if got == 0 {
                break;
            }
            total += got;
        }
        CloseHandle(h);
        buf.truncate(total as usize);
        Ok(buf)
    }
}

// ── Entry export ─────────────────────────────────────────────────────────────
//
// rundll32 convention: `void entry(HWND hwnd, HINSTANCE hinst, LPSTR cmdline, int cmdshow)`.
// We ignore hwnd/hinst/cmdshow and parse `cmdline` as the blob path.

#[no_mangle]
pub unsafe extern "system" fn nyx_probe_run(
    _hwnd: *mut c_void,
    _hinst: *mut c_void,
    cmdline: *mut u8,
    _cmdshow: i32,
) {
    // Always start by clearing any stale result file so the driver doesn't
    // mis-read a previous run's output if this one dies early.
    write_result_raw(b"FAIL stage=entry not-reached\n");

    if cmdline.is_null() {
        write_result_raw(b"FAIL stage=args null-cmdline\n");
        return;
    }
    // cmdline is ANSI; build a length-prefixed view (NUL-terminated by rundll32).
    let mut len = 0usize;
    while *cmdline.add(len) != 0 {
        len += 1;
        if len > 260 {
            write_result_raw(b"FAIL stage=args cmdline-too-long\n");
            return;
        }
    }
    let cmdline_bytes = core::slice::from_raw_parts(cmdline, len);
    // Trim leading whitespace + optional quotes.
    let mut s = cmdline_bytes;
    while let Some(&first) = s.first() {
        if first == b' ' || first == b'\t' || first == b'"' {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(&last) = s.last() {
        if last == b' ' || last == b'\t' || last == b'"' || last == b'\r' || last == b'\n' {
            s = &s[..s.len() - 1];
        } else {
            break;
        }
    }
    if s.is_empty() {
        write_result_raw(b"FAIL stage=args empty-blob-path\n");
        return;
    }

    let path_os = OsString::from(std::str::from_utf8(s).unwrap_or(""));
    let mut path_wide: Vec<u16> = path_os.encode_wide().collect();
    path_wide.push(0); // NUL terminator for CreateFileW
    if path_wide.len() < 2 {
        write_result_raw(b"FAIL stage=args path-encode-failed\n");
        return;
    }

    let blob = match read_blob(&path_wide) {
        Ok(b) => b,
        Err(e) => {
            let msg = format!("FAIL stage=read {}\n", e);
            write_result_raw(msg.as_bytes());
            return;
        }
    };
    if blob.len() < 0x40 {
        let msg = format!("FAIL stage=read blob-too-small={}\n", blob.len());
        write_result_raw(msg.as_bytes());
        return;
    }

    // Allocate RWX. Round up to page size for safety.
    let page = 0x1000usize;
    let size = (blob.len() + page - 1) & !(page - 1);
    let base = VirtualAlloc(
        core::ptr::null(),
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if base.is_null() {
        let gle = GetLastError();
        let msg = format!("FAIL stage=alloc GLE={gle} size={size}\n");
        write_result_raw(msg.as_bytes());
        return;
    }

    // Copy + flush.
    core::ptr::copy_nonoverlapping(blob.as_ptr(), base as *mut u8, blob.len());
    let _ = FlushInstructionCache(GetCurrentProcess(), base, blob.len());

    // Register VEH to catch a crash before we invoke.
    let veh = AddVectoredExceptionHandler(1, veh_handler);
    if veh.is_null() {
        // Soft warning — still try the invoke, but record if we crash we can't
        // write the FAIL line ourselves (will be WER-only).
        write_result_raw(b"FAIL stage=veh veh-registration-failed\n");
        let _ = VirtualFree(base, 0, MEM_RELEASE);
        return;
    }

    // Reset crash bookkeeping.
    LAST_EXC_CODE = 0;
    LAST_EXC_ADDR = 0;

    // Invoke. The blob's entry is at offset 0 (PIC stub).
    let entry: unsafe extern "system" fn() -> usize = core::mem::transmute(base);
    let rv = entry();

    // If we reached here, the stub RETURNED (which for a reflective loader
    // means DllMain completed and control came back). Either VEH didn't fire
    // or it caught+passed-through — either way the return path is intact.
    RemoveVectoredExceptionHandler(veh);

    write_result_ok(rv);

    let _ = VirtualFree(base, 0, MEM_RELEASE);
}

// DllMain — minimal, just returns TRUE so LoadLibrary / rundll32 don't reject us.
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h: *mut c_void,
    _reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    1
}
