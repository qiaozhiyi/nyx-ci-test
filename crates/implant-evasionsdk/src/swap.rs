//! CET-aware RSP-swap decision — pure logic.
//!
//! Intel CET / the Windows kernel shadow stack acts at every `ret`: the CPU
//! pops from RSP AND from the shadow stack, faulting (#CP) on mismatch. A
//! naive RSP swap that moves the stack onto a fake chain of gap addresses
//! will fault on CET-on hosts, because those addresses were never pushed by
//! a real `call`. (The .pdata gap technique is CET-safe at the UNWINDER/
//! detection layer, NOT at the `ret` execution layer — see stack.rs docs.)
//!
//! This module is the pure decision: given the runtime posture (CET on? gaps
//! usable?), decide whether to EXECUTE the swap or DEGRADE. The decision is
//! deliberately pessimistic — when in doubt, degrade (never risk a #CP).

#![cfg_attr(not(test), allow(dead_code))]

/// The swap decision returned by [`decide`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapDecision {
    /// Safe to execute the RSP swap (CET off + gaps usable).
    Execute,
    /// Degrade to the no-swap floor. Carries the reason for diagnostics.
    Degrade(&'static str),
}

/// Decide whether to execute the RSP swap given the runtime posture.
///
/// - `cet_on`: is user-mode CET / shadow stack active for this process?
///   (Win11 24H2+ opt-in per-process; probe at runtime in the live impl.)
/// - `gaps_usable`: did the PdataGapScanner yield a non-empty GapPool?
///
/// Returns `Execute` only when BOTH CET is off AND gaps are usable. Any other
/// combination degrades with a specific reason.
pub fn decide(cet_on: bool, gaps_usable: bool) -> SwapDecision {
    if cet_on {
        return SwapDecision::Degrade("CET/shadow-stack active — RSP swap would #CP");
    }
    if !gaps_usable {
        return SwapDecision::Degrade("no .pdata gaps — nothing to spoof onto");
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

    #[test]
    fn cet_off_gaps_usable_executes() {
        assert_eq!(decide(false, true), SwapDecision::Execute);
    }

    #[test]
    fn cet_on_degrades_even_if_gaps_usable() {
        // CET takes precedence — never risk a #CP even with good gaps.
        assert_eq!(
            decide(true, true),
            SwapDecision::Degrade("CET/shadow-stack active — RSP swap would #CP")
        );
    }

    #[test]
    fn no_gaps_degrades_even_if_cet_off() {
        assert_eq!(
            decide(false, false),
            SwapDecision::Degrade("no .pdata gaps — nothing to spoof onto")
        );
    }

    #[test]
    fn both_bad_degrades_with_cet_reason_first() {
        // CET is checked first → its reason wins.
        assert_eq!(
            decide(true, false),
            SwapDecision::Degrade("CET/shadow-stack active — RSP swap would #CP")
        );
    }

    #[test]
    fn should_execute_helper_matches_decide() {
        assert!(should_execute(false, true));
        assert!(!should_execute(true, true));
        assert!(!should_execute(false, false));
    }
}
