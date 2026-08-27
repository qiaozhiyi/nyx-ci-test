//! Compile-time traffic-timing baseline baked from `NYX_PROFILE`.
//!
//! `build.rs` emits `OUT_DIR/timing.rs` with [`TIMING_BASELINE_BURSTY`].
//! Default is `false` (uniform) when no profile is set. Per-implant override
//! is a trailing `.nyx_cfg` u8 decoded into `Config::timing_baseline`.

include!(concat!(env!("OUT_DIR"), "/timing.rs"));

/// Cadence helper matching agent-dev `bursty_sleep` (`BURST_LEN = 4`).
///
/// `base` is in whole seconds (PIC `kits::sleep` quantum). In-burst interval
/// is `max(1, base / 8)` — the seconds equivalent of agent-dev's
/// `(base / 8).max(Duration::from_millis(500))`. Quiet gap after a burst is
/// the full `base`. Pure (no sleep) so the sequence is host-testable.
pub fn bursty_delay(cycle: u32, base: u32) -> u32 {
    const BURST_LEN: u32 = 4;
    if cycle % (BURST_LEN + 1) == BURST_LEN {
        base
    } else {
        (base / 8).max(1)
    }
}

/// Resolve whether this implant uses bursty cadence.
///
/// Wire u8: 0 = inherit bake, 1 = uniform, 2 = bursty. Unknown values
/// fail-closed to inherit (generate already rejects them).
pub fn is_bursty(timing_baseline: u8) -> bool {
    match timing_baseline {
        1 => false,
        2 => true,
        _ => TIMING_BASELINE_BURSTY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bursty_delay_matches_agent_dev_cadence() {
        // agent-dev `bursty_sleep` over cycles 0..10 with BURST_LEN=4:
        // cycles 4 and 9 are the long gap; the rest are short in-burst.
        let base = 60u32;
        for c in 0..10u32 {
            let d = bursty_delay(c, base);
            if c % 5 == 4 {
                assert_eq!(d, base, "cycle {c} should be the long gap");
            } else {
                assert_eq!(d, 7, "cycle {c} in-burst = base/8");
            }
        }
        // Tiny base: in-burst is floored to 1s (agent-dev floors to 500ms).
        assert_eq!(bursty_delay(0, 1), 1);
        assert_eq!(bursty_delay(4, 1), 1);
    }

    #[test]
    fn is_bursty_override_and_inherit() {
        assert!(!is_bursty(1), "explicit uniform");
        assert!(is_bursty(2), "explicit bursty");
        // Inherit (0 / unknown) follows the bake; default bake is uniform.
        assert_eq!(is_bursty(0), TIMING_BASELINE_BURSTY);
        assert_eq!(is_bursty(3), TIMING_BASELINE_BURSTY);
    }

    #[test]
    fn default_bake_is_uniform() {
        // Host tests run without NYX_PROFILE.
        assert!(!TIMING_BASELINE_BURSTY);
    }
}
