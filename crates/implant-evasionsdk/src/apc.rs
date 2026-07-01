//! APC / NtContinue chain synthesis — pure model of how Foliage/Ekko queue
//! `NtContinue(ctx)` APCs to walk a thread through a multi-step context dance.
//!
//! In the real technique (Foliage: `NtQueueApcThread`; Ekko: `CreateTimerQueue
//! Timer`), each queued callback invokes `NtContinue(&CONTEXT, FALSE)` to
//! install a new thread CONTEXT — driving the sequence: save→spoof→sleep→
//! restore→... without the thread's own instruction stream touching any of it.
//!
//! This module models the chain as pure data: given a list of target RIPs
//! (the spoof frame addresses from the GapPool), produce the ordered list of
//! `NtContinue` APC descriptors. The live executor resolves the syscall
//! numbers + CONTEXT field layout; here we only validate the structure.

#![cfg_attr(not(test), allow(dead_code))]

extern crate alloc;
use alloc::vec::Vec;
use crate::GapPool;

/// One queued `NtContinue(&ctx)` APC in the chain. `target_rip` is the RIP
/// field of the manufactured CONTEXT the APC will install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApcFrame {
    pub target_rip: u64,
    /// Depth index (0 = outermost / first queued, executes last). The Foliage
    /// chain queues in reverse so the innermost (most-recent) context is the
    /// one the thread resumes into first.
    pub queue_index: usize,
}

/// An ordered APC chain: frames[0] is queued first (executes last in the
/// LIFO APC queue), frames[last] is queued last (executes first).
#[derive(Clone, Debug)]
pub struct ApcChain {
    pub frames: Vec<ApcFrame>,
}

impl ApcChain {
    /// Build an APC chain of `depth` frames, drawing leaf-gap addresses from
    /// `pool.gaps` (the .pdata gap addresses — CET-safe leaf frames). Returns
    /// an empty chain if the pool has no gaps (caller degrades to no-spoof).
    pub fn build(depth: usize, pool: &GapPool) -> Self {
        let mut frames = Vec::new();
        if pool.gaps.is_empty() {
            return Self { frames };
        }
        for i in 0..depth {
            // Round-robin the gaps so consecutive frames don't share an addr.
            let gap = pool.gaps[i % pool.gaps.len()] as u64;
            frames.push(ApcFrame { target_rip: gap, queue_index: i });
        }
        Self { frames }
    }

    /// Chain depth (number of NtContinue APCs). 0 = no chain (degrade).
    pub fn depth(&self) -> usize { self.frames.len() }

    /// True iff every frame's target_rip is non-zero (a coarse validity
    /// check; the real leaf-legal property is RtlLookupFunctionEntry==NULL,
    /// which only the kernel confirms at runtime).
    pub fn looks_valid(&self) -> bool {
        !self.frames.is_empty() && self.frames.iter().all(|f| f.target_rip != 0)
    }

    /// The RIP the thread resumes into FIRST (the last-queued frame).
    pub fn entry_rip(&self) -> Option<u64> {
        self.frames.last().map(|f| f.target_rip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool_with_gaps(n: usize) -> GapPool {
        let gaps = (1..=n).map(|i| 0x1000_0000 + i * 0x10).collect();
        GapPool { gaps, ..Default::default() }
    }

    #[test]
    fn build_yields_requested_depth() {
        let pool = pool_with_gaps(20);
        let chain = ApcChain::build(8, &pool);
        assert_eq!(chain.depth(), 8);
    }

    #[test]
    fn empty_pool_yields_empty_chain() {
        let pool = GapPool::default();
        let chain = ApcChain::build(8, &pool);
        assert_eq!(chain.depth(), 0);
        assert!(!chain.looks_valid());
    }

    #[test]
    fn fewer_gaps_than_depth_round_robins() {
        // 3 gaps, depth 8 → the 3 gaps repeat round-robin.
        let pool = pool_with_gaps(3);
        let chain = ApcChain::build(8, &pool);
        assert_eq!(chain.depth(), 8);
        // frame[0] and frame[3] and frame[6] share the same gap (index 0).
        assert_eq!(chain.frames[0].target_rip, chain.frames[3].target_rip);
        assert_eq!(chain.frames[3].target_rip, chain.frames[6].target_rip);
    }

    #[test]
    fn looks_valid_when_all_nonzero() {
        let pool = pool_with_gaps(8);
        let chain = ApcChain::build(8, &pool);
        assert!(chain.looks_valid());
    }

    #[test]
    fn entry_rip_is_last_queued_frame() {
        let pool = pool_with_gaps(8);
        let chain = ApcChain::build(5, &pool);
        assert_eq!(chain.entry_rip(), Some(chain.frames[4].target_rip));
    }
}
