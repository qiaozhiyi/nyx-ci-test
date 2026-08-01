//! Host-side layout tests for the emitted loader stub (spec §5.4).
//!
//! These verify the byte-level contract the on-target PIC stub must satisfy:
//!   - `stub_starts_with_call_pop` — the stub opens with the 6-byte
//!     `call $+5; pop rax` self-location sequence (spec §5.2 step 1).
//!   - `stub_finds_magic_within_max_scan` — the scan logic, exercised through
//!     the pure-Rust model in [`nyx_loader::on_target::find_magic_offset`],
//!     terminates at the NYX2 magic within the 256-byte bound (spec §5.2
//!     step 2). This is the algorithm the on-target scan loop at
//!     `LAYER1_BOOTSTRAP` offset `0x10` runs; extracting it into a pure
//!     function lets the macOS host exercise it without a Windows process.
//!
//! # Loader status: Layer 2 is NOT implemented
//!
//! [`nyx_loader::generate_loader_stub`] fails with
//! `LoaderError::Layer2Unavailable` until a real on-target Layer-2 exists.
//! The layout tests therefore exercise the intact Layer-1 prefix
//! (`LAYER1_BOOTSTRAP`) directly — the fixed prefix any future stub will
//! start with — and pin the fail-loud contract so a silent "success" can
//! never sneak back in. These tests do NOT execute the stub (no Windows, no
//! PEB); they assert structure. Execution validation is the VPS loader
//! probe's job (spec §5.5).

use nyx_loader::{
    generate_loader_stub, on_target,
    on_target::{KEY_LEN, KEY_PATCH_OFFSET, LAYER1_BOOTSTRAP, MAGIC_SCAN_BOUND},
    LoaderConfig,
};

/// The loader capability is not shippable: `generate_loader_stub` must fail
/// loudly (return `Err`) instead of emitting a stub fragment, because no real
/// Layer-2 on-target shellcode exists. A silent success here would ship a
/// blob that cannot decrypt or load anything on-target.
#[test]
fn generate_loader_stub_fails_loudly() {
    let config = LoaderConfig::new([0x42u8; 32], [0x33u8; 12]);
    let err = generate_loader_stub(&config)
        .expect_err("generate_loader_stub must fail: Layer-2 is not implemented");
    assert_eq!(err, nyx_loader::LoaderError::Layer2Unavailable);
}

/// The (future) stub must begin with `E8 00 00 00 00 58` — `call $+5; pop rax`.
///
/// This is the canonical PIC self-location idiom: `call $+5` pushes the
/// address of the next instruction onto the stack and jumps to it (i.e. a
/// no-op control-flow-wise), and `pop rax` recovers that address into `rax`.
/// From there Layer 1 walks forward to find the NYX2 magic. If this prefix
/// changes, every offset in the stub shifts and the scan/header parse break.
#[test]
fn stub_starts_with_call_pop() {
    // Layer 1 is the fixed prefix of every emitted stub; assert it directly
    // (no stub is emitted today — `generate_loader_stub` fails loudly).
    assert_eq!(
        &LAYER1_BOOTSTRAP[..6],
        &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58],
        "LAYER1_BOOTSTRAP must start with `call $+5; pop rax` for self-location"
    );
}

/// The scan loop terminates at the NYX2 magic within the 256-byte bound.
///
/// This embeds the Layer-1 prefix + the NYX2 magic in a single buffer
/// (mimicking what the on-target scan sees in memory) and runs the pure-Rust
/// scan model [`on_target::find_magic_offset`] over it. The scan starts at
/// offset 5 (the address `pop rax` would recover) and must land exactly on
/// the magic.
#[test]
fn stub_finds_magic_within_max_scan() {
    // Build a "memory" image: LAYER1_BOOTSTRAP bytes followed immediately by
    // the NYX2 header (this is the layout `wrap_payload` would produce once
    // Layer 2 exists). The scan does not care what follows the magic; a
    // minimal header suffices.
    let mut image = Vec::with_capacity(LAYER1_BOOTSTRAP.len() + 4 + 4 + 12);
    image.extend_from_slice(LAYER1_BOOTSTRAP);
    let magic_off = image.len();
    image.extend_from_slice(&nyx_loader::NYX2_MAGIC.to_le_bytes());
    image.extend_from_slice(&1234u32.to_le_bytes()); // encrypted_len (placeholder)
    image.extend_from_slice(&[0u8; 12]); // nonce (placeholder)

    // The scan starts at offset 5 (pop rax recovers stub_base + 5). It must
    // find the magic exactly at `magic_off`, well within the 256-byte bound.
    let found = on_target::find_magic_offset(&image, 5, MAGIC_SCAN_BOUND)
        .expect("scan must locate the NYX2 magic");
    assert_eq!(found, magic_off);
    assert!(
        found < 5 + MAGIC_SCAN_BOUND,
        "magic must be within the 256-byte scan bound"
    );

    // The header fields are at the documented offsets relative to the magic
    // (lib.rs payload layout: magic+4 = enc_len, magic+8 = nonce).
    let enc_len = u32::from_le_bytes(image[magic_off + 4..magic_off + 8].try_into().unwrap());
    assert_eq!(enc_len, 1234);
}

/// The scan must succeed even when the Layer-1 prefix + key slot sits at its
/// maximum realistic length, confirming the bound is generous enough for the
/// prefix a future stub will carry.
#[test]
fn stub_scan_bound_accommodates_layer1_plus_key_slot() {
    // The magic sits at LAYER1_BOOTSTRAP.len() (+ 32-byte key slot when the
    // stub is emitted) in the wrapped payload. For the scan to succeed
    // (bound = 256 from offset 5), the stub start must be at most
    // 5 + 256 bytes in. Confirm this is comfortably true today and pin the
    // invariant so a Layer-1 size regression is caught here, not on the
    // VPS probe.
    let key_slot_end = KEY_PATCH_OFFSET + KEY_LEN;
    assert!(
        key_slot_end <= 5 + MAGIC_SCAN_BOUND,
        "Layer 1 + key slot end at {key_slot_end} bytes must fit within the 256-byte scan \
         bound from offset 5; bump MAGIC_SCAN_BOUND if the stub grows past {} bytes",
        5 + MAGIC_SCAN_BOUND
    );

    // The key slot begins exactly at the end of Layer 1 (the emitter contract
    // a future Layer-2 relies on: `lea reg, [rip + (KEY_PATCH_OFFSET - here)]`).
    assert_eq!(KEY_PATCH_OFFSET, LAYER1_BOOTSTRAP.len());
}

/// When the magic is absent the pure-scan model returns `None`, matching the
/// on-target stub's silent `ret` on scan exhaustion (spec §5.2: bound at
/// `rax+256`; missing magic ⇒ bail).
#[test]
fn stub_scan_returns_none_when_magic_absent() {
    // A Layer-1-only image with no NYX2 header appended: scan must fail
    // cleanly.
    assert!(
        on_target::find_magic_offset(LAYER1_BOOTSTRAP, 5, MAGIC_SCAN_BOUND).is_none(),
        "scan must return None when no NYX2 magic is present"
    );
}
