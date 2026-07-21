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
//! These tests do NOT execute the stub (no Windows, no PEB); they assert
//! structure. Execution validation is the VPS loader probe's job (spec §5.5).

use nyx_loader::{
    generate_loader_stub, on_target,
    on_target::{KEY_LEN, KEY_PATCH_OFFSET, LAYER1_BOOTSTRAP, LAYER2_PEB_WALK, MAGIC_SCAN_BOUND},
    LoaderConfig,
};

/// The stub must begin with `E8 00 00 00 00 58` — `call $+5; pop rax`.
///
/// This is the canonical PIC self-location idiom: `call $+5` pushes the
/// address of the next instruction onto the stack and jumps to it (i.e. a
/// no-op control-flow-wise), and `pop rax` recovers that address into `rax`.
/// From there Layer 1 walks forward to find the NYX2 magic. If this prefix
/// changes, every offset in the stub shifts and the scan/header parse break.
#[test]
fn stub_starts_with_call_pop() {
    let config = LoaderConfig::new([0x42u8; 32], [0x33u8; 12]);
    let stub = generate_loader_stub(&config);

    // Spec §5.2 step 1: stub starts with E8 00 00 00 00 58.
    assert_eq!(
        &stub[..6],
        &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58],
        "stub must start with `call $+5; pop rax` for self-location"
    );
    // The first byte of Layer 1 in isolation is the same opcode — belt and
    // braces, so a future reordering that moves Layer 1 is caught.
    assert_eq!(
        &LAYER1_BOOTSTRAP[..6],
        &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58]
    );
}

/// The scan loop terminates at the NYX2 magic within the 256-byte bound.
///
/// This embeds the stub + the NYX2 magic in a single buffer (mimicking what
/// the on-target scan sees in memory) and runs the pure-Rust scan model
/// [`on_target::find_magic_offset`] over it. The scan starts at offset 5
/// (the address `pop rax` would recover) and must land exactly on the magic.
#[test]
fn stub_finds_magic_within_max_scan() {
    let config = LoaderConfig::new([0x77u8; 32], [0x88u8; 12]);
    let stub = generate_loader_stub(&config);

    // Build a "memory" image: stub bytes followed immediately by the NYX2
    // header (this is the layout `wrap_payload` produces). The scan does not
    // care what follows the magic; a minimal header suffices.
    let mut image = Vec::with_capacity(stub.len() + 4 + 4 + 12);
    image.extend_from_slice(&stub);
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

/// The scan must succeed even when the stub itself is at its maximum realistic
/// length (Layer 1 + key + Layer 2), confirming the bound is generous enough.
#[test]
fn stub_scan_bound_accommodates_full_stub_plus_header() {
    let config = LoaderConfig::new([0x55u8; 32], [0x66u8; 12]);
    let stub = generate_loader_stub(&config);

    // The magic sits at stub.len() in the wrapped payload. For the scan to
    // succeed (bound = 256 from offset 5), we need stub.len() - 5 <= 256,
    // i.e. stub.len() <= 261. Confirm this is comfortably true today and
    // pin the invariant so a stub-size regression is caught here, not on the
    // VPS probe.
    assert!(
        stub.len() <= 5 + MAGIC_SCAN_BOUND,
        "stub ({} bytes) + magic must fit within the 256-byte scan bound from offset 5; \
         bump MAGIC_SCAN_BOUND if the stub grows past {} bytes",
        stub.len(),
        5 + MAGIC_SCAN_BOUND
    );

    // Also assert the structural composition (Layer 1 + key + Layer 2) so the
    // length budget is auditable.
    assert_eq!(
        stub.len(),
        LAYER1_BOOTSTRAP.len() + KEY_LEN + LAYER2_PEB_WALK.len()
    );
    assert_eq!(KEY_PATCH_OFFSET, LAYER1_BOOTSTRAP.len());
}

/// When the magic is absent the pure-scan model returns `None`, matching the
/// on-target stub's silent `ret` on scan exhaustion (spec §5.2: bound at
/// `rax+256`; missing magic ⇒ bail).
#[test]
fn stub_scan_returns_none_when_magic_absent() {
    // A stub-only image with no NYX2 header appended: scan must fail cleanly.
    let config = LoaderConfig::new([0x99u8; 32], [0xAAu8; 12]);
    let stub = generate_loader_stub(&config);
    assert!(
        on_target::find_magic_offset(&stub, 5, MAGIC_SCAN_BOUND).is_none(),
        "scan must return None when no NYX2 magic is present"
    );
}
