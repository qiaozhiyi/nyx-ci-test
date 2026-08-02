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
//!   - `layer1_bridge_sets_pic_loader_entry_abi` — the bridge appended to
//!     Layer 1 sets the pic-loader Win64 entry ABI
//!     (`rcx=&key, rdx=&nonce, r8=&ct, r9=ct_len`) right before the `jmp
//!     rel32` into Layer 2.
//!
//! # Loader status: Layer 2 is live
//!
//! [`nyx_loader::generate_loader_stub`] emits `[LAYER1_BOOTSTRAP][key 32B]`
//! (the Layer-2 blob, [`nyx_loader::on_target::LAYER2_CODE`], is appended by
//! `wrap_payload` after the ciphertext). These tests do NOT execute the stub
//! (no Windows, no PEB); they assert structure. Execution validation is the
//! VPS loader probe's job (spec §5.5).

use nyx_loader::{
    generate_loader_stub, on_target,
    on_target::{KEY_LEN, KEY_PATCH_OFFSET, LAYER1_BOOTSTRAP, MAGIC_SCAN_BOUND},
    LoaderConfig, LAYER2_JMP_OFFSET,
};

/// `generate_loader_stub` emits the definitive stub prefix: `LAYER1_BOOTSTRAP`
/// verbatim, then the 32-byte key at `KEY_PATCH_OFFSET` (= end of Layer 1).
#[test]
fn generate_loader_stub_emits_layer1_plus_key() {
    let key = [0x42u8; 32];
    let nonce = [0x33u8; 12];
    let config = LoaderConfig::new(key, nonce);
    let stub = generate_loader_stub(&config).expect("stub emission must succeed");

    assert_eq!(
        &stub[..LAYER1_BOOTSTRAP.len()],
        LAYER1_BOOTSTRAP,
        "stub must start with LAYER1_BOOTSTRAP verbatim"
    );
    assert_eq!(KEY_PATCH_OFFSET, LAYER1_BOOTSTRAP.len());
    assert_eq!(
        &stub[KEY_PATCH_OFFSET..KEY_PATCH_OFFSET + KEY_LEN],
        &key[..],
        "the 32-byte key must be baked in at KEY_PATCH_OFFSET"
    );
    assert_eq!(stub.len(), LAYER1_BOOTSTRAP.len() + KEY_LEN);
}

/// The stub must begin with `E8 00 00 00 00 58` — `call $+5; pop rax`.
///
/// This is the canonical PIC self-location idiom: `call $+5` pushes the
/// address of the next instruction onto the stack and jumps to it (i.e. a
/// no-op control-flow-wise), and `pop rax` recovers that address into `rax`.
/// From there Layer 1 walks forward to find the NYX2 magic. If this prefix
/// changes, every offset in the stub shifts and the scan/header parse break.
#[test]
fn stub_starts_with_call_pop() {
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
    // the NYX2 header (the layout `wrap_payload` produces). The scan does not
    // care what follows the magic; a minimal header suffices.
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

/// The scan must succeed even with the full stub + key slot in front of the
/// header, confirming the bound is generous enough for the definitive layout
/// (LAYER1 + bridge + 32-byte key; the header sits at ~0x68).
#[test]
fn stub_scan_bound_accommodates_layer1_plus_key_slot() {
    // In the wrapped payload the magic sits at LAYER1_BOOTSTRAP.len() + KEY_LEN
    // (after the key slot). For the scan to succeed (bound = 256 from offset
    // 5), the header must be at most 5 + 256 bytes in. Confirm this is
    // comfortably true today and pin the invariant so a Layer-1 size
    // regression is caught here, not on the VPS probe.
    let header_off = KEY_PATCH_OFFSET + KEY_LEN;
    assert!(
        header_off <= 5 + MAGIC_SCAN_BOUND,
        "LAYER1 + key slot ends at {header_off} bytes; the header must fit within the \
         256-byte scan bound from offset 5; bump MAGIC_SCAN_BOUND if the stub grows past \
         {} bytes",
        5 + MAGIC_SCAN_BOUND
    );

    // The key slot begins exactly at the end of Layer 1 (the emitter contract
    // the bridge relies on: `lea rcx, [rbx-0x20]` assumes key 0x20 before the
    // header, i.e. KEY_PATCH_OFFSET + KEY_LEN == header position).
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

/// The bridge appended to Layer 1 (immediately before the `jmp rel32`) sets
/// the pic-loader Win64 entry ABI from the Layer-1 register state:
///
/// ```text
/// lea rcx, [rbx-0x20]   ; rcx = &key    (key slot is 0x20 before the header)
/// mov rdx, rsi          ; rdx = &nonce
/// mov r8, rdi           ; r8  = &ct || tag
/// mov r9, rax           ; r9  = ct_len
/// ```
#[test]
fn layer1_bridge_sets_pic_loader_entry_abi() {
    let bridge = &LAYER1_BOOTSTRAP[LAYER2_JMP_OFFSET - 13..LAYER2_JMP_OFFSET];
    assert_eq!(
        bridge,
        &[
            0x48, 0x8D, 0x4B, 0xE0, // lea rcx, [rbx-0x20]
            0x48, 0x89, 0xF2, // mov rdx, rsi
            0x49, 0x89, 0xF8, // mov r8, rdi
            0x49, 0x89, 0xC1, // mov r9, rax
        ],
        "bridge must set rcx=&key, rdx=&nonce, r8=&ct, r9=ct_len for the pic-loader entry"
    );
    // The jmp rel32 opcode immediately follows the bridge.
    assert_eq!(
        LAYER1_BOOTSTRAP[LAYER2_JMP_OFFSET], 0xE9,
        "bridge must be followed by the Layer-2 jmp rel32"
    );
}

/// `wrap_payload`'s displacement math assumes the `jmp rel32` is the last
/// instruction of Layer 1: `jmp_end = LAYER2_JMP_OFFSET + 5` must equal
/// `LAYER1_BOOTSTRAP.len()` (the offset where the key slot begins). Pin it so
/// a Layer-1 edit that moves the jmp cannot silently break the emitter.
#[test]
fn layer2_jmp_is_last_instruction_of_layer1() {
    assert_eq!(
        LAYER2_JMP_OFFSET + 5,
        LAYER1_BOOTSTRAP.len(),
        "the Layer-2 jmp rel32 must end exactly at LAYER1_BOOTSTRAP.len()"
    );
}
