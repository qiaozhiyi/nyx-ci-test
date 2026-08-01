//! Host-side payload-format tests for `wrap_payload` (spec §5.4) — CURRENTLY
//! ASSERTING THE FAIL-LOUD GATE.
//!
//! `wrap_payload` previously emitted a blob with the documented wire layout
//!
//! ```text
//! [loader stub (Layer 1 + key + Layer 2)][NYX2 magic (4B)]
//! [encrypted_len u32 LE (4B)][nonce (12B)]
//! [ciphertext (N bytes)][Poly1305 tag (16B)]
//! ```
//!
//! That emitter is gated off: the on-target Layer-2 shellcode does not exist,
//! so [`nyx_loader::wrap_payload`] / [`nyx_loader::generate_loader_stub`]
//! return `LoaderError::Layer2Unavailable` and emit nothing. These tests pin
//! that fail-loud contract and the header-offset constants that a future
//! emitter must honour.

use nyx_loader::{
    on_target,
    wrap_payload, LoaderConfig, CIPHERTEXT_OFFSET, ENCRYPTED_LEN_OFFSET, NONCE_OFFSET, TAG_LEN,
};

/// Build a small but non-trivial fake DLL body.
fn fake_dll() -> Vec<u8> {
    let mut dll = Vec::new();
    dll.extend_from_slice(b"MZ");
    dll.extend_from_slice(&[0u8; 62]);
    dll.extend_from_slice(b"PE\0\0");
    dll.extend_from_slice(&[0xAAu8; 200]);
    dll
}

/// `wrap_payload` must fail loudly while Layer-2 is unimplemented — emitting
/// a blob whose stub cannot decrypt or reflectively load the DLL would be a
/// silent failure on-target.
#[test]
fn wrap_payload_fails_loudly_without_layer2() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let config = LoaderConfig::new(key, nonce);
    let dll = fake_dll();

    let err = wrap_payload(&dll, &config)
        .expect_err("wrap_payload must fail: no on-target Layer-2 exists");
    assert_eq!(err, nyx_loader::LoaderError::Layer2Unavailable);
}

/// The header field offsets are absolute constants documented in `stub.rs`
/// (`ENCRYPTED_LEN_OFFSET = 4`, `NONCE_OFFSET = 8`, `CIPHERTEXT_OFFSET = 20`).
/// Pin them so a change is caught here rather than as an on-target parse
/// failure once the emitter is re-enabled.
#[test]
fn header_offsets_match_documented_layout() {
    assert_eq!(ENCRYPTED_LEN_OFFSET, 4);
    assert_eq!(NONCE_OFFSET, 8);
    assert_eq!(CIPHERTEXT_OFFSET, 20);
    assert_eq!(TAG_LEN, 16);
    // magic + enc_len + nonce = 4 + 4 + 12 = 20 = CIPHERTEXT_OFFSET.
    assert_eq!(4 + 4 + 12, CIPHERTEXT_OFFSET);
}

/// `on_target` module must publicly expose the constants the layout contract
/// relies on (Layer-1 boundary + the Layer-2 design constants a future
/// implementation must honour). This is a structural assertion: if a constant
/// is renamed/removed the test stops compiling, surfacing the API change at
/// the right call site.
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
    let _ = on_target::LAYER2_JMP_OFFSET;
}
