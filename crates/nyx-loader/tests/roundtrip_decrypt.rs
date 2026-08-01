//! Host-side crypto/roundtrip contract tests (spec §5.4) — CURRENTLY
//! ASSERTING THE FAIL-LOUD GATE.
//!
//! These tests previously wrapped a DLL via `wrap_payload` and verified the
//! emitted blob decrypts back to the original PE with the same (key, nonce).
//! That contract is now **void**: the on-target Layer-2 shellcode (the inline
//! ChaCha20-Poly1305 the blob would rely on) does not exist, so
//! [`nyx_loader::wrap_payload`] fails with `LoaderError::Layer2Unavailable`
//! and no blob is emitted at all.
//!
//! What these tests pin instead:
//!   - `wrap_payload_fails_loudly_without_layer2` — the headline contract:
//!     no payload can be produced while the loader cannot actually load.
//!
//! The *host-side* ChaCha20-Poly1305 roundtrip itself is trivially true
//! (encrypt + decrypt with the same crate under the same key/nonce) and is
//! exercised by the `chacha20poly1305` crate's own test suite; our side of
//! that contract will be re-tested here end-to-end once a real Layer-2 lands
//! and `wrap_payload` emits blobs again (spec §5.3 + §5.5).

use nyx_loader::{wrap_payload, LoaderConfig};

/// A small but non-trivial fake DLL.
fn fake_dll() -> Vec<u8> {
    let mut dll = Vec::new();
    dll.extend_from_slice(b"MZ");
    dll.extend_from_slice(&[0x5Au8; 62]);
    dll.extend_from_slice(b"PE\0\0");
    for i in 0..512u32 {
        dll.push((i & 0xFF) as u8);
    }
    dll
}

/// `wrap_payload` must fail loudly while Layer-2 is unimplemented — a blob
/// emitted without a working on-target decrypt+reflect sequence would be
/// unusable (and silently so) on the engagement target.
#[test]
fn wrap_payload_fails_loudly_without_layer2() {
    let key = [0x42u8; 32];
    let nonce = [0x33u8; 12];
    let config = LoaderConfig::new(key, nonce);
    let dll = fake_dll();

    let err = wrap_payload(&dll, &config)
        .expect_err("wrap_payload must fail: no on-target Layer-2 exists");
    assert_eq!(err, nyx_loader::LoaderError::Layer2Unavailable);
    // The error message must explain the gap, not just name a variant.
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("layer-2"),
        "error must explain the Layer-2 gap, got: {msg}"
    );
}

/// The failure must be independent of the input: even an empty payload cannot
/// be wrapped while the loader stub cannot be emitted.
#[test]
fn wrap_payload_fails_for_empty_dll_too() {
    let config = LoaderConfig::new([0xABu8; 32], [0xCDu8; 12]);
    assert_eq!(
        wrap_payload(&[], &config),
        Err(nyx_loader::LoaderError::Layer2Unavailable)
    );
}
