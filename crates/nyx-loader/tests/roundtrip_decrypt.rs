//! Host-side crypto/roundtrip contract tests (spec §5.4).
//!
//! `wrap_payload` encrypts the DLL with ChaCha20-Poly1305 under
//! `(config.key, config.nonce)` and emits
//!
//! ```text
//! [LAYER1 + bridge][key 32B][NYX2 magic (4B)][encrypted_len (4B)][nonce (12B)]
//! [ciphertext (N bytes)][Poly1305 tag (16B)][LAYER2 code]
//! ```
//!
//! The on-target Layer-2 decrypts the `ct||tag` region with the SAME
//! (key, nonce) — key from the stub slot, nonce from the header. These tests
//! reproduce that decrypt host-side with the `chacha20poly1305` crate and
//! assert it round-trips to the original DLL, pinning the emitter's crypto
//! contract (same key/nonce in both places, `encrypted_len` excluding the
//! tag).

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use nyx_loader::{
    wrap_payload, LoaderConfig, CIPHERTEXT_OFFSET, ENCRYPTED_LEN_OFFSET, KEY_LEN, LAYER1_BOOTSTRAP,
    NONCE_OFFSET, TAG_LEN,
};

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

/// Offsets of the header + ciphertext inside the wrapped blob.
fn layout_offsets(dll_len: usize) -> (usize, usize, usize) {
    let header_off = LAYER1_BOOTSTRAP.len() + KEY_LEN;
    let ct_off = header_off + CIPHERTEXT_OFFSET;
    let ct_tag_len = dll_len + TAG_LEN;
    (header_off, ct_off, ct_tag_len)
}

/// `wrap_payload` emits a blob that decrypts back to the original DLL with
/// the same (key, nonce): the key baked into the stub slot and the nonce in
/// the NYX2 header are exactly the ones the host-side encrypt used.
#[test]
fn wrap_payload_roundtrips_dll() {
    let key = [0x42u8; 32];
    let nonce = [0x33u8; 12];
    let config = LoaderConfig::new(key, nonce);
    let dll = fake_dll();
    let payload = wrap_payload(&dll, &config).expect("wrap_payload must succeed");

    let (header_off, ct_off, ct_tag_len) = layout_offsets(dll.len());

    // Header fields: encrypted_len excludes the tag; nonce matches config.
    let enc_len_off = header_off + ENCRYPTED_LEN_OFFSET;
    let enc_len = u32::from_le_bytes(payload[enc_len_off..enc_len_off + 4].try_into().unwrap());
    assert_eq!(enc_len, dll.len() as u32);
    assert_eq!(
        &payload[header_off + NONCE_OFFSET..header_off + CIPHERTEXT_OFFSET],
        &nonce[..]
    );

    // Decrypt ct||tag with the same (key, nonce) — must reproduce the DLL.
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let ct = &payload[ct_off..ct_off + ct_tag_len];
    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), ct)
        .expect("decrypt of the emitted blob must succeed");
    assert_eq!(plain, dll, "decrypted payload must equal the original DLL");
}

/// Even an empty DLL wraps and round-trips (a degenerate but valid payload:
/// ct||tag is just the 16-byte tag, and LAYER2 still follows it).
#[test]
fn wrap_payload_roundtrips_empty_dll() {
    let key = [0xABu8; 32];
    let nonce = [0xCDu8; 12];
    let config = LoaderConfig::new(key, nonce);
    let payload = wrap_payload(&[], &config).expect("empty DLL must wrap");

    let (header_off, ct_off, ct_tag_len) = layout_offsets(0);

    // encrypted_len = 0, tag-only ciphertext.
    let enc_len_off = header_off + ENCRYPTED_LEN_OFFSET;
    let enc_len = u32::from_le_bytes(payload[enc_len_off..enc_len_off + 4].try_into().unwrap());
    assert_eq!(enc_len, 0);

    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let ct = &payload[ct_off..ct_off + ct_tag_len];
    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), ct)
        .expect("empty decrypt must succeed");
    assert!(plain.is_empty());
}
