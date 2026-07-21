//! Host-side crypto roundtrip tests (spec §5.4).
//!
//! These verify the contract between the host-side encryptor
//! (`wrap_payload`) and what the on-target stub's inline ChaCha20-Poly1305
//! routine must decrypt:
//!
//!   - `host_decrypt_matches_crate` — wrap a test DLL with key K + nonce N,
//!     then decrypt the ciphertext portion on the host using the SAME K + N
//!     via the `chacha20poly1305` crate, and verify the recovered plaintext
//!     equals the original DLL. This is exactly what the on-target decrypt
//!     must produce.
//!   - `tag_check_rejects_corruption` — flip one ciphertext byte and confirm
//!     the crate's decrypt fails (Poly1305 tag mismatch). This mirrors the
//!     on-target stub's tag-mismatch path: zero the buffer, return silently.
//!
//! These tests do NOT exercise the inline PIC crypto (that runs only on the
//! Windows target); they exercise the *contract* the inline crypto must
//! honour. The on-target inline implementation is validated end-to-end by the
//! VPS loader probe (spec §5.5).

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use nyx_loader::{
    on_target::{KEY_LEN, KEY_PATCH_OFFSET, LAYER1_BOOTSTRAP, LAYER2_PEB_WALK},
    wrap_payload, LoaderConfig, CIPHERTEXT_OFFSET, TAG_LEN,
};

/// Expected stub length: Layer 1 + 32-byte key + Layer 2.
fn expected_stub_len() -> usize {
    LAYER1_BOOTSTRAP.len() + KEY_LEN + LAYER2_PEB_WALK.len()
}

/// A small but non-trivial fake DLL. The body has no NYX2 magic and no
/// 0x00 runs that would mask a tag-mismatch path.
fn fake_dll() -> Vec<u8> {
    let mut dll = Vec::new();
    dll.extend_from_slice(b"MZ");
    dll.extend_from_slice(&[0x5Au8; 62]);
    dll.extend_from_slice(b"PE\0\0");
    // A recognisable pattern so we can eyeball a successful decrypt in a
    // debugger and so a partial-tag-failure that returns near-garbage is
    // caught by the exact equality check.
    for i in 0..512u32 {
        dll.push((i & 0xFF) as u8);
    }
    dll
}

/// Parse the (magic-relative) header fields out of a wrapped payload blob.
/// Returns `(magic_off, encrypted_len, nonce, ciphertext_with_tag)`.
fn parse_payload(payload: &[u8]) -> (usize, u32, &[u8], &[u8]) {
    let stub_len = expected_stub_len();
    let magic_off = stub_len;
    let enc_len = u32::from_le_bytes(payload[magic_off + 4..magic_off + 8].try_into().unwrap());
    let nonce = &payload[magic_off + 8..magic_off + 20];
    let ct_off = magic_off + CIPHERTEXT_OFFSET;
    let ct_with_tag = &payload[ct_off..ct_off + enc_len as usize + TAG_LEN];
    (magic_off, enc_len, nonce, ct_with_tag)
}

/// Host-side decrypt of a `wrap_payload` blob with the same (key, nonce) must
/// recover the original DLL — this is the contract the on-target inline
/// ChaCha20-Poly1305 routine must honour.
#[test]
fn host_decrypt_matches_crate() {
    let key = [0x42u8; 32];
    let nonce = [0x33u8; 12];
    let config = LoaderConfig::new(key, nonce);
    let dll = fake_dll();

    let payload = wrap_payload(&dll, &config);
    let (magic_off, enc_len, embedded_nonce, ct_with_tag) = parse_payload(&payload);

    // The nonce in the header must be the config nonce (the on-target stub
    // reads it from here).
    assert_eq!(embedded_nonce, &nonce);

    // Cross-check encrypted_len against the DLL length.
    assert_eq!(enc_len as usize, dll.len());

    // Decrypt with the chacha20poly1305 crate under the SAME key + nonce.
    // The key the on-target stub reads from KEY_PATCH_OFFSET is identical to
    // the config key (verified in payload_format tests), so this decryption
    // mirrors what the inline PIC routine produces.
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let decrypt_nonce = Nonce::from_slice(&nonce);
    let decrypted = cipher
        .decrypt(decrypt_nonce, ct_with_tag)
        .expect("host-side decrypt with the correct key + nonce must succeed");

    assert_eq!(
        decrypted, dll,
        "host-side decrypt must recover the original DLL byte-for-byte"
    );
    let _ = magic_off; // (used for clarity in diagnostics if parsing shifts)
}

/// The key baked into the stub at `KEY_PATCH_OFFSET` must be exactly the key
/// that decrypts the ciphertext. This is the invariant the inline PIC routine
/// relies on: it reads the key from the stub, not from the NYX2 header.
#[test]
fn key_baked_into_stub_decrypts_ciphertext() {
    let key = [0x77u8; 32];
    let nonce = [0x88u8; 12];
    let config = LoaderConfig::new(key, nonce);
    let dll = fake_dll();
    let payload = wrap_payload(&dll, &config);

    // Read the key back out of the stub at the documented offset.
    let baked_key: [u8; 32] = payload[KEY_PATCH_OFFSET..KEY_PATCH_OFFSET + KEY_LEN]
        .try_into()
        .unwrap();
    assert_eq!(baked_key, key);

    // Decrypting with the *baked* key (not the config field) must succeed.
    let (_, _, embedded_nonce, ct_with_tag) = parse_payload(&payload);
    let cipher = ChaCha20Poly1305::new_from_slice(&baked_key).unwrap();
    let decrypted = cipher
        .decrypt(Nonce::from_slice(embedded_nonce), ct_with_tag)
        .expect("baked-in key must decrypt the ciphertext");
    assert_eq!(decrypted, dll);
}

/// Flipping one ciphertext byte must cause Poly1305 tag verification to fail.
/// This mirrors the on-target stub's tag-mismatch path (zero the buffer,
/// return silently — spec §5.2 step 6).
#[test]
fn tag_check_rejects_corruption() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let config = LoaderConfig::new(key, nonce);
    let dll = fake_dll();
    let payload = wrap_payload(&dll, &config);

    let (_, enc_len, _, _) = parse_payload(&payload);
    assert!(
        enc_len > 0,
        "test DLL must be non-empty for a flip to matter"
    );

    // Build a corrupted payload: flip a single ciphertext byte (the first
    // byte of the ciphertext, not the tag, so we exercise the AEAD's
    // stream-cipher + tag path rather than just a tag-bit flip).
    let mut corrupted = payload.clone();
    let stub_len = expected_stub_len();
    let ct_off = stub_len + CIPHERTEXT_OFFSET;
    corrupted[ct_off] ^= 0xFF;

    // The crate's decrypt must reject the corrupted ciphertext.
    let (_, _, embedded_nonce, ct_with_tag) = parse_payload(&corrupted);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let result = cipher.decrypt(Nonce::from_slice(embedded_nonce), ct_with_tag);
    assert!(
        result.is_err(),
        "Poly1305 tag verification must reject a flipped ciphertext byte"
    );

    // The error must be an AEAD failure (not e.g. a length error): this is
    // what the on-target stub's tag-compare-and-zero path catches.
    let err = result.unwrap_err();
    let err_str = format!("{err}");
    assert!(
        err_str.to_lowercase().contains("aead")
            || err_str.to_lowercase().contains("tag")
            || err_str.to_lowercase().contains("poly1305")
            || err_str.to_lowercase().contains("mac"),
        "error should indicate an AEAD/tag failure, got: {err_str}"
    );
}

/// Flipping a byte in the Poly1305 tag itself must also fail verification.
/// This is the other half of the corruption contract: the on-target stub
/// compares the computed tag against the trailing 16 bytes constant-time,
/// and any mismatch ⇒ zero-and-return.
#[test]
fn tag_check_rejects_flipped_tag_byte() {
    let key = [0xEEu8; 32];
    let nonce = [0xFFu8; 12];
    let config = LoaderConfig::new(key, nonce);
    let dll = fake_dll();
    let payload = wrap_payload(&dll, &config);

    let mut corrupted = payload.clone();
    // Flip the LAST byte of the blob — that's the last byte of the 16-byte tag.
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0x01;

    let (_, _, embedded_nonce, ct_with_tag) = parse_payload(&corrupted);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    assert!(
        cipher
            .decrypt(Nonce::from_slice(embedded_nonce), ct_with_tag)
            .is_err(),
        "a flipped tag byte must fail Poly1305 verification"
    );
}

/// Decrypting under the wrong key must fail (defence-in-depth: even if an
/// attacker recovers the ciphertext, without the 32-byte stub key the inline
/// decrypt produces a tag mismatch and the stub returns silently).
#[test]
fn wrong_key_fails_to_decrypt() {
    let key = [0x01u8; 32];
    let nonce = [0x02u8; 12];
    let config = LoaderConfig::new(key, nonce);
    let dll = fake_dll();
    let payload = wrap_payload(&dll, &config);

    let (_, _, embedded_nonce, ct_with_tag) = parse_payload(&payload);
    let wrong_key = [0x03u8; 32];
    let cipher = ChaCha20Poly1305::new_from_slice(&wrong_key).unwrap();
    assert!(
        cipher
            .decrypt(Nonce::from_slice(embedded_nonce), ct_with_tag)
            .is_err(),
        "decrypt under a wrong key must fail"
    );
}
