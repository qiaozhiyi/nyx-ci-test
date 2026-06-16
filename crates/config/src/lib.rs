//! Per-build encrypted implant config — runtime half.
//!
//! [`nyx_config_macros::embed!`] reads a config file at **compile time**,
//! encrypts it with a fresh random ChaCha20-Poly1305 key+nonce and a random
//! decoy prefix, and emits a call to [`decrypt`] that returns the plaintext at
//! runtime. Every build (and every call site) bakes a different key/nonce/offset,
//! so the static config bytes — and the surrounding instruction layout — differ
//! per build, defeating extractors/signature tools (the CS `1768.py` problem and
//! the BRC4 signing problem).
//!
//! Why AEAD (not bare stream): config-in-binary is integrity-sensitive (a
//! defender patching the embedded config should fail the Poly1305 tag), so we
//! reuse the same ChaCha20-Poly1305 the beacon loop already trusts.

use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// Encrypt `plain` under a freshly generated key+nonce. Returns
/// `(key, nonce, ciphertext_with_tag)`. Used by the proc-macro at compile time
/// (and by tests).
pub fn encrypt(plain: &[u8]) -> ([u8; KEY_LEN], [u8; NONCE_LEN], Vec<u8>) {
    use rand::RngCore;
    let mut key = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad: b"" })
        .expect("chacha20poly1305 encrypt is infallible");
    (key, nonce, ct)
}

/// Decrypt config baked by [`encrypt`] / `embed!`. Panics on tag mismatch —
/// in practice all material is baked at compile time, so a failure means
/// tampering and the implant should treat it as fatal.
pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: b"" })
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
            .decrypt(Nonce::from_slice(&n1), Payload { msg: &ct1[..], aad: b"" })
            .is_err());
    }

    #[test]
    fn roundtrip_large_config() {
        let plain = (0..4096).map(|i| (i & 0xff) as u8).collect::<Vec<_>>();
        let (k, n, ct) = encrypt(&plain);
        assert_eq!(decrypt(&k, &n, &ct), plain);
    }
}
