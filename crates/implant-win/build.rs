//! Build script for nyx-implant-win.
//!
//! Bakes the team server's long-term X25519 public key into the implant as a
//! compile-time constant via a generated `OUT_DIR/server_pub.rs`. This is the
//! implant-side half of H7: previously `server_pub = [0u8; 32]`, which collapses
//! X25519 to the identity point and makes the derived session key predictable
//! — i.e. the "encrypted" beacon frames had zero confidentiality.
//!
//! Source of the key (first match wins):
//!   1. `NYX_SERVER_PUB` env var — 64 hex chars (32 bytes). Set this for a real
//!      engagement build from the operator's long-term server identity.
//!   2. A development fallback keypair baked into the protocol crate's tests
//!      (clearly marked, NOT for production) — lets `cargo build` succeed in dev
//!      without env setup, while never silently shipping an all-zero key.
//!
//! Either way the baked value is real (non-zero) 32-byte X25519 public key, so
//! the ECDH no longer collapses and the session key is genuinely derived.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Re-run if the operator changes the key.
    println!("cargo:rerun-if-env-changed=NYX_SERVER_PUB");

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
            // (This is the same dummy used by the protocol selftest round-trip.)
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

/// Decode a 64-char hex string into 32 bytes, or None if malformed.
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
