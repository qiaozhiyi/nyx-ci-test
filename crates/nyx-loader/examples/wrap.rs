//! Command-line wrapper around `nyx_loader::wrap_payload`.
//!
//! Reads a PE DLL, generates a random `LoaderConfig`, encrypts the DLL, and
//! emits the full NYX2 payload blob (`PIC stub with key baked in` + header +
//! ciphertext + tag). Used by the release pipeline (`scripts/release/wrap_blob.ps1`).
//!
//! The random key is baked into the PIC stub AND used to encrypt the DLL, so
//! the blob is fully self-contained — no separate key exfiltration is needed.
//! A hex dump of the key/nonce is printed to stderr for auditability (so the
//! operator can verify host-side decrypt if needed), but the blob itself is
//! the deliverable.
//!
//! Usage:
//!   cargo run -p nyx-loader --release --example wrap -- <input.dll> <output.bin>

use std::env;
use std::fs;
use std::io::Write;
use std::process::ExitCode;

use nyx_loader::{wrap_payload, LoaderConfig};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "usage: {} <input.dll> <output.bin>",
            args.first().map(String::as_str).unwrap_or("wrap")
        );
        eprintln!("  reads the DLL, encrypts with a random key, writes the reflective blob.");
        return ExitCode::from(2);
    }
    let input_path = &args[1];
    let output_path = &args[2];

    let dll_bytes = match fs::read(input_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read input '{input_path}': {e}");
            return ExitCode::from(1);
        }
    };

    // Light PE sanity check — MZ + PE\0\0. Full parse is wrap_payload's job.
    if dll_bytes.len() < 0x40 || &dll_bytes[..2] != b"MZ" {
        eprintln!("error: '{input_path}' does not look like a PE file (no MZ magic)");
        return ExitCode::from(1);
    }
    let pe_off = u32::from_le_bytes([
        dll_bytes[0x3c],
        dll_bytes[0x3d],
        dll_bytes[0x3e],
        dll_bytes[0x3f],
    ]) as usize;
    if pe_off + 4 > dll_bytes.len() || &dll_bytes[pe_off..pe_off + 4] != b"PE\0\0" {
        eprintln!("error: '{input_path}' has an invalid PE header offset");
        return ExitCode::from(1);
    }

    let config = LoaderConfig::random();
    let blob = wrap_payload(&dll_bytes, &config);

    if let Err(e) = fs::write(output_path, &blob) {
        eprintln!("error: cannot write output '{output_path}': {e}");
        return ExitCode::from(1);
    }

    // Audit trail to stderr (stdout stays clean for pipeline parsing).
    eprintln!(
        "wrap: {} ({} bytes) -> {} ({} bytes)",
        input_path,
        dll_bytes.len(),
        output_path,
        blob.len()
    );
    eprintln!("audit key (hex): {}", hex_encode(&config.key));
    eprintln!("audit nonce (hex): {}", hex_encode(&config.nonce));
    eprintln!("note: key is baked into the PIC stub in the blob; the blob is self-contained.");

    let _ = std::io::stderr().flush();
    ExitCode::SUCCESS
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
