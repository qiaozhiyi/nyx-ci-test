//! Compile-time, per-build randomized config embedding.
//!
//! `embed!("path/to/config")` reads the file at compile time, encrypts it under
//! a ChaCha20-Poly1305 key+nonce, prepends a random-length decoy byte prefix,
//! and emits an expression that returns the decrypted bytes at runtime via
//! `nyx_config::decrypt`.
//!
//! ⚠ SECURITY: the decryption key is emitted as a literal array in the SAME
//! binary as the ciphertext. This is obfuscation, not secrecy — the key, nonce,
//! and ciphertext are trivially recoverable by a reverse engineer. Do not rely
//! on `embed!` to keep sensitive config values confidential. Set
//! `NYX_CONFIG_KEY=<hex>` at build time to bake a unique key per build; the key
//! is still embedded either way.

use std::path::Path;

use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use proc_macro::TokenStream;
use quote::quote;
use rand::{Rng, RngCore};

/// Embed an encrypted config blob into the binary.
///
/// `embed!("path")` → expression of type `Vec<u8>` (the decrypted config at
/// runtime). The file is read at compile time, encrypted under ChaCha20-Poly1305
/// with a fresh per-build nonce, and the ciphertext is emitted alongside the key
/// and nonce so `nyx_config::decrypt` can recover the plaintext at runtime.
///
/// ⚠ WARNING: The decryption key is embedded as a literal array in the SAME
/// binary as the ciphertext. This provides obfuscation against a casual
/// `strings` dump, but it does NOT defeat a reverse engineer — the key, nonce,
/// and ciphertext are all recoverable in minutes by anyone holding the binary.
/// Do NOT rely on this for the confidentiality of sensitive config values
/// (server addresses, credentials, etc.).
///
/// Set `NYX_CONFIG_KEY=<64 hex chars>` at build time to substitute your own
/// 32-byte key for the default random one (e.g. to give each operator/build a
/// unique key). The key is still embedded in the binary either way.
#[proc_macro]
pub fn embed(input: TokenStream) -> TokenStream {
    let lit = syn::parse_macro_input!(input as syn::LitStr);
    let rel = lit.value();
    let path = resolve(&rel);

    let plain = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            return syn::Error::new(lit.span(), format!("nyx_config::embed: {rel}: {e}"))
                .to_compile_error()
                .into();
        }
    };

    // Resolve the ChaCha20-Poly1305 key. NYX_CONFIG_KEY=<hex> (64 hex chars →
    // 32 bytes) overrides the default; this lets operators bake a unique key
    // per build. Either way the key ends up embedded in the binary — see the
    // WARNING on this macro's doc comment.
    let (key, custom_key) = match resolve_key() {
        Ok(Some(custom)) => (custom, true),
        Ok(None) => {
            let mut k = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut k);
            (k, false)
        }
        Err(e) => {
            return syn::Error::new(lit.span(), format!("nyx_config::embed: {e}"))
                .to_compile_error()
                .into();
        }
    };

    let (nonce, ct) = encrypt(&plain, key);
    let pad: usize = rand::thread_rng().gen_range(0..256);
    let mut padded = vec![0u8; pad];
    padded.extend_from_slice(&ct);

    let key_bytes = key.iter().copied();
    let nonce_bytes = nonce.iter().copied();
    let ct_bytes = padded.iter().copied();

    // When no custom key was supplied, surface a real compiler-visible warning
    // at the call site so operators know the default key is recoverable. Done
    // via a deprecated-item reference (stable, warn-by-default) rather than the
    // unstable `proc_macro::Diagnostic` API.
    let key_warning = if custom_key {
        quote! {}
    } else {
        quote! {
            #[deprecated(note = "nyx_config::embed!: NYX_CONFIG_KEY was not set at build \
                time, so the default (random) config key is embedded in this binary. It is \
                recoverable by a reverse engineer — do NOT rely on it for confidentiality of \
                sensitive config values.")]
            const NYX_CONFIG_DEFAULT_KEY_WARNING: () = ();
            const _: () = NYX_CONFIG_DEFAULT_KEY_WARNING;
        }
    };

    // The embedded key/nonce/ciphertext are generated in this same macro
    // invocation (just above), so a `decrypt` failure here can only mean the
    // build-time encrypt and runtime decrypt went out of sync — i.e. a broken
    // build, never a runtime attack. This expansion runs at *runtime* inside
    // `embed!` consumers; under the implant's `panic = "abort"` a tag mismatch
    // would abort with no diagnostic. Surface a message naming the macro so a
    // build-integration break is identifiable from a crash dump, then unwind.
    let expanded = quote!({
        #key_warning
        nyx_config::decrypt(
            &[#(#key_bytes),*],
            &[#(#nonce_bytes),*],
            &[#(#ct_bytes),*][#pad..],
        )
        .expect("nyx_config::embed!: build-time-encrypted config failed AEAD                  verification at runtime (key/nonce/ciphertext out of sync —                  rebuild the consuming crate)")
    });
    expanded.into()
}

/// Resolve a relative path against `CARGO_MANIFEST_DIR` (the invoking crate's
/// root), so `embed!("tests/fixtures/x")` works regardless of build CWD.
fn resolve(rel: &str) -> String {
    if Path::new(rel).is_absolute() {
        return rel.to_string();
    }
    match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => Path::new(&dir).join(rel).to_string_lossy().to_string(),
        Err(_) => rel.to_string(),
    }
}

/// Per-call AEAD encrypt under an explicit key, with a fresh random nonce.
/// Mirrors `nyx_config::encrypt` minus key generation; duplicated here to keep
/// this crate dependency-cycle-free.
fn encrypt(plain: &[u8], key: [u8; 32]) -> ([u8; 12], Vec<u8>) {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: b"",
            },
        )
        .expect("chacha20poly1305 encrypt is infallible");
    (nonce, ct)
}

/// Resolve the config key from the build environment.
///
/// Returns:
/// - `Ok(Some(key))` if `NYX_CONFIG_KEY` is set and parses as 64 hex chars.
/// - `Ok(None)` if `NYX_CONFIG_KEY` is unset/empty (caller falls back to a
///   random key).
/// - `Err(msg)` if `NYX_CONFIG_KEY` is set but malformed (surfaced as a
///   compile error at the call site).
fn resolve_key() -> Result<Option<[u8; 32]>, String> {
    match std::env::var("NYX_CONFIG_KEY") {
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

/// Parse 64 hex chars into a 32-byte key. Kept inline (no `hex` dependency).
fn parse_hex_key(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!(
            "NYX_CONFIG_KEY must be 64 hex chars (32 bytes), got {}",
            s.len()
        ));
    }
    let mut key = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        key[i] = (hi << 4) | lo;
    }
    Ok(key)
}

fn hex_digit(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!(
            "NYX_CONFIG_KEY contains non-hex char {:?}",
            b as char
        )),
    }
}
