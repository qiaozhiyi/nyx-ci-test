//! Compile-time, per-build randomized config embedding.
//!
//! `embed!("path/to/config")` reads the file at compile time, encrypts it under
//! a freshly generated ChaCha20-Poly1305 key+nonce, prepends a random-length
//! decoy byte prefix, and emits an expression that returns the decrypted bytes
//! at runtime via `nyx_config::decrypt`. Every build and every call site yields
//! a different key/nonce/offset, so the embedded config bytes (and the emitted
//! instruction layout around them) are polymorphic per build.

use std::path::Path;

use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use proc_macro::TokenStream;
use quote::quote;
use rand::Rng;

/// `embed!("path")` → expression of type `Vec<u8>` (the decrypted config).
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

    let (key, nonce, ct) = encrypt(&plain);
    let pad: usize = rand::thread_rng().gen_range(0..256);
    let mut padded = vec![0u8; pad];
    padded.extend_from_slice(&ct);

    let key_bytes = key.iter().copied();
    let nonce_bytes = nonce.iter().copied();
    let ct_bytes = padded.iter().copied();

    let expanded = quote!({
        nyx_config::decrypt(
            &[#(#key_bytes),*],
            &[#(#nonce_bytes),*],
            &[#(#ct_bytes),*][#pad..],
        )
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

/// Per-call AEAD encrypt (mirrors `nyx_config::encrypt`; duplicated here to keep
/// this crate dependency-cycle-free).
fn encrypt(plain: &[u8]) -> ([u8; 32], [u8; 12], Vec<u8>) {
    use rand::RngCore;
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut key);
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
    (key, nonce, ct)
}
