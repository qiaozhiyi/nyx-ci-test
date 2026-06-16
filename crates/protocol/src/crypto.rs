//! Per-session cryptography: X25519 ECDH key agreement, HKDF, ChaCha20-Poly1305 AEAD.

use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const PUBKEY_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// A 32-byte symmetric key derived per session via ECDH + HKDF.
pub type SessionKey = [u8; KEY_LEN];

/// The team server's long-term identity keypair. The public half is baked
/// into every implant's config; the secret never leaves the server.
#[derive(Clone)]
pub struct ServerKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl ServerKeypair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; PUBKEY_LEN] {
        self.public.to_bytes()
    }

    /// Serialize the long-term secret so the server identity can persist across
    /// restarts (`NYX_KEYFILE`). The secret never leaves the server.
    pub fn to_secret_bytes(&self) -> [u8; KEY_LEN] {
        self.secret.to_bytes()
    }

    /// Reconstruct the identity from a persisted secret (e.g. read from
    /// `NYX_KEYFILE`). Derives the matching public key.
    pub fn from_secret_bytes(bytes: [u8; KEY_LEN]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Derive the AEAD session key for a connecting implant whose ephemeral
    /// public key is `implant_pub`. Both sides compute this and must agree.
    pub fn derive_for(&self, implant_pub: &[u8; PUBKEY_LEN]) -> SessionKey {
        let their = PublicKey::from(*implant_pub);
        let shared = self.secret.diffie_hellman(&their);
        derive_session_key(&shared.to_bytes(), &self.public.to_bytes(), implant_pub)
    }
}

/// An implant's per-run keypair.
pub struct ImplantKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl ImplantKeypair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; PUBKEY_LEN] {
        self.public.to_bytes()
    }

    /// Derive the session key given the server's known public key.
    pub fn session_key(&self, server_pub: &[u8; PUBKEY_LEN]) -> SessionKey {
        let server = PublicKey::from(*server_pub);
        let shared = self.secret.diffie_hellman(&server);
        derive_session_key(&shared.to_bytes(), server_pub, &self.public.to_bytes())
    }
}

/// HKDF-SHA256 over the shared secret, bound to both public keys so the
/// resulting key is unique per (implant, server) pair.
pub fn derive_session_key(
    shared: &[u8; 32],
    server_pub: &[u8; PUBKEY_LEN],
    implant_pub: &[u8; PUBKEY_LEN],
) -> SessionKey {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut info = Vec::with_capacity(16 + PUBKEY_LEN * 2);
    info.extend_from_slice(b"nyx-session-v1");
    info.extend_from_slice(server_pub);
    info.extend_from_slice(implant_pub);
    let mut okm = [0u8; KEY_LEN];
    // HKDF expand only fails if the requested length exceeds 255 * HashLen; 32 is fine.
    hk.expand(&info, &mut okm)
        .expect("32-byte HKDF expand cannot fail");
    okm
}

/// AEAD-encrypt `plaintext` under `key` with a counter-derived nonce.
/// `aad` is authenticated but not encrypted (we bind the session pubkey).
pub fn seal(key: &SessionKey, counter: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .expect("chacha20poly1305 encrypt is infallible")
}

/// AEAD-decrypt `ciphertext`. Returns `Err` on tag mismatch (tampering / wrong key).
pub fn open(
    key: &SessionKey,
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.decrypt(nonce, Payload { msg: ciphertext, aad })
}
