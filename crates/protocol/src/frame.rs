//! Transport frame: the per-request body layout, parsed and (de)crypted here.
//!
//! `[32B pubkey][8B counter LE][4B ct_len LE][ciphertext || 16B Poly1305 tag]`
//!
//! The pubkey identifies & keys the session (it is also the AEAD AAD), so the
//! server can be largely stateless per request: read pubkey → derive/look up
//! key → decrypt. The counter is anti-replay (monotonic, checked server-side).

use crate::crypto::{self, Direction, SessionKey, PUBKEY_LEN};
use crate::wire::WireError;
use alloc::vec::Vec;

/// pubkey(32) + counter(8) + length(4)
pub const FRAME_HEADER: usize = PUBKEY_LEN + 8 + 4;
/// Poly1305 authentication tag.
pub const TAG_LEN: usize = 16;
/// Upper bound on a beacon frame's declared ciphertext length. Beacon payloads
/// are tiny (a SessionInfo or a small task/response batch), so anything larger
/// is either malformed or an attempt to induce an oversized allocation.
/// Defense-in-depth on top of the transport's body-size limit (the raw-TLS
/// `serve_connection` path has no default limit, so this cap is the backstop).
pub const MAX_CT_LEN: usize = 512 * 1024; // 512 KiB — matches documented limit

/// Lower bound on a beacon frame's declared ciphertext length. A real frame
/// always carries at least one byte of plaintext (a SessionInfo, a task
/// batch's `u32 count`, a response batch's `u32 count` — never empty), so the
/// ciphertext is always `≥ TAG_LEN + 1`. A frame whose ct_len equals exactly
/// `TAG_LEN` would carry zero plaintext bytes — the AEAD's "all tag, no data"
/// degenerate case, which an attacker could craft without compromising the
/// key. Reject it at the parser so the decoder never has to handle an empty
/// plaintext (the wire codec doesn't define a meaningful interpretation for
/// one anyway). Defense-in-depth, not a correctness fix.
pub const MIN_CT_LEN: usize = TAG_LEN + 1;

/// A frame that has been parsed but not yet decrypted.
#[derive(Debug, Clone)]
pub struct RawFrame {
    pub pubkey: [u8; PUBKEY_LEN],
    pub counter: u64,
    pub ciphertext: Vec<u8>,
}

/// Build a complete request frame from plaintext, sealed with the given
/// [`Direction`]'s nonce space. The direction must match what the receiver
/// will use in [`open_frame_dir`].
///
/// Returns `Err(chacha20poly1305::Error)` only if the underlying AEAD encrypt
/// fails (allocator failure — the AEAD itself is otherwise infallible). The
/// pre-fix `seal_dir` used `.expect()` here, which under the implant's
/// `panic = "abort"` killed the process on a transient alloc failure; the
/// error is now propagated so the caller can drop the frame or retry.
///
/// **Panics** if `plaintext` is empty. The wire codec never produces a
/// zero-byte plaintext (every batch carries at least a `u32 count` and every
/// SessionInfo is non-empty), so an empty plaintext here signals a caller bug.
/// The parser also rejects the resulting "all-tag, no-data" frame on the
/// receive side (see [`MIN_CT_LEN`]); panicking here gives the developer a
/// louder signal at the source rather than a silent round-trip failure.
pub fn encode_frame_dir(
    pubkey: &[u8; PUBKEY_LEN],
    dir: Direction,
    counter: u64,
    key: &SessionKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    assert!(
        !plaintext.is_empty(),
        "encode_frame_dir: empty plaintext is not a valid beacon frame"
    );
    let ciphertext = crypto::seal_dir(key, dir, counter, pubkey, plaintext)?;
    let mut out = Vec::with_capacity(FRAME_HEADER + ciphertext.len());
    out.extend_from_slice(pubkey);
    out.extend_from_slice(&counter.to_le_bytes());
    out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Back-compat shim: seals with [`Direction::ClientToServer`] (the historical
/// implant→server direction). Existing implant/agent-dev callers that *send*
/// should keep using this; server senders must use [`encode_frame_dir`] with
/// [`Direction::ServerToClient`]. See [`encode_frame_dir`] for error semantics.
pub fn encode_frame(
    pubkey: &[u8; PUBKEY_LEN],
    counter: u64,
    key: &SessionKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    encode_frame_dir(pubkey, Direction::ClientToServer, counter, key, plaintext)
}

/// Parse (but do not decrypt) a frame received off the wire.
pub fn parse_frame(frame: &[u8]) -> Result<RawFrame, WireError> {
    if frame.len() < FRAME_HEADER {
        return Err(WireError::Eof);
    }
    let mut pubkey = [0u8; PUBKEY_LEN];
    pubkey.copy_from_slice(&frame[..PUBKEY_LEN]);
    let counter = u64::from_le_bytes(
        frame[PUBKEY_LEN..PUBKEY_LEN + 8]
            .try_into()
            .expect("8 bytes"),
    );
    let ct_len = u32::from_le_bytes(
        frame[PUBKEY_LEN + 8..PUBKEY_LEN + 12]
            .try_into()
            .expect("4 bytes"),
    ) as usize;
    let ct_end = FRAME_HEADER + ct_len;
    // Require the frame to be length-exact (no unauthenticated trailing bytes)
    // AND that the declared ciphertext is within the beacon bounds. The upper
    // cap (MAX_CT_LEN) is a backstop against a future extractor change or the
    // raw-TLS serve_connection path (which has no body-size limit) turning a
    // bogus ct_len into a huge allocation. The lower bound (MIN_CT_LEN) rejects
    // the "all tag, no data" degenerate case so the decoder never has to handle
    // an empty plaintext — see MIN_CT_LEN for the rationale.
    if frame.len() != ct_end || !(MIN_CT_LEN..=MAX_CT_LEN).contains(&ct_len) {
        return Err(WireError::BadLen(ct_len));
    }
    let ciphertext = frame[FRAME_HEADER..ct_end].to_vec();
    Ok(RawFrame {
        pubkey,
        counter,
        ciphertext,
    })
}

/// Decrypt a parsed frame using the given direction's nonce space.
pub fn open_frame_dir(
    key: &SessionKey,
    dir: Direction,
    raw: &RawFrame,
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    crypto::open_dir(key, dir, raw.counter, &raw.pubkey, &raw.ciphertext)
}

/// Back-compat shim: opens with [`Direction::ClientToServer`]. Existing
/// server/implant callers that *receive* implant-origin frames should keep
/// using this; receivers of server-origin frames must use [`open_frame_dir`]
/// with [`Direction::ServerToClient`].
pub fn open_frame(key: &SessionKey, raw: &RawFrame) -> Result<Vec<u8>, chacha20poly1305::Error> {
    open_frame_dir(key, Direction::ClientToServer, raw)
}
