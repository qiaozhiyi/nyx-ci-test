//! Transport frame: the per-request body layout, parsed and (de)crypted here.
//!
//! `[32B pubkey][8B counter LE][4B ct_len LE][ciphertext || 16B Poly1305 tag]`
//!
//! The pubkey identifies & keys the session (it is also the AEAD AAD), so the
//! server can be largely stateless per request: read pubkey → derive/look up
//! key → decrypt. The counter is anti-replay (monotonic, checked server-side).

use crate::crypto::{self, SessionKey, PUBKEY_LEN};
use crate::wire::WireError;
use alloc::vec::Vec;

/// pubkey(32) + counter(8) + length(4)
pub const FRAME_HEADER: usize = PUBKEY_LEN + 8 + 4;
/// Poly1305 authentication tag.
pub const TAG_LEN: usize = 16;

/// A frame that has been parsed but not yet decrypted.
#[derive(Debug, Clone)]
pub struct RawFrame {
    pub pubkey: [u8; PUBKEY_LEN],
    pub counter: u64,
    pub ciphertext: Vec<u8>,
}

/// Build a complete request frame from plaintext.
pub fn encode_frame(
    pubkey: &[u8; PUBKEY_LEN],
    counter: u64,
    key: &SessionKey,
    plaintext: &[u8],
) -> Vec<u8> {
    let ciphertext = crypto::seal(key, counter, pubkey, plaintext);
    let mut out = Vec::with_capacity(FRAME_HEADER + ciphertext.len());
    out.extend_from_slice(pubkey);
    out.extend_from_slice(&counter.to_le_bytes());
    out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    out.extend_from_slice(&ciphertext);
    out
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
    if frame.len() < ct_end || ct_len < TAG_LEN {
        return Err(WireError::BadLen(ct_len));
    }
    let ciphertext = frame[FRAME_HEADER..ct_end].to_vec();
    Ok(RawFrame {
        pubkey,
        counter,
        ciphertext,
    })
}

/// Decrypt a parsed frame.
pub fn open_frame(
    key: &SessionKey,
    raw: &RawFrame,
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    crypto::open(key, raw.counter, &raw.pubkey, &raw.ciphertext)
}
