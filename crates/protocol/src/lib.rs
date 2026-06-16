//! Nyx wire protocol: crypto + framing + task/response messages.
//!
//! Shared by the team server, the (std) dev agent, and — eventually — the
//! Windows PIC implant. Encoding is a hand-rolled little-endian binary codec
//! (deliberately *not* protobuf) so the same logic can be compiled `no_std`
//! for the position-independent implant without a serde/prost footprint.
//!
//! Transport framing (per HTTP body / DNS blob / pipe message):
//! `[32B session pubkey][8B counter][4B ct_len][ciphertext || 16B tag]`
//!
//! Crypto (per session):
//! - Implant generates an ephemeral X25519 keypair; the server holds a
//!   long-term X25519 identity whose public half is baked into implant config.
//! - Session key = HKDF-SHA256(ECDH(implant_eph, server_id)).
//! - AEAD = ChaCha20-Poly1305, 96-bit nonce = zero-padded little-endian
//!   counter. The implant pubkey is bound as AAD on every operation.

pub mod crypto;
pub mod frame;
pub mod msg;
pub mod wire;

pub use crypto::{ImplantKeypair, ServerKeypair, SessionKey, KEY_LEN, NONCE_LEN, PUBKEY_LEN};
pub use frame::{encode_frame, open_frame, parse_frame, RawFrame, FRAME_HEADER, TAG_LEN};
pub use msg::{Command, Response, SessionInfo, Task, TaskResponse};
