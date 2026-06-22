#![cfg_attr(feature = "no_std", no_std)]
//! Nyx Malleable C2 profile: parser, data-transform engine, and `c2lint`.
//!
//! Implements the Cobalt Strike Malleable C2 profile *language* (grammar
//! cross-checked against the Fox-IT/NCC `dissect.cobaltstrike` Lark grammar and
//! the canonical `rsmudge/Malleable-C2-Profiles` reference profile) so operators
//! can reuse the enormous corpus of community profiles unmodified.
//!
//! What lives here vs. the team server:
//! - **This crate** parses a profile into a typed AST, can apply (and invert)
//!   the byte transforms declared in `output`/`metadata`/`id` blocks, and
//!   lints a profile the way CS's `c2lint` does.
//! - The team server / implant will later *consume* a parsed profile to shape
//!   the HTTP envelope (URIs, headers, jitter, staging). That wiring is the
//!   remaining P1 transport work; this crate is the standalone foundation.
//!
//! Deliberately dependency-light (only `thiserror`): the transform engine
//! hand-rolls base64/base64url/netbios so the crate stays auditable and the
//! `c2lint` binary stays tiny.

extern crate alloc;

// The parser/lexer/lint/envelope layers need `std` (Cow, thiserror derives).
// Only the pure byte-transform engine is `no_std`+`alloc`-clean, so under the
// `no_std` feature we expose JUST `transform` — letting the PIC implant apply
// and invert profile transforms without pulling std. build.rs (host-side, std)
// still parses profiles and bakes the resolved step lists into the implant.
#[cfg(feature = "std")]
pub mod ast;
#[cfg(feature = "std")]
pub mod envelope;
#[cfg(feature = "std")]
pub mod lexer;
#[cfg(feature = "std")]
pub mod lint;
#[cfg(feature = "std")]
pub mod parser;
pub mod transform;

#[cfg(feature = "std")]
pub use ast::{Block, Item, Profile, Setting, Str};
#[cfg(feature = "std")]
pub use envelope::{
    get_client_envelope, get_server_envelope, post_client_envelope, post_server_envelope,
    ClientEnvelope, ServerEnvelope,
};
#[cfg(feature = "std")]
pub use lexer::LexError;
#[cfg(feature = "std")]
pub use lint::{lint, Diagnostic, Severity};
#[cfg(feature = "std")]
pub use parser::{parse, ParseError};
pub use transform::{decode, encode, Step, Terminator, TransformError};
// `steps_from_block` needs `ast::Block` → gated out under `no_std`; build.rs
// resolves steps host-side for the implant instead.
#[cfg(feature = "std")]
pub use transform::steps_from_block;
