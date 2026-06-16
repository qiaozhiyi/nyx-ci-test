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

pub mod ast;
pub mod lexer;
pub mod lint;
pub mod parser;
pub mod transform;

pub use ast::{Block, Item, Profile, Setting, Str};
pub use lexer::LexError;
pub use lint::{lint, Diagnostic, Severity};
pub use parser::{parse, ParseError};
pub use transform::{decode, encode, steps_from_block, Step, Terminator, TransformError};
