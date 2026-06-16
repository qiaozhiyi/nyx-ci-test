//! Nyx transport fingerprint engine.
//!
//! The #1 way modern C2 traffic is caught at the edge is fingerprinting the
//! transport, not the HTTP layer: TLS [JA3]/[JA4] over the ClientHello, and the
//! [Akamai passive HTTP/2 fingerprint] over the frame sequence. This crate is
//! the **computation/verification half** of Nyx's answer: parse a TLS ClientHello
//! and an HTTP/2 connection preface into structured fields and compute the same
//! fingerprint strings defenders (Cloudflare, Akamai, Fastly) key on, so the
//! team server can profile / allowlist connecting clients and an operator can
//! pin a target.
//!
//! ## Honest boundary
//! Computing a fingerprint is not the same as **emitting** a browser-matching
//! one. Emission needs a TLS stack with controllable ClientHello field order
//! (BoringSSL / `rquest`), and `rquest` is currently **fully yanked on
//! crates.io** (all 2.x–5.x) — so the emission backend is a separate, native /
//! rustls-fork task. This crate gives you the engine to *target and verify* it.
//!
//! [JA3]: https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/
//! [JA4]: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
//! [Akamai passive HTTP/2 fingerprint]: https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf

pub mod h2;
pub mod tls;

pub use h2::{akamai_h2, H2Fingerprint};
pub use tls::{ja3, ja4, parse_client_hello, ClientHello};
