//! Nyx transport fingerprint engine.
//!
//! The #1 way modern C2 traffic is caught at the edge is fingerprinting the
//! transport, not the HTTP layer: TLS [JA3]/[JA4] over the ClientHello, and the
//! [Akamai passive HTTP/2 fingerprint] over the frame sequence. This crate has
//! two halves:
//!
//! - **Computation/verification** (`tls`, `h2`): parse a TLS ClientHello and an
//!   HTTP/2 connection preface into structured fields and compute the same
//!   fingerprint strings defenders (Cloudflare, Akamai, Fastly) key on. The team
//!   server uses these to profile/allowlist connecting clients.
//! - **Emission** (`emitter`): the [`emitter::FingerprintEmitter`] trait is the
//!   seam where a browser-matching ClientHello is produced. Computing a
//!   fingerprint is not the same as emitting one; emission needs a TLS stack
//!   with controllable field order. The default (pure-Rust rustls) produces a
//!   configurable-but-not-Chrome-identical hello; the optional `rquest` backend
//!   (BoringSSL) emits exact Chrome/Firefox/Safari JA3/JA4.
//!
//! ## emission backend status
//! The `rquest` crate (BoringSSL, browser JA3/JA4 impersonation) was renamed
//! **`wreq`** by its author (0x676e67); rquest 5.x is yanked and wreq 6.0 is
//! still on a release-candidate track. So the emission backend is **not yet
//! pinned** — the [`emitter::FingerprintEmitter`] trait + `rquest` feature flag
//! exist as the seam, but the feature is a no-op until wreq 6.0 goes stable
//! (ROADMAP M5). The default pure-Rust rustls path works today; it just can't
//! produce a Chrome-identical ClientHello.
//!
//! [JA3]: https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/
//! [JA4]: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
//! [Akamai passive HTTP/2 fingerprint]: https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf

pub mod emitter;
pub mod h2;
pub mod tls;
pub mod traits;
pub mod llm_api;
pub mod doh_dns;
pub mod slack_api;
pub mod smb_pipe;
pub mod mcp;
pub mod webtransport;
pub mod malleable;

pub use h2::{akamai_h2, H2Fingerprint};
pub use tls::{ja3, ja4, parse_client_hello, sniff_client_hello, ClientHello};
