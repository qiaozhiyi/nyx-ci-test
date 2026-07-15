//! Nyx transport fingerprint engine.
//!
//! The #1 way modern C2 traffic is caught at the edge is fingerprinting the
//! transport, not the HTTP layer: TLS [JA3]/[JA4] over the ClientHello, and the
//! [Akamai passive HTTP/2 fingerprint] over the frame sequence.
//!
//! - **Computation/verification** (`tls`, `h2`): parse a TLS ClientHello and an
//!   HTTP/2 connection preface into structured fields and compute the same
//!   fingerprint strings defenders (Cloudflare, Akamai, Fastly) key on. The team
//!   server uses these to profile/allowlist connecting clients.
//! - **Emission** (`fingerprint`): the inverse — the API surface and mapping
//!   logic for building an HTTP client whose ClientHello and HTTP/2 frames
//!   impersonate a real browser (Chrome/Firefox/Safari/Edge). The backend
//!   (BoringSSL `rquest`) is not yet wired — see `fingerprint` module docs.
//!
//! [JA3]: https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/
//! [JA4]: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
//! [Akamai passive HTTP/2 fingerprint]: https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf

pub mod doh_dns;
pub mod fingerprint;
pub mod h2;
pub mod llm_api;
pub mod malleable;
pub mod mcp;
pub mod slack_api;
pub mod smb_pipe;
pub mod tls;
pub mod traits;

pub use h2::{akamai_h2, H2Fingerprint};
pub use tls::{ja3, ja4, parse_client_hello, sniff_client_hello, ClientHello};
