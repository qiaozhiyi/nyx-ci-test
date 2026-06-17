//! Malleable C2 HTTP *envelope* helpers.
//!
//! The transform engine ([`crate::transform`]) applies byte transforms to a
//! payload, but a profile's `server { output { ... } }` block also declares
//! *where* the transformed bytes go (header / parameter / body / uri-append)
//! and which response headers to set. This module turns a parsed profile into
//! ready-to-use request/response shaping so the team server can stop emitting
//! raw encrypted frames and instead make beacon traffic look like the
//! transaction the profile describes.
//!
//! Scope of M0: server-side response shaping only (what the server sends back
//! to the beacon). Client-side request shaping (what the beacon sends) is the
//! implant's job and is wired up alongside the PIC transport.

use crate::ast::{Block, Profile};
use crate::transform::{self, Terminator};

/// A fully-resolved description of how to shape the server→beacon response for
/// one transaction (`http-get` or `http-post`). Derived from the profile's
/// `server { output { ... } }` + `header` statements.
#[derive(Debug, Clone, Default)]
pub struct ServerEnvelope {
    /// Transform steps to apply to the encrypted frame body (in source order).
    pub steps: Vec<transform::Step>,
    /// Where the transformed body goes. `None` means "no output block; body is
    /// raw" (the legacy behaviour before profile envelopes were wired up).
    pub terminator: Option<Terminator>,
    /// `(name, value)` pairs from `header "N" "V";` statements in the server
    /// block, to set on the HTTP response.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
}

impl ServerEnvelope {
    /// Shape an encrypted frame body for the wire: apply the transform pipeline
    /// and, if the terminator is a header/parameter, return `(body, extra)`
    /// where `extra` is the bytes to inject there. For `print`/`uri-append`
    /// the bytes ride in the body itself, so `extra` is empty.
    pub fn shape_body(&self, frame: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let transformed = transform::encode(&self.steps, frame);
        match &self.terminator {
            Some(Terminator::Header(_)) | Some(Terminator::Parameter(_)) => {
                (Vec::new(), transformed)
            }
            Some(Terminator::Print) | Some(Terminator::UriAppend) | None => (transformed, Vec::new()),
        }
    }
}

/// Resolve the server-side envelope for the profile's `http-post` transaction
/// (the beacon's main task-delivery channel). Returns a default (no-op) envelope
/// when the profile has no `server { output { } }` block, so callers can always
/// apply it without a None-check.
pub fn post_server_envelope(profile: &Profile) -> ServerEnvelope {
    transaction_server_envelope(profile.http_post())
}

/// Resolve the server-side envelope for `http-get`.
pub fn get_server_envelope(profile: &Profile) -> ServerEnvelope {
    transaction_server_envelope(profile.http_get())
}

fn transaction_server_envelope(txn: Option<&Block>) -> ServerEnvelope {
    let Some(txn) = txn else {
        return ServerEnvelope::default();
    };
    let server = match txn.sub("server") {
        Some(s) => s,
        None => return ServerEnvelope::default(),
    };
    let mut env = ServerEnvelope::default();
    // The `output` data block carries the body transform chain + terminator.
    if let Some(output) = server.sub("output") {
        env.steps = transform::steps_from_block(output);
        env.terminator = terminator_of(output);
    }
    // `header "N" "V";` statements (both inside and outside data blocks in CS).
    for args in server.stmts("header") {
        if args.len() >= 2 {
            env.headers.push((args[0].0.clone(), args[1].0.clone()));
        }
    }
    env
}

/// The terminator of a data block = the last non-transform statement that
/// declares where bytes go (`header`, `parameter`, `print`, `uri-append`).
fn terminator_of(block: &Block) -> Option<Terminator> {
    for item in &block.items {
        if let crate::ast::Item::Stmt { keyword, args, .. } = item {
            match keyword.as_str() {
                "header" => {
                    return Some(Terminator::Header(
                        String::from_utf8_lossy(&args.first()?.0).into_owned(),
                    ));
                }
                "parameter" => {
                    return Some(Terminator::Parameter(
                        String::from_utf8_lossy(&args.first()?.0).into_owned(),
                    ));
                }
                "print" => return Some(Terminator::Print),
                "uri-append" => return Some(Terminator::UriAppend),
                _ => {}
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> Profile {
        crate::parse(src).expect("profile must parse")
    }

    #[test]
    fn empty_profile_is_noop_envelope() {
        let p = parse(
            r#"http-post { set uri "/p"; client { output { print; } } server { output { print; } } }"#,
        );
        let env = post_server_envelope(&p);
        assert_eq!(env.steps, vec![]);
        assert_eq!(env.terminator, Some(Terminator::Print));
        assert!(env.headers.is_empty());
    }

    #[test]
    fn output_transform_chain_is_extracted() {
        let p = parse(
            r#"http-post {
                set uri "/api/telemetry";
                client { output { base64; } }
                server {
                    output {
                        base64;
                        mask;
                        prepend "\x1f\x8b";
                        print;
                    }
                    header "Content-Type" "application/json";
                    header "X-Trace" "abc";
                }
            }"#,
        );
        let env = post_server_envelope(&p);
        assert_eq!(
            env.steps,
            vec![
                transform::Step::Base64,
                transform::Step::Mask,
                transform::Step::Prepend(vec![0x1f, 0x8b]),
            ]
        );
        assert_eq!(env.terminator, Some(Terminator::Print));
        assert_eq!(env.headers.len(), 2);
        assert_eq!(env.headers[0].0, b"Content-Type");
        assert_eq!(env.headers[0].1, b"application/json");
    }

    #[test]
    fn shaping_then_unshaping_roundtrips() {
        let p = parse(
            r#"http-post { set uri "/p"; client { output { print; } } server { output { base64; prepend "PRE"; append "POST"; print; } } }"#,
        );
        let env = post_server_envelope(&p);
        let frame = b"encrypted-frame-bytes-here";
        let (body, extra) = env.shape_body(frame);
        assert!(extra.is_empty(), "print terminator keeps bytes in body");
        assert!(body.starts_with(b"PRE"));
        assert!(body.ends_with(b"POST"));
        // The transform pipeline is invertible: decode(body) == frame.
        let restored = transform::decode(&env.steps, &body).unwrap();
        assert_eq!(restored, frame);
    }

    #[test]
    fn header_terminator_puts_bytes_in_extra() {
        let p = parse(
            r#"http-post { set uri "/p"; client { output { print; } } server { output { base64; header "Cookie"; } } }"#,
        );
        let env = post_server_envelope(&p);
        let (body, extra) = env.shape_body(b"hello");
        assert!(body.is_empty(), "body should be empty for header terminator");
        assert!(!extra.is_empty(), "transformed bytes go in extra");
    }
}
