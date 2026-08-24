//! `c2lint` — validate a parsed Malleable C2 profile.
//!
//! Mirrors the spirit of Cobalt Strike's `c2lint`: catch profiles that will
//! break at runtime (missing required blocks, a data transform with no
//! terminator) and flag ones that are functional but noisy (Beacon-default
//! user-agent, a URI that doesn't start with `/`, an out-of-range jitter).

use crate::ast::{Item, Profile};

/// Diagnostic severity. `c2lint` exits non-zero iff at least one `Error` exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Note,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub severity: Severity,
    pub line: u32,
    pub message: String,
}

/// Statements that transform bytes inside a `output`/`metadata`/`id` block.
const TRANSFORMS: &[&str] = &[
    "base64",
    "base64url",
    "netbios",
    "netbiosu",
    "mask",
    "prepend",
    "append",
];
/// Statements that terminate a data block (place the result on the wire).
const TERMINATORS: &[&str] = &["header", "parameter", "print", "uri-append"];

/// Substrings that mark a user-agent as a known Beacon default (a classic IOC).
const DEFAULT_UA_FRAGMENTS: &[&str] = &["compatible; MSIE", "CobaltStrike", "Beacon"];

/// Legal values for the top-level `set timing_baseline` (traffic cadence).
const TIMING_BASELINES: &[&str] = &["uniform", "bursty"];

/// Padding above this size gets a Note: oversized bodies are themselves an
/// IOC (and the self-delimiting length suffix caps at
/// [`crate::transform::PAD_LEN_CAP`], above which the envelope clamps).
const LARGE_PADDING_BYTES: u64 = 4096;

/// Lint a profile. Returns diagnostics in source order; a profile with no
/// `Error`s gets a trailing `Note: profile OK`.
pub fn lint(p: &Profile) -> Vec<Diagnostic> {
    let mut d = Vec::new();

    let get = p.http_get();
    let post = p.http_post();
    if get.is_none() {
        d.push(err(0, "no `http-get` block (required)"));
    }
    if post.is_none() {
        d.push(err(0, "no `http-post` block (required)"));
    }

    for (name, blk) in [("http-get", get), ("http-post", post)] {
        let Some(b) = blk else { continue };
        match b.get("uri") {
            None => d.push(err(b.line, format!("{name}: missing `set uri`"))),
            Some(u) => {
                let s = u.as_str();
                if !s.starts_with('/') {
                    d.push(warn(
                        b.line,
                        format!("{name}: uri {s:?} should start with '/'"),
                    ));
                }
                // CRLF in the request URI enables request-line splitting when
                // the transport builds the HTTP request line from this value.
                if has_crlf(s) {
                    d.push(err(
                        b.line,
                        format!("{name}: uri contains CR/LF (HTTP request-splitting risk)"),
                    ));
                }
            }
        }
        if let Some(v) = b.get("verb") {
            let s = v.as_str();
            if !matches!(&*s, "GET" | "POST") {
                d.push(warn(
                    b.line,
                    format!("{name}: verb {s:?} should be GET or POST"),
                ));
            }
        }
        for side in ["client", "server"] {
            if let Some(sb) = b.sub(side) {
                check_data_blocks(side, sb, &mut d);
                // Recursively reject CR/LF in any `header`/`parameter`/
                // `uri-append` statement args anywhere under this side — those
                // bytes ride on the wire (headers / query / URL) where a stray
                // CR or LF splits the HTTP message.
                check_no_crlf_in_wire_stmts(sb, &mut d);
            }
        }
    }

    // useragent
    match p.option("useragent") {
        None => d.push(warn(
            0,
            "no `set useragent` (Beacon's default is a well-known IOC)",
        )),
        Some(u) => {
            let s = u.as_str();
            if DEFAULT_UA_FRAGMENTS.iter().any(|frag| s.contains(frag)) {
                d.push(warn(0, "useragent matches a known Beacon default"));
            }
            // `set useragent` is baked verbatim into the implant's User-Agent
            // header on every check-in — CR/LF there is header injection /
            // request splitting, the same class the block-level scan rejects.
            if has_crlf(s) {
                d.push(err(
                    0,
                    "`set useragent` contains CR/LF (HTTP header injection risk)",
                ));
            }
        }
    }

    // jitter / sleeptime sanity
    if let Some(j) = p.option("jitter") {
        if let Ok(n) = j.as_str().parse::<u32>() {
            if n > 100 {
                d.push(err(0, format!("jitter {n}% is out of range (0-100)")));
            }
        }
    }
    if let Some(s) = p.option("sleeptime") {
        if s.as_str().parse::<u64>().is_err() {
            d.push(warn(0, "`sleeptime` is not a number"));
        }
    }

    // ---- traffic-metadata shaping (padding / timing baseline) --------------
    // Content-layer mimicry alone leaves timing and packet-length distributions
    // as a detectable residue — metadata-only detection of CS Malleable C2 is
    // practical (Striking Back At Cobalt, arXiv:2506.08922).
    let pad_min = padding_option(p, "padding_min", &mut d);
    let pad_max = padding_option(p, "padding_max", &mut d);
    if let (Some(min), Some(max)) = (pad_min, pad_max) {
        if min > max {
            d.push(err(0, format!("padding_min {min} > padding_max {max}")));
        }
    }
    if let Some(max) = pad_max {
        if max > LARGE_PADDING_BYTES {
            d.push(note(
                0,
                format!(
                    "padding_max {max} is large — oversized bodies are themselves an IOC \
                     (also clamped to {} by the length suffix encoding)",
                    crate::transform::PAD_LEN_CAP
                ),
            ));
        }
    }
    if let Some(tb) = p.option("timing_baseline") {
        let s = tb.as_str();
        if !TIMING_BASELINES.contains(&s.as_ref()) {
            d.push(err(
                0,
                format!("unknown `timing_baseline` {s:?} (expected uniform|bursty)"),
            ));
        }
    }
    if p.option("padding_min").is_none()
        && p.option("padding_max").is_none()
        && p.option("timing_baseline").is_none()
    {
        d.push(warn(
            0,
            "no `padding_min/max` or `timing_baseline` set — content-layer mimicry alone \
             does not counter metadata-level detection (timing / packet-length / cadence; \
             cf. Striking Back At Cobalt, arXiv:2506.08922)",
        ));
    }

    // duplicate top-level blocks
    for name in [
        "http-get",
        "http-post",
        "http-stager",
        "stage",
        "process-inject",
        "post-ex",
    ] {
        let n = p.blocks(name).count();
        if n > 1 {
            d.push(warn(
                0,
                format!("{n} `{name}` blocks (CS allows named variants; usually one)"),
            ));
        }
    }

    if !d.iter().any(|x| x.severity == Severity::Error) {
        d.push(note(0, "profile OK"));
    }
    d
}

fn check_data_blocks(side: &str, side_block: &crate::ast::Block, d: &mut Vec<Diagnostic>) {
    let dbs = side_block
        .subs("output")
        .chain(side_block.subs("metadata"))
        .chain(side_block.subs("id"));
    for db in dbs {
        let mut terms = 0usize;
        // The RESOLVED terminator is the FIRST terminator statement in the
        // block (envelope.rs::terminator_of) — the downstream enforcement
        // points (implant-win/build.rs emit_envelopes, the server's
        // handle_beacon bail) check exactly that resolved value, so mirror
        // them here instead of counting every terminator occurrence.
        let mut seen_first_term = false;
        for item in &db.items {
            if let Item::Stmt { keyword, line, .. } = item {
                let kw = keyword.as_str();
                if TRANSFORMS.contains(&kw) {
                    // transform step
                } else if TERMINATORS.contains(&kw) {
                    if !seen_first_term {
                        seen_first_term = true;
                        // Capability matrix: the shipping implant/server pair
                        // cannot serve a client-side `parameter` terminator
                        // (the server bails every check-in,
                        // server/src/lib.rs:1135-1137, and the implant build
                        // panics) nor a server-response `header` terminator
                        // (the implant never queries response headers;
                        // implant-win/build.rs panics). A clean lint verdict
                        // for a profile that hard-fails downstream is a trap.
                        if side == "client" && kw == "parameter" {
                            d.push(err(
                                *line,
                                format!(
                                    "`{}`: client `parameter` terminator is unsupported \
                                     (server bails every check-in; implant build panics)",
                                    db.name
                                ),
                            ));
                        }
                        if side == "server" && kw == "header" {
                            d.push(err(
                                *line,
                                format!(
                                    "`{}`: server `header` terminator is unsupported \
                                     (implant never queries response headers; build panics)",
                                    db.name
                                ),
                            ));
                        }
                    }
                    terms += 1;
                } else {
                    d.push(err(
                        *line,
                        format!("`{}`: unknown statement `{}`", db.name, kw),
                    ));
                }
            }
        }
        if terms == 0 {
            d.push(err(
                db.line,
                format!(
                    "`{}` block has no terminator (need one of header/parameter/print/uri-append)",
                    db.name
                ),
            ));
        } else if terms > 1 {
            d.push(warn(
                db.line,
                format!(
                    "`{}` block has {terms} terminators (expected exactly 1)",
                    db.name
                ),
            ));
        }
    }
}

/// Does `s` contain a CR or LF byte? Those are the request-splitting characters
/// for HTTP (a bare CR or LF, or CRLF, can terminate a header/request line in
/// many parsers and frontends).
fn has_crlf(s: impl AsRef<str>) -> bool {
    let s = s.as_ref();
    s.contains('\r') || s.contains('\n')
}

/// Walk a block tree and reject CR/LF in any statement whose args end up on the
/// HTTP wire as headers (`header`), query parameters (`parameter`), or URL
/// suffix (`uri-append`). A CR/LF there splits the HTTP message — header
/// injection / request smuggling. Recurses into nested blocks.
fn check_no_crlf_in_wire_stmts(block: &crate::ast::Block, d: &mut Vec<Diagnostic>) {
    /// Statements whose string args are reflected into HTTP headers / the
    /// request line / the query string and therefore must not contain CR/LF.
    const WIRE_STMTS: &[&str] = &["header", "parameter", "uri-append"];
    fn walk(b: &crate::ast::Block, d: &mut Vec<Diagnostic>) {
        for item in &b.items {
            if let Item::Stmt {
                keyword,
                args,
                line,
            } = item
            {
                if WIRE_STMTS.contains(&keyword.as_str()) {
                    for arg in args {
                        if has_crlf(arg.as_str()) {
                            d.push(err(*line, format!("`{}` statement arg contains CR/LF (HTTP header/request splitting risk)", keyword)));
                        }
                    }
                }
            }
            if let Item::Block(inner) = item {
                walk(inner, d);
            }
        }
    }
    walk(block, d);
}

/// Parse a top-level padding option (`padding_min`/`padding_max`) as a byte
/// count. Non-numeric values are a hard Error (the runtime would silently
/// treat them as 0); absent → `None`.
fn padding_option(p: &Profile, key: &str, d: &mut Vec<Diagnostic>) -> Option<u64> {
    let v = p.option(key)?;
    let s = v.as_str();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        d.push(err(
            0,
            format!("`{key}` must be a byte count (digits only), got {s:?}"),
        ));
        return None;
    }
    s.parse::<u64>().ok()
}

fn err(line: u32, msg: impl Into<String>) -> Diagnostic {
    Diagnostic {
        severity: Severity::Error,
        line,
        message: msg.into(),
    }
}
fn warn(line: u32, msg: impl Into<String>) -> Diagnostic {
    Diagnostic {
        severity: Severity::Warning,
        line,
        message: msg.into(),
    }
}
fn note(line: u32, msg: impl Into<String>) -> Diagnostic {
    Diagnostic {
        severity: Severity::Note,
        line,
        message: msg.into(),
    }
}
