//! PE export-directory resolver — a foundation for the position-independent
//! implant.
//!
//! The PIC implant can't call `GetProcAddress`; it walks a loaded module's bytes
//! directly. This module parses a PE (DLL) image's DOS/NT headers + section
//! table + export directory and resolves an exported function **name → RVA**
//! (add the module base address to call it). Pure Rust, no_std-friendly, tested
//! here against a real DLL file. The implant applies the same logic to a loaded
//! module's in-memory image (where RVA == offset from base, so the section
//! RVA→file-offset mapping is identity).

const MAGIC_MZ: u16 = 0x5A4D;
const MAGIC_PE32_PLUS: u16 = 0x020B;
const SIGNATURE_PE: u32 = 0x00004550; // "PE\0\0"

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_ptr: u32,
}

/// Resolve an exported function `fn_name` to its RVA within `image`, or `None`.
pub fn resolve_export(image: &[u8], fn_name: &str) -> Option<u32> {
    let nt = nt_headers_off(image)?;
    let opt_off = nt + 4 + 20; // signature(4) + IMAGE_FILE_HEADER(20)
    let magic = u16le(image, opt_off);
    // DataDirectory starts at optional-header offset 112 (PE32+) or 96 (PE32).
    let dd_off = opt_off + if magic == MAGIC_PE32_PLUS { 112 } else { 96 };
    let export_rva = u32le(image, dd_off);
    let _export_size = u32le(image, dd_off + 4);
    if export_rva == 0 {
        return None;
    }

    let sections = parse_sections(image, nt)?;
    let edir = rva_to_offset(&sections, export_rva)?;
    // IMAGE_EXPORT_DIRECTORY: NumberOfNames@+24, AddressOfFunctions@+28,
    // AddressOfNames@+32, AddressOfNameOrdinals@+36.
    let n_names = u32le(image, edir + 24) as usize;
    let funcs_off = rva_to_offset(&sections, u32le(image, edir + 28))?;
    let names_off = rva_to_offset(&sections, u32le(image, edir + 32))?;
    let ords_off = rva_to_offset(&sections, u32le(image, edir + 36))?;

    for i in 0..n_names {
        let name_rva = u32le(image, names_off + i * 4);
        if let Some(name_off) = rva_to_offset(&sections, name_rva) {
            if cstr_at(image, name_off) == fn_name {
                let ordinal = u16le(image, ords_off + i * 2) as usize;
                return Some(u32le(image, funcs_off + ordinal * 4));
            }
        }
    }
    None
}

fn nt_headers_off(image: &[u8]) -> Option<usize> {
    if image.len() < 0x40 || u16le(image, 0) != MAGIC_MZ {
        return None;
    }
    let e_lfanew = u32le(image, 0x3C) as usize;
    if e_lfanew + 4 > image.len() || u32le(image, e_lfanew) != SIGNATURE_PE {
        return None;
    }
    Some(e_lfanew)
}

fn parse_sections(image: &[u8], nt_off: usize) -> Option<Vec<Section>> {
    let n_sec = u16le(image, nt_off + 4 + 2) as usize; // NumberOfSections
    let opt_size = u16le(image, nt_off + 4 + 16) as usize; // SizeOfOptionalHeader
    let sec_off = nt_off + 4 + 20 + opt_size;
    let mut out = Vec::with_capacity(n_sec);
    for i in 0..n_sec {
        let so = sec_off + i * 40;
        if so + 40 > image.len() {
            break;
        }
        out.push(Section {
            virtual_size: u32le(image, so + 8),
            virtual_address: u32le(image, so + 12),
            raw_ptr: u32le(image, so + 20),
        });
    }
    Some(out)
}

fn rva_to_offset(sections: &[Section], rva: u32) -> Option<usize> {
    for s in sections {
        let va = s.virtual_address;
        let vsize = if s.virtual_size != 0 { s.virtual_size } else { u32::MAX };
        if rva >= va && rva < va.saturating_add(vsize) {
            return Some((rva - va + s.raw_ptr) as usize);
        }
    }
    None
}

fn cstr_at(image: &[u8], off: usize) -> &str {
    let end = image[off..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(image.len() - off);
    std::str::from_utf8(&image[off..off + end]).unwrap_or("")
}
