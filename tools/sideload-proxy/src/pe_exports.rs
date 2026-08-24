//! Self-contained PE export-table parser.
//!
//! Deliberately does NOT use goblin: `goblin::pe::PE::exports` walks only the
//! name-pointer table, so ordinal-only exports (NONAME, address-table entries
//! with no name) are invisible through it. A proxy generator that drops those
//! produces a broken proxy (the host resolves the ordinal and crashes), so we
//! parse the export directory directly:
//!
//! - every named export (name + ordinal + optional forwarder string),
//! - every ordinal-only export (no name, ordinal from address-table index),
//! - forwarder detection (export RVA inside the export-directory range means
//!   the "function address" is actually a `DLL.Func` / `DLL.#ord` string).
//!
//! Only what the generator needs is implemented; this is not a general PE
//! parser. All reads are bounds-checked; malformed input is an error, never a
//! panic (best effort — adversarial fuzzing has NOT been done).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedSymbol {
    /// Export name, or `None` for ordinal-only (NONAME) exports.
    pub name: Option<String>,
    /// Ordinal (ordinal base already added).
    pub ordinal: u32,
    /// Forwarder string (e.g. `KERNEL32.Sleep`) when the *original* DLL
    /// forwards this export to another DLL. The proxy still forwards to the
    /// original DLL — the Windows loader chains forwarders — so this is
    /// informational, but we surface it so operators see unusual targets.
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExportTable {
    /// DLL name stored in the export directory (often the original filename).
    pub dll_name: Option<String>,
    /// All exports, sorted by ordinal.
    pub symbols: Vec<ExportedSymbol>,
}

#[derive(Debug)]
pub enum ParseError {
    Truncated(&'static str),
    BadSignature(&'static str),
    NoExportDirectory,
    Malformed(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated(what) => write!(f, "truncated PE: {what}"),
            ParseError::BadSignature(what) => write!(f, "bad signature: {what}"),
            ParseError::NoExportDirectory => write!(f, "PE has no export directory"),
            ParseError::Malformed(msg) => write!(f, "malformed PE: {msg}"),
        }
    }
}

impl std::error::Error for ParseError {}

type Result<T> = std::result::Result<T, ParseError>;

fn u16_at(b: &[u8], off: usize) -> Result<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(ParseError::Truncated("u16 read out of bounds"))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(ParseError::Truncated("u32 read out of bounds"))
}

fn cstr_at(b: &[u8], off: usize) -> Result<String> {
    let s = b
        .get(off..)
        .ok_or(ParseError::Truncated("string offset out of bounds"))?;
    let end = s
        .iter()
        .position(|&c| c == 0)
        .ok_or(ParseError::Truncated("unterminated string"))?;
    String::from_utf8(s[..end].to_vec())
        .map_err(|_| ParseError::Malformed("non-UTF8 export name".into()))
}

struct Section {
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_ptr: u32,
}

impl Section {
    fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        // The loader maps max(virtual_size, raw_size) bytes; use the larger
        // span so RVAs into zero-padded tails still resolve.
        let span = self.virtual_size.max(self.raw_size);
        if rva >= self.virtual_address && rva < self.virtual_address + span {
            let off = (rva - self.virtual_address + self.raw_ptr) as usize;
            Some(off)
        } else {
            None
        }
    }
}

/// Parse the export table of a PE32/PE32+ image.
pub fn parse_exports(b: &[u8]) -> Result<ExportTable> {
    // DOS header → e_lfanew.
    if b.len() < 0x40 || b[0] != b'M' || b[1] != b'Z' {
        return Err(ParseError::BadSignature("missing MZ"));
    }
    let pe_off = u32_at(b, 0x3C)? as usize;
    if b.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return Err(ParseError::BadSignature("missing PE\\0\\0"));
    }
    let coff = pe_off + 4;
    let num_sections = u16_at(b, coff + 2)? as usize;
    let opt_size = u16_at(b, coff + 16)? as usize;
    let opt = coff + 20;
    let magic = u16_at(b, opt)?;
    // Data-directory array start (directory 0 = export table).
    let dir0 = match magic {
        0x10B => opt + 96,  // PE32
        0x20B => opt + 112, // PE32+
        _ => return Err(ParseError::BadSignature("unknown optional-header magic")),
    };
    let export_rva = u32_at(b, dir0)?;
    let export_size = u32_at(b, dir0 + 4)?;
    if export_rva == 0 || export_size == 0 {
        return Err(ParseError::NoExportDirectory);
    }

    // Section headers.
    let sec_base = opt + opt_size;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = sec_base + i * 40;
        sections.push(Section {
            virtual_size: u32_at(b, s + 8)?,
            virtual_address: u32_at(b, s + 12)?,
            raw_size: u32_at(b, s + 16)?,
            raw_ptr: u32_at(b, s + 20)?,
        });
    }
    let rva_to_off = |rva: u32, what: &'static str| -> Result<usize> {
        sections
            .iter()
            .find_map(|s| s.rva_to_offset(rva))
            .filter(|&off| off < b.len())
            .ok_or(ParseError::Malformed(format!(
                "cannot map {what} RVA {rva:#x} to a file offset"
            )))
    };

    let dir_off = rva_to_off(export_rva, "export directory")?;
    let dll_name = {
        let name_rva = u32_at(b, dir_off + 12)?;
        if name_rva != 0 {
            Some(cstr_at(b, rva_to_off(name_rva, "DLL name")?)?)
        } else {
            None
        }
    };
    let ordinal_base = u32_at(b, dir_off + 16)?;
    let num_funcs = u32_at(b, dir_off + 20)? as usize;
    let num_names = u32_at(b, dir_off + 24)? as usize;
    let funcs_rva = u32_at(b, dir_off + 28)?;
    let names_rva = u32_at(b, dir_off + 32)?;
    let ords_rva = u32_at(b, dir_off + 36)?;
    let funcs_off = rva_to_off(funcs_rva, "export address table")?;
    let names_off = rva_to_off(names_rva, "name pointer table")?;
    let ords_off = rva_to_off(ords_rva, "ordinal table")?;

    let mut symbols: Vec<ExportedSymbol> = Vec::new();
    let mut named_ords: Vec<u16> = Vec::with_capacity(num_names);

    // An export RVA inside the export-directory range is a forwarder string
    // RVA, not code (per the PE spec — this is how the loader distinguishes).
    let fwd_lo = export_rva;
    let fwd_hi = export_rva.saturating_add(export_size);

    for i in 0..num_names {
        let name_rva = u32_at(b, names_off + i * 4)?;
        let ord_idx = u16_at(b, ords_off + i * 2)?;
        named_ords.push(ord_idx);
        let func_rva = u32_at(b, funcs_off + ord_idx as usize * 4)?;
        let forwarder = if func_rva >= fwd_lo && func_rva < fwd_hi {
            Some(cstr_at(b, rva_to_off(func_rva, "forwarder string")?)?)
        } else {
            None
        };
        symbols.push(ExportedSymbol {
            name: Some(cstr_at(b, rva_to_off(name_rva, "export name")?)?),
            ordinal: ordinal_base + ord_idx as u32,
            forwarder,
        });
    }

    // Ordinal-only exports: address-table slots not referenced by any name.
    for j in 0..num_funcs {
        if named_ords.contains(&(j as u16)) {
            continue;
        }
        let func_rva = u32_at(b, funcs_off + j * 4)?;
        if func_rva == 0 {
            continue; // hole in the address table — nothing exported here
        }
        let forwarder = if func_rva >= fwd_lo && func_rva < fwd_hi {
            Some(cstr_at(b, rva_to_off(func_rva, "forwarder string")?)?)
        } else {
            None
        };
        symbols.push(ExportedSymbol {
            name: None,
            ordinal: ordinal_base + j as u32,
            forwarder,
        });
    }

    symbols.sort_by_key(|s| s.ordinal);
    Ok(ExportTable { dll_name, symbols })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal PE32+ image with:
    /// - ordinal base 1, 4 address-table slots
    /// - `FuncA` @1 (plain RVA), `SleepFwd` @2 (forwarder "KERNEL32.Sleep")
    /// - slot 3 = hole (RVA 0), slot 4 = ordinal-only export @4
    /// - DLL name "orig.dll"
    fn build_test_pe() -> Vec<u8> {
        let mut b = vec![0u8; 0x800];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        // COFF: 1 section, optional header 0xF0.
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        b[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        let opt = 0x98;
        b[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        // NumberOfRvaAndSizes @ opt+108; data dir 0 @ opt+112.
        b[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        b[opt + 112..opt + 116].copy_from_slice(&0x1000u32.to_le_bytes()); // export RVA
        b[opt + 116..opt + 120].copy_from_slice(&0x200u32.to_le_bytes()); // export size
        // Section ".edata": vsize 0x600, vaddr 0x1000, raw 0x600 @ 0x200.
        let s = opt + 0xF0;
        b[s..s + 6].copy_from_slice(b".edata");
        b[s + 8..s + 12].copy_from_slice(&0x600u32.to_le_bytes());
        b[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[s + 16..s + 20].copy_from_slice(&0x600u32.to_le_bytes());
        b[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes());
        // Export directory @ file 0x200 (RVA 0x1000).
        let d = 0x200;
        b[d + 12..d + 16].copy_from_slice(&0x1080u32.to_le_bytes()); // Name
        b[d + 16..d + 20].copy_from_slice(&1u32.to_le_bytes()); // Base
        b[d + 20..d + 24].copy_from_slice(&4u32.to_le_bytes()); // NumberOfFunctions
        b[d + 24..d + 28].copy_from_slice(&2u32.to_le_bytes()); // NumberOfNames
        b[d + 28..d + 32].copy_from_slice(&0x1028u32.to_le_bytes()); // AddressOfFunctions
        b[d + 32..d + 36].copy_from_slice(&0x1038u32.to_le_bytes()); // AddressOfNames
        b[d + 36..d + 40].copy_from_slice(&0x1040u32.to_le_bytes()); // AddressOfNameOrdinals
        // Address table @ file 0x228: FuncA(0x3000), fwd str(0x1090), hole, ordinal-only(0x3200).
        let funcs = [0x3000u32, 0x1090, 0, 0x3200];
        for (i, rva) in funcs.iter().enumerate() {
            b[0x228 + i * 4..0x22C + i * 4].copy_from_slice(&rva.to_le_bytes());
        }
        // Name pointer table @ 0x238 → 0x1060 "FuncA", 0x1068 "SleepFwd".
        b[0x238..0x23C].copy_from_slice(&0x1060u32.to_le_bytes());
        b[0x23C..0x240].copy_from_slice(&0x1068u32.to_le_bytes());
        // Ordinal table @ 0x240: slots 0 and 1.
        b[0x240..0x242].copy_from_slice(&0u16.to_le_bytes());
        b[0x242..0x244].copy_from_slice(&1u16.to_le_bytes());
        // Strings.
        b[0x260..0x266].copy_from_slice(b"FuncA\0");
        b[0x268..0x271].copy_from_slice(b"SleepFwd\0");
        b[0x280..0x289].copy_from_slice(b"orig.dll\0");
        b[0x290..0x29F].copy_from_slice(b"KERNEL32.Sleep\0");
        b
    }

    #[test]
    fn parses_named_forwarded_hole_and_ordinal_only() {
        let table = parse_exports(&build_test_pe()).unwrap();
        assert_eq!(table.dll_name.as_deref(), Some("orig.dll"));
        assert_eq!(
            table.symbols,
            vec![
                ExportedSymbol {
                    name: Some("FuncA".into()),
                    ordinal: 1,
                    forwarder: None,
                },
                ExportedSymbol {
                    name: Some("SleepFwd".into()),
                    ordinal: 2,
                    forwarder: Some("KERNEL32.Sleep".into()),
                },
                ExportedSymbol {
                    name: None,
                    ordinal: 4,
                    forwarder: None,
                },
            ]
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            parse_exports(b"not a pe"),
            Err(ParseError::BadSignature(_))
        ));
        let mut pe = build_test_pe();
        pe.truncate(0x100); // cut before the export directory contents
        assert!(parse_exports(&pe).is_err());
    }
}
