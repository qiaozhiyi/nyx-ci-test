//! Minimal PE32+ (x86-64) parsing — sections, exports, relocations.
//!
//! Only the fields the raw-image extractor needs. All offsets are validated;
//! a malformed file is a hard error (a broken loader binary must never be
//! silently dumped).

use std::fmt;

#[derive(Debug)]
pub struct Section {
    pub name: String,
    /// Virtual address (RVA space).
    pub vaddr: u32,
    /// Virtual size (in-memory extent).
    pub vsize: u32,
    /// File offset of raw data.
    pub roff: u32,
    /// Raw data size on disk.
    pub rsize: u32,
}

#[derive(Debug)]
pub struct Pe {
    pub data: Vec<u8>,
    pub sections: Vec<Section>,
    pub image_base: u64,
}

#[derive(Debug)]
pub enum PeError {
    NotPe,
    BadOffset(&'static str),
    Truncated(&'static str),
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeError::NotPe => write!(f, "not a PE32+ image (bad MZ/PE signature)"),
            PeError::BadOffset(w) => write!(f, "malformed PE: bad {w} offset"),
            PeError::Truncated(w) => write!(f, "malformed PE: truncated {w}"),
        }
    }
}

impl Pe {
    pub fn parse(data: Vec<u8>) -> Result<Pe, PeError> {
        if data.len() < 0x40 || &data[..2] != b"MZ" {
            return Err(PeError::NotPe);
        }
        let pe_off = rd32(&data, 0x3C).ok_or(PeError::BadOffset("PE header"))? as usize;
        if pe_off + 24 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
            return Err(PeError::NotPe);
        }
        let coff = pe_off + 4;
        let machine = rd16(&data, coff).ok_or(PeError::Truncated("COFF header"))?;
        if machine != 0x8664 {
            return Err(PeError::BadOffset("machine (want x86-64)"));
        }
        let nsec = rd16(&data, coff + 2).ok_or(PeError::Truncated("COFF header"))? as usize;
        let opt_size = rd16(&data, coff + 16).ok_or(PeError::Truncated("COFF header"))? as usize;
        let opt = coff + 20;
        if opt + opt_size > data.len() {
            return Err(PeError::Truncated("optional header"));
        }
        let magic = rd16(&data, opt).ok_or(PeError::Truncated("optional header"))?;
        if magic != 0x20B {
            return Err(PeError::BadOffset("optional header magic (want PE32+)"));
        }
        let image_base = rd64(&data, opt + 24).ok_or(PeError::Truncated("ImageBase"))?;
        let sec_off = opt + opt_size;
        if sec_off + nsec * 40 > data.len() {
            return Err(PeError::Truncated("section table"));
        }
        let mut sections = Vec::with_capacity(nsec);
        for i in 0..nsec {
            let s = sec_off + i * 40;
            let raw_name = &data[s..s + 8];
            let name = raw_name
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as char)
                .collect::<String>();
            let vsize = rd32(&data, s + 8).ok_or(PeError::Truncated("section"))?;
            let vaddr = rd32(&data, s + 12).ok_or(PeError::Truncated("section"))?;
            let rsize = rd32(&data, s + 16).ok_or(PeError::Truncated("section"))?;
            let roff = rd32(&data, s + 20).ok_or(PeError::Truncated("section"))?;
            sections.push(Section { name, vaddr, vsize, roff, rsize });
        }
        Ok(Pe { data, sections, image_base })
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// File offset for an RVA, or None.
    pub fn rva_to_off(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            if rva >= s.vaddr && rva < s.vaddr + s.vsize.max(s.rsize) {
                return Some(s.roff as usize + (rva - s.vaddr) as usize);
            }
        }
        None
    }

    /// RVA → section name, or None.
    pub fn section_at(&self, rva: u32) -> Option<&str> {
        for s in &self.sections {
            if rva >= s.vaddr && rva < s.vaddr + s.vsize.max(s.rsize) {
                return Some(&s.name);
            }
        }
        None
    }

    /// Raw bytes of a section (as stored on disk).
    pub fn section_bytes(&self, name: &str) -> Option<&[u8]> {
        let s = self.section(name)?;
        Some(&self.data[s.roff as usize..s.roff as usize + s.rsize as usize])
    }

    /// Resolve the exported function named `name`; returns its RVA.
    pub fn export_rva(&self, name: &str) -> Option<u32> {
        let s = self.section(".edata")?;
        let b = self.section_bytes(".edata")?;
        if b.len() < 40 {
            return None;
        }
        let n_names = rd32(b, 24)?;
        let eat_rva = rd32(b, 28)?;
        let ent_rva = rd32(b, 32)?;
        for i in 0..n_names as usize {
            let nrva = rd32(b, (ent_rva.checked_sub(s.vaddr)? as usize) + 4 * i)?;
            let noff = self.rva_to_off(nrva)?;
            let bytes = &self.data[noff..];
            let end = bytes.iter().position(|&x| x == 0).unwrap_or(bytes.len());
            if &bytes[..end] == name.as_bytes() {
                return rd32(b, (eat_rva.checked_sub(s.vaddr)? as usize) + 4 * i);
            }
        }
        None
    }

    /// All base-relocation targets (RVAs). The extractor requires the image to
    /// have NONE (raw shellcode cannot be fixed up), so any relocation is a
    /// hard error upstream.
    pub fn reloc_targets(&self) -> Vec<u32> {
        let Some(s) = self.section(".reloc") else { return Vec::new() };
        let Some(b) = self.section_bytes(".reloc") else { return Vec::new() };
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + 8 <= b.len() {
            let Some(page) = rd32(b, i) else { break };
            let Some(size) = rd32(b, i + 4) else { break };
            if size == 0 || size < 8 || (i + size as usize) > b.len() {
                break;
            }
            let n = ((size as usize) - 8) / 2;
            for j in 0..n {
                let ent = rd16(b, i + 8 + 2 * j).unwrap_or(0);
                let typ = ent >> 12;
                if typ != 0 {
                    // 0 = ABSOLUTE (padding, harmless); anything else is a
                    // real fixup we cannot honour in raw shellcode.
                    out.push(page + (ent & 0xFFF) as u32);
                }
            }
            i += size as usize;
        }
        out
    }
}

fn rd16(b: &[u8], o: usize) -> Option<u16> {
    if o + 2 > b.len() {
        None
    } else {
        Some(u16::from_le_bytes([b[o], b[o + 1]]))
    }
}

fn rd32(b: &[u8], o: usize) -> Option<u32> {
    if o + 4 > b.len() {
        None
    } else {
        Some(u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]))
    }
}

fn rd64(b: &[u8], o: usize) -> Option<u64> {
    if o + 8 > b.len() {
        None
    } else {
        Some(u64::from_le_bytes([
            b[o],
            b[o + 1],
            b[o + 2],
            b[o + 3],
            b[o + 4],
            b[o + 5],
            b[o + 6],
            b[o + 7],
        ]))
    }
}
