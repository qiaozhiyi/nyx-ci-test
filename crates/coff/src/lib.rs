//! Nyx COFF / BOF loader *core* — parse a Windows x86_64 COFF object file and
//! apply its AMD64 relocations against a symbol-resolver table.
//!
//! This is the portable, unit-testable half of the BOF loader: a Beacon Object
//! File is just a COFF `.o` whose external references (`BeaconPrintf`,
//! `BeaconDataParse`, …) the loader resolves against the host's Beacon API and
//! whose section bytes it relocates into executable memory. Parsing +
//! relocation are pure functions over bytes, so they compile and test on any
//! host with a real fixture `.o` (here: one cross-compiled with
//! `clang --target=x86_64-pc-windows-msvc`). The actual allocation + execution
//! (module stomping, `CreateThread`) is the Windows PIC implant's job.
//!
//! ## AMD64 relocation types handled
//! `ADDR64` (0x01), `ADDR32` (0x02), `ADDR32NB` (0x03), `REL32` (0x04),
//! `REL32_1..5` (0x05..0x09). `ABSOLUTE` (0x00) is skipped. Others return
//! [`ApplyError::UnsupportedReloc`] (extend as needed).
//!
//! `REL32_N` follows the PE/COFF spec: the loader applies
//! `(target - (field_loc + 4 + N))`, where N is the `_N` suffix.
//!
//! `#![no_std]`-compatible (uses only `alloc`): the parser is pure byte-work,
//! so it links into a Windows PIC implant as well as the std dev agent. The
//! error type is hand-rolled (no `thiserror` derive) to keep `no_std`.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// `IMAGE_FILE_MACHINE_AMD64`.
pub const MACHINE_AMD64: u16 = 0x8664;

/// AMD64 relocation type constants (subset), per the PE/COFF spec (winnt.h
/// `IMAGE_REL_AMD64_*`). NOTE: the numbering is NOT contiguous in the way one
/// might expect — `ADDR32NB` is 0x0003 and plain `REL32` is 0x0004, so the
/// `REL32_N` family starts at 0x0005. An earlier revision of this table had
/// every value from `ADDR32NB` on shifted down by one, which made plain REL32
/// (what both clang and MinGW GCC emit for ordinary call/lea) decode as
/// REL32_1 and shifted every branch target by a byte.
pub mod reloc {
    pub const ABSOLUTE: u16 = 0x0000;
    pub const ADDR64: u16 = 0x0001;
    pub const ADDR32: u16 = 0x0002;
    pub const ADDR32NB: u16 = 0x0003;
    pub const REL32: u16 = 0x0004;
    /// First of the REL32_1..REL32_5 family (0x05..=0x09).
    pub const REL32_1: u16 = 0x0005;
    pub const REL32_2: u16 = 0x0006;
    pub const REL32_3: u16 = 0x0007;
    pub const REL32_4: u16 = 0x0008;
    pub const REL32_5: u16 = 0x0009;
}

#[derive(Debug)]
pub enum CoffError {
    Truncated,
    UnsupportedMachine(u16),
}

impl core::fmt::Display for CoffError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CoffError::Truncated => f.write_str("truncated COFF input"),
            CoffError::UnsupportedMachine(m) => {
                write!(f, "unsupported machine 0x{m:04x} (only AMD64)")
            }
        }
    }
}

#[derive(Debug)]
pub enum ApplyError {
    BadSymbolIndex(u32),
    Unresolved(String),
    BadOffset,
    UnsupportedReloc(u16),
    /// A REL32[_N] relocation's computed displacement did not fit in an i32.
    /// This happens when the resolved target is more than ~2 GiB away from the
    /// fixup location (e.g. a BOF and its trampoline loaded far apart). Silently
    /// truncating the i64 displacement to i32 would apply a wrong fixup and jump
    /// to an unintended address; we surface it as a hard error instead.
    RelocOverflow,
}

impl core::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ApplyError::BadSymbolIndex(i) => {
                write!(f, "relocation references an out-of-range symbol index {i}")
            }
            ApplyError::Unresolved(s) => write!(f, "unresolved external symbol `{s}`"),
            ApplyError::BadOffset => f.write_str("relocation offset out of section bounds"),
            ApplyError::UnsupportedReloc(t) => {
                write!(f, "unsupported relocation type 0x{t:04x}")
            }
            ApplyError::RelocOverflow => {
                f.write_str("REL32 displacement out of i32 range (target > ~2 GiB from fixup)")
            }
        }
    }
}

/// A parsed COFF object.
#[derive(Debug)]
pub struct Coff<'a> {
    pub machine: u16,
    pub sections: Vec<Section<'a>>,
    pub symbols: Vec<Symbol>,
}

#[derive(Debug)]
pub struct Section<'a> {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub characteristics: u32,
    /// Raw section bytes (as in the file).
    pub raw: &'a [u8],
    pub relocations: Vec<Reloc>,
}

#[derive(Debug, Clone, Copy)]
pub struct Reloc {
    /// Offset within the section where the fixup applies.
    pub offset: u32,
    /// Index into `Coff::symbols`.
    pub symbol_index: u32,
    /// `IMAGE_REL_AMD64_*` type.
    pub typ: u16,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    /// Raw index in the COFF symbol table (counting auxiliary records). This is
    /// what relocation entries reference, so we must look symbols up by it.
    pub index: u32,
    pub name: String,
    pub value: u32,
    /// 1-based section index; 0 = undefined (external); <0 = absolute/debug.
    pub section_number: i16,
    pub storage_class: u8,
}

/// Resolves a COFF external symbol name to an absolute load address. The
/// implant backs this with its Beacon-API / Win32 table.
pub trait SymbolResolver {
    fn resolve(&self, name: &str) -> Option<u64>;
}

// ---- little-endian readers --------------------------------------------------

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn i16le(b: &[u8], o: usize) -> i16 {
    i16::from_le_bytes([b[o], b[o + 1]])
}

/// Parse an AMD64 COFF object from raw bytes.
pub fn parse<'a>(data: &'a [u8]) -> Result<Coff<'a>, CoffError> {
    if data.len() < 20 {
        return Err(CoffError::Truncated);
    }
    let machine = u16le(data, 0);
    if machine != MACHINE_AMD64 {
        return Err(CoffError::UnsupportedMachine(machine));
    }
    let nsec = u16le(data, 2) as usize;
    let sym_ptr = u32le(data, 8) as usize;
    let nsym = u32le(data, 12) as usize;
    let opt_hdr = u16le(data, 16) as usize;
    // All offset arithmetic uses checked_add/checked_mul: a malformed COFF can
    // set nsec/nsym/raw_ptr/raw_size to drive `usize` past MAX and wrap to a
    // small in-range value, defeating the length guards. The server/agent run
    // under panic = "abort", so a wrapping-then-slice would crash the process.
    let sec_off = opt_hdr.checked_add(20).ok_or(CoffError::Truncated)?;
    let sec_table_end = sec_off
        .checked_add(nsec.checked_mul(40).ok_or(CoffError::Truncated)?)
        .ok_or(CoffError::Truncated)?;
    if data.len() < sec_table_end {
        return Err(CoffError::Truncated);
    }
    // Reject an absurd symbol count up front: nsym * 18 must fit and the
    // declared symbol table must actually live within the file. A huge nsym
    // (e.g. 0xFFFFFFFF) used to wrap `nsym * 18` and point str_off at section
    // data; now it's a clean Truncated.
    let sym_size = nsym.checked_mul(18).ok_or(CoffError::Truncated)?;
    let sym_end = sym_ptr.checked_add(sym_size).ok_or(CoffError::Truncated)?;
    if sym_end > data.len() {
        return Err(CoffError::Truncated);
    }

    // String table sits immediately after the symbol table.
    let str_table: &[u8] = data.get(sym_end..).unwrap_or(&[]);

    // Sections.
    let mut sections = Vec::with_capacity(nsec);
    for i in 0..nsec {
        let so = sec_off
            .checked_add(i.checked_mul(40).ok_or(CoffError::Truncated)?)
            .ok_or(CoffError::Truncated)?;
        // so..so+40 is guaranteed in range by the sec_table_end check above.
        let name = sec_name(&data[so..so + 8], str_table);
        let virtual_size = u32le(data, so + 8);
        let virtual_address = u32le(data, so + 12);
        let raw_size = u32le(data, so + 16) as usize;
        let raw_ptr = u32le(data, so + 20) as usize;
        let reloc_ptr = u32le(data, so + 24) as usize;
        let nreloc = u16le(data, so + 32) as usize;
        let characteristics = u32le(data, so + 36);
        // STRICT raw window: reject (don't silently truncate to &[]) when the
        // declared (raw_ptr, raw_size) doesn't fit in the file. A silently-empty
        // .text would let apply() relocate against zero bytes and a crafted
        // window could alias header bytes — either way a malformed BOF must be
        // rejected, not accepted with garbage contents.
        let raw_end = raw_ptr.checked_add(raw_size).ok_or(CoffError::Truncated)?;
        let raw = if raw_ptr == 0 && raw_size == 0 {
            // BSS-like sections legitimately have no raw bytes.
            &[]
        } else if raw_end <= data.len() {
            &data[raw_ptr..raw_end]
        } else {
            return Err(CoffError::Truncated);
        };
        let mut relocations = Vec::with_capacity(nreloc);
        for r in 0..nreloc {
            let ro = reloc_ptr
                .checked_add(r.checked_mul(10).ok_or(CoffError::Truncated)?)
                .ok_or(CoffError::Truncated)?;
            let Some(window) = data.get(ro..ro + 10) else {
                return Err(CoffError::Truncated);
            };
            relocations.push(Reloc {
                offset: u32le(window, 0),
                symbol_index: u32le(window, 4),
                typ: u16le(window, 8),
            });
        }
        sections.push(Section {
            name,
            virtual_size,
            virtual_address,
            characteristics,
            raw,
            relocations,
        });
    }

    // Symbols (skip auxiliary records).
    let mut symbols = Vec::new();
    let mut i = 0;
    while i < nsym {
        let so = sym_ptr
            .checked_add(i.checked_mul(18).ok_or(CoffError::Truncated)?)
            .ok_or(CoffError::Truncated)?;
        // so..so+18 is within [sym_ptr, sym_end) which we validated <= len.
        let window = &data[so..so + 18];
        let name = sym_name(&window[0..8], str_table);
        let value = u32le(window, 8);
        let section_number = i16le(window, 12);
        let storage_class = window[16];
        let aux = window[17];
        symbols.push(Symbol {
            index: i as u32,
            name,
            value,
            section_number,
            storage_class,
        });
        i = i
            .checked_add(1)
            .and_then(|x| x.checked_add(aux as usize))
            .ok_or(CoffError::Truncated)?;
    }

    Ok(Coff {
        machine,
        sections,
        symbols,
    })
}

/// Section name: 8-byte field; if it begins with `b'/'`, the rest is a decimal
/// offset into the COFF string table (long name).
fn sec_name(field: &[u8], str_table: &[u8]) -> String {
    if field.first() == Some(&b'/') {
        let digits: String = field[1..]
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();
        if let Ok(off) = digits.parse::<usize>() {
            if let Some(name) = cstr_at(str_table, off) {
                return name;
            }
        }
    }
    inline_cstr(field)
}

/// Symbol name: 8-byte field; if the first 4 bytes are zero, bytes [4..8] are a
/// little-endian u32 offset into the string table (long name).
fn sym_name(field: &[u8], str_table: &[u8]) -> String {
    if field[..4].iter().all(|&b| b == 0) {
        let off = u32le(field, 4) as usize;
        if let Some(name) = cstr_at(str_table, off) {
            return name;
        }
    }
    inline_cstr(field)
}

fn cstr_at(table: &[u8], off: usize) -> Option<String> {
    // COFF string-table offsets are absolute from the start of the table (whose
    // first u32 is the table size), so valid offsets are >= 4.
    let slice = table.get(off..)?;
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Some(String::from_utf8_lossy(&slice[..end]).into_owned())
}

fn inline_cstr(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Copy a section's raw bytes and apply its relocations. `section_base` is the
/// absolute address the section will be loaded at (so REL32 PC-relative math is
/// correct); `resolver` maps external symbol names to absolute addresses.
pub fn apply<'a>(
    section: &Section<'a>,
    coff: &Coff<'a>,
    section_base: u64,
    resolver: &dyn SymbolResolver,
) -> Result<Vec<u8>, ApplyError> {
    let mut buf = section.raw.to_vec();
    for r in &section.relocations {
        if r.typ == reloc::ABSOLUTE {
            continue;
        }
        // Relocation symbol indices are raw (count aux records), so find by
        // Symbol::index rather than by Vec position.
        let sym = coff
            .symbols
            .iter()
            .find(|s| s.index == r.symbol_index)
            .ok_or(ApplyError::BadSymbolIndex(r.symbol_index))?;
        let target = resolver
            .resolve(&sym.name)
            .ok_or_else(|| ApplyError::Unresolved(sym.name.clone()))?;
        let off = r.offset as usize;
        let loc = section_base + r.offset as u64;
        match r.typ {
            reloc::ADDR64 => {
                let end = off.checked_add(8).ok_or(ApplyError::BadOffset)?;
                if end > buf.len() {
                    return Err(ApplyError::BadOffset);
                }
                // COFF relocs are *deltas*: the field already holds the
                // compiler's value (incl. any in-section addend); add the
                // symbol's final address to it.
                let cur = i64::from_le_bytes(buf[off..end].try_into().unwrap());
                let v = cur.wrapping_add(target as i64);
                buf[off..end].copy_from_slice(&v.to_le_bytes());
            }
            reloc::REL32
            | reloc::REL32_1
            | reloc::REL32_2
            | reloc::REL32_3
            | reloc::REL32_4
            | reloc::REL32_5 => {
                let end = off.checked_add(4).ok_or(ApplyError::BadOffset)?;
                if end > buf.len() {
                    return Err(ApplyError::BadOffset);
                }
                // AMD64 REL32[_N]: per PE/COFF spec the decoded target sits at
                // (field_loc + 4 + N), where N is the `_N` suffix (0 for plain
                // REL32, 1..5 for REL32_1..REL32_5). The field holds the
                // compiler's disp32 baseline; the loader adds
                // (resolved_target - (field_loc + 4 + N)) to relocate it.
                let n: i64 = match r.typ {
                    reloc::REL32 => 0,
                    reloc::REL32_1 => 1,
                    reloc::REL32_2 => 2,
                    reloc::REL32_3 => 3,
                    reloc::REL32_4 => 4,
                    reloc::REL32_5 => 5,
                    // unreachable: the match arm above enumerates exactly these.
                    _ => unreachable!("REL32 family arm caught non-family type"),
                };
                let cur = i32::from_le_bytes(buf[off..end].try_into().unwrap());
                // The displacement must fit in an i32 (the field width). If the
                // resolved target is more than ~2 GiB away from the fixup
                // location (e.g. BOF and trampoline loaded far apart), casting
                // the i64 disp to i32 would silently truncate and apply a wrong
                // fixup. Reject it instead. The pre-existing `end - off == 4`
                // bounds check above makes the `try_into().unwrap()` above
                // unreachable; it is left in because removing it would require
                // an extra local.
                let disp = target as i64 - loc as i64 - 4 - n;
                if !(-2_147_483_648i64..=2_147_483_647i64).contains(&disp) {
                    return Err(ApplyError::RelocOverflow);
                }
                let v = cur.wrapping_add(disp as i32);
                buf[off..end].copy_from_slice(&v.to_le_bytes());
            }
            reloc::ADDR32 | reloc::ADDR32NB => {
                // ADDR32NB (RVA / base-not-applied): BOF loaders conventionally
                // treat it as a flat u32 of the resolved virtual address — the
                // "NB" (no base) is absorbed because sections load at their own
                // base, not the PE image base. Matches CobaltStrike / inline-exec.
                // ADDR32 strictly wants image_base + RVA; a BOF has no image
                // base, so it gets the same flat-u32 treatment (what CS's own
                // loader and TrustedSec's COFFLoader do for both types).
                let end = off.checked_add(4).ok_or(ApplyError::BadOffset)?;
                if end > buf.len() {
                    return Err(ApplyError::BadOffset);
                }
                let v = target as u32;
                buf[off..end].copy_from_slice(&v.to_le_bytes());
            }
            other => return Err(ApplyError::UnsupportedReloc(other)),
        }
    }
    Ok(buf)
}
