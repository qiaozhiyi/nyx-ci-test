//! Fixture-driven COFF loader tests. The fixture (`bof.o`) is a real Windows
//! x86_64 COFF cross-compiled with `clang --target=x86_64-pc-windows-msvc`:
//!   extern void BeaconPrintf(int, const char*);
//!   int go(void) { BeaconPrintf(0, "hi"); return 42; }
//! so it has a defined `go`, an undefined external `BeaconPrintf`, and a
//! `.text` relocation (a REL32-family call) against `BeaconPrintf`.

use std::collections::HashMap;

use nyx_coff::{apply, parse, reloc, SymbolResolver};

struct TableResolver(HashMap<String, u64>);
impl SymbolResolver for TableResolver {
    fn resolve(&self, name: &str) -> Option<u64> {
        // Resolve every symbol to a deterministic address so apply() succeeds;
        // we single out BeaconPrintf for an exact displacement check.
        self.0.get(name).copied().or(Some(0xAA00_0000))
    }
}

const FIXTURE: &[u8] = include_bytes!("fixtures/bof.o");

#[test]
fn parses_amd64_coff() {
    let coff = parse(FIXTURE).expect("fixture must parse");
    assert_eq!(coff.machine, 0x8664, "AMD64 COFF");
    assert!(
        coff.sections.iter().any(|s| s.name == ".text"),
        "must have a .text section (got: {:?})",
        coff.sections.iter().map(|s| &s.name).collect::<Vec<_>>()
    );
}

#[test]
fn finds_beacon_api_extern_and_entry() {
    let coff = parse(FIXTURE).unwrap();
    let bp = coff
        .symbols
        .iter()
        .find(|s| s.name == "BeaconPrintf")
        .expect("BeaconPrintf external must be present");
    assert_eq!(
        bp.section_number, 0,
        "BeaconPrintf is undefined/external (section_number 0)"
    );
    assert!(
        coff.symbols.iter().any(|s| s.name == "go"),
        "`go` entry symbol must be present"
    );
}

#[test]
fn applies_rel32_call_relocation_correctly() {
    let coff = parse(FIXTURE).unwrap();
    let text = coff
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .expect(".text section");
    let bp_idx = coff
        .symbols
        .iter()
        .find(|s| s.name == "BeaconPrintf")
        .expect("BeaconPrintf present")
        .index; // raw symbol-table index (what relocations reference)

    // The call to BeaconPrintf is a REL32-family relocation in .text.
    let call = text
        .relocations
        .iter()
        .find(|r| r.symbol_index == bp_idx)
        .expect("a relocation against BeaconPrintf in .text");
    assert!(
        matches!(call.typ, reloc::REL32 | reloc::REL32_1..=0x0008),
        "expected a REL32-family call reloc, got 0x{:04x}",
        call.typ
    );

    let base: u64 = 0x0001_0000;
    let target: u64 = 0xDEAD_BEEF;
    let mut map = HashMap::new();
    map.insert("BeaconPrintf".to_string(), target);
    let resolver = TableResolver(map);

    let patched = apply(text, &coff, base, &resolver).expect("apply must succeed");

    // COFF relocs are deltas: the patched field = original_field +
    // (target - (field_loc + 4)). The `_N` is baked into the original field.
    let off = call.offset as usize;
    let orig = i32::from_le_bytes([
        text.raw[off],
        text.raw[off + 1],
        text.raw[off + 2],
        text.raw[off + 3],
    ]);
    let loc = base + call.offset as u64;
    let expected = orig.wrapping_add((target as i64 - loc as i64 - 4) as i32);
    let got = i32::from_le_bytes([
        patched[off],
        patched[off + 1],
        patched[off + 2],
        patched[off + 3],
    ]);
    assert_eq!(got, expected, "REL32 delta must match the addend formula");

    // Determinism: applying twice with identical inputs yields identical bytes.
    let patched2 = apply(text, &coff, base, &resolver).unwrap();
    assert_eq!(patched, patched2);
}

#[test]
fn apply_fails_on_unresolved_external() {
    let coff = parse(FIXTURE).unwrap();
    let text = coff.sections.iter().find(|s| s.name == ".text").unwrap();

    struct ResolveNothing;
    impl SymbolResolver for ResolveNothing {
        fn resolve(&self, _name: &str) -> Option<u64> {
            None
        }
    }
    let err = apply(text, &coff, 0x10000, &ResolveNothing).unwrap_err();
    assert!(
        matches!(err, nyx_coff::ApplyError::Unresolved(_)),
        "unresolved extern must surface as Unresolved, got {err:?}"
    );
}

// ---- malformed-input hardening (panic = "abort" makes every panic a crash) ----

/// Helper: take the real fixture and overwrite the `.text` section's
/// (raw_ptr, raw_size) so the declared raw window runs past EOF. Before the
/// fix this silently produced an empty `.text` (`unwrap_or(&[])`); after, it
/// must return Truncated so a malformed/weaponized BOF can't slip through with
/// garbage section contents.
fn fixture_with_text_raw_overrunning_eof() -> Vec<u8> {
    let mut buf = FIXTURE.to_vec();
    let _coff = parse(FIXTURE).unwrap();
    let nsec = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    let opt_hdr = u16::from_le_bytes([buf[16], buf[17]]) as usize;
    let sec_off = 20 + opt_hdr;
    // Find the .text section's entry in the section table and inflate its
    // raw_size so raw_ptr + raw_size > buf.len().
    for i in 0..nsec {
        let so = sec_off + i * 40;
        let name = &buf[so..so + 8];
        if name.starts_with(b".text") {
            // raw_size is at section-offset + 16 (u32 LE). Set it huge.
            let huge = (buf.len() as u32).saturating_add(0x0010_0000);
            buf[so + 16..so + 20].copy_from_slice(&huge.to_le_bytes());
            return buf;
        }
    }
    panic!("fixture has no .text section to corrupt");
}

#[test]
fn section_raw_window_overrunning_eof_is_rejected() {
    let bad = fixture_with_text_raw_overrunning_eof();
    let err = parse(&bad).unwrap_err();
    assert!(
        matches!(err, nyx_coff::CoffError::Truncated),
        "a section whose declared raw window exceeds EOF must be Truncated, got {err:?}"
    );
    // The clean fixture still parses (sanity).
    parse(FIXTURE).expect("clean fixture must still parse");
}

#[test]
fn absurd_symbol_count_is_rejected_not_wrapped() {
    // A COFF header claiming nsym = 0xFFFFFFFF would make `nsym * 18` wrap on
    // 32-bit (and is just nonsensical on 64-bit). The str_off computation must
    // detect the overflow / absurdity and reject, not silently wrap str_off to
    // a small value that aliases section data.
    let mut buf = FIXTURE.to_vec();
    // nsym (NumberOfSymbols) is a u32 at file offset 12.
    buf[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let err = parse(&buf).unwrap_err();
    assert!(
        matches!(err, nyx_coff::CoffError::Truncated),
        "absurd nsym must be Truncated, got {err:?}"
    );
}

#[test]
fn truncated_section_table_is_rejected() {
    // A COFF whose header claims more sections than the body can hold.
    let mut buf = FIXTURE.to_vec();
    buf[2..4].copy_from_slice(&0x7FFFu16.to_le_bytes()); // 32767 sections
    let err = parse(&buf).unwrap_err();
    assert!(matches!(err, nyx_coff::CoffError::Truncated), "got {err:?}");
}
