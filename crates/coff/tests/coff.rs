//! Fixture-driven COFF loader tests. The fixture (`bof.o`) is a real Windows
//! x86_64 COFF cross-compiled with `clang --target=x86_64-pc-windows-msvc`:
//!   extern void BeaconPrintf(int, const char*);
//!   int go(void) { BeaconPrintf(0, "hi"); return 42; }
//! so it has a defined `go`, an undefined external `BeaconPrintf`, and a
//! `.text` relocation (a REL32-family call) against `BeaconPrintf`.

use std::collections::HashMap;

use nyx_coff::{apply, parse, SymbolResolver};

struct TableResolver(HashMap<String, u64>);
impl SymbolResolver for TableResolver {
    fn resolve(&self, name: &str) -> Option<u64> {
        // Resolve every symbol to a deterministic address so apply() succeeds.
        // The default is kept within i32 displacement of the 0x10000 base so a
        // REL32 fixup's disp actually fits — a far-away default (e.g.
        // 0xAA00_0000, ~2.8 GiB) would now correctly trip RelocOverflow, now
        // that the truncation is a hard error rather than silent.
        self.0.get(name).copied().or(Some(0x0001_0000 + 0x2000))
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
    // Raw spec numbers, NOT nyx_coff::reloc::* constants: IMAGE_REL_AMD64_REL32
    // is 0x0004 and REL32_1..5 are 0x0005..=0x0009 per winnt.h. Asserting
    // against the crate's own constants would re-import a wrong constant table
    // into the test and make it a tautology (this bug actually shipped).
    assert!(
        matches!(call.typ, 0x0004..=0x0009),
        "expected a REL32-family call reloc (REL32=0x0004..REL32_5=0x0009), got 0x{:04x}",
        call.typ
    );
    // An ordinary `call` with no bytes after its disp32 field must be plain
    // REL32 — both clang and MinGW GCC emit 0x0004 for it.
    assert_eq!(
        call.typ, 0x0004,
        "a plain call reloc must be IMAGE_REL_AMD64_REL32 (0x0004)"
    );

    // Pick a target within i32 displacement of the fixup so the REL32 disp
    // actually fits — historically this test used 0xDEAD_BEEF (~3.7 GiB away
    // from the 0x10000 base), which exceeds the ±2 GiB REL32 range and only
    // "worked" because the old code silently truncated the i64 disp to i32.
    // The disp range check now rejects that, so exercise the happy path with
    // an in-range target (the dedicated applies_rel32_overflow_rejected test
    // below covers the out-of-range branch).
    let base: u64 = 0x0001_0000;
    let target: u64 = 0x0001_0000 + 0x1000;
    let mut map = HashMap::new();
    map.insert("BeaconPrintf".to_string(), target);
    let resolver = TableResolver(map);

    let patched = apply(text, &coff, base, &resolver).expect("apply must succeed");

    // AMD64 REL32[_N]: per PE/COFF spec, patched = original_field +
    // (target - (field_loc + 4 + N)), where N is the `_N` suffix. N is derived
    // from the RAW reloc type number (REL32=0x0004 → N=0, REL32_N=0x0004+N),
    // independent of the crate's reloc::* constants — see the comment above.
    let n: i64 = match call.typ {
        0x0004..=0x0009 => (call.typ - 0x0004) as i64,
        other => panic!("unexpected non-REL32-family reloc 0x{:04x}", other),
    };
    let off = call.offset as usize;
    let orig = i32::from_le_bytes([
        text.raw[off],
        text.raw[off + 1],
        text.raw[off + 2],
        text.raw[off + 3],
    ]);
    let loc = base + call.offset as u64;
    let expected = orig.wrapping_add((target as i64 - loc as i64 - 4 - n) as i32);
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

/// Regression for the off-by-one reloc-type table (REL32 was declared 0x0003,
/// so plain REL32 = 0x0004 decoded as REL32_1 and every branch target shifted
/// by -1 byte — the BOF's `call BeaconPrintf` jumped one byte before the shim).
/// Decodes every patched .text disp32 exactly the way the CPU would
/// (branch target = next_insn + disp32) and asserts control flow lands
/// EXACTLY on the resolved symbol — not one byte off in either direction.
#[test]
fn relocated_branches_land_exactly_on_symbols() {
    let coff = parse(FIXTURE).unwrap();
    let text = coff
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .expect(".text section");
    assert!(
        !text.relocations.is_empty(),
        "fixture .text must carry relocations"
    );
    let base: u64 = 0x0001_0000;
    let resolver = TableResolver(HashMap::new()); // default addrs, all in range
    let patched = apply(text, &coff, base, &resolver).expect("apply must succeed");
    for r in &text.relocations {
        if r.typ == 0x0000 {
            continue; // ABSOLUTE: apply() skips it
        }
        // All .text relocs in this fixture are plain REL32 (0x0004) — no bytes
        // follow the disp32 field, so the CPU decodes target = loc + 4 + disp.
        assert_eq!(r.typ, 0x0004, "fixture .text relocs are plain REL32");
        let sym = coff
            .symbols
            .iter()
            .find(|s| s.index == r.symbol_index)
            .expect("reloc symbol");
        let target = resolver.resolve(&sym.name).expect("resolver covers all");
        let off = r.offset as usize;
        let cur = i32::from_le_bytes(text.raw[off..off + 4].try_into().unwrap());
        let field = i32::from_le_bytes(patched[off..off + 4].try_into().unwrap());
        let loc = base + r.offset as u64;
        let decoded = (loc as i64 + 4 + field as i64) as u64;
        let expected = (target as i64 + cur as i64) as u64; // symbol + addend
        assert_eq!(
            decoded, expected,
            "reloc at +{off:#x} against `{}` must land exactly on the symbol",
            sym.name
        );
    }
}

#[test]
fn applies_rel32_overflow_is_rejected() {
    // A REL32[_N] displacement that does not fit in i32 must be reported as
    // RelocOverflow rather than silently truncated. We place the resolved
    // BeaconPrintf target ~3.7 GiB away from the fixup location; before the
    // range check this produced a wrong-but-deterministic fixup via an `as i32`
    // truncation. The whole point of the fix is that this now fails cleanly.
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
        .index;
    assert!(
        text.relocations.iter().any(|r| r.symbol_index == bp_idx),
        "fixture must have a REL32 reloc against BeaconPrintf"
    );

    let base: u64 = 0x0001_0000;
    let target: u64 = 0xDEAD_BEEF; // ~3.7 GiB from base → disp > i32::MAX
    let mut map = HashMap::new();
    map.insert("BeaconPrintf".to_string(), target);
    let resolver = TableResolver(map);

    let err = apply(text, &coff, base, &resolver).expect_err("out-of-range disp must be rejected");
    assert!(
        matches!(err, nyx_coff::ApplyError::RelocOverflow),
        "out-of-range REL32 disp must surface as RelocOverflow, got {err:?}"
    );
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
