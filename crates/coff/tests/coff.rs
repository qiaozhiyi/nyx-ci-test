//! Fixture-driven COFF loader tests. The fixture (`bof.o`) is a real Windows
//! x86_64 COFF cross-compiled with `clang --target=x86_64-pc-windows-msvc`:
//!   extern void BeaconPrintf(int, const char*);
//!   int go(void) { BeaconPrintf(0, "hi"); return 42; }
//! so it has a defined `go`, an undefined external `BeaconPrintf`, and a
//! `.text` relocation (a REL32-family call) against `BeaconPrintf`.

use std::collections::HashMap;

use nyx_coff::{reloc, apply, parse, SymbolResolver};

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

    // Verify the patched 4-byte displacement matches the REL32[_N] formula
    // exactly: disp = target - (section_base + reloc_offset + 4 + N).
    let n = if call.typ == reloc::REL32 {
        0i64
    } else {
        call.typ as i64 - reloc::REL32 as i64
    };
    let loc = base + call.offset as u64;
    let expected = (target as i64 - loc as i64 - 4 - n) as i32;
    let off = call.offset as usize;
    let got = i32::from_le_bytes([
        patched[off],
        patched[off + 1],
        patched[off + 2],
        patched[off + 3],
    ]);
    assert_eq!(got, expected, "REL32 displacement must match the formula");

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
