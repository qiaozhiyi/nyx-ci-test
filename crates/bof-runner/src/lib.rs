//! BOF execution layer — the other half of the BOF story.
//!
//! `nyx-coff` parses + relocates a Windows COFF; this crate *runs* it: map the
//! sections into memory with a **W^X** discipline, resolve every external
//! reference against a table of Beacon-API shims + kernel32/ntdll/CRT exports,
//! apply relocations, then call the BOF's entry (`go(char *args, int alen)` —
//! the CS ABI). Runtime is Windows-only (it allocates memory and jumps into
//! position-relocated machine code); build with `--target
//! x86_64-pc-windows-gnu` and run under Wine (or real Windows).
//!
//! ## W^X mapping
//! Every section is allocated `PAGE_READWRITE`, raw bytes are copied and
//! relocations are applied while the write window is open, and only THEN are
//! code sections (`Characteristics & IMAGE_SCN_MEM_EXECUTE`) flipped to
//! `PAGE_EXECUTE_READ` via `VirtualProtect` — so at the moment `go()` is
//! invoked, no page is simultaneously writable and executable. Data sections
//! stay `PAGE_READWRITE`. The REL32 trampoline page (one shared page of
//! absolute-jump stubs near the BOF) is written RW and flipped to
//! `PAGE_EXECUTE_READ` before `go()`; the scratch hint page that seeds the
//! near-address allocator is `PAGE_READWRITE` and never executed. The pure
//! section-mapping / protection decisions live in the host-testable `layout`
//! module.
//!
//! ## Externals table
//! Besides the Beacon-API shims (`BeaconPrintf`, the `datap` argument-parser
//! family, `BeaconIsAdmin`, `BeaconGetSpawnTo`, the token family
//! (`BeaconUseToken`/`BeaconRevertToken`), the spawn family
//! (`BeaconSpawnTemporaryProcess`/`BeaconCleanupProcess`), `BeaconOutput` —
//! see `layout::BEACON_APIS`), the loader resolves a table of common
//! kernel32/ntdll exports (`GetModuleHandleA/W`, `GetProcAddress`,
//! `VirtualAlloc`, `VirtualProtect`, `VirtualFree`, `LoadLibraryA`,
//! `GetLastError`, the memcpy family, …) at load time via `GetModuleHandleA`
//! and `GetProcAddress`, with no C CRT dependency. Every external gets a stub
//! in the shared trampoline page, so REL32 relocations can reach addresses
//! >2 GiB away from the low-address BOF allocation.
//!
//! ## ABI
//!
//! [`execute`]`(blob, args)` loads the BOF and invokes its entry as
//! `go(args.as_ptr(), args.len() as i32)`. `args` is the packed CS argument
//! blob; pass `&[]` for a no-args BOF — the entry then receives a NULL buffer
//! and length 0, preserving the `BeaconDataParse(NULL, 0)` idiom.

// Windows PE-layout helpers: constants + pure math consumed by `win`.
// Compiled on all platforms so the host-side unit tests below still run in
// macOS/Linux CI; the helpers are dead code outside Windows.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod layout;
#[cfg(target_os = "windows")]
mod shim;
#[cfg(target_os = "windows")]
mod win;

#[cfg(target_os = "windows")]
pub use win::{execute, load, ExecResult, Loaded, Resolver};

#[cfg(test)]
mod tests {
    use super::layout;
    use nyx_coff::parse;

    /// Real cross-compiled BOF fixture (`tests/fixtures/bof_print.c`): a
    /// clang-produced COFF whose `.text` holds a `go` entry that calls
    /// `BeaconPrintf`. Ground truth (verified offline): 7 sections — `.text`
    /// (characteristics `0x60500020` = CODE|EXECUTE|READ|ALIGN16), `.data`,
    /// `.bss`, `.rdata`, `.xdata`, `.pdata`, and the string-table section —
    /// with `go` defined in section 1 (`.text`).
    const BOF_PRINT: &[u8] = include_bytes!("../tests/fixtures/bof_print.o");

    #[test]
    fn fixture_classifies_text_as_code() {
        let coff = parse(BOF_PRINT).expect("fixture parses");
        let code: Vec<_> = coff
            .sections
            .iter()
            .filter(|s| layout::is_code(s.characteristics))
            .collect();
        // This fixture has exactly one IMAGE_SCN_MEM_EXECUTE section.
        assert_eq!(code.len(), 1, "expected exactly one code section");
        assert_eq!(code[0].name, ".text");
        assert_eq!(
            layout::final_protection(code[0].characteristics),
            layout::PAGE_EXECUTE_READ,
            "code section must be flipped to RX before go()"
        );
    }

    #[test]
    fn fixture_data_sections_stay_readwrite() {
        let coff = parse(BOF_PRINT).expect("fixture parses");
        for s in coff
            .sections
            .iter()
            .filter(|s| !layout::is_code(s.characteristics))
        {
            assert_eq!(
                layout::final_protection(s.characteristics),
                layout::PAGE_READWRITE,
                "section `{}` must stay writable (W^X)",
                s.name
            );
        }
    }

    #[test]
    fn go_entry_lives_in_a_code_section() {
        let coff = parse(BOF_PRINT).expect("fixture parses");
        let go = coff
            .symbols
            .iter()
            .find(|s| s.name == "go")
            .expect("fixture defines `go`");
        assert!(go.section_number >= 1, "`go` must be a defined symbol");
        let sec = &coff.sections[(go.section_number - 1) as usize];
        assert!(
            layout::is_code(sec.characteristics),
            "`go` must sit in an executable section (it does: `.text`)"
        );
    }

    #[test]
    fn section_sizes_are_page_aligned() {
        let coff = parse(BOF_PRINT).expect("fixture parses");
        // The loader maps each section at a page-aligned offset with a
        // page-aligned size so per-section VirtualProtect calls cannot bleed
        // into a neighbour (empty sections map to 0 bytes).
        for s in &coff.sections {
            let sz = layout::page_align((s.virtual_size.max(s.raw.len() as u32)) as usize);
            assert_eq!(sz % layout::PAGE_SIZE, 0, "section `{}`", s.name);
        }
        // And the sizes must sum to what the loader allocates (>= 1 page).
        let total: usize = coff
            .sections
            .iter()
            .map(|s| layout::page_align((s.virtual_size.max(s.raw.len() as u32)) as usize))
            .sum::<usize>()
            .max(layout::PAGE_SIZE);
        assert!(total >= layout::PAGE_SIZE);
        assert_eq!(total % layout::PAGE_SIZE, 0);
    }

    #[test]
    fn externals_table_has_no_duplicate_names() {
        // Same invariant as layout's own test, re-asserted at the loader
        // boundary: duplicate names would silently shadow in the externals
        // HashMap passed into `load()`.
        let mut names: Vec<&str> = layout::EXTERN_SINGLES.iter().map(|(_, n)| *n).collect();
        names.extend_from_slice(layout::CRT_NAMES);
        let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len());
        assert!(names.len() <= layout::TRAMP_STUBS_PER_PAGE);
    }
}
