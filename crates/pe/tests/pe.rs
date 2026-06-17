//! PE export resolver tests, against a real mingw-built DLL fixture that
//! exports `nyx_pe_target` (and keeps `nyx_pe_internal` private).

const DLL: &[u8] = include_bytes!("fixtures/nyx_pe_fixture.dll");

#[test]
fn resolves_an_exported_function_to_an_rva() {
    let rva = nyx_pe::resolve_export(DLL, "nyx_pe_target")
        .expect("nyx_pe_target is __declspec(dllexport) and must resolve");
    assert!(rva > 0, "resolved RVA must be non-zero, got 0x{rva:x}");
}

#[test]
fn returns_none_for_private_and_unknown_names() {
    assert_eq!(
        nyx_pe::resolve_export(DLL, "nyx_pe_internal"),
        None,
        "a private (non-dllexport) function is not in the export table"
    );
    assert_eq!(nyx_pe::resolve_export(DLL, "DoesNotExist"), None);
}

#[test]
fn malformed_pe_returns_none_not_panic() {
    // The resolver must never panic on a truncated/malformed image: every
    // offset derived from a PE header field must be bounds-checked before it's
    // indexed. These inputs used to slice-panic (panic = "abort" would crash a
    // process that linked this crate).
    // Too small to even have a DOS header.
    assert_eq!(nyx_pe::resolve_export(&[], "x"), None);
    assert_eq!(nyx_pe::resolve_export(&[0u8; 4], "x"), None);
    // Has an MZ magic but a garbage e_lfanew pointing past EOF.
    let mut bad = vec![0u8; 64];
    bad[0] = b'M';
    bad[1] = b'Z';
    bad[0x3C..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    assert_eq!(nyx_pe::resolve_export(&bad, "x"), None);
    // MZ + a PE signature at a sane offset but no section table / export dir.
    let mut bad = vec![0u8; 512];
    bad[0] = b'M';
    bad[1] = b'Z';
    bad[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
    bad[0x80..0x84].copy_from_slice(&"PE\0\0".as_bytes()); // signature
    // export RVA = 0x10 (set DataDirectory[0].VirtualAddress) → points nowhere
    // in a section table that doesn't exist; must return None, not panic.
    assert_eq!(nyx_pe::resolve_export(&bad, "x"), None);
}

#[test]
fn export_dir_rva_resolving_near_eof_does_not_panic() {
    // Craft a minimal PE whose export-directory RVA resolves to a file offset
    // close enough to EOF that reading the export directory fields
    // (NumberOfNames @+24, AddressOf* @+28..+36) would index past the buffer.
    // rva_to_offset only checks the RVA is inside a section's virtual range —
    // it does NOT check the resulting file offset + read width is in bounds.
    // Before the fix, u32le(image, edir + 24) panicked here.
    let mut img = vec![0u8; 0x400];
    img[0] = b'M';
    img[1] = b'Z';
    let nt = 0x80usize;
    img[0x3C..0x40].copy_from_slice(&(nt as u32).to_le_bytes());
    img[nt..nt + 4].copy_from_slice(b"PE\0\0");
    // IMAGE_FILE_HEADER at nt+4: NumberOfSections=1 (offset +2), SizeOfOptionalHeader=240 (offset +16)
    img[nt + 4 + 2..nt + 4 + 4].copy_from_slice(&1u16.to_le_bytes());
    img[nt + 4 + 16..nt + 4 + 18].copy_from_slice(&240u16.to_le_bytes());
    // Optional header magic PE32+ (0x020b) at opt_off = nt+4+20
    let opt_off = nt + 4 + 20;
    img[opt_off..opt_off + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
    // DataDirectory[0] (Export) at opt_off + 112 (PE32+): VirtualAddress, Size
    let dd_off = opt_off + 112;
    // Section table starts after optional header: sec_off = nt+4+20+240
    let sec_off = nt + 4 + 20 + 240;
    // One section covering the tail of the image: VA=0x1000, VSize=0x1000,
    // raw_ptr = 0x200 (so file offset 0x200..0x400 maps to RVA 0x1000..0x1200).
    img[sec_off + 8..sec_off + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual_size
    img[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual_address
    img[sec_off + 20..sec_off + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw_ptr
    // Export directory RVA = 0x11F0 → file offset = 0x11F0 - 0x1000 + 0x200 = 0x3F0.
    // edir+24..edir+40 = 0x408..0x418, past img.len() (0x400) → u32le would panic.
    img[dd_off..dd_off + 4].copy_from_slice(&0x11F0u32.to_le_bytes());
    img[dd_off + 4..dd_off + 8].copy_from_slice(&40u32.to_le_bytes()); // size (ignored)
    // Grow image so the section table parse + rva_to_offset succeed, but the
    // export-dir field reads still overrun.
    img.resize(0x400, 0);
    assert_eq!(
        nyx_pe::resolve_export(&img, "x"),
        None,
        "export dir near EOF must return None, not panic"
    );
}
