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
