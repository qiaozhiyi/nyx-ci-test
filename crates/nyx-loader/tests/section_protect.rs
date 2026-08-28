//! Host-side tests for the UDRL section-protect mapping.
//!
//! The pic-loader duplicates [`nyx_loader::on_target::section_protect_from_characteristics`]
//! (no shared module: that crate is no_std PIC). These tests pin the mapping
//! so a drift in the host-side helper is caught before the blob is rebuilt.

use nyx_loader::on_target::{
    section_protect_from_characteristics, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE,
};

const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

#[test]
fn execute_maps_to_rx() {
    assert_eq!(
        section_protect_from_characteristics(IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ),
        PAGE_EXECUTE_READ
    );
}

#[test]
fn execute_write_collapses_to_rx_not_rwx() {
    let prot = section_protect_from_characteristics(
        IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
    );
    assert_eq!(prot, PAGE_EXECUTE_READ);
    assert_ne!(prot, PAGE_EXECUTE_READWRITE);
    assert_ne!(prot, PAGE_READWRITE);
}

#[test]
fn write_maps_to_rw() {
    assert_eq!(
        section_protect_from_characteristics(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE),
        PAGE_READWRITE
    );
}

#[test]
fn read_or_empty_maps_to_r() {
    assert_eq!(
        section_protect_from_characteristics(IMAGE_SCN_MEM_READ),
        PAGE_READONLY
    );
    assert_eq!(section_protect_from_characteristics(0), PAGE_READONLY);
}

#[test]
fn no_characteristics_combo_returns_rwx() {
    let combos = [
        0,
        IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_WRITE,
        IMAGE_SCN_MEM_EXECUTE,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
    ];
    for c in combos {
        assert_ne!(
            section_protect_from_characteristics(c),
            PAGE_EXECUTE_READWRITE,
            "characteristics {c:#x} must not map to RWX"
        );
    }
}
