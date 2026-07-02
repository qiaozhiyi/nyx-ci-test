//! x64 4-level page-table walk — pure algorithm (VA → PA translation).
//!
//! RTCore64 and most physical-memory BYOVD drivers operate on **physical**
//! addresses. To read/write a kernel **virtual** address, we must translate
//! VA→PA by walking the 4-level page table (PML4 → PDPT → PD → PT) starting
//! from the process's CR3 (DirectoryTableBase).
//!
//! This module is the pure walk logic: given a `read_phys(pa, &mut [u8])`
//! closure (backed by the driver's physical-read IOCTL), translate any VA.
//! Unit-tested with a mock physical-memory reader on the dev host.
//!
//! ## x64 paging (Intel SDM Vol 3, Chapter 4)
//! VA bits [47:39] → PML4 index, [38:30] → PDPT index, [29:21] → PD index,
//! [20:12] → PT index, [11:0] → page offset. Each table entry is 8 bytes;
//! bit 0 = present, bit 63 = large/super page marker in PD/PDPT entries.

#![cfg_attr(not(test), allow(dead_code))]

/// A physical-memory read primitive (the driver's read IOCTL, abstracted).
/// Reads `dst.len()` bytes from physical address `pa`.
pub trait PhysRead {
    fn read_phys(&self, pa: u64, dst: &mut [u8]) -> Result<(), PhysReadError>;
}

#[derive(Debug)]
pub enum PhysReadError {
    /// The driver IOCTL failed.
    Ioctl,
    /// A page-table entry is not present (bit 0 = 0) → VA is unmapped.
    NotPresent { level: PageLevel },
    /// The physical address calculation overflowed (shouldn't happen).
    Overflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageLevel {
    Pml4,
    Pdpt,
    Pd,
    Pt,
}

/// Translate a virtual address to a physical address via the 4-level walk.
///
/// `cr3` is the DirectoryTableBase (physical address of the PML4 table; the
/// low 12 bits are ignored per the Intel SDM — CR3 is page-aligned).
///
/// Returns the physical address on success, or an error if any level's entry
/// is not present or the read fails.
pub fn translate_va<P: PhysRead>(reader: &P, cr3: u64, va: u64) -> Result<u64, PhysReadError> {
    // CR3 points at the PML4 table; low 12 bits are flags, mask them off.
    let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;

    // PML4 index = VA bits [47:39].
    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pml4_entry_pa = pml4_base + (pml4_idx as u64 * 8);
    let pml4_entry = read_u64(reader, pml4_entry_pa)?;
    if pml4_entry & 1 == 0 {
        return Err(PhysReadError::NotPresent {
            level: PageLevel::Pml4,
        });
    }

    // PDPT: entry = PML4_entry & mask (bits 51:12, the PFN).
    let pdpt_base = pml4_entry & 0x000F_FFFF_FFFF_F000;
    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pdpt_entry_pa = pdpt_base + (pdpt_idx as u64 * 8);
    let pdpt_entry = read_u64(reader, pdpt_entry_pa)?;
    if pdpt_entry & 1 == 0 {
        return Err(PhysReadError::NotPresent {
            level: PageLevel::Pdpt,
        });
    }
    // 1GB large page: PDPT entry bit 7 set → PA = entry[51:30] | VA[29:0].
    if pdpt_entry & (1 << 7) != 0 {
        let pa = (pdpt_entry & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF);
        return Ok(pa);
    }

    // PD.
    let pd_base = pdpt_entry & 0x000F_FFFF_FFFF_F000;
    let pd_idx = ((va >> 21) & 0x1FF) as usize;
    let pd_entry_pa = pd_base + (pd_idx as u64 * 8);
    let pd_entry = read_u64(reader, pd_entry_pa)?;
    if pd_entry & 1 == 0 {
        return Err(PhysReadError::NotPresent {
            level: PageLevel::Pd,
        });
    }
    // 2MB large page: PD entry bit 7 set → PA = entry[51:21] | VA[20:0].
    if pd_entry & (1 << 7) != 0 {
        let pa = (pd_entry & 0x000F_FFFF_FFE0_0000) | (va & 0x001F_FFFF);
        return Ok(pa);
    }

    // PT.
    let pt_base = pd_entry & 0x000F_FFFF_FFFF_F000;
    let pt_idx = ((va >> 12) & 0x1FF) as usize;
    let pt_entry_pa = pt_base + (pt_idx as u64 * 8);
    let pt_entry = read_u64(reader, pt_entry_pa)?;
    if pt_entry & 1 == 0 {
        return Err(PhysReadError::NotPresent {
            level: PageLevel::Pt,
        });
    }

    // 4KB page: PA = entry[51:12] | VA[11:0].
    let page_base = pt_entry & 0x000F_FFFF_FFFF_F000;
    let offset = va & 0xFFF;
    page_base.checked_add(offset).ok_or(PhysReadError::Overflow)
}

/// Read a little-endian u64 from physical memory via the reader.
fn read_u64<P: PhysRead>(reader: &P, pa: u64) -> Result<u64, PhysReadError> {
    let mut buf = [0u8; 8];
    reader
        .read_phys(pa, &mut buf)
        .map_err(|_| PhysReadError::Ioctl)?;
    Ok(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    /// A mock physical memory reader over a sparse byte map (physical address → bytes).
    /// Lets us lay out fake page tables + verify the walk without a real driver.
    struct MockPhys {
        mem: BTreeMap<u64, [u8; 8]>,
    }
    impl PhysRead for MockPhys {
        fn read_phys(&self, pa: u64, dst: &mut [u8]) -> Result<(), PhysReadError> {
            // Read 8-byte-aligned entries; for our tests we only ever read u64s.
            let entry = self.mem.get(&pa).copied().unwrap_or([0u8; 8]);
            let n = dst.len().min(8);
            dst[..n].copy_from_slice(&entry[..n]);
            Ok(())
        }
    }

    #[test]
    fn translate_4kb_page() {
        // Build a minimal 4-level walk for VA 0xFFFF_8000_0000_0000.
        // All indices = 0 → entry 0 at each level. Present bit set.
        let cr3 = 0x1000; // PML4 table at physical 0x1000.
        let mut mem = BTreeMap::new();

        // PML4[0] → points to PDPT at 0x2000, present.
        mem.insert(0x1000, (0x2000u64 | 1).to_le_bytes());
        // PDPT[0] → points to PD at 0x3000, present.
        mem.insert(0x2000, (0x3000u64 | 1).to_le_bytes());
        // PD[0] → points to PT at 0x4000, present.
        mem.insert(0x3000, (0x4000u64 | 1).to_le_bytes());
        // PT[0] → points to page at 0x5000, present.
        mem.insert(0x4000, (0x5000u64 | 1).to_le_bytes());

        let reader = MockPhys { mem };
        let va = 0x0000_0000_0000_0000; // all indices 0, offset 0
        let pa = translate_va(&reader, cr3, va).unwrap();
        assert_eq!(pa, 0x5000); // page base + offset 0
    }

    #[test]
    fn translate_with_offset() {
        // Same tables as above, but VA has a non-zero page offset.
        let cr3 = 0x1000;
        let mut mem = BTreeMap::new();
        mem.insert(0x1000, (0x2000u64 | 1).to_le_bytes());
        mem.insert(0x2000, (0x3000u64 | 1).to_le_bytes());
        mem.insert(0x3000, (0x4000u64 | 1).to_le_bytes());
        mem.insert(0x4000, (0x5000u64 | 1).to_le_bytes());

        let reader = MockPhys { mem };
        let va = 0x0ABC; // offset 0xABC, same page (indices all 0)
        let pa = translate_va(&reader, cr3, va).unwrap();
        assert_eq!(pa, 0x5ABC);
    }

    #[test]
    fn not_present_pte_returns_error() {
        let cr3 = 0x1000;
        let mut mem = BTreeMap::new();
        mem.insert(0x1000, (0x2000u64 | 1).to_le_bytes()); // PML4 present
        mem.insert(0x2000, (0x3000u64 | 1).to_le_bytes()); // PDPT present
        mem.insert(0x3000, (0x4000u64 | 1).to_le_bytes()); // PD present
                                                           // PT[0] NOT inserted → reads 0 → not present.

        let reader = MockPhys { mem };
        let r = translate_va(&reader, cr3, 0);
        assert!(matches!(
            r,
            Err(PhysReadError::NotPresent {
                level: PageLevel::Pt
            })
        ));
    }

    #[test]
    fn translate_2mb_large_page() {
        // PD entry with bit 7 set (large page) → skip PT level.
        let cr3 = 0x1000;
        let mut mem = BTreeMap::new();
        mem.insert(0x1000, (0x2000u64 | 1).to_le_bytes());
        mem.insert(0x2000, (0x3000u64 | 1).to_le_bytes());
        // PD[0]: large page, base 0x0020_0000, present + large.
        let large_entry = 0x0020_0000u64 | 1 | (1 << 7);
        mem.insert(0x3000, large_entry.to_le_bytes());

        let reader = MockPhys { mem };
        let va = 0x0010_0000; // within the 2MB page (offset 0x10_0000)
        let pa = translate_va(&reader, cr3, va).unwrap();
        // PA = large_base | VA[20:0] = 0x0020_0000 | 0x0010_0000 = 0x0030_0000.
        assert_eq!(pa, 0x0030_0000);
    }

    #[test]
    fn cr3_low_bits_ignored() {
        // CR3 with low 12 flag bits set should be masked off.
        let cr3 = 0x1ABC; // base 0x1000 + flags 0xABC
        let mut mem = BTreeMap::new();
        mem.insert(0x1000, (0x2000u64 | 1).to_le_bytes());
        mem.insert(0x2000, (0x3000u64 | 1).to_le_bytes());
        mem.insert(0x3000, (0x4000u64 | 1).to_le_bytes());
        mem.insert(0x4000, (0x5000u64 | 1).to_le_bytes());

        let reader = MockPhys { mem };
        let pa = translate_va(&reader, cr3, 0).unwrap();
        assert_eq!(pa, 0x5000); // same result as clean CR3
    }
}

extern crate alloc;
