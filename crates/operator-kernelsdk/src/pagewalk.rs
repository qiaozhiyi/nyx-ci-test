//! x64 4-level page-table walk — pure algorithm (VA → PA translation).
//!
//! Physical-memory BYOVD drivers (e.g. WDTKernel) operate on **physical**
//! addresses. To read/write a kernel **virtual** address, we must translate
//! VA→PA by walking the 4-level page table (PML4 → PDPT → PD → PT) starting
//! from the process's CR3 (DirectoryTableBase).
//!
//! This module is the pure walk logic: given a `read_phys(pa, &mut [u8])`
//! closure (backed by the driver's physical-read IOCTL), translate any VA.
//! Unit-tested with a mock physical-memory reader on the dev host.
//!
//! It also hosts [`VaKernelRw`] — the phys→VA adapter that turns a
//! physical-only driver (WDTKernel, ALSysIO64) into the standard
//! VA-addressing [`crate::KernelRw`] contract by translating every VA
//! through [`translate_va`] before the driver's physical R/W. The adapter
//! lives here (crate root, NOT `win/`) so its mock-phys tests run on the
//! dev host; `win::va_rw` re-exports it for the Windows bootstrap shell.
//!
//! ## x64 paging (Intel SDM Vol 3, Chapter 4)
//! VA bits [47:39] → PML4 index, [38:30] → PDPT index, [29:21] → PD index,
//! [20:12] → PT index, [11:0] → page offset. Each table entry is 8 bytes;
//! bit 0 = present, bit 7 = large-page marker in PD/PDPT entries, bits
//! [51:12] = the PFN (page frame number × 4 KiB) — the mask
//! `0x000F_FFFF_FFFF_F000` keeps the full 52-bit physical address, so
//! pages above 4 GiB translate without truncation.

#![cfg_attr(not(test), allow(dead_code))]

use crate::{KernelRw, KrwError};

/// A physical-memory read primitive (the driver's read IOCTL, abstracted).
/// Reads `dst.len()` bytes from physical address `pa`.
pub trait PhysRead {
    fn read_phys(&self, pa: u64, dst: &mut [u8]) -> Result<(), PhysReadError>;
}

/// Physical-memory write primitive (paired with [`PhysRead`]).
pub trait PhysWrite {
    fn write_phys(&self, pa: u64, src: &[u8]) -> Result<(), PhysReadError>;
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

// ---- phys→VA adapter: KernelRw over a physical primitive + the walk --------

/// A VA-aware [`KernelRw`] backed by a physical-memory driver + page walk.
/// `P` must support BOTH physical read AND physical write.
///
/// ## Address-space contract (kernelsdk-2-1)
/// This adapter presents the base [`KernelRw`] **virtual** contract: the
/// addresses fed to `kread`/`kwrite` are kernel VAs (canonical high-half,
/// `0xFFFF_8000_…`+). Every VA is validated with
/// [`crate::netsec::is_plausible_kernel_va`] before the walk, so feeding a
/// **physical** address (or a user VA) — the classic VA/PA mix-up — returns
/// a clear [`KrwError`] instead of walking a bogus page table or reading
/// unrelated memory. Contrast with `netsec::KrwPhysRead` / `read_process_mem`,
/// which require a PHYSICAL-addressing `KernelRw`; the two spaces must never
/// be mixed on one primitive.
///
/// ## Error contract
/// - VA fails the plausibility check → `KrwError::Other` naming the mix-up.
/// - Any page-table level not present (unmapped VA) → `KrwError::Other`
///   naming the failing level (PML4/PDPT/PD/PT).
/// - Driver IOCTL failure → `KrwError::Other("physical IOCTL failed")`.
/// Reads/writes that span a 4 KiB boundary are split per page and
/// RE-translated each chunk — consecutive virtual pages are rarely mapped
/// to contiguous physical pages, so linearly incrementing the PA would
/// read/write unrelated physical memory (a BSOD path on a live driver).
pub struct VaKernelRw<P: PhysRead + PhysWrite> {
    phys: P,
    /// The kernel CR3 (DirectoryTableBase) for VA→PA translation.
    cr3: u64,
}

impl<P: PhysRead + PhysWrite> VaKernelRw<P> {
    pub fn new(phys: P, cr3: u64) -> Self {
        Self { phys, cr3 }
    }

    /// The address space this adapter presents: `KernelRwAddressSpace::Virtual`
    /// (the base VA contract; the type lives in `crate::netsec`).
    ///
    /// Queryable at runtime so an operator can confirm an impl matches the
    /// consumer's expectation before wiring it into a page-walk (physical)
    /// path like `netsec::KernelLsassReader::read_process_mem`.
    pub fn address_space(&self) -> crate::netsec::KernelRwAddressSpace {
        crate::netsec::KernelRwAddressSpace::Virtual
    }
}

/// Adapt PhysReadError → KrwError.
fn map_phys_err(e: PhysReadError) -> KrwError {
    match e {
        PhysReadError::Ioctl => KrwError::Other("physical IOCTL failed".into()),
        PhysReadError::NotPresent { level } => {
            KrwError::Other(alloc::format!("page not present at {:?} level", level))
        }
        PhysReadError::Overflow => KrwError::Other("physical address overflow".into()),
    }
}

impl<P: PhysRead + PhysWrite + Send + Sync> KernelRw for VaKernelRw<P> {
    fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
        // Contract check: kread takes kernel VAs. A physical address (or user
        // VA) fed here means the caller mixed address spaces — error clearly
        // instead of walking garbage page tables (kernelsdk-2-1).
        if !crate::netsec::is_plausible_kernel_va(kaddr as u64) {
            return Err(KrwError::Other(
                "VaKernelRw: address is not a kernel VA (physical/user address fed to a \
                 VA-based KernelRw?)"
                    .into(),
            ));
        }
        // Chunk reads by 4KB page boundary — consecutive virtual pages are
        // rarely mapped to contiguous physical pages. Reading across a boundary
        // without re-translating fetches data from unrelated physical pages
        // (or past physical RAM), triggering bus errors / BSOD. Mirror kwrite.
        let mut va = kaddr as u64;
        let mut remaining = dst;
        while !remaining.is_empty() {
            let page_off = (va & 0xFFF) as usize;
            let bytes_in_page = 0x1000 - page_off;
            let chunk_len = remaining.len().min(bytes_in_page);
            let (chunk, rest) = remaining.split_at_mut(chunk_len);
            let pa = translate_va(&self.phys, self.cr3, va).map_err(map_phys_err)?;
            self.phys.read_phys(pa, chunk).map_err(map_phys_err)?;
            va += chunk_len as u64;
            remaining = rest;
        }
        Ok(())
    }

    fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError> {
        // Contract check: kwrite takes kernel VAs (see kread).
        if !crate::netsec::is_plausible_kernel_va(kaddr as u64) {
            return Err(KrwError::Other(
                "VaKernelRw: address is not a kernel VA (physical/user address fed to a \
                 VA-based KernelRw?)"
                    .into(),
            ));
        }
        // Write crossing a page boundary: walk each 4KB page separately.
        // Most kernel writes are small (u64 IsEnabled, pointer unlink) and
        // fit in one page, but handle the general case for correctness.
        let mut va = kaddr as u64;
        let mut remaining = src;
        while !remaining.is_empty() {
            // Bytes left in the current 4KB page.
            let page_off = (va & 0xFFF) as usize;
            let bytes_in_page = 0x1000 - page_off;
            let chunk_len = remaining.len().min(bytes_in_page);
            let (chunk, rest) = remaining.split_at(chunk_len);

            let pa = translate_va(&self.phys, self.cr3, va).map_err(map_phys_err)?;
            self.phys.write_phys(pa, chunk).map_err(map_phys_err)?;

            va += chunk_len as u64;
            remaining = rest;
        }
        Ok(())
    }
}

// SAFETY: VaKernelRw owns its PhysRead + PhysWrite + a u64 CR3.
// P: Send+Sync (by the trait bound) → VaKernelRw: Send+Sync.
unsafe impl<P: PhysRead + PhysWrite + Send + Sync> Send for VaKernelRw<P> {}
unsafe impl<P: PhysRead + PhysWrite + Send + Sync> Sync for VaKernelRw<P> {}

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

    #[test]
    fn translate_1gb_large_page() {
        // PDPT entry with bit 7 set (1 GiB page) → skip PD + PT levels.
        let cr3 = 0x1000;
        let mut mem = BTreeMap::new();
        mem.insert(0x1000, (0x2000u64 | 1).to_le_bytes());
        // PDPT[0]: 1 GiB large page, base 0x4000_0000 (1 GiB), present + large.
        let large_entry = 0x4000_0000u64 | 1 | (1 << 7);
        mem.insert(0x2000, large_entry.to_le_bytes());

        let reader = MockPhys { mem };
        // Offset 0x1234_5678 within the 1 GiB page (VA[29:0]).
        let va = 0x1234_5678u64;
        let pa = translate_va(&reader, cr3, va).unwrap();
        // PA = large_base | VA[29:0] = 0x4000_0000 | 0x1234_5678.
        assert_eq!(pa, 0x5234_5678);
    }

    #[test]
    fn pfn_above_4gb_is_not_truncated() {
        // The PFN mask must keep bits [51:12]: a page frame above 4 GiB
        // (bit 32+ of the PA) must survive the walk. A narrower mask (e.g.
        // 32-bit) would silently alias the page into low memory — on a live
        // driver that is a wrong-address read/write.
        let cr3 = 0x1000;
        let mut mem = BTreeMap::new();
        mem.insert(0x1000, (0x2000u64 | 1).to_le_bytes());
        mem.insert(0x2000, (0x3000u64 | 1).to_le_bytes());
        mem.insert(0x3000, (0x4000u64 | 1).to_le_bytes());
        // PT[0] → page at 0x1_2345_0000 (≈ 4.7 GiB), present.
        mem.insert(0x4000, (0x1_2345_0000u64 | 1).to_le_bytes());

        let reader = MockPhys { mem };
        let pa = translate_va(&reader, cr3, 0xABC).unwrap();
        assert_eq!(pa, 0x1_2345_0ABC, "PFN bits above 4 GiB must survive");
    }

    #[test]
    fn not_present_pdpt_and_pd_levels_report_their_level() {
        // The error contract names the failing level — a diagnosis of WHERE
        // the mapping ends (PML4-only vs deeper), not a generic failure.
        let cr3 = 0x1000;

        // PML4 present, PDPT entry absent.
        let mut mem = BTreeMap::new();
        mem.insert(0x1000, (0x2000u64 | 1).to_le_bytes());
        let reader = MockPhys { mem };
        assert!(matches!(
            translate_va(&reader, cr3, 0),
            Err(PhysReadError::NotPresent {
                level: PageLevel::Pdpt
            })
        ));

        // PML4 + PDPT present, PD entry absent.
        let mut mem = BTreeMap::new();
        mem.insert(0x1000, (0x2000u64 | 1).to_le_bytes());
        mem.insert(0x2000, (0x3000u64 | 1).to_le_bytes());
        let reader = MockPhys { mem };
        assert!(matches!(
            translate_va(&reader, cr3, 0),
            Err(PhysReadError::NotPresent {
                level: PageLevel::Pd
            })
        ));

        // Nothing present at all → fails at the PML4 level.
        let reader = MockPhys {
            mem: BTreeMap::new(),
        };
        assert!(matches!(
            translate_va(&reader, cr3, 0),
            Err(PhysReadError::NotPresent {
                level: PageLevel::Pml4
            })
        ));
    }

    // ---- VaKernelRw: phys→VA adapter over mock physical RAM ----------------

    use crate::netsec::KernelRwAddressSpace;
    use alloc::vec::Vec;
    use spin::mutex::Mutex;

    /// Mock physical RAM (sparse byte map) with a page-table builder — the
    /// physical-memory driver the adapter translates through. Out-of-range
    /// addresses read as 0, like an MmMapIoSpace'd hole.
    struct MockPhysMem {
        mem: Mutex<BTreeMap<u64, u8>>,
    }
    impl MockPhysMem {
        fn new() -> Self {
            Self {
                mem: Mutex::new(BTreeMap::new()),
            }
        }
        fn write(&self, pa: u64, bytes: &[u8]) {
            let mut m = self.mem.lock();
            for (i, b) in bytes.iter().enumerate() {
                m.insert(pa + i as u64, *b);
            }
        }
        fn write_u64(&self, pa: u64, v: u64) {
            self.write(pa, &v.to_le_bytes());
        }
        fn read_u8(&self, pa: u64) -> u8 {
            *self.mem.lock().get(&pa).unwrap_or(&0)
        }
        /// Map one 4 KiB page in tables rooted at `dtb` (bump-allocated
        /// intermediate tables).
        fn map_page(&self, dtb: u64, va: u64, pa: u64, bump: &mut u64) {
            let ensure = |entry_pa: u64, bump: &mut u64| -> u64 {
                let mut raw = [0u8; 8];
                self.read_phys(entry_pa, &mut raw).unwrap();
                let cur = u64::from_le_bytes(raw);
                if cur & 1 != 0 {
                    return cur & 0x000F_FFFF_FFFF_F000;
                }
                let table = *bump;
                *bump += 0x1000;
                self.write_u64(entry_pa, table | 1);
                table
            };
            let pdpt = ensure(
                (dtb & 0x000F_FFFF_FFFF_F000) + ((va >> 39) & 0x1FF) * 8,
                bump,
            );
            let pd = ensure(pdpt + ((va >> 30) & 0x1FF) * 8, bump);
            let pt = ensure(pd + ((va >> 21) & 0x1FF) * 8, bump);
            self.write_u64(pt + ((va >> 12) & 0x1FF) * 8, pa | 1);
        }
        /// Map a 2 MiB LARGE page (PD entry bit 7, no PT level).
        /// `pa` must be 2 MiB-aligned.
        fn map_large_page_2mb(&self, dtb: u64, va: u64, pa: u64, bump: &mut u64) {
            assert_eq!(pa & 0x1F_FFFF, 0, "2 MiB large-page base must be aligned");
            let ensure = |entry_pa: u64, bump: &mut u64| -> u64 {
                let mut raw = [0u8; 8];
                self.read_phys(entry_pa, &mut raw).unwrap();
                let cur = u64::from_le_bytes(raw);
                if cur & 1 != 0 {
                    return cur & 0x000F_FFFF_FFFF_F000;
                }
                let table = *bump;
                *bump += 0x1000;
                self.write_u64(entry_pa, table | 1);
                table
            };
            let pdpt = ensure(
                (dtb & 0x000F_FFFF_FFFF_F000) + ((va >> 39) & 0x1FF) * 8,
                bump,
            );
            let pd = ensure(pdpt + ((va >> 30) & 0x1FF) * 8, bump);
            self.write_u64(pd + ((va >> 21) & 0x1FF) * 8, pa | 1 | (1 << 7));
        }
    }
    impl PhysRead for MockPhysMem {
        fn read_phys(&self, pa: u64, dst: &mut [u8]) -> Result<(), PhysReadError> {
            let m = self.mem.lock();
            for (i, b) in dst.iter_mut().enumerate() {
                *b = *m.get(&(pa + i as u64)).unwrap_or(&0);
            }
            Ok(())
        }
    }
    impl PhysWrite for MockPhysMem {
        fn write_phys(&self, pa: u64, src: &[u8]) -> Result<(), PhysReadError> {
            self.write(pa, src);
            Ok(())
        }
    }

    const ADAPTER_CR3: u64 = 0x10_0000;
    const VA_A: u64 = 0xFFFF_8000_1000_0000;
    const PA_A: u64 = 0x20_0000;
    // Adjacent VA page maps to a NON-contiguous PA — the adapter must
    // re-translate at the page boundary, not linearly increment the PA.
    const PA_B: u64 = 0x35_0000;

    fn mapped_mem() -> MockPhysMem {
        let mem = MockPhysMem::new();
        let mut bump = 0x11_0000u64;
        mem.map_page(ADAPTER_CR3, VA_A, PA_A, &mut bump);
        mem.map_page(ADAPTER_CR3, VA_A + 0x1000, PA_B, &mut bump);
        mem
    }

    #[test]
    fn address_space_is_virtual() {
        let rw = VaKernelRw::new(MockPhysMem::new(), ADAPTER_CR3);
        assert_eq!(rw.address_space(), KernelRwAddressSpace::Virtual);
    }

    #[test]
    fn kread_crossing_page_boundary_retranslates() {
        let mem = mapped_mem();
        // Page A tail: 0x800 bytes of 0xAA; page B head: 0x800 bytes of 0xBB.
        mem.write(PA_A + 0x800, &[0xAA; 0x800]);
        mem.write(PA_B, &[0xBB; 0x800]);
        let rw = VaKernelRw::new(mem, ADAPTER_CR3);
        let mut buf = [0u8; 0x1000];
        rw.kread(VA_A as usize + 0x800, &mut buf).unwrap();
        assert_eq!(&buf[..0x800], &[0xAA; 0x800]);
        assert_eq!(
            &buf[0x800..],
            &[0xBB; 0x800],
            "second page must come from PA_B (0x350000), not PA_A+0x1000"
        );
    }

    impl PhysRead for &MockPhysMem {
        fn read_phys(&self, pa: u64, dst: &mut [u8]) -> Result<(), PhysReadError> {
            (**self).read_phys(pa, dst)
        }
    }
    impl PhysWrite for &MockPhysMem {
        fn write_phys(&self, pa: u64, src: &[u8]) -> Result<(), PhysReadError> {
            (**self).write_phys(pa, src)
        }
    }

    #[test]
    fn kwrite_crossing_page_boundary_lands_in_right_pages() {
        let mem = mapped_mem();
        let rw = VaKernelRw::new(&mem, ADAPTER_CR3);
        let src: Vec<u8> = (0..0x1000u32).map(|i| (i & 0xFF) as u8).collect();
        rw.kwrite(VA_A as usize + 0x800, &src).unwrap();
        // First chunk: src[0..0x800] → PA_A + 0x800.
        assert_eq!(mem.read_u8(PA_A + 0x800), 0x00);
        assert_eq!(mem.read_u8(PA_A + 0xFFF), 0xFF);
        // Second chunk: src[0x800..] → PA_B (NOT PA_A + 0x1000).
        assert_eq!(mem.read_u8(PA_B), 0x00);
        assert_eq!(mem.read_u8(PA_B + 0x7FF), 0xFF);
        // Nothing leaked into the linearly-adjacent PA page.
        assert_eq!(mem.read_u8(PA_A + 0x1000), 0x00);
    }

    #[test]
    fn physical_address_fed_as_va_is_rejected() {
        let mem = mapped_mem();
        let rw = VaKernelRw::new(mem, ADAPTER_CR3);
        let mut buf = [0u8; 8];
        // A physical address (< 2^46) fed to the VA-based adapter: the classic
        // VA/PA mix-up must error clearly, not walk garbage tables.
        let r = rw.kread(PA_A as usize, &mut buf);
        assert!(matches!(r, Err(KrwError::Other(_))));
        // User VAs are rejected too.
        assert!(rw.kread(0x0000_7FF0_0000_0000, &mut buf).is_err());
        assert!(rw.kwrite(0x20_0000, &[1, 2, 3]).is_err());
    }

    #[test]
    fn unmapped_va_surfaces_page_walk_error() {
        let mem = mapped_mem();
        let rw = VaKernelRw::new(mem, ADAPTER_CR3);
        let mut buf = [0u8; 8];
        // VA whose PML4 index has no entry (VA_A lives in PML4[0x1F0]; this
        // one is PML4[0x1F8]) — the walk fails at the PML4 level.
        let r = rw.kread(0xFFFF_C000_0000_0000usize, &mut buf);
        match r {
            Err(KrwError::Other(msg)) => {
                assert!(
                    msg.contains("Pml4"),
                    "error must name the failing level, got: {msg}"
                );
            }
            other => panic!("unmapped VA must fail the walk, got {other:?}"),
        }
    }

    #[test]
    fn kread_write_over_2mb_large_page() {
        // Kernel image / largepool regions are often 2 MiB large pages: the
        // adapter chunks by 4 KiB but each chunk re-translates through the
        // large-page PD entry, so reads/writes anywhere in the large page
        // land in the right physical frame.
        let mem = MockPhysMem::new();
        let mut bump = 0x11_0000u64;
        let large_pa = 0x40_0000u64; // 2 MiB-aligned
        mem.map_large_page_2mb(ADAPTER_CR3, VA_A, large_pa, &mut bump);
        let rw = VaKernelRw::new(&mem, ADAPTER_CR3);

        // Write a pattern spanning a 4 KiB boundary INSIDE the 2 MiB large
        // page (offset 0x1F_0800), then read it back through the walk.
        let va = VA_A + 0x1F_0800;
        let src: Vec<u8> = (0..0x1000u32).map(|i| (i & 0xFF) as u8).collect();
        rw.kwrite(va as usize, &src).unwrap();
        assert_eq!(mem.read_u8(large_pa + 0x1F_0800), 0x00);
        assert_eq!(mem.read_u8(large_pa + 0x1F_0FFF), 0xFF);
        // The cross-boundary half lands at the START of the NEXT 4 KiB frame
        // inside the SAME 2 MiB large page.
        assert_eq!(mem.read_u8(large_pa + 0x1F_1000), 0x00);
        assert_eq!(mem.read_u8(large_pa + 0x1F_17FF), 0xFF);

        let mut buf = [0u8; 0x1000];
        rw.kread(va as usize, &mut buf).unwrap();
        assert_eq!(buf[..], src[..], "read-back through the large page");
    }

    #[test]
    fn ioctl_failure_surfaces_as_clear_error() {
        // A driver IOCTL failure mid-walk (or on the data read) must surface
        // as an error — never a silent partial/garbage read.
        struct FailingPhys;
        impl PhysRead for FailingPhys {
            fn read_phys(&self, _pa: u64, _dst: &mut [u8]) -> Result<(), PhysReadError> {
                Err(PhysReadError::Ioctl)
            }
        }
        impl PhysWrite for FailingPhys {
            fn write_phys(&self, _pa: u64, _src: &[u8]) -> Result<(), PhysReadError> {
                Err(PhysReadError::Ioctl)
            }
        }
        let rw = VaKernelRw::new(FailingPhys, ADAPTER_CR3);
        let mut buf = [0u8; 8];
        assert!(matches!(
            rw.kread(VA_A as usize, &mut buf),
            Err(KrwError::Other(_))
        ));
        assert!(matches!(
            rw.kwrite(VA_A as usize, &[1, 2, 3]),
            Err(KrwError::Other(_))
        ));
    }
}

extern crate alloc;
