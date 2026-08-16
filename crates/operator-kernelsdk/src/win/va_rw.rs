//! VA-aware KernelRw over a physical-memory driver + page-table walk.
//!
//! Physical-only BYOVD drivers (e.g. WDTKernel, dbutil) operate on **physical**
//! addresses. The `KernelRw` trait works in kernel **virtual** addresses.
//! This adapter bridges them: each `kread/kwrite` call translates the VA to
//! physical via the 4-level page walk, then calls the driver's physical R/W.
//!
//! ## Address-space contract (kernelsdk-2-1)
//! This adapter presents the base [`KernelRw`] **virtual** contract: the
//! addresses fed to `kread`/`kwrite` are kernel VAs (canonical high-half,
//! `0xFFFF_8000_…`+). Every VA is validated with
//! [`crate::netsec::is_plausible_kernel_va`] before the walk, so feeding a
//! **physical** address (or a user VA) — the classic VA/PA mix-up — returns
//! a clear [`KrwError`] instead of walking a bogus page table or reading
//! unrelated memory. Contrast with `netsec::KrwPhysRead` / `read_process_mem`,
//! which require a PHYSICAL-addressing `KernelRw`; the two spaces must never
//! be mixed on one primitive.
//!
//! ## CR3 source
//! The page walk needs the kernel's CR3 (DirectoryTableBase). For kernel
//! addresses, CR3 is the SYSTEM process's DTB. We read it from
//! `PsInitialSystemProcess->DirectoryTableBase` via the physical driver
//! (chasing: resolve PsInitialSystemProcess VA → translate to PA via the
//! bootstrap CR3 → read the DTB field). The bootstrap CR3 comes from a
//! well-known physical address or NtQuerySystemInformation.

#![cfg(target_os = "windows")]

use crate::win::pagewalk::{translate_va, PhysRead, PhysReadError};
use crate::{KernelRw, KrwError};

/// Physical-memory write primitive (paired with [`PhysRead`]).
pub trait PhysWrite {
    fn write_phys(&self, pa: u64, src: &[u8]) -> Result<(), PhysReadError>;
}

/// A VA-aware KernelRw backed by a physical-memory driver + page walk.
/// `P` must support BOTH physical read AND physical write.
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
    use crate::netsec::KernelRwAddressSpace;
    use alloc::collections::BTreeMap;
    use spin::mutex::Mutex;

    /// Mock physical RAM (sparse byte map) with a page-table builder — the
    /// physical-memory driver the adapter translates through.
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
            let pdpt = ensure((dtb & 0x000F_FFFF_FFFF_F000) + ((va >> 39) & 0x1FF) * 8, bump);
            let pd = ensure(pdpt + ((va >> 30) & 0x1FF) * 8, bump);
            let pt = ensure(pd + ((va >> 21) & 0x1FF) * 8, bump);
            self.write_u64(pt + ((va >> 12) & 0x1FF) * 8, pa | 1);
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

    const CR3: u64 = 0x10_0000;
    const VA_A: u64 = 0xFFFF_8000_1000_0000;
    const PA_A: u64 = 0x20_0000;
    // Adjacent VA page maps to a NON-contiguous PA — the adapter must
    // re-translate at the page boundary, not linearly increment the PA.
    const PA_B: u64 = 0x35_0000;

    fn mapped_mem() -> MockPhysMem {
        let mem = MockPhysMem::new();
        let mut bump = 0x11_0000u64;
        mem.map_page(CR3, VA_A, PA_A, &mut bump);
        mem.map_page(CR3, VA_A + 0x1000, PA_B, &mut bump);
        mem
    }

    #[test]
    fn address_space_is_virtual() {
        let rw = VaKernelRw::new(MockPhysMem::new(), CR3);
        assert_eq!(rw.address_space(), KernelRwAddressSpace::Virtual);
    }

    #[test]
    fn kread_crossing_page_boundary_retranslates() {
        let mem = mapped_mem();
        // Page A tail: 0x800 bytes of 0xAA; page B head: 0x800 bytes of 0xBB.
        mem.write(PA_A + 0x800, &[0xAA; 0x800]);
        mem.write(PA_B, &[0xBB; 0x800]);
        let rw = VaKernelRw::new(mem, CR3);
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
        let rw = VaKernelRw::new(&mem, CR3);
        let src: alloc::vec::Vec<u8> = (0..0x1000u32).map(|i| (i & 0xFF) as u8).collect();
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
        let rw = VaKernelRw::new(mem, CR3);
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
        let rw = VaKernelRw::new(mem, CR3);
        let mut buf = [0u8; 8];
        // VA in an unmapped region (no PML4 entry for this index).
        let r = rw.kread(0xFFFF_8000_9000_0000usize, &mut buf);
        assert!(matches!(r, Err(KrwError::Other(_))));
    }
}
