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

use crate::win::pagewalk::{PhysRead, PhysReadError, translate_va};
use crate::{KernelRw, KrwError};

/// A VA-aware KernelRw backed by a physical-memory driver + page walk.
pub struct VaKernelRw<P: PhysRead> {
    phys: P,
    /// The kernel CR3 (DirectoryTableBase) for VA→PA translation.
    cr3: u64,
}

impl<P: PhysRead> VaKernelRw<P> {
    pub fn new(phys: P, cr3: u64) -> Self {
        Self { phys, cr3 }
    }
}

/// Adapt PhysReadError → KrwError.
fn map_phys_err(e: PhysReadError) -> KrwError {
    match e {
        PhysReadError::Ioctl => KrwError::Other("physical read IOCTL failed".into()),
        PhysReadError::NotPresent { level } => KrwError::Other(
            alloc::format!("page not present at {:?} level", level),
        ),
        PhysReadError::Overflow => KrwError::Other("physical address overflow".into()),
    }
}

impl<P: PhysRead + Send + Sync> KernelRw for VaKernelRw<P> {
    fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
        let pa = translate_va(&self.phys, self.cr3, kaddr as u64).map_err(map_phys_err)?;
        self.phys.read_phys(pa, dst).map_err(map_phys_err)
    }

    fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError> {
        let pa = translate_va(&self.phys, self.cr3, kaddr as u64).map_err(map_phys_err)?;
        // Need a write-capable adapter — PhysRead only has read. For now,
        // physical-write is added via a separate trait (PhysWrite) in the
        // consumer. This returns an error if the consumer hasn't bound writes.
        let _ = (pa, src);
        Err(KrwError::Other("VaKernelRw write requires a PhysWrite binding — use ByovdDriver directly for writes".into()))
    }
}

// SAFETY: VaKernelRw owns its PhysRead + a u64 CR3. PhysRead: Send+Sync (by
// the trait bound) → VaKernelRw: Send+Sync → satisfies KernelRw: Send+Sync.
unsafe impl<P: PhysRead + Send + Sync> Send for VaKernelRw<P> {}
unsafe impl<P: PhysRead + Send + Sync> Sync for VaKernelRw<P> {}
