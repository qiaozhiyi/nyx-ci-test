//! System-process CR3 discovery by physical-memory scan — pure algorithm,
//! host-testable.
//!
//! A phys-only BYOVD driver (WDTKernel) gives raw physical R/W but no CR3.
//! The page walk in [`crate::pagewalk`] needs the System process's
//! DirectoryTableBase, so we scan physical RAM for the System `_EPROCESS`
//! and read it. Gating, in order:
//!   1. ASCII `System\0` needle (`_EPROCESS.ImageFileName`, build-specific
//!      offset from [`EprocessOffsets`]),
//!   2. candidate base 0x40-aligned (pool object allocation alignment),
//!   3. `UniqueProcessId == 4` (the System process),
//!   4. non-zero `DirectoryTableBase` (+0x28 — KPROCESS is embedded at
//!      `_EPROCESS+0` and ABI-frozen; 0x28 on every build 10240–26200),
//!   5. DECISIVE: page-walk the ntoskrnl base VA through the candidate CR3
//!      and require `MZ` at the resolved physical page (false-positive
//!      probability ≈ 0 — a bogus DTB is discarded, never fed to the walk).
//!
//! ## Chunk-boundary carry
//! The scan reads 1 MiB chunks. The 7-byte needle can straddle a chunk
//! boundary, so each iteration carries the last `NEEDLE - 1` bytes of the
//! previous window as a prefix for the search (the reads themselves are
//! unchanged — same PAs, same budget). The original disjoint-chunk scan
//! missed a boundary-straddling needle; the regression test below places
//! `System\0` split 3+4 across the 1 MiB boundary.
//!
//! The WDTKernel phys-mode bootstrap ([`crate::win::wdt`]) drives this with
//! a live `\\.\__WDT__` handle; unit tests drive it with mock RAM.

use crate::offsets::EprocessOffsets;
use crate::pagewalk::{translate_va, PhysRead};
use alloc::vec;

/// `_KPROCESS.DirectoryTableBase` — x64 offset inside `_EPROCESS`. KPROCESS
/// is embedded at `_EPROCESS+0` and ABI-frozen; 0x28 on every build
/// 10240–26200 (matches the pg-pdb-verify symbol-server pass).
pub const DIRECTORY_TABLE_BASE_OFF: u64 = 0x28;

/// Bytes per physical read during the CR3 scan (one MmMapIoSpace mapping).
const SCAN_CHUNK: usize = 1024 * 1024;

/// `_EPROCESS.ImageFileName` needle for the System process.
const NEEDLE: &[u8; 7] = b"System\x00";

/// Consecutive failed chunks before giving up (a long hole ⇒ past RAM end).
const MAX_SCAN_FAILURES: u32 = 32;

/// Scan physical RAM for the System EPROCESS and return its CR3.
///
/// `scan_budget_mb` caps the scan in MiB (default 2048 from the CLI). Reads
/// 1 MiB chunks from PA 0x1000 upward; inside each chunk window (previous
/// chunk's 6-byte tail ++ fresh chunk) looks for the ASCII `System\0` of
/// `_EPROCESS.ImageFileName` at the build-specific offset. For each
/// candidate (pool-aligned, PID 4), reads `DirectoryTableBase`, then
/// VALIDATES by walking the ntoskrnl base VA through it — the resolved
/// physical page must start with `MZ`. Only a validated CR3 is returned;
/// everything else is discarded.
pub fn discover_system_cr3<P: PhysRead>(
    phys: &P,
    nt_base: u64,
    ep: &EprocessOffsets,
    scan_budget_mb: usize,
) -> Option<u64> {
    let budget = scan_budget_mb
        .max(1)
        .saturating_mul(1024 * 1024)
        .max(SCAN_CHUNK) as u64;
    // Search window = tail-overlap from the previous chunk (NEEDLE - 1
    // bytes) ++ the freshly read chunk, so a needle split across a chunk
    // boundary is found. Chunk reads are unchanged (same PAs, same budget,
    // same failure accounting).
    const TAIL: usize = NEEDLE.len() - 1;
    let mut win = vec![0u8; SCAN_CHUNK + TAIL];
    let mut tail: usize = 0;
    let mut pa: u64 = 0x1000;
    let mut failures: u32 = 0;
    while pa < budget {
        let n = (budget - pa).min(SCAN_CHUNK as u64) as usize;
        if phys.read_phys(pa, &mut win[tail..tail + n]).is_err() {
            failures += 1;
            if failures >= MAX_SCAN_FAILURES {
                break; // long hole ⇒ past the end of physical RAM
            }
            tail = 0; // hole: the next chunk is NOT contiguous with this one
            pa += n as u64;
            continue;
        }
        failures = 0;

        // Global physical address of win[0].
        let base = pa - tail as u64;
        let win_len = tail + n;
        for i in 0..win_len.saturating_sub(NEEDLE.len() - 1) {
            if win[i..i + NEEDLE.len()] != NEEDLE[..] {
                continue;
            }
            let g = base + i as u64; // global PA of the needle
            if g < ep.image_file_name as u64 {
                continue;
            }
            let ep_pa = g - ep.image_file_name as u64;
            if ep_pa % 0x40 != 0 {
                continue; // object allocation alignment
            }
            // Secondary structural check: the System process has PID 4.
            let mut pid = [0u8; 8];
            if phys
                .read_phys(ep_pa + ep.unique_process_id as u64, &mut pid)
                .is_err()
            {
                continue;
            }
            if u64::from_le_bytes(pid) != 4 {
                continue;
            }
            // DirectoryTableBase at +0x28 (KPROCESS, ABI-frozen).
            let mut dtb = [0u8; 8];
            if phys
                .read_phys(ep_pa + DIRECTORY_TABLE_BASE_OFF, &mut dtb)
                .is_err()
            {
                continue;
            }
            let cr3 = u64::from_le_bytes(dtb) & 0x000F_FFFF_FFFF_F000;
            if cr3 == 0 {
                continue;
            }
            // Decisive validation: ntoskrnl base VA → PA via candidate CR3,
            // and the mapped page must start with the DOS header.
            if let Ok(nt_pa) = translate_va(phys, cr3, nt_base) {
                let mut mz = [0u8; 2];
                if phys.read_phys(nt_pa, &mut mz).is_ok() && &mz == b"MZ" {
                    return Some(cr3);
                }
            }
        }
        // Carry the last NEEDLE - 1 bytes into the next chunk's window.
        tail = TAIL.min(win_len);
        win.copy_within(win_len - tail..win_len, 0);
        pa += n as u64;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pagewalk::PhysReadError;
    use alloc::vec::Vec;

    /// Dense mock physical RAM. Out-of-range reads fail like a driver IOCTL
    /// hitting unmapped physical memory (this is also how the scan detects
    /// the end of RAM).
    struct MockPhysRam {
        mem: Vec<u8>,
    }
    impl MockPhysRam {
        fn new(size: usize) -> Self {
            Self {
                mem: vec![0u8; size],
            }
        }
        fn write(&mut self, pa: u64, bytes: &[u8]) {
            let start = pa as usize;
            self.mem[start..start + bytes.len()].copy_from_slice(bytes);
        }
        fn write_u64(&mut self, pa: u64, v: u64) {
            self.write(pa, &v.to_le_bytes());
        }
        /// Map one 4 KiB page in tables rooted at `dtb` (bump-allocated
        /// intermediate tables) — same builder as pagewalk's MockPhysMem.
        fn map_page(&mut self, dtb: u64, va: u64, pa: u64, bump: &mut u64) {
            let mut ensure = |entry_pa: u64, bump: &mut u64| -> u64 {
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
    }
    impl PhysRead for MockPhysRam {
        fn read_phys(&self, pa: u64, dst: &mut [u8]) -> Result<(), PhysReadError> {
            let start = pa as usize;
            let end = start.checked_add(dst.len()).ok_or(PhysReadError::Ioctl)?;
            if end > self.mem.len() {
                return Err(PhysReadError::Ioctl);
            }
            dst.copy_from_slice(&self.mem[start..end]);
            Ok(())
        }
    }

    /// Real table offsets for build 19041 (ImageFileName 0x5a8, PID 0x440).
    fn ep_19041() -> EprocessOffsets {
        crate::offsets::for_build(19041).unwrap().offsets
    }

    const NT_VA: u64 = 0xFFFF_8000_1000_0000;
    const CR3: u64 = 0x50_0000;
    const NT_PA: u64 = 0x60_0000;

    /// 8 MiB of mock RAM with ntoskrnl's `MZ` page mapped through CR3.
    fn ram_with_nt() -> MockPhysRam {
        let mut ram = MockPhysRam::new(0x80_0000);
        let mut bump = 0x61_0000u64;
        ram.map_page(CR3, NT_VA, NT_PA, &mut bump);
        ram.write(NT_PA, b"MZ");
        ram
    }

    /// Plant a fake System EPROCESS at `ep_pa` (must be 0x40-aligned):
    /// "System\0" name, UniqueProcessId == 4, DirectoryTableBase == CR3.
    fn plant_system_eprocess(ram: &mut MockPhysRam, ep: &EprocessOffsets, ep_pa: u64) {
        assert_eq!(ep_pa % 0x40, 0);
        ram.write(ep_pa + ep.image_file_name as u64, b"System\x00");
        ram.write_u64(ep_pa + ep.unique_process_id as u64, 4);
        ram.write_u64(ep_pa + DIRECTORY_TABLE_BASE_OFF, CR3);
    }

    /// All budget-1 placements must sit BELOW 0x100000 — the minimum scan
    /// budget covers exactly [0x1000, 0x100000).
    const EP_PA: u64 = 0x8_0000;

    #[test]
    fn scan_finds_system_eprocess_and_validates_cr3() {
        let ep = ep_19041();
        let mut ram = ram_with_nt();
        plant_system_eprocess(&mut ram, &ep, EP_PA);
        let cr3 = discover_system_cr3(&ram, NT_VA, &ep, 1);
        assert_eq!(cr3, Some(CR3));
    }

    #[test]
    fn scan_skips_decoys_and_finds_real_candidate() {
        let ep = ep_19041();
        let mut ram = ram_with_nt();
        // Decoy 1: name + PID 4 but NOT 0x40-aligned.
        ram.write(0x4_0020 + ep.image_file_name as u64, b"System\x00");
        ram.write_u64(0x4_0020 + ep.unique_process_id as u64, 4);
        ram.write_u64(0x4_0020 + DIRECTORY_TABLE_BASE_OFF, CR3);
        // Decoy 2: aligned + name but wrong PID.
        ram.write(0x6_0000 + ep.image_file_name as u64, b"System\x00");
        ram.write_u64(0x6_0000 + ep.unique_process_id as u64, 0x1234);
        ram.write_u64(0x6_0000 + DIRECTORY_TABLE_BASE_OFF, CR3);
        // Real candidate sits ABOVE both decoys — the scan must skip them.
        plant_system_eprocess(&mut ram, &ep, EP_PA);
        let cr3 = discover_system_cr3(&ram, NT_VA, &ep, 1);
        assert_eq!(cr3, Some(CR3));
    }

    #[test]
    fn misaligned_candidate_is_rejected() {
        let ep = ep_19041();
        let mut ram = ram_with_nt();
        // ep_pa 0x20-aligned but not 0x40-aligned.
        ram.write(0x8_0020 + ep.image_file_name as u64, b"System\x00");
        ram.write_u64(0x8_0020 + ep.unique_process_id as u64, 4);
        ram.write_u64(0x8_0020 + DIRECTORY_TABLE_BASE_OFF, CR3);
        assert_eq!(discover_system_cr3(&ram, NT_VA, &ep, 1), None);
    }

    #[test]
    fn wrong_pid_candidate_is_rejected() {
        let ep = ep_19041();
        let mut ram = ram_with_nt();
        ram.write(EP_PA + ep.image_file_name as u64, b"System\x00");
        ram.write_u64(EP_PA + ep.unique_process_id as u64, 0x1234);
        ram.write_u64(EP_PA + DIRECTORY_TABLE_BASE_OFF, CR3);
        assert_eq!(discover_system_cr3(&ram, NT_VA, &ep, 1), None);
    }

    #[test]
    fn wrong_name_candidate_is_rejected() {
        let ep = ep_19041();
        let mut ram = ram_with_nt();
        // "SystemX" — the NUL terminator is part of the needle, so this
        // never matches even though every other gate would pass.
        ram.write(EP_PA + ep.image_file_name as u64, b"SystemX");
        ram.write_u64(EP_PA + ep.unique_process_id as u64, 4);
        ram.write_u64(EP_PA + DIRECTORY_TABLE_BASE_OFF, CR3);
        assert_eq!(discover_system_cr3(&ram, NT_VA, &ep, 1), None);
    }

    #[test]
    fn candidate_with_bogus_dtb_fails_mz_validation() {
        let ep = ep_19041();
        let mut ram = ram_with_nt();
        // Name + alignment + PID all pass, but the DTB points at zeroed
        // memory (PML4 not present) → page-walk validation must reject it.
        ram.write(EP_PA + ep.image_file_name as u64, b"System\x00");
        ram.write_u64(EP_PA + ep.unique_process_id as u64, 4);
        ram.write_u64(EP_PA + DIRECTORY_TABLE_BASE_OFF, 0x30_0000);
        assert_eq!(discover_system_cr3(&ram, NT_VA, &ep, 1), None);
        // Zero DTB is rejected before the walk too.
        ram.write_u64(EP_PA + DIRECTORY_TABLE_BASE_OFF, 0);
        assert_eq!(discover_system_cr3(&ram, NT_VA, &ep, 1), None);
    }

    /// Regression: the 7-byte needle straddling the 1 MiB chunk boundary
    /// (3 bytes in chunk 1, 4 in chunk 2) must still be found. The original
    /// disjoint-chunk scan missed this — chunk 1's search stops 7 bytes
    /// short of the boundary and chunk 2 starts past the needle's head.
    #[test]
    fn needle_straddling_chunk_boundary_is_found() {
        // ImageFileName 0x5bd (mod 0x40 = 0x3d) puts the needle head at
        // 0x...FFD for a 0x40-aligned EPROCESS — i.e. 3 bytes before the
        // 0x101000 chunk boundary. (With the real 0x5a8 the aligned
        // placement never straddles THIS boundary; the gate logic is
        // offset-agnostic.)
        let ep = EprocessOffsets {
            image_file_name: 0x5bd,
            ..ep_19041()
        };
        let mut ram = ram_with_nt();
        // Chunk 1 = [0x1000, 0x101000): needle at 0x100FFD..0x101003.
        let ep_pa = 0x100A40u64;
        assert_eq!((ep_pa + 0x5bd) % 0x1_0000, 0xFFD % 0x1_0000);
        plant_system_eprocess(&mut ram, &ep, ep_pa);
        // Budget 2 MiB ⇒ exactly two chunk reads; the needle is split
        // across them.
        let cr3 = discover_system_cr3(&ram, NT_VA, &ep, 2);
        assert_eq!(cr3, Some(CR3), "boundary-straddling needle must be found");
    }

    /// The scan budget caps the search: a candidate placed beyond the
    /// budget is not found.
    #[test]
    fn candidate_beyond_scan_budget_is_not_found() {
        let ep = ep_19041();
        let mut ram = ram_with_nt();
        // Budget 1 MiB scans [0x1000, 0x100000); the candidate sits in the
        // second MiB.
        plant_system_eprocess(&mut ram, &ep, 0x18_0000);
        assert_eq!(discover_system_cr3(&ram, NT_VA, &ep, 1), None);
    }
}
