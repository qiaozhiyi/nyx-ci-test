# Nyx P2 — Windows-Bypass Research Survey (top-venue, annotated)

Comprehensive sweep of **top-venue** Windows-bypass research (USENIX Security,
IEEE S&P/Oakland, ACM CCS, NDSS, RAID, Black Hat, DEF CON, BlueHat, OffensiveCon)
+ high-signal industry research, for authorized red-team enhancement of Nyx.
Annotated + mapped to concrete Nyx enhancements. Complements
`docs/p2-edr-bypass-plan.md` (the layered plan) — this is the **evidence base**.

## A. EDR architecture & telemetry (understand the target)
- **[EvilEDR — USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-alachkar.pdf)** — "EDR repurposing": turn the EDR's own kernel presence into the offensive primitive. The cornerstone paper for Nyx's kernel tier.
- **[Evolution of EDR — E3S 2024 (42+ cites)](https://www.e3s-conferences.org/articles/e3sconf/pdf/2024/86/e3sconf_rawmu2024_01006.pdf)** — comprehensive EDR review (detection methods, scaling, evasion).
- **[EDR Tradecraft: Internals, Detection, Evasion](https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/)** — practitioner reference; dedicated ETW-TI-bypass section.
- **[Endpoint Security Evasion 2020–2025: Bypass→Kill](https://windshock.github.io/en/post/2025-05-28-endpoint-security-evasion-techniques-20202025/)** — BYOI/BYOVD/DLL-hijack/service-abuse taxonomy.
→ *Nyx: ground the threat-model section of the plan in these.*

## B. Userland hook bypass — DONE in Nyx
- **[RedOps — Indirect syscalls + Halos Gate](https://redops.at/en/blog/indirect-syscalls-and-hooked-ssns)** · **[Hadess — Hell's Hall (PDF)](https://hadess.io/wp-content/uploads/2023/10/EDR-Evasion-Techniques-using-Syscalls.pdf)**.
→ *Nyx already ships this (`crates/evasion`: Hells/Halos/Tartarus Gate + indirect stubs).*

## C. Kernel callbacks — removal / repurpose (the kernel tier)
- **[EDRSandBlast — Wavestone](https://github.com/wavestone-cdt/EDRSandblast)** — weaponizes a vulnerable signed driver to disable **Notify-Routine + Object callbacks + ETW-TI** together. Reference implementation for Nyx's `CallbackKit`.
- **[RealBlindingEDR (2025)](https://siembiot.eu/cyber-security-news/realblindingedr-tool-that-permanently-turns-off-av-edr-using-kernel-callbacks/58811)** — clears critical kernel callbacks to permanently blind AV/EDR. **[Analysis](https://medium.com/@iambivash.bn/analyzing-realblindingedrs-novel-technique-to-disable-windows-security-via-kernel-callback-e4fd9bc8b61f)**.
- **[MDSec — Bypassing Image Load Kernel Callbacks](https://www.mdsec.co.uk/2021/06/bypassing-image-load-kernel-callbacks/)** — `PsSetLoadImageNotifyRoutine` bypass.
- **[Blinding EDR On Windows — synzack](https://synzack.github.io/Blinding-EDR-On-Windows/)** — Ps-callback experiments; cites Hoang Bui + Omri Misgav/Udi Yavo on EDR memory-protection bypass.
- **[Detecting EDR Bypass: Malicious Drivers (Kernel Callbacks)](https://posts.bluraven.io/detecting-edr-bypass-malicious-drivers-kernel-callbacks-f5e6bf8f7481)** — the defensive flip side (what to anticipate).
- **[Kernel Karnage — NVISO](https://blog.nviso.eu/2021/10/21/kernel-karnage-part-1/)** — series on bypassing EDR from the kernel.
→ *Nyx: `CallbackKit` (repurpose/remove Ps + Ob callbacks) — prefer **repurpose** (EvilEDR) over remove.*

## D. ETW + ETW-TI — blind AND deceive
- **[Black Hat USA 2025 — "I'm in Your Logs Now" (ETW deception)](https://www.youtube.com/watch?v=G3Ft0gtmm4I)** — **NEW angle**: don't just blind ETW, **forge/manipulate telemetry** to deceive the SOC. Stronger than suppression.
- **[Praetorian — ETW-TI + Hardware Breakpoints](https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/)** · **[undev.ninja — Intro to TI ETW](https://undev.ninja/introduction-to-threat-intelligence-etw/)** — `NtContinue` HW-BP bypass of ETW-TI callbacks.
- **[fluxsec.red — ETW patching in Rust](https://fluxsec.red/etw-patching-rust)** — directly applicable to Nyx (Rust implant).
→ *Nyx: extend `blind.rs` from suppress-only to suppress+deceive (forge benign ETW events).*

## E. PatchGuard / KPP bypass — the gating primitive for PERSISTENT kernel hooks
*Why it matters: PatchGuard is why SSDT/inline kernel hooks don't persist. Bypassing it unlocks the whole "old-school" persistent-hook toolbox modern EDR assumes is dead.*
- **[Melting Down PatchGuard (KPTI-based bypass) — Fortinet](https://www.fortinet.com/blog/threat-research/melting-down-patchguard-leveraging-kpi-to-bypass-kernel-patch-protection)** — novel KPTI lever.
- **[Windows 11 24H2 PatchGuard analysis + new bypass — HackMD](https://hackmd.io/@Wane/BymwoGa5ee)** — current Win11.
- **[Kento Ooki PatchGuard bug → unsigned kernel code — Cyber Defense Mag](https://www.cyberdefensemagazine.com/experts-devised/)**.
- **[PatchGuard Peekaboo (2026) — Outflank](https://www.outflank.nl/blog/2026/01/07/patchguard-peekaboo-hiding-processes-on-systems-with-patchguard-in-2026/)** — process hiding with PG live.
- **[PatchGuard Internals — r0keb](https://r0keb.github.io/posts/PatchGuard-Internals/)** · **[Cisco Talos — Uroburs vs PG](https://blog.talosintelligence.com/the-windows-81-kernel-patch-protection/)**.
→ *Nyx: a `PatchGuardKit` (PG-bypass + relocation-safe hooking) is the prerequisite for any persistent-kernel-hook module; track the KPTI + 24H2 bypasses.*

## F. Memory & sleep obfuscation — defeat memory forensics
- **[Defeating EDR: Evading Malware with Memory Forensics — DEF CON 24 (Volexity/Andrew Case)](https://www.volexity.com/wp-content/uploads/2024/08/Defcon24_EDR_Evasion_Detection_White-Paper_Andrew-Case.pdf)** — **the defense side**: how memory forensics catches sleep-obfuscated beacons. Read this to know what the sleep mask must defeat.
- **[Foliage sleep obfuscation — oblivion-malware](https://oblivion-malware.xyz/posts/sleep-obf-foliage/)** · **[IBM X-Force — hide beacon during BOF](https://www.ibm.com/think/x-force/how-to-hide-beacon-during-bof-execution)**.
- **[Module stomping — dtsec](https://dtsec.us/2023-11-04-ModuleStompin/)** · **[advanced module stomping (heap/stack enc)](https://oblivion-malware.xyz/posts/advanced-module-stomping-heap-stack-enc/)** · **[Threadless Ops II — Avantguard](https://avantguard.io/en/blog/threadless-ops-ii-enhanced-evasion)**.
- **[Behind the Mask (call-stack spoof) — Cobalt Strike](https://www.cobaltstrike.com/blog/behind-the-mask-spoofing-call-stacks-dynamically-with-timers)** · **[InsomniacUnwinding](https://lorenzomeacci.com/unwind-data-cant-sleep-introducing-insomniacunwinding)** · **[mgeeky/ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer)**.
→ *Nyx P2.1: implement `SleepmaskKit` (Ekko/Foliage) + stack-spoof, validated against the DEF CON 24 forensics techniques.*

## G. VBS / HVCI / enclaves — the new frontier
- **[Abusing VBS Enclaves to Create Evasive Malware — Akamai](https://www.akamai.com/blog/security-research/abusing-vbs-enclaves-evasive-malware)** — **NEW**: run beacon inside a VBS enclave where the EDR cannot introspect memory. High-value future evasion haven.
- **[Connor McGarr — Living in the Age of VBS/HVCI](https://connormcgarr.github.io/hvci/)** — exploitation under VBS/HVCI + bypass strategies.
- **[CVE-2024-21305 — HVCI security-feature bypass (ZDI, Jan 2024)](https://www.thezdi.com/blog/2024/1/9/the-january-2024-security-update-review)**.
→ *Nyx: track VBS-enclave execution as a P2.3 research item — enclave-resident beacon is EDR-opaque by construction.*

## H. Rootkits / minifilter / IRP — file & registry hiding
- **[Kernel-level Rootkit Detection, Prevention, Behavior Profiling — arXiv 2304.00473](https://arxiv.org/pdf/2304.00473)** — academic; memory-resident rootkit evolution.
- **[Benthic — minifilter rootkit (IRP file/folder hiding)](https://github.com/TheMalwareGuardian/Benthic)** · **[Fantastic Rootkits Pt 2 — CyberArk (Husky/Mingloa)](https://www.cyberark.com/resources/threat-research-blog/fantastic-rootkits-and-where-to-find-them-part-2)** · **[Anti-Anti-Rootkit (stomped drivers/hidden threads) — eversinc33](https://eversinc33.com/2024/09/19/anti-anti-rootkit-techniques-part-ii-stomped-drivers-and-hidden-threads)**.
→ *Nyx: a minifilter-based hide module (files/registry/process) gated behind SYSTEM — reference Benthic's IRP filtering.*

## I. Virtualization (ring -1)
- **[NICKLE — VMM-based rootkit prevention (RAID 2008)](https://www.cs.purdue.edu/homes/dxu/pubs/RAID08.pdf)** (defense, foundational) · **[Blue Pill — Wikipedia](https://en.wikipedia.org/wiki/Blue_Pill_(software))** · **[SoK index (Oakland)](https://oaklandsok.github.io/)** · **[Creating Modern Blue Pills and Red Pills — JYX](https://jyx.jyu.fi/bitstreams/90680d4e-489c-4dd0-8eb6-e9fea2f794b2/download)**.
→ *Nyx: lowest practical priority — VBS counters it; document only.*

## J. eBPF (Linux/cloud + Windows frontier)
- **[TripleCross — offensive eBPF (academic PDF)](https://raw.githubusercontent.com/h3xduck/TripleCross/master/docs/ebpf_offensive_rootkit_tfg.pdf)** · **[ebpfkit — Datadog](https://github.com/Gui774ume/ebpfkit)** · **[LinkPro — Synacktiv 2025](https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis)**.
- Evasion: **[Doyensec](https://blog.doyensec.com/2022/10/11/ebpf-bypass-security-monitoring.html)** · **[Form3](https://www.form3.tech/blog/engineering/bypassing-ebpf-tools)** · **[io_uring syscall bypass — linuxsecurity](https://linuxsecurity.com/features/ebpf-security-tools-rootkit-evasion)**.
→ *Nyx Linux v2 agent: an eBPF-abuse module (privileged BPF to subvert/blind Tetragon/Falco + io_uring ops).*

## K. Hardware (DMA) — EDR-blind by construction
- **[PCILeech — FPGA DMA kernel R/W](https://github.com/ufrink/pcileech)** · **[MITRE emb3D TID-107](https://emb3d.mitre.org/threats/TID-107.html)** · **[Eclypsium — DMA attacks](https://eclypsium.com/blog/direct-memory-access-attacks-a-walk-down-memory-lane/)**.
→ *Nyx: DMA as the hardware-assisted bootstrap into the kernel tier (no telemetered driver load).*

## L. UEFI / firmware persistence
- **[BlackLotus (CVE-2022-21894 Baton Drop) — ESET](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)** · **[CosmicStrand — Kaspersky](https://www.kaspersky.com/about/press-releases/cosmicstrand-sophisticated-firmware-rootkit-allows-durable-persistence)** · **[Binarly — BlackLotus deep-dive](https://www.binarly.io/blog/untold-story-blacklotus-uefi-bootkit)**.
→ *Nyx: persistence tier (not runtime evasion) — separate milestone.*

## Consolidated Nyx enhancement map (research → build)
| Research finding | Nyx module | Priority |
|---|---|---|
| EvilEDR (USENIX'25) | `RepurposeKit` (ride resident EDR) | P2.2 core |
| EDRSandBlast / RealBlindingEDR / MDSec | `CallbackKit` (Ps+Ob callbacks) | P2.2 |
| Black Hat'25 ETW deception + Praetorian | `blind.rs` → suppress+**forge** | P2.1→P2.2 |
| KPTI/KentoOoki/24H2/Outflank PG bypass | `PatchGuardKit` (persistent-hook enabler) | P2.2 gate |
| DEF CON'24 forensics + Foliage/Ekko + stack-spoof | `SleepmaskKit` impl | **P2.1** |
| Akamai VBS enclaves | enclave-resident beacon | P2.3 research |
| arXiv rootkit + Benthic minifilter | hide module (file/reg/proc) | P2.2 |
| ebpfkit/TripleCross/LinkPro + io_uring | eBPF-abuse module | Linux v2 |
| PCILeech | DMA bootstrap to kernel | engagement-gated |
| BlackLotus/CosmicStrand | UEFI persistence | separate milestone |

## Gaps / open questions
- Few **formal academic** (IEEE/USENIX/CCS) papers specifically on PatchGuard bypass (it's mostly industry research — PG internals are partly undocumented). The HackMD/Fortinet/Outflank sources are the current best.
- eBPF-for-Windows offensive research is nascent — monitor as it matures.
- HVCI/VBS-on hosts degrade most kernel tiers to userland-only (P2.1) — per-host capability detection belongs in the beacon.

---

# Revision 2 — 2026-current (mid-2026 sweep)

Re-searched with 2026 recency. The standout NEW current items:

## M. eBPF — "Curing" io_uring rootkit (the definitive 2026 PoC)
- **[ARMO — Curing io_uring rootkit](https://www.armosec.io/blog/io-uring-rootkit-bypasses-linux-security/)** · **[InfoQ 2025-09](https://www.infoq.com/news/2025/09/linux-security-rootkit/)** · **[THN 2025-04](https://thehackernews.org/2025/04/linux-iouring-poc-rootkit-bypasses.html)** — a PoC that operates entirely through `io_uring` async I/O, **validated against Falco + Tetragon + Microsoft Defender for Endpoint**. This is the concrete reference for Nyx's eBPF-evasion module (not just the concept).
- **[Cilium — Migrating Falco→Tetragon (Jan 2026)](https://cilium.io/blog/2026/01/19/tetragon-falco-migrate/)** — key defender trend: Tetragon's **in-kernel ENFORCEMENT** (policy enforced in-kernel, not just detected in userspace) is the resilient answer. Nyx must assume enforcement-grade eBPF, not detection-only.
→ *Nyx Linux v2: model the eBPF-abuse module on Curing (io_uring ops + privileged BPF to blind), and assume Tetragon-enforcement-grade targets.*

## N. BYOVD — 2026 landscape (still viable, still churning)
- **[Bellator Cyber — 54 EDR Killers via signed drivers (2026)](https://bellatorcyber.com/blog/edr-killers-byovd-signed-vulnerable-drivers-2026)** · **[BlackSnufkin/BYOVD PoC collection](https://github.com/BlackSnufkin/BYOVD)**.
- Microsoft blocklist updates only **1-2×/year** ([Dark Reading](https://www.darkreading.com/application-security/microsoft-under-pressure-defenses-byovd-attacks)); **CVE-2023-52271 driver still unblocked in 2026** ([r/redteamsec](https://www.reddit.com/r/redteamsec/comments/1r9c8mp/does_killing_edr_with_a_vulnerable_driver_still/)). 2026 patch cycles: Jan (112 CVEs), May (CVE-2026-42898 DC vuln), June (206 CVEs).
→ *Confirms BYOVD as the viable-but-churning fallback — the kit model (operator-selectable current driver) is mandatory; EDR-repurposing remains the primary.*

## O. Sleep obfuscation — current whitepapers + the detection to beat
- **[Nation State Minds — EKKO/Foliage/Cronos comparative whitepaper](https://www.nationstateminds.com/whitepapers/sleep-obfuscation-ekko-foliage-and-the-memory-scanner-evasion-landscape)** — current comparative analysis of the major techniques + detection artifacts.
- **[Kyle Avery — Avoiding Memory Scanners (author of Hunt-Sleeping-Beacons)](https://kyleavery.com/posts/avoiding-memory-scanners/)** — FOLIAGE is detected via **threads in wait states**; the tool was updated to catch it. THIS is the concrete validation target for Nyx's `SleepmaskKit`.
- **[SysWhispers4 docs — ETW-Ti limitations + sleep-encryption](https://joasasantos-syswhispers4.mintlify.app/advanced/etw-ti-limitations)** — current reference for the ETW-Ti-monitored syscall set + Ekko-inspired sleep encryption.
→ *Nyx P2.1: implement `SleepmaskKit` (Ekko/Foliage) and validate it specifically against Hunt-Sleeping-Beacons + the Nation State Minds artifacts (RWX→RW transitions, wait-state threads).*

## P. EDR-bypass technique + the cutting-edge DEFENSE
- **[HookChain — DEF CON 32 "A New Perspective for Bypassing EDR"](https://www.youtube.com/watch?v=0L6TlFYwy2U)** — distinct EDR-bypass approach worth cataloging.
- **[fluxsec.red — Full-Spectrum ETW Detection in-kernel vs rootkits (Sanctum EDR)](https://fluxsec.red/full-spectrum-event-tracing-for-windows-detection-in-the-kernel-against-rootkits)** — the state-of-the-art DEFENSE Nyx's ETW tier must anticipate (kernel ETW-tamper detection).

## Q. 2026 conference status (as of mid-2026)
- **USENIX Security '26** (Aug 12-14 2026, Baltimore) · **IEEE S&P 2026** (May 18-20, SF) · **NDSS 2026** (publishing) · **Black Hat USA 2026** (Aug 1-6, 100+ briefings announced Jun 2026, catalog not yet detailed). Full 2026 proceedings are not yet web-indexed as of mid-2026 — re-sweep Aug-Oct 2026 once USENIX'26 + BH'26 + DEF CON 34 land.
