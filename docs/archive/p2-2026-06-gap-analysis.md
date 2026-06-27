# Nyx C2 — EDR Bypass Gap Analysis vs. 2025-2026 State of the Art

**Date:** 2026-06-25
**Scope:** All shipped and gated capabilities in Nyx vs. current detection and evasion landscape
**Classification:** Authorized red-team research only
**Sources:** 12 parallel research agents (8 searches + 3 deep reads + 1 synthesis), ~600k tokens, 202 tool calls

---

## 1. USERLAND GAPS

### CRITICAL

#### 1.1 Indirect Syscall Stack Disclosure — DETECTED TODAY
- **What Nyx lacks:** The current indirect syscall stub (`syscalls.rs` — `mov r10,rcx; mov eax,SSN; mov r11,gadget; jmp r11`) leaves an implant return address on `[RSP]`. The **xacone** VEH+HWBP detector at `Nt*+0x14` (the `ret`) checks `*((void**)RSP)` against a list of legitimate overlying-DLL exports (kernel32/kernelbase/user32). An implant address on the stack is not in that list, triggering a flag. This defeats Hell's Gate / Halo's Gate / Tartarus Gate class indirect loaders.
- **SOTA technique:** **LACUNA Chain / BYOUD-Gap** (0xmaz, 2026-06). Scan ntdll/kernelbase/win32u `.pdata` for gaps (addresses between functions with no `RUNTIME_FUNCTION` coverage). When `RtlLookupFunctionEntry(addr)` returns NULL, `RtlVirtualUnwind` treats it as a leaf function and advances RSP by 8 bytes — no crash, no `.pdata` modification, zero forensic artifact. Place gap addresses as leaf "bridge frames" so `[RSP]` resolves to signed-DLL addresses. Win32u NOP gaps are categorically whitelisted by EDR module-of-origin rules. LACUNA Chain is verified against Sysmon E10, ETW-Ti STACKWALK, shadow/user compare. BYOUD-RT computes RSP distance at runtime from `TEB.StackBase` — works in injected shellcode without pre-calibration.
- **Detection countermeasures:** StackSentry (Vith0r, 2026-05) monitors `.pdata`/`.xdata`/`RUNTIME_FUNCTION` timing changes, but BYOUD-Gap modifies nothing — StackSentry cannot flag zero-modification chains. Elastic's `RtlLookupFunctionEntry(gap)==NULL` heuristic exists in research but is not commercially deployed as of 2026-06.
- **Priority:** ⚠️ **CRITICAL** — this is the single highest-leverage gap. Every syscall the implant makes is detectable right now. Fixing this hardens the entire syscall surface, not just one kit.

#### 1.2 Foliage Sleep Mask Not Default-On
- **What Nyx lacks:** The Foliage APC sleep mask data path is complete (`evasionsdk/foliage.rs`, `implant-win/sleep.rs`) but gated behind `FOLIAGE_ENABLED = false`. The beacon still sleeps via `NtDelayExecution` which sets wait-reason `DelayExecution` — a direct Hunt-Sleeping-Beacons signal. Even when armed, the current chain uses `NtDelayExecution` for the actual delay rather than `WaitForSingleObject` (wait-reason `UserRequest`). The ETW-Ti APC window attack (keep thread non-alertable during the op, clean the stack before entering alertable wait) is not wired, so `KiUserApcDispatcher` appears on the call stack during HSB inspection.
- **SOTA technique:** **Foliage 10-step APC-to-`NtContinue` chain** (Kyle Avery, DEF CON 30) with `WaitForSingleObject` wait dodge + RC4 via `SystemFunction032` from advapi32 image-commit + `NtSetContextThread` to manufacture return addresses at rest + the ETW-Ti APC window attack (0xmaz) to keep `KiUserApcDispatcher` off the stack at scan time. hypnus (joaoviictorti) confirms Rust sleep+spoof viability with `TpSetWait` thread-pool variant.
- **Detection countermeasures:** HSB updated for Foliage: flags `UserRequest` wait-reason AND `KiUserApcDispatcher` on call stack. Moneta flags executable+private-commit memory. PE-sieve checks thread return addresses. BeaconEye scans heap for Cobalt Strike config structs. MalMemDetect hooks `RtlAllocateHeap` and checks return address at execution time.
- **Priority:** ⚠️ **CRITICAL** — second highest-leverage. Without the sleep mask, the implant is visible to memory scanners for the entire sleep window (potentially minutes).

### HIGH

#### 1.3 No ThreadlessInject (PE-sieve .text Hash Mismatch)
- **What Nyx lacks:** Module stomping (`inject.rs`) overwrites the cover DLL's `.text` section with shellcode. PE-sieve detects this via `.text` hash mismatch between the on-disk PE and the in-memory section. The `MODULESTOMP_ENABLED` gate is default OFF.
- **SOTA technique:** **ThreadlessInject** (avantguard) + **ThreadlessStompingKann** — inject without creating threads or allocating new executable memory. Execution flows through existing thread scheduling. Combined with **Caro-Kann** encryption. **BYORWXDLL** injection (meterpreter, 2026-06): write code into existing RWX sections of loaded signed DLLs rather than creating new allocations.
- **Detection countermeasures:** PE-sieve `.text` hash check (NOT bypassed by current stomp), Elastic OXLOADER detection of `.reloc` section code placement.
- **Priority:** 🟡 **HIGH** — current injection is PE-sieve detectable.

#### 1.4 No HW-BP Patchless Blind (AMSI/ETW)
- **What Nyx lacks:** Current AMSI/ETW blind uses `VirtualProtect` RX-to-RW + byte write + restore — the `VirtualProtect` on a code page is itself a detectable signal.
- **SOTA technique:** **HW-BP patchless** (Turla Kazuar v3, 2026-01). Register HW breakpoints via `SetThreadContext` `DR0`-`DR7`. VEH handler patches bytes at the `EXCEPTION_SINGLE_STEP` breakpoint hit, sets TF (trap flag) to execute one instruction, restores on next trap. No `VirtualProtect`, no `NtWriteVirtualMemory`, no code-page attribute change. Verified in-the-wild by APT.
- **Detection countermeasures:** Anomalous VEH registration. HW breakpoint detection via `GetThreadContext` DR register inspection. Most EDRs do not routinely inspect DR registers.
- **Priority:** 🟡 **HIGH** — eliminates the last userland write signal on blind.rs.

#### 1.5 No ETW Deception (Forge Benign Events)
- **What Nyx lacks:** `blind.rs` suppresses ETW events but does not forge replacements. A robust EDR can detect the *absence* of events that should be present.
- **SOTA technique:** **ETW deception** (Olaf Hartong, Black Hat USA 2025). Instead of suppressing events, inject/forge benign telemetry events. **SunnyDayBPF** (2026-05) generalizes: let events happen, then rewrite the user-mode buffer between syscall return and agent parsing.
- **Detection countermeasures:** Event frequency analysis. Sequence validation. No commercial EDR does this for ETW yet.
- **Priority:** 🟡 **HIGH** — future-proofs against detection of the blind itself.

#### 1.6 VirtualProtect Code-Page Signal
- **What Nyx lacks:** `blind.rs` write_patch flow calls `VirtualProtect` to flip code pages RX→RW→RX. This memory attribute change on a PE `.text` section is a signal.
- **SOTA technique:** Eliminate via HW-BP patchless (item 1.4). For Foliage mask cycle, route through indirect `NtProtectVirtualMemory` with spoofed return address.
- **Priority:** 🟡 **HIGH** — reduces the observable surface for every kit that touches memory permissions.

### MEDIUM

#### 1.7 No ETW-TI Userland Comprehensive Blind
- **What Nyx lacks:** `NtTraceEvent` patch covers userland ETW notification path, but ETW-TI kernel provider fires from inside ntoskrnl after kernel operation. Userland cannot reach it. `NtTraceControl` provider-disable returns `0xC000000D` for kernel providers.
- **SOTA technique:** Kernel-tier ETW-TI blind via BYOVD (already shipped as `EtwTiBlind`). Userland supplement: `NtContinue` to bypass ETW-TI callbacks from userland.
- **Priority:** 🔵 **MEDIUM** — kernel tier addresses this.

#### 1.8 No Parameter Encryption at Syscall Boundary
- **What Nyx lacks:** Syscall parameters (virtual addresses, buffer pointers, sizes) are passed in registers, visible to any hook at the `syscall` instruction.
- **SOTA technique:** **LACUNA Chain** parameter encryption (0xmaz): encrypt syscall params at staging, decrypt inside HW-BP VEH at the `syscall` instruction.
- **Priority:** 🔵 **MEDIUM** — defense-in-depth.

#### 1.9 No Reflective Loading / UDRL
- **What Nyx lacks:** No Unhooked Reflective DLL Loader. All payloads are statically compiled or loaded via `LoadLibrary`.
- **SOTA technique:** Reflective DLL loading (Stephen Fewer original, Outflank/CCob). UDRL bypasses ntdll hooks during load.
- **Priority:** 🔵 **MEDIUM** — important for operator flexibility in postex.

---

## 2. KERNEL GAPS

### CRITICAL

#### 2.1 No KslD.sys Bootstrap (Living off the Defender)
- **What Nyx lacks:** Current kernel bootstrap is BYOVD via RTCore64.sys (CVE-2019-16098). This is on the Microsoft Vulnerable Driver Blocklist with growing coverage (~70% for security/forensic drivers). Requires loading a third-party driver → Sysmon EID 6.
- **SOTA technique:** **KslD.sys** — weaponize Windows Defender's own signed kernel driver (fndsec, 2026-04). KslD.sys exposes kernel IOCTL interfaces for R/W + privilege escalation. Ships with Defender → never blocklisted (Microsoft cannot block its own driver). No new driver load event, no Sysmon EID 6.
- **Detection countermeasures:** detect.fyi "Ghost in LSASS" detects KslKatz's LSASS access pattern. But the bootstrap itself (no new driver) is nearly invisible.
- **Priority:** ⚠️ **CRITICAL** — kernel tier's value depends on getting kernel R/W without being blocklisted. RTCore64 fallback will eventually be blocklisted everywhere.

#### 2.2 No MiniFilter Disconnect
- **What Nyx lacks:** No ability to detach EDR MiniFilter callbacks from the FltMgr callback list. EDRs (WdFilter for Defender, Falcon for CrowdStrike) use MiniFilter altitude-based callbacks for file-system telemetry.
- **SOTA technique:** S12 (2026-05) — unlink EDR MiniFilter callback nodes from `FltGlobals` 链表 (Flink/Blink removal). Bypasses kCFG (kCFG protects dispatch tables, not linked lists). HVCI-compatible (data-section write). Minimal noise.
- **Detection countermeasures:** FltMgr internal consistency checks. PatchGuard watches MiniFilter callback lists — but only for NULL writes.
- **Priority:** 🟡 **HIGH** — file-system telemetry is one of three pillars of EDR detection.

### HIGH

#### 2.3 No PPL Bypass from Kernel
- **What Nyx lacks:** The PPL strip code clears the `Protection` field on target EPROCESS, but there is no ability to make the attacker's own process PPL (process immortality) — the EDR cannot kill or dump the implant.
- **SOTA technique:** **PPLReaper** (S12cybersecurity). Make implant process PPL → process immortality. 9 methods to dump LSASS under RunAsPPL=1 documented.
- **Priority:** 🟡 **HIGH** — PPL is increasingly enforced on security processes.

#### 2.4 No WFP Callout Neutralization
- **What Nyx lacks:** WFP (Windows Filtering Platform) is the network-filtering kernel framework. Current kernel tier has WFP filter rule generation but no kernel-side callout pointer overwrite.
- **SOTA technique:** **EDRChoker** (TwoSevenOneT, 2026-06) — QoS Packet Scheduler throttle of EDR process bandwidth to 8 bit/s. pacer.sys operates below WFP → no WFP events generated. Lowest noise option.
- **Priority:** 🟡 **HIGH** — network telemetry is the second pillar. EDRChoker (userland, admin) is simpler than kernel WFP pointer overwrite.

#### 2.5 No Runtime PatchGuard Bypass
- **What Nyx lacks:** Current PatchGuard interaction is Peekaboo-style timing repair (short DKOM window <1s). No runtime PG bypass for persistent kernel modifications.
- **SOTA technique:** **kurasagi** (NeoMaster831) — runtime PatchGuard bypass for Win11 24H2-25H2. **TheiaPg** (quokka867) — same for 25H2. Allows persistent kernel data modifications.
- **Priority:** 🟡 **HIGH** — removes time constraint on kernel operations.

### MEDIUM

#### 2.6 No EDR Process Freeze/Choke
- **What Nyx lacks:** No "freeze" (WerFaultSecure coma) or "choke" (EDRChoker QoS starvation) capability.
- **SOTA technique:** **EDR-Freeze** — crash dump trigger that hangs EDR without killing (PPL survives). **EDRChoker** — QoS throttle to 8 bit/s, TLS handshake timeout. Both userland-only, admin required.
- **Priority:** 🔵 **MEDIUM** — kill is often too loud. Freeze/choke are subtler.

#### 2.7 No Kernel Credential Access (LSASS Direct Read)
- **What Nyx lacks:** LSASS read framework exists but not specialized for LSASS memory parsing.
- **SOTA technique:** **KslKatz** — kernel R/W to directly read LSASS memory, bypassing RunAsPPL and Credential Guard.
- **Priority:** 🔵 **MEDIUM** — important for post-exploitation but separate from stealth mission.

#### 2.8 No Driverless CVE Bootstrap Path
- **What Nyx lacks:** No driverless (no driver load) path to kernel R/W. CVE-2026-40369 provides complete exploit for arbitrary kernel memory R/W. CR3-based IOCTL primitives are a new vector class.
- **SOTA technique:** **CVE-2026-40369** — 12-byte browser-sandbox escape to kernel R/W. Complete PoC. Time-limited (patches close window). **CR3-IOCTL** — new primitive class, not dependent on specific vulnerability.
- **Priority:** 🔵 **MEDIUM** — time-limited but valuable for unpatched targets.

---

## 3. CROSS-CUTTING CONCERNS

### 3.1 CET (Control-flow Enforcement Technology) — Affects Both Tiers
- Shadow stack validates return addresses. Any userland return-address spoof (Gen-2/Gen-3 class) faults with `#CP`.
- **Current Nyx:** Stack spoof degrades when CET detected.
- **Solution:** BYOUD-Gap leaf-chain approach is CET-safe at unwinder-walk layer (doesn't modify return addresses). The RSP swap itself is the problem — must route through `KiControlProtectionFault`'s lenient-repair path (Synacktiv SSTIC 2025).
- **Recommendation:** The gated RSP swap (`stack.rs SPOOF_SWAP_ENABLED`) must route through `KiControlProtectionFault` before being armed.

### 3.2 HVCI (Hypervisor-enforced Code Integrity) — Affects Kernel Tier
- Under HVCI, code pages are R-X in EPT. Inline kernel hooks cause EPT violation → VM-exit → VTL1 `KeBugCheckEx`. Data sections remain RW-.
- **Impact:** All kernel-tier code-section operations (inline hook of callback functions, SSDT hooking) are dead under HVCI. Only data-section manipulation works.
- **Recommendation:** Ensure all callback/MiniFilter/WFP kits use data-section-only operations.

### 3.3 NDR Behavioral Modeling (Unavoidable Ceiling)
- Network Detection and Response shifted to behavioral modeling: beaconing interval, periodicity, protocol anomalies (Vectra, 2026-06).
- **Impact:** No technical bypass eliminates behavioral detection of periodic C2 beaconing. Mitigation is operational: large jitter, low-and-slow, CDN fronting.
- **Recommendation:** Transport layer should support Cloudflare Worker relay with subdomain channeling.

### 3.4 Cortex XDR = Pure Kernel Callbacks
- Cortex XDR uses zero userland hooks — operates entirely through kernel callbacks. NTDLL unhook, AMSI blind, ETW userland blind have **zero effect** on Cortex XDR.
- **Impact:** Against Cortex XDR targets, only kernel-tier evasion is effective.
- **Recommendation:** Document in threat model. Kernel bootstrap is not optional against Cortex XDR.

---

## 4. DETECTION ARMS RACE — 2025-2026 EDR Additions

| Detector | Date | What It Catches | Nyx Technique Affected | Nyx Status |
|---|---|---|---|---|
| **xacone** indirect syscall VEH | 2025-2026 | Return address on `[RSP]` not in legitimate DLL export list | All indirect syscalls | ❌ DETECTED — needs BYOUD-Gap (1.1) |
| **StackSentry** (Vith0r) | 2026-05 | `.pdata`/`.xdata`/`RUNTIME_FUNCTION` timing changes | BYOUD (non-gap) | ✅ BYOUD-Gap is safe (zero mod) |
| **K2** (titansoftwork) | 2026-05 | Precise stack frame check during syscall | Direct + indirect syscalls | ❌ Needs BYOUD-Gap (1.1) |
| **cet-spoofing-detection** (0xjbb) | 2026-05 | Shadow stack vs user stack comparison | RSP swap / return address spoof | ✅ BYOUD-Gap is CET-safe |
| **Hunt-Sleeping-Beacons** (updated) | 2025-2026 | `UserRequest` wait-reason + `KiUserApcDispatcher` on call stack | Foliage APC chain | ❌ Needs ETW-Ti APC window attack |
| **Sleep-Duck-Eye** (Olivaire) | 2025-12 | Generic call-stack integrity: SleepMask/ROP/VEH/encrypted stacks | All sleep-mask variants | ⚠️ Validate Foliage against this |
| **Elastic OXLOADER** | 2026-06 | Code in `.reloc` section (static red flag) | Module stomping variant | ⚠️ Avoid .reloc for shellcode |
| **Elastic detection-rules rewrite** (#6028) | 2026-03 | PPID spoofing detection (#6016) | Postex parent process spoofing | ⚠️ Ensure PPID chain consistent |
| **Peregrine** (patchi.fyi) | 2025-12 | Enumerates ObCallbacks, driver blocklist, HVCI state | BYOVD driver loaded | ❌ Use KslD.sys (never blocklisted) |
| **Sanctum EDR** (fluxsec) | 2026 | Full-spectrum in-kernel ETW detects ETW blinding | NtTraceEvent patch | ⚠️ Honest ceiling |
| **BeaconHunter / MalMemDetect** | 2025-2026 | Return address at execution time | Module stomping, shellcode | ❌ ThreadlessInject is evasion |
| **EDRChoker** (TwoSevenOneT) | 2026-06 | — (this is an ATTACK tool, not detector) | — | ✅ Use against EDR |
| **KslKatz detection** (detect.fyi) | 2026-03 | LSASS abnormal access from kernel R/W | KslD.sys credential dump | ⚠️ Detection exists |

---

## 5. RECOMMENDED NEXT STEPS (Ordered by Impact vs. Effort)

### Tier 1: Must-Do First (CRITICAL)

| # | Step | Impact | Effort | Dependencies |
|---|---|---|---|---|
| **1** | **BYOUD-Gap stack spoof** — Extend `resolve.rs` to scan ntdll/kernelbase/win32u `.pdata` for gap+ghost addresses. Wrap `syscalls.rs::trampoline_for` so each indirect syscall's `[RSP]` resolves to a signed-DLL gap/ghost leaf chain. | CRITICAL: hardens every syscall | Medium | None |
| **2** | **Foliage sleep mask default-on** — Replace `NtDelayExecution` with `WaitForSingleObject`. Wire ETW-Ti APC window attack. Integrate return-address spoof from step 1. Swap `const SLEEPMASK_KIT`. | CRITICAL: eliminates sleep visibility | Medium-High | Step 1 |
| **3** | **KslD.sys bootstrap** — Add `LivingOffDefender` impl of `KernelRw` trait. Resolve KslD.sys IOCTL interface. Operator-side tooling. | CRITICAL: future-proofs kernel bootstrap | Medium | None |

### Tier 2: High Impact (After Tier 1)

| # | Step | Impact | Effort | Dependencies |
|---|---|---|---|---|
| **4** | **ThreadlessInject** — Replace module stomping as injection floor. Eliminate PE-sieve `.text` hash mismatch. | HIGH | High | None |
| **5** | **HW-BP patchless blind** — Replace VirtualProtect+write in `blind.rs` with HW breakpoint + VEH. | HIGH | Medium | None |
| **6** | **MiniFilter disconnect** — Kernel data-section write to unlink EDR MiniFilter nodes from `FltGlobals`. | HIGH | Medium | Kernel R/W |
| **7** | **EDRChoker operator tool** — QoS Packet Scheduler throttle. Userland PowerShell, admin required. | HIGH | Low | Admin on target |

### Tier 3: Medium Impact

| # | Step | Impact | Effort | Dependencies |
|---|---|---|---|---|
| **8** | **PPL bypass / process immortality** | MEDIUM-High | High | Kernel R/W |
| **9** | **Runtime PG bypass (kurasagi)** | MEDIUM-High | High | Kernel R/W + specific Win11 |
| **10** | **ETW deception mode** | MEDIUM | High | ETW event format research |
| **11** | **Syscall parameter encryption** | MEDIUM | Medium | Step 5 |
| **12** | **Cloudflare Worker C2 relay** | MEDIUM | Medium | Phase 1 malleable C2 |
| **13** | **Driverless CVE bootstrap (CVE-2026-40369)** | MEDIUM | High | Unpatched target |
| **14** | **Reflective loading / UDRL** | MEDIUM | Medium | None |

### Tier 4: Research / Long-Term

| # | Step | Impact | Effort |
|---|---|---|---|
| **15** | **SunnyDayBPF telemetry integrity** | Future | Very High |
| **16** | **EvilEDR repurposing** | Future | Very High |
| **17** | **KDP bypass** | Research | Very High |
| **18** | **Telemetry Complexity Attacks** | Research | Medium |

---

## 6. CAPABILITY MATRIX: Before and After Recommended Steps

| Detection Surface | Nyx Today | After Tier 1 | After Tier 2 | After Tier 3 |
|---|---|---|---|---|
| Indirect syscall return address check | ❌ DETECTED | ✅ EVASION | ✅ EVASION | ✅ EVASION |
| Memory scanner during sleep | ❌ VISIBLE | ❌ VISIBLE (gated) | ✅ EVASION | ✅ EVASION |
| PE-sieve .text hash | ❌ DETECTED | ❌ DETECTED | ✅ EVASION | ✅ EVASION |
| Code-page VirtualProtect signal | ⚠️ SIGNAL | ⚠️ SIGNAL | ✅ ELIMINATED | ✅ ELIMINATED |
| ETW-TI kernel provider | ⚠️ PARTIAL | ⚠️ PARTIAL | ⚠️ PARTIAL | ✅ FULL |
| MiniFilter file telemetry | ❌ FULLY VISIBLE | ❌ FULLY VISIBLE | ✅ SILENCED | ✅ SILENCED |
| WFP network telemetry | ❌ FULLY VISIBLE | ❌ FULLY VISIBLE | ✅ CHOKED | ✅ CHOKED |
| PPL process protection | ⚠️ BYPASSED (DKOM) | ⚠️ BYPASSED | ⚠️ BYPASSED | ✅ ELIMINATED |
| PatchGuard integrity check | ⚠️ TIMED (<1s) | ⚠️ TIMED | ⚠️ TIMED | ✅ BYPASSED |
| CET shadow stack | ⚠️ DEGRADES | ✅ SAFE | ✅ SAFE | ✅ SAFE |
| NDR behavioral modeling | ⚠️ MITIGATED | ⚠️ MITIGATED | ⚠️ MITIGATED | ⚠️ MITIGATED |
| Cortex XDR (kernel-only) | ❌ NO EVASION | ❌ NO EVASION | ✅ EVASION | ✅ EVASION |

---

*Generated by 12-agent research workflow. Sources: Exa search (8 parallel angles), deep source reads (3), synthesis (1 adversarial verify). ~600k tokens, 202 tool calls.*
