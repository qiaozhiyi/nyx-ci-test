# Nyx P2 — 2026 Research Addendum (call-stack/CET era + ETW-TI kernel blind)

Companion to `docs/p2-integration-analysis.md` (the per-kit build-spec source of truth)
and `docs/p2-{edr-bypass-plan,windows-bypass-research}.md`. This addendum captures
**2025–2026 primary sources** gathered 2026-06-23 and the **one re-prioritization** they
force. **For authorized red-team / security-research use only.**

## 0. Method + the single re-prioritization

Gathered via **direct sequential web fetches** (web reader), modest parallelism — NOT the
`deep-research` Workflow fan-out (that crashed this exact project with API rate errors and
orphaned runs across session restart; see memory `ecc-workflow-tool-dsl` /
`nyx-p2-evasion-integration`). Zero concurrency stacking throughout.

**The re-prioritization in one line:** the call-stack layer is now the decisive battleground,
our shipped Tier-0 indirect syscalls have a **known detection ceiling today**, and CET makes
the Gen-2/Gen-3 stack-spoof approach (what `stack.rs`'s skeleton implies) **fault on
contact**. → `stack.rs` is upgraded from "later" to **co-primary with SleepmaskKit**, and its
design target moves to **BYOUD-Gap-class (`.pdata` zero-modification, CET-safe)**.

## 1. NEW — the call-stack / CET battleground (largest delta vs prior docs)

### 1.1 Our Tier-0 indirect syscalls are detectable NOW (the ceiling)
**xacone — "Catching Potential Indirect Syscalls."** A VEH + hardware breakpoint at
`Nt*+0x14` (the `ret`) checks `*((void**)RSP)` against a list of legitimate overlying-DLL
exports (kernel32/kernelbase/user32). A bare indirect syscall jumps into ntdll's `syscall`
gadget — RIP is clean, but **the return address on the stack still points at implant
memory**, which is not in that export list → flagged. Defeats Hell's Hall / MalDev indirect
loaders. PoC in BestEdrOfTheMarket.
→ **Nyx implication:** confirms `stack.rs` is not optional. Our `stub.rs` indirect stub
(`mov r10,rcx; mov eax,SSN; mov r11,gadget; jmp r11`) leaves an implant return address. The
spoof must make `[RSP]` resolve into a signed-DLL address at the `ret`.
- https://xacone.github.io/mitigate-indirect-syscalls.html

### 1.2 CET kills Gen-2/Gen-3 spoof → must go BYOUD-class
Intel CET (shadow stack) is increasingly default on Win11. Every `CALL` pushes the return
address to **both** RSP-stack and the read-only shadow stack; `RET` validates they match.
Mismatch → `#CP` fault. **SilentMoonwalk / ThreadStackSpoofer / any return-address
manipulation on the RSP stack breaks under CET.**
- Background: https://windows-internals.com/cet-on-windows/ (legitimate cases that mutate the
  shadow-stack pointer: exception unwind, APCs — the seams attackers also use).
- Defender side: Elastic "Finding Truth in the Shadows" (shadow-stack-aware stack inspection).

### 1.3 BYOUD — CET-compliant spoof via `.pdata` manipulation (klezVirus, BHEU 2025)
**"Fantastic unwind information and where to find them."** CET validates return addresses;
CET does **not** validate `.pdata` unwind metadata — they are separate systems. BYOUD
manipulates `UNWIND_INFO`/`RUNTIME_FUNCTION` records so `RtlVirtualUnwind` walks a synthetic
legitimate chain. CET-clean, but **leaves a `.pdata` forensic artifact** (modified unwind
data). Rust PoC lineage via SilentMoonwalk's unwinder.
- https://klezvirus.github.io/posts/Byoud/
- Black Hat EU 2025 talk: "Ghost In The Stack" (Magnosi) —
  http://i.blackhat.com/BH-EU-25/eu-25-Magnosi-Ghost-in-the-stack.pdf

### 1.4 LACUNA Chain / Ghost Frames (0xmaz, 2026-06) — the current SOTA, zero-modification
**Deep-read primary.** Extends BYOUD with **zero-`.pdata`-modification** variants by reversing
`nt!RtlVirtualUnwind` in Ghidra. The load-bearing primitive: when
`RtlLookupFunctionEntry(addr)` returns **NULL** (the address has no `RUNTIME_FUNCTION`
coverage), the unwinder treats it as a **leaf function** and advances RSP by exactly 8 — no
crash, no abort. These uncovered "gaps" exist in every DLL between functions.

Contributions (all first-hand from binary analysis of lab-host DLLs):
- **BYOUD-Gap** — use gap addresses as leaf "bridge frames"; each consumes 8 bytes, hiding N
  real frames. **Zero artifact** (modifies nothing). ntdll: 3,913 gaps / 73,745 B; kernelbase:
  3,982 gaps.
- **Ghost functions** — 1,031 of ntdll's gaps contain *real executable code* with no
  `.pdata` entry (compiler helpers/inlined thunks). Richest leaf-frame source. Plus a **Ghost
  Gadget**: `JMP [RBX]` at `ntdll+0xFC47B` inside an 80-byte ghost — a dual-use primitive
  (real execution redirect AND zero-artifact bridge frame; the unwinder treats it as a leaf so
  it never sees the JMP).
- **Win32u NOP Gap Chain** — win32u.dll is nothing but 24-byte syscall stubs + 8-byte NOP
  gaps (1,242 of them). Those NOP addresses are *categorically whitelisted* by EDR
  module-of-origin rules (win32u is trusted) → weaponize the whitelist against the defender.
- **kernelbase semantic ghost proximity** — a 238-byte ghost ending exactly at
  `VirtualProtect`'s entry; a fake frame there is indistinguishable from a real VirtualProtect
  return site. 432 kernelbase ghosts + a second `JMP[RBX]` gadget.
- **BYOUD-MF** — `UWOP_PUSH_MACHFRAME` (opcode 10): the unwinder reads RSP *from the stack*
  for it. Four `KiUser*` dispatchers carry it (`KiUserApcDispatcher`,
  `KiUserCallbackDispatcher`, `KiUserExceptionDispatcher`, +1), prolog_offset=0. Place a fake
  40-byte machine frame → **arbitrary RSP teleport in one frame**, no `.pdata` write, no gadget.
- **BYOUD-RT** — compute the RSP distance at call time from `TEB.StackBase` (GS:[0x08]) minus
  current RSP. **No pre-calibration** — works in injected shellcode that doesn't know its own
  stack depth (verified across CreateThread / thread-hijack / APC / reflective / hollowing).
- **ETW-Ti APC window attack** — ETW-Ti stack collection is **not synchronous**: it queues a
  `USER_APC` delivered only at the next alertable wait. Between the event firing (T+0) and the
  APC delivery (T+5), the thread runs unmonitored. Keep the thread non-alertable during the
  op, clean the stack, then enter the alertable wait → the collected stack is whatever you
  constructed. **This is the key to defeating HSB's updated FOLIAGE check** (wait-reason
  `UserRequest` + `KiUserApcDispatcher` on stack).
- **Parameter encryption** — encrypt syscall params at staging, decrypt inside a HW-BP VEH at
  the `syscall` instruction. Defeats user-mode hook param inspection + memory scanning
  (`PAGE_EXECUTE_READWRITE` never at rest). Pairs with BYOUD (spoof the *who*, encrypt the
  *what*).
- **Lab result:** full LACUNA Chain evades Sysmon E10, ETW-Ti STACKWALK, shadow/user compare.
  Only surviving telemetry = behavioral kernel callbacks. PoC: github.com/MazX0p/LACUNA-Chain.
- The author's honest detection gap: **no public EDR enumerates `.pdata` gaps at runtime** to
  flag gap-address frames — the open defensive problem.
- https://0xmaz.me/posts/LACUNA-Chain-Ghost-Frames-defeats-All-EDR-layers-of-call-stack-based-detection/

### 1.5 LayeredSyscall (WKL-Sec, 2024) — the VEH alternative
Generate a legitimate call stack *by letting the OS build it*: VEH + HW breakpoints; on the
`syscall`-opcode hit, save context, redirect RIP into a benign Win32 API (e.g. `MessageBox`)
to push legit frames, single-step (trap flag) until inside ntdll, then emulate the syscall
and `ret` back. Supports up to 12 args. Tested vs Sophos Intercept X (process hollowing →
undetected). Detection: flag maliciously-registered VEHs / anomalous API-derived stacks.
- https://whiteknightlabs.com/2024/07/31/layeredsyscall-abusing-veh-to-bypass-edrs/ ·
  https://github.com/WKL-Sec/LayeredSyscall

→ **Nyx design target for `stack.rs`:** BYOUD-Gap-class (zero-mod, CET-safe) is the primary
target — it needs no `.pdata` writes (cleaner under no_std/PIC, no RWX on ntdll) and degrades
gracefully. Init-time scan of ntdll/kernelbase/win32u/wow64 `.pdata` for gap + ghost
addresses (extend `resolve.rs`); wrap the indirect trampoline (`syscalls.rs::trampoline_for`)
so each syscall's `[RSP]` resolves to a signed-DLL gap/ghost. LayeredSyscall's VEH approach is
the fallback on CET-off hosts or where gap scanning is blocked.

## 2. NEW — ETW-TI kernel blind (concrete primary for P2.2)

### 2.1 Silencing ETW-TI via BYOVD (S12, 2026-05) — the pointer chain
**Deep-read primary, with working C++.** ETW-TI is a kernel-native provider in
`ntoskrnl.exe`, not a callback/filter. From a userland process holding a BYOVD kernel R/W
primitive (GIO driver, IOCTL `0xC3502808`), one QWORD write silences it:

```
ntoskrnl base (via NtQuerySystemInformation SystemModuleInformation=11)
  + offset EtwThreatIntProvRegHandle   → _ETW_REG_ENTRY
  + 0x020  (GuidEntry)                 → _ETW_GUID_ENTRY
  + 0x060  (ProviderEnableInfo)
  + 0x000  (IsEnabled)                 = 0   ← single QWORD write, kernel drops all TI events
```
Offsets are build-specific (his build: `EtwThreatIntProvRegHandle` @ ntoskrnl+`0xefed98`).
**Resolve at runtime, never hardcode.** Verified: ProviderEnableInfo `0xff00000001 → 0x0`,
ETW-TI disabled. Kleenscan: undetected by 30+ AVs incl. CrowdStrike/Kaspersky/Defender.

**The S12 BYOVD EDR-bypass series (same author, complementary techniques):**
- File telemetry: unlink MiniFilter callback nodes from the FltMgr callback list.
- Network telemetry: overwrite WFP callout function pointers.
- ETW-TI (this one): the ProviderEnableInfo zero-write.
→ **Nyx:** this is the concrete `EtwTiKit` / kernel-tier spec. Three data-section
pointer-chain writes, no inline hook → **HVCI-compatible** (aligns with the Outflank
PatchGuard Peekaboo finding that data-section manipulation is the only viable kernel path
under HVCI).
- https://medium.com/@s12deff/silencing-etw-threat-intelligence-via-byovd-c2ba9e3bb072

### 2.2 Canonical tooling + the honest defense ceiling
- **EDRSandblast (wavestone-cdt)** — `ETWThreatIntel.c`, the reference ETW-TI + callback
  bypass tool (BYOVD-driven). https://github.com/wavestone-cdt/EDRSandblast
- **Binarly — "Design issues of modern EDRs: bypassing ETW"** (Black Hat).
  https://www.binarly.io/blog/design-issues-modern-edrs-bypassing-etw
- **fluxsec — "Full spectrum ETW detection in the kernel against rootkits"** — the DEFENSE:
  in-kernel full-spectrum ETW *can* detect ETW-blinding tampering (one edge case remains per
  the author). This is the honest ceiling — blind buys time, not invisibility.
  https://fluxsec.red/full-spectrum-event-tracing-for-windows-detection-in-the-kernel-against-rootkits
- **Elastic — "Kernel ETW is the best ETW"** — defender rationale for kernel-tier logging.
- **Praetorian — ETW-TI + hardware breakpoints** (already in prior docs): `NtContinue` to
  bypass ETW-TI callbacks from userland (the userland answer when no kernel primitive).

## 3. NEW — ETW deception (the harder target beyond blinding)

**Olaf Hartong — "I'm in Your Logs Now, Deceiving Your Analysts and Blinding Your EDR"
(Black Hat USA 2025).** Rather than blind ETW (which a robust EDR can detect the *absence*
of), **inject/forge benign telemetry events** so the analyst/log pipeline sees plausible
normal activity. Attacks the *trust* placed in ETW. This is the future `blind.rs` mode
flagged in `p2-integration-analysis.md §2.3` — deception > blinding.
- Slides: https://i.blackhat.com/BH-USA-25/Presentations/Hartong-Im-in-your-logs-now.pdf

## 4. Refreshed / confirmed (already in prior docs, re-validated 2026)

- **Foliage/Ekko** (oblivion-malware, C5pider, Kyle Avery) — unchanged SOTA for sleep-mask;
  `WaitForSingleObject` wait-reason dodge + the ETW-Ti APC window (§1.4) are the HSB-defeat
  combo.
- **hypnus (joaoviictorti)** — Rust sleep obfuscation, `TpSetWait` thread-pool variant
  (Zilean-evolved). Confirms Rust sleep+spoof viable — directly relevant to a no_std Rust kit.
  https://github.com/joaoviictorti/hypnus
- **Module stomping** — advanced variants: oblivion-malware heap/stack-encrypt stomping,
  Astral Projection (Kuwaiti) IOC avoidance, William Knowles code-coverage target selection.
- **Threadless Ops II (avantguard)** + **ThreadlessStompingKann** — threadless + stomp +
  Caro-Kann, still the injection-floor target.
- **Outflank PatchGuard Peekaboo (2026-01)** — unchanged: under HVCI inline kernel hooks are
  dead; data-section manipulation + timing repair (the `EPROCESS.ActiveProcessLinks` unlink +
  termination-callback repair) is the only viable hide. Reinforced by S12's data-chain writes
  (§2.1) being HVCI-compatible.
- **EDRKillShifter (Huntress)** — real-world BYOVD EDR kill via undocumented Huawei driver;
  confirms BYOVD-kill is the dominant in-the-wild kernel path (and is telemetered/loud).
  https://www.huntress.com/blog/w2-malvertising-to-kernel-mode-edr-kill
- **Academic — "Evading and Crashing Anti-Malware via Data Collection Overloading"
  (arXiv:2511.04472)** — overload EDR data collection as an orthogonal evasion.

## 5. Revised build plan (re-prioritized)

The prior plan ordered **P2.1a SleepmaskKit → P2.1b stack-spoof**. The 2026 research makes
**stack-spoof co-primary**, because (a) our steady-state syscalls are detectable today
(§1.1), (b) SleepmaskKit's APC chain needs clean frames to beat updated HSB, and (c) the
skeleton's implied Gen-2/3 approach is dead under CET (§1.2). The two are now a **co-build**.

| Phase | Scope | Seam (Nyx) | Validates vs | Gate |
|---|---|---|---|---|
| **P2.1a-i** | **Gap/ghost scanner** — extend `resolve.rs` to enumerate ntdll/kernelbase/win32u/wow64 `.pdata` gaps + ghost funcs at runtime; cache a frame pool. (Pure read; HVCI/CFG-irrelevant.) | `resolve.rs` + new `stack.rs` data | selftest bitmask | scanner yields >0 gaps on Win10/11 |
| **P2.1a-ii** | **BYOUD-Gap call-stack spoof** — wrap `syscalls.rs::trampoline_for` so each indirect syscall's `[RSP]` resolves to a signed-DLL gap/ghost leaf chain; `BYOUD-RT` runtime RSP distance via `TEB.StackBase`. CET-safe (no RSP-stack return-addr mutation). Fallback: LayeredSyscall VEH on CET-off. | `stack.rs` (replace no-op) + `stub.rs` prologue | xacone-style VEH detector (build one), ETW-Ti STACKWALK | defeats the `[RSP]`-export check |
| **P2.1a-iii** | **SleepmaskKit Foliage** — 10-step APC→`NtContinue` chain; `SystemFunction032` RC4 (advapi32 image-commit); `WaitForSingleObject` wait dodge; APC frames built via the §1.4 ETW-Ti APC window + the new spoof so `KiUserApcDispatcher`-on-stack is clean. Swap `const SLEEPMASK_KIT`. | `kits.rs` + `sleep.rs` (replace skeleton) | HSB (updated), Moneta, PE-sieve, BeaconEye, MalMemDetect, Defender mem scan | zero HSB hits on looping sleep |
| **P2.1b** | **ETW harden** — verify `blind.rs` patches `NtTraceEvent` byte0→`0xC3` at the PEB-resolved addr (not `GetProcAddress`); add provider-disable. (Deception mode §3 = future.) | `blind.rs` | fluxsec's full-spectrum detector (honest ceiling) | ETW consumer emits nothing |
| **P2.1c** | **ProcessInjectKit — module stomping** | `kits.rs` (`NotImpl` → real) | Moneta exec-private, PE-sieve unbacked check | stomped region passes as legit module |
| **P2.2** | **Kernel tier (engagement-gated)** — `EtwTiKit` (the S12 `ProviderEnableInfo` zero-write, §2.1) + `CallbackKit`/`PatchGuardKit` (Outflank data-section + timing repair). HVCI-aware; degrade to floor on HVCI-on. **Honest: the PIC no_std implant cannot host a kernel driver** — P2.2 is operator-side tooling (BYOVD/DMA bootstrap from a userland process, like S12's), not implant-resident. | new `crates/edr-kit-*` (operator tool) | Sysmon EID 6, HVCI-on + HVCI-off VMs | ETW-TI consumer goes silent post-run |

**Build order rationale:** a-i/a-ii (the spoof) unblocks both a-iii (sleep mask needs it) and
hardens every existing syscall against the §1.1 ceiling — so it is the highest-leverage first
commit. a-iii then lands on top of clean frames. The kernel tier (P2.2) stays last and
operator-side.

## 6. Sources new this pass (2025–2026, first-hand)

- xacone — *Catching Potential Indirect Syscalls*. https://xacone.github.io/mitigate-indirect-syscalls.html
- klezVirus — *Fantastic unwind information and where to find them (BYOUD)*, BHEU 2025. https://klezvirus.github.io/posts/Byoud/
- Magnosi — *Ghost In The Stack*, BHEU 2025. http://i.blackhat.com/BH-EU-25/eu-25-Magnosi-Ghost-in-the-stack.pdf
- 0xmaz (Alzhrani) — *LACUNA Chain: Ghost Frames*. 2026-06. https://0xmaz.me/posts/LACUNA-Chain-Ghost-Frames-defeats-All-EDR-layers-of-call-stack-based-detection/ · PoC https://github.com/MazX0p/LACUNA-Chain
- WKL-Sec — *LayeredSyscall: Abusing VEH to Bypass EDRs*. 2024. https://whiteknightlabs.com/2024/07/31/layeredsyscall-abusing-veh-to-bypass-edrs/ · https://github.com/WKL-Sec/LayeredSyscall
- S12 — *Silencing ETW Threat Intelligence via BYOVD*. 2026-05. https://medium.com/@s12deff/silencing-etw-threat-intelligence-via-byovd-c2ba9e3bb072
- wavestone-cdt — *EDRSandblast* (ETWThreatIntel.c). https://github.com/wavestone-cdt/EDRSandblast
- Binarly — *Design issues of modern EDRs: bypassing ETW*. https://www.binarly.io/blog/design-issues-modern-edrs-bypassing-etw
- fluxsec — *Full spectrum ETW detection in the kernel against rootkits*. https://fluxsec.red/full-spectrum-event-tracing-for-windows-detection-in-the-kernel-against-rootkits
- Hartong — *I'm in Your Logs Now (ETW deception)*, BH USA 2025. https://i.blackhat.com/BH-USA-25/Presentations/Hartong-Im-in-your-logs-now.pdf
- joaoviictorti — *hypnus* (Rust sleep obf, TpSetWait). https://github.com/joaoviictorti/hypnus
- Huntress — *EDRKillShifter (BYOVD EDR kill)*. https://www.huntress.com/blog/w2-malvertising-to-kernel-mode-edr-kill
- arXiv:2511.04472 — *Evading and Crashing Anti-Malware via Data Collection Overloading*.
- CET context: https://windows-internals.com/cet-on-windows/ · Elastic "Finding Truth in the Shadows".

## 7. Academic deep-dives (second pass, 2026-06-23)

> **Honest search-tool note:** the only web-search backend available in this environment is the
> GLM `web_search_prime` (both `mcp__web-search-prime` and the built-in `WebSearch` route to it).
> Per the operator's "don't use GLM search" directive, this pass used `web-reader` to fetch
> **specific academic URLs directly** (fetch ≠ search), not the GLM search. The Exa/ECC academic
> search tool is **not registered** in this harness. Two consequences: (1) discovery is limited
> to known URLs, so this is not exhaustive; (2) the Windows-EDR-evasion frontier genuinely lives
> in **conference talks + practitioner blogs (Black Hat, DEF CON, SSTIC, Outflank, 0xmaz)**, not
> arXiv — arXiv is thin in this niche, which is why "newest academic paper" here bottoms out
> around HookChain (2024) + TCAs (2025-11).

### 7.1 HookChain — the academic root of the LACUNA lineage (arXiv:2404.16856, 2024)
Helvio Carvalho Junior. 50 pp, 23 figs. The peer-reviewed foundation LACUNA Part I builds on:
**IAT hooking + dynamic SSN resolution (Halo's Gate) + indirect syscalls** chained to redirect
the Windows-subsystem execution flow invisibly to EDRs that only instrument `ntdll.dll`. The
empirical claim LACUNA leans on — "94% of EDRs hook nothing above the NTDLL subsystem layer" —
originates here. Cited 3×. https://arxiv.org/abs/2404.16856

### 7.2 Synacktiv — Analyzing the Windows kernel shadow-stack mitigation (SSTIC, 2025-06-20)
Jullian & Aulnette. **Deep-read primary (full slide deck).** The definitive first-hand
treatment of the CET shadow stack under Windows — directly validates the §1.2/§1.4 claim that
old return-address spoof is dead and `.pdata`/exception-seam approaches are required:
- **Not yet default** on Win11 24H2; opt-in via Core Isolation / registry
  (`...\DeviceGuard\Scenarios\KernelShadowStacks\Enabled`). Likely default in a future release.
- **Protected like HVCI**: VTL1 secure kernel + EPT make the shadow-stack page read-only to the
  regular kernel (VTL0); a plain PTE-write bypass fails. VTL0 requests EPT protection via
  `vmcall(rcx=0xc)` → `HvModifyVtlProtectionMask`.
- **The `#CP` handler is permissive (`nt!KiControlProtectionFault`):** it walks the shadow
  stack and **if ANY stored return address matches the one at RSP, no BSOD** — it "fixes up"
  the shadow stack via secure call `nt!VslKernelShadowStackAssist`. Only a total mismatch →
  `KERNEL_SECURITY_CHECK_FAILURE (0x139, arg1=0x39)`. PoC: incrementing the return address,
  skipping a frame, and the **try/except exception-unwind path** (`nt!KeKernelShadowStackRestoreContext`
  → `VslKernelShadowStackAssist`) all reconcile the shadow stack through this fixup seam.
- **JOP gadgets still work** (they never touch the stack); IBT not yet enforced on Windows.
- PoC repo: github.com/synacktiv/windows_kernel_shadow_stack.
→ **Nyx implication for `stack.rs`:** this is the operational justification for going
**BYOUD-Gap-class** rather than return-address mutation — and it reveals the **exception-unwind
reconciliation seam** (`RtlRestoreContext`/`VslKernelShadowStackAssist`) as the mechanism to
keep shadow/user stacks consistent after a synthetic chain, on top of the `.pdata`-gap leaf
trick from §1.4. Until kernel shadow stacks are default (today: off), userland CET
(`/CETCOMPAT` per-process) is the live constraint.
PDF: https://www.synacktiv.com/sites/default/files/2025-06/sstic_windows_kernel_shadow_stack_mitigation.pdf

### 7.3 Telemetry Complexity Attacks (TCAs) — arXiv:2511.04472 (2025-11-06)
Gkritsis, Patsakis, Stergiopoulos. **Orthogonal, sensor-agnostic evasion.** Instead of
defeating sensors, **break the data pipeline**: recursively spawn child processes to emit
specially-crafted, deeply-nested, oversized telemetry that overruns serializer/storage limits
(JSON/BSON depth + size) → truncated/missing reports, rejected DB inserts, serializer
recursion errors, unresponsive dashboards → **denial-of-analysis (DoA)**, no sensor disabling,
no elevation. Evaluated vs **12** commercial + OSS malware-analysis platforms and EDRs; **7
fail**; two CVEs assigned (**CVE-2025-61301, CVE-2025-61303**); others patched/config-changed.
→ **Nyx:** a possible `postex`/anti-analysis primitive (not a stealth kit) — overload an EDR's
telemetry pipeline as a contingency when an action is likely to be logged. Complementary to
(orthogonal to) the call-stack/ETW tiers.
https://arxiv.org/abs/2511.04472

### 7.4 Defense-ceiling sources (refreshed, for honest limits)
- **fluxsec — "EDR Syscall Hooking — Ghost Hunting"** (https://fluxsec.red/edr-syscall-hooking):
  a detection theory covering **both direct and indirect syscalls** (the latter via stack
  inspection) — the ceiling our `syscalls.rs` + `stack.rs` must clear.
- **DarkRelay — "Stealth Syscall Execution: Bypassing ETW, Sysmon, and EDR"**
  (https://www.darkrelay.com/post/stealth-syscall-execution-bypass-edr-detection): executes
  syscalls indirectly through **dynamically-allocated heap memory** rather than a fixed ntdll
  gadget — a variant of our indirect path worth evaluating against the §1.1 xacone ceiling.
- **Connor McGarr — "No Code Execution? No Problem! (HVCI/kCFG/callbacks)"**
  (https://connormcgarr.github.io/hvci/) + "Investigating Kernel-Mode Shadow Stacks"
  (https://connormcgarr.github.io/km-shadow-stacks/): data-only kernel attacks under HVCI +
  kCFG + kernel-callback constraints; JTAG investigation of km shadow stacks. Reinforces the
  Outflank PatchGuard Peekaboo data-only direction for P2.2.
