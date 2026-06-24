# Nyx P2 — Evasion Integration Analysis (primary-source grounded)

Companion to `docs/p2-edr-bypass-plan.md` (the layered plan) and
`docs/p2-windows-bypass-research.md` (the cited survey). **This doc is the
build-spec layer**: per-kit implementation detail mapped onto Nyx's real code
surfaces, grounded in first-hand primary sources.

**For authorized red-team / security-research use only.**

## 0. Method

This pass deep-read **four primary sources in full** (not summaries):

| Source | Status | Drives |
|---|---|---|
| Kyle Avery — *Avoiding Memory Scanners* (DEF CON 30 / AceLdr) | full text | `SleepmaskKit` build spec + scanner taxonomy |
| fluxsec.red — *EDR Evasion: ETW Patching in Rust* | full text + code | `blind.rs` exact patch |
| Alachkar et al. — *EvilEDR: Repurposing EDR* (USENIX Security 2025) | full paper | `RepurposeKit` (operator strategy) |
| Outflank — *PatchGuard Peekaboo* (2026) | full text | `PatchGuardKit`/`CallbackKit` HVCI re-design |

Nation State Minds sleep whitepaper was **paywalled** (abstract only); the
remainder is cited from the companion survey. All technique detail below is
first-hand unless marked *(survey)*.

> **Process note:** this research was gathered with *direct sequential web
> fetches*, NOT the `deep-research` Workflow fan-out (which caused API rate
> errors when run ≥1 concurrently). Future research sessions: fetch directly
> with the web reader, modest parallelism. See memory
> `ecc-workflow-tool-dsl.md`.

## 1. Nyx seams today (where integration lands)

- **`SleepmaskKit`** (`crates/implant-win/src/kits.rs`) — the trait *owns* the
  whole mask→sleep→unmask window (deliberately indivisible; an Ekko/Foliage
  APC timer IS the sleep). `NoMask` default delegates to
  `beacon::sleep_seconds`. Beacon sleeps via
  `sleep_jitter → crate::kits::sleep → SLEEPMASK_KIT.sleep_masked`. **Swap is
  one line: `const SLEEPMASK_KIT: NoMask = NoMask;` → a real impl.**
- **`sleep_seconds`** (`beacon.rs`) = `NtDelayExecution` via the indirect-syscall
  runtime. ⚠️ `NtDelayExecution` sets thread wait-reason = `DelayExecution` — a
  **direct Hunt-Sleeping-Beacons / BeaconHunter signal**. A real kit must sleep
  via `WaitForSingleObject` (`NtWaitForSingleObject`) → wait-reason `UserRequest`.
- **indirect-syscall stub** (`crates/evasion/src/stub.rs`) =
  `mov r10,rcx; mov eax,<ssn>; mov r11,<ntdll!syscall gadget>; jmp r11`. This is
  the **insertion point for the return-address-spoof prologue/epilogue** (§2.2).
- **`blind.rs`** — AMSI + ETW patches, AMSI re-tried each cycle (demand-loaded),
  ETW once at entry. Idempotent. The ETW-TI *userland* half.
- **`resolve.rs`** — PEB-walk export resolution (Hell's Gate). Already gives
  ntdll/advapi32 export addresses **without `GetProcAddress`** (which is itself
  an EDR red flag — used by the fluxsec ETW patch).

## 2. Per-kit build specs

### 2.1 `SleepmaskKit` — EKKO/Foliage  ← **NEXT BUILD**

**The FOLIAGE chain (Kyle Avery, first-hand)** — queue APCs that each call
`NtContinue(ctx)` to walk the thread through 10 context-switches:

1. Wait on a new event (keep the thread alive)
2. Implant memory → non-executable (`NtProtectVirtualMemory` RX→RW)
3. **KsecDD driver encrypts** the implant memory (`\Device\KsecDD`)
4. Save the original thread context
5. Set the original thread context to a **fake (spoofed)** context
6. `NtDelayExecution` sleep (the actual delay)
7. **KsecDD decrypts** the implant memory
8. Restore the original thread context
9. Implant memory → executable (RW→RX)
10. Exit the new thread

**Ekko** = the identical chain but uses `CreateTimerQueueTimer` instead of
`NtQueueApcThread` to queue the `NtContinue` calls (C5pider's reverse of MDSec
NightHawk).

**Encryption primitive — `SystemFunction032`** resolved from `advapi32.dll`:
RC4, bidirectional, takes `(USTRING* data, USTRING* key)`. Runs from *image
commit* (advapi32), so it evades Moneta's "executable private-commit memory"
check. (`SystemFunction033` is the documented decrypt; RC4 is symmetric so
either works.) **Use this, not a hand-rolled XOR/AES stub** (a private-commit
crypto stub is itself a Moneta hit).

**Wait-reason dodge**: `Sleep()` → wait-reason `DelayExecution` (caught).
`WaitForSingleObject(handle, ms)` → wait-reason `UserRequest` (not caught by
the original HSB).

**Detection to beat — Hunt-Sleeping-Beacons (updated for FOLIAGE)**: flags
threads with wait-reason `UserRequest` **AND** `KiUserApcDispatcher` somewhere
on the call stack. Public FOLIAGE can't easily bypass this because it
obfuscates its own return-address-spoof shellcode, so the APC thread can't
invoke it. → **Nyx's differentiator: integrate return-address spoofing INTO the
sleep chain** (§2.2) so the APC frames resolve to image-commit addresses.

**Scanner taxonomy (Kyle Avery, first-hand):**
- *Pattern matching* — YARA (Carbon Black, CrowdStrike); BeaconEye (heap-scan
  for Cobalt Strike config structs).
- *Memory attributes* — Moneta (executable + private-commit); PE-sieve (all
  perms + thread **return-address** check for private-commit).
- *Stack tracing* — BeaconHunter/HSB (`DelayExecution` wait-reason; updated for
  FOLIAGE as above); MalMemDetect (hooks `RtlAllocateHeap`, checks the return
  address **at execution time**).

**Nyx approach (no_std / PIC-safe):**
- New `struct Foliage` (and/or `Ekko`) impl of `SleepmaskKit` — new module or
  extend `kits.rs`. Swap `const SLEEPMASK_KIT`.
- Mask `.text` (image base + range from the PEB walk `resolve.rs` already does).
- All syscalls via the indirect-syscall runtime (`syscalls.rs`): `NtProtectVirtualMemory`,
  `NtQueueApcThread` (Foliage) or `CreateTimerQueueTimer` (Ekko),
  `NtWaitForSingleObject` (sleep, not `NtDelayExecution`), `NtContinue`,
  `NtSetContextThread`.
- Encryption: `SystemFunction032` via `resolve.rs` (`resolve("advapi32.dll","SystemFunction032")`).
  Key per-sleep from the existing `xorshift32` seed in `beacon::sleep_jitter`
  (non-secret — just needs determinism across the mask/restore).
- *v2 heap encryption*: `RtlCreateHeap` a secondary heap, re-point the implant's
  `GetProcessHeap` IAT entry to it, encrypt that whole heap on sleep (defeats
  BeaconEye). [Kyle Avery's TitanLdr-fork approach.]
- **Contract change:** none — pure impl swap of `const SLEEPMASK_KIT` (the trait
  already owns the window). Optional: a `masking` config knob (`off`/`ekko`/`foliage`)
  selected per build.
- **no_std constraints:** every call through the indirect-syscall runtime; no
  std/thiserror/serde; crypto via image-commit `SystemFunction032` (no
  private-commit stub); `CONTEXT` structs on a heap region the kit manages.
- **Validation:** Hunt-Sleeping-Beacons (zero hits), Moneta, PE-sieve, BeaconEye,
  MalMemDetect, **Defender static + memory scan on a looping sleep** = the P2.1
  acceptance bar.

### 2.2 Return-address-spoof layer (pairs with §2.1)

Two modes (Kyle Avery, first-hand):
- **At rest (during sleep):** PE-sieve checks return addresses. ThreadStackSpoofer
  overwrites the return addr with `0` (truncates stack — can leak args that look
  like addresses). FOLIAGE instead uses `NtSetContextThread` to set a
  manufactured context with the desired return address. (`NtSetContextThread` is
  rare → a *potential* detection point, but not currently alerted.)
- **At execution:** MalMemDetect hooks `RtlAllocateHeap` etc. and inspects the
  return address when the implant calls them. The **x64 Return Address Spoofing
  PoC**: store a ROP gadget (`jmp rbx`) from a loaded DLL as the return address
  before the API call; it jumps to a stub that restores context and continues.

**Nyx:** wrap `indirect_stub` (`stub.rs`) with a spoof prologue/epilogue. At
minimum spoof the syscalls scanners hook (for Nyx: `RtlAllocateHeap`,
`NtWaitForSingleObject`, the file-op syscalls, the WinHTTP path). **This is what
makes §2.1 evade the updated HSB** — without it, Foliage trips the
`KiUserApcDispatcher`-on-stack check.

### 2.3 `blind.rs` — suppress (+ future deceive) ETW / AMSI

First-hand (fluxsec, *ETW Patching in Rust*):
- `NtTraceEvent` ntdll stub = `4C 8B D1 / B8 5E000000 / 0F 05`
  (`mov r10,rcx; mov eax,0x5E; syscall`) — SSN **0x5E (94)** on the tested
  build; **resolve it live, never hardcode.**
- **Patch:** overwrite byte 0 (`0x4C`) with `0xC3` (`ret`) via
  `NtWriteVirtualMemory` (indirect syscall). One byte, ret-on-entry → ETW never
  receives the event from this process.
- `EtwEventWrite` and `EtwEventWriteFull` **both proxy into `NtTraceEvent`** →
  patching `NtTraceEvent` alone suffices.
- **Resolve via PEB-walk (Hell's Gate), NEVER `GetProcAddress("NtTraceEvent")`** —
  that string resolve is itself a red flag.
- **KERNEL ceiling:** the Threat-Intelligence provider
  (`Microsoft-Windows-Threat-Intelligence`) is kernel-mode, fires on
  `NtAllocateVirtualMemory` / `NtProtectVirtualMemory` / `NtMapViewOfSection` /
  `NtReadVirtualMemory` / `NtWriteVirtualMemory`. Userland patching can't reach
  it → fully blinding TI needs the **kernel tier (§2.6, P2.2)**.
- **Anticipate the defense:** fluxsec is building Sanctum EDR, which detects
  NTDLL patching via *in-kernel full-spectrum ETW*. The harder target is **ETW
  deception** (forge benign events, Black Hat'25 *I'm in Your Logs Now*) — a
  future `blind.rs` mode.

**Nyx:** verify `blind.rs` patches `NtTraceEvent` byte0→`0xC3` at the
**PEB-resolved** address (not via `GetProcAddress`), idempotently. Add
**provider-disable** (set the provider GUID `IsEnabled` bit false) as
belt-and-suspenders. Document the ETW-TI kernel ceiling honestly.

### 2.4 `ProcessInjectKit` — module stomping  *(survey + Kyle Avery)*

`LoadLibrary` a legit, rarely-used signed DLL, `NtProtectVirtualMemory` its
`.text` → RW, `memcpy` shellcode, reprotect → RX. The region then "lives" inside
a trusted module → defeats Moneta (executable-private) + the unbacked-memory
call-stack check. Swap `NotImpl` → real impl. no_std via indirect syscalls +
PEB-walk `LoadLibraryA`. *(dtsec.us / oblivion-malware advanced module stomping.)*

### 2.5 `RepurposeKit` — EvilEDR  ← **operator strategy, NOT an implant trait**

First-hand (EvilEDR, USENIX Security 2025, full paper):
- **Concept:** deploy an attacker-controlled EDR ("EvilEDR") *alongside* the
  enterprise EDR and misuse its **legitimate features** — it is **not** a
  software vulnerability; it repurposes the EDR as designed.
- **Live-response console** = remote command execution (C2); **file download** =
  exfiltration; **file upload** = lateral tool transfer (**bypasses Mark-of-the-Web**);
  **passive telemetry** = discovery; runs as **SYSTEM**; inherent persistence +
  tamper protection.
- **EPP Takeover:** register own EPP as the default via the **Windows Security
  Center API** → disables/replaces the existing EPP, **no alert**.
- **Host isolation:** isolate the host so it only talks to the EvilEDR server →
  enterprise EDR shows the host **offline, no logs**, not flagged.
- **Credential:** **MDE-only** can export SAM/SYSTEM/SECURITY hives via live
  response, bypassing OS protections, **undetected**.
- Tested on **MDE, Elastic, Sophos, Trend Micro**. The paper's Appendix A is a
  full **EDR driver + process table** (MDE: `WdFilter.sys`/`WdNisDrv.sys` +
  `MsSense.exe`/`SenseIR.exe`; Falcon: `csagent.sys` + `CSFalconService.exe`; …).
- **Defense:** Sigma rules on driver-load (**Sysmon EID 6**) + EDR process names;
  WDAC; least privilege; outbound network controls.
- Authors' future-work note: redirect an *existing* enterprise EDR to an attacker
  server — couldn't fully (integrity controls); found **one vendor's
  tamper-protection bypass** (under embargo, bounty paid).

**Nyx implication:** this is an **operator capability** (ride/trust a resident or
secondary EDR), *not* an implant kit trait. Nyx value-add = operator tooling to
deploy/operate an EvilEDR-style secondary agent **plus** the defensive Sigma set
(for the operator's own lab). It **informs the kernel-tier philosophy**: RIDE the
resident EDR rather than kill its callbacks.

### 2.6 `CallbackKit` / `PatchGuardKit` — the HVCI re-shaping  (P2.2, kernel, engagement-gated)

First-hand (Outflank, *PatchGuard Peekaboo*, 2026):
- **HVCI = code pages R-X in EPT** (hypervisor, not software). Writing a code
  page → EPT violation → VM-exit → VTL1 `KeBugCheckEx`. `CR0.WP` / PTE tricks are
  **powerless** (EPT is a second translation layer the guest cannot touch).
  → **INLINE KERNEL HOOKS ARE DEAD under HVCI.**
- **BUT data sections are EPT RW-** (writable). **HVCI does NOT check data
  sections.** → **DATA-SECTION MANIPULATION is the only viable in-kernel path.**
- **VTL0** (normal kernel: `ntoskrnl`, drivers) vs **VTL1** (`securekernel.exe`,
  `ci.dll`/`skci.dll`, `LsaIso` for Credential Guard). VTL1 reads VTL0; VTL0
  cannot read VTL1.
- **SKPG (Secure Kernel PatchGuard)** runs in VTL1 and watches VTL0 from the
  hypervisor — separate, harder, **largely unexplored**. Their bypass addresses
  *traditional* PG only; SKPG is the open unknown.
- **Working PoC (process hiding):** unlink `EPROCESS.ActiveProcessLinks`
  (`Flink`/`Blink`). Problem: `PspProcessDelete` runs a LIST_ENTRY integrity
  check at termination → `int 29h` fast-fail →
  `0x139 KERNEL_SECURITY_CHECK_FAILURE`. Check: `Flink->Blink == our entry` AND
  `Blink->Flink == our entry`.
- **Solution:** register a `PsSetCreateProcessNotifyRoutineEx` callback; in the
  **termination** callback (`CreateInfo == NULL`), extract `ActiveProcessLinks`,
  verify corruption, **repair** (`*Flink->Blink = OurListEntry; *Blink->Flink = OurListEntry`)
  microseconds before `PspProcessDelete` validates → PG sees consistent links.
- **Constraint:** needs a **signed kernel driver** (legit-signed / stolen cert /
  vulnerable signed driver = BYOVD). HVCI does **not** block it (data
  manipulation via documented callbacks, no code modification).
- Other paths explored (harder/fragile): data-section function-pointer hooks,
  vtable hooks, callback-array replacement (`ObRegisterCallbacks` `OBJECT_TYPE`
  **IS** monitored by PG → bugchecks), context manipulation during thread
  transitions (APC/trap-frame RIP redirect — fragile, CET/Shadow-Stack counters
  it).

**Nyx implication:** **re-design `CallbackKit`/`PatchGuardKit` around
data-section manipulation + timing-based repair, NOT inline hooks.** Kernel
presence needs a signed driver (BYOVD / DMA bootstrap). On HVCI-on hosts the
kernel tier **degrades**; the userland tier (§2.1–2.4) is the floor that always
works.

### 2.7 eBPF module (Linux v2)  *(survey)*

"Curing" io_uring rootkit (ARMO): ops via **io_uring async I/O** (bypasses
syscall-path probes) + **privileged BPF** to blind/subvert Tetragon/Falco;
validated vs **Falco + Tetragon + MDE**. Tetragon **enforces in-kernel** (not
just detects) → assume enforcement-grade targets. Linux v2 agent module.

## 3. Dependency order + capability ladder

- **Floor (always, userland, no kernel):** §2.1 sleep mask + §2.2 stack spoof +
  §2.3 ETW/AMSI blind + §2.4 module stomp = **P2.1**. Acceptance: Defender
  static + memory scan on a looping sleep.
- **Runtime capability detection (beacon):** HVCI? VBS? PG/SKPG present?
  ETW-TI registered? AMSI present? → select tier; on HVCI-on, the kernel tier
  degrades to the floor.
- **Kernel (needs SYSTEM + signed driver / DMA):** §2.6 CallbackKit/PatchGuardKit
  (data-section, timing repair) = **P2.2**, engagement-gated.
- **Operator strategy (separate track):** §2.5 EvilEDR repurposing.
- **Shared infrastructure to build once:** indirect-syscall stub generator (have),
  PEB export resolver (have), **timer+APC helper** (shared by §2.1 sleep + §2.2
  spoof + future threadless inject), `SystemFunction032` wrapper, image-base /
  `.text`-range discovery.

## 4. Build order (gated)

| Phase | Kits | Gate |
|---|---|---|
| **P2.1a** | `SleepmaskKit` Ekko/Foliage + `WaitForSingleObject` wait dodge + `SystemFunction032` | floor works; image base from PEB |
| **P2.1b** | stack-spoof wrap (`stub.rs`) + `blind.rs` NtTraceEvent-via-PEB verify + provider-disable | P2.1a green vs HSB/Moneta |
| **P2.1c** | `ProcessInjectKit` module stomp | postex needs it |
| **P2.2** | `CallbackKit` + `PatchGuardKit` (data-section, timing repair) | SYSTEM + signed driver; HVCI-aware fallback |
| **op** | EvilEDR repurposing (operator tooling + Sigma set) | separate track |
| **Linux v2** | eBPF-abuse module | Linux agent |

## 4a. 实现状态 (2026-06-24)

| Phase | 代码 | 本机测试 | 真机验证 |
|---|---|---|---|
| P2.1a-i (gap scanner) | ✅ evasion_glue.rs | ✅ selftest bitmask | 待真机 gap_count>0 |
| P2.1a-ii (stack spoof) | 🔶 swap.rs 决策✅, RSP asm 待调试 | ✅ swap 5测 | 待真机 CET 探测 |
| P2.1b (blind) | ✅ NtTraceEvent + provider-disable | — | 待真机 logman 沉默 |
| P2.1a-iii (foliage) | 🔶 foliage.rs 状态机✅, sleep.rs 同步骨架✅, APC 链待真机 | ✅ foliage 5测 | 待 HSB/Moneta |
| P2.1c (inject) | 🔶 stomp 骨架 (gated OFF) | — | 待 PE-sieve |
| P2.2 (kernel) | ✅ 6 模块算法 + win/ 壳占位 | ✅ 27 mock 测 | driver load (operator) |

**测试总数:** evasionsdk 39 + kernel 27 = 66 个本机可测；implant-win 外壳全部
`cargo +nightly check --target x86_64-pc-windows-gnu` 交叉通过。真机验证清单见
`docs/p2-real-machine-validation-checklist.md`。

## 5. Validation matrix

| Kit | Validate against |
|---|---|
| `SleepmaskKit` | Hunt-Sleeping-Beacons, Moneta, PE-sieve, BeaconEye, MalMemDetect, Defender memory scan |
| `blind.rs` | custom ETW-provider emit test (`logman … tracerpt … .csv`, fluxsec's method) |
| `PatchGuardKit`/`CallbackKit` | HVCI-on AND HVCI-off VM; Sysmon EID 6 detection |
| `RepurposeKit` | the operator's own lab EDR + the paper's Sigma rules |

## 6. Honest limits

- ETW-TI is kernel; userland blind reduces but does **not** kill TI (needs §2.6).
- HVCI/VBS-on: kernel tier degrades to the floor; **inline hooks dead**; only
  data-section manipulation + timing.
- BYOVD churns (MS Vulnerable-Driver Blocklist); DMA needs hardware; EvilEDR
  needs a distinct EDR license.
- A sleep mask lengthens the detection window — it is **not** invisibility.
  Network/identity sensors are addressed separately by malleable C2 (Phase 1 ✅)
  + redirectors (P4).

## 7. Sources (first-hand this pass)

- Kyle Avery — *Avoiding Memory Scanners* (DEF CON 30 / AceLdr). https://kyleavery.com/posts/avoiding-memory-scanners/
- fluxsec.red — *EDR Evasion: ETW Patching in Rust*. https://fluxsec.red/etw-patching-rust
- Alachkar, Gaastra, Barbaro, van Eeten, Zhauniarovich — *EvilEDR: Repurposing EDR as an Offensive Tool*, USENIX Security 2025. https://www.usenix.org/system/files/usenixsecurity25-alachkar.pdf
- Outflank (K. Czapczyński) — *PatchGuard Peekaboo: Hiding Processes on Systems with PatchGuard in 2026*. https://www.outflank.nl/blog/2026/01/07/patchguard-peekaboo-hiding-processes-on-systems-with-patchguard-in-2026/
- Nation State Minds — *Sleep Obfuscation: EKKO, Foliage, and the Memory Scanner Evasion Landscape* (abstract only, paywalled). https://www.nationstateminds.com/whitepapers/sleep-obfuscation-ekko-foliage-and-the-memory-scanner-evasion-landscape
- Companion survey: `docs/p2-windows-bypass-research.md` (sections A–Q).
