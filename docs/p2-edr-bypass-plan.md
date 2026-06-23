# Nyx P2 — Windows EDR Bypass Plan (kernel + userland)

Authorized red-team capability research for the Nyx C2 framework (P2 stealth —
the design doc's stated hardest, most-critical milestone; acceptance bar =
**lab-pass Windows Defender + 1 commercial EDR**, static + memory). This document
maps how modern EDRs instrument the Windows kernel + userland, what Nyx already
defeats, and a layered plan to close the remaining gaps using current (2024-2026)
techniques.

## 1. Threat model — how a modern EDR sees you

A current EDR (CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint,
Elastic, Bitdefender) is **kernel-parasitic** by design. Its telemetry comes from
six overlapping layers; bypassing any one is insufficient because they corroborate.

| Layer | Mechanism | What it catches |
|---|---|---|
| **Userland hooks** | DLL injected into every process; inline-hooks `ntdll!Nt*` stubs | every sensitive syscall at the user/kernel boundary (VM ops, thread/process, ALPC…) |
| **Kernel callbacks** | `PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine`, `ObRegisterCallbacks`, `CmRegisterCallback`, minifilter `fltlib` | process/thread create, cross-process **handle opens** (this is what "protects" the EDR process — `Ob` callbacks strip `PROCESS_VM_READ` rights), registry, file IO |
| **ETW + ETW-TI** | `EtwEventWrite` (userland) + the kernel **Threat-Intelligence** provider (`Microsoft-Windows-Threat-Intelligence`) | ETW-TI is the crown jewel: kernel-mode telemetry of `NtMapViewOfSection`, cross-process VM write, alloc→write→exec sequences, thread hijack/suspend. It runs *in kernel*, so userland patching cannot reach it |
| **Memory scanning** | Periodic scans of process working set for beacon signatures / RWX regions / unmapped thread start addresses | the beacon at rest between tasks |
| **Call-stack analysis** | On a suspicious syscall, EDR walks the calling thread's stack; return addresses must resolve into a known module | syscalls originating from an unbacked/injected region (reflective load, direct syscalls) |
| **HVCI / VBS + driver blocklist** | Hypervisor-protected code integrity enforces kernel CFG; Microsoft Vulnerable Driver Blocklist blocks known-bad signed drivers | unsigned execution, classic BYOVD drivers |

The defensive trend 2024→2026: **ETW-TI + memory scanning + call-stack walking**
are doing the heavy lifting as userland hooks lose ground to direct/indirect
syscalls. Kernel callbacks + `Ob` stripping remain the backbone for
process-protection and behavior policy.

## 2. What Nyx already defeats (crates/evasion + implant-win)

- **NTDLL hook bypass — DONE.** `crates/evasion/src/syscalls.rs` resolves SSNs
  via **Hells Gate → Halos Gate → Tartarus Gate** (triangulating an unhooked SSN
  from neighbouring stubs when the target is hooked) over an abstract
  `SyscallSource`. `crates/evasion/src/stub.rs` emits **direct** and **indirect**
  syscall stubs (indirect = `mov r11,<ntdll!syscall gadget>; jmp r11`, so the
  return address lands inside legitimate `ntdll`, defeating the simplest
  call-stack check). `implant-win/src/{resolve,syscalls}` turns this into a live
  indirect-syscall runtime. This neutralizes Layer 1 (userland hooks).
- **AMSI/ETW blinding — partial.** `implant-win/src/blind.rs` exists (idempotent
  AMSI + ETW patches); per-cycle AMSI retry. This is userland `EtwEventWrite` /
  `AmsiScanBuffer` prologue patching (Layer 3 *userland* half).

So Layer 1 is covered. Everything below targets Layers 2-5.

## 3. Bypass plan — layered, prioritized

### Tier 0 — already shipped
Indirect syscalls (above). No further work for Layer 1.

### Tier 1 — userland, no kernel, deployable on every beacon (do first)
Highest value-per-risk: works without privilege, defeats the dominant modern
detection vectors (memory scan + call-stack + userland ETW).

1. **Sleep masking (Ekko/Foliage via APC timer + ROP, or CreateTimerQueueTimer).**
   Between beacon cycles, encrypt the beacon's own memory + beacon thread
   context so a memory scan mid-sleep finds no signature. Nyx already has the
   seam: `implant-win/src/kits.rs` defines `SleepmaskKit::sleep_masked(seconds)`
   with a `NoMask` default and `beacon::sleep` routes through it. **Implement a
   real Ekko/Foliage impl** (CreateTimerQueueTimer + ROP gadgets to
   `VirtualProtect`→XOR→restore on wake). Reference: Cobalt Strike's sleep-mask
   kit; the timer-based "Behind the Mask" call-stack-spoofing sleep.
2. **Call-stack spoofing.** During every syscall the beacon issues, spoof the
   thread's return-address chain so it resolves into a legitimate module (not the
   unbacked beacon region). Timer/APC-based spoofing (set a fake stack before the
   `syscall`, restore after) defeats Layer 5. PoC reference: `mgeeky/ThreadStackSpoofer`,
   Cobalt Strike "Behind the Mask: Spoofing Call Stacks Dynamically with Timers".
   **Nyx seam:** extend the indirect-syscall stub (`stub.rs`) to optionally
   wrap the call with a stack-spoof prologue/epilogue.
3. **Module stomping for the beacon image.** Load a legitimate, little-used
   signed DLL into the process, then overwrite its `.text` with beacon code
   (RWX avoided — `VirtualProtect` to RW, write, back to RX). The beacon then
   "lives" inside a module the EDR trusts, defeating Layer 4 signature scans +
   the unbacked-memory call-stack check. Reference: dtsec.us "Module Stomping",
   oblivion-malware advanced module stomping (heap/stack encrypt), Avantguard
   "Threadless Ops II". **Nyx seam:** `implant-win` loader path (currently RWX
   per bof-runner, which is dev-only) — add a module-stomp allocator for the
   production beacon.
4. **Harden the AMSI/ETW blind.** Confirm `blind.rs` patches ETW-TI's *userland*
   edge (`EtwEventWrite`) + AMSI; add **provider-disable** (set the ETW
   provider's `IsEnabled` to false via the registry/ETW API) as a belt-and-
   suspenders. Reference: fluxsec.red "EDR Evasion: ETW Patching in Rust",
   Praetorian (ETW-TI + hardware breakpoints — note hardware-BP bypass via
   `NtContinue` is the userland answer to ETW-TI callbacks).

**Tier 1 acceptance:** beacon passes Windows Defender static + memory scan on a
looping sleep. This is the realistic P2.1 bar.

### Tier 2 — kernel, requires SYSTEM, highest evasion payoff (P2.2)
Targets Layers 2 + the kernel half of 3 (ETW-TI) — the things userland cannot
reach. Gate behind a privilege check; these are post-exploitation, not initial.

5. **BYOVD for a kernel read/write primitive.** Drop a signed-but-vulnerable
   driver not on the current Microsoft blocklist and exploit it for arbitrary
   kernel R/W. Current (2025) candidates researched:
   [Lenovo `CVE-2025-8061` (Quarkslab write-up)](https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html),
   [Safetica `CVE-2026-0828` + ThrottleStop `CVE-2025-7771` (0xKern3lCrush)](https://github.com/DeathShotXD/0xKern3lCrush).
   The blocklist rotates, so ship a **kit** (`VulnDriverKit` trait, mirroring
   `SleepmaskKit`) so the operator selects a current driver per engagement
   without recompiling. Reference: [Picus BYOVD](https://www.picussecurity.com/resource/blog/what-are-bring-your-own-vulnerable-driver-byovd-attacks),
   KDMapper for DSE bypass.
6. **Blind ETW-TI (kernel).** With the kernel R/W primitive, disable the
   `Microsoft-Windows-Threat-Intelligence` provider — zero its provider
   registration / the `EtwTi` enablement so its kernel callbacks stop firing.
   This is the single highest-value kernel action: it removes the alloc→write→exec
   and cross-process-VM-write telemetry that catches beacon injection. (Honest
   caveat: MDE + some EDRs cross-check ETW-TI liveness; full kill may need the
   callback tier too.)
7. **Kernel callback neutralization.** Null (or, per the 2025 evolution,
   **overwrite**) the EDR's entries in `PspCreateProcessProcessNotifyRoutineEx` /
   `PspCreateThreadNotifyRoutine` and deregister its `ObRegisterCallbacks`
   (so handle opens to the beacon process stop being stripped — this is what
   un-protects the *EDR* process too). Reference:
   [V-i-x-x/kernel-callback-removal](https://github.com/V-i-x-x/kernel-callback-removal),
   [CovertSwarm EDR-bypass timeline](https://www.covertswarm.com/post/timeline-of-edr-bypass-techniques).
   Combine with ETW-TI blind so the callback-removal itself isn't reported.

### Tier 3 — OPSEC hygiene (cross-cutting)
8. **Threadless injection** (CreateThreadPoolWait / APC-on-existing-thread)
   instead of `CreateRemoteThread` — avoids Layer 2 thread-create callback.
9. **UDRL** (userland reflective DLL loader) that maps the implant without the
   classic `MSCoreee`/`LoadLibrary` tells, + **per-build encrypted config +
   random offsets** (defeat static signature — `config` crate exists).
10. **EDR preloading** (run before the EDR's injected DLL initializes) as an
    alternative hook-avoidance path — [MalwareTech 2024](https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html).

## 4. Implementation sequencing for Nyx

| Phase | Scope | Risk | Detection bar met |
|---|---|---|---|
| **P2.1** | Tier 1 (sleep mask kit, call-stack spoof, module stomp, ETW/AMSI hardening) | low-medium, no kernel | Defender static + memory |
| **P2.2** | Tier 2 (BYOVD kit → ETW-TI blind → callback neutralization) | high — kernel, SYSTEM, blocklist-dependent | + 1 commercial EDR (engagement-gated) |
| **P2.3** | Tier 3 (threadless, UDRL, per-build config/offsets) | medium | operational hardening |

Nyx seams to extend (all already exist as P2 plug-in points): `SleepmaskKit` +
`ProcessInjectKit` (kits.rs) → add `VulnDriverKit`, `EtwTiKit`, `CallbackKit`;
the indirect-syscall stub (stub.rs) → add stack-spoof variant; `blind.rs` →
add provider-disable.

## 5. Honest limitations / what this does NOT guarantee
- ETW-TI blind + callback removal are **loud** post-exploitation actions; they
  buy time, not invisibility. Network + identity sensors (the design doc's
  detection layers) still see the beacon's traffic — malleable C2 (Phase 1) +
  redirectors (P4) address that separately.
- BYOVD is a moving target: the Microsoft Vulnerable Driver Blocklist grows, so
  a driver that works today may be blocked next Patch Tuesday. The kit model
  (operator-selectable) is the mitigation.
- HVCI/VBS-on enforces kernel CFG and blocks many callback-overwrite primitives;
  on HVCI-enforced hosts Tier 2 may degrade to Tier 1 only. Document per-host.

## Sources (2024-2026, authorized red-team / security-research)
- Kernel callbacks: [V-i-x-x/kernel-callback-removal](https://github.com/V-i-x-x/kernel-callback-removal), [CovertSwarm timeline](https://www.covertswarm.com/post/timeline-of-edr-bypass-techniques), [hxr1 — Silencing EDR via kernel debugging](https://hxr1.ghost.io/silencing-edr-via-windows-kernel-debugging/)
- ETW-TI: [Praetorian — ETW-TI + hardware breakpoints](https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/), [undev.ninja — Intro to TI ETW](https://undev.ninja/introduction-to-threat-intelligence-etw/), [fluxsec.red — ETW patching in Rust](https://fluxsec.red/etw-patching-rust)
- BYOVD: [Quarkslab — CVE-2025-8061 Lenovo](https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html), [0xKern3lCrush — CVE-2026-0828/CVE-2025-7771](https://github.com/DeathShotXD/0xKern3lCrush), [Picus](https://www.picussecurity.com/resource/blog/what-are-bring-your-own-vulnerable-driver-byovd-attacks)
- Indirect syscalls: [RedOps — Indirect syscalls + Halos Gate](https://redops.at/en/blog/indirect-syscalls-and-hooked-ssns), [Hadess — Hell's Hall PDF](https://hadess.io/wp-content/uploads/2023/10/EDR-Evasion-Techniques-using-Syscalls.pdf)
- Sleep mask + call-stack spoof: [Cobalt Strike — Behind the Mask](https://www.cobaltstrike.com/blog/behind-the-mask-spoofing-call-stacks-dynamically-with-timers), [InsomniacUnwinding](https://lorenzomeacci.com/unwind-data-cant-sleep-introducing-insomniacunwinding), [mgeeky/ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer)
- Module stomping / threadless: [dtsec.us — Module Stomping](https://dtsec.us/2023-11-04-ModuleStompin/), [Avantguard — Threadless Ops II](https://avantguard.io/en/blog/threadless-ops-ii-enhanced-evasion)
- EDR tradecraft overview: [0xdbgman — EDR Internals, Detection, Evasion](https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/)
