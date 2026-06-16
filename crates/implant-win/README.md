# nyx-implant-win — Windows PIC implant (the "BRC4-grade stealth" agent)

> **Status:** scaffolded. This is the real production agent (NOT the `agent-dev`
> std stub that proves the protocol). It compiles only with a pinned **nightly**
> toolchain against a **Windows x86_64** target and a PIC extraction step — it
> cannot be built or run-tested on the macOS dev host. Build on a Windows host
> (or a Linux/macOS host with `mingw-w64` / `lld-link`) per the pipeline below.

## Goal

A 64-bit **position-independent** implant in Rust whose default-on evasion matches
BRC4's out-of-the-box capabilities, while reusing [`nyx-protocol`](../protocol)
verbatim for the wire/crypto layer. Reference implementations that prove the
approach: [`safedv/Rustic64`](https://github.com/safedv/Rustic64) and
[`Cracked5pider/Stardust`](https://github.com/Cracked5pider/Stardust).

## Module plan (`src/`)

| module | responsibility |
|---|---|
| `entry` | PIC entry stub; bootstrap: locate base, set up global instance, call `main` |
| `alloc` | custom allocator over the **NT Heap** (`RtlCreateHeap`/`RtlAllocateHeap`/`RtlFreeHeap`) so `Vec`/`String` work in PIC |
| `resolve` | **PEB walk** + djb2 hash API/module resolution (no import table) |
| `core` | task loop, custom **IOCP reactor** (async pivot/sleep without tokio), transport abstraction |
| `transport/http` | Malleable HTTP(S) transport (schannel/winhttp via syscalls) |
| `evasion/*` | **Evasion Kit** — see below (default-on, each technique a feature flag) |
| `bof` | COFF loader + relocation + CS Beacon API → reuse community BOFs |
| `postex` | token, lateral, lsass-read, kerberos, ldap, screenshot |

## Evasion Kit (`evasion/`) — default ON, individually toggleable

Mirrors BRC4's evasion table. Each is a feature-gated native module so the core
stays swappable (CS "kit" philosophy + BRC4 "on by default" reality).

| technique | module | reference |
|---|---|---|
| indirect syscalls (Halo's Gate SSN resolve + `jmp ntdll!syscall`) | `evasion::syscalls` | `0xflux/Rust-Hells-Gate`, RedOps |
| call-stack spoofing (legit return-address emulation) | `evasion::stack` | Ethradjius spoof, mrexodia ThreadStackSpoofer |
| sleep obfuscation (Ekko/Foliage APC-timer; encrypt self + all thread stacks, RX-only) | `evasion::sleep` | C5pider Ekko/Foliage |
| module stomping + PEB hooking | `evasion::stomp` | BRC4 |
| AMSI/ETW bypass (HW-breakpoint patch, LoadLibrary proxy) | `evasion::blind` | Boku8 HWBP |
| NTDLL fresh-map unhook (from KnownDlls, not disk — avoids IOC) | `evasion::unhook` | S12 selective unhooking |
| heap/stack encryption + secure heap free (anti-Volatility) | `evasion::mem` | BRC4 |
| anti-debug / anti-sandbox | `evasion::antidebug` | — |
| drip loading (break injection primitives across time) | `evasion::drip` | CS 4.12 |

**Honest boundary:** ETW-TI is kernel-mode; user-mode blinds ETW *providers*
but not ETW-TI. Fully defeating ETW-TI needs a kernel module (future "scheme C",
out of v1 scope).

## Build pipeline (PIC)

```
nightly + target x86_64-pc-windows-{msvc,gnu}
  └─ #![no_std]#![no_main], panic=abort, custom NT Heap global allocator
  └─ cargo build --release --target x86_64-pc-windows-gnu   (or -msvc)
        → produces a PE with a single PIC .text section
  └─ extract: dump the position-independent .text (+ resolve relocations) → agent.bin
        (Stardust-style sRDI extraction / Rustic64 linker script)
```

- Pin nightly via a crate-local `rust-toolchain.toml` (`channel = "nightly-2025-XX"`).
- GNU path: `x86_64-pc-windows-gnu` + `mingw-w64` (`brew install mingw-w64` on macOS
  lets you *compile-check* here, but PIC extraction + runtime still need Windows).
- MSVC path: requires the Windows SDK / `lld-link`.

## Why not built yet

- No nightly toolchain installed on the dev host (added stable only).
- PIC extraction + Windows runtime testing need a Windows environment.
- `nyx-protocol`'s crypto/codec is already `no_std`-portable, so porting the
  beacon loop here is mostly mechanical once the toolchain is in place.

Next concrete step: install nightly + the `x86_64-pc-windows-gnu` target,
port `agent-dev`'s task loop into the `#![no_std]` skeleton with the NT Heap
allocator and PEB resolver, then wire the Evasion Kit modules.
