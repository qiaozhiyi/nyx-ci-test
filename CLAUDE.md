# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**Nyx** — an authorized red-team / pentest C2 framework, Rust full-stack. P0 (the encrypted
beacon loop) is done and verified end-to-end on the dev host. The roadmap fuses Cobalt Strike's
extensibility with Brute Ratel C4's default-on stealth; see `README.md` and the full design at
`~/.claude/plans/composed-zooming-wombat.md`. For authorized security testing only.

## Build & test

```bash
cargo test --workspace                 # all tests: 8 protocol (nyx-protocol) + 1 e2e (nyx-server)

# single test
cargo test -p nyx-protocol frame_seal_open_roundtrip
cargo test -p nyx-server checkin_then_shell_task_roundtrips

cargo build --workspace                # build everything in the workspace
```

### Run the loop locally (three terminals)

```bash
# 1. team server — binds 0.0.0.0:8443 (override with NYX_BIND). It logs its `server_pub` hex
#    on startup; that hex is the key the agent needs. Keypair is ephemeral per start.
cargo run --release -p nyx-server

# 2. dev agent — needs the server's pubkey hex (NYX_SERVER_PUB, hex) to derive the session key.
NYX_SERVER_PUB=<pubkey-from-server-logs> cargo run -p nyx-agent-dev

# 3. operator CLI — talks to the plaintext control API
cargo run -p nyx-cli -- list                                  # one-shot: list sessions
cargo run -p nyx-cli -- shell <session-hex> "whoami"          # one-shot: task + poll output
cargo run -p nyx-cli -- repl                                  # interactive (default if no subcommand)
```

Toolchain is pinned to **stable** (`rust-toolchain.toml`). The Windows PIC implant
(`crates/implant-win`) is **not** a workspace member and doesn't build here (see below). The
desktop client is pure-Rust **Makepad** (`crates/client-ui`) — no Node/JS anywhere in the project.

## Architecture: the beacon loop

There are two distinct surfaces on the team server — keep them separate:

- **`POST /beacon`** — encrypted implant traffic. Binary frame body, never JSON.
- **`GET/POST /api/*`** (`/api/sessions`, `/api/task`, `/api/tasks`, `/api/results`,
  `/api/profile`) — plaintext JSON, the **operator** control API. The CLI and the Makepad client
  both drive the loop through it (tests too).

A session's identity is the **implant's 32-byte ephemeral X25519 public key**. That pubkey does
three jobs at once: it identifies the session, it is the AEAD AAD on every frame, and the server
derives the per-session key from it on first contact. This makes the beacon handler almost
stateless per request: read pubkey → derive-or-look-up key → decrypt.

**Loop sequence** (`crates/agent-dev/src/lib.rs` is the readable reference): generate eph keypair →
check-in (first message is always `SessionInfo`) → sleep+jitter → POST last cycle's task
responses → receive queued tasks → execute → repeat. Server replies are always an encrypted task
batch (possibly empty).

### Wire protocol (hand-rolled, NOT protobuf)

The plan/design doc mentions protobuf; **the actual implementation is a hand-rolled little-endian
binary codec** (`crates/protocol/src/wire.rs`). This is deliberate so the same `protocol` crate
compiles `no_std` for the position-independent implant without a serde/prost footprint — do not
"fix" this by introducing protobuf.

Frame layout (per request body): `[32B pubkey][8B counter LE][4B ct_len LE][ciphertext || 16B tag]`
(`crates/protocol/src/frame.rs`).

Crypto (`crates/protocol/src/crypto.rs`): X25519 ECDH (implant ephemeral × server long-term
identity) → `HKDF-SHA256` bound to both pubkeys → `ChaCha20-Poly1305`; 96-bit nonce = zero-padded
LE counter; anti-replay via monotonic counter checked server-side (`raw.counter <= s.last_recv`
is rejected).

### Crate roles

| crate | role |
|---|---|
| `protocol` | shared by all: crypto, framing, message types + LE codec. The heart of the repo. |
| `server` | team server: `/beacon` listener, session registry, task queue, JSON control API |
| `agent-dev` | **std**-based dev implant — exists only to prove the loop on the dev host (macOS/Linux/Windows). **Not** the production implant. |
| `client-cli` | operator REPL/CLI over the REST API |
| `client-ui` | pure-Rust **Makepad** desktop client over the REST API (no Node/JS) |
| `implant-win` | the real Windows PIC implant (`#![no_std]`/`#![no_main]`); standalone, not a workspace member (see below) |

## Working in this codebase

- **`agent-dev` is the dev harness, not the implant.** It is `std`-based (`ureq`, blocking
  threads) to validate the protocol + server on the dev host. The real Windows PIC implant
  (`crates/implant-win`) reuses `protocol` (crypto/framing/codec) plus a few small `no_std`
  helper crates: `config` (per-build encrypted config), `evasion` (SSN + indirect-syscall
  runtime), `coff` (BOF loader), and `profile` (`no_std` feature — only the pure transform
  engine; the std parser/lexer/lint layers are resolved host-side by `build.rs` and never
  enter the PIC binary). It does **not** pull `std` or `thiserror`.
- **Adding/changing a wire message type touches a hand-mirrored chain, not a derived one.** A new
  `Command`/`Response` variant must be updated in lockstep across: `Command::encode`/`decode`
  (`msg.rs`), the server's `JsonCommand` + `into_command` mapping (`server/src/lib.rs`), and the
  client command surface (CLI / Makepad client). The wire `Command` enum is broader than the JSON
  operator surface (e.g. `Connect`/`Socks` exist on the wire but have no JSON command yet) — by
  design, narrow it deliberately when wiring up.
- **Server keypair is ephemeral per process.** `AppState::default()` and `main.rs` both call
  `ServerKeypair::generate()`, so the `server_pub` changes every restart and live sessions don't
  survive a restart. Known P0 limitation; persistence is a later-phase item.
- **Tag bytes must stay stable.** Message variants are dispatched on a `u8` tag (`1`=Ping …).
  Reordering or reusing a tag silently breaks the wire format — append new tags, don't renumber.
- **Workspace `[profile.release]`** (`opt-level = "z"`, `lto`, `panic = "abort"`, `strip`) is
  tuned for tiny implant binaries and applies workspace-wide — it affects server/CLI release
  builds too.

## `crates/implant-win` — Windows PIC implant (standalone, nightly cross-built)

The real Windows position-independent implant. It is `#![no_std]`/`#![no_main]`,
registers a **bump allocator over `NtAllocateVirtualMemory`** as `GlobalAlloc`
(`ntalloc::NtHeapAllocator` — the name is historical; it is NOT an NT-Heap), and
is built as a standalone crate **outside** the workspace (its own empty
`[workspace]` so `cargo build --workspace` stays green on the dev host).
Cross-built from macOS after `brew install mingw-w64`:

```bash
cargo +nightly check --manifest-path crates/implant-win/Cargo.toml --target x86_64-pc-windows-gnu
```

Modules (all `cfg(target_os = "windows")` except `heap`/`server_pub`):

- **Foundation:** `heap` (alloc glue), `ntalloc` (bump allocator = the global
  allocator), `resolve` (PEB walk + djb2; `LiveNtdll` impls
  `nyx_evasion::SyscallSource` over the live ntdll), `syscalls` (indirect-syscall
  runtime: SSN table + ntdll `syscall;ret` gadget + RX trampoline; `syscall!`
  macro + global accessor), `config` (per-build encrypted config, re-randomized
  each build by `build.rs`), `server_pub` (baked server long-term pubkey).
- **Evasion (the P2 surface — mind shipped vs skeleton):** `unhook` (KnownDlls
  `\ntdll` fresh-map + disk fallback → pristine SSN bytes & clean gadget;
  **shipped**), `blind` (AMSI/ETW userland byte-patch; **shipped**), `antidebug`
  (PEB.BeingDebugged + `ProcessDebugPort` + uptime; **shipped**), `kits`
  (`SleepmaskKit`/`NoMask` + `ProcessInjectKit`/`NotImpl` — **seams only, default
  no-op**), `stack` (call-stack spoof — **skeleton, not wired**), `sleep`+`mem`
  (sleep-mask — **skeletons → `NoMask`/no-op**).
- **Loop & capabilities:** `beacon` (the task loop; dispatches every wire
  `Command`), `transport` (WinHTTP POST + TLS), `envelopes` (build-time-baked
  malleable-C2 shapes), `hostinfo` (real `SessionInfo`), `fs` (Upload/Download/
  FileOp via NT syscalls → RIP in ntdll), `shell`, `recon`, `bof` (no_std W^X
  COFF loader + Beacon-API shims), `screenshot`, `keylog` (polling), `hashdump`,
  `pivot` (SOCKS relay across cycles), `postex` (token ops), `entry` (`nyx_entry`
  + selftest exports), `selftests` (per-module `rundll32` self-tests, bitmask
  exit codes).

Full link + sRDI extraction happen on a Windows host; the macOS dev host
type-checks via cross-compile.

(The old `crates/client-tauri` Tauri+React scaffold was removed, and the first-generation
`crates/client` egui client was in turn superseded and removed — the project is pure Rust and the
sole native GUI is `crates/client-ui`, a pure-Rust Makepad app. The operator CLI/TUI lives in
`crates/client-cli`.)

## Current focus & next step (P2 evasion)

Phases 1 (malleable C2), 2 (cred store), 3 (named operators + audit), 4 (SOCKS relay) are
**DONE**. **P2 stealth is the active milestone.** Research pass is complete and primary-source
grounded; the source of truth is **`docs/p2-integration-analysis.md`** (per-kit build-specs), with
`docs/p2-edr-bypass-plan.md` (layered plan), `docs/p2-windows-bypass-research.md` (cited survey),
and `docs/p2-2026-research-addendum.md` (2025-2026 call-stack/CET + ETW-TI kernel sources, which
**re-prioritize call-stack spoof to co-primary with SleepmaskKit** — our Tier-0 indirect syscalls
are now detectable, and CET kills the old return-addr spoof; go BYOUD-Gap-class).

**Capability floor (shipped vs seam vs research — read this before assuming what exists):**
- *Shipped (Tier 0 / EDR Layer 1 — live in `nyx_entry`):* indirect syscalls, Hell/Halo/Tartarus
  SSN resolution, KnownDlls+disk NTDLL unhook, AMSI/ETW userland blind, anti-debug.
- *P2.1a-i SHIPPED (verified live, `nyx_selftest_gap_scan` bitmask=0b1111):* real
  `PdataGapScanner` — `resolve::pdata_view` reads live `.pdata` from ntdll/kernelbase/win32u,
  feeds `gap::enumerate_gaps`; produced 4945 gaps + 65 ghosts + 12671 nops on a live
  Server 2019 (ntdll alone: 120404 anchors). `evasion_glue::LivePdataScanner` impls the SDK
  trait; the shared `GapPool` (absolute addresses) is the foundation for ii/iii.
- *P2.1a-ii GATED INTERMEDIATE (data path live, RSP swap gated):* `stack.rs` synthesizes +
  stages real BYOUD-Gap leaf-bridge chains via `frame::build_leaf_bridge` and wires the
  syscall hot-path hook (`spoof_wrap` + global `GapPool`). The RSP swap itself is gated
  behind `stack::SPOOF_SWAP_ENABLED` (default OFF) — see the module's CET two-layer note:
  leaf-gap chains are CET-safe at the *unwinder-walk* layer but a blind `ret`-from-fake-chain
  swap faults with `#CP` at the *execution* layer; the live swap must route through the
  `KiControlProtectionFault` lenient-repair seam (Synacktiv SSTIC 2025) before arming.
- *P2.1a-iii RC4 MASK SHIPPED / FOLIAGE TIMING GATED:* `mem.rs` masks registered regions
  with real RC4 (`rc4::apply_oneshot`, verified round-trip, `nyx_selftest_mem` bitmask=0b0011).
  The Foliage APC→`NtContinue` timing primitive (which owns the mask→sleep→unmask window and
  also masks `.text`/stacks) is gated in `kits::SleepmaskKit` (still `NoMask` default) —
  needs target-side APC-chain debugging.
- *P2.1b SHIPPED (verified live, `nyx_selftest_blind_nttrace` bitmask=0b1111):*
  `blind::patch_nt_trace_event` patches `ntdll!NtTraceEvent` → `xor eax,eax;ret` ([31 C0 C3]),
  one patch covering the whole `EtwEventWrite*` family. `impl BlindKit for LiveBlind` routes
  all `BlindTarget` variants; `entry.rs` calls it on the live bootstrap path. Less-watched
  than the P0 `EtwEventWrite` patch in 2026 Defender.
- *P2.1c GATED INTERMEDIATE (data path live, stomp+resume gated):* `inject.rs` does real
  `CreateProcessW(CREATE_SUSPENDED)` + API resolve (verified `nyx_selftest_inject`
  bitmask=0b1111, IOC-free). The `.text` stomp + `ResumeThread` is gated behind
  `inject::MODULESTOMP_ENABLED` (default OFF) — cross-process write is the loudest user-mode
  signal + a botched stomp crashes the sacrificial process; `kits::inject` now routes through
  `ModuleStompKit` (no longer `NotImpl`). Evades Moneta unbacked/private-exec; does NOT evade
  PE-sieve `.text` hash-mismatch (use ThreadlessInject for that).
- *P2.2 kernel tier — TWO IMPLS SHIPPED (algorithm + bootstrap, NOT kernel-loaded):*
  `operator-kernelsdk::etwti::EtwTiBlind` (ETW-TI provider blind: chase
  `EtwThreatIntProvRegHandle → provider block → EnableInfo → IsEnabled=0`, HVCI-safe
  data-section write, 5 mock-KernelRw tests green) + `operator-kernelsdk::byovd::
  ByovdDriver` (BYOVD `KernelRw` over a driver IOCTL channel, `RtCore64` CVE-2019-16098
  reference binding + pure ntoskrnl export resolver, 4 tests green). The driver LOAD
  step (`sc create`/`NtLoadDriver`) is operator-side and deliberately never runs in
  dev — irreversible kernel op + BSOD risk + Defender flagging; reserved for the
  authorized target. Remaining kits (CallbackKit/MiniFilterKit/WfpKit/PatchGuardKit/
  PplKit/CredKit) stay seam-only.
- *Seam only (trait exists, default no-op — NOT built):* the Foliage `SleepmaskKit` timing
  primitive (`kits.rs` `NoMask`), the live RSP swap (`stack.rs` gated), the remaining
  kernel kits (CallbackKit/MiniFilterKit/WfpKit/PatchGuardKit/PplKit/CredKit in
  `operator-kernelsdk`).
- *Research only (docs, no code):* EvilEDR repurposing, eBPF.
- *Open floor gaps after P2.1:* beacon sleep still uses `NtDelayExecution` until the Foliage
  timing primitive lands (gated); the userland ETW blind is now `NtTraceEvent`-class (P2.1b
  done); VirtualProtect-on-code-page is still a signal (blind.rs `write_patch` — upgrade to
  indirect `NtProtectVirtualMemory` is a future tech-debt fix).

**Next build = P2.1a `SleepmaskKit` (Ekko/Foliage).** The seam is `crates/implant-win/src/kits.rs`
(`SleepmaskKit` owns the mask→sleep→unmask window; swap `const SLEEPMASK_KIT` — no beacon-loop edit).
Build spec (§2.1 of the integration doc): FOLIAGE 10-step APC→`NtContinue` chain, encrypt via
`SystemFunction032` (RC4, advapi32 image-commit), sleep via `WaitForSingleObject` (not `Sleep` —
dodges the `DelayExecution` wait-reason HSB signal), validate against Hunt-Sleeping-Beacons +
Moneta/PE-sieve/BeaconEye/MalMemDetect. Wire §2.2 return-address-spoof into the chain so the
APC frames evade the updated HSB `KiUserApcDispatcher`-on-stack check.

**Key 2026 finding that re-shapes the kernel tier (P2.2):** under HVCI **inline kernel hooks are
dead**; only data-section manipulation + timing-based repair works (Outflank PatchGuard Peekaboo).
So `CallbackKit`/`PatchGuardKit` must be designed around data+timing, not inline hooks, and degrade
to the userland floor on HVCI-on hosts.

**Research method note:** do NOT run the `deep-research`/`code-review` Workflow flows concurrently
(they fan out many internal agents → API rate errors); for paper-reading fetch sources directly
with the web reader. See memory `ecc-workflow-tool-dsl.md`.
