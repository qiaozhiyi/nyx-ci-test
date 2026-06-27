# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**Nyx** — an authorized red-team / pentest C2 framework, Rust full-stack. P0 (the encrypted
beacon loop) is done and verified end-to-end on the dev host. The roadmap fuses Cobalt Strike's
sensibility with Brute Ratel C4's default-on stealth; see `README.md` and the full design at
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
- **`resolve.rs` PEB-walk handles PE forwarded exports** (`export_addr_by_hash_pub` →
  `resolve_forwarder` → `find_module_for_forwarder`). This was the **root cause of a nasty
  0xC0000005 crash** (see `docs/p2-2026-06-hwbp-resolve-forwarder-postmortem.md`): two stacked
  bugs — (1) the forwarder bounds check used `number_of_functions` (a count) instead of
  `export_dir_size` (bytes), so high-RVA forwarders escaped detection and were returned as raw
  ASCII string addresses; (2) forwarder module stems are abbreviated (`NTDLL`) but the PEB loader
  list has full names (`ntdll.dll`), so `find_module_by_hash` never matched. Both fixed; guarded by
  `nyx_selftest_resolve_forwarder` (exit=7, red-green verified). **If a resolved export AV's on
  call, suspect a forwarder — dump 16 bytes at the address; printable ASCII = a forwarder string,
  not code.**
- **Server keypair persists via NYX_KEYFILE** (set since 2026-06). When `NYX_KEYFILE` is
  set, the server loads (or creates + saves) a long-lived keypair via `load_or_create_keypair()`,
  so `server_pub` survives restarts and live sessions persist. Without `NYX_KEYFILE`, falls back to
  ephemeral `ServerKeypair::generate()` — in that case `server_pub` changes every restart.
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
  allocator, **slab-tracked** for heap enumeration at sleep-mask time),
  `resolve` (PEB walk + djb2; `LiveNtdll` impls
  `nyx_evasion::SyscallSource` over the live ntdll), `syscalls` (indirect-syscall
  runtime: SSN table + ntdll `syscall;ret` gadget + RX trampoline; `syscall!`
  macro + global accessor), `config` (per-build encrypted config, re-randomized
  each build by `build.rs`), `server_pub` (baked server long-term pubkey).
- **Evasion (the P2 surface — mind shipped vs skeleton):** `unhook` (KnownDlls
  `\ntdll` fresh-map + disk fallback → pristine SSN bytes & clean gadget;
  **shipped**), `blind` (AMSI/ETW userland byte-patch; **shipped**), `antidebug`
  (PEB.BeingDebugged + `ProcessDebugPort` + uptime; **shipped**), `blind_hwbp`
  (HWBP patchless blind — **shipped**, zero `.text` modification), `kits`
  (`Foliage` SleepmaskKit + `ModuleStompKit` ProcessInjectKit — **fully wired**),
  `stack` (call-stack spoof — **gated, CET-aware**), `sleep`+`mem`
  (sleep-mask — **shipped, RC4 + APC timing; heap regions now tracked and
  masked alongside .text via Foliage helper**).
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

## Current status & next steps

**P2 stealth is DONE and verified.** All userland kits shipped; kernel tier G-K tasks all pass on
real machine (Server 2019 17763.1339, 2026-06-26). Overall bypass completion: ~90%
(userland 98%, kernel algo 100%, wiring 97%, kernel real-machine all pass).
P1 dev tasks (C1 KslD dynamic device, C2 PG windows, B1 heap enumerator, B2 Foliage
heap mask) all completed 2026-06-27.

### Shipped & verified (2026-06-27)

**Userland (implant-win):**
- *Tier 0 — live in nyx_entry:* indirect syscalls (Hell/Halo/Tartarus SSN), KnownDlls+disk NTDLL unhook, AMSI/ETW userland blind, anti-debug
- *P2.1a-i SHIPPED:* `PdataGapScanner` — 4945 gaps + 65 ghosts + 12671 nops on live Server 2019
- *P2.1a-ii SHIPPED (gated):* BYOUD-Gap RSP swap — `SPOOF_SWAP_ENABLED` default OFF, CET-aware
- *P2.1a-iii SHIPPED:* `mem.rs` RC4 mask + Foliage APC timing primitive (fully wired in `kits.rs`)
- *P2.1a-iv SHIPPED:* **Heap region tracking + sleep-mask integration** — `ntalloc.rs` slab tracking (`SlabDesc[16]`), `mem::enumerate_beacon_heap_regions()` merges registered regions + all allocator slabs, `sleep.rs` Foliage helper now masks/unmaskes heap alongside `.text` (heap before .text unmask on wake)
- *P2.1b SHIPPED:* `blind::patch_nt_trace_event` (byte-patch blind)
- *P2.1c SHIPPED (gated):* `inject::module_stomp` — `MODULESTOMP_ENABLED` default OFF
- *P2.1f SHIPPED:* HWBP patchless blind (`blind_hwbp.rs`) — zero `.text` modification, invisible to PE-sieve

**Kits wiring (`kits.rs`):**
- `SLEEPMASK_KIT: Foliage` → delegates to `crate::sleep::sleep()` ✅
- `PROCESS_INJECT_KIT: ModuleStompKit` → delegates to `crate::inject::module_stomp()` ✅
- `NoMask` fallback → `crate::beacon::sleep_seconds()` (infinite recursion guard) ✅

**Kernel (operator-kernelsdk):**
- *BYOVD driver load:* `bootstrap_chain()` — Priority 1: KslD.sys (Living off the Defender) → Priority 2: RTCore64 fallback ✅
- *KslD device resolution:* **Dynamic `QueryDosDeviceW` enumeration** — tries operator-supplied → default `\\.\MpKsl` → full dos-device namespace scan for `MpKsl*` prefix ✅ (2026-06-27)
- *ETW-TI blind:* `blind_etw_ti_full()` — bootstrap_byovd → EtwTiBlind::blind(), `IsEnabled` zeroed ✅
- *DKOM process hide:* `hide_pid()` / `restore()` — `ActiveProcessLinks` unlink/relink ✅
- *Callback repurpose:* DATA write ctx pointer → ret gadget (HVCI-safe) — migrated to `telemetry.rs::CallbackNeutralizer::repurpose()` ✅ (needs selective slot targeting)
- *PatchGuard windows:* **`TimingRepairWindow`** real probe (valid_flag gate + repair callback write), **`RuntimePgBypassWindow`** data-only suspension (zero valid_flag, restore on Drop) — both wired, both HVCI-safe ✅ (2026-06-27)
- *MiniFilter:* `bootstrap_chain()` includes MiniFilter path ✅ (code done, pending real-machine verify)

**Bug fixes during kernel testing (7 total):** resolve_sym stub, GetModuleHandleA fallback, strip_prefix off-by-one, RegCreateKeyExW param swap, missing Type field, ImagePath relative path, RtCore64 device_path/IOCTL/protocol fixes

### P0 next task — selective slot targeting for repurpose

`CallbackNeutralizer::repurpose()` currently processes ALL callback slots including slot[0]
(ntoskrnl internal dispatcher). Need:
1. Migrate `callback_owner_map.rs` slot→driver mapping logic into `CallbackNeutralizer::repurpose()`
2. Add ntoskrnl skip for slot[0]
3. EDR-only filtering (skip ntoskrnl internal slots)

### Remaining gaps (not blocking)

| Item | Status | Priority |
|---|---|---|
| HSB/Moneta scan not deployed | Need download + run | P1 |
| Win11 24H2 VM not available | Only Server 2019 for real-machine | P1 |
| PDB field walker TODO in offset-resolver | Not blocking bypass logic | P2 |
| `neutralize()` marked dangerous | `.text` write → triple fault; warn in docs | P3 |
| ThreadlessInject | PE-sieve `.text` hash-mismatch true fix | P3 |
| Pattern scan 兜底 | Unknown build fallback | P3 |

### Architecture reference

- `docs/BYPASS_DEVELOPMENT_REPORT.md` — full development report (2026-06-26 updated)
- `docs/BYPASS_CAPABILITIES.md` — capability matrix with real-machine status per item
- `docs/p2-integration-analysis.md` — per-kit build-specs (research phase)
- `docs/p2-edr-bypass-plan.md` — layered plan (research phase)

### Key 2026 finding

Under HVCI **inline kernel hooks are dead**; only data-section manipulation + timing-based repair
works. `CallbackKit`/`PatchGuardKit` are designed around data+timing (repurpose ctx pointer), not
inline hooks, and degrade to the userland floor on HVCI-on hosts. `neutralize()` (.text write)
causes triple fault on slot[0] — **never use in production**; `repurpose()` is the safe path.

### Research method note

Do NOT run the `deep-research`/`code-review` Workflow flows concurrently (they fan out many
internal agents → API rate errors); for paper-reading fetch sources directly with the web reader.
