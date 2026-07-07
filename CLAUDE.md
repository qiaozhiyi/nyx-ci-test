# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**Nyx** — an authorized red-team / pentest C2 framework, Rust full-stack. P0 (the encrypted
beacon loop) is done and verified end-to-end on the dev host. The roadmap fuses Cobalt Strike's
sensibility with Brute Ratel C4's default-on stealth; see `README.md` and the full design at
`~/.claude/plans/composed-zooming-wombat.md`. For authorized security testing only.

## Build & test

> **Authoritative status is `docs/STATUS.md`** — code-verified, single source of
> truth. This file (`CLAUDE.md`) is the agent *guide*; when its status claims
> disagree with `docs/STATUS.md` or the code, the code + `STATUS.md` win.
> Historical audit/research docs are archived under `docs/archive/`.

```bash
cargo test --workspace                 # 326 tests green (protocol codec + server e2e + SDK + store/audit/profile + client-cli)

# single test
cargo test -p nyx-protocol frame_seal_open_roundtrip
cargo test -p nyx-server checkin_then_shell_task_roundtrips

cargo build --workspace                # build everything in the workspace
```

### Run the loop locally (three terminals)

```bash
# 1. team server — binds 0.0.0.0:8443 (override with NYX_BIND). It logs its `server_pub` hex
#    on startup; that hex is the key the agent needs. Keypair is ephemeral per
#    start UNLESS `NYX_KEYFILE` is set (then it persists across restarts).
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
- **Evasion (P6 — military-grade):** `fluctuation` + `fluctuation_thunk`
  (PAGE_NOACCESS sleep mask — CFG/CET immune, replaces Foliage/Ekko),
  `lacuna` (cross-version .pdata gap scanner → ghost frame chain builder),
  `lacuna_stomp` (BYOUD-Gap stack injection via inline asm),
  `unhook` (KnownDlls fresh-map + disk fallback), `blind` (AMSI/ETW byte-patch;
  with BLIND_OK tracking + AMSI_PATCHED cycle cap), `blind_hwbp` (HWBP patchless
  blind — VEH chain probe before registration), `antidebug`, `kits`
  (Fluctuation SleepmaskKit + ModuleStompKit — fully wired),
  `stack` (call-stack spoof — gated, CET-aware), `sleep`+`mem`
  (delegates to fluctuation; old Foliage code retained for reference).
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

**2026-07-06: Military-grade sleep obfuscation + LACUNA ghost frames shipped.**

- **Fluctuation sleep mask** (`fluctuation.rs`, `fluctuation_thunk.rs`): replaces Foliage/Ekko.
  Flips `.text` to `PAGE_NOACCESS` during sleep (memory scanners cannot read), back to
  `PAGE_EXECUTE_READ` on wake. CFG/CET immune — no ROP chains, no NtContinue, no indirect
  calls. Thunk placed on dynamically allocated RWX page (outside CFG bitmap coverage).
- **LACUNA ghost-frame scanner** (`lacuna.rs`): cross-version `.pdata` gap scanner.
  Scans ntdll/kernelbase/win32u for RUNTIME_FUNCTION lacunae at bootstrap.
  Dual-path: DataDirectory[3] first, section-header fallback for builds where
  Exception Directory is empty (17763 ntdll). Builds ghost frame chains for call-stack
  spoofing — addresses in .pdata gaps are treated as leaf frames by RtlVirtualUnwind.
  Ported from Mohamed Alzhrani's LACUNA Chain (June 2026).
- **Pool Party fix**: `local_base` replaces `target_base` for TpDirect write (was
  causing STATUS_ACCESS_VIOLATION). `TP_DIRECT_CALLBACK_OFFSET` 0x08→0x10.
- **WinHTTP TLS fix**: `WINHTTP_OPTION_SECURITY_FLAGS` 32→31 (0x1F). Added retry
  pattern: send with strict validation → on failure, set IGNORE flags → retry.

**53/53 selftests pass on Server 2019 (17763.1339), 0 timeout.** 35 validated exit
codes match expected values.

Previous milestones retained below for history.

**2026-07-01 真机全量回归（3 处 CRITICAL 修复）：** 修复了 `operator-kernelsdk` 的 2 个编译
错误（`netsec.rs:269/282` 缺失 `peb_offset` 字段 + usize/u64 类型）+ PEB 地址空间逻辑 bug、
`etw_deception.rs` 堆指针信息泄露、`client-cli` 的 `urlencoding` 未用导入 + query 参数未编码、
以及 `implant-win/envprobe.rs` 的 MAC-OUI 沙箱检测失效（`KEY_VALUE_PARTIAL_INFORMATION.Data`
偏移 8→12 + UTF-16 stride）。在 17763.1339 真机验证：workspace 88 测试全过、kernelsdk 90/94
（4 个预存平台 gate 缺陷）、evasionsdk 53 全过、**49 个 selftest 全部正常退出**（含
`nyx_selftest_envprobe`=177 证明 OUI 检测恢复工作）。`cargo test --workspace` = **88 passed / 0 failed**（implant-win/kernelsdk 为非 workspace 独立 crate，单独计）。详情见 `docs/STATUS.md` §0a。

**2026-07-02 Beacon Loop 打通（里程碑）：** implant beacon loop 在真机 Windows Server 2019
上完整运行，含全部隐蔽手段（HookChain + HWBP blind + PDT gap scan + Foliage heap masking +
CSPRNG PEB-walk）。通过 `diag_mark` 文件标记诊断法精确定位 3 个 abort 根因：
(1) CSPRNG：`getrandom` 静态链接 `advapi32` 在 PIC cdylib IAT 解析失败 → 改用 PEB-walk 动态
解析 `SystemFunction036`（适配 XP SP2 → 11 25H2）；
(2) curve25519 SIMD 后端栈问题 → 强制 serial 后端；
(3) Foliage APC helper 加密自身 .text → 降级到 data-only floor（heap RC4 + indirect-syscall
sleep，Foliage 保持启用）。
**全接线闭合**：26/26 Command 变体 TUI→REST→server→implant 完整贯通；inject pid 接线
（`pid != 0` → OpenProcess+NtAllocVM+NtWriteVM+CreateRemoteThread）；screenshot Session 0
已有 cross_session_capture（schtasks 到交互会话）。
**新增**：CI pipeline（fmt+clippy+test 跨平台）、protocol fuzz harness（1050 万输入无 panic）、
selftest 退出码验证 gate、`nyx-operator-kernel-cli` bin（kernel tier 操作化）。
详情见 `docs/STATUS.md` §0c。

### Shipped & verified (2026-06-27)

**Userland (implant-win):**
- *Tier 0 — live in nyx_entry:* indirect syscalls (Hell/Halo/Tartarus SSN), KnownDlls+disk NTDLL unhook, AMSI/ETW userland blind, anti-debug
- *P2.1a-i SHIPPED:* `PdataGapScanner` — 4945 gaps + 65 ghosts + 12671 nops on live Server 2019
- *P2.1a-ii SHIPPED (gated):* BYOUD-Gap RSP swap — `SPOOF_SWAP_ENABLED` default OFF, CET-aware
- *P2.1a-iii SHIPPED:* `mem.rs` RC4 mask + Foliage APC timing primitive (fully wired in `kits.rs`)
- *P2.1a-iv SHIPPED:* **Heap region tracking + sleep-mask integration** — `ntalloc.rs` slab tracking (`SlabDesc[16]`), `mem::enumerate_beacon_heap_regions()` merges registered regions + all allocator slabs, `sleep.rs` Foliage helper now masks/unmaskes heap alongside `.text` (heap before .text unmask on wake)
- *P2.1b SHIPPED:* `blind::patch_nt_trace_event` (byte-patch blind)
- *P2.1c SHIPPED (default ON):* `inject::module_stomp` — `MODULESTOMP_ENABLED`
  defaults **ON** (`inject.rs:56`). Module stomping + ThreadlessInject(HWBP).
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
- *Callback repurpose:* DATA write ctx pointer → ret gadget (HVCI-safe) — migrated to `telemetry.rs::CallbackNeutralizer::repurpose()` ✅ **selective slot targeting DONE** (range-based ntoskrnl skip + slot[0] fallback, real-machine verified)
- *PatchGuard windows:* **`TimingRepairWindow`** real probe (valid_flag gate + repair callback write), **`RuntimePgBypassWindow`** data-only suspension (zero valid_flag, restore on Drop) — both wired, both HVCI-safe ✅ (2026-06-27). Only the legacy `PatchGuardWindow` is a refusing skeleton.
- *MiniFilter:* **algorithm in `telemetry.rs::MiniFilterUnlinker`** (list-unlink of registered filters, data-only, HVCI-safe), **but `bootstrap_chain()` does NOT wire it** — `win/mod.rs:286` leaves `flt_globals_kva=0`. No `minifilter.rs` / `FltRegisterFilter`. 🔶 (next: wire `flt_globals` resolution)

**Bug fixes during kernel testing (7 total):** resolve_sym stub, GetModuleHandleA fallback, strip_prefix off-by-one, RegCreateKeyExW param swap, missing Type field, ImagePath relative path, RtCore64 device_path/IOCTL/protocol fixes

### DONE — postex token operations wired (G1) ✅

`postex.rs` token primitives are now first-class `Command` variants dispatched
from `beacon.rs::execute()`. The implant can impersonate / move laterally.
- New `Command` variants (tags 22-25): `StealToken{pid}`, `MakeToken{domain,
  user,password,logon_type}`, `Rev2Self`, `GetUid` — wired through the full
  hand-mirrored chain (`msg.rs` encode/decode → `JsonCommand`+`into_command`
  in `server/src/lib.rs` → both clients).
- `postex.rs` gained `make_token` (LogonUserW + DuplicateTokenEx) and `getuid`
  (OpenThreadToken → GetTokenInformation(TokenUser) → LookupAccountSidW).
  `steal_token`/`use_token`/`revert`/`current` retained unchanged.
- Clients: CLI `/steal /make_token /rev2self /getuid`; GUI console parser.
- **Real-machine verified** on Server 2019 (2026-06-27): rebuilt DLL →
  `nyx_selftest_postex` exit=15 (0b1111, 4/4); aggregate selftest no regression.
  See `docs/g1-g5-real-machine-verify-2026-06-27.md`.

### DONE — selective slot targeting for repurpose ✅

`CallbackNeutralizer::repurpose()` (`telemetry.rs:126-200`) now skips
ntoskrnl-internal slots: range-based skip when `ntoskrnl_base`+`size` are
resolved (routine ∈ `[base, base+size)` → skip, `telemetry.rs:179-184`), with a
fallback `slot[0]` skip when bounds are unknown (`:186-191`). Real-machine
verified: SysmonDrv slot[5] EID1 SILENCED + RESUMED. Only the per-driver
`callback_owner_map` mapping migration remains (refinement, not required).

### Remaining gaps (not blocking)

| Item | Status | Priority |
|---|---|---|
| Win11 24H2 VM not available | Only Server 2019 for real-machine | P1 |
| PDB field walker upgraded | Auto-detect build + ETW-TI per build + DirectoryTableBase | ✅ Done (2026-06-27) |
| HSB/Moneta scan scripts | `deploy_detectors.ps1` + `scan_linger.ps1` ready | ✅ Done (2026-06-27) |
| ThreadlessInject DR scan | DR0-DR3 slot scan + enable bit check in inject.rs | ✅ Done (was already shipped) |
| `neutralize()` marked dangerous | `.text` write → triple fault; warn in docs | P3 |
| ThreadlessInject | PE-sieve `.text` hash-mismatch true fix | P3 |
| Pattern scan 兜底 | Unknown build fallback — `pattern_scan.rs` shipped (algo done; 🔶 needs real ntoskrnl image) | ✅ Algo done |

### Architecture reference

- **`docs/STATUS.md`** — **authoritative** current status (single source of truth; gaps G1-G5 closed, only G6=Win11 24H2 hardware remains)
- `docs/BYPASS_DEVELOPMENT_REPORT.md` — full development report
- `docs/BYPASS_CAPABILITIES.md` — capability matrix with real-machine status per item
- `docs/kernel-test-results.md`, `docs/p2-real-machine-verify-2026-06-27.md` — kernel real-machine data
- `docs/g1-g5-real-machine-verify-2026-06-27.md` — G1-G5 real-machine + G5 symbol-server verification
- `docs/archive/` — historical audit/research/test docs (NOT authoritative; see `docs/archive/README.md`)

### Key 2026 finding

Under HVCI **inline kernel hooks are dead**; only data-section manipulation + timing-based repair
works. `CallbackKit`/`PatchGuardKit` are designed around data+timing (repurpose ctx pointer), not
inline hooks, and degrade to the userland floor on HVCI-on hosts. `neutralize()` (.text write)
causes triple fault on slot[0] — **never use in production**; `repurpose()` is the safe path.

### Research method note

Do NOT run the `deep-research`/`code-review` Workflow flows concurrently (they fan out many
internal agents → API rate errors); for paper-reading fetch sources directly with the web reader.

## Agent 调度规范（Nyx）

> 本仓库定义了 13 个项目级 subagent（`.claude/agents/nyx-*.md`），规范开发流程。每个 agent 内嵌
> Nyx 专属上下文（unsafe/手镜像消息链/selftest/HVCI 约束等），比通用插件 agent 更贴本项目。
> 调用方式：Agent 工具，`subagent_type` = 下表 name（需会话重载后激活）。中文为主。

### A. Rust 核心与安全（每次 `.rs` 改动必过）

| 角色 | name | 触发场景 |
|---|---|---|
| Rust 审查 | `nyx-rust-reviewer` | 任何 `.rs` 改动后；重点 unsafe/手镜像链/tag 稳定/no_std |
| build 修复 | `nyx-rust-build-resolver` | cargo build/clippy/test/交叉编译失败时；最小 diff |
| 安全审查 | `nyx-security-reviewer` | 改动触及凭据/API 端点/shell tasking/crypto/路径时 |
| 静默失败猎手 | `nyx-silent-failure-hunter` | 改动触及 evasion/sleep/inject/syscall/kernel 时 |

### B. 规划与探索（新功能开发前）

| 角色 | name | 触发场景 |
|---|---|---|
| 规划 | `nyx-planner` | 新 capability（G6/MiniFilter/UDC2/QUIC）实施蓝图 |
| 架构 | `nyx-architect` | P3/P4 路线（multiplayer/redirector/Linux agent）系统设计 |
| 代码探索 | `nyx-code-explorer` | 深挖 beacon loop/消息链/kernel 引导链路径地图 |
| 功能架构 | `nyx-code-architect` | planner 之后、实现前，出文件/接口/build order 蓝图 |

### C. 测试与验证（完成前关卡）

| 角色 | name | 触发场景 |
|---|---|---|
| TDD 指导 | `nyx-tdd-guide` | 新功能先写测试；326 基线不得回退 |
| 验证关卡 | `nyx-verification` | **任务完成声明前必过**：五条 build 链路全绿 |
| 真机 e2e | `nyx-e2e-runner` | 真机 beacon 循环（autossh+keyfile+schtasks）、selftest、TUI 47 命令矩阵 |
| 性能体积 | `nyx-performance` | implant 二进制体积、beacon 时延、sleep-mask 性能 |

### D. 维护与 MCP 调度

| 角色 | name | 触发场景 |
|---|---|---|
| 维护调度 | `nyx-devops` | STATUS.md 单一事实源维护、死代码清理、MCP/skill 调度卡（含禁用规则）|

### MCP 调度速查（详见 `nyx-devops.md`）

| MCP | 用途 |
|---|---|
| `chrome-devtools` (`mcp__plugin_ecc_chrome-devtools__*`) | REST/beacon HTTP 行为、TLS/JA3 嗅探、真机联调监控 |
| `context7` (`mcp__plugin_context7_context7__*`) | 查 axum/tokio/rustls/windows-sys/ntapi/rhai/makepad 最新文档 |
| `web reader` (`mcp__web_reader__webReader`) | 读 MSDN/内核文档/EDR 研究论文（**单串行，禁并发**，见上方 Research method note）|
| `analyze_image` (`mcp__4_5v_mcp__analyze_image`) | 分析 client-ui Makepad 截图 → 指导 UI 复刻 |

### 明确不适用（勿调用）

React/Vue/Angular/Nuxt/Next、移动端（Android/Flutter/Kotlin/Swift/HarmonyOS）、ML（PyTorch/RecSys）、
行业域（healthcare/finance/ITO/Defi）、基础设施（homelab/network/kubernetes）等 skills 与对应
reviewer/builder agent **一律不用于本仓库**（纯 Rust C2，无 Node/JS/Python/Java 后端）。完整
清单见 `.claude/agents/nyx-devops.md`。
