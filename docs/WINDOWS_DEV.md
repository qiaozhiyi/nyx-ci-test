# Windows 侧开发开工指南（远程 Windows 构建机）

> 本机（`ssh win` / `ssh server` = `administrator@154.201.73.219`，Windows Server 2019 1809，build 10.0.17763）
> 是 **implant-win 的原生构建/链接/sRDI 提取机**。macOS 开发机只能 cross-`check`，真正的 Windows PIC
> 落地在此。本文给远程 Claude Code 会话的开工说明。
> 项目主说明：根 `CLAUDE.md`（必读，权威）。研究情报：`docs/p2-*.md` + 根目录 5 份研究 `.md`。

---

## 0. 当前要做的（一句话）

**把 `implant-win` 接上 `implant-evasionsdk` 的纯算法核心**：用 `resolve.rs`（已有 PEB walk）读取 live
`ntdll`/`kernelbase`/`win32u`/`wow64` 的 `.pdata` 字节 → 喂给 SDK 的 `gap::enumerate_gaps` → 产出真实
`GapPool` → 实现 `PdataGapScanner` trait。这是 `StackSpoofKit`（BYOUD-Gap）和 `SleepmaskKit`
（InsomniacUnwinding）的地基，**所有用户态 tier-1 规避都依赖它**。详见 `docs/p2-2026-h2-latest-sweep.md`、
`docs/p2-2026-kernel-tier-deepdive.md`、根 `p2_research_synthesis.md` 的 build 顺序（P2.1a-i → ii → iii）。

---

## 1. 环境安装（本机目前是裸的，只有 tar.exe）

以 `administrator` 登录（已配免密：`ssh win`）。在 **PowerShell（管理员）** 里：

```powershell
# 1) Rust（nightly + MSVC + build-std 所需的 rust-src）
Invoke-WebRequest -Uri https://win.rustup.rs/x86_64 -OutFile "$env:TEMP\rustup-init.exe"
& "$env:TEMP\rustup-init.exe" -y --default-toolchain nightly --profile default
# 重开 shell 后：
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
rustup target add x86_64-pc-windows-msvc

# 2) C++ 构建工具（MSVC 链接器 link.exe）—— 装 Visual Studio Build Tools
#    https://aka.ms/buildtools （选 "Desktop development with C++"）

# 3) git（可选，仅为版本管理；代码已通过 tar 推送）
winget install --id Git.Git -e

# 4) Claude Code（需 Node.js：winget install OpenJS.NodeJS.LTS）
npm install -g @anthropic-ai/claude-code
```

> implant-win 是 `#![no_std]`/`#![no_main]`，**链接需要 `-Z build-std`**（从源码构建 core/alloc），
> 所以 nightly + `rust-src` 是硬依赖。

---

## 2. 仓库布局（已推送到 `C:\Users\administrator\nyx\pentest`）

```text
pentest/
├─ CLAUDE.md                  ← 项目权威说明（必读）
├─ docs/
│  ├─ WINDOWS_DEV.md          ← 本文件
│  ├─ p2-integration-analysis.md   ← 每-kit build spec（最权威落地手册）
│  ├─ p2-2026-h2-latest-sweep.md   ← 最新 Exa 情报（EDRChoker/SunnyDayBPF/LACUNA…）
│  ├─ p2-2026-kernel-tier-deepdive.md ← 内核 tier 深度 + Rust kit 接口设计
│  └─ p2-*.md …                ← 分层计划/文献综述/2026 增补
├─ academic_papers_database.md / commercial_c2_security_research.md /
│  edr_kernel_complete_handbook.md / kernel_edr_evasion_2026.md / p2_research_synthesis.md
│                              ← 根目录 5 份研究语料（USENIX/BH/DC 论文 + CVE + 商业 C2 对标）
│
├─ crates/  （主 workspace 成员，`cargo build --workspace` 在本机也能跑）
│  ├─ protocol/ … server/ agent-dev/ client-cli/ client-ui/ store/ pe/ evasion/ parse/
│  │  coff/ config/ config-macros/ profile/ transport/ rest/ scripting*/ bof-runner/
│  │
│  └─ （standalone，各自带空 [workspace]，不在主 workspace 内）
│     ├─ implant-win/          ← 【本机主战场】真实 Windows PIC implant
│     │  src/{resolve, syscalls, unhook, blind, antidebug, kits, stack, sleep, mem,
│     │       beacon, fs, shell, recon, bof, screenshot, keylog, hashdump, pivot, postex, …}.rs
│     ├─ implant-evasionsdk/   ← 用户态规避·纯算法核心 + trait 接缝（no_std，已 24 测试绿）
│     │  src/{lib, gap, frame, rc4}.rs
│     └─ operator-kernelsdk/   ← 内核态 operator 工具·trait 接缝（cfg windows，seam-only）
│        src/lib.rs
```

**两个新 SDK crate（本会话新建，CLAUDE.md 可能尚未提及）：**
- `implant-evasionsdk`：用户态规避接缝面。9 个 trait（`SyscallSource`/`PdataGapScanner`/
  `StackSpoofKit`+`SpoofGuard`/`SleepmaskKit`/`MemoryMaskKit`+`MaskToken`/`BlindKit`+`BlindTarget`/
  `UnhookKit`/`AntiDebugKit`/`ProcessInjectKit`）+ `EvasionStack` 组装器 + `Floors` no-op 地板。
  已含 3 个纯算法实现模块：`gap.rs`（.pdata gap 枚举，10 测试）、`frame.rs`（BYOUD 假帧链合成，8 测试）、
  `rc4.rs`（SystemFunction032 睡眠掩码 RC4，6 测试）。
- `operator-kernelsdk`：内核 tier 接缝（operator-side）。`KernelRw` 基础 → `EtwTiKit`/`CallbackKit`/
  `MiniFilterKit`/`WfpKit`/`PatchGuardKit`+`PgGuard`/`ProcHideKit`/`PplKit`/`EdrNeutralizeKit`/`CredKit` +
  `NoKernel` 地板 + `KernelTier` 组装。**接缝-only，无真实 impl。**

---

## 3. 构建与验证命令（原生 Windows）

```powershell
cd C:\Users\administrator\nyx\pentest

# A. 主 workspace（server/cli/ui 等）—— 验证回归不破
cargo build --workspace
cargo test --workspace

# B. 两个 SDK crate（独立，no_std；evasionsdk 有 24 个 host 测试）
cargo test --manifest-path crates\implant-evasionsdk\Cargo.toml
cargo check --manifest-path crates\operator-kernelsdk\Cargo.toml

# C. implant-win —— type-check（nightly + build-std）
cargo +nightly check --manifest-path crates\implant-win\Cargo.toml --target x86_64-pc-windows-msvc -Z build-std=core,alloc

# D. implant-win —— 完整 link + sRDI PIC 提取（链接器 link.exe 必须就绪）
cargo +nightly build --release --manifest-path crates\implant-win\Cargo.toml --target x86_64-pc-windows-msvc -Z build-std=core,alloc,panic_abort
# 然后 sRDI 把产物转成 position-independent shellcode（见 CLAUDE.md "Full link + sRDI extraction"）
```

> macOS 开发机用 `--target x86_64-pc-windows-gnu`（mingw cross）；**本机用原生 `msvc`**。
> 若 MSVC 工具链暂时没装，先做 A/B/C（C 的 check 不需要链接器），D 等 Build Tools 装好再做。

---

## 4. 接线任务详述：第一个真实 `PdataGapScanner` impl（P2.1a-i）

**架构（纯核心 + 平台外壳，别重复实现 gap 数学）：**
```
implant-win/resolve.rs  (平台外壳)
  PEB walk → ntdll/kernelbase/win32u/wow64 的内存基址
  PE 头解析 → 定位 .pdata section 的 VA + size → 读出字节
        │  (Windows 专属：要 PEB、要读活内存)
        ▼  raw bytes
implant-evasionsdk/gap.rs  (纯算法，已写好测好)
  gap::parse_table(bytes) → Vec<RuntimeFunctionEntry>
  gap::enumerate_gaps(entries, image_size, max_per_gap) → Vec<Gap>
  gap::classify_into_pool(gaps, image, ghost_pred, nop_pred) → GapPool
        │
        ▼
  → 喂给 StackSpoofKit::ByoudGap / SleepmaskKit
```

**具体改动：**
1. `crates/implant-win/Cargo.toml` 加依赖：
   ```toml
   [dependencies]
   nyx-implant-evasionsdk = { path = "../implant-evasionsdk", default-features = false }
   ```
2. `crates/implant-win/src/resolve.rs` 加一个函数：给定一个已加载 DLL 的基址，
   解析其 PE 头（`IMAGE_DOS_HEADER`→`IMAGE_NT_HEADERS`→`IMAGE_SECTION_HEADER` 找 `.pdata`），
   返回 `.pdata` 的 `(byte_slice, image_size)`。（resolve.rs 已有 PEB walk + djb2 export 解析，
   扩展它而非新建模块。）
3. 新增 `impl nyx_implant_evasionsdk::PdataGapScanner for LivePdataScanner`（放在 implant-win，
   例如 `stack.rs` 或新 `evasion_glue.rs`）：对 ntdll/kernelbase/win32u/wow64 各跑步骤 2，
   调 `gap::parse_table`+`enumerate_gaps`+`classify_into_pool`，合并成一个 `GapPool` 返回。
4. `selftests.rs` 加一个 bitmask 自检：在 Win10/11/Server2019 上 `gap_count > 0`。
5. 验证：`cargo +nightly check … -Z build-std`（C 命令）+ 在本机 `rundll32` 跑自检。

**关键约束（别踩坑）：**
- gap 数学**只在 `gap.rs` 里有一份**——implant-win 只负责取字节，绝不重算。
- `.pdata` 是**已排序**的 `RUNTIME_FUNCTION_ENTRY` 数组（PE 规范保证），`gap::enumerate_gaps` 据此假设。
- `image_size` = 该 DLL 的 `SizeOfImage`（PE 头里）。
- 运行时解析偏移，**绝不硬编码**（跨 Win 版本会变）。

---

## 5. 接下来的开发顺序（P2.1，地基→分支）

依 `p2_research_synthesis.md` §四 的最终 build 顺序：

| 步 | 模块 | 依赖 | 验证靶机 | 状态 (2026-06-24) |
|---|---|---|---|---|
| **P2.1a-i** | `PdataGapScanner` 真实 impl（本文 §4） | `gap.rs` ✅ | gap_count>0 | ✅ 完成 (evasion_glue.rs, gap_scan selftest) |
| P2.1a-ii | `StackSpoofKit::ByoudGap`（用 `frame.rs`+`GapPool`，接 `syscalls.rs::trampoline_for`） | i | 自建 xacone-style VEH 检测器；ETW-Ti STACKWALK 无告警 | 🔶 swap 决策完成 (swap.rs 5测), RSP asm 执行待真机 |
| P2.1b | `BlindKit::NtTraceEventBytePatch`（`blind.rs` 升级：`EtwEventWrite`→`NtTraceEvent` byte0→0xC3） | — | `logman`+`tracerpt` provider 沉默 | ✅ 完成 (NtTraceEvent + provider-disable 双保险) |
| P2.1a-iii | `SleepmaskKit::Foliage`/`InsomniacUnwinding`（`rc4.rs`+APC→NtContinue 链，集成 ii 的 spoof） | ii | HSB/Moneta/PE-sieve/BeaconEye 零命中 | 🔶 状态机完成 (foliage.rs 5测), 同步骨架完成, APC 异步链待真机 |
| P2.1c | `ProcessInjectKit::ModuleStomping` | — | Moneta exec-private / PE-sieve unbacked 通过 | 🔶 stomp 骨架完成 (gated), threadless 待定 |

**验证工具需在本机备好**：Hunt-Sleeping-Beacons、Moneta、PE-sieve、BeaconEye、MalMemDetect、
Defender 实时扫描（本机已装 Defender）。检测器参考：StackSentry、Sleep-Duck-Eye（见 H2 sweep §D）。

---

## 6. 重要约束速查（摘自 CLAUDE.md）

- **不要把 implant-win 加进主 workspace**（它自带空 `[workspace]`，否则 `cargo build --workspace` 会尝试
  编译 no_std PIC 而炸）。单独用 `--manifest-path` 操作。
- **wire 协议是 hand-rolled LE 二进制，不是 protobuf**——别"修"成 protobuf。
- **tag 字节稳定**（`Command` 各 variant 的 u8 tag），追加新 tag 不重排。
- **server keypair 每次启动 ephemeral**——重启后 live session 不存活（P0 已知限制）。
- `agent-dev` 是 std 开发 implant（验证回路用），**不是**生产 implant；生产是 `implant-win`。
- `[profile.release]`（opt-level=z、lto、panic=abort、strip）workspace 级，为 implant 瘦身，也影响 server/cli。

---

## 7. SSH / 同步

- 本机别名：`ssh win` 或 `ssh server`（同一台）。免密已配（ed25519 → `administrators_authorized_keys`）。
- 从 macOS 推更新：`tar czf - -C /Users/qiaozhiyi/Desktop --exclude='*/target' --exclude=.agents pentest | ssh win "tar xzf - -C C:/Users/administrator/nyx"`（会覆盖）。
- 反向拉：`ssh win "tar czf - -C C:/Users/administrator/nyx --exclude='*/target' pentest" | tar xzf - -C /Users/qiaozhiyi/Desktop/`
