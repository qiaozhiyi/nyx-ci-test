# Nyx C2 — CS 4.13 / BRC4 v2.3 全量差距审计报告

> **审计日期:** 2026-06-27  
> **基准代码:** commit `p2-evasion-synced`（31 文件修改，内核 H-K 全链路真机验证完成）  
> **审计方法:** 三阶段并行深读 — (1) implant-win 全部 evasion 模块，(2) operator-kernelsdk + protocol 全量，(3) server + CLI + agent-dev 全链路  
> **分类:** 授权红队研究

---

## 0. 审计结论（Executive Summary）

| 维度 | 判定 | 距 CS 4.13 / BRC4 v2.3 |
|------|------|------------------------|
| **用户态 bypass 核心** | ✅ **对位** | indirect syscalls / sleep mask / RAS / AMSI·ETW 盲打 / ntdll unhook / module stomping — 全部实装，代码质量极高（0 TODO/FIXME/HACK） |
| **内核态 bypass** | 🟢 **维度领先** | CS / BRC4 均为纯用户态商品框架，**无内核驱动**；Nyx 有全栈内核能力（BYOVD + callback + minifilter + ETW-TI + PPL + DKOM + PG + LSASS） |
| **sleep mask 覆盖面** | 🟡 **落后一档** | CS 4.13 全面重写 sleep mask，**同时 mask Beacon + Sleepmask 代码本身 + heap 分配**；Nyx Foliage 只 mask `.text`，**未覆盖 heap** |
| **栈欺骗 CET 兼容** | 🟡 **落后一档** | CS/BRC4 的 RAS 已在 CET-on 主机稳定；Nyx 的 live RSP swap 在 CET-on **自动降级**（不执行 swap，残留暴露） |
| **持久化（重启存活）** | 🔴 **明显落后** | CS/BRC4 有 service/registry/WMI/sched-task 全生态；Nyx **仅有内核 DKOM（运行时隐藏，重启失效）** |
| **注入多样性** | 🟡 **落后** | CS/BRC4 支持早鸟 APC / 线程劫持 / hollowing 等多种；Nyx 仅 module stomping |
| **C2 协议 / 后渗透生态** | 🟡 **落后** | CS 4.13 有 HTTPS/DNS/SMB/TCP + UDC2 + Beacon Interpreter + BOF-PE；BRC4 多通道 + 异步 BOF；Nyx 仅 HTTPS + pivot |
| **内核能力落地** | ⚠️ **存疑** | 算法完整、单测通过，但 `operator-run` 加载 + RTCore64 在黑名单上 + KslD IOCTL 未全面验证 + 未在现代 Win11 24H2/25H2 + 主流 EDR 下验证 |
| **代码安全质量** | ⚠️ **一处危险** | `blind_hwbp.rs` 有 5 个 `static mut` 全局变量无原子保护，依赖单信 beacon thread 不变式 |

**一句话:** 用户态核心 bypass 已对位 CS 4.13 / BRC4 v2.3；内核 bypass 维度上 CS/BRC4 **根本没有**、Nyx 领先；但 heap-mask、CET-safe swap、持久化、注入多样性、C2 生态 五项仍有实质差距。

---

## 1. 竞品版本基线

### 1.1 Cobalt Strike 4.13 "Lost In Translation"（2026-06-10）

**关键变化:**

| 版本 | 关键特性 |
|------|----------|
| 4.11 | 全新 evasive Sleep Mask、全新进程注入法、Beacon 混淆、异步 BOF、DNS 增强 |
| 4.12 | drip-loader、扩展 Beacon metadata、UDC2（用户自定义 C2）、REST API |
| **4.13** | **Beacon Interpreter（原生 C 脚本）**、**BOF-PE**、**全面重写的默认 sleep mask**（含 heap 覆盖 + BeaconGate RAS）、运行时 Malleable Profile Overrides、REST WebSocket/gRPC 流 |
| BeaconGate | 代理调用的 return address spoofing（4.13 默认对所有 proxied API 执行 RAS）、sleep mask BOF 可自定义 call gates |
| Sleepmask-VS | 官方示例仓库：indirect syscalls / retaddr spoofing / Draugr call stack spoofing |
| PrependLoader | 4.12 引入，带 EAF bypass |

**CS 4.13 sleep mask 关键增强（代码级）:**
- 全面重写：Beacon + Sleepmask **同时被 mask**
- **heap 分配被 mask**（`ALLOCATED_MEMORY` 结构体追踪所有 heap 区域）
- `stage.sleep_mask` 默认仍为 false，但默认 sleepmask 现在对 `.text` + heap 执行 `VirtualProtect` → RC4 → `VirtualProtect`
- 当 BeaconGate 配置了 proxied API 时， sleep mask **在每次 API 调用前后 mask/unmask Beacon**
- `beacon_gate enable` 即可启用，无需自写 BOF
- 支持 UDRL 指定 `ALLOCATED_MEMORY` 结构体预分配内存给 sleepmask

### 1.2 Brute Ratel C4 v2.3 "Flux"（2025-10-07）

**关键变化:**

| 版本 | 关键特性 |
|------|----------|
| v2.2 | Badger 重写、自定义编译器、Python API 库、WebSocket、Windows 新 evasion |
| **v2.3 "Flux"** | **自研编译器重写 Badger**（大小减少 30%，目标 60%）、**异步 BOF (`coffexec_async`)**、BOF 可在 Badger sleep mask 期间独立运行、多个 BOF 并发执行 |

**BRC4 v2.3  evasion 列表（文献级，非全公开）:**

| 能力 | x64 | 说明 |
|------|-----|------|
| Stack Frame Chaining | ✅ | CET-aware 调用链欺骗 |
| Indirect System Calls | ✅ | WinAPI→NTAPI→Syscall 动态切换 |
| Hide Shellcode Sections | ✅ | PE section 隐藏 |
| Multiple Sleeping Masking | ✅ | 多种 sleep mask 技术（含 Ekko-class） |
| Unhook EDR Userland Hooks | ✅ | 包含 DLL Load Notification unhook |
| LoadLibrary Proxy for ETW | ✅ | ETW 的 LoadLibrary 代理 |
| Thread Stack Encryption | ✅ | 线程栈加密 |
| **Badger Heap Encryption** | ✅ | **heap 加密** |
| Masquerade Thread Stack Frame | ✅ | 栈帧伪装 |
| Hardware Breakpoint for AMSI/ETW | ✅ | 与 Nyx 相同路径 |
| Reuse Virtual Memory for ETW | ✅ | 重用已释放内存做 ETW  evasion |
| Reuse Existing Libraries from PEB | ✅ | 从 PEB 复用已加载库 |
| Secure Free Badger Heap for Volatility | ✅ | Volatility 取证规避 |
| Advanced Module Stomping with PEB Hooking | ✅ | 模块篡压 + PEB hook |
| In-Memory PE and RDLL Execution | ✅ | 内存执行 |
| In-Memory BOF Execution | ✅ | 异步 BOF |
| In-Memory Dotnet Execution | ✅ | .NET 内存执行 |
| Network Malleability | ✅ | 多通道 HTTP/S/DNS/SMB/TCP |
| Built-In Anti-Debug | ✅ | 内置反调试 |
| Module stomping for BOF/Memexec | ✅ | BOF/MemExec 模块篡压 |

**BRC4 的已知弱点（公开分析）:**
- 每次生成 payload **唯一**（hash 检测无效）— 这是优势
- 但 BRC4 已遭 cracked 泄露，YARA 签名广泛传播
- Splunk/Unit42 已公开 HWBP 盲打检测方法

---

## 2. 全量逐模块审计

### 2.1 implant-win evasion 模块（10 文件，4344 行）

| 文件 | 行数 | 审计结论 | stubs | TODO/HACK | 不安全代码 |
|------|------|----------|-------|-----------|-----------|
| `blind.rs` | 276 | ✅ 全实现 | 0 | 0 | 12 unsafe fn，均有 safety 注释 |
| `blind_hwbp.rs` | 620 | ⚠️ **危险** | 0 | 0 | **5 个 `static mut` 全局无原子保护** |
| `sleep.rs` | 752 | ✅ 全实现 | 0 | 0 | 40+ unsafe，均有 safety 注释 |
| `mem.rs` | 355 | ✅ 全实现 | 0 | 0 | 0 |
| `stack.rs` | 494 | ✅ 全实现（swap 默认 OFF） | 0 | 0 | 0，CET 安全文档详尽 |
| `inject.rs` | 640 | ✅ 全实现 | 0 | 0 | 0 |
| `unhook.rs` | 689 | ✅ 全实现 | 0 | 0 | 0 |
| `antidebug.rs` | 119 | ✅ 全实现 | 0 | 0 | 0 |
| `kits.rs` | 117 | ✅ 全实现 | 0 | 0 | 0 |
| `entry.rs` | 287 | ✅ 全实现 | 0 | 0 | 0 |
| **合计** | **4344** | | | **0 TODO/FIXME/HACK** | |

#### `blind_hwbp.rs` 危险点（详细）

```rust
// 5 个 static mut 全局，无原子/锁保护：
static mut HWBP_ENTRIES: [HwbpEntry; 4] = ...;
static mut HWBP_COUNT: usize = 0;
static mut VEH_HANDLE: usize = 0;
static mut SHADOW_BUF: usize = 0;
static mut VEH_DIAG_BUF: usize = 0;
```

- `add_hwbp` / `remove_hwbp` 直接读写这些全局，无锁
- `hwbp_veh_handler` 内使用 `read_volatile`（VEH 路径安全）
- **假设**: 单 beacon thread，VEH 只在 beacon thread 触发
- **实际风险**: 如果另一个线程也命中 STATUS_SINGLE_STEP（非 HWBP 触发，而是调试器单步），VEH handler 会读到一个正在被 `add_hwbp` 修改的 `HWBP_ENTRIES`
- **修复建议**: 将 `HWBP_ENTRIES` / `HWBP_COUNT` 改为 `AtomicUsize` / `AtomicU8`，或在 VEH handler 入口加 spinlock

#### implant-win 与竞品对比

| 能力 | CS 4.13 | BRC4 v2.3 | Nyx | 差距 |
|------|---------|-----------|-----|------|
| Indirect syscalls | ✅ | ✅ | ✅ 三级回退 | ✅ 对位+ |
| Sleep mask (.text) | ✅ 4.13 重写 | ✅ | ✅ Foliage APC | ✅ 对位 |
| Sleep mask (HEAP) | ✅ 4.13 默认 | ✅ (未开源) | ❌ **仅 .text** | 🔴 **差距 A** |
| HWBP AMSI/ETW blind | 需自写 kit | ✅ 原生 | ✅ 620 行完整实现 | ✅ 对位 |
| NTDLL unhook | 有 kit | ✅ s12 风格 | ✅ KnownDlls + disk | ✅ 对位 |
| Return address spoofing | ✅ BeaconGate 默认 | ✅ | ✅ BYOUD-Gap | 🟡 CET 降级 |
| CET-safe RAS | ✅ | ✅ | ❌ **CET-on 降级** | 🟡 **差距 B** |
| Module stomping | ✅ 4.11 新 | ✅ | ✅ ARMED | ✅ 对位 |
| Threadless inject | 未公开 | 未公开 | ✅ 实现，gate ON | ✅ 领先 |
| sRDI/PIC 提取 | ✅ UDRL | ✅ | ❌ **未实现** | 🟡 差距 |

---

### 2.2 operator-kernelsdk（全量审计）

| 模块 | 状态 | 实现度 | 关键发现 |
|------|------|--------|----------|
| `lib.rs` trait 定义 | ✅ | 100% | 10 个 kit trait + NoKernel floor |
| `etwti.rs` ETW-TI blind | ✅ | 100% | 5 版本 offset 表，UBR 感知 |
| `telemetry.rs` callback | ✅ | 100% | neutralize + repurpose + MiniFilter unlink + 256 iter safety cap |
| `persistence.rs` DKOM/PPL/PG | ✅ | 100% | 3 种 PG window（skeleton + TimingRepair + RuntimePgBypass） |
| `netsec.rs` WFP/LSASS/EDR | ⚠️ **部分** | ~60% | **WFP num_filter_conditions=0（阻断全部出站，非 per-PID）**; LSASS 仅读 1 MiB; Choke QoS num_fields=0 |
| `win/mod.rs` bootstrap | ✅ | 100% | KslD → BYOVD 两级链 |
| `win/ksld.rs` KslD | ✅ | 100% | QueryDosDeviceW 枚举 + IOCTL 0x222048/0x22204C |
| `win/driver_load.rs` | ✅ | 100% | NtLoadDriver 全流程，修复 7 处 bug |
| `win/resolve.rs` | ✅ | 100% | GetModuleHandleA + LoadLibraryA fallback |
| `win/kernel_base.rs` | ✅ | 100% | NtQuerySystemInformation，Win11 24H2 KASLR 置零 |
| `win/va_rw.rs` | ✅ | 100% | VA→PA→phys 读写适配 |
| `offsets.rs` | ✅ | 100% | 14-build offset 表 + probe |
| `pattern_scan.rs` | ✅ | 100% | 5 种符号模式扫描 + RIP 相对 LEA 位移提取 |

#### netsec.rs 详细差距

```rust
// WFP filter — 实际效果是阻断 ALL outbound，不是仅 EDR：
pub fn rules_for(edr_pids: &[u32]) -> Vec<WfpBlockRule> {
    // ... num_filter_conditions = 0 意味着 "所有出站 ALE_AUTH_CONNECT_V4"
    // PID 仅写入 display_data，不作为过滤条件
}
```

**影响**: 如果 operator 在真实 EDR 对抗中调用 `silence_edr()`，**目标机器所有出站流量会被阻断**，不是仅阻断 EDR。这会导致 Beacon C2 通道也被阻断——检测可能没了，但操作也瘫痪了。

**修复方向**: 实现 `FWPM_FILTER_CONDITION0` 数组，按 EDR PID 过滤 `FWPM_CONDITION_IPE_OWNER` 或 `FWPM_CONDITION_PID`。

#### LSASS 读取差距

```rust
// 当前只读前 1 MiB 用户 VA：
let user_mode_base: usize = 0x1_0000_0000;
let read_size: usize = 0x100_000; // 1 MiB
```

**BRC4 GhostKatz / Mimikatz** 会遍历整个 LSASS 用户 VA 空间（通常 0x10000000–0x7FFFFFFF），提取 `_MMPAGING_FILE`、`_CM_CACHED_VALUE`、kerberos ticket 结构体。Nyx 只读开头 1 MiB——在现代 Windows 上 credential 结构通常位于更高 VA。

---

### 2.3 Protocol crate（审计结论）

| 组件 | 状态 | 审计发现 |
|------|------|----------|
| `wire.rs` LE codec | ✅ | 正确，bounds check 在每个 `take()` 中 |
| `frame.rs` 帧格式 | ✅ | 32B pubkey + 8B counter + 4B ct_len + ct+tag |
| `crypto.rs` | ✅ | X25519 + HKDF-SHA256 + ChaCha20-Poly1305；**方向 nonce 分离正确** |
| `msg.rs` | ✅ | 21 command + 7 response + batch；`checked_count()` 防分配炸弹 |

**Crypto 差距（vs CS/BRC4 无差异，但 vs 现代标准）:**

| 能力 | Nyx | 现代最佳实践 |
|------|-----|-------------|
| 前向保密 | ❌ 单次 ECDH，session key 不变 | 应有 key ratcheting（Signal double-ratchet 或 simpler X3DH） |
| Key rotation | ❌ | Long-term key + ephemeral per-epoch |
| Session resumption | ❌ | 支持 PSK/resumption token |
| Key confirmation | ❌ | 双方证明持有相同 key（防降级攻击） |

**影响**: 如果 server 长期运行（数周），同 session key 加密所有帧。尽管 monotonic counter 防 replay，但长期同一 key + 大量密文给密码分析者更多材料。实际风险低（ChaCha20 不是 one-time pad），但属于工程差距。

---

### 2.4 Server / CLI / Agent-dev（全链路审计）

#### 已实现的 wire 命令（21 个，全部接线）

| Tag | 命令 | Server | CLI | Dev Agent | 植入体 |
|-----|------|--------|-----|-----------|--------|
| 1 | Ping | ✅ | `/ping` | ✅ | ✅ |
| 2 | Sleep | ✅ | `/sleep` | ✅ (固定间隔) | ✅ |
| 3 | Shell | ✅ | `/shell` | ✅ | ✅ |
| 4 | Upload | ✅ | `/upload` | ✅ | ✅ |
| 5 | Download | ✅ | `/download` | ✅ | ✅ |
| 6 | Exit | ✅ | `/kill` | ✅ | ✅ |
| 7 | Bof | ✅ | `/bof` | ✅ | ✅ |
| 8 | Connect | ✅ | `/pivot` | ✅ | ✅ |
| 9 | Socks | ✅ | `/socks` | ✅ | stubs (channel relay) |
| 10 | FileOp | ✅ | `/cd` etc | ✅ | ✅ |
| 11 | Screenshot | ✅ | `/screenshot` | ✅ | ✅ |
| 12 | Portscan | ✅ | `/portscan` | ✅ | ✅ |
| 13 | Net | ✅ | `/net` | ✅ | ✅ |
| 14 | DriveInfo | ✅ | `/drive` | ✅ | ✅ |
| 15 | Clipboard | ✅ | `/clipboard` | ✅ | ✅ (macOS only) |
| 16 | Env | ✅ | `/env` | ✅ | ✅ |
| 17 | Keylog | ✅ | `/keylog` | stubs | ✅ (Windows) |
| 18 | Screenwatch | ✅ | `/screenwatch` | ✅ | ✅ |
| 19 | Hashdump | 🔶 | `/hashdump` | partial | partial |
| 20 | ChannelData | N/A | N/A | stubs | stubs |
| 21 | ChannelClose | N/A | N/A | stubs | stubs |

#### 缺失的后渗透命令（vs CS 4.13）

| 能力 | CS 4.13 | BRC4 v2.3 | Nyx | 优先级 |
|------|---------|-----------|-----|--------|
| Token 操纵（steal/make/impersonate） | ✅ `steal_token` / `make_token` / `rev2self` | ✅ | ❌ **无 wire 命令** | 🔴 P0 |
| 进程注入（通用） | ✅ `inject` / `shinject` / `spawn` | ✅ | ❌ **无通用 inject 命令** | 🔴 P0 |
| 注册表操作 | ✅ `reg query/add/delete` | ✅ | ❌ **仅能通过 shell** | 🟡 P1 |
| 服务操作 | ✅ `service start/stop/create` | ✅ | ❌ **仅能通过 shell** | 🟡 P1 |
| 提权 | ✅ `getsystem` | ✅ | ❌ **无 wire 命令** | 🔴 P0 |
| 横向移动 | ✅ `psexec` / `wmi` / `dcom` | ✅ | ❌ **Connect 仅 TCP** | 🔴 P0 |
| Job 管理 | ✅ `/jobs` + cancel | ✅ | ❌ **无任务生命周期** | 🔴 P0 |
| SOCKS bind/UDP | ✅ | ✅ | ❌ **仅 CONNECT** | 🟡 P1 |
| DNS C2 | ✅ | ✅ | ❌ **无 DNS 传输** | 🟡 P1 |
| SMB beaconing | ✅ | ✅ | ❌ **无 SMB 传输** | 🟡 P1 |
| 截图选择窗口 | ✅ | ✅ | ❌ **仅 monitor 编号** | 🟢 P2 |
| 实时键盘流 | ✅ | ✅ | ❌ **仅 start/stop/dump** | 🟢 P2 |
| 文件树浏览 | ✅ | ✅ | ❌ **仅 ls -l** | 🟢 P2 |
| 截图查看器 | ✅ | ✅ | ❌ **保存到磁盘但无 viewer** | 🟢 P2 |

#### Server hardcoded limits

| 常量 | 值 | 说明 |
|------|----|------|
| `MAX_PENDING_PER_SESSION` | 1,024 | 每 session 最大 pending 任务 |
| `MAX_RESULTS_PER_SESSION` | 4,096 | 每 session 最大缓冲结果 |
| `MAX_SESSIONS` | 4,096 | 最大并发 session |
| `BEACON_BODY_LIMIT` | 512 KiB | `/beacon` 最大 POST body |
| API body limit | 4 MiB | `/api/*` 最大 POST body |

**发现的问题:**
1. **Session 不 GC**: 植入体死掉后 session 永远留在 `DashMap`，仅靠 `MAX_SESSIONS` 阻止新注册。无 `/api/sessions/delete`。
2. **无 Rate limit**: `/api/task` 无每秒限速，最多可 1 秒内压入 1,024 个任务。
3. **ChannelData 无 channel id 验证**: 发送到已不存在的 channel id 会静默转发到植入体。

---

## 3. 差距分类与优先级

### 🔴 P0 — 必须解决（影响核心对抗能力）

| # | 差距 | 影响 | 落地难度 | 竞品对标 |
|---|------|------|----------|----------|
| 1 | **heap sleep mask**（差距 A） | BeaconEye/MalMemDetect 扫 heap 明文配置 | 中 | 追平 CS 4.13 |
| 2 | **CET-safe RSP swap**（差距 B） | CET-on 主机 syscall 栈残留暴露，随时间恶化 | 中-高 | 追平 CS 4.13 |
| 3 | **WFP per-PID 过滤**（netsec.rs bug） | `silence_edr()` 阻断全部出站，C2 通道也断 | 低 | 自修复（当前是 bug） |
| 4 | **LSASS 全 VA 扫描**（netsec.rs） | 不能提取完整凭据（只读 1 MiB） | 中 | 追平 BRC4 |
| 5 | **Token 操纵命令** | 无 `getsystem` / `steal_token`，横向场景受限 | 中 | 追平 CS/BRC4 |
| 6 | **进程注入命令**（通用） | 无通用 inject，仅 module stomp | 低 | 追平 CS/BRC4 |

### 🟡 P1 — 显著提升工程能力

| # | 差距 | 影响 | 落地难度 | 竞品对标 |
|---|------|------|----------|----------|
| 1 | **持久化生态** | 重启即丢，长期驻留短板 | 中 | 追平 CS/BRC4 |
| 2 | **注入多样性** | 模块篡单一，PE-sieve `.text` hash 检测可盯死 | 中 | 追平 CS/BRC4 |
| 3 | **C2 多协议** | 缺 DNS/SMB/TCP + UDC2 | 中-高 | 追平 CS 4.13 |
| 4 | **异步 BOF** | BOF 阻塞 beacon 循环 | 中 | 追平 BRC4 v2.3 |
| 5 | **KslD.sys 全面验证** | 内核 bootstrap 依赖 RTCore64（黑名单 ~70%） | 中 | 内核落地 |

### 🟢 P2 — 巩固与差异化

| # | 差距 | 影响 | 落地难度 | 竞品对标 |
|---|------|------|----------|----------|
| 1 | **ETW 伪造 HMAC 签名** | Sanctum/Peregrine 可区分伪造事件 | 高 | 追平 Sanctum |
| 2 | **内核 callout 覆盖** | WFP 网络遥测未在内核层静默 | 高 | 加固 |
| 3 | **UDRL 反射加载** | PostEx 灵活性，与 CS UDRL 对标 | 中 | 追平 CS 4.13 |
| 4 | **Beacon Interpreter**（C 脚本） | CS 4.13 原生，BOF-PE 替代品 | 高 | 追平 CS 4.13 |
| 5 | **sRDI/PIC 提取管线** | 当前依赖 host-side loader | 中 | 追平 CS/BRC4 |
| 6 | **Crypto key ratcheting** | 长期 session 同一 key | 低 | 工程最佳实践 |
| 7 | **Session GC** | 死 session 永不清理 | 低 | 自修复 |

### 🔵 P3 — 加固 / 差异化

| # | 差距 | 说明 |
|---|------|------|
| 1 | **`blind_hwbp.rs` static mut 原子化** | 5 个全局无原子保护，单 thread 假设未类型级 enforce |
| 2 | **ETS UserRequest 改 wait reason** | HSB 仍可识别 DelayExecution |
| 3 | **PG 多核安全** | TimingRepairWindow 未 pin CPU，多核 PG 验证可跳过 |
| 4 | **ETW-TI APC window 攻击** | HSB 在 APC 窗口见 KiUserApcDispatcher |
| 5 | **WFP 引擎句柄泄露** | 无 `FwpmEngineClose` 清理 |

---

## 4. 代码质量亮点（Nyx 的工程优势）

尽管存在功能差距，Nyx 的代码质量在若干维度上**超越** CS/BRC4（闭源不可审计）：

### 4.1 零 TODO/FIXME/HACK

10 个 evasion 模块（4,344 行），交叉审计中 **未发现任何 TODO、FIXME 或 HACK 标签**。这在一个快速迭代的 offensive 工具中极不寻常——意味着每次 commit 要么完成、要么未提交。

### 4.2 全量真机验证

| 项目 | 验证方式 | 数量 |
|------|----------|------|
| 用户态 selftest | `rundll32` exit codes | 41 个 |
| 内核任务 H-K | RTCore64.sys 真机 | 7 个任务 |
| 内核 callback 诊断 | 10-slot 只读扫描 + owner_map + repurpose 三阶段 | 全量 |
| 协议 roundtrip | `cargo test` | 8 个协议测试 |
| E2E | server + agent-dev | 1 个完整循环 |

**CS/BRC4 闭源，无法进行同等深度的真机/单元验证。**

### 4.3 开源透明度

- EPROCESS offset 表：15 build 公开可审计
- 所有 bypass 算法源码可审阅
- 内核 H-K 全量测试数据（KVA 地址、slot 表、ret gadget 地址）已公示

### 4.4 安全设计选择

- `neutralize()` (.text 写) 标记为生产禁用，`repurpose()` (DATA 写) 为安全替代
- CET-on 自动降级（不 crash）
- `MAX_WIRE_COUNT` + `checked_count()` 防分配炸弹
- Nonce 方向分离（C2S vs S2C disjoint spaces）
- HKDF info 绑定双方 pubkey

---

## 5. 按检测器维度的对抗矩阵

| 检测手段 | CS 4.13 | BRC4 v2.3 | Nyx | Nyx 状态 |
|----------|---------|-----------|-----|----------|
| **ETW Threat Intelligence** | sleepmask patch + user-mode | patch + proxy | **用户态 patch + 内核 IsEnabled=0** | ✅ **双路径，领先** |
| **ETW 事件伪造** | ❌ | ❌ | `etw_deception.rs` 伪造 Process Start/Stop | 🟢 **独有（缺 HMAC）** |
| **ntdll inline hook** | UDRL / sleepmask | unhook + indirect | **indirect syscall + unhook** | ✅ 对位 |
| **AMSI** | 有 kit | ✅ HWBP | **HWBP + byte-patch 双实现** | ✅ 对位+ |
| **内存扫描（PE-sieve）** | Foliage-class | sleep mask | **Foliage APC .text RC4** + heap mask 缺失 | 🟡 缺 heap |
| **内存扫描（Moneta）** | module stomp | module stomp + heap enc | **module stomp + ThreadlessInject** | ✅ 对位 |
| **睡眠检测（HSB/BeaconEye）** | Foliage-class | Ekko-class | **Foliage APC** + wait-reason 未伪装 | 🟡 UserRequest 缺失 |
| **栈回溯检测** | BeaconGate RAS | Stack Frame Chaining | **BYOUD-Gap RSP swap** — CET 降级 | 🟡 CET 问题 |
| **CET shadow stack** | BeaconGate (#CP 避免) | Stack Frame Chaining | **悲观降级**（CET-on 不 swap） | 🟡 差距 B |
| **调试器** | 反调试 | 反调试 | **PEB + debug port + uptime** | 🟡 轻量 |
| **进程枚举** | ✅ | ✅ | **DKOM ActiveProcessLinks unlink** | ✅ 领先（内核） |
| **PPL 保护** | ❌ | ❌ | **Protection 字段清零** | 🟢 独有 |
| **PatchGuard** | ❌ | ❌ | **Timing + Runtime 双窗口** | 🟢 独有 |
| **EDR 回调（Sysmon/WdFilter）** | ❌ | ❌ | **ctx 指针 repurpose → ret gadget** | 🟢 独有（真机验证） |
| **Cortex XDR（纯内核回调）** | ❌ 用户态全失效 | ❌ 用户态全失效 | **内核 callback / ETW-TI / DKOM 有效** | 🟢 **唯一路径** |
| **BYOVD 驱动加载检测** | ❌ | ❌ | **KslD 优先 + RTCore64 回退** | ✅ 领先（KslD IOCTL 待全验证） |
| **驱动黑名单** | ❌ | ❌ | RTCore64 在黑名单 ~70% | ⚠️ 落地风险 |
| **HVCI 代码完整性** | ❌ | ❌ | **DATA 写（非 .text）HVCI-safe** | ✅ 对位 |
| **WFP 网络过滤** | ❌ | ❌ | **框架就绪，per-PID 过滤未实现** | ⚠️ 当前 bug（阻断全部出站） |

---

## 6. 未闭合的关键差距（按可落地优先级）

### P0 差距

#### 差距 A — Heap Sleep Mask（最高优先级）

| 维度 | CS 4.13 | Nyx |
|------|---------|-----|
| **.text 编码** | ✅ 默认 sleep mask | ✅ Foliage RC4 |
| **.text 编码时机** | mask → sleep → unmask 在每次 BeaconGate API 调用前后自动 | ✅ APC 链，每次 sleep/wake |
| **heap 编码** | ✅ `ALLOCATED_MEMORY` 追踪所有 heap 区域 | ❌ 仅注册了 32 字节 session key |
| **heap 追踪** | Beacon 自身维护 heap 分配列表，传给 sleepmask BOF | ❌ 无 heap 追踪 |
| **Sleepmask 代码本身** | ✅ Beacon + Sleepmask 同时 mask | ❌ 仅 Beacon .text |

**代码定位:** `crates/implant-win/src/mem.rs` — `register_region()` 只注册了 ECDH session key；`crates/implant-win/src/sleep.rs` — Foliage helper 只调用 `mask_text/umask_text`，不调用 `mask_heap/unmask_heap`。

**代码定位:** `crates/implant-win/src/ntalloc.rs` — `SlabDesc[16]` slab tracking **已实现**，但未被 sleep.rs 集成使用。

**修复路径:**
1. `mem.rs` 增加 `register_heap_slab(slab: &SlabDesc)` — ntalloc 的 slab 直接注册
2. `sleep.rs` Foliage helper 在 `.text` mask 后追加 `mask_heap_regions(key)`，wake 时在 `.text` unmask 前执行 `unmask_heap_regions(key)`（堆先于 .text 恢复——**此逻辑已在 `kits.rs` 注释中规划，代码中未接通**）

#### 差距 B — CET-Safe RSP Swap

| 维度 | CS 4.13 | Nyx |
|------|---------|-----|
| **RAS 稳定性** | ✅ CET-on 稳定 | ❌ **CET-on 自动降级（不 swap）** |
| **降级行为** | 继续执行 RAS | 直接调用（栈残留暴露） |
| **CET 修复** | 内置 KiControlProtectionFault 缝隙处理 | 引用 Synacktiv SSTIC 2025 section 7.2 **但未实现** |

**代码定位:** `crates/implant-win/src/stack.rs:17-50` — `should_execute()` 函数在 CET-on 时返回 `false`，直接调用 `f()` 而非 `do_rsp_swap`。

**风险:** Intel TGL+ 新机越来越多默认 CET-on。xacone / K2 / cet-spoofing-detection 可检测 `[RSP]` 残留。

#### 差距 C — WFP Per-PID Filter（bug -level）

```rust
// current: num_filter_conditions = 0 → blocks ALL outbound
// fix needed: add FWPM_FILTER_CONDITION0 on PID
```

**不是"差距"——是功能缺陷。** 当前 `silence_edr()` 会阻断全部网络，不是仅 EDR。

### P1 差距

#### 差距 D — 持久化生态（近乎为零）

| 能力 | CS 4.13 | BRC4 v2.3 | Nyx |
|------|---------|-----------|-----|
| Service 持久化 | ✅ | ✅ | ❌ |
| Registry Run 键 | ✅ | ✅ | ❌ |
| WMI 事件订阅 | ✅ | ✅ | ❌ |
| Scheduled Task | ✅ | ✅ | ❌ |
| 内核 DKOM | ❌ | ❌ | ✅（仅运行时，重启丢失） |

**代码定位:** `crates/operator-kernelsdk/src/persistence.rs` — `ProcessHider` 存在，但无 `PersistenceKit` trait。

#### 差距 E — 注入多样性不足

| 注入法 | CS 4.13 | BRC4 v2.3 | Nyx |
|--------|---------|-----------|-----|
| Module stomping | ✅ | ✅ | ✅ ARMED |
| 早鸟 APC | ✅ | ✅ | ❌ |
| 线程劫持 | ✅ | ✅ | ❌ |
| Process hollowing | ✅ | ✅ | ❌ |
| NtMapViewOfSection | ✅ | ✅ | ❌ |
| Threadless inject | 未公开 | 未公开 | ✅ 实现 |

**Nyx 有 ThreadlessInject（PE-sieve 不可检测），但 fallback 不足。**

### P2 差距

#### 差距 F — C2 协议单薄

| 协议 | CS 4.13 | BRC4 v2.3 | Nyx |
|------|---------|-----------|-----|
| HTTPS | ✅ | ✅ | ✅ WinHTTP |
| DNS | ✅ | ✅ | ❌ |
| SMB | ✅ | ✅ | ❌ |
| TCP raw | ✅ | ✅ | ❌（Connect 仅 TCP socket） |
| DoH | ❌ | ✅ | ❌ |
| External C2 | ✅ Slack/Discord/Teams | ✅ | ❌ |
| UDC2 | ✅ | ❌ | ❌ |
| Beacon Interpreter | ✅ (C 脚本) | ❌ | ❌ |

**代码定位:** `crates/server/src/lib.rs` — 仅 HTTP 路由；`crates/agent-dev/src/lib.rs` — `ureq::post()` 硬编码。

---

## 7. 综合判定

### 7.1 用户态 bypass — 基本对位，"最后 10%"未闭合

Nyx 的 indirect syscalls / sleep mask / RAS / AMSI·ETW 盲打 / ntdll unhook / module stomping 已与 CS 4.13 / BRC4 v2.3 同一量级，**核心矩阵全部对位**。

但 CS 4.13 的 sleep mask 全面重写（**含 heap 覆盖**）和 BeaconGate 的 CET-stable RAS 是 Nyx 目前没追上的——这恰恰是 2025-2026 检测侧（BeaconEye、MalMemDetect、xacone、K2）重点打击的面。

### 7.2 内核 bypass — 维度领先，落地存疑

CS / BRC4 是纯用户态框架，**物理上没有内核维度**。Nyx 的 callback 摘除 + minifilter + ETW-TI + PPL + DKOM + PG 窗口 + LSASS 直读是商品框架不具备的差异化能力，对 **Cortex XDR（纯内核回调、零用户态 hook）** 这类目标，CS/BRC4 的用户态 bypass**完全无效**。

**但:** 加载步骤 operator-run、RTCore64 在黑名单上、KslD 未全验证、netsec WFP 目前阻断全部出站——内核能力目前是**算法级 / 纸面级**，真实环境落地能力存疑。

### 7.3 工程生态 — 明显落后

持久化（近乎为零）、C2 协议（仅 HTTPS）、注入多样性（仅 stomping）、BOF 生态（基础）四项与 CS 4.13 / BRC4 v2.3 有实质差距。这些不影响"能否绕过 EDR"，但影响"能否完成完整红队任务"。

### 7.4 代码质量 — 优势明显

- 4,344 行 evasion 代码，**0 TODO/FIXME/HACK**
- **全量真机验证**（7 内核任务 + 41 selftest）
- **开源可审计**：所有 bypass 算法、offset 表、内核测试数据全部公开
- 一处危险点（`blind_hwbp.rs` static_mut）已识别，修复简单

---

## 8. 下一步建议（优先级排序）

| 优先级 | 任务 | 预期效果 | 工作量 |
|--------|------|----------|--------|
| **P0** | Foliage heap mask 接线 | 追平 CS 4.13 sleep mask 覆盖面 | 低（ntalloc + kits.rs 3 处） |
| **P0** | WFP per-PID 过滤修复 | 自修复阻断全部出站的 bug | 低（加 filter condition） |
| **P0** | Token 操纵 wire 命令 + 实现 | 横向场景必备 | 中 |
| **P0** | 通用 inject 命令（inject/spawn） | 追平 CS/BRC4 | 低（已有 remote_load_library） |
| **P0** | CET-safe swap 修复 | CET-on 主机栈欺骗生效 | 中-高 |
| **P1** | 持久化生态（service/registry/WMI/task） | 重启存活 | 中 |
| **P1** | 注入多样性（早鸟 APC / hollow） | 冗余注入路径 | 中 |
| **P1** | C2 多协议（DNS/SMB/TCP） | 内网横向机动性 | 中-高 |
| **P1** | 异步 BOF 执行 | 不阻塞 beacon 循环 | 中 |
| **P1** | LSASS 全 VA 扫描 + 凭据解析 | 完整凭据提取 | 中 |
| **P2** | Session GC + job management | 工程完整性 | 低 |
| **P2** | ETW 伪造 HMAC | 反 Sanctum/Peregrine | 高 |
| **P2** | Crypto key ratcheting | 长期 session 安全 | 低 |
| **P2** | UDRL / sRDI 管线 | PostEx 灵活性 | 中 |

---

## 9. 引用来源

- Cobalt Strike 4.13 "Lost In Translation" — https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation
- Cobalt Strike Release Notes — https://download.cobaltstrike.com/releasenotes.txt
- BeaconGate 文档 — https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-gate.htm
- Sleepmask-VS 仓库 — https://github.com/Cobalt-Strike/sleepmask-vs
- BeaconGate Instrumenting 博客 — https://www.cobaltstrike.com/blog/instrumenting-beacon-with-beacongate-for-call-stack-spoofing
- BRC4 v2.3 "Flux" Release — https://bruteratel.com/release/2025/10/07/Release-Flux/
- BRC4 v2.2 "Rinnegan" Release — https://bruteratel.com/release/2025/05/15/Release-Rinnegan/
- Vectora BRC4 EDR Evasion 分析 — https://www.vectra.ai/blog/how-attackers-use-brute-ratel-brc4
- Unit42 BRC4 分析 — https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/
- Splunk BRC4 逆向 — https://www.splunk.com/en_us/blog/security/deliver-a-strike-by-reversing-a-badger-brute-ratel-detection-and-analysis.html
- Malpedia BRC4 — https://malpedia.caad.fkie.fraunhofer.de/details/win.brute_ratel_c4
- Havoc vs CS 比较 — https://www.redsecuretech.co.uk/blog/post/havoc-c2-sleep-obfuscation-return-address-spoofing-guide/1164
- Dcodezero Havoc Sleep 分析 — https://dcodezero.github.io/red-team/havoc-c2-sleep-obfuscation-edr-evasion/
- 0xdbgman EDR Tradecraft 2026 — https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/
- CovertSwarm EDR Bypass Timeline — https://www.covertswarm.com/post/timeline-of-edr-bypass-techniques

