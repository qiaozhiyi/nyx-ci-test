# T-REX v2.0 · Nyx P8-P12 火线开发计划

> **制定日期:** 2026-07-07 · **情报基线:**  
> Meltloader (2026) — 内存反射加载 + 自毁 · Reflectra (2026) — 模块化 UDRL + 自清理  
> GhostLink (2026) — DNS/HTTPS/ICMP 多信道 · Dead Drop Resolver (MITRE T1102.001)  
> NTFS Anti-Forensics (2026) — USNJ/$LogFile/VSS 交叉检测 · Win11 24H2 Self-Delete (POSIX 修复)  
> NastyC2 (2026.06) — Rust 跨平台 · CS-EDR-Enumeration (2026) — 六级噪声分级

---

## 0. 核心理念变更

**T-REX v1.0（当前）:** 植入体内的探测器模块——随 beacon 运行，有落地痕迹。

**T-REX v2.0（目标）:** 独立的、一次性的、零痕迹侦察探针。

```
                         ┌─────────────────────────────────┐
                         │        T-REX Probe               │
                         │                                  │
                         │  Stage 0: PIC Shellcode (<1KB)   │
                         │  Stage 1: Reflective DLL (RX)    │
                         │                                  │
                         │  ┌─────────────────────────────┐ │
                         │  │  Module Plugins (RX pages)  │ │
                         │  │  T0: Process Scanner        │ │
                         │  │  T1: Registry Scanner       │ │
                         │  │  T2: WMI Scanner            │ │
                         │  │  T3: Service Scanner        │ │
                         │  │  T4: Kernel Scanner         │ │
                         │  │  T5: Callback Scanner       │ │
                         │  └─────────────────────────────┘ │
                         │                                  │
                         │  ┌─────────────────────────────┐ │
                         │  │  Exfiltration Engine         │ │
                         │  │  DNS TXT · HTTPS ·  DeadDrop │ │
                         │  └─────────────────────────────┘ │
                         │                                  │
                         │  ┌─────────────────────────────┐ │
                         │  │  Self-Destruct Sequence      │ │
                         │  │  1. Zero stack frames        │ │
                         │  │  2. Unmap all RX pages       │ │
                         │  │  3. VirtualFree MEM_RELEASE  │ │
                         │  │  4. Thread self-termination  │ │
                         │  │  5. Forensic artifact clean  │ │
                         │  └─────────────────────────────┘ │
                         └─────────────────────────────────┘

                         EXECUTION: fire-and-forget
                         RESULT: encrypted report → covert channel
                         AFTERMATH: zero memory + zero disk trace
```

---

## 第一阶段：P8 · T-REX 自毁侦察探针（8 周）

### P8a. 独立 Shellcode 入口 + 反射式 DLL 加载（2 周）

> **情报来源:** Meltloader (2026) — Go 反射加载器，NtAllocateVirtualMemory + NtProtectVirtualMemory，RC4 内存加密，PE 头后置零  
> Reflectra (2026) — 模块化 UDRL + Crystal Palace，支持执行后自清理

| 子任务 | 细节 | 交付物 |
|--------|------|--------|
| **P8a.1** | PIC Stage 0 — 微壳代码（<512 bytes）: 定位 kernel32 → 解析 `VirtualAlloc` + `LoadLibraryA` → 加载 Stage 1 | `trex/stage0.bin` |
| **P8a.2** | 反射式 DLL 加载器 — 手动 PE 解析 + 导入表重定位 + 基址重定位，全程无 `LoadLibraryA` | `trex/reflective_loader.rs` |
| **P8a.3** | RC4 内存加密 — Stage 1 DLL 在内存中加密存储，执行前 `SystemFunction032` 解密 | `trex/crypto.rs` |
| **P8a.4** | PE 头清零 — 加载完成后 `RtlZeroMemory(module_base, 0x1000)`，消除 PE-sieve `.text` hash | `trex/stealth.rs` |
| **P8a.5** | 模块基址伪装 — 通过 `NtMapViewOfSection` 从 `\KnownDlls\ntdll.dll` 映射合法页到 implant 内存区域，覆盖 VAD 特征 | `trex/vad_spoof.rs` |

**验收:** 注入 `rundll32.exe` → T-REX 完整运行 → 进程内存无异常（`malfind` / `hollowfind` 零告警）。

### P8b. 模块化探测插件系统（2 周）

> **情报来源:** CS-EDR-Enumeration (2026) — 六级噪声分级命令体系  
> S12 BYOVD Recon (2026.04) — 内核回调枚举 + Code Integrity 检测

| 子任务 | 细节 | 交付物 |
|--------|------|--------|
| **P8b.1** | `ProbeModule` trait — `fn noise_level() -> u8`, `fn requires_elevation() -> bool`, `fn execute() -> ProbeResult` | `trex/module.rs` |
| **P8b.2** | T0: ProcessScanner — `CreateToolhelp32Snapshot` + 25 厂商进程名匹配 | `trex/modules/t0_process.rs` |
| **P8b.3** | T1: RegistryScanner — `HKLM\SYSTEM\CurrentControlSet\Services` 直读，零 SCManager | `trex/modules/t1_registry.rs` |
| **P8b.4** | T2: WmiScanner — `ROOT\SecurityCenter2:AntiVirusProduct` + `Win32_Service` | `trex/modules/t2_wmi.rs` |
| **P8b.5** | T3: ServiceScanner — `OpenSCManagerW` + `EnumServicesStatusExW` | `trex/modules/t3_service.rs` |
| **P8b.6** | T4: KernelScanner — `NtQuerySystemInformation(SystemModuleInformation)` + `SystemCodeIntegrityInformation`(class 103) | `trex/modules/t4_kernel.rs` |
| **P8b.7** | T5: CallbackScanner — BYOVD `PspCreateProcessNotifyRoutine` + `PspLoadImageNotifyRoutine` 枚举 | `trex/modules/t5_callbacks.rs` |
| **P8b.8** | 模块编排器 — 按噪声级递增执行：T0→T1→T2... 每级成功后评估是否需要下一级 | `trex/orchestrator.rs` |

**验收:** 单模块可独立加载/卸载/热替换。`noise_level=0` 模块零 EDR 事件。

### P8c. 隐蔽外传引擎（2 周）

> **情报来源:** GhostLink (2026) — DNS/HTTPS/ICMP 多信道 + ChaCha20-Poly1305  
> Dead Drop Resolver (MITRE T1102.001) — GitHub Gist / Pastebin 作为中间存储  
> DDR Taxonomy (Delta ThreatLabs 2026) — 三级结构（静态/轮换/链式）+ 三种检索机制

| 子任务 | 细节 | 交付物 |
|--------|------|--------|
| **P8c.1** | `ExfilChannel` trait — `fn send(&self, payload: &[u8]) -> Result<()>` + `fn latency_ms() -> u64` | `trex/exfil.rs` |
| **P8c.2** | DNS TXT 外传 — Base64 编码 → 分片（每片 255 字节）→ `query.trex.c2.domain` TXT 查询 → 权威 DNS 服务器记录 | `trex/exfil/dns.rs` |
| **P8c.3** | HTTPS Dead Drop — `POST https://gist.github.com/...` 或 `PUT https://pastebin.com/...` → JSON payload → 一次性读取后自删除 | `trex/exfil/deaddrop.rs` |
| **P8c.4** | HTTPS Domain Fronting — SNI = `cdn.cloudflare.com` → Host = `c2.evil.com` → AES-256-GCM payload | `trex/exfil/https.rs` |
| **P8c.5** | 信道自动选择 — DNS 优先（最隐蔽）→ HTTPS Fronting（中等）→ Dead Drop（高噪）。按目标网络环境自动切换 | `trex/exfil/selector.rs` |
| **P8c.6** | 侦查报告加密 — `X25519 ECDH` 派生一次性对称密钥 → `ChaCha20-Poly1305` 加密 → 服务器公钥预置在 Stage 0 | `trex/report.rs` |

**验收:** DNS 信道外传 10KB 报告 < 60 秒。HTTPS 信道 Wireshark 显示为 Cloudflare CDN 流量。

### P8d. 自毁序列 + 反取证清理（2 周）

> **情报来源:** Meltloader (2026) — 线程终止 → `NtFreeVirtualMemory(MEM_RELEASE)` → PE 头清零  
> Win11 24H2 Self-Delete (TKYN 2025) — `FileDispositionInformationEx` + `POSIX_SEMANTICS`  
> NTFS Anti-Forensics (MFT Parser 2026) — USNJ/$LogFile/VSS 交叉检测 → 唯一真正零痕迹是不碰磁盘

| 子任务 | 细节 | 交付物 |
|--------|------|--------|
| **P8d.1** | **内存自毁序列:** (1) `RtlZeroMemory` 所有模块页 (2) `NtFreeVirtualMemory(MEM_RELEASE)` 每页 (3) 栈帧归零 (4) `NtTerminateThread(NT_CURRENT_THREAD, 0)` 自终止 | `trex/melt.rs` |
| **P8d.2** | **磁盘痕迹清理 (仅当不可避免时):** (1) Prefetch: `DeleteFileW("C:\\Windows\\Prefetch\\*.pf")` 通配删除 (2) USN Journal: `FSCTL_DELETE_USN_JOURNAL` (3) Event Log: 选择性清除 1102/4688 事件 (4) MFT: 覆盖已删除条目 | `trex/cleanup/disk.rs` |
| **P8d.3** | **VSS 快照污染:** 触发新快照 → 覆盖旧快照 → 删除新快照。可选（高噪） | `trex/cleanup/vss.rs` |
| **P8d.4** | **内存痕迹清除:** `NtQueryVirtualMemory` 遍历 → 每页 `MEM_PRIVATE` + `MEM_COMMIT` → `VirtualFree(MEM_DECOMMIT)` → 再 `VirtualFree(MEM_RELEASE)` | `trex/cleanup/memory.rs` |
| **P8d.5** | **自毁验证:** `NtQuerySystemInformation(SystemProcessInformation)` → 确认 PID 不再存在 → 确认无残留线程/句柄 | `trex/cleanup/verify.rs` |

**验收:** 自毁后 `volatility pslist` 无进程。`volatility malfind` 零异常。`Velociraptor` 采集无 T-REX 痕迹。

---

## 第二阶段：P9 · Nyx 基础设施升级（6 周）

### P9a. implant-core 抽象层（3 周）

> 从 T-REX 的模块化设计中提取通用模式，为所有 implant 提供共享基础设施。

| 子任务 | 细节 | 交付物 |
|--------|------|--------|
| **P9a.1** | `ProbeModule` trait 提升为 `implant_core::Module` —— 跨 agent 的模块化标准 | `crates/implant-core/src/module.rs` |
| **P9a.2** | `ExfilChannel` trait 提升为 `implant_core::Transport` —— T-REX + beacon 共享传输层 | `crates/implant-core/src/transport.rs` |
| **P9a.3** | `MeltSequence` trait 提升为 `implant_core::SelfDestruct` —— 统一自毁接口 | `crates/implant-core/src/melt.rs` |
| **P9a.4** | `ForensicCleaner` trait —— 跨平台的痕迹清理抽象 | `crates/implant-core/src/cleanup.rs` |

### P9b. 多信道传输层（3 周）

| 子任务 | 细节 | 交付物 |
|--------|------|--------|
| **P9b.1** | DNS TXT 隧道 — 完整实现（编码/分片/重组/重试/超时），从 T-REX 提取 | `crates/transport/src/dns.rs` |
| **P9b.2** | HTTPS Domain Fronting — Cloudflare Workers 中继模板 + SNI 伪装 + Host Header 控制 | `crates/transport/src/fronting.rs` |
| **P9b.3** | WebSocket over TLS — wss:// 长连接，从 HTTPS 降级时激活 | `crates/transport/src/ws.rs` |
| **P9b.4** | Dead Drop Resolver — GitHub Gist API + Pastebin API + 轮换账户池 | `crates/transport/src/deaddrop.rs` |
| **P9b.5** | `TransportStack` — 主/备/降三级信道自动切换 + 健康检查 | `crates/transport/src/orchestrator.rs` |

---

## 第三阶段：P10 · 反取证深度加固（4 周）

> **核心原则 (NTFS Anti-Forensics 2026):** 磁盘痕迹清理永远不完美——USNJ/$LogFile/VSS/MFT 形成交叉验证网。**唯一真正零痕迹的方法是从不碰磁盘。**T-REX 的 "Zero-Footprint by Design" 理念推广到整个 Nyx。

### P10a. 零磁盘模式（2 周）

| 子任务 | 细节 | 交付物 |
|--------|------|--------|
| **P10a.1** | `MemoryOnly` 执行模式 — 所有 payload 通过反射式加载，零 `CreateFileW` / `WriteFile` | `implant-core/src/memory_only.rs` |
| **P10a.2** | 内存驻留持久化 — `NtCreateSection` + `NtMapViewOfSection` 从 `\KnownDlls` 映射合法 DLL → 注入 payload → 无新文件 | `implant-win/src/persist/memory.rs` |
| **P10a.3** | 配置参数内存传递 — Stage 0 → Stage 1 参数通过寄存器/栈传递，不写入任何文件 | `trex/stage0.rs` |

### P10b. forensic artifact cleanup（2 周）

| 子任务 | 细节 | 交付物 |
|--------|------|--------|
| **P10b.1** | USN Journal 清理 — `FSCTL_DELETE_USN_JOURNAL` + 等待新 journal 创建 → `FSCTL_CREATE_USN_JOURNAL` | `crates/implant-core/src/cleanup/usn.rs` |
| **P10b.2** | Prefetch 清理 — 枚举 `C:\Windows\Prefetch\*.pf` → `NtSetInformationFile(FileDispositionInformationEx)` + POSIX 语义删除 | `crates/implant-core/src/cleanup/prefetch.rs` |
| **P10b.3** | Event Log 选择性清除 — `OpenEventLogW` → `GetOldestEventLogRecord` → 选择性 `ClearEventLogW` | `crates/implant-core/src/cleanup/eventlog.rs` |
| **P10b.4** | Amcache/Shimcache 清理 — 注册表 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` 覆盖 | `crates/implant-core/src/cleanup/appcompat.rs` |
| **P10b.5** | MFT 记录覆盖 — `NtCreateFile` + `FileDispositionInformationEx(POSIX_DELETE)` → 覆盖已释放的 MFT 条目 | `crates/implant-core/src/cleanup/mft.rs` |

---

## 第四阶段：P11 · Nyx 全平台多信道 beacon（6 周）

### P11a. Windows beacon 多信道升级（3 周）

| 子任务 | 细节 | 交付物 |
|--------|------|--------|
| **P11a.1** | 将 `TransportStack` 集成到 `beacon.rs` — 替换当前单 WinHTTP 路径 | `implant-win/src/beacon.rs` |
| **P11a.2** | JA4 指纹旋转 — 每次信标随机选择 Chrome 124/125/126/Firefox 125/Edge 124 TLS 指纹 | `crates/transport/src/tls_fingerprint.rs` |
| **P11a.3** | Jitter Beacon — 指数退避 + 30% 随机抖动 + 办公时间感知 | `implant-core/src/scheduler/jitter.rs` |
| **P11a.4** | 信道健康检查 — 15 秒间隔 ping → 连续 3 次失败 → 降级到备用信道 | `crates/transport/src/health.rs` |

### P11b. Nyx agent-dev 升级为 Linux/macOS 原型（3 周）

| 子任务 | 细节 | 交付物 |
|--------|------|--------|
| **P11b.1** | `Platform` trait 的 Linux 实现 — `memfd_create` + `ptrace` 注入 + vDSO syscall 解析 | `crates/agent-dev/src/linux.rs` |
| **P11b.2** | `Platform` trait 的 macOS 实现 — `processor_set_tasks` + `mach_vm_write` + `thread_create_running` | `crates/agent-dev/src/macos.rs` |
| **P11b.3** | T-REX 跨平台探测 — Linux: `/proc` 扫描 + `systemd-detect-virt` + `lsmod` · macOS: `system_profiler SPSoftwareDataType` + `kextstat` | `trex/modules/cross_platform/` |

---

## 第五阶段：P12 · 载荷变形 + CI/CD（4 周）

### P12a. LLVM 载荷变形（2 周）

| 子任务 | 细节 | 交付物 |
|--------|------|--------|
| **P12a.1** | LLVM IR pass — 寄存器随机分配 + 指令重排 + NOP 插入 + 立即数 XOR 混淆 | `tools/payload_mutator/pass.cpp` |
| **P12a.2** | 三编译目标 (Cavern Manticore 标准) — GNU as / MSVC / LLVM-IR → 每次编译不同二进制 | `crates/implant-win/.cargo/config.toml` |
| **P12a.3** | 签名验证 — ED25519 签名嵌入 Stage 0 → Stage 1 加载前验证 → 失败 → 自毁 | `trex/verify.rs` |

### P12b. CI/CD 自动化载荷工厂（2 周）

| 子任务 | 细节 | 交付物 |
|--------|------|--------|
| **P12b.1** | GitHub Actions 私有 Runner — `Windows Server 2022` + `macOS 15` + `Ubuntu 24.04` | `.github/workflows/payload_factory.yml` |
| **P12b.2** | 自动化编译 → LLVM 变形 → ED25519 签名 → S3/CDN 分发 | `scripts/payload_pipeline.sh` |
| **P12b.3** | 检测器沙箱 — Docker 化 CrowdStrike/S1/Defender ATP 自动回归 → 每周报告 | `tools/detector_sandbox/` |
| **P12b.4** | 版本化载荷管理 — 编号 DLL 版本 (Cavern Manticore 标准) + `get_latest_dll()` 热更新 | `implant-core/src/module/version.rs` |

---

## 时间线总览

```
2026 Q3 ───────────────────────────────────────────────────
  Jul │ P7 ■ 已交付 · P8a ▓▓ 微壳代码 + 反射加载器
  Aug │ P8b ▓▓▓▓ 模块化探测插件 · P8c ▓▓▓▓ 隐蔽外传引擎
  Sep │ P8d ▓▓▓▓ 自毁序列 + 反取证 · P9a ▓▓▓ implant-core 抽象
2026 Q4 ───────────────────────────────────────────────────
  Oct │ P9b ▓▓▓▓ 多信道传输层 · P10a ▓▓ 零磁盘模式
  Nov │ P10b ▓▓▓▓ 取证痕迹清理 · P11a ▓▓▓ Windows beacon 多信道
  Dec │ P11b ▓▓▓ Linux/macOS 原型 · P12a ▓▓ 载荷变形
2027 Q1 ───────────────────────────────────────────────────
  Jan │ P12b ▓▓▓▓ CI/CD 载荷工厂 · 全量集成测试
  Feb │ Nyx 2.0 RC — 红队演练
```

## 即刻行动（本周）

```
1. P8a.1 — 创建 trex/stage0/  目录，编写 <512B PIC x64 微壳代码
2. P8a.2 — 移植 meltloader 逻辑到 Rust: 手动 PE 解析 + 重定位
3. P8b.1 — 定义 ProbeModule trait 接口
4. P8b.3 — T0 ProcessScanner: 从 trex.rs 提取进程名匹配逻辑
```
