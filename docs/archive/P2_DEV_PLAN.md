# Nyx P2 — 下一阶段开发指导方案

> **日期:** 2026-06-27
> **分支:** `p2-evasion-synced`
> **当前完成度:** ~95%（用户态 98%，内核算法 100%，接线 100%，内核真机 7/7 PASS）
> **目标:** 追平 Cobalt Strike 4.13 / Brute Ratel C4 v2.3 核心工程能力，同时保持内核 bypass 差异化优势
> **授权:** 仅限授权红队 / 安全研究

---

## 1. 现状速查

| 维度 | 当前状态 | 距目标 |
|------|----------|--------|
| 用户态 bypass 核心 | ✅ 对位 CS 4.13 / BRC4 v2.3 | 最后 10%（heap mask + CET swap） |
| 内核 bypass | 🟢 维度领先（竞品无此维度） | 落地验证缺 Win11 + 主流 EDR |
| 持久化 | 🔴 近乎为零 | 需全套 service/registry/WMI/task |
| C2 协议 | 🔴 仅 HTTPS + pivot | 需 DNS/SMB/TCP + UDC2 |
| 注入多样性 | 🟡 仅 module stomp | 需 early bird APC / hollow / spawn |
| BOF 生态 | 🟡 基础同步执行 | 需异步 BOF + BOF-PE |
| 后渗透命令 | 🟡 基础 | 需 token / reg / service / getsystem |
| 代码安全 | ⚠️ 一处危险（blind_hwbp static_mut） | 需原子化修复 |

---

## 2. 开发路线图（4 个 Phase）

```
Phase 1: 闭合"最后 10%"（2 周）
Phase 2: 工程化补全（4 周）
Phase 3: 内核落地验证（2 周）
Phase 4: 差异化巩固（持续）
```

---

## 3. Phase 1 — 闭合"最后 10%"（2 周）

目标：解决用户态 bypass 中剩下的两个实质差距，以及 netsec 的 blocking bug。

### 3.1 P0-A: Foliage Heap Mask 接线

**问题:** Foliage sleep mask 只 RC4-mask `.text` 段，heap 上的 beacon 配置结构体、token、句柄等仍是明文。CS 4.13 默认 sleep mask 同时 mask Beacon + heap 分配。

**现状:**
- `ntalloc.rs` 已有 `SlabDesc[16]` slab tracking（`enumerate_slabs()` / `heap_bytes()`）
- `mem.rs` 已有 `mask_heap_regions()` / `unmask_heap_regions()` RC4 实现
- `kits.rs` 注释中规划的"堆先于 .text 恢复"逻辑存在，但**未接通**

**交付物:**
1. `sleep.rs` — Foliage helper 在 `.text` mask 后追加 `mask_heap_regions(key)`，wake 时在 `.text` unmask 前执行 `unmask_heap_regions(key)`
2. `mem.rs` — 增加 `register_heap_slab(slab: &SlabDesc)` 便捷方法
3. `ntalloc.rs` — 在 slab 分配时自动注册（或通过 `heap_bytes()` 批量注册）
4. `selftests.rs` — 新增 `nyx_selftest_heap_mask`：在 heap 上写入已知模式 → mask → 验证密文 → unmask → 验证恢复

**验收标准:**
- PE-sieve / Moneta 在 sleep 窗口内扫 heap 配置结构体，0 命中
- BeaconEye heap 扫描无 beacon 特征
- Selftest exit code 通过

**代码定位:**
- `crates/implant-win/src/sleep.rs` — Foliage helper 函数 (~line 624)
- `crates/implant-win/src/mem.rs` — `mask_heap_regions` (~line 280)
- `crates/implant-win/src/kits.rs` — `Foliage` impl (~line 45)

### 3.2 P0-B: WFP Per-PID Filter 修复

**问题:** `netsec.rs::rules_for()` 生成的 WFP filter 的 `num_filter_conditions = 0`，实际效果是**阻断全部出站流量**，不是仅阻断 EDR。这会导致 Beacon C2 通道也被阻断。

**现状:**
```rust
// current (bug):
let filter = FWPM_FILTER0 {
    // ...
    numFilterConditions: 0,  // ← 阻断 ALL outbound
    // ...
};
```

**交付物:**
1. `netsec.rs` — 在 `rules_for()` 中为每个 EDR PID 生成 `FWPM_FILTER_CONDITION0`:
   - `FWPM_CONDITION_PID` 或 `FWPM_CONDITION_IPE_OWNER`
   - 条件值 = EDR PID
   - 匹配方式 = `FWP_MATCH_EQUAL`
2. `netsec.rs` — 增加 `remove_rules()` / cleanup 路径（当前无反向操作）
3. `tests/` — 单元测试验证 filter condition 数组正确性

**验收标准:**
- `silence_edr(edr_pid)` 后，非 EDR 进程出站正常，EDR 进程出站阻断
- 可通过 `remove_rules()` 恢复

**代码定位:**
- `crates/operator-kernelsdk/src/netsec.rs` — `rules_for()` (~line 200)

### 3.3 P0-C: CET-Safe RSP Swap 修复

**问题:** 当前 `stack.rs` 的 `should_execute()` 在 CET-on 时返回 `false`，直接调用（栈残留 `[RSP]` 暴露给 xacone / K2 / cet-spoofing-detection）。

**现状:**
- `stack.rs:17-50` — CET 检测 + 降级逻辑
- 注释引用了 Synacktiv SSTIC 2025 section 7.2 的修复思路，但未实现

**修复方案（两种路径，选一）:**

**路径 1: CET-aware indirect syscall（推荐，更稳健）**
- 不执行 RSP swap，改为在 CET-on 主机上使用 **CET 标记的 indirect syscall  trampoline**
- 原理: CET 提供 `ENDBR64` 标记，合法模块的 `syscall; ret` gadget 如果以 `ENDBR64` 开头，可以直接跳转，CET 不报错
- 实现: 扫描 ntdll `.text` 找 `ENDBR64 + syscall + ret` 序列，建立 CET-safe trampoline
- 参考: Windows 11 24H2+ 的 CET 用户模式 API (`SetThreadInformation` / `QueryInformation`)

**路径 2: CONTEXT-based return address spoofing（更复杂）**
- 不 swap RSP，改为在 `NtContinue` 的 CONTEXT 中伪造 RIP 和 RSP：
  - RIP = gap address（假帧返回地址）
  - RSP = 原栈（不动）
- 需要 `NtSetContextThread` + `NtResumeThread` 链，更接近 CS BeaconGate 的 `NtContinue` 伪造路径

**交付物（路径 1）:**
1. `evasionsdk/cet.rs` — CET 检测 + ENDBR64 序列扫描
2. `syscalls.rs` — 在 `syscall!` macro 中添加 CET 路径：
   - CET-off: 当前 RSP swap（spoofed stack）
   - CET-on: ENDBR64-tagged indirect syscall（无 RSP swap）
3. `stack.rs` — `do_rsp_swap` 保持，但 `should_execute` 在 CET-on 时走新路径

**验收标准:**
- CET-on 主机（Intel TGL+）上，间接 syscall 栈上 `[RSP]` 指向 ntdll，不指向 implant
- xacone / K2 栈追溯检查通过
- CET-off 主机行为不变

**代码定位:**
- `crates/implant-win/src/stack.rs` — `should_execute()` (~line 17)
- `crates/implant-win/src/syscalls.rs` — `syscall!` macro (~line 310)

### 3.4 P0-D: Token 操纵 + 通用 Inject Wire 命令

**问题:** wire protocol（21 个命令）中完全没有 token 操作或通用进程注入。只有 module stomp 通过 `kits.rs` 硬编码接入 beacon loop，无 operator 命令入口。

**交付物 1 — Token 操纵:**

| 命令 | 功能 | 参考 CS |
|------|------|---------|
| `steal_token <pid>` | 窃取目标进程 token | `steal_token` |
| `make_token <domain> <user> <pass>` | 创建新 token | `make_token` |
| `rev2self` | 恢复原始 token | `rev2self` |
| `getprivs` | 启用当前 token 所有特权 | `getprivs` |

**实现:**
1. `protocol/src/msg.rs` — 新增 4 个 Command variant（tag 22-25）
2. `server/src/lib.rs` — 新增 `JsonCommand` + handler
3. `implant-win/src/token.rs` — 新模块:
   - `steal_token(pid)` → `NtOpenProcess` → `NtOpenProcessToken` → `NtSetInformationThread(ThreadImpersonationToken)`
   - `make_token()` → `NtLogonUser` / `LsaLogonUser`（需要 LSASS 交互）
   - `rev2self()` → `NtSetInformationThread(ThreadImpersonationToken, NULL)`
   - `getprivs()` → `RtlAdjustPrivilege` 循环启用所有特权

**交付物 2 — 通用 Inject:**

| 命令 | 功能 | 参考 CS |
|------|------|---------|
| `inject <pid> <shellcode>` | 通用注入（spawn + inject） | `inject` / `shinject` |
| `spawn <exe> <args>` | 创建新进程并返回 | `spawn` |

**实现:**
1. `protocol/src/msg.rs` — 新增 2 个 Command variant（tag 26-27）
2. `implant-win/src/inject.rs` — 公开 `remote_load_library()` 作为通用 inject 路径（已有实现，需封装为 wire command）
3. `server/src/lib.rs` — handler 转发到 implant

**代码定位:**
- `crates/protocol/src/msg.rs` — Command enum (~line 90)
- `crates/server/src/lib.rs` — `into_command()` (~line 848)
- `crates/client-cli/src/rest.rs` — `Cmd` enum (~line 76)
- `crates/implant-win/src/inject.rs` — `remote_load_library()` (~line 200)

---

## 4. Phase 2 — 工程化补全（4 周）

目标：追平 CS 4.13 / BRC4 v2.3 的工程生态能力。

### 4.1 P1-A: 持久化生态

**差距:** Nyx 无任何重启存活持久化。当前仅有内核 DKOM（运行时隐藏，重启丢失）。

**交付物:**

| 方法 | 实现复杂度 | 检测风险 | 优先级 |
|------|------------|----------|--------|
| Registry Run 键 | 低 | 中 | P1 |
| Scheduled Task | 中 | 中低 | P1 |
| Service | 中 | 高（Sysmon EID 7045） | P2 |
| WMI Event Subscription | 中 | 中 | P2 |

**实现路径:**
1. `operator-kernelsdk/src/persistence.rs` — 新增 `PersistenceKit` trait:
   ```rust
   pub trait PersistenceKit {
       fn registry_run(&self, name: &str, payload_path: &str) -> Result<()>;
       fn scheduled_task(&self, name: &str, payload_path: &str, trigger: &str) -> Result<()>;
       fn remove(&self, method: &str, name: &str) -> Result<()>;
   }
   ```
2. `implant-win/src/persistence.rs` — 新模块，使用间接 syscall 实现:
   - `registry_run()` → `NtOpenKey` / `NtSetValueKey`（`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`）
   - `scheduled_task()` → COM 接口（`Schedule.Service`）或 XML 任务文件 + `NtCreateFile` + `NtSetInformationFile`
   - 每个方法默认 OFF（gated），operator 显式 arm 才执行

**注意:** 持久化需配合 `PPL strip`（已有）将 beacon 进程设为 `UNPROTECTED`，防止被 PPL 保护机制终止。

### 4.2 P1-B: C2 多协议

**差距:** Nyx 仅 HTTPS WinHTTP + TCP pivot relay。CS 4.13 有 HTTPS/DNS/SMB/TCP + UDC2；BRC4 有 HTTP/S/DNS/SMB/TCP + DoH + External C2。

**优先级排序:**

| 协议 | 工作量 | 价值 | 说明 |
|------|--------|------|------|
| DNS C2 | 中 | 高 | 绕过 most egress 过滤，C2 over DNS |
| SMB beacon | 高 | 高 | 内网横向，命名管道通信 |
| TCP raw | 低 | 中 | Connect 已有 TCP 基础，缺 bind/UDP |
| DoH | 中 | 中 | BRC4 有，DNS over HTTPS |
| External C2 | 高 | 中低 | Slack/Discord/Teams — 需服务端集成 |

**实现路径:**
1. **DNS C2（推荐优先）:**
   - `protocol/src/dns.rs` — DNS 帧编码（TXT/CNAME 记录承载加密帧）
   - `implant-win/src/transport.rs` — DNS 传输层（`NtDnsQuery` 或 `DnsQuery_A` 间接 syscall）
   - `server/src/dns.rs` — DNS listener（需绑定 UDP 53 或依赖 NS 记录）
   - malleable profile 增加 `dns_profile` block

2. **SMB Beacon (Pivot):**
   - `implant-win/src/pivot.rs` — 已有 `do_connect` TCP pivot，扩展 named pipe (`\\.\pipe\nyx_pipe_<id>`) + SMB session binding
   - `server/src/pivot.rs` — server 端 SMB pivot acceptor（需与 HTTPS listener 解耦）

### 4.3 P1-C: 注入多样性

**差距:** Nyx 仅 module stomp（+ ThreadlessInject 已实现但 gate 行为未完全调通）。

**交付物:**

| 注入法 | 实现位置 | 说明 |
|--------|----------|------|
| Early Bird APC | `inject.rs` 新函数 | `NtCreateThreadEx` + `NtQueueApcThread` + `NtTestAlert` — 在新线程 APC 队列中执行，绕过 CreateRemoteThread 检测 |
| Thread Hijack | `inject.rs` 新函数 | `NtSuspendThread` → `NtGetContextThread` → 修改 RIP → `NtResumeThread` |
| Process Hollowing | `inject.rs` 新函数 | `NtCreateProcess` / `NtCreateProcessEx` → unmapped section → `NtWriteVirtualMemory` 替换 `.text` |

**注:** ThreadlessInject 已有实现（DR0-DR3 HWBP trigger），但：
- 当前仅通过 `inject.rs` 内部调用，无 wire command 入口
- 需要一个通用 `inject <pid> <shellcode>` wire command（见 Phase 1 P0-D）

### 4.4 P1-D: 异步 BOF

**差距:** Nyx `bof.rs` 是同步阻塞执行。BRC4 v2.3 的 `coffexec_async` 允许多个 BOF 在 Badger sleep mask 期间**并发执行**。

**实现路径:**
1. `protocol/src/msg.rs` — 新增 `BofAsync` command（tag 28）+ `BofAsyncOutput` response
2. `implant-win/src/bof.rs` — 在现有 `execute_bof()` 外增加 `execute_bof_async()`:
   - `NtCreateThread` 在新线程执行 BOF（避免阻塞 beacon 主循环）
   - BOF 完成后通过 `NtQueueApcThread` 或共享内存 + event 回传结果
   - beacon 下次 cycle 读取结果
3. `server/src/lib.rs` — handler 支持 async BOF 任务生命周期（pending → running → done）
4. `client-cli` — `/bof_async` 命令，不阻塞等待

### 4.5 P1-E: LSASS 全 VA 扫描 + 凭据解析

**差距:** 当前 `netsec.rs` 只读 LSASS 前 1 MiB 用户 VA。BRC4 GhostKatz / Mimikatz 会遍历整个 LSASS 用户 VA。

**实现路径:**
1. `netsec.rs` — 扩展 `read_process_mem()` 为 `scan_user_va()`:
   - 从 `0x10000000` 遍历到 `0x7FFFFFFF`（4 GiB 用户 VA 空间）
   - 跳过未提交区域（检查 PTE present bit）
   - 识别 credential 结构体（`_MMPAGING_FILE`、`_CM_CACHED_VALUE`、kerberos ticket、lsass.logon session）
2. `parse/` crate 或新模块 — 凭据结构体解析:
   - `mimikatz/sekurlsa` 风格的 `_KI_GUEST_CREDENTIAL` / `_PESSO` 解析
   - Kerberos ticket 提取（`_KERB_TICKET_LOGON`）
   - DPAPI master key 定位（`_KI_MASTERKEY`）

---

## 5. Phase 3 — 内核落地验证（2 周）

目标：将内核能力从"算法级/纸面级"推进到"真机可用级"。

### 5.1 P1-F: KslD.sys 全面真机验证

**现状:** KslD IOCTL 绑定已完成，但 RTCore64 仍为主验证路径。KslD 是"Living off the Defender"正解（Defender 自带签名驱动，无新驱动加载事件）。

**验证计划:**
1. 在 Server 2019 上验证 KslD `QueryDosDeviceW` 枚举路径（`\\.\MpKsl` → 枚举 MpKsl*）
2. 验证 KslD IOCTL 读/写与 RTCore64 等价（测试模式下用 KslD 跑通 H-I-J-K 全链路）
3. 记录 KslD 在不同 Defender 版本下的 IOCTL 稳定性
4. 评估 Sysmon 对 KslD 的可见性（EID 6 driver load / EID 7 image load）

### 5.2 P1-G: 现代 Win11 + EDR 真机矩阵

**目标:** 在内核能力在现代 EDR 下验证。

| 环境 | 优先级 | 说明 |
|------|--------|------|
| Win11 24H2 (26100) | P1 | CET-on 默认 + 新 PatchGuard + 新 offset |
| Win11 22H2 (22621) | P1 | 主流企业部署版本 |
| Server 2022 (20348) | P2 | 逐渐替代 Server 2019 |
| Defender for Endpoint | P1 | 纯内核回调 EDR，CS/BRC4 用户态全失效 |
| Sysmon + WdFilter | P1 | 已验证 slot[5] repurpose |

**每环境的验证计划:**
1. Offset probe — `pg_context_offsets` + `etwti` + `persistence` 全量 probe
2. ETW-TI blind — IsEnabled → 0
3. Process hide — tasklist 1→0→1 + PG 无触发
4. Callback repurpose — SysmonDrv / WdFilter EID1 SILENCED + RESUMED
5. PG window — TimingRepairWindow + RuntimePgBypassWindow 各一次成功 DKOM

### 5.3 P1-H: netsec WFP Kernel Callout 覆盖

**现状:** WFP filter 注入（用户态）已框架化，但 per-PID 过滤未实现。更安静的路径是**内核 callout 指针覆盖**（覆盖 WFP 内核 callout 的 dispatch 函数指针）。

**实现路径:**
1. `netsec.rs` — 在 WFP engine open 后，resolve `FwpmCalloutAdd0` / `FwpmFilterAdd0` 的 kernel-mode dispatch
2. 通过内核 R/W 覆写 callout 的 `ClassifyFn` 指针 → ret gadget（类似 callback repurpose 的数据写路径）
3. 在 classify 函数入口写 `ret`，EDR 的 WFP callout 不执行

**价值:** 比用户态 block rule 更安静（无 FWPM 引擎日志、无 WFP 审计事件）。

---

## 6. Phase 4 — 差异化巩固（持续）

目标：将 Nyx 的内核维度优势从"理论领先"推进到"工程壁垒"。

### 6.1 P2-A: ETW 伪造 HMAC 签名

**现状:** `etw_deception.rs` 可伪造 Process Start/Stop 事件，但缺内核 HMAC 签名。Sanctum / Peregrine 可验证 ETW 事件完整性。

**实现:** 在内核层解析 `EtwpProviderSecurityDescriptor` + HMAC key material，伪造事件时附带正确的 MIC（Message Integrity Code）。

**价值:** 使"事件缺失"检测（只看到 EDR 自己产生的事件）和"事件伪造"检测（HMAC 不匹配）同时失效。

### 6.2 P2-B: Crypto Key Ratcheting

**现状:** 会话密钥在第一次 check-in 时 ECDH 派生一次，之后所有帧用同一 key。

**实现:**
1. 每个 cycle 的 `NYX_COUNTER` 作为 ratchet input
2. HKDF-SHA256 重新派生，info = `"nyx-session-v2" || server_pub || implant_pub || counter`
3. `ServerKeypair` 支持定期轮转（NYX_KEYFILE 持久化）

**价值:** 长期 session（数周）的密文材料不累积在同一 key 下，即使 server 日志泄露，历史密文也无法被联合分析。

### 6.3 P2-C: 线程安全加固

**问题:** `blind_hwbp.rs` 有 5 个 `static mut` 全局无原子保护。

**修复:**
```rust
// 将以下变量改为原子类型:
static HWBP_COUNT: AtomicU8 = AtomicU8::new(0);
static HWBP_ENTRIES: [AtomicUsize; 4] = ...; // 或 RwLock
```

**价值:** 消除单线程假设的未定义行为，使 VEH handler 在多线程场景下安全。

### 6.4 P2-D: Session GC + Job Management

**问题:**
- 植入体死掉后 session 永远留在 `DashMap`
- 无 `/jobs` / `/cancel` / 任务生命周期管理

**实现:**
1. `server/src/session.rs` — `SessionRegistry` 增加 GC 循环（每 60s 扫描，超过 `MAX_SILENCE` 未 check-in 的 session 自动移除）
2. `protocol/src/msg.rs` — `JobId` + `JobCancel` command
3. `server/src/lib.rs` — `POST /api/jobs/{id}/cancel`

---

## 7. 开发优先级总表

| Phase | 任务 | 优先级 | 工作量 | 影响 | 竞品对标 |
|-------|------|--------|--------|------|----------|
| **1** | Foliage heap mask 接线 | 🔴 P0 | 低（2-3 天） | 追平 CS 4.13 sleep mask | CS 4.13 |
| **1** | WFP per-PID filter 修复 | 🔴 P0 | 低（1 天） | 自修复 blocking bug | 自修复 |
| **1** | CET-safe RSP swap | 🔴 P0 | 中（1-2 周） | 追平 CS BeaconGate RAS | CS 4.13 |
| **1** | Token 操纵 wire 命令 | 🔴 P0 | 中（1 周） | 横向场景必备 | CS 4.13 |
| **1** | 通用 inject wire 命令 | 🔴 P0 | 低（2 天） | 追平 CS/BRC4 | CS/BRC4 |
| **2** | 持久化生态 | 🟡 P1 | 中（2 周） | 重启存活 | CS 4.13 |
| **2** | C2 多协议（DNS/SMB） | 🟡 P1 | 中-高（3-4 周） | 内网机动性 | CS 4.13 |
| **2** | 注入多样性（early bird / hollow） | 🟡 P1 | 中（2 周） | 冗余注入路径 | CS/BRC4 |
| **2** | 异步 BOF | 🟡 P1 | 中（2 周） | 不阻塞 beacon | BRC4 v2.3 |
| **2** | LSASS 全 VA + 凭据解析 | 🟡 P1 | 中（2-3 周） | 完整凭据提取 | BRC4 GhostKatz |
| **3** | KslD 全面真机验证 | 🟡 P1 | 中（1 周） | 内核落地 | 自验证 |
| **3** | Win11 + EDR 真机矩阵 | 🟡 P1 | 中（2 周） | 跨版本验证 | 自验证 |
| **3** | WFP kernel callout 覆盖 | 🟡 P1 | 高（3-4 周） | 更安静网络 silencing | 自研 |
| **4** | ETW 伪造 HMAC | 🟢 P2 | 高（3-4 周） | 反 Sanctum/Peregrine | Sanctum |
| **4** | Crypto key ratcheting | 🟢 P2 | 低（3-5 天） | 长期 session 安全 | 工程最佳实践 |
| **4** | 线程安全加固 (static_mut) | 🟢 P2 | 低（1 天） | 消除 UB | 自修复 |
| **4** | Session GC + Job mgmt | 🟢 P2 | 低（1 周） | 工程完整性 | CS 4.13 |
| **4** | UDRL / sRDI 管线 | 🟢 P2 | 中（2 周） | PostEx 灵活性 | CS 4.13 |

---

## 8. 与现有文档的关系

| 文档 | 关系 |
|------|------|
| `docs/p2-next-dev-guidance.md` | 早期版本（06-26 快照），部分过时，本文档据实修正 |
| `docs/p2-benchmark-vs-cs413-brc4-v23.md` | 差距清单，本文档为其提供**修复实现路径** |
| `docs/nyx-gap-analysis-cs413-brc4.md` | 全量逐文件审计，本文档为其提供**开发执行计划** |
| `docs/BYPASS_CAPABILITIES.md` | 能力矩阵，本文档为其提供**未实现项的落地计划** |
| `docs/BYPASS_DEVELOPMENT_REPORT.md` | 开发进度报告，阶段完成后更新 |

---

## 9. 附录：关键代码入口速查

| 需要改动的文件 | 关键位置 | 改动类型 |
|----------------|----------|----------|
| `implant-win/src/sleep.rs` | Foliage helper (~L624) | 追加 heap mask 调用 |
| `implant-win/src/mem.rs` | `mask_heap_regions` (~L280) | 新增 `register_heap_slab` |
| `implant-win/src/stack.rs` | `should_execute` (~L17) | CET-safe 路径 |
| `implant-win/src/inject.rs` | `remote_load_library` (~L200) | 暴露为 wire command |
| `operator-kernelsdk/src/netsec.rs` | `rules_for` (~L200) | WFP filter conditions |
| `operator-kernelsdk/src/persistence.rs` | 新建 `PersistenceKit` trait | 持久化 kit |
| `protocol/src/msg.rs` | Command enum (~L90) | 新增 token / inject / async_bof |
| `server/src/lib.rs` | `into_command` (~L848) | 新 handler |
| `client-cli/src/rest.rs` | `Cmd` enum (~L76) | 新 CLI 命令 |
| `implant-win/src/token.rs` | 新建 | Token 操纵模块 |

---

## 10. 里程碑检查点

| 里程碑 | 预期完成 | 验证标准 |
|--------|----------|----------|
| M1: Heap mask 接线 | Phase 1 结束 | PE-sieve heap scan 0 命中 |
| M2: WFP bug 修复 | Phase 1 结束 | `silence_edr()` 仅阻断 EDR PID |
| M3: CET-safe swap | Phase 1 结束 | CET-on 主机栈追溯通过 |
| M4: Token/Inject 命令 | Phase 1 结束 | CLI 可执行 `steal_token` / `inject` |
| M5: 持久化（service+reg）| Phase 2 中 | 重启后 beacon 自动恢复 |
| M6: DNS C2 | Phase 2 中 | beacon 通过 DNS TXT 通信 |
| M7: KslD 真机 | Phase 3 结束 | H-K 全链路用 KslD 跑通 |
| M8: Win11 + Defender ATP | Phase 3 结束 | 全部 7 内核任务通过 |
| M9: ETW HMAC | Phase 4 中 | Sanctum 不报警 |
