# Windows EDR 内核态技术全景 & 对抗方案完整手册

> 📚 **参考文档** — 外部资料/ API 参考/设计探索，与当前代码状态无关。项目实际能力见 [`README.md`](../../README.md) 与 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md)。

> 2026年6月 | 基于网络搜索实证 + 项目文档综合 | 授权红队研究

---

## 总览：EDR 内核态防御层次图

```
┌─────────────────────────────────────────────────────────┐
│                  VTL1 (Secure Kernel)                   │
│  SKPG | kCFG bitmap | VBS Enclave 内存 | 影子栈保护      │
├─────────────────────────────────────────────────────────┤
│                  VTL0 (Normal Kernel)                   │
│  ① Ps/Ob/Cm 内核回调    ② ETW-TI 原生提供者             │
│  ③ MiniFilter 文件I/O   ④ WFP 网络过滤                 │
│  ⑤ 内核栈检查           ⑥ DKOM 保护/检测                │
│  ⑦ PPL 进程保护         ⑧ kCFG 控制流完整性             │
├─────────────────────────────────────────────────────────┤
│                  用户态（已几乎完全失效）                  │
│  ntdll hook | AMSI | ETW userland                       │
└─────────────────────────────────────────────────────────┘
```

**总结论（2026年）**：用户态层对抗已经基本完成（间接系统调用 + NTDLL 解钩）。战场完全转移到内核态。攻防双方都在这8层上博弈。

---

## 第一层：内核回调（Kernel Callbacks）

### EDR 使用的完整回调列表

| 回调注册函数 | 监控目标 | 典型 EDR 用途 |
|------------|---------|-------------|
| `PsSetCreateProcessNotifyRoutineEx` | 进程创建/终止 | 进程树分析、白名单检查 |
| `PsSetCreateThreadNotifyRoutineEx` | 线程创建/终止 | 远程线程注入检测 |
| `PsSetLoadImageNotifyRoutineEx` | PE 映像加载（EXE/DLL） | 模块加载监控、签名验证 |
| `ObRegisterCallbacks` | 进程/线程句柄操作 | 剥夺对 EDR 进程的 `PROCESS_VM_READ` 等权限 |
| `CmRegisterCallbackEx` | 注册表操作 | 键值修改监控、持久化检测 |
| `IoRegisterBootDriverCallback` | 启动驱动加载 | 早期加载恶意驱动检测 |
| `ExRegisterCallback` | 通用系统通知 | 各类系统事件订阅 |

### 内核回调数组在内存中的位置

```
PspCreateProcessNotifyRoutine       ← 进程回调数组（64个槽）
PspCreateThreadNotifyRoutine        ← 线程回调数组
PspLoadImageNotifyRoutine           ← 镜像加载数组
CallbackListHead (ObRegCallbacks)   ← 双向链表
CmpCallBackVector                   ← 注册表回调
```

### 攻击方法

#### 方法 A：BYOVD → 回调清零（最主流）
```
签名漏洞驱动 IOCTL
  → 内核 R/W 原语
  → 扫描 ntoskrnl.exe 找回调数组地址（特征码扫描）
  → 将 EDR 注册的回调指针清零或重定向

问题：PatchGuard 检测 NULL 指针 → bugcheck！
正确做法：覆写为 KCFG-compliant 的 ret-only stub 地址
  → 回调被调用但立即返回（no-op）
  → PG 看到合法非 NULL 指针，不触发
```

#### 方法 B：kd.exe LotLK（无第三方驱动）
- 启用内核调试模式 (`bcdedit /debug on`)
- 用 `kd.exe`（微软签名合法调试器）直接操作内核内存
- 自动符号解析，无需硬编码偏移（避免 BSOD）
- **检测面**：`bcdedit` 变更 + `kd.exe` 执行 = 高优先级告警

#### 方法 C：RealBlindingEDR 类工具自动化
- 通过特征码扫描动态找回调数组（适配不同 Windows 版本）
- 同时清零 Ps/Ob/Cm 回调 + MiniFilter + ETW-TI
- 高偏移错误风险 → BSOD；需要精确版本适配

### Nyx 影响
- P2.2 `CallbackKit` 实现时必须用 KCFG-compliant ret-stub 覆写，不能 NULL
- 路径：BYOVD → 内核 R/W → 动态特征码扫描 → KCFG-ret 覆写
- 备选路径：kd.exe LotLK（需 bcdedit 预置）
- HVCI 兼容性：**数据节写入 = 兼容**；代码 inline hook = 不兼容

---

## 第二层：ETW-TI（Event Tracing for Windows - Threat Intelligence）

### 检测机制
ETW-TI 是 ntoskrnl.exe 内置的**内核原生**提供者，GUID `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`。在以下系统调用**进入内核的瞬间**生成事件，用户态修改无法影响：

| 监控的系统调用 | 检测目标 |
|-------------|---------|
| `NtAllocateVirtualMemory` | 内存分配（shellcode 落地） |
| `NtProtectVirtualMemory` | 内存属性变更（RW→RX） |
| `NtMapViewOfSection` | 节映射（DLL 注入） |
| `NtWriteVirtualMemory` | 跨进程写（进程注入） |
| `NtReadVirtualMemory` | 跨进程读（凭据窃取） |
| `NtQueueApcThread` | APC 注入 |
| `NtCreateThreadEx` | 远程线程创建 |
| `NtSuspendThread/ResumeThread` | 线程控制 |

**关键**：用户态 `NtTraceEvent` 补丁对 ETW-TI **完全无效**（不同层）。

### 攻击方法

#### 方法 A：S12 BYOVD 单次 QWORD 写（最有效，HVCI 兼容）
```
内核 R/W 原语 → 运行时解析偏移：
  nt!EtwThreatIntProvRegHandle          → _ETW_REG_ENTRY
  + 0x020 (GuidEntry)                   → _ETW_GUID_ENTRY
  + 0x060 (ProviderEnableInfo)
  + 0x000 (IsEnabled) = 0               ← 单次写，TI 停止

永远不硬编码偏移！必须在每次运行时通过 NtQuerySystemInformation 解析。
```

#### 方法 B：HW-BP + NtContinue（用户态，Praetorian 方案）
- 通过硬件断点和 `NtContinue` 在 ETW-TI 回调送达前干预
- 不需要内核 R/W 原语，纯用户态
- 有效绕过 ETW-TI 的用户态触发部分（不能完全屏蔽内核侧）

#### 方法 C：ETW-TI APC 窗口攻击（LACUNA Chain §1.4）
- ETW-TI 的栈采集是异步的：先发 USER_APC，在下一个 alertable wait 才交付
- 在 T+0（事件发生）到 T+5（APC 交付）之间线程处于无监控状态
- 保持线程 non-alertable 完成操作并清理栈，再进入 alertable wait
- ETW-TI 采集到的是事后伪造的干净调用栈

### Nyx 影响
- `blind.rs` 当前补丁 `EtwEventWrite` **无法阻断 ETW-TI**
- P2.1b：`NtTraceEvent` byte0→`0xC3`（阻断用户态 ETW）
- P2.2 `EtwTiKit`：S12 QWORD 写方案（需要 BYOVD/DMA 内核 R/W 原语）
- ETW-TI APC 窗口：集成进 `SleepmaskKit` 的 Foliage 链

---

## 第三层：MiniFilter 驱动（文件 I/O 遥测）

### 检测机制
EDR 通过 `FltMgr.sys` 注册 MiniFilter 驱动，监控所有文件 I/O 操作（读/写/创建/删除）。过滤管理器维护一个**按 altitude 排序的双向链表**，每个 I/O 操作都遍历该链表通知所有注册的 minifilter。

### 攻击方法

#### 方法 A：回调链表断链（Callback Unlinking，当前最有效）
```
BYOVD → 内核 R/W 原语
  → 找到 FltMgr.sys 中的 FltGlobals 结构
  → 遍历 MiniFilter 回调的双向链表（FLT_FILTER 链表）
  → 找到 EDR 的节点
  → 修改 Flink/Blink 指针，将 EDR 的节点从链表中摘除
  → FltMgr 不再向 EDR 发送 I/O 通知
```
- KCFG 使函数指针覆写无效（kCFG 保护调度表）→ 链表断链绕过 kCFG
- HVCI 兼容（数据节操作，非代码修改）

#### 方法 B：Altitude 冲突（历史方法，已部分缓解）
- 注册一个相同 altitude 的 minifilter，阻止 EDR 初始化
- 当前 Windows 版本已对注册表做保护，不那么好用

### Nyx 影响
- P2.2 operator-side 工具需要包含 MiniFilter 断链
- S12 系列文章已记录 MiniFilter 断链的完整实现

---

## 第四层：WFP（Windows Filtering Platform，网络遥测）

### 检测机制
EDR 通过 WFP 注册 Callout 驱动监控网络流量（包检查、连接监控、DNS 查询）。也用于保护 EDR 自身的出站通信。

### 攻击方法

#### 方法 A：EDRSilencer 类工具（用户态，无需驱动）
```python
# 技术流程：
1. CreateToolhelp32Snapshot 枚举进程，找 EDR 进程路径
2. 自定义 FwpmGetAppIdFromFileName0 获取 AppID（不触发 CreateFileW 监控）
3. FwpmEngineOpen0 + FwpmFilterAdd0 添加 WFP 过滤规则：
   - 阻断特定 EDR 进程的出站流量
   - 规则不显示在 Windows Defender 防火墙 GUI
4. EDR 进程继续运行但无法向云端发送告警/遥测
```
- **仅需管理员权限**（不需要内核 R/W）
- 检测：Event ID 5447（WFP 过滤器修改）

#### 方法 B：内核层 WFP Callout 函数指针覆写
```
BYOVD → 内核 R/W
  → 找到 WFP Callout 结构
  → 覆写 EDR 的 Callout 函数指针为 ret-stub
  → EDR 的网络过滤代码被调用但直接返回
```
- S12 系列文章已记录完整实现

### Nyx 影响
- WFP 沉默：操作者层面工具（不需要在 implant 层实现）
- 通过 WFP 沉默 EDR 通信 = SOC 视角失去目标主机可见性
- 检测：Event ID 5447 监控；防御者依赖"遥测消失"告警

---

## 第五层：内核调用栈检查（Kernel Stack Inspection）

### 检测机制
在敏感系统调用（如 `NtAllocateVirtualMemory`）发生时，EDR 遍历调用线程的栈，检查每个返回地址：
- **模块绑定检查**：返回地址必须落在已加载的签名 DLL 范围内
- **unbacked 内存检测**：返回地址指向非映射（私有提交）内存 = shellcode
- **xacone 检测器（VEH + 硬件断点）**：在 `Nt*+0x14`（ret）处拦截，检查 `*RSP` 是否在合法导出范围内

**当前已知检测上限**：即使间接系统调用让 `syscall` 指令的 RIP 在 ntdll（合法），但 **`[RSP]` 仍然指向 implant 内存** → 被 xacone-style 检测器 flag。

### 攻击方法

#### 方法 A：BYOUD-Gap / LACUNA Chain（★ 最优，CET-safe）
```
原理：.pdata 中函数之间存在"gap"地址，
      RtlLookupFunctionEntry(gap_addr) 返回 NULL
      → unwinder 视为 leaf function，RSP 仅进 8 字节，不崩溃

构建假调用链：
  [RSP]   = ntdll gap 地址（leaf frame，无.pdata条目）
  [RSP+8] = kernelbase ghost function 地址
  [RSP+16]= win32u NOP gap 地址（EDR 白名单内）
  ...

零.pdata修改 | CET-safe（不碰 shadow stack）| 无 forensic artifact
ntdll: 3913 gaps | kernelbase: 3982 gaps | win32u: 1242 NOP gaps
```

**Ghost Gadget**：`ntdll+0xFC47B` 处 `JMP [RBX]`，在无.pdata的80字节 ghost 中，既可做执行重定向又可做 bridge frame。

**BYOUD-MF**：`UWOP_PUSH_MACHFRAME`（opcode 10），`KiUserApcDispatcher` 携带它，可做任意 RSP 跳转，无.pdata写。

**BYOUD-RT**：从 `TEB.StackBase (GS:[0x08])` 动态计算 RSP 偏移，无需预标定，适合注入 shellcode。

#### 方法 B：LayeredSyscall（WKL-Sec，CET-off 备选）
- VEH + 硬件断点：在 syscall 时重定向 RIP 进入合法 Win32 API（如 MessageBox），让 OS 自己建立合法的调用帧，再恢复
- 测试 vs Sophos Intercept X：未检测

#### 方法 C：模块踩踏（Module Stomping）
- 将 shellcode 写入合法已加载 DLL 的 `.text` 节
- 执行地址属于合法已知模块 → 栈检查通过
- 配合 threadless injection 效果最佳

### CET（Control-flow Enforcement Technology）约束

| 特性 | 当前状态 |
|-----|---------|
| Win11 24H2 默认启用？ | **否**，opt-in，未来可能默认 |
| 保护机制 | 每次 CALL 同时写 RSP-stack 和只读 shadow stack；RET 时验证一致性 |
| 旧方案影响 | SilentMoonwalk/ThreadStackSpoofer 在 CET 环境下 `#CP` 崩溃 |
| `#CP` handler 宽容性 | **宽容**：若 shadow stack 中任一地址与 RSP 处匹配则修复，不 BSOD |
| JOP gadget | **仍有效**（不触碰 stack） |
| CFOP 绕过 | C++20 协程帧在 heap，指针无 CFI 保护 → 可劫持（USENIX'25） |
| BYOUD-Gap | CET-safe：gap 是 leaf frame，无返回地址操纵 |

### Nyx 影响
- `stack.rs` 必须实现 BYOUD-Gap，不能用旧式 RSP 返回地址操纵
- P2.1a-i：扩展 `resolve.rs` 枚举 .pdata gap 池
- P2.1a-ii：`stack.rs` 真实实现，接入 `syscalls.rs::trampoline_for`

---

## 第六层：DKOM（Direct Kernel Object Manipulation）

### 检测机制
现代 EDR 通过以下结构枚举进程，**多路交叉验证**：
- `EPROCESS.ActiveProcessLinks`（主进程链表）
- 线程列表（`EPROCESS.ThreadListHead`）
- 句柄表
- ETW 遥测

单独断开 `ActiveProcessLinks` **不够**：EDR 通过交叉验证会发现不一致。

### 攻击方法

#### 方法 A：Outflank PatchGuard Peekaboo 方案（HVCI 兼容）
```
EPROCESS.ActiveProcessLinks 断链（Flink/Blink 修改）
+ 注册 PsSetCreateProcessNotifyRoutineEx 终止回调
+ 在进程终止的 callback（CreateInfo==NULL）中：
  检测 ActiveProcessLinks 是否已被修改（Flink->Blink != entry）
  → 在 PspProcessDelete 校验前几微秒 repair：
    *Flink->Blink = OurListEntry
    *Blink->Flink = OurListEntry
→ PatchGuard 看到链表一致，不 bugcheck
```

这是唯一在 PatchGuard + HVCI 约束下可行的持久进程隐藏方案。

### Nyx 影响
- P2.2 `CallbackKit` 需要 signed kernel driver（无法仅靠 implant）
- 进程隐藏属于 operator-side 工具功能

---

## 第七层：PPL（Protected Process Light）/ 进程保护

### 检测机制
EDR 自身进程以 PPL（`PsProtectedSignerAntimalware`）运行：
- 内核 `ObRegisterCallbacks` 在其他进程打开 EDR 进程句柄时剥夺 `PROCESS_TERMINATE` 等权限
- `ZwTerminateProcess` 对 PPL 进程直接拒绝
- 进程终止时触发 `PsSetCreateProcessNotifyRoutine` 回调

### 攻击方法

#### 方法 A：BYOVD ZwTerminateProcess（最直接）
- 内核模式下调用 `ZwTerminateProcess` → 绕过 PPL（内核态有权限）

#### 方法 B：EDR-Freeze（用户态，2025年新技术）
```
无需内核权限，纯用户态：
1. 用 WerFaultSecure.exe（微软签名合法工具）触发对 EDR 进程的 dump
2. MiniDumpWriteDump 内部会 SuspendThread 所有目标进程线程（OS 行为）
3. 立即 SuspendThread WerFaultSecure.exe 自身
4. EDR 进程所有线程无限期挂起（"coma" 状态）
5. EDR 无法监控、上报或响应
```
- **可绕过 PPL**（WerFaultSecure 有特殊权限处理 PPL 进程）
- 仅需管理员权限
- 检测：WerFaultSecure.exe 以 EDR PID 为参数启动

#### 方法 C：注册表/Service 滥用
- 在 EDR 服务更新/重启窗口期降低保护
- `PendingFileRenameOperations` 在重启时替换 EDR 二进制

### Nyx 影响
- EDR-Freeze 是操作者层面的有效工具（无需内核权限）
- 使用 WerFaultSecure.exe 不受 BYOVD blocklist 影响

---

## 第八层：内核 CFG（kCFG）/ 控制流完整性

### 检测机制
kCFG 通过 HVCI 在 VTL1 中维护一个只读 bitmap，标记合法的间接调用目标。任何调用非法目标 → 内核崩溃。

**重要约束**：
- kCFG 是**前向边**（forward-edge）保护，不保护返回地址
- 代码页在 HVCI 下为只读 → 函数指针覆写常触发 kCFG 检查
- 数据节的指针操纵不在 kCFG 保护范围内

### CFOP 绕过（USENIX Security 2025，CISPA）

**Coroutine Frame-Oriented Programming**：
- C++20 协程帧存储在 heap（可写），内含**无 CFI 保护的函数指针**
- 通过堆损坏劫持协程帧的执行指针
- **绕过 CET**（不操纵 return address）
- **绕过 CFG**（利用协程合法代码路径）
- 覆盖：Clang/LLVM、GCC、MSVC；已在 ScyllaDB/SerenityOS 验证

**CVE-2026-40369（2026年新 ntoskrnl.exe 逻辑漏洞）**：
- 允许未授权写操作绕过 `ProbeForWrite` 验证
- 可在用户态触发确定性内核内存写入原语
- 利用链：内存增量原语 → 破坏内核结构 → 劫持执行流 → KASLR 绕过

### Nyx 影响
- P2.2 kernel tier 的 `CallbackKit` 实现应使用 KCFG-compliant ret-only stub
- `PatchGuardKit` 本质上是 DKOM（数据节），天然 HVCI/KCFG 兼容

---

## 第九层：VBS Enclave（新兴，隐藏执行）

### 机制
VBS Enclave 在 VTL1 运行，比 VTL0（普通内核）权限更高，且对 VTL0 **不可见**（包括 EDR 内核驱动）。API 调用从 enclave 内部发出时，对 EDR 的钩子完全不可见。

### Mirage / BYOVE 技术（Akamai，DEF CON 33 2025）
```
BYOVE 攻击链：
1. 找漏洞 enclave 模块（CVE-2023-36880，Edge enclave 模块）
2. 利用漏洞获得 VTL1 内 R/W 能力
3. Shellcode 存储在 VTL1 enclave 内存（EDR 无法扫描）
4. 需要执行：短暂投入 VTL0 → 执行 → 擦除
5. 内存扫描在 VTL0 找不到持续驻留代码
```

检测难点：VBS 的隔离设计本身就造成防御者的结构性盲点。

### Nyx 影响
- P2.3 目标：VBS Enclave 作为 beacon payload 的安全存储
- 挑战：no_std + PIC 环境下 enclave API 调用兼容性评估

---

## 第十层：内存扫描器（Memory Scanners）

### 检测机制与对应扫描器

| 扫描器 | 检测原理 | 检测目标 |
|-------|---------|---------|
| **Moneta** | 可执行+私有提交内存异常 | 非映射的 RX 内存 |
| **PE-sieve** | 磁盘 PE vs 内存 PE 比对 + 返回地址检查 | 被修改的 DLL、注入代码 |
| **BeaconEye** | 堆扫描找 CS 配置结构 | CS beacon 配置 |
| **MalMemDetect** | hook `RtlAllocateHeap`，检查调用时的返回地址 | 从非法地址调用分配器 |
| **Hunt-Sleeping-Beacons (HSB)** | wait-reason + 调用栈组合检测 | 睡眠中的 beacon |

**HSB 更新后的检测逻辑**（对 FOLIAGE 的更新）：
- wait-reason `UserRequest` **AND** `KiUserApcDispatcher` 在调用栈上 → flag
- 没有 call-stack spoof 的普通 FOLIAGE 实现绕不过

### 攻击方法

#### 方法 A：SleepmaskKit Foliage + Stack Spoof 集成
```
在睡眠窗口期：
  ① 加密 .text 节（SystemFunction032 RC4，advapi32 image-commit）
  ② RX → RW 内存权限
  ③ WaitForSingleObject（wait-reason UserRequest，不是 DelayExecution）
  ④ APC 帧通过 BYOUD-Gap 伪造（KiUserApcDispatcher 不出现在栈上）
  ⑤ ETW-Ti APC 窗口：non-alertable 操作，alertable wait 时提供干净栈
  
结果：HSB 零命中 | Moneta 通过（RC4 加密后是私有提交但非可执行）
      PE-sieve 通过（.text 已加密，签名不匹配不重要）
```

#### 方法 B：模块踩踏（Module Stomping）
- 将 shellcode 写入合法 DLL 的 `.text` 节（RW→RX）
- Moneta："可执行+私有提交"→ 变为"可执行+image-backed"
- PE-sieve：会发现内容不匹配，但模块本身来自磁盘映射

### Nyx 影响
- P2.1a-iii：SleepmaskKit Foliage 必须集成 stack spoof（P2.1a-ii 先做）
- P2.1c：ProcessInjectKit 模块踩踏

---

## 第十一层：EDR-Freeze（新兴用户态技术）

### 机制（已在第七层详述）
- WerFaultSecure.exe + MiniDumpWriteDump + 自身挂起 = EDR 进程无限期 coma
- 纯用户态，无需内核权限，可绕过 PPL

### 检测与缓解
- EDR 厂商正在开发"watchdog"机制（检测自身线程被挂起 → 自动恢复或告警）
- 监控 WerFaultSecure.exe 以 EDR PID 为参数的启动

---

## 第十二层：kd.exe LotLK + BTR 驱动滥用（Living off the Land Kernel）

### kd.exe 内核调试器滥用
- `kd.exe`（微软签名）= 合法任意内核内存 R/W
- 流程：`bcdedit /debug on` → 重启 → `kd.exe` 清零回调
- 优点：无第三方驱动加载，绕过 BYOVD 检测签名
- 缺点：`bcdedit` 变更是强 IOC，需要提前预置

### BTR 驱动滥用（Check Point BH2026，8月）
- Windows Defender Boot-Time Removal 驱动（微软自带）
- 被逆向为内核操作原语
- 无 blocklist 风险，无第三方驱动签名
- 技术细节 2026年8月发布

---

## 完整攻击面对照表

| EDR 内核层 | 监控机制 | 主要绕过方法 | HVCI 兼容 | Nyx 现状 |
|-----------|---------|------------|----------|---------|
| 内核回调 (Ps/Ob/Cm) | 进程/线程/注册表事件 | BYOVD→KCFG-ret覆写；kd.exe LotLK | ✅ 数据节 | P2.2 CallbackKit 待实现 |
| ETW-TI | NtAlloc/Map/Protect等11个syscall | BYOVD→ProviderEnableInfo=0；HW-BP+NtContinue | ✅ 数据节 | P2.2 EtwTiKit 待实现 |
| MiniFilter | 文件 I/O | FltGlobals 链表断链 | ✅ 数据节 | P2.2 待实现 |
| WFP | 网络流量 | EDRSilencer(用户态)；Callout覆写(内核) | ✅ | P2.2 待实现 |
| 内核栈检查 | 返回地址合法性 | BYOUD-Gap/LACUNA；模块踩踏 | ✅ | P2.1a-ii stack.rs 待实现 |
| DKOM/进程可见性 | 多路交叉验证 | Outflank 时序修复方案 | ✅ 数据节 | P2.2 待实现 |
| PPL 进程保护 | 内核句柄剥夺 | BYOVD ZwTerminate；EDR-Freeze | N/A(用户态) | operator tool |
| kCFG | 间接调用目标合法性 | CFOP(协程帧)；数据节不在保护范围 | 数据节操作不受影响 | 间接影响 CallbackKit |
| VBS Enclave | VTL0 无法读VTL1 | BYOVE + Mirage | VTL1 固有隔离 | P2.3 research |
| 内存扫描 | 可执行私有内存/PE比对 | 睡眠加密+栈spoof；模块踩踏 | ✅ | P2.1a-iii/P2.1c 待实现 |
| EDR-Freeze | 进程活性 | WerFaultSecure + coma 状态 | ✅ 用户态 | operator tool |
| 遥测丢失检测 | "遥测消失" | 需要 NDR 兜底检测 | N/A | NDR 无法规避 |

---

## 综合攻击链设计（Red Team Engagement 完整流程）

### 阶段 0：预置（管理员权限，低噪声）
```
A. (可选) bcdedit /debug on + 重启 → kd.exe LotLK 预置
B. (推荐) 准备 BYOVD 驱动包 + 当前未被 blocklist 的驱动
C. EDRSilencer 类工具部署 → WFP 沉默 EDR 通信（无需内核）
```

### 阶段 1：内核 R/W 原语获取
```
BYOVD 首选路径：
  → 加载 loldrivers.io 当前未封锁驱动
  → IOCTL → 任意内核 R/W
  → Sysmon EID 6 可检测（噪声点）

备选（如 BH2026 后可用）：
  → BTR 驱动滥用（系统自带，不受 blocklist）
```

### 阶段 2：全面 EDR 盲化（有顺序）
```
按顺序执行（减少检测窗口）：
① ETW-TI blind (ProviderEnableInfo=0)     ← 首先！避免后续操作被记录
② Ps/Ob/Cm 回调清零（KCFG-ret 覆写）
③ MiniFilter 链表断链（FltGlobals）
④ WFP Callout 覆写
⑤ EDR-Freeze 作为补充（coma 进程）
```

### 阶段 3：Implant 自我保护（P2.1）
```
① BYOUD-Gap stack spoof（修复[RSP]检测）
② SleepmaskKit Foliage（睡眠期加密+HSB规避）
③ NtTraceEvent 补丁（用户态ETW）
④ ProcessInjectKit 模块踩踏（解决内存扫描）
```

---

## 诚实的防御天花板（攻击者视角的真实限制）

| 防御层 | 能被全部绕过？ | 残留风险 |
|-------|-------------|---------|
| EDR 内核态（全部9层） | ✅ 理论上可以 | 每层操作本身都有 IOC |
| "遥测消失"检测 | ❌ 无法规避 | SOC 会注意到 EDR 静默 |
| NDR（网络检测响应） | ❌ 无法规避 | C2 流量在网络层可见（需 malleable C2） |
| SIEM/历史日志 | 部分 | 盲化前的行为已被记录 |
| HVCI+VBS 开启时 | 内核 tier 降级 | 只能依赖用户态 floor |
| SKPG（VTL1 PatchGuard） | 几乎未知 | largely unexplored，难评估 |

**最终结论**：内核层 EDR 对抗是一场**时间窗口**游戏，不是"无痕"。操作速度（盲化 EDR 到完成目标）是关键变量。配合 malleable C2（Phase 1 ✅）和流量重定向（P4），才能构建完整的隐蔽链。

---

## Nyx 项目当前缺口汇总（对照完整攻击面）

### ✅ 已实现
- 用户态 NTDLL hook 绕过（间接系统调用）
- AMSI/ETW userland 盲化（`blind.rs`，需升级为 NtTraceEvent）
- 反调试、NTDLL 解钩、SSN 解析

### 🚧 P2.1（用户态 floor，无内核）
- `stack.rs`：BYOUD-Gap 实现（先做）
- `kits.rs`：SleepmaskKit Foliage（依赖 stack.rs）
- `blind.rs`：升级为 NtTraceEvent 补丁
- `kits.rs`：ProcessInjectKit 模块踩踏

### 🔴 P2.2（内核 tier，operator-side 工具）
- ETW-TI：ProviderEnableInfo QWORD 写
- 内核回调：KCFG-ret 覆写（所有 Ps/Ob/Cm）
- MiniFilter：FltGlobals 链表断链
- WFP：Callout 函数指针覆写
- DKOM：Outflank 时序修复进程隐藏
- 工具包装：VulnDriverKit（operator 选驱动）

### 🔬 P2.3（研究，未来）
- VBS Enclave 存储（BYOVE）
- CFOP 利用链（如果目标内核使用 C++20 coroutines）
- BTR 驱动滥用（等 BH2026 8月细节）
- EDR-Freeze 集成
