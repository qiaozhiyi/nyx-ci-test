# Windows 内核层 EDR 对抗 — 学术论文全景数据库

> 📚 **参考文档** — 外部资料/ API 参考/设计探索，与当前代码状态无关。项目实际能力见 [`README.md`](../../README.md) 与 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md)。

> 覆盖顶会论文、安全大会 Briefings、arXiv 预印本 | 2022–2026 | 2026-06-23 整理

---

## 一、顶会学术论文（USENIX / IEEE S&P / CCS / NDSS）

---

### 论文 P1
**标题：** *"Await() a Second: Evading Control Flow Integrity by Hijacking C++ Coroutines"*（CFOP）
**会议：** USENIX Security 2025（34th USENIX Security Symposium）
**作者：** Marcos Bajo, Christian Rossow（CISPA Helmholtz Center for Information Security）
**链接：** https://www.usenix.org/conference/usenixsecurity25/presentation/bajo
**演示：** Black Hat USA 2025（同年）
**arXiv/代码：** GitHub (cispa-io/cfop)

#### 核心贡献
- 发现 **C++20 协程帧（coroutine frame）** 存储在 heap（可写），包含**无 CFI 保护的函数指针**（resume/destroy 指针）
- 提出 CFOP：通过堆损坏劫持协程帧，绕过 Intel CET + Windows CFG，实现任意代码执行
- 测试平台：MSVC + Win11（CET+CFG 启用），GCC+Linux，Clang+Linux
- 两个原语：
  - **Frame Manipulation**：覆写已有协程帧的执行指针
  - **Frame Injection**：注入新协程帧，重定向执行流
- 覆盖率：MSVC/GCC/Clang 三大编译器；ScyllaDB/SerenityOS 真实软件验证

#### 关键技术要点
```
CET Shadow Stack 保护 return address（后向边）
CFG 保护间接调用目标合法性（前向边）

C++20 协程 resume/destroy 指针在 heap：
  - 不受 shadow stack 保护（不是 return address）
  - 编译器通常不对协程指针做 CFG bitmap 标注
  → 两重保护都绕过

攻击路径：heap uaf/oob → coroutine frame → frame.resume_fn = &gadget
```

#### 防御状态
- 无现成修复；需要编译器级别结构性变更（将协程指针移至不可写内存）
- MSVC/GCC/Clang 均已被通知，但修复周期长

#### Nyx 影响
- 如果目标 EDR 驱动使用 C++20 coroutines（C++20/23 内核驱动极少见，但有先例）
- CFOP 可绕过 EDR 的 kCFG 保护，实现 kernel R/W 原语获取
- 更直接：在攻击 LSASS 等用户态目标（coroutine 使用广泛）时绕过 CFI

---

### 论文 P2
**标题：** *"EvilEDR: Repurposing EDR as an Offensive Tool"*
**会议：** USENIX Security 2025（34th USENIX Security Symposium）
**作者：** Kotaiba Alachkar, Dirk Gaastra, Eduardo Barbaro, Michel van Eeten, Yury Zhauniarovich
**链接：** https://www.usenix.org/conference/usenixsecurity25/presentation/alachkar
**Artifacts：** Zenodo DOI: 10.5281/zenodo.14732733

#### 核心贡献
- 首次系统化提出"EDR 重用"（repurposing）攻击模型：不破坏 EDR，而是**利用 EDR 的合法功能作为攻击载体**
- 证明攻击者在进入 EDR 管理控制台后，可以：
  1. 通过 EDR 自身响应控制台执行任意命令
  2. 通过 EDR 受信任通信信道渗出数据/工具
  3. 利用 EDR 被动采集信息辅助横向移动
  4. 注册自己的 EPP（端点保护平台）为默认策略，冒充合法安全进程
  5. 将目标主机从网络隔离，切断 SOC 可见性

#### 攻击面分析
```
EDR 攻击面层次：
  [管理控制台] → 凭据攻击、会话劫持
  [云端 API]  → API token 盗用
  [Agent 通信信道] → MITM（前提：agent 无双向 TLS 互认证）
  [本地 Agent 权限] → 滥用 Agent 已有的高权限
```

#### 与内核回调的关系
- EDR 利用的内核机制（PsSetCreateProcessNotifyRoutine 等）在 repurposing 后被攻击者继承
- repurposing 不删除回调，而是将回调收集到的数据转发给攻击者，比盲化 EDR 更隐蔽

#### Nyx 影响
- P2.2 EvilEDR 路径：替代 BYOVD 的最低噪声路径
- 前提：engagement 阶段拿到 EDR 管理控制台凭据
- 实现门槛：依赖具体 EDR 产品的 API，不能做成通用 kit

---

### 论文 P3
**标题：** *"VIPER: Spotting Syscall-Guard Variables for Data-Only Attacks"*
**会议：** USENIX Security 2023
**作者：** Pengfei Zhong et al.（Pennsylvania State University）
**链接：** https://www.usenix.org/conference/usenixsecurity23/presentation/zhong
**代码：** https://github.com/psu-security-universe/viper

#### 核心贡献
- 引入"**syscall-guard variables**"概念：控制程序是否调用安全敏感系统调用的非控制流数据变量
- 提出自动化识别工具 VIPER（Branch Force + VariableRator 两阶段）
- 在 13 个程序中发现 **34 个之前未知的 syscall-guard variables**
- 对 SQLite 和 V8 构建 4 个新的 data-only 攻击

#### 技术机制
```
Branch Force 方法：
  用 AFL 模糊测试器强制翻转每个条件分支
  → 观察是否触发新的安全敏感 syscall
  → 如果是，该分支即为 syscall-guard

VariableRator：
  对 syscall-guard 变量进行数据流分析
  → 判断是否可通过内存错误漏洞（OOB/UAF）污染
  → 确认可利用性
```

#### 对 EDR 对抗的意义
- **data-only 攻击在 CET + CFG 下完全有效**（不触碰返回地址或间接调用目标）
- 可以通过污染 syscall-guard variable，让程序在 EDR 不知情的情况下触发敏感系统调用
- 应用于 Windows：修改控制"是否做安全检查"的标志变量（例如 `g_bSecureMode` 类全局量）

#### Nyx 影响
- 理论上可构建 data-only 攻击绕过 ETW-TI 的触发条件（修改内核内的 syscall guard 变量）
- 研究方向：寻找 ntoskrnl 中控制 ETW-TI 事件发射的 guard 变量（需要内核 R/W 原语）

---

### 论文 P4（NDSS 2026）
**标题：** *"PCPLost: Cross-Cache Attacks for the Linux Kernel via PCP Massaging"*
**会议：** NDSS 2026
**链接：** https://www.ndss-symposium.org/

#### 关联意义
- 展示了现代内核内存分配器保护如何被旁道绕过
- **Windows 类比**：同样的方法论可应用于 Windows 内核堆（pool）布局操作，辅助 BYOVD 提权链中的堆喷/堆操纵原语

---

## 二、安全大会 Briefings（Black Hat / DEF CON）

---

### 论文 B1
**标题：** *"Out Of Control: How KCFG and KCET Redefine Control Flow Integrity in the Windows Kernel"*
**大会：** Black Hat USA 2025
**演讲者：** Connor McGarr
**视频：** YouTube（已公开）
**幻灯片：** https://blackhat.com/us-25/briefings/schedule/

#### 核心贡献
- 第一次系统阐明 **kCFG（Kernel Control Flow Guard）** 和 **kCET（Kernel Control Flow Enforcement Technology）** 的完整实现
- kCFG 依赖 VTL1 中的只读 bitmap（HVCI 管理），标记合法间接调用目标
- kCET = 内核态 shadow stack（Supervisor Shadow Stack, SSS），保护返回地址
- 分析了 **IAT（Import Address Table）被排除在 kCFG 保护范围之外**的设计漏洞

#### kCFG/kCET 详细机制
```
kCFG 工作原理：
  - 编译时标注合法 indirect call target，写入 bitmap
  - bitmap 存储在 VTL1（HVCI 管理），VTL0 只读
  - 每次间接调用前，硬件/软件检查目标是否在 bitmap

kCET 工作原理：
  - CALL 指令同时写 RSP-stack 和 Shadow Stack（SSS）
  - RET 时 CPU 比较两者；不一致 → #CP fault
  - SSS 存储在 VTL1（Hypervisor 管理），VTL0 不可写

排除项（攻击者可利用）：
  - IAT 不在 kCFG 保护范围 → IAT hook 仍可行（如果有写权限）
  - Data-only 攻击完全绕过两者
  - JOP（Jump-Oriented Programming）不受 shadow stack 影响
```

#### Nyx 影响
- 确认：BYOUD-Gap（LACUNA Chain）是当前对 kCET 正确处理的 CET-safe 栈 spoof
- IAT 排除项：如果能写 ntoskrnl IAT，可以做 kCFG-bypassing IAT hook（需要内核 W 权限）
- Data-only 路径（KCET 不保护）：VIPER 方法、Outflank 数据节操作

---

### 论文 B2
**标题：** *"Windows Downdate: Downgrade Attacks Using Windows Updates"*
**大会：** Black Hat USA 2024 + DEF CON 32（2024年8月）
**演讲者：** Alon Leviev（SafeBreach）
**白皮书：** https://safebreach.com/blog/2024/windows-downdate/

#### 核心贡献（极其重要）
- 发现可以**接管 Windows Update 进程**，将 OS 组件（内核、驱动、DLL）**降级到已知漏洞版本**
- 系统显示"完全更新"但实际运行有漏洞的旧代码
- **最关键发现：即使 UEFI Lock 也无法阻止 VBS/HVCI 的禁用**

#### 具体攻击链
```
步骤 1：修改注册表项（Update 文件解析器路径）
        → 劫持 Windows Update 流程

步骤 2：构造自定义降级包
        → 将 ntoskrnl.exe 降至存在 BYOVD 相关漏洞的版本
        → SFC.exe 修改为忽略这些更改

步骤 3（最关键）：强制 VBS 降级
        → 触发 VBS/HVCI 启动验证失败
        → 系统在 boot 时放弃 VBS（以兼容性为由）
        → HVCI 被禁用，kCFG 失效，unsigned kernel code 可加载

步骤 4：加载未签名 rootkit
        → DSE（Driver Signature Enforcement）已无效
        → 完整内核控制
```

#### CVE 状态
- Microsoft 认为"需要管理员权限执行，不跨越安全边界"→ 拒绝修复核心机制
- 部分具体提权漏洞已修复（CVE 分配）

#### Nyx 影响
- **P2.2 VulnDriverKit 的终极形态**：如果目标环境存在降级窗口，可将 HVCI 降级后加载任意驱动
- 操作复杂，需要 admin 权限 + 重启，适合 long-term engagement
- 结合 engagement 初期的持久化，预置降级然后等待维护窗口

---

### 论文 B3
**标题：** *"HookChain: A New Perspective for Bypassing EDR Solutions"*
**大会：** DEF CON 32（2024年8月）
**演讲者：** Helvio Carvalho Junior
**arXiv：** arXiv:2404.16856
**GitHub：** [Helvio Junior 仓库]

#### 核心贡献
- 对 26 款 EDR 产品测试，**88% 绕过率**
- 不修改 ntdll.dll，而是在**更高层（kernel32.dll IAT）** 截获执行流
- 关键洞察：EDR 几乎全部 hook 在 ntdll，而 kernel32 层很少被监控

#### 三原语组合
```
原语 1：IAT Hook（kernel32.dll）
  - 修改 ReadFile 等 API 的 IAT 条目
  - 重定向到 HookChain 的 stub

原语 2：动态 SSN 解析
  - Halo's Gate 方法：扫描"未 hook 的邻居"或 patch 后的字节
  - 运行时得到正确 syscall number

原语 3：间接系统调用
  - 在 stub 中执行：jmp 到 ntdll 中已有的 syscall;ret gadget
  - 调用栈看起来是从 ntdll 发起的
```

#### 执行上下文
- 无需修改源代码，纯 post-exploitation 框架
- EDR 监控的是 ntdll hook，完全看不到 IAT 层劫持
- 推动了 EDR 向内核层转移监控（这正是 ETW-TI 的加固动力）

#### Nyx 影响
- `syscalls.rs` 已覆盖原语 2+3（间接系统调用 + SSN 解析）
- IAT hook 不在 Nyx 的 implant 功能中（属于 loader/初始化阶段）

---

### 论文 B4
**标题：** *"StackMoonwalk: Bypassing EDR Stack Monitoring with Advanced Stack Spoofing"*
**大会：** DEF CON 31（2023年8月）
**演讲者：** SpecterDev（Namaszo）
**链接：** 演讲录像（DEF CON 官方）

#### 核心贡献（栈 spoof 的奠基性工作）
- **SilentMoonwalk**：完全动态调用栈 spoofer
  - ROP 去同步化：让 stack unwinder 和真实执行流脱钩
  - 构造动态大小的合成帧，"月球漫步"式拼接假调用链
- **VulcanRaven**：基于 SilentMoonwalk 的 synthetic thread stack 构建

#### Gen-2 spoof 的核心问题（被后续研究发现）
```
SilentMoonwalk 的 Achilles 跟：
  - 它修改 RSP-stack 上的返回地址
  - Windows 11 + Intel CET shadow stack：RSP-stack 和 SSS 比较
  - 修改 RSP-stack 但 SSS 不变 → MISMATCHES → #CP fault
  
这就是为什么需要 BYOUD（P3 方案）
```

#### Nyx 影响
- `stack.rs` skeleton 最初参考的可能是这个方向
- **不能在 CET 环境使用 SilentMoonwalk/VulcanRaven 的方法**
- 必须升级为 LACUNA Chain/BYOUD-Gap

---

## 三、CVE / 安全公告（内核层相关）

---

### CVE C1+C2（ETW 子系统 LPE）
**CVE-2025-47985**：ETW 不受信任指针解引用（CWE-822）
**CVE-2025-49660**：ETW `_ETW_REG_ENTRY` 引用计数溢出导致 Use-After-Free（CWE-416）
**来源：** StarLabs Research，2025年7月公开
**链接：** starlabs.sg

#### 详细技术（CVE-2025-47985）
```
漏洞位置：ETW 子系统的 LPC 消息处理器
攻击方式：发送包含未验证指针的 LPC 消息
内核效果：不受信任指针 dereference → 任意内核 R/W
利用结果：低权限 → SYSTEM 提权（CVSS 7.8）
```

#### 详细技术（CVE-2025-49660）
```
漏洞位置：ntoskrnl.exe ETW provider 注册/注销
CWE：
  - CWE-416：UAF（_ETW_REG_ENTRY 对象被提前释放）
  - CWE-190：引用计数整数溢出触发 UAF
利用结果：低权限 → 内核 R/W → SYSTEM（CVSS 7.8）
```

#### Nyx 影响（重大发现）
> **这是唯一已知的可从低权限直接获得内核 R/W 原语的 ETW 内核漏洞！**

- 如果目标系统未打 2025-07 补丁，可用 CVE-2025-47985/49660 **无需 BYOVD** 直接获得内核 R/W
- 获得内核 R/W 后，执行 P2.2 的 ETW-TI 盲化、回调清零等所有操作
- 补丁状态：2025年7月 Patch Tuesday 修复
- 实战价值：企业环境补丁延迟普遍，3-6 个月窗口期

---

### CVE C3
**CVE-2026-40369**：ntoskrnl.exe 逻辑漏洞（ProbeForWrite 绕过）
**发现日期：** 2026年5月
**CVSS：** 严重
**来源：** rewterz.com / securityonline.info

#### 详细技术
```
漏洞位置：ntoskrnl.exe 中的系统调用处理器（NtQuerySystemInformation）
利用原理：
  - 绕过 ProbeForWrite 验证（应该确保目标地址在用户空间）
  - 可从用户进程触发内核内存"增量写入"（increment primitive）
  - 利用链：memory increment → 破坏内部结构 → 重定向执行 → KASLR bypass
利用结果：浏览器沙箱逃逸 + 本地提权
```

#### Nyx 影响
- 2026年的新漏洞，大量企业尚未补丁
- 可作为"无驱动内核 R/W 原语获取"的替代路径（替代 BYOVD）
- 结合 P2.2 的内核操作，完全不需要第三方驱动加载

---

### CVE C4+C5（2025年 Windows 内核 LPE）
**CVE-2025-62215**：Windows 内核竞态条件导致 LPE
**CVE-2025-24063**：Windows 内核堆缓冲区溢出
**发现/补丁：** 2025年11月 / 2025年初

---

## 四、研究工具 / 重要技术文档

---

### 工具 T1
**项目：** Sanctum EDR（0xflux/Sanctum，GitHub + fluxsec.red）
**性质：** 开源 Rust 语言 EDR 实验性实现

#### 防御视角最新检测技术
Sanctum EDR 集成以下检测机制，直接对应我们的攻击面：

| 检测功能 | 检测机制 | 针对的攻击 |
|---------|---------|----------|
| Ghost Hunting | ETW-TI + syscall hook 多源相关 | 内存注入类操作 |
| 栈帧合法性 | 调用栈 unwind + 模块归属验证 | SilentMoonwalk 类 spoof |
| BYOVD 检测 | Sysmon EID 6 + loldrivers hash | 漏洞驱动加载 |
| ETW-TI 盲化检测 | ProviderEnableInfo 完整性监控 | S12 QWORD 写方案 |

#### 对 Nyx 的意义
- Sanctum 是当前最全面的"攻防对照"项目，代码级别理解防御
- 其"Ghost Hunting"的 ETW-TI 监控是对我们 blind.rs 升级的最直接压力

---

### 工具 T2
**项目：** LACUNA Chain（0xmaz.me, 2026年6月发布）
**性质：** BYOUD-Gap call stack spoof 技术文档 + PoC

#### 核心数据
```
.pdata gap 统计（Windows 11 24H2）：
  ntdll.dll:       3913 gaps（.pdata 函数间隙地址）
  kernelbase.dll:  3982 gaps
  win32u.dll:      1242 NOP gaps（3+ NOP 对齐空洞）

Ghost Gadget（ntdll+0xFC47B）：
  位置：80字节的 "ghost function" 中（无.pdata条目）
  指令：JMP [RBX]
  用途：执行重定向 + bridge frame 构建
  
BYOUD-MF（Machine Frame Technique）：
  利用 UWOP_PUSH_MACHFRAME（unwind code opcode 10）
  来自：KiUserApcDispatcher 携带此 opcode
  效果：任意 RSP 跳转，零.pdata修改，CET-safe
  
BYOUD-RT（Runtime Technique）：
  从 TEB.StackBase（GS:[0x08]）动态计算 RSP
  适合：注入的 shellcode 无法预标定的场景
```

#### 分段 frame 构建（完整链）
```asm
; 完整 BYOUD-Gap 欺骗栈帧（简化伪代码）
[RSP]    = ntdll_gap_1      ; leaf frame：没有.pdata，RSP+8直接到下一帧
[RSP+8]  = kernelbase_gap_2 ; 非leaf frame：.pdata查找返回合法unwind info
[RSP+16] = ntdll_ghost_JMP  ; ghost gadget桥接，连接到win32u
[RSP+24] = win32u_nop_gap   ; NOP对齐空洞，CET不检查（leaf）
[RSP+32] = ntdll_export_fn  ; 最终"来源"，EDR白名单中的合法导出
```

#### CET-safe 证明
```
Gap 地址特性：
  - RtlLookupFunctionEntry(gap_addr) == NULL
  - unwinder 视为 leaf function
  - CALL 时不在 shadow stack 写 return address（leaf 不保存）
  - RET 时不做 shadow stack 比较
  → 整个链路没有任何位置触发 #CP fault
```

---

### 工具 T3
**项目：** Windows Downdate / PatchGuard Peekaboo（Outflank）
**来源：** outflank.nl（2026年1月）

#### Outflank PatchGuard Peekaboo 时序修复方案
```
目标：进程隐藏（EPROCESS.ActiveProcessLinks 断链）
问题：PatchGuard 检测断链 → bugcheck

解决方案（精确时序）：
  1. 注册 PsSetCreateProcessNotifyRoutine 回调（CreateInfo == NULL = 终止事件）
  2. 断开 ActiveProcessLinks（正常操作期）
  3. 在进程终止事件前，回调中检测 Flink->Blink 不一致
  4. 在 PspProcessDelete 校验窗口之前：
     *Flink->Blink = OurListEntry
     *Blink->Flink = OurListEntry
  5. PatchGuard 扫描时：链表一致，不 bugcheck
```

---

## 五、行业报告 / 高质量技术 Blog

---

### 报告 I1
**来源：** fluxsec.red（0xflux，Sanctum EDR 作者）
**重要文章：**
- "Alt Syscalls in Windows 11"（2025）：分析 Win11 引入的"替代系统调用表"机制，允许虚拟化环境替换 syscall handler
- "Kernel ETW Blind Spot Analysis"：逐一分析 ETW-TI 的 11 个监控 syscall 和旁路方法

---

### 报告 I2
**来源：** 0xmaz.me（"LACUNA Chain"作者）
**重要文章：**
- "LACUNA Chain: CET-safe call stack spoofing via .pdata gaps"（2026-06）
- 附带完整 Rust PoC 实现

---

### 报告 I3
**来源：** S12（Medium）
**系列文章：** "BYOVD: Bring Your Own Vulnerable Driver" 技术系列
- Part 1：ETW-TI ProviderEnableInfo 盲化
- Part 2：Ps/Ob/Cm 内核回调清零（KCFG-ret 覆写）
- Part 3：MiniFilter 链表断链（FltGlobals traversal）
- Part 4：WFP Callout 函数覆写

---

### 报告 I4
**来源：** SafeBreach（Alon Leviev）
**报告：** "Windows Downdate" 完整技术报告
**链接：** safebreach.com/blog/2024/windows-downdate/

---

### 报告 I5
**来源：** StarLabs Research（Singapore）
**报告：** CVE-2025-47985 / CVE-2025-49660 ETW UAF/指针解引用技术分析
**链接：** starlabs.sg

---

### 报告 I6
**来源：** Akamai Security Research（Ori David）
**报告：** "Abusing VBS Enclaves to Create Evasive Malware"（2025-02）
**DEF CON 33 演讲：** "Mirage: Hiding Malicious Code Inside VBS Enclaves"（2025-08）
**GitHub：** Akamai-Security-Research/mirage-vbs-enclave

---

### 报告 I7
**来源：** Connor McGarr 个人博客
**链接：** connormcgarr.github.io
**重要文章：**
- "Kernel-mode Hardware-enforced Shadow Stack" 深度分析
- "Exploit Development: KCFG Internals and Bypass Primitives"

---

## 六、论文对应的 Nyx 建设路径总图

```
P1 CFOP → 未来利用链（如果目标 EDR/OS 使用 C++20 coroutines）
P2 EvilEDR → P2.2 operator tool：EvilEDR 路径（替代 BYOVD）
P3 VIPER → P2.3 研究：syscall-guard variable 定位（ETW-TI bypass 新方向）
B1 KCFG/KCET → P2.1a-ii stack.rs：确认 BYOUD-Gap 是唯一 CET-safe 路径
B2 Downdate → P2.2 VulnDriverKit：降级 HVCI，loader 任意驱动（long-term）
B3 HookChain → P1.x 已实现（间接 syscall + SSN 解析）
B4 StackMoonwalk → 历史参考，Gen-2 已被 CET 淘汰
C1/C2 ETW CVE → P2.2 无驱动内核 R/W 路径（目标未打 2025-07 补丁时）
C3 CVE-2026-40369 → P2.2 无驱动内核 R/W 路径（目标未打 2026-05 补丁时）
T2 LACUNA Chain → P2.1a-i/ii 直接实现参考
T3 Outflank Peekaboo → P2.2 进程隐藏参考实现
I5 ETW CVE 分析 → P2.2 EtwTiKit：CVE 路径获取内核 R/W
I6 Mirage/BYOVE → P2.3 VBS Enclave 实现参考
```

---

## 七、关键知识点汇总（论文结论速查）

| 结论 | 来源论文 | 可信度 |
|------|---------|-------|
| C++20 协程帧指针不受 CET/CFG 保护 | CFOP (P1, USENIX'25) | ★★★★★ |
| ETW-TI 可通过单次 QWORD 写盲化 | S12 系列 (I3) + 多个验证 | ★★★★★ |
| .pdata gap 是 CET-safe stack spoof 的基础 | LACUNA Chain (T2) | ★★★★★ |
| HVCI 可通过 Downdate 禁用 | Downdate (B2, BH'24) | ★★★★★ |
| EDR 可以被"重用"而非破坏 | EvilEDR (P2, USENIX'25) | ★★★★★ |
| ETW 子系统本身存在 LPE 漏洞（无需驱动） | StarLabs (C1/C2) | ★★★★★ |
| MiniFilter 必须用链表断链（KCFG 防止函数覆写） | S12 Part 3 (I3) | ★★★★☆ |
| 88% EDR 在 kernel32 IAT 层无监控 | HookChain (B3, DC32) | ★★★★☆ |
| KCFG IAT 不在保护范围内 | KCFG/KCET (B1, BH'25) | ★★★★☆ |
| VBS Enclave 对 VTL0 完全不可见 | Mirage (I6, DC33) | ★★★★★ |
| syscall-guard variable 攻击绕过 CET+CFG | VIPER (P3, USENIX'23) | ★★★★☆ |
| PatchGuard 可通过时序修复绕过 | Outflank Peekaboo (T3) | ★★★★☆ |
