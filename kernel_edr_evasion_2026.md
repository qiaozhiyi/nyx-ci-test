# Windows 内核层 EDR 对抗 — 2026年6月最新研究综合

> 网络搜索实证，覆盖学术会议、行业研究、PoC 仓库。授权红队研究用途。

---

## 一、2026 内核层格局总览

2026 年中的核心趋势：**用户态 hook 已基本失效**（间接/直接系统调用普及），攻击者全面向内核层集中，且正在从"破坏 EDR"（BYOVD kill）演进为"利用受信任的系统组件"（Living off the Land Kernel, LotLK）。

防御侧反应：
- EDR 越来越多依赖 ETW（Event Tracing for Windows）内核层遥测，而非单纯用户态 hook
- 关注"遥测消失"事件（EDR 进程突然停止上报 = IoC）
- NDR（网络检测响应）作为 EDR 被盲化后的兜底层

---

## 二、已验证的内核对抗技术路径（当前可用）

### 2.1 BYOVD — 工业化，依然是主要现实路径

**状态：仍然有效，但正在被商品化 + 对抗措施加强**

#### 工业化趋势（2026 Q1-Q2 新变化）
- **GentleKiller 框架**："The Gentlemen" RaaS 组织向 affiliate 提供标准化的 BYOVD 模块框架，支持同时针对多个 EDR 产品
- **Embedded EDR Killers**（Reynolds 勒索软件）：漏洞驱动直接打包进 payload，消除了单独"EDR Kill 阶段"可被检测的时间窗
- **PoC 武器化速度**：新披露 BYOVD PoC 在**数天内**被威胁组织实战化
- **未被封锁的驱动**：2026 年 blocklist 更新频率仍为 1-2 次/年，`CVE-2023-52271` 驱动截至 2026 年仍未被封锁

#### 典型操作链
```
加载签名漏洞驱动
  → IOCTL 发送目标 PID
  → 驱动调用 ZwTerminateProcess（内核层，无 PPL 保护）
  → EDR 进程终止

或：
  → 内核 R/W 原语
  → 定位并清零 PsSetCreateProcessNotifyRoutine 回调数组
  → EDR 盲化
```

#### 当前最实用驱动
- loldrivers.io 维护了 2026 年可用驱动列表
- 主要使用 IOCTL-based 任意内核 R/W，绕过 PPL 终止安全进程

#### Nyx 影响
- 原有项目文档中的 `VulnDriverKit` trait 设计是正确的（operator-selectable current driver）
- 2026 年须将驱动选择完全下放给操作者，不能硬编码；blocklist 随时可能更新

---

### 2.2 ★ 新增 — Living off the Land Kernel (LotLK)：kd.exe 滥用

**来源：hxr1.ghost.io（"Silencing EDR via Windows Kernel Debugging"），2025-2026**

**状态：新兴，可无驱动加载实现内核回调清零**

#### 机制
- `kd.exe`（Windows Kernel Debugger）是微软签名的合法工具，设计上就支持任意内核内存 R/W
- 攻击链：`bcdedit /debug on`（重启）→ 用 `kd.exe` 定位内核回调数组 → 将回调指针覆写为 `ret` 指令地址 → EDR 盲化
- **无需第三方驱动**：完全用微软工具链完成，不触发 BYOVD 检测签名
- 通过 `kd.exe` 自带的符号解析，避免硬编码版本相关偏移（防止 BSOD）

#### 限制 / 检测面
- 需要 `bcdedit /debug on` + 重启（高噪声操作，可被监控）
- 需要 SYSTEM 权限
- 现代 EDR 将 `kd.exe` 执行和 `bcdedit` 变更列为高优先级遥测点

#### Nyx 影响
- P2.2 `CallbackKit` 的实现除了 BYOVD 路径外，这是备选的 operator-side 路径
- 现实中需要在 red team engagement 初期就完成 `bcdedit /debug on` 配置（持久化阶段）

---

### 2.3 ★ 新增 — Windows Defender BTR 驱动滥用

**来源：Check Point Research，计划在 Black Hat USA 2026 发表**

**状态：研究披露阶段，PoC 预计随 BH2026 发布（2026年8月）**

#### 机制
- **Windows Defender Boot-Time Removal (BTR)** 驱动是微软签名的合法安全组件，历史上用于在启动阶段清除顽固恶意软件
- Check Point 逆向了该驱动，证明可以**以该驱动为内核操作原语**实现安全控制绕过
- **无需 BYOVD**（利用系统自带安全组件），绕过 DSE（Driver Signature Enforcement）检查
- 历史背景：CVE-2021-24092 展示过 BTR 驱动的提权漏洞（通过投放方式）

#### 重要性
- 这是"利用系统自带安全工具对抗 EDR"的新变体，与 EvilEDR 哲学一致
- 完全绕过"驱动 blocklist"机制（BTR 是微软自己的驱动，永远不会被封锁）

#### Nyx 影响
- P2.2 须关注此方向；**技术细节等待 BH2026（2026年8月）发布后补充**
- 与 kd.exe 滥用一起归入 operator 工具箱的"LotLK"分类

---

### 2.4 ★ 新增 — VBS Enclave 恶意软件（Mirage / BYOVE）

**来源：Akamai Research（Ori David），DEF CON 33，2025年8月**

**状态：PoC 已公开（GitHub），可研究**

#### 机制
VBS（Virtualization-Based Security）Enclave 在 VTL1 运行，比 VTL0（普通内核）权限更高，且**对 VTL0 不可见**（包括 EDR 内核驱动）。

**BYOVE（Bring Your Own Vulnerable Enclave）攻击链：**
1. 找到已签名但存在漏洞的 enclave 模块（如 CVE-2023-36880，Microsoft Edge enclave）
2. 加载该漏洞 enclave，利用漏洞获得在 enclave 内读写任意数据的能力
3. 将恶意 shellcode 存储在 VTL1 enclave 内存中

**Mirage 执行逻辑：**
- Shellcode 平时住在 VTL1 enclave 内存 → EDR 内核驱动无法扫描（VTL 隔离）
- 需要执行时，短暂投入 VTL0 执行，执行完毕立即擦除
- 内存扫描器在 VTL0 无法找到持续驻留的恶意代码

#### 检测难点
- 传统内存扫描器工作在 VTL0，无法看到 VTL1 内容
- API 调用来自 enclave 内部，对 EDR 钩子不可见
- 微软的 VBS 设计本身就是这种隔离——形成防御者的结构性盲点

#### 限制
- 需要 VBS 已启用（不是所有目标都开启）
- 需要一个可利用的签名 enclave 模块（随漏洞修复会消耗）
- 执行复杂度高

#### Nyx 影响
- 项目文档将此列为"P2.3 research item"；现在 PoC 已经公开，升级为**P2.3 可研究的实现目标**
- 对 Nyx 最直接的用途：VBS enclave 作为 beacon 的持久化存储（payload 在 enclave，按需执行）
- 约束：`no_std` PIC implant 调用 enclave API 的复杂度需要评估

---

### 2.5 ETW-TI 内核盲化 — S12 方案确认（原有）

**来源：S12 Medium 博客（2026-05），EDRSandblast**

**状态：已记录在项目 docs 中，确认有效**

单次 QWORD 写，路径：
```
ntoskrnl!EtwThreatIntProvRegHandle 
  → _ETW_REG_ENTRY 
  → +0x020 GuidEntry → _ETW_GUID_ENTRY 
  → +0x060 ProviderEnableInfo
  → +0x000 IsEnabled = 0
```

2026 更新确认：
- **HVCI 兼容**（数据节操纵，非代码修改）
- 需要 BYOVD 或 DMA 提供内核 R/W 原语
- 防御侧：`fluxsec` 的 Sanctum EDR 项目在研究内核层全谱 ETW 检测，可检测 ETW 盲化篡改

---

### 2.6 PatchGuard / HVCI 下的内核回调操纵 — Outflank 方案（原有，确认）

**来源：Outflank PatchGuard Peekaboo（2026-01）**

**状态：已记录在项目 docs 中，得到网络搜索确认**

关键结论（网络搜索强化确认）：
- **HVCI 下 inline kernel hook 完全死亡**（EPT 阻止代码页写入）
- **数据节操纵是唯一可行的内核路径**（EPT 对数据节为 RW-）
- 进程隐藏：`EPROCESS.ActiveProcessLinks` 断链 + termination callback 中时序修复
- PatchGuard 检查的时序特性可被利用（在检查窗口前修改+修复）

2026 新增技术细节（内核回调 nullification 的绕过 PG 方式）：
- 不是将回调数组条目置零，而是**覆写为 KCFG-compliant 的 `ret`-only 函数地址**（避免触发 PatchGuard 对 NULL 指针的检查）
- 回调本身执行但立即返回（do-nothing），EDR 失去监控但 PG 不 bugcheck

---

### 2.7 内核回调清零的防御演进（需要了解以规避检测）

2026 年防御侧新对策：
1. **"遥测消失"监测**：EDR 进程停止上报 = 高优先级告警（不需要检测攻击本身）
2. **Sysmon EID 6**：驱动加载事件 + loldrivers.io hash 比对（对 BYOVD 有效，对 kd.exe/BTR 无效）
3. **WDAC（Windows Defender Application Control）**：比 blocklist 更激进的驱动白名单策略
4. **NDR（网络检测响应）**：EDR 盲化后 C2 流量仍可被网络层检测，是防御者的兜底

---

## 三、当前内核对抗技术优先级排序（2026-06）

| 排名 | 技术 | 有效性 | HVCI 兼容 | 噪声 | 成熟度 |
|------|------|--------|-----------|------|--------|
| 1 | **BYOVD + ETW-TI 盲化** | ★★★★★ | ✅ | 中（驱动加载可测） | 生产可用 |
| 2 | **kd.exe LotLK 回调清零** | ★★★★ | ✅ | 高（bcdedit 可测） | PoC 阶段 |
| 3 | **Outflank 数据节 + 时序修复** | ★★★★ | ✅ | 低（数据操作） | PoC 阶段 |
| 4 | **BTR 驱动滥用** | ★★★★ | ✅（预期） | 低（系统自带） | BH2026 待公开 |
| 5 | **VBS Enclave (BYOVE/Mirage)** | ★★★ | ✅（VTL1） | 极低 | PoC 已公开 |
| 6 | **EvilEDR repurposing** | ★★★★ | ✅ | 低（合法功能） | 学术已验证 |
| - | ~~DMA (PCILeech)~~ | ★★★★★ | ✅ | 极低 | 需硬件，不普适 |

---

## 四、与项目现有文档的对比 —— 新增发现

### 原文档已有，网络搜索确认
| 原文档方向 | 确认状态 |
|-----------|---------|
| BYOVD 工业化 / kit 模型 | ✅ 确认，RaaS 框架化趋势超出预期 |
| ETW-TI 内核 ProviderEnableInfo 清零 | ✅ 确认有效，HVCI 兼容 |
| Outflank 数据节 + PG 时序修复 | ✅ 确认，KCFG-compliant ret 覆写是新细节 |
| EvilEDR USENIX 2025 | ✅ 确认，是学术验证的最强"无噪声"路径 |
| BYOVD 是 fallback，EvilEDR 是主路 | ✅ 确认（但现实中 BYOVD 仍占主导，EvilEDR 实现门槛高） |

### 原文档未覆盖，本次搜索新发现
| 新技术 | 对 Nyx 的价值 | 优先级 |
|-------|-------------|-------|
| **kd.exe LotLK 回调清零**（hxr1） | P2.2 CallbackKit 的无驱动备选路径 | P2.2 |
| **BTR 驱动滥用**（Check Point BH2026） | 系统自带驱动原语，绕过 blocklist | P2.2，等待 8 月细节 |
| **VBS Enclave Mirage（BYOVE）**（Akamai DEF CON 33） | P2.3 beacon payload 存储的革新性方案 | P2.3 |
| **KCFG-compliant `ret` 覆写**（替代 NULL 清零） | `CallbackKit` 的 PatchGuard 兼容实现细节 | P2.2 实现细节 |
| **GentleKiller 框架**（RaaS 工业化） | 证明 kit 模型设计是正确的，operator 选择驱动 | 设计确认 |
| **回调 KCFG 绕过**：覆写为合法 ret 函数而非 NULL | `CallbackKit` 实现规避 PG 的关键技巧 | P2.2 |

---

## 五、对 Nyx P2.2 设计的更新建议

基于本次搜索结果，对 `p2-integration-analysis.md §2.6` 的补充：

### 回调清零的正确实现（避免 PG bugcheck）
```
// 错误方式（PatchGuard 会检测 NULL）：
callback_array[edr_index] = 0;

// 正确方式（KCFG-compliant，ret-only stub）：
// 1. 在已加载的内核模块中找一个只含 ret 的地址（合法 CFG target）
// 2. 将回调指针覆写为该地址
// 3. EDR 的回调被调用但立即返回（no-op），PG 不触发
callback_array[edr_index] = find_ret_stub_in_ntoskrnl();
```

### P2.2 建议的三层路径（按噪声从低到高）

```
路径 A（最隐蔽）: EvilEDR repurposing
  → 无驱动加载，利用 EDR 合法功能
  → 门槛：需要 EDR license + 复杂操作者工具

路径 B（最务实）: BYOVD → ETW-TI ProviderEnableInfo 清零 + KCFG-ret 回调覆写
  → Sysmon EID 6 可检测驱动加载，但操作本身低噪声
  → 需要 operator 选择 blocklist 之外的当前可用驱动

路径 C（无第三方驱动）: kd.exe LotLK（需 bcdedit + 重启）
  → 适合 engagement 初期有管理员权限时的预置
  → bcdedit 变更是高噪声操作

路径 D（研究前沿）: BTR 驱动滥用
  → 等待 Black Hat 2026（2026年8月）完整技术细节
  → 系统自带组件，不受 blocklist 影响
```

### VBS Enclave 的新用途建议
P2.3 研究方向新增：
- 利用 VBS Enclave 作为 beacon 的 **payload 安全存储**（替代当前在 heap/stack 上驻留）
- 在 enclave 内保存加密 shellcode，按 beacon cycle 按需执行，执行后擦除
- 主要挑战：no_std + PIC 环境下的 enclave API 调用兼容性

---

## 六、BH/DC 2026 新增研究（8月发布前）

**Black Hat USA 2026（2026年8月1-6日，即将举行）已确认相关议题：**

| 议题 | 演讲者/机构 | 内容 |
|------|------------|------|
| "Vulnerabilities Assembled! The Vulnerability Factory Inside the Windows Kernel" | Angelboy Yang | Windows 内核漏洞发现 + 利用 |
| Windows Defender BTR Driver Abuse | Check Point Research | BTR 驱动内核操作原语（★重点关注） |
| "Windows Kernel Rootkit Techniques"（培训课程） | T.Roy (CodeMachine) | 内核态隐身端到端 |

**DEF CON 34（2026年8月，具体日期待定）**：议题目录尚未公开，预计 2026年8月后发布。

→ **建议**：2026年8月 BH/DC 结束后重新扫描，重点关注 BTR 技术细节 + 任何新内核 LotLK 技术。

---

## 七、防御天花板（诚实限制）

无论攻击多么先进，以下防御措施在 2026 年仍然有效：

| 防御措施 | 对抗内核攻击的有效性 |
|---------|---------------------|
| **HVCI 启用** | 阻止所有 inline kernel hook；数据节攻击依然有效 |
| **WDAC 严格策略** | 阻止已知漏洞驱动（但 kd.exe/BTR 不受影响） |
| **Sysmon EID 6 + loldrivers.io** | 对 BYOVD 有效；对 LotLK 路径无效 |
| **遥测消失监测** | 通用兜底；EDR 盲化本身是 IoC |
| **NDR（网络层）** | EDR 被干掉后 C2 流量仍可检测 |
| **SKPG（VTL1 PatchGuard）** | 在 VTL1 运行，对 VTL0 数据操纵有额外保护（largely unexplored） |

---

## 八、信息来源

| 来源 | 内容 |
|------|------|
| hxr1.ghost.io | kd.exe 滥用清零内核回调 |
| checkpoint.com | BTR 驱动滥用（BH2026 预告） |
| akamai.com / DEF CON 33 | VBS Enclave Mirage/BYOVE |
| medium.com/@s12deff | ETW-TI ProviderEnableInfo 清零（BYOVD） |
| outflank.nl | PatchGuard Peekaboo 2026 |
| mine2.io / vectra.ai | BYOVD RaaS 工业化趋势 |
| thehackernews.com | GentleKiller 框架 |
| blackhat.com | BH2026 议题预告 |
