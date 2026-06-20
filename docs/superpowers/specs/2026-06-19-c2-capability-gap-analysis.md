# Nyx vs Cobalt Strike 4.13 — 能力差距全景分析

**日期**: 2026-06-19
**目的**: 从 C2 操作台能力全景评估 nyx-cli TUI 与业界标杆（Cobalt Strike 4.13）的差距，
为本次更新及未来路线图提供基线。参考横向对比 Sliver（2025 Bishop Fox 排名 #1）、Havoc。

## 评估方法

按 C2 操作台的 **7 大能力域** 逐项对比。每域标注 nyx 现状、CS 对应能力、差距等级：
- 🟢 **领先/持平**：nyx 实现质量不亚于 CS
- 🟡 **部分实现**：核心有，缺关键子能力
- 🔴 **缺失**：完全没有

---

## 能力域对比

### 域 1：操作员交互界面（Operator UI）

| 子能力 | CS 4.13 | nyx-cli 现状 | 差距 |
|--------|---------|-------------|------|
| 多会话可视化（Pivot Graph） | ✅ 三视图：Pivot Graph / Session Table / Target Table | 🔴 仅有 session 列表 overlay，无关系图 | 🔴 |
| 分屏/多窗格操作 | ✅ 多 tab + 独立窗口 | 🔴 单一事件流视图 | 🔴（本次阶段4 补） |
| 命令历史/补全 | ✅ | 🟡 popup 补全 `/` 命令，无 shell 历史补全 | 🟡 |
| 鼠标交互 | ✅ | 🟡 滚轮+点击（刚加） | 🟢 |
| REST API（4.12 新增） | ✅ 4.12 引入 | 🟢 nyx 本身就是 REST 客户端 | 🟢 |
| Aggressor 脚本（4.13 加 AI） | ✅ Aggressor Script + 即将推出 Aggressor AI | 🟡 nyx 有 scripting-rhai crate，TUI 未接入 | 🟡 |
| 主题/字体 | ✅ 4.13 新增 UI 字体 | 🟢 Catppuccin Mocha 主题（刚做） | 🟢 |

**域 1 结论**: 分屏（阶段4）+ pivot 图（阶段3）补完后达 CS 水平。脚本接入（Rhai→TUI）是中
期可做的加分项。

### 域 2：会话管理（Session Management）

| 子能力 | CS | nyx | 差距 |
|--------|----|----|------|
| 会话列表（host/user/pid/admin） | ✅ | ✅（sessions overlay 完整） | 🟢 |
| 会话元数据（rename/tag/note） | ✅ | 🔴 纯列表，无本地元数据 | 🔴（阶段1 补） |
| 会话过滤/搜索 | ✅ | 🔴 | 🔴（阶段1 补） |
| 多操作员共享会话视图 | ✅ team server 支持 | 🟢 nyx-server 有 dashmap 注册表 | 🟢 |
| 会话分组/标签持久化 | ✅ | 🔴 | 🔴（阶段1 补） |
| 自动化会话事件钩子 | ✅ Aggressor onEvent | 🟡 nyx 有 EventBus + Rhai，TUI 不消费 | 🟡 |

### 域 3：文件系统操作（File Ops）

| 子能力 | CS | nyx | 差距 |
|--------|----|----|------|
| upload/download | ✅ | ✅（含分片重组） | 🟢 |
| 文件浏览（结构化 ls） | ✅ 内建文件浏览器 GUI | 🟡 `/ls` 解析 shell 输出，无交互式浏览 | 🟡 |
| 文件管理（cd/mkdir/rm/mv） | ✅ 内建命令 | 🔴 靠 shell 命令，非结构化 | 🔴 |
| 拖拽上传 | ✅ GUI | ❌ TUI 不适用 | N/A |
| 递归下载（目录） | ✅ | 🔴 单文件 | 🔴 |

**域 3 结论**: nyx 的文件操作靠"shell+客户端解析"，CS 是内建结构化命令。差距明显，但补齐
需要扩展 protocol（加 file 操作命令）或继续走 shell 路线。**短期建议**：增强 shell 解析（阶段
1 的 ls/ps），中期加 protocol 级文件命令。

### 域 4：横移与链路（Lateral Movement & Pivoting）—— 最大差距

| 子能力 | CS | nyx | 差距 |
|--------|----|----|------|
| SMB Beacon（named pipe 内网链） | ✅ 核心特性 | 🔴 protocol 有 Connect，server/agent 未接通 | 🔴（阶段2/3） |
| TCP Beacon（P2P） | ✅ | 🔴 同上 | 🔴 |
| SOCKS 代理（rportfwd） | ✅ socks + rportfwd | 🔴 protocol 有 Socks，未接通 | 🔴（阶段2） |
| 反向端口转发 | ✅ rportfwd | 🔴 | 🔴 |
| Pivot Graph 可视化 | ✅ 核心卖点 | 🔴 | 🔴（阶段3） |
| 端口扫描（内建 portscan） | ✅ portscan 命令 | 🔴 靠 nmap shell | 🔴 |
| 横移到新目标（jump/run） | ✅ jump + remote-exec | 🔴 | 🔴 |

**域 4 结论**: 这是 nyx 和 CS 差距最大的域。阶段 2（接通 Connect/Socks）+ 阶段 3（拓扑图）
是核心，但 **named pipe SMB beacon、rportfwd、portscan 内建命令** 是更大的缺口，需要
protocol 扩展 + implant 实现。建议本次先做 Connect/Socks 接通，SMB beacon 等列为长期。

### 域 5：凭据与权限（Credential & Privilege）

| 子能力 | CS | nyx | 差距 |
|--------|----|----|------|
| hashdump（LSASS 凭据） | ✅ 内建 | 🟡 靠 BOF，CLI 只解析展示 | 🟡 |
| pass-the-hash（pth） | ✅ 内建 | 🔴 | 🔴 |
| kerberos 票据操作 | ✅ kerberos_* | 🔴 | 🔴 |
| 凭据库（结构化存储） | ✅ 凭据视图 | 🟡 `/creds` 解析展示，无持久凭据库 | 🟡 |
| 令牌操作（steal_token） | ✅ | 🔴 | 🔴 |
| 提权建议（elevate） | ✅ elevate + Elevate Kit | 🔴 | 🔴 |

**域 5 结论**: nyx 的凭据能力依赖 BOF（这是正确的设计——CS 也在 BOF 化），但凭据**持久化库**
和 **pth/kerberos** 是缺口。pth/kerberos 需 Windows implant 实现，TUI 侧只能加凭据库持久化。

### 域 6：监控与采集（Surveillance & Collection）

| 子能力 | CS | nyx | 差距 |
|--------|----|----|------|
| 屏幕截图 | ✅ screenshot | 🔴 protocol 无此命令 | 🔴 |
| 键盘记录 | ✅ keylogger | 🔴 | 🔴 |
| 浏览器劫持 | ✅ browser_pivot | 🔴 | 🔴 |
| 进程列表（结构化） | ✅ ps | 🟡 `/ps` 解析 shell 输出 | 🟡 |
| 进程注入 | ✅ inject（4.12 改进） | 🔴 | 🔴 |
| 屏幕监控录像 | ✅ | 🔴 | 🔴 |

**域 6 结论**: screenshot/keylogger 是 CS 的高价值功能，**protocol 需新增命令 + implant 实
现**。这是 nyx 当前完全没有的一整类能力。

### 域 7：规避与对抗（Evasion & Defense）

| 子能力 | CS | nyx | 差距 |
|--------|----|----|------|
| Malleable C2 配置 | ✅ | ✅ nyx-profile crate（完整） | 🟢 |
| 睡眠混淆（sleep mask） | ✅ Sleep Mask Kit | 🟡 implant-win 有堆栈欺骗设计，未完成 | 🟡 |
| BOF 执行 | ✅ | ✅ nyx-coff + bof-runner（完整） | 🟢 |
| 进程注入（APT 级） | ✅ | 🔴 | 🔴 |
| AMSI/ETW 绕过 | ✅ | 🟡 implant-win 有设计，未完成 | 🟡 |
| JA3/JA4 指纹模拟 | ❌ CS 无 | ✅ nyx-transport crate（**领先**） | 🟢 |
| User Defined C2（4.12） | ✅ UDC2 | 🔴 | 🔴 |

**域 7 结论**: nyx 在 **Malleable C2 + BOF + JA3 指纹** 上持平甚至领先（JA3）。sleep mask/
AMSI 绕过在 implant-win 路线图里，UDC2 是长期。

---

## 差距热力图（优先级矩阵）

按「操作价值 × 实现成本」排序，本次更新该覆盖的标 ⭐：

| 能力 | 价值 | 成本 | 本次 | 说明 |
|------|------|------|------|------|
| 分屏窗格树 | 高 | 高 | ⭐ 阶段4 | 交互基础 |
| Session 元数据/过滤 | 高 | 低 | ⭐ 阶段1 | 操作效率 |
| 命令 alias/历史 | 中 | 低 | ⭐ 阶段1 | 体验 |
| Connect/Socks 接通 | 高 | 中 | ⭐ 阶段2 | 链路前置 |
| Pivot Graph 拓扑图 | 高 | 中 | ⭐ 阶段3 | 链路可视化 |
| **文件管理命令（cd/mkdir/rm）** | 高 | 中 | ⭐ 新增 | 需扩 protocol |
| **凭据库持久化** | 中 | 低 | ⭐ 新增 | 纯 TUI |
| screenshot/keylogger | 高 | 高 | ❌ | 需 protocol+implant，列为下一周期 |
| portscan 内建 | 中 | 中 | ❌ | 可 shell 替代 |
| pth/kerberos | 高 | 高 | ❌ | 需 Windows implant |
| SMB named pipe beacon | 高 | 极高 | ❌ | implant 重构 |
| 文件递归下载 | 中 | 中 | ❌ | 后续 |
| Rhai 脚本→TUI 接入 | 中 | 中 | ❌ | 后续 |
| UDC2（User Defined C2） | 中 | 高 | ❌ | 长期 |

## 建议修订：在原 4 阶段基础上增加 2 项

基于差距分析，建议在本次更新里**追加 2 个之前漏掉的高价值项**：

### 追加 A：文件管理命令（扩 protocol）
CS 内建 cd/mkdir/rm/mv/cp，nyx 全靠 shell。建议：
- `protocol` 加 `Command::FileOp { op: FileOp, path: String, dest: Option<String> }`
  其中 `FileOp = Cd | Mkdir | Rm | Mv | Cp`
- server `JsonCommand` 映射
- agent-dev 实现（std::fs 直接做）
- TUI `/cd` `/mkdir` `/rm` `/mv` `/cp` 命令
- 这样 `/ls` 配合文件操作形成完整的文件管理闭环

### 追加 B：凭据库持久化
CS 有结构化凭据视图。建议：
- TUI 本地 `~/.nyx/creds.json`，`/creds` 解析出的凭据自动入库
- 凭据库 overlay 支持搜索/导出（JSON/CSV）
- 与 session 关联（哪个 beacon dump 的）

## 总结：nyx 在 C2 生态中的定位

**nyx 的强项**（已超 CS 或持平）：
- Malleable C2 配置（完整）
- BOF 执行（完整）
- JA3/JA4 指纹（CS 没有）
- 加密协议设计（X25519+ChaCha20，现代化）
- REST API 架构（CS 4.12 才加，nyx 天生 REST）

**nyx 的弱项**（与 CS 主要差距）：
- 操作员 UI（分屏/可视化/脚本）← 本次补
- 链路/横移（SMB/TCP beacon、rportfwd）← 本次补 Connect/Socks
- 监控采集（screenshot/keylog）← 下一周期
- 凭据操作（pth/kerberos）← 依赖 Windows implant 成熟
- 文件管理（内建命令）← 本次追加

**一句话**: nyx 的**底层（协议/规避/BOF/指纹）设计先进**，但**操作员侧体验和横移能力**与
CS 差一代。本次 4 阶段 + 2 追加能把操作员体验和基础链路补到 CS 7-8 成；screenshot/keylog/
SMB beacon 等深水区是后续周期。

## Sources
- [Cobalt Strike Release Notes](https://download.cobaltstrike.com/releasenotes.txt)
- [Cobalt Strike 4.12 — Fix Up, Look Sharp](https://www.cobaltstrike.com/blog/cobalt-strike-412-fix-up-look-sharp)
- [Session and Target Visualizations — Fortra Docs](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/ui_session-target-visualizations.htm)
- [Bishop Fox 2025 Red Team Tools & C2](https://bishopfox.com/blog/2025-red-team-tools-c2-frameworks-active-directory-network-exploitation)
- [Havoc C2 Guide — Redfox Sec](https://www.redfoxsec.com/blog/havoc-c2-framework-a-red-teamers-complete-guide-to-setup-commands-and-tradecraft)
- [Cobalt Strike Components & BEACON — Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/defining-cobalt-strike-components)
