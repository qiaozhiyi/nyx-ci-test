# Nyx 操作端重写设计 — Tauri 2 + React 3D 拓扑

> 2026-07-17 · 范围：删除 `crates/client-cli/`（ratatui TUI）+ `crates/client-ui/`（Makepad GUI），从零重写为 `crates/client-ui-web/`（Tauri 2 + React + Three.js）。
>
> 目标：对标 Cobalt Strike 4.12 / Brute Ratel v2.3，做一个**颠覆性的 C2 操作端**——不是给老框架换皮，而是重新定义操作员与 C2 的交互方式。

## 1. 核心认知：C2 ≠ 渗透自动化

这是整个设计的认知地基。**Nyx 是 C2，不是渗透流程向导**。

- **渗透自动化**（Decepticon/RedTeamAgent）：AI 驱动，按 kill chain 走流程，UI 是"流程进度导航"。把 kill chain 8 阶段做成主导航条，对的。
- **C2**（CS/BRC4/Mythic/Nyx）：**人**驱动，操作员想干嘛干嘛，C2 是"命令通道 + 状态面板"。红队可能第一个 session 就直奔 DA，也可能一直在低权限 session 上侦察。**没有固定流程**。

因此：**kill chain / MITRE 不是主导航**，只是 session 上的可选标签/筛选维度。主操作面是 **session 列表 + console**，符合 CS/BRC4/Mythic 的真实范式。

## 2. 操作逻辑全景

```
1. 启动：打开 GUI → 连接页 → 输入 server URL + bearer → 连接
2. 主工作区（90% 时间）：
   - 左：session 列表（轮询 /api/sessions 每 2s）
   - 右：选中 session 的 console
   - 初始无 session → 空状态引导
3. 对 session 下命令（核心循环）：
   用户输入 → 前端构造 JsonCommand → invoke('send_command')
   → 后端 POST /api/task → 命令进队列（task_id）→ 异步等 beacon check-in
   → beacon 拉取执行 → 结果回传 → 后端轮询 drain /api/results
   → emit('nyx://result') → 前端渲染输出（5 种渲染器）
4. 按需切换视图（dock 导航）：
   ◈ 拓扑图（3D）/ 🔑 凭据库 / 📁 下载物 / ≡ 事件流 / ⚙ Implant 生成
5. 断开：回到连接页
```

## 3. 六大设计支柱

| 支柱 | 来源 | 在 Nyx 的体现 |
|---|---|---|
| **极简主义工作流** | Linear | 每个操作只有一个最佳方式；⌘K 命令面板是主入口；深色作为身份不是选项 |
| **语义化命令** | Raijin | 28 命令是结构化 AST，输 `shell` 自动识别、参数按类型着色验证、OPSEC 实时预警 |
| **上下文自适应** | 生成式 UI | 选中 admin session → 右侧能力面板自动展开提权能力；死宿 → 诊断面板 |
| **3D 空间拓扑** | Heliox/Three.js | 独立全屏页，3D 可旋转网络拓扑，节点带官方 OS 图标，展示 beacon 链/pivot |
| **协同态势感知** | Figma multiplayer | 头像栈、session 标"谁在操作"、关键事件主动推送 |
| **结构化输出** | Mythic browser scripting | `ls`→文件表、`ps`→进程表（带 inject/kill）、不再是纯文本 |

## 4. 信息架构（IA）

**多页面 + 左侧 dock 导航**（不是顶部 kill chain 流程条）：

```
左 dock（48px 图标条）：
  ⌘ Sessions/Console   ← 主工作区（默认页）
  ◈ 拓扑图             ← 3D 全屏（MVP 必须）
  🔑 凭据库
  📁 下载物/截图
  ≡ 事件流/审计
  ⚙ Implant 生成
  ⋮ 设置
```

**主工作区布局（混合范式）**：默认 session 列表（280px）+ 单 console（剩余）；用户可点"分屏"把多个 session console 并排。

## 5. MVP 范围（必须）

### 5.1 主工作区
- **连接页**：server URL + bearer 输入，连接状态反馈，bearer 校验
- **session 列表**：实时轮询，带筛选标签（admin/DA/x64/活跃），异步任务状态指示（queued/running）
- **console**：选中 session 的工作区，顶部显示目标元信息（host/user/权限/OS/sleep/jitter）
- **任务块**：每个命令一个块，带状态机（queued→processing→completed/error），异步提示（"已下发，等 beacon check-in，预计 XX:XX 返回"）
- **命令输入**：语义化着色 + OPSEC 实时预警（如 mimikatz 提示改用 hashdump --method sam）
- **6 核心命令**：`ping` / `shell` / `exit` / `sleep` / `download` / `fileop(cd/ls)`
- **3 种输出渲染器**（MVP）：终端文本、文件表（ls）、状态标记（ok/error）

### 5.2 3D 拓扑页（MVP 必须，核心卖点）
- Three.js 全屏画布，可拖拽旋转/滚轮缩放/点击选中
- 节点 = session，**每个节点带官方 OS 图标**（Canvas + Path2D 渲染官方 SVG path）
- OS 支持：Windows / Windows Server / Ubuntu / Debian / macOS / Kali / Fedora / Alpine / Arch / RHEL
- 连线 = 通道（HTTPS egress 蓝色 / SMB pivot 橙色 / TCP pivot 紫色）+ 匀速流动粒子
- 节点状态色：admin/DA 红、活跃绿、stale 灰；选中态紫色环
- 右侧详情面板（选中节点）：OS/架构/用户/权限/通道/sleep/pivot 链/任务
- 左下图例 + 右下统计

## 6. 视觉设计令牌

```
背景 ramp（Zinc 深色系）：
  bg      #08090c   最深背景
  panel   #0a0b0f   面板/侧栏底
  elev    #0a0c10   卡片/输入框
  border  #161a22   发丝分隔线
  hover   #0d0f14   行 hover

文本：
  primary  #e4e4e7
  second   #9ca3af
  muted    #525866
  faint    #4a4f5a

强调 + 语义：
  accent   #7c5cff   紫罗兰（唯一饱和信号色）
  acchov   #a78bfa
  success  #3fb68b   活跃/完成
  danger   #f87171   admin/错误
  warn     #d9a036   异步等待/OPSEC 中
  info     #60a5fa   Windows/egress

OS 官方色（仅用于 OS 图标，不参与 UI 主题）：
  Windows      #0078D4
  Windows Srv  #00A4EF
  Ubuntu       #E95420
  Debian       #A81D33
  macOS        #9ca3af
  Kali         #2FA8D8
  Fedora       #51A2DA
  Alpine       #0D597F
  Arch         #1793D1
  RHEL         #EE0000

字体：Inter（界面）+ JetBrains Mono（数据/代码/host名）
间距阶梯：4/8/12/14/16/18
圆角：卡片 7-11、按钮 5-6、徽章 2-3
无 @keyframes 循环动画（避免刷新闪烁）；动画只用 transition + requestAnimationFrame 平滑过渡
```

## 7. 技术架构

```
crates/client-ui-web/
├── src-tauri/              Rust 后端
│   ├── src/
│   │   ├── main.rs         Tauri builder + 注册 commands + 启动轮询 task
│   │   ├── state.rs        BackendState（连接/bearer/pending/tokio handle）
│   │   ├── poll.rs         2s 轮询：sessions（签名变更检测）+ per-session results drain
│   │   ├── commands.rs     #[tauri::command]：connect/disconnect/send_command/creds/implant
│   │   └── lib.rs          复用 nyx_rest 的所有 wire 类型
│   └── Cargo.toml
├── src/                    React 前端
│   ├── app/                ConnectPage / Workspace / TopologyPage
│   ├── components/         SessionTable / CommandConsole / TaskBlock / CommandInput
│   │                       Topology3D / Dock / StatusBar / FileTable / ProcessTable
│   ├── hooks/              useSessions / useResults / useConnection（订阅 Tauri events）
│   ├── lib/                invoke.ts / types.ts（镜像 nyx_rest）/ os-icons.ts（官方 SVG path）
│   └── styles/             tokens.css
├── package.json
└── ...
```

### 关键技术决策
1. **复用 `nyx_rest`**：所有 wire 类型（SessionView/TaskAck/ResultView/JsonCommand）+ helper（authed/session_signature），不重抄。
2. **`send_command` 是 generic**：一个 `#[tauri::command]` 接收任意 `JsonCommand`，后端只 POST /api/task。彻底消除旧 dispatch.rs 912 行巨兽。
3. **轮询在后端**：Tauri Rust 侧 spawn 2s 轮询 task，通过 `Window::emit` 推前端。前端只 listen，不自己 fetch。
4. **OS 图标用 Path2D + Canvas 纹理**：官方 SVG path data 硬编码在前端，不依赖外部图片，绝不加载失败。
5. **3D 用 Three.js**：React Three Fiber 或裸 Three.js（MVP 用裸的更轻）。

## 8. 实施步骤

### 阶段 1：归档 + 清理 + 骨架
1. `git add -A && git commit`（保护 untracked 重构产物）
2. 删除 `crates/client-cli/` + `crates/client-ui/` + `bridge.rs.bak`
3. 根 Cargo.toml 移除两个 member
4. 搭 `crates/client-ui-web/`（Tauri 2 + React + Vite + TS）
5. 加入 workspace，`cargo check --workspace` 绿

### 阶段 2：Rust 后端核心
- state.rs / poll.rs / commands.rs / lib.rs
- connect + 轮询 + send_command + creds

### 阶段 3：React 主工作区
- 连接页 + session 列表 + console + 6 命令 + 3 渲染器
- 设计令牌 tokens.css

### 阶段 4：React 3D 拓扑页
- Three.js 全屏 + OS 图标 + 连线 + 详情面板

### 阶段 5：验收
- `cargo build -p nyx-client-ui-web` 零警告
- 起 mock server，连接，验证全流程
- 截图连接页 + 主工作区 + 3D 拓扑

## 9. 约束
- server / protocol / transport / rest / store 等 crate 一律不动
- workspace 结构保持（client-ui-web 作为新 member 替代旧两个）
- 不改 server REST API 契约

## 10. 对标参考
- **Cobalt Strike 4.12**（2025-11）：FlatLNF 换皮，Java Swing，上下分栏 + Pivot Graph。颠覆点：我们用 Web/3D 重新定义。
- **Brute Ratel v2.3**（2025-10）：Qt6.9，Commander UI，MITRE 图。颠覆点：我们的拓扑是 3D 实时可旋转的。
- **Mythic**：React，browser scripting 结构化输出。我们继承这个理念。
- **Linear**：极简主义、键盘优先、深色身份、opinionated。我们继承设计哲学。
