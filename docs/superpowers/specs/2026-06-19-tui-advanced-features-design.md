# Nyx TUI 高级功能 — 设计文档

**日期**: 2026-06-19
**状态**: 待批准
**范围**: `crates/client-cli` (TUI) + `crates/server` + `crates/agent-dev` + `crates/protocol`

## 背景与动机

当前 `nyx-cli` TUI 已实现 opencode 风基础交互（状态条/事件流/圆角输入框/`/` 菜单/popup
↑↓选择/滚轮），核心命令（shell/ls/ps/creds/bof/upload/download/sleep/ping/kill）全部接通
server REST API。但与 opencode 及成熟 C2 操作台相比仍有 4 个方向的差距，用户要求全部补齐。

## 锁定的设计决策

| 决策点 | 选定方案 |
|--------|---------|
| ③ 控制链路真实性 | 改 server + agent-dev（暴露 Connect/Socks），不做假可视化 |
| ④ 分屏深度 | 完整 tmux 式窗格树（任意嵌套分割） |
| 默认布局 | 单窗格（一个 console），手动分割，布局存 config 永久化 |
| 输入框归属 | 全局底部统一输入框，命令发往焦点窗格绑定的 session |
| 范围策略 | 4 阶段全部交付，按依赖排序分阶段 |

## 技术约束（代码事实）

- `tui.rs` 当前 1467 行，硬编码三段布局（状态条/流/输入框）。窗格树重构前**必须先拆模块**，
  否则单文件会失控。
- server 的 `JsonCommand`（`crates/server/src/lib.rs:636`）只有 ping/shell/sleep/upload/
  download/bof/exit，**不含 Connect/Socks**。这两个变体只存在于 implant 二进制协议
  `Command`（`crates/protocol/src/msg.rs:88-101`）。
- `agent-dev` 的 `execute()`（`crates/agent-dev/src/lib.rs:170`）**未处理** Connect/Socks
  命令（只有 ping/shell/sleep/upload/download/exit/bof）。
- server 的 session 注册表是 `dashmap`，SessionView 结构无 tag/alias 字段——session
  管理的元数据必须客户端本地维护。
- 现有命令路由设计（`classify()` 纯函数）：裸输入=shell、`/`=元命令。阶段 1 要在此基础上加
  "有选中 beacon 时裸输入直接跑"和"`!`前缀强制 shell"。

---

## 阶段 1：命令体验 + Session 管理（纯 TUI 侧，零协议改动）

**目标**: 把日常操作体验做到位。这是后面所有阶段的基础——分屏的每个窗格都要能跑命令、
显示 session。

### 1.1 模块拆分（窗格树重构的前置）

当前 `tui.rs` 1467 行做太多事（App state + 输入处理 + 渲染 + popup + overlay）。拆为：

```
crates/client-cli/src/
  main.rs          # 入口（不变）
  rest.rs          # REST client + worker（不变）
  parse.rs         # 输出解析（不变）
  types.rs         # 类型（不变）
  theme.rs         # 主题（不变）
  tui/
    mod.rs         # App 结构 + run() + main_loop + 事件分发
    input.rs       # classify() + parse_sleep_args + 输入历史 + alias
    render.rs      # render() 入口 + 布局计算
    widgets.rs     # statusbar / stream / input / popup / overlay 渲染函数
    session_meta.rs # session 本地元数据管理
    config.rs      # ~/.nyx/ 配置读写（alias + session_meta + layout）
```

**原则**: 每个文件 < 400 行，单一职责。渲染函数从 `tui.rs` 平移到 `widgets.rs`，逻辑不变。

### 1.2 命令体验增强

| 功能 | 实现 |
|------|------|
| **选中 beacon 后裸输入=shell** | 现已工作（`run_shell` 检查 `selected`，无则提示）。本阶段改为：输入框 placeholder 动态显示"将执行于 beacon \<alias\>"，让操作者明确命令去向 |
| **shell 历史前缀补全** | 输入框打字时，若非 `/` 开头且 popup 未开，显示匹配前缀的历史命令 popup（复用 popup 机制，数据源换 `history` 过滤） |
| **`!` 强制 shell** | `classify()`: `!` 开头 → 剥离 `!`，强制 shell（即使有同名 `/` 命令） |
| **命令 alias** | `/alias <name> <command...>`，存 config。`classify()` 解析时先查 alias 表替换。如 `/alias ll ls -la` 后打 `ll` 实际跑 `ls -la` |

`classify()` 改造（纯函数，TDD）：

```rust
enum Input {
    Empty,
    Shell(String),           // 裸输入 or ! 前缀
    Meta { name, args },     // / 前缀
    Alias { expanded },      // alias 表命中，展开后的命令
}
fn classify(raw: &str, selected: bool, aliases: &HashMap<String,String>) -> Input
```

### 1.3 Session 管理（客户端本地状态）

**数据结构**（`session_meta.rs`）：
```rust
struct SessionMeta {
    alias: Option<String>,      // /rename 设的自定义名
    tags: Vec<String>,          // /tag web db ...
    favorite: bool,             // /star 标记
    notes: Option<String>,      // /note 备注
}
struct SessionStore {
    map: HashMap<String, SessionMeta>,  // key = session_id
    path: PathBuf,                       // ~/.nyx/sessions.json
}
```

**持久化**: `~/.nyx/sessions.json`，启动加载、变更即写。

**命令**:
- `/rename <id> <name>` — 设别名
- `/tag <id> +web -db` — 加/减标签
- `/star <id>` — 收藏切换
- `/note <id> <text>` — 备注
- `/sessions` 列表显示别名/标签/收藏标记，支持 `/sessions tag:web` 过滤

**过滤语法**（纯函数，TDD）：`/sessions <filter>` 解析 `tag:x`、`star`、`alias:keyword` 组合。

### 1.4 配置系统（`config.rs`）

```rust
struct Config {
    aliases: HashMap<String, String>,
    session_meta: SessionStore,
    // 阶段 4 用：layout: Option<PaneTree>,
    path: PathBuf,  // ~/.nyx/config.json
}
```
启动读 `~/.nyx/config.json`（不存在则默认空），变更即写。

### 1.5 阶段 1 验证
- 模块拆分后 `cargo test` 全绿（现有 57 测试平移）
- 新增 TDD 测试：classify 带 alias、`!` 前缀、session 过滤解析
- `cargo clippy -D warnings` 干净
- 手动：`/alias ll ls -la` → 打 `ll` 跑 `ls -la`；`/rename`/`/tag` 生效且持久化

---

## 阶段 2：Server 扩展 Connect/Socks（跨 3 crate，③前置）

**目标**: 让 REST API 能下发真实的链路/SOCKS 命令。不动这个，阶段 3 永远做不出真链路。

### 2.1 protocol 层（无需改动）
`Command::Connect`/`Socks` 已在 `crates/protocol/src/msg.rs:88-101` 定义且编解码完整。

### 2.2 server 层（`crates/server/src/lib.rs`）

`JsonCommand` 加两个变体：
```rust
enum JsonCommand {
    // ... 现有 ...
    /// Open an outbound connection from the implant (P2P / rportfwd).
    /// `chan` is server-assigned; returned in the TaskAck for the client to track.
    Connect { host: String, port: u16 },
    /// SOCKS5 relay control on a channel.
    Socks { chan: u32, op: u8, addr: String, port: u16 },
}
```
`into_command()` 映射：`Connect` 需 server 分配 `chan`（`AppState` 加一个原子计数器）。

**REST 不变**：仍走 `POST /api/task`，只是 body 的 `command.type` 多了 `connect`/`socks`。
`/api/results` 已能返回 `Channel` 类型的结果（`kind=="channel"`），TUI 阶段 3 消费。

### 2.3 agent-dev 层（`crates/agent-dev/src/lib.rs`）

`execute()` 加 `Command::Connect`/`Socks` 分支：
- `Connect`: `tokio::net::TcpStream::connect((host, port))`，成功后回 `Response::Channel{chan, status:0}`，
  后续在该 channel 上转发数据（agent-dev 是 std+tokio，可实现）。
- `Socks`: 按 op 处理 SOCKS5 握手（agent-dev 可做简化版：只支持 CONNECT 方法）。

**注意**: agent-dev 的 beacon 循环是同步轮询（`run()` 里 sleep+fetch），真正的长连接 channel
转发需要改成**持久任务**模型。这是 agent-dev 内部改动，不影响 protocol wire 格式。

### 2.4 client-cli 层
- `rest.rs` 加 `Cmd::Connect`/`Cmd::Socks` + `enqueue_connect`/`enqueue_socks`
- TUI 加 `/pivot <host> <port>`（= Connect）、`/socks <on|off> <addr> <port>` 命令
- 结果回流：worker poll 到 `kind=="channel"` 的结果，log 输出 channel 状态

### 2.5 阶段 2 验证
- `cargo build --workspace` 全绿
- server 单测：JsonCommand::Connect → Command::Connect 映射、chan 分配
- 手动：起 server + 两个 agent-dev，`/pivot <agent2的监听>` 建立 channel

---

## 阶段 3：控制链路可视化（依赖阶段 2）

**目标**: 可视化 session 之间的 pivot 通道和 SOCKS 代理状态。

### 3.1 channel 状态追踪

worker 维护 `Vec<ChannelState>`：
```rust
struct ChannelState {
    chan: u32,
    source_session: String,   // 发起 Connect 的 session
    target: String,           // host:port
    kind: ChannelKind,        // Pivot | Socks
    status: ChannelStatus,    // Open | Data | Closed | Error
    bytes_in: u64,
    bytes_out: u64,
}
```
从 `/api/results` 的 `kind=="channel"` 结果更新。

### 3.2 拓扑 overlay

`/graph` 弹全屏 overlay（复用 Overlay 机制），画链路图：
- 节点 = session（用 alias/hostname 显示）
- 边 = channel（pivot 实线、socks 虚线，标注状态）
- ratatui 无画图 widget，用 ASCII/Unicode 框线手绘（`┌─┐│└─┘` + 箭头 `─→`）

**布局算法**（纯函数，TDD）：给定 `Vec<ChannelState>` + `Vec<SessionView>`，输出一个
`Vec<(node_id, x, y)>` 坐标布局（简化版：按拓扑层级分层，每层水平排列）。

### 3.3 阶段 3 验证
- 拓扑布局纯函数单测
- 手动：两个 agent + 一个 pivot channel，`/graph` 看到两个节点一条边

---

## 阶段 4：tmux 式窗格树（依赖 1/2/3 都有内容可放）

**目标**: 可任意分割的窗格树，每个窗格独立显示一种视图，布局持久化。

### 4.1 窗格树数据结构

```rust
/// 一个可递归分割的窗格。叶节点持有一个视图；内节点持有一对子窗格+分割方向。
enum Pane {
    Leaf {
        id: usize,                    // 唯一 id，焦点切换用
        view: PaneView,               // 这个窗格显示什么
        scroll_offset: usize,         // 独立滚动
        bound_session: Option<String>,// 绑定的 session（Console 视图用）
    },
    Split {
        dir: SplitDir,                // Horizontal | Vertical
        ratio: f32,                   // 0.0-1.0，第一个子窗格占比
        children: Box<[Pane; 2]>,
    },
}

/// 窗格里能显示的视图类型。
enum PaneView {
    Console,        // 事件流（绑定 session）
    SessionList,    // beacon 列表（可点击选中）
    Files,          // /ls 结果
    Procs,          // /ps 结果
    Creds,          // 凭据
    Topology,       // 链路图（阶段 3）
}
```

### 4.2 焦点与操作

- **焦点**: App 持 `focused_pane: usize`。`Ctrl+hjkl` 在窗格树中按方向移动到相邻叶节点。
- **分割**: `Ctrl+%`（垂直）/`Ctrl+"`（水平）把当前焦点叶节点一分为二，新窗格继承视图类型。
- **关闭**: `Ctrl+x` 关闭当前窗格（父 Split 收缩，兄弟提升）。
- **切换视图**: 焦点窗格里 `Ctrl+1..6` 切换 Console/SessionList/Files/Procs/Creds/Topology。
- **绑定 session**: 焦点 Console 窗格里 `/use <id>` 只改该窗格的 `bound_session`（不影响其他窗格）。
  **全局输入框的命令发往焦点窗格的 `bound_session`**。

焦点移动算法（纯函数，TDD）：给定窗格树 + 当前焦点 id + 方向，返回新焦点 id。需要计算
每个叶节点的屏幕矩形（递归 layout）来判断"相邻"。

### 4.3 布局持久化

`~/.nyx/layout.json` 存窗格树（序列化 Pane，去掉运行时状态如 scroll_offset）。
启动时若有则恢复，否则默认单 Leaf(Console)。

### 4.4 渲染重写

`render()` 从硬编码三段 →：
1. 顶部状态条（全局，1 行）
2. 窗格树区域（递归 `render_pane(pane, rect)`：Split 按 ratio 切分 rect 递归，Leaf 渲染对应视图）
3. 底部全局输入框（3 行）
4. overlay/popup 浮层（不变）

**窗格边框**: 每个叶窗格用细 Faint 边框；焦点窗格用 Accent 边框高亮。

### 4.5 阶段 4 验证
- 窗格树 split/close/focus 纯函数单测（构造树、split、close、焦点移动）
- 布局算法单测（给定树+rect，输出每个叶的 rect）
- TestBackend 渲染烟雾测试（多窗格布局不崩）
- 手动：`Ctrl+%` 分屏，两个窗格分别 `/use` 不同 session，`Ctrl+l`/`Ctrl+h` 切焦点打命令

---

## 执行顺序总览

| 阶段 | 改动范围 | 工作量 | 依赖 |
|------|---------|--------|------|
| 1 | client-cli 内部拆分 + 命令增强 + session 管理 | 中 | 无 |
| **1.5** | **protocol 加 FileOp + server 映射 + agent-dev 实现 + TUI 文件命令**（追加A） | **中** | **1（借 session 管理基础设施）** |
| **1.6** | **凭据库持久化 `~/.nyx/creds.json` + 搜索/导出**（追加B） | **低** | **1（借 config 基础设施）** |
| 2 | server 暴露 Connect/Socks + agent-dev 长连接 | 大 | 无（可与 1 并行，但建议先 1） |
| 3 | client-cli（channel 追踪 + 拓扑图） | 中 | 2 |
| 4 | client-cli（窗格树重构） | 最大 | 1/1.5/1.6/3（有内容可放） |

### 追加 A：文件管理命令（阶段 1.5）

CS 内建 cd/mkdir/rm/mv/cp，nyx 全靠 shell。扩 protocol：

```rust
// protocol/src/msg.rs
enum Command {
    // ... 现有 ...
    FileOp { op: FileOp, path: String, dest: Option<String> },  // tag 10
}
enum FileOp { Cd, Mkdir, Rm, Mv, Cp }  // u8 tags 0-4
```
- server `JsonCommand::FileOp` 映射 + REST
- agent-dev `execute()` 用 `std::fs` 实现（POSIX 全支持，Windows 路径转换）
- TUI `/cd` `/mkdir` `/rm` `/mv` `/cp` 命令
- Response::Ok/Error 反馈结果，与 `/ls` 配合形成文件管理闭环

### 追加 B：凭据库持久化（阶段 1.6）

```rust
// client-cli/src/tui/credstore.rs
struct CredStore {
    entries: Vec<StoredCred>,   // CredEntry + source_session + collected_at
    path: PathBuf,              // ~/.nyx/creds.json
}
```
- `/creds` 解析出的凭据自动入库（去重：principal+secret 唯一）
- `/creds` overlay 显示完整库（非单次）
- `/creds export json|csv` 导出
- 搜索：`/creds user:admin` / `/creds kind:hash`

## 不在本设计范围

- Windows PIC implant（`crates/implant-win`）的 Connect/Socks 实现（独立于 agent-dev）
- Malleable C2 profile 编辑器
- 多操作员协同（server 已支持，TUI 不涉及）
- 凭据一键采集（依赖 BOF 侧，CLI 只解析展示）
- 链路加密强化（现有 X25519+ChaCha20 已端到端验证）

## 风险

1. **agent-dev 的 channel 持久连接**：现有 beacon 循环是同步轮询，Connect 的长连接转发需要
   改成持久任务模型。这是 agent-dev 内部最大改动，可能需要重构 `run()` 循环。
2. **窗格树焦点算法复杂度**：相邻窗格判断需要屏幕坐标，递归 layout 的正确性靠 TDD 保证。
3. **拓扑图无现成 widget**：纯 ASCII 手绘，复杂拓扑（>5 节点）可读性有限。
