# Nyx UI 重构共享契约 (2026-07-17)

两个子代理并行重构 GUI (crates/client-ui) 和 TUI (crates/client-cli)。本文件是唯一共享事实源。
**已批准范围：交互修复 + 结构重构。不换 UI 框架（GUI 留 Makepad,TUI 留 ratatui)，不重做布局范式，不加新 server 端点，不加新依赖，不改 workspace/Cargo.toml。**

## 1. 产品身份：一套配色语言

GUI 已有未提交的 violet 换肤（theme.rs `Palette::dark()`),TUI 新增同 ramp 的默认 palette。两端必须读作同一产品。

| token | hex | 用途 |
|---|---|---|
| bg | #0D0E12 | 最深背景 |
| panel | #14161B | 侧栏/面板底 |
| elev | #1B1E26 | 卡片/输入框/表头 |
| rowhov | #1F2330 | 行 hover |
| rowsel | #2E2849 | 行选中（violet tint) |
| border | #262A35 | 分隔线 |
| input_b | #3A3F4C | 输入框边 |
| primary | #E2E4EA | 主文本 |
| second | #9BA0AE | 次文本 |
| muted | #6B707E | 弱文本 |
| accent | #8B7CF6 | 唯一饱和信号色 violet |
| acchov | #A395FF | accent hover |
| success | #3FB68B | 成功 |
| danger | #E5534B | 危险/错误 |
| warn | #D9A036 | 警告 |
| info | #5EB1EF | 信息 |

规则：一个信号色（violet)。成功/危险/警告/信息只用于状态语义，不做装饰。

## 2. 交互铁律（两端同）

1. **零死控件**：界面上每个按钮/菜单/入口必须有真实功能，否则删除。GUI 现有的假菜单栏 (NYX/View/Attacks/Reporting/Help，源码注释自认 "dummy actions") 整条删除，主题切换等真实功能并入工具栏。
2. **禁 emoji 当图标**:📊🕸📁⚙️🔑📋🌗 全部移除。GUI 用文字标签 + 可选 Makepad 矢量绘制小图标；TUI 沿用其 unicode 符号语言（◉⇄▣ 这类可以，终端里渲染稳定）。
3. **空状态必须引导**：任何空面板告诉用户下一步做什么（按什么键/输什么命令），不留白。
4. **文本不被截断**：提示文案溢出即 bug，布局必须容纳或换行。
5. **术语统一**：用户可见文案一律用 **session**（不用 beacon)。TUI 状态栏 "0 beacons"、"no beacon",GUI "No beacon selected" 等全部改 session。内部 API/协议字段名不动。
6. **键盘流完整**：输入框 Enter 提交、Esc 取消/关弹层、焦点顺序合理。已有快捷键体系（TUI prefix、/ 菜单）保留并确保可发现（hint 文案）。

## 3. 文件边界（防冲突）

- GUI 代理：只动 `crates/client-ui/**` + `tmp/ui_refactor/`（验证产物）+ 根目录 `screenshot.png`（最后更新）。
- TUI 代理：只动 `crates/client-cli/**` + `tmp/ui_refactor/`。
- 都不碰：README、docs/、server、workspace Cargo.toml、任何 Cargo.toml、git 提交（工作区改动留给用户）。
- 冒烟端口：GUI 用 8443,TUI 用 8444(NYX_BIND=127.0.0.1:8444,NYX_SERVER=http://127.0.0.1:8444)。hub 进程名前缀各自 `gui-*` / `tui-*`，用完必须 stop。

## 4. 结构重构目标

### GUI (client-ui)
现状：`main.rs` 3,478 行（含 ~1,300 行 script_mod! DSL + App 上帝对象）,`bridge.rs` 2,496 行。
- `main.rs` 瘦身到 ≤ ~900 行：按区域拆 widget（参照 widgets/ 已有模式，各自注册 script_mod)：连接对话框、主工作区头部/工具栏、session 表+详情、console+BOF 底栏可各成模块。拆分后每个 id 引用必须可解析，编译为准。
- `bridge.rs` 拆成 `bridge/` 模块目录：mod.rs(Bridge 核心+通道）、auth/connect、轮询（sessions/tasks/events)、files、creds、console 命令派发。pub API 对 main 侧保持语义一致。
- 颜色全部走 theme.rs token;DSL 里只允许透明 literal (#x00000000) 和 token 引用。
- 头部收敛为一条工具栏：视图切换（Sessions/Graph/Files/Processes/Creds/Event Log 文字 tab，活动态 accent 下划线或底色）+ 右侧连接状态 + 主题切换。
- 空状态：session 表空→"Waiting for sessions… 先启动 agent-dev 验证";console 未选 session→说明怎么选（点击行 / `/use <id>`)。
- 修掉 "No beacon selected" 文案截断。

### TUI (client-cli)
现状：`tui/mod.rs` 4,413 行上帝对象（App + 事件循环 + 64 命令派发全在内）,panes/render 已是纯函数好底子，保留。
- `tui/mod.rs` 瘦身：命令派发大 match（约 1300-1800 行段）移入 `tui/commands.rs`;overlay/confirm/search 状态与逻辑移入 `tui/overlay.rs`。App 字段可按域分组为子结构。现有测试必须全绿（纯函数搬家后修 import)。
- **默认布局**:启动即 `console | session list` 双窗格（`Pane::single(1)` 改默认 split，比例约 70/30)；用户可 split/close 照旧。加一启动标志位使 `--help`/测试行为不变。
- 主题：新增 `Palette::nyx()`（按第 1 节 ramp）为**无配置时默认**;Catppuccin 五套保留可选，config 文件指定行为不变。`init` 默认分支改 nyx。
- 状态栏文案 session 化；空 console 显示引导行（"/ 菜单 · prefix+s 横分 · prefix+v 竖分"这类真实键位，以代码为准）。

## 5. 验证（各自完成，产物存 tmp/ui_refactor/)

- GUI:`cargo build -p nyx-client-ui --target-dir target/gui` 零警告错误；hub 起 `gui-smoke-server`(./target/release/nyx-server）和 GUI(NYX_AUTO_CONNECT=1),screencapture 登录页+主界面+每个 tab，存 `tmp/ui_refactor/gui_*.png`；最后更新根 `screenshot.png`。进程用完 stop。
- TUI:`cargo test -p nyx-cli` 全绿；`cargo build --release -p nyx-cli`;hub PTY 起 `tui-smoke`(8444 连服务器），验证启动默认双窗格、/ 菜单、prefix split、session 列表点击切换，渲染日志存 `tmp/ui_refactor/tui_*.txt`。
- 完成报告：列出每个修复点 + 前后对比证据（文件：行 / 截图名）。
