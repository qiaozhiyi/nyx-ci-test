# Nyx Client UI — One Dark 重做 + 登录鉴权修复

**日期**: 2026-06-19
**范围**: `crates/client-ui`(`main.rs`、`theme.rs`、`bridge.rs`、4 个 widget)
**动机**: 现有 UI 视觉粗糙(配色发黑、强调色过亮、输入框/按钮廉价感),且登录界面无法连接(鉴权头缺失,导致服务端一律 401)。

## 1. 目标 / 非目标

### 目标
1. **视觉重做**:整体风格从"钴蓝亮色 + 发黑底"切换到 **One Dark Pro** 深色 + 粉紫强调,对标用户提供的参考图(VS Code/One Dark 风格的 C2 界面)。
2. **登录界面**:重画为参考图风格 + 输入框采用"实心填充 + 聚焦粉紫发光"样式(用户确认的候选 A)。
3. **登录鉴权修复**:bridge worker 的所有 REST 请求带上 `Authorization: Bearer <token>`,密码字段实际接入 `Cmd::Connect`。
4. 保持现有功能骨架不变(会话表 / 命令 Tab / 事件日志 / BOF-Files-Procs-Creds),只改视觉层 + 鉴权数据流。

### 非目标
- 不重构 widget 架构(仍是 PortalList 虚拟化方案)。
- 不引入新依赖(继续用 Makepad 现有原语)。
- 不做 Light 主题的 One Dark 适配——保留现有 Light ramp 但**重调**以匹配新强调色;深色(One Dark)是主用主题。
- 不新增 Pivot Graph 可视化(参考图有,但属未来工作)。

## 2. 设计决策(已与用户确认)

| 决策点 | 选择 | 依据 |
|---|---|---|
| 整体风格 | One Dark Pro 深色 + 粉紫强调 | 用户提供参考图(第三屏),明确否决了 JetBrains 暖灰方案 |
| 强调色 | `#C586C0`(粉紫) | One Dark 招牌色;原 `#2f88ff` 钴蓝被否 |
| 登录输入框 | 实心填充 + 聚焦粉紫发光 | 第四屏用户确认候选 A |
| 布局 | CS 三段式:菜单栏+工具栏 / Sessions 表+Event Log / Beacon 命令 Tab | 第二屏确认 CS 骨架 |
| 鉴权 | `Authorization: Bearer` | server 已实现 `require_auth`,客户端未对接 |

## 3. 配色 token(theme.rs)

新 `Palette::dark()`(One Dark):

| token | 旧值 | 新值 | 用途 |
|---|---|---|---|
| `bg` | `#0d0f13` | `#1A1A25` | 主区 / 控制台背景 |
| `panel` | `#14171d` | `#1E1E2E` | 顶栏 / 侧栏 / 事件日志壳 |
| `elev` | `#1b1f27` | `#252533` | 输入框填充 / 对话框卡片 / 列头 |
| `bar` | `#0a0c10` | `#1E1E2E` | recessed 条(与 panel 合并,保持兼容) |
| `row` | `#12151b` | `#1E1E2E` | 表行基色 |
| `rowhov` | `#1f2531` | `#2A2A3A` | 行 hover |
| `rowsel` | `#1b3a5e` | `#3A2A3E` | 行选中(粉紫调) |
| `border` | `#242935` | `#2A2A3A` | 发丝分隔线 |
| `accent` | `#2f88ff` | `#C586C0` | **粉紫强调**(tab 下边框/选中条/按钮) |
| `acchov` | `#5aa3ff` | `#D89ED4` | 强调 hover |
| `primary` | `#e6e9ef` | `#CCCCCC` | 主文本(One Dark 前景) |
| `second` | `#96a0b0` | `#AAAAAA` | 次文本 |
| `muted` | `#626c7d` | `#8A8A8A` | 静默文本 |
| `success` | `#3ecf8e` | `#4EC9B0` | teal(进程名/在线) |
| `danger` | `#ff5b5b` | `#F44747` | 红(错误) |
| `warn` | `#ffb454` | `#DCDCAA` | 暖黄(凭证/警告) |
| 新增 `info` | — | `#9CDCFE` | 浅蓝(命令关键字/信息),用于控制台着色 |

`Palette::light()`(保留并微调以匹配新强调色):`accent`/`acchov` 改为粉紫系的浅色变体,其余保持中性纸色。**深色为默认主用主题。**

## 4. 登录界面(重画)

DSL 侧 `connect_view` 结构调整:
- **删除**顶部彩色 stripe(`connect_stripe`)——One Dark 不要这条。
- **logo**:30px 圆角方块,粉紫→浅蓝渐变填充,内显 "N"。替换原 30px 黑体 "NYX" 大字。
- **副标题**:"Connect to a team server",小字 muted。
- **输入框**(候选 A 实心填充):
  - 背景 `elev`(`#252533`),1px `border`,圆角 4px,高度 30。
  - 聚焦态:2px `accent` 边框 + `accent` 30% 透明外发光(`box_shadow` 不可直接用;通过 `draw_bg.border_size` 切 1→2 + 额外一层半透明 View 模拟,或在 apply 时切边框色实现)。
  - 字段:Server URL(单行,host+port 合并,默认 `http://127.0.0.1:8443`)、Operator、Password(API Token)。
  - **删除**独立的 HOST/PORT 两栏,合并为 Server URL——简化表单,也更贴合参考图。
- **按钮**:Connect = 粉紫实心;Cancel/主题切换 = `elev` 描边次要按钮,右下角对齐。
- **错误行**:输入框下方 `danger` 小字,等宽字体,带 ✕ 图标。修复鉴权后此处会显示真实错误而非误报的 401。

## 5. 主控制台(重画)

### 5.1 顶栏(菜单栏 + 工具栏)
- 菜单栏:单行文字(File/View/Beacons/Downloads/Attacks/Reporting/Help)+ 左侧 Nyx 字标。深色 `panel` 底,1px `border` 下分隔。
- 工具栏:图标按钮排(new conn / listeners / pivot / session table / target table),扁平,hover `rowhov`,激活态 `elev` 背景。
- 右侧保留状态:Connected · host:port + 主题切换按钮。

### 5.2 左面板(Sessions + Event Log)
- Sessions 表:列头 `elev` 深底大写小字;数据行 `row`,hover `rowhov`,**选中行 `rowsel`(粉紫底)+ 左侧 2px `accent` 竖条**。
- 行内:序号 `muted`、主机 `primary`、用户 `second`、进程名 `success`(teal)、PID/ARCH `muted` 等宽。
- Event Log:独立子区,顶部小 tab,内容等宽 `#CCCCCC`,时间戳更暗 `#5A5A6A`,`[+]` 成功用 teal。

### 5.3 右面板(Beacon 命令 Tab + 控制台)
- Tab 区:`panel` 底,激活 tab `elev` 背景 + 2px 粉紫下边框,非激活 `row`。
- 控制台:`bg` 底,等宽字体,`beacon>` 提示符 `accent`(粉紫),命令关键字 `info`(浅蓝),输出 `primary`。光标 `accent`。
- 底部状态栏:`panel` 底,等宽小字,显示 `[host] | arch | process | pid`。

### 5.4 BOF/Files/Procs/Creds 子面板
保持现有 4 个 widget 结构,仅:
- 表头/行背景/选中色随新 palette(通过 `Palette::current()` 自动生效,因为 `draw_walk` 已读 palette)。
- 静态表头(在 `script_mod!` 里的 `Celev`/`Cmuted` 等 token)同步换成 One Dark 值。

## 6. 鉴权修复(bridge.rs)

### 6.1 根因(已定位)
- `Cmd::Connect { server }` 只带 URL,丢弃了对话框收集的 password。
- worker 的 `fetch_sessions`/`enqueue_shell`/`enqueue_bof`/`poll_result` 四个请求**均无 `Authorization` 头**。
- server `require_auth`(`server/src/lib.rs:582`)要求 `Bearer <NYX_TOKEN>`,缺失即 401 → `connected` 永假 → 卡在登录框。

### 6.2 修复
1. **`Cmd::Connect` 扩展**为 `Connect { server: String, password: Option<String> }`。
2. **worker 持有 token**:`server: Option<(String, Option<String>)>`(server URL + token)。每次请求构造时若有 token,设 `.bearer_auth(token)`(reqwest 原生 API)。
3. **`main.rs` 对话框**:`format!("http://{}:{}", host, port)` → 单一 Server URL 字段(配合 4.3 的表单简化),password 字段值随 `Cmd::Connect` 一并发送。
4. **连接判定**:worker 首次 `fetch_sessions` 成功(2xx + JSON 解析成功)才发 `connected:true`;401 时 log `! sessions: 401 Unauthorized (check API token)` 并保持 `connected:false`,错误透传到对话框错误行。

### 6.3 兼容
- server 未设 `NYX_TOKEN` 时 `require_auth` 直接 `None`(放行),客户端 `password` 为空也不影响——向后兼容无鉴权的本地测试服务器。

## 7. 验证计划

1. **编译**:`cargo build -p nyx-client-ui`(macOS dev host,Makepad 在该平台可构建)。
2. **单元**:bridge 的 token 透传无法纯单测(需 HTTP),但 `Cmd::Connect` 结构变更后,现有 `bridge.rs` tests 保持绿(签名测试不受影响)。
3. **运行时**:启动 server(无 token)→ 启动 client-ui → 登录框输入默认值 → 应进入主控制台(验证修复 + 不回退)。
4. **鉴权路径**:server 设 `NYX_TOKEN=secret` → client 登录框填入 secret → 应连上;填错 → 401 显示在错误行,不卡死。
5. **视觉**:目视确认 One Dark 配色生效(粉紫 tab 下边框、深紫行选中、teal 进程名)。

## 8. 风险

| 风险 | 缓解 |
|---|---|
| Makepad DSL 不支持聚焦态外发光 | 降级为聚焦时边框 1px→2px + 边框色切 `accent`(已验证 `border_size`/`border_color_focus` 可用) |
| `script_apply_eval!` 换色后冷启动首帧仍是旧色 | 保持 DSL token 与 `Palette::dark()` 同步(现有约定),`handle_startup` 已调 `apply_theme` |
| 改 `Cmd::Connect` 签名影响其他调用方 | 全仓 grep 确认仅 `bridge.rs`(定义) + `main.rs`(构造)引用 |
