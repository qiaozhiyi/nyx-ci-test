# GUI 换肤设计 — 现代深色专业工具风(紫罗兰)

> 2026-07-16 · 范围:`crates/client-ui`(Makepad 2.0 GUI)· 用户已确认方向
>
> 目标:把现有 GUI(被评"丑爆了")重做为 **现代深色专业工具风**(参考 Linear / VS Code Dark+),
> 全局换肤 + 布局微调,不改功能逻辑。主强调色:**紫罗兰**。

## 设计令牌(单一事实源)

所有视觉决策收敛到两处镜像:`crates/client-ui/src/theme.rs` 的 `Palette`(动态绘制时读取)
和 `crates/client-ui/src/main.rs` `script_mod!` 里的 `C*` 令牌块(首帧渲染)。
**两者必须逐值一致;令牌名不变,只改值。**

### 深色 ramp(默认主题,新)

| 令牌 | 值 | 用途 |
|---|---|---|
| `bg` | `#0D0E12` | 窗口底色(最深) |
| `panel` | `#14161B` | 侧栏 / 日志壳 / 凹陷条 |
| `bar` | `#181A21` | 次级的条带(标签栏等) |
| `elev` | `#1B1E26` | 卡片 / 表头 / 对话框 |
| `row` | `#14161B` | 表格行底 |
| `rowhov` | `#1F2330` | 行悬停 |
| `rowsel` | `#2E2849` | 行选中(淡紫底,替换刺眼蓝 `#094771`) |
| `border` | `#262A35` | 发丝分隔线 |
| `input` | `#1B1E26` | 输入框填充(与卡片同面,GitHub-dark 模式) |
| `input_b` | `#3A3F4C` | 输入框静止边框(清晰可见的 1px) |
| `primary` | `#E2E4EA` | 主文字 |
| `second` | `#9BA0AE` | 次文字 |
| `muted` | `#6B707E` | 弱化文字 / 占位 |
| `accent` | `#8B7CF6` | 紫罗兰主信号色 |
| `acchov` | `#A395FF` | 强调色悬停 |
| `success` | `#3FB68B` | 成功(柔化 teal,替换刺眼绿 `#00C800`) |
| `danger` | `#E5534B` | 危险 / 错误 |
| `warn` | `#D9A036` | 警告 |
| `info` | `#5EB1EF` | 信息 / 命令关键字 |
| `under` | `#8B7CF6` | 活动标签下划线 |
| `grad_top` / `grad_bot` | `#0D0E12` / `#08090C` | 背景渐变 |
| `node` / `line` | `#3A3F4C` / `#8B7CF6` | 网络背景节点 / 连线 |
| `glow` | `#8B7CF6` | (仅保留令牌;专业风不使用发光效果) |
| `btn_grad2` | `#6D5FD3` | (仅保留令牌;按钮改为纯色不用渐变) |

### 浅色 ramp(保留双主题,只换强调色家族)

中性纸面不变,强调色换紫罗兰:`accent #6D5FD3`、`acchov #8B7CF6`、`rowsel #D9D4F5`、
`line/glow #6D5FD3`、`btn_grad2 #5848B8`、`node #9BA0AE`。其余字段维持现状。

### 字体阶梯

- 界面文字统一无衬线(`theme.font_regular` / `font_bold`),数据(URL/token/控制台/表格数字)用等宽 `theme.font_code`
- 字阶:10(caps 小标签)/ 11-12(辅助)/ 13(正文)/ 15(节标题)/ 18(品牌)
- 修复现状混乱:连接页 label 与输入框字体不一致、字级随意

### 间距 / 圆角 / 阴影

- 间距阶梯 4 / 8 / 12 / 16 / 20 / 24,收敛现状里的散值
- 圆角:卡片 8、按钮/输入框 6、徽章 4(新增令牌 `Cradius_l = 8.0`)
- 阴影:连接卡片用柔和落影;**全面去除霓虹发光**(glow_keep / glow 色实例)

## 默认主题切换

当前 `IS_DARK` 默认 `false`(首屏浅色)。改为 **`true`(深色默认)**,DSL 令牌块首帧值 = 深色 ramp。
`theme.rs` 头部注释已声明"DSL 必须镜像 `Palette::dark()`",本次使其名副其实。

## 连接页重设计(main.rs)

- NetworkBg:**静态化/极弱化** —— 去掉漂移动画(或降速到几乎静止),节点更暗更稀,连线用 violet 低 alpha;专业工具不闪
- GlassCard:柔和落影 + 1px `border` 边,**去掉品红霓虹边**
- 品牌区:`Nyx Operator` 18px bold + 副标题 `muted` 正常大小写(去掉全大写 10px 的廉价感);logo 方块圆角 8、紫罗兰底
- 表单:label 用 `second` 11px 无衬线 semibold;输入框 6px 圆角、聚焦时边框 = `accent`;错误文字 `danger`
- Connect 按钮:**纯色 `accent`,去渐变**(`color_2` / `gradient_fill_horizontal` 删除),hover = `acchov`,圆角 6,高 36
- Theme 切换按钮:降为次级样式(透明底 + `border` 边 + `muted` 字),不再与主按钮抢视觉
- ConnectProgress 进度条:绿色 `#x00C800` → `success #3FB68B`,红色 → `danger #E5534B`,track → `border`
- 页脚 "Authorized use only" 用 `muted`

## 主窗口框架(main.rs)

- 连接栏:深色 `bar` 底,状态点用 `success`/`danger`,文字层级按字阶收敛
- Session 面板:列头 11px caps `muted` + 底部 hairline;行高 30→32;选中行 = `rowsel` 淡紫底(现有 ItemSel 模板机制不变)
- 标签栏:活动标签指示 = 2px `accent` 下划线(现有 `Cunder` 机制,换值即可),文字 `second`→活动 `primary`
- 事件日志:等宽 12px,行距收紧,时间戳 `muted`、级别着色沿用 Palette
- 空状态(EmptySessions 等):主句 `second` 13px semibold + 副句 `muted` 11px

## Widgets(widgets/*.rs)

- 六个 widget 已用 `Palette::current()` 动态取色 —— 换 ramp 即自动换肤,**不得** 在 Rust 里硬编码颜色
- `console_list.rs` 着色规则沿用(`$` 命令 = accent,错误 = danger,其余 = second)
- `session_graph.rs` 节点/连线/文字颜色确认全部走 Palette;布局参数(节点半径、间距)可微调
- Rust draw 代码里的间距/尺寸散值可向设计令牌收敛,但不强求

## 明确的非目标(YAGNI)

- 不改任何功能逻辑(bridge、命令处理、会话管理)
- 不新增界面、不重排信息架构
- 不引入新依赖
- 不动 `docs/` 其他文档;README 的 GUI 描述如失实另行同步

## Makepad 已验证的坑(代码注释为准,严禁重踩)

1. DSL 2.0 用**点路径属性 + 构造器**(`draw_bg.color: X`、`Inset{..}`),禁止嵌套 object 块(运行期崩 "expected DrawQuad, got object")
2. 需要运行时重着色的容器用 `View`,**不用 `SolidView`**(`self.ui.view()` 类型不符会写坏 draw_bg)
3. 列表行选中用**双模板 CachedView**(`Item` / `ItemSel`),不要试图运行时 set_color
4. 覆盖点击用 `flow: Overlay` + 透明 Button 置顶
5. `script_mod!` DSL 错误部分要到**运行期**才暴露 —— `cargo check` 过了不算完,必须运行验证

## 验证

1. `cargo check --profile gui -p nyx-client-ui`(注意:运行必须 `--profile gui`,release 会在 macOS Metal SIGSEGV)
2. `cargo clippy -p nyx-client-ui -- -D warnings`
3. 运行 GUI 截图对比:连接页 + 主窗口(连接前空状态)
