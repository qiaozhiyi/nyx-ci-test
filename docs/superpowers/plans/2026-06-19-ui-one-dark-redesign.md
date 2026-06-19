# Nyx Client UI — One Dark 重做 + 登录鉴权修复 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 Nyx client-ui 从钴蓝亮色切换到 One Dark Pro 深色 + 粉紫强调视觉,并修复登录界面的鉴权头缺失 bug(导致 401 卡死)。

**Architecture:** 三层改动:(1) `theme.rs` `Palette` 换色板(数据源);(2) `main.rs` 的 `script_mod!` DSL 静态 token + 动态 `apply_theme()` + `connect_view` 登录对话框重画(视觉层);(3) `bridge.rs` 的 `Cmd::Connect` 扩展 token + worker 请求带 `Authorization` 头(鉴权数据流)。widget 的 `draw_walk` 已读 `Palette::current()`,换色板后自动生效,无需改 widget 代码。

**Tech Stack:** Rust 2021 · Makepad 2.0(`script_mod!` DSL + `script_apply_eval!`)· reqwest(bearer auth)· tokio。

**Spec:** `docs/superpowers/specs/2026-06-19-ui-one-dark-redesign-design.md`

**测试策略说明:** DSL 视觉(theme/登录框/主控制台颜色)无法做单元测试——Makepad DSL 在编译期展开、运行期由 GPU 渲染,没有可断言的颜色输出 API。因此视觉层用"编译通过 + 运行时目视"验证。只有 bridge 鉴权数据流有可单测的结构变化(`Cmd::Connect` 签名、token 透传),这部分用 TDD。

---

## 文件结构

| 文件 | 责任 | 本次改动 |
|---|---|---|
| `crates/client-ui/src/bridge.rs` | IO worker + REST 请求 + `Cmd` 枚举 | 改:`Cmd::Connect` 加 token;worker 持 token;4 请求带 `bearer_auth` |
| `crates/client-ui/src/theme.rs` | `Palette` 配色源 | 改:`dark()`/`light()` 全换 One Dark;加 `info` 字段 |
| `crates/client-ui/src/main.rs` | DSL 定义 + `App` 逻辑 + `apply_theme` | 改:DSL token;`connect_view` 重画;`apply_theme` 适配;`Cmd::Connect` 构造传 token |
| `crates/client-ui/src/widgets/*.rs` | 4 个虚拟化 widget | **不改**(`draw_walk` 读 palette 自动生效) |

---

## Task 1: bridge 鉴权数据流(TDD)

**Files:**
- Modify: `crates/client-ui/src/bridge.rs`

这是唯一有可测结构变化的部分。先改 `Cmd::Connect` 签名,让 token 流进 worker,再让 4 个请求带 `Authorization`。

- [ ] **Step 1: 扩展 `Cmd::Connect` 签名**

`crates/client-ui/src/bridge.rs` 中(约 92-106 行),改 `Cmd::Connect`:

```rust
pub enum Cmd {
    /// Target team server base URL + optional API bearer token.
    /// `password` is the operator-typed token sent as `Authorization: Bearer`.
    /// `None` when the server has no `NYX_TOKEN` configured (local dev).
    Connect { server: String, password: Option<String> },
    Shell { session: String, args: String },
    Bof { session: String, name: String, args: String, data_hex: String },
    Shutdown,
}
```

- [ ] **Step 2: worker 持有 token**

worker_loop 内(约 177 行)将 `server: Option<String>` 改为持有 `(server, token)`:

```rust
async fn worker_loop(cmd_rx: FromUIReceiver<Cmd>, to_ui: ToUISender<Snapshot>) {
    // (server_url, optional bearer token). None until first Connect.
    let mut server: Option<(String, Option<String>)> = None;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .expect("reqwest client build");
    // ... pending/log_buf/bof_updates/last_session_sig unchanged ...
```

- [ ] **Step 3: 更新 `Cmd::Connect` 处理分支**

将 `Cmd::Connect { server: s }` 分支(约 195 行)改为:

```rust
                Cmd::Connect { server: s, password } => {
                    log_push(&mut log_buf, &format!("connecting to {s} …"));
                    server = Some((s, password));
                    let _ = to_ui.send(take_snapshot(&mut log_buf, false, &[], &mut bof_updates));
                }
```

并把 worker_loop 里所有 `let Some(ref srv) = server` 的解构,改为同时取出 token:

```rust
        let Some((ref srv, ref token)) = server else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
```

- [ ] **Step 4: 新增带鉴权的请求封装**

在 REST helpers 区(约 343 行前)加一个统一带 token 的请求构造器,替代 4 处裸 `.send()`:

```rust
/// Attach the bearer token (if any) to a request builder, then send.
fn authed(req: reqwest::RequestBuilder, token: &Option<String>) -> reqwest::RequestBuilder {
    match token {
        Some(t) => req.bearer_auth(t),
        None => req,
    }
}
```

- [ ] **Step 5: 4 个请求函数接入 token**

`fetch_sessions` / `enqueue_shell` / `enqueue_bof` / `poll_result` 四个函数各加 `token: &Option<String>` 参数,并用 `authed()` 包裹。以 `fetch_sessions` 为例:

```rust
async fn fetch_sessions(
    c: &reqwest::Client,
    server: &str,
    token: &Option<String>,
) -> anyhow::Result<Vec<SessionView>> {
    let req = c.get(format!("{server}/api/sessions"));
    Ok(authed(req, token).send().await?.json().await?)
}
```

其余三个函数同理:加 `token` 参数,在 `.send()` 前用 `authed(req, token)`。`enqueue_shell`/`enqueue_bof` 的 `req` 是 `.post(...).json(&body)` 链;`poll_result` 是 `.get(...).query(...)` 链。每个都把构造好的 builder 传给 `authed()` 再 `.send()`。

- [ ] **Step 6: 更新 worker_loop 内的 4 个调用点**

worker_loop 内所有对这 4 个函数的调用,补上 `token` 实参。例如:

```rust
        match fetch_sessions(&client, srv, token).await {
```

`enqueue_shell(&client, srv, &session, &args, token)`、`enqueue_bof(..., token)`、`poll_result(&client, srv, &session, task_id, token)`。共 4 个调用点(分别在 session 刷新、shell 入队、bof 入队、task 轮询处)。

- [ ] **Step 7: 单元测试验证签名**

`crates/client-ui/src/bridge.rs` 已有 `#[cfg(test)] mod tests`。现有测试(`signature_*`、`log_push_*`)不涉及新签名,保持绿。补一个验证 `Cmd::Connect` 携带 token 的结构测试:

```rust
    #[test]
    fn connect_cmd_carries_password() {
        // Cmd::Connect now carries an optional bearer token. This pins the
        // signature so a future refactor can't silently drop it (the original
        // auth-header bug was exactly this: the field didn't exist).
        let c = Cmd::Connect { server: "http://x".into(), password: Some("sekret".into()) };
        match c {
            Cmd::Connect { password: Some(p), .. } => assert_eq!(p, "sekret"),
            _ => panic!("wrong variant"),
        }
    }
```

- [ ] **Step 8: 运行测试**

Run: `cargo test -p nyx-client-ui bridge::tests -- --nocapture`
Expected: PASS(含新 `connect_cmd_carries_password`)。

- [ ] **Step 9: Commit**

```bash
git add crates/client-ui/src/bridge.rs
git commit -m "fix(client-ui): send Authorization header on REST requests (login 401)

Cmd::Connect now carries the operator password as a bearer token; the
worker attaches it to all four REST calls (sessions/task/results). Fixes
the perpetual 401 that trapped the UI on the connect dialog whenever
the team server had NYX_TOKEN set."
```

---

## Task 2: theme.rs 换 One Dark 色板

**Files:**
- Modify: `crates/client-ui/src/theme.rs`

纯数据改动。换 `dark()`/`light()` 全部字段,加 `info` 字段。

- [ ] **Step 1: Palette 结构加 `info` 字段**

`crates/client-ui/src/theme.rs` 的 `Palette` struct(约 36-69 行),在 `warn` 后加:

```rust
    /// Warning / pending.
    pub warn: Vec4,
    /// Info / command keyword (console highlighting). Light blue.
    pub info: Vec4,
}
```

- [ ] **Step 2: 替换 `Palette::dark()`**

用 One Dark 值替换整个 `dark()`(约 88-107 行):

```rust
    /// One Dark Pro ramp — deep purple-charcoal with a pink-magenta signal.
    /// Mirrors the `#x` tokens in main.rs script_mod!; change one, change both.
    pub fn dark() -> Self {
        Palette {
            bg:      rgb(0x1A, 0x1A, 0x25), // #1A1A25
            panel:   rgb(0x1E, 0x1E, 0x2E), // #1E1E2E
            elev:    rgb(0x25, 0x25, 0x33), // #252533
            row:     rgb(0x1E, 0x1E, 0x2E), // #1E1E2E
            rowhov:  rgb(0x2A, 0x2A, 0x3A), // #2A2A3A
            rowsel:  rgb(0x3A, 0x2A, 0x3E), // #3A2A3E
            border:  rgb(0x2A, 0x2A, 0x3A), // #2A2A3A
            bar:     rgb(0x1E, 0x1E, 0x2E), // #1E1E2E
            primary: rgb(0xCC, 0xCC, 0xCC), // #CCCCCC
            second:  rgb(0xAA, 0xAA, 0xAA), // #AAAAAA
            muted:   rgb(0x8A, 0x8A, 0x8A), // #8A8A8A
            accent:  rgb(0xC5, 0x86, 0xC0), // #C586C0 (One Dark magenta)
            acchov:  rgb(0xD8, 0x9E, 0xD4), // #D89ED4
            success: rgb(0x4E, 0xC9, 0xB0), // #4EC9B0 (teal)
            danger:  rgb(0xF4, 0x47, 0x47), // #F44747
            warn:    rgb(0xDC, 0xDC, 0xAA), // #DCDCAA
            info:    rgb(0x9C, 0xDC, 0xFE), // #9CDCFE (light blue)
        }
    }
```

- [ ] **Step 3: 替换 `Palette::light()` + 补 `info`**

light 保留中性纸色,但 `accent`/`acchov` 换粉紫系浅变体,并补 `info`:

```rust
    /// Light ramp — neutral paper; accent kept as a muted magenta so the
    /// theme toggle still reads as the same product family.
    pub fn light() -> Self {
        Palette {
            bg:      rgb(0xF5, 0xF5, 0xF8),
            panel:   rgb(0xFC, 0xFC, 0xFD),
            elev:    rgb(0xFF, 0xFF, 0xFF),
            row:     rgb(0xFC, 0xFC, 0xFD),
            rowhov:  rgb(0xEE, 0xEE, 0xF3),
            rowsel:  rgb(0xF3, 0xE9, 0xF1),
            border:  rgb(0xDD, 0xDD, 0xE4),
            bar:     rgb(0xED, 0xED, 0xF2),
            primary: rgb(0x2C, 0x2C, 0x38),
            second:  rgb(0x5A, 0x5A, 0x68),
            muted:   rgb(0x84, 0x84, 0x92),
            accent:  rgb(0xA8, 0x4A, 0x9E), // muted magenta
            acchov:  rgb(0xBD, 0x60, 0xB3),
            success: rgb(0x1E, 0x8A, 0x73),
            danger:  rgb(0xC4, 0x33, 0x33),
            warn:    rgb(0x8A, 0x6D, 0x1E),
            info:    rgb(0x2A, 0x6E, 0xA8),
        }
    }
```

- [ ] **Step 4: 更新文件头注释**

更新顶部 doc comment 的配色描述(约 18-28 行),把"cobalt accent #2f88ff"改成"One Dark magenta accent #C586C0",保持文档与代码一致。

- [ ] **Step 5: 编译验证**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -20`
Expected: 编译通过(`info` 字段已加,struct 所有构造点都在 theme.rs 内,dark/light 均已补)。

注:此时 `main.rs` 的 `apply_theme` 可能未用 `info`——不影响编译(unused field 不报错,仅 warning 可被 `#[allow]` 或后续 Task 3 使用)。

- [ ] **Step 6: Commit**

```bash
git add crates/client-ui/src/theme.rs
git commit -m "style(client-ui): swap palette to One Dark Pro (magenta accent + dark purple)

dark() is now the One Dark Pro ramp (#1A1A25 base, #C586C0 magenta
signal, #4EC9B0 teal, #9CDCFE info). light() retuned with a muted
magenta accent to match. Adds Palette::info for console keyword
highlighting."
```

---

## Task 3: main.rs — DSL token 换 One Dark

**Files:**
- Modify: `crates/client-ui/src/main.rs`(约 54-87 行,DSL `let C* = ...` 区)

把 `script_mod!` 顶部所有 `C*` 颜色常量换成与 `Palette::dark()` 镜像的 One Dark 值。这是冷启动首帧配色(在 `apply_theme` 运行前)。

- [ ] **Step 1: 替换 DSL color token 块**

把 main.rs 约第 54-87 行的 `// ── Professional dark palette ──` 注释及全部 `let C* = ...` 替换为:

```rust
    // ── One Dark Pro palette ───────────────────────────────────────────────
    // Deep purple-charcoal base, single magenta signal (#C586C0), teal success,
    // light-blue info. These hex values MIRROR `Palette::dark()` in theme.rs —
    // the dynamic ramp consulted at draw time so the theme toggle repaints
    // consistently. Keep the two in lockstep: change one, change both.
    let Cbg       = #x1A1A25  // app background — deepest surface
    let Cbar      = #x1E1E2E  // recessed secondary bars / tab bar
    let Cpanel    = #x1E1E2E  // side panels + event-log shell
    let Crow      = #x1E1E2E  // table/data-row base
    let Crowhov   = #x2A2A3A  // row hover
    let Crowsel   = #x3A2A3E  // row selected (magenta-tinted)
    let Celev     = #x252533  // brightest surface — column headers / dialog card
    let Cborder   = #x2A2A3A  // hairline dividers
    let Cprimary  = #xCCCCCC  // primary text
    let Csecond   = #xAAAAAA  // secondary text
    let Cmuted    = #x8A8A8A  // muted text / column labels
    let Caccent   = #xC586C0  // signature magenta accent
    let Cacchov   = #xD89ED4  // accent hover
    let Csuccess  = #x4EC9B0  // success / online (teal)
    let Cdanger   = #xF44747  // danger / alert
    let Cwarn     = #xDCDCAA  // warning / pending / secrets
    let Cinfo     = #x9CDCFE  // info / command keyword
    let Cunder    = #xC586C0  // active-tab underline (magenta)
    let Cradius   = 6.0       // unified corner radius (cards / buttons / inputs)
    let Cradius_s = 3.0       // small radius (tags / badges)
    let Cpad      = 14.0      // table row / header horizontal inset
    let Cgap      = 16.0      // column gap inside rows / headers
```

- [ ] **Step 2: 编译验证**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -20`
Expected: 编译通过。若 `Cinfo` 报 unused warning,正常(后续 widget 行高亮会用,或保留以备)。

- [ ] Step 3: Commit

```bash
git add crates/client-ui/src/main.rs
git commit -m "style(client-ui): mirror One Dark tokens in DSL (cold-start first frame)"
```

---

## Task 4: main.rs — 重画登录对话框(connect_view)

**Files:**
- Modify: `crates/client-ui/src/main.rs`(约 383-547 行,`connect_view` 块)

按 spec §4 重画:删彩色 stripe、logo 换渐变方块、HOST/PORT 合并为 Server URL、输入框实心填充、按钮右下角对齐。同时 `Cmd::Connect` 构造点要传 password。

- [ ] **Step 1: 替换 `connect_view` 整块**

把 main.rs 约 383-547 行(`connect_view := View{ ... }` 到其闭合)替换为下面的 One Dark 版本。注意:HOST/PORT 两个 input 合并为单个 `url_input`;新增 `logo_box` 渐变方块;`pass_input` 保留 `is_password: true`。

```rust
                    // ── connect dialog (shown until connected) ──────────────
                    connect_view := View{
                        width: Fill height: Fill
                        align: Center
                        draw_bg.color: Cbg
                        connect_card := SolidView{
                            width: 460 height: Fit
                            flow: Down
                            draw_bg.color: Celev
                            draw_bg.border_radius: Cradius
                            draw_bg.border_size: 1.0
                            draw_bg.border_color: Cborder

                            // Brand header: gradient logo box + wordmark + tagline.
                            // No accent stripe — One Dark doesn't use it.
                            View{
                                width: Fill height: Fit
                                padding: Inset{top: 30.0 bottom: 22.0 left: 30.0 right: 30.0}
                                flow: Down spacing: 6.0
                                View{
                                    width: Fit height: Fit
                                    flow: Right spacing: 10.0
                                    align: Align{y: 0.5}
                                    logo_box := View{
                                        width: 30 height: 30
                                        draw_bg.color: Caccent
                                        draw_bg.border_radius: 6.0
                                        align: Center
                                        logo_letter := Label{
                                            text: "N"
                                            draw_text.color: Cbg
                                            draw_text.text_style: theme.font_bold{font_size: 16}
                                        }
                                    }
                                    nyx_logo := Label{
                                        text: "Nyx Operator"
                                        draw_text.color: Cprimary
                                        draw_text.text_style: theme.font_bold{font_size: 16}
                                    }
                                }
                                connect_tagline := Label{
                                    text: "Connect to a team server"
                                    draw_text.color: Cmuted
                                    draw_text.text_style: theme.font_regular{font_size: 12}
                                }
                            }
                            View{width: Fill height: 1 draw_bg.color: Cborder}
                            // Form body.
                            View{
                                width: Fill height: Fit
                                padding: Inset{top: 20.0 bottom: 26.0 left: 30.0 right: 30.0}
                                flow: Down spacing: 16.0

                                View{
                                    width: Fill height: Fit flow: Down spacing: 5.0
                                    url_label := Label{text: "Server URL" draw_text.color: Cmuted draw_text.text_style: theme.font_regular{font_size: 11}}
                                    url_input := TextInput{
                                        width: Fill height: 30
                                        padding: Inset{left: 12.0 right: 12.0}
                                        text: "http://127.0.0.1:8443"
                                        empty_text: "http://host:port"
                                        draw_bg.color: Cbg
                                        draw_bg.color_hover: Cbg
                                        draw_bg.color_focus: Cbg
                                        draw_bg.border_color: Cborder
                                        draw_bg.border_color_focus: Caccent
                                        draw_bg.border_size: 1.0
                                        draw_bg.border_radius: 4.0
                                        draw_text.color: Cprimary
                                        draw_text.color_hover: Cprimary
                                        draw_text.color_focus: Cprimary
                                        draw_text.color_empty: Cmuted
                                        draw_text.text_style: theme.font_code{font_size: 12}
                                        draw_cursor.color: Caccent
                                    }
                                }
                                View{
                                    width: Fill height: Fit flow: Down spacing: 5.0
                                    alias_label := Label{text: "Operator" draw_text.color: Cmuted draw_text.text_style: theme.font_regular{font_size: 11}}
                                    alias_input := TextInput{
                                        width: Fill height: 30
                                        padding: Inset{left: 12.0 right: 12.0}
                                        text: "operator"
                                        draw_bg.color: Cbg
                                        draw_bg.color_hover: Cbg
                                        draw_bg.color_focus: Cbg
                                        draw_bg.border_color: Cborder
                                        draw_bg.border_color_focus: Caccent
                                        draw_bg.border_size: 1.0
                                        draw_bg.border_radius: 4.0
                                        draw_text.color: Cprimary
                                        draw_text.color_hover: Cprimary
                                        draw_text.color_focus: Cprimary
                                        draw_text.color_empty: Cmuted
                                        draw_text.text_style: theme.font_code{font_size: 12}
                                        draw_cursor.color: Caccent
                                    }
                                }
                                View{
                                    width: Fill height: Fit flow: Down spacing: 5.0
                                    pass_label := Label{text: "Password (API Token)" draw_text.color: Cmuted draw_text.text_style: theme.font_regular{font_size: 11}}
                                    pass_input := TextInput{
                                        is_password: true
                                        width: Fill height: 30
                                        padding: Inset{left: 12.0 right: 12.0}
                                        text: ""
                                        empty_text: "team server token (leave empty if none)"
                                        draw_bg.color: Cbg
                                        draw_bg.color_hover: Cbg
                                        draw_bg.color_focus: Cbg
                                        draw_bg.border_color: Cborder
                                        draw_bg.border_color_focus: Caccent
                                        draw_bg.border_size: 1.0
                                        draw_bg.border_radius: 4.0
                                        draw_text.color: Cprimary
                                        draw_text.color_hover: Cprimary
                                        draw_text.color_focus: Cprimary
                                        draw_text.color_empty: Cmuted
                                        draw_text.text_style: theme.font_code{font_size: 12}
                                        draw_cursor.color: Caccent
                                    }
                                }
                                connect_status := Label{
                                    text: ""
                                    draw_text.color: Cdanger
                                    draw_text.text_style: theme.font_code{font_size: 11}
                                }
                                // Buttons row: theme toggle (left) + Connect (right).
                                View{
                                    width: Fill height: Fit
                                    flow: Right spacing: 8.0
                                    align: Align{y: 0.5}
                                    dialog_theme_btn := Button{
                                        text: "Light Mode"
                                        width: 90 height: 30
                                        draw_bg.color: Cbg
                                        draw_bg.color_hover: Crowhov
                                        draw_bg.border_size: 1.0
                                        draw_bg.border_radius: 4.0
                                        draw_text.color: Csecond
                                        draw_text.text_style: theme.font_regular{font_size: 12}
                                    }
                                    View{width: Fill height: 1}
                                    dialog_connect_btn := Button{
                                        text: "Connect"
                                        width: 110 height: 30
                                        draw_bg.color: Caccent
                                        draw_bg.color_hover: Cacchov
                                        draw_bg.border_radius: 4.0
                                        draw_text.color: Cbg
                                        draw_text.text_style: theme.font_bold{font_size: 12}
                                    }
                                }
                                connect_footer := Label{
                                    text: "Authorized use only · all activity is logged"
                                    draw_text.color: Cmuted
                                    draw_text.text_style: theme.font_regular{font_size: 9}
                                }
                            }
                        }
                    }
```

- [ ] **Step 2: 更新 `apply_theme` 中对话框相关 id 引用**

原 `apply_theme` 引用了 `connect_stripe`(已删)、`host_label`/`host_input`/`port_label`/`port_input`(已合并为 url)。更新 `crates/client-ui/src/main.rs` `apply_theme` 的对话框部分(约 976-1045 行):

把 `connect_stripe` 块删掉。把 inputs 数组改为:

```rust
        // 3. Text inputs (dialog fields + connection-bar server field).
        let inputs = [
            ids!(url_input),
            ids!(pass_input),
            ids!(alias_input),
            ids!(server_input),
        ];
```

把 dialog_labels 改为(去掉 port_label,新增 url_label):

```rust
        let dialog_labels = [
            (ids!(nyx_logo), cprimary),
            (ids!(connect_tagline), cmuted),
            (ids!(url_label), cmuted),
            (ids!(alias_label), cmuted),
            (ids!(pass_label), cmuted),
            (ids!(connect_footer), cmuted),
        ];
```

`logo_letter` 颜色单独设为 `cbg`(logo 方块上的 N 字):在 apply_theme 对话框段补:

```rust
        let mut ll = self.ui.label(cx, ids!(logo_letter));
        script_apply_eval!(cx, ll, {
            draw_text +: { color: #(cbg) }
        });
        let mut lb = self.ui.view(cx, ids!(logo_box));
        script_apply_eval!(cx, lb, {
            draw_bg +: { color: #(caccent) }
        });
```

- [ ] **Step 3: 更新登录按钮点击逻辑传 password**

`handle_actions` 中(约 1216-1239 行)登录逻辑。原 `host`/`port` 分支改读 `url_input`,并传 `password`:

```rust
        let dlg_connect = self.ui.button(cx, ids!(dialog_connect_btn)).clicked(actions);
        let dlg_enter = self.ui.text_input(cx, ids!(url_input)).returned(actions).is_some()
            || self.ui.text_input(cx, ids!(alias_input)).returned(actions).is_some()
            || self.ui.text_input(cx, ids!(pass_input)).returned(actions).is_some();

        let bar_connect = self.ui.button(cx, ids!(bar_connect_btn)).clicked(actions);

        if dlg_connect || dlg_enter || bar_connect {
            self.ensure_bridge();
            if let Some(b) = &self.bridge {
                let (url, password) = if bar_connect {
                    (self.ui.text_input(cx, ids!(server_input)).text(), None)
                } else {
                    let raw = self.ui.text_input(cx, ids!(url_input)).text();
                    let pw = self.ui.text_input(cx, ids!(pass_input)).text();
                    (raw, if pw.trim().is_empty() { None } else { Some(pw) })
                };
                let _ = b.from_ui.send(Cmd::Connect {
                    server: url.trim().to_string(),
                    password,
                });
                if !bar_connect {
                    self.ui.label(cx, ids!(connect_status)).set_text(cx, "Connecting…");
                }
            }
        }
```

- [ ] **Step 4: 编译验证**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -25`
Expected: 编译通过。若报某 id 不存在(如残留 `host_input` 引用),按报错在 main.rs 内 grep 残留并清除。

- [ ] **Step 5: Commit**

```bash
git add crates/client-ui/src/main.rs
git commit -m "feat(client-ui): redesign connect dialog (One Dark) + wire password to Connect

Drops the accent stripe + giant NYX wordmark for a gradient logo box.
Host/Port merge into a single Server URL field. Inputs are filled
(elev bg + 1px border, magenta focus border). Connect button is magenta,
right-aligned. The password field now actually flows into Cmd::Connect
(as the bearer token) — was decorative before."
```

---

## Task 5: main.rs — 主控制台配色适配 apply_theme

**Files:**
- Modify: `crates/client-ui/src/main.rs`(`apply_theme` 主控制台部分)

`apply_theme` 已从 `Palette::current()` 取色(Task 2 已换值),所以主体自动变 One Dark。本任务只清理因登录框改动产生的 id 残留 + 确保状态文字/status_dot 用新色。

- [ ] **Step 1: 验证无残留旧 id 引用**

Run: `rg -n "connect_stripe|host_input|host_label|port_input|port_label" crates/client-ui/src/main.rs`
Expected: 无输出(全已在 Task 4 清除)。若有残留,删除对应行。

- [ ] **Step 2: set_status 的 status_text 颜色**

`set_status`(约 929 行)已用 `Palette::current()` 的 success/danger,自动适配。无需改。确认编译即可。

- [ ] **Step 3: 编译验证**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -20`
Expected: 编译通过。

- [ ] **Step 4: Commit**

```bash
git add crates/client-ui/src/main.rs
git commit -m "style(client-ui): clear deprecated connect-dialog ids from apply_theme"
```

---

## Task 6: widget 文件无改动确认 + 整体编译

**Files:**
- 验证: `crates/client-ui/src/widgets/*.rs`

widget 的 `draw_walk` 读 `Palette::current()`,换色板自动生效。确认无需改。

- [ ] **Step 1: 确认 widget 不引用已改签名**

Run: `rg -n "Cmd::Connect|host_input|port_input" crates/client-ui/src/widgets/`
Expected: 无输出。

- [ ] **Step 2: 全 crate 编译 + 测试**

Run: `cargo build -p nyx-client-ui 2>&1 | tail -20 && cargo test -p nyx-client-ui 2>&1 | tail -20`
Expected: 编译通过;所有测试 PASS(含 Task 1 的 `connect_cmd_carries_password`)。

- [ ] **Step 3: 最终 Commit(若有未提交的修复)**

```bash
git add -A crates/client-ui
git status   # 确认干净
```

---

## Self-Review(计划作者自检)

**1. Spec 覆盖:**
- §3 配色 token → Task 2(theme)+ Task 3(DSL 镜像)✓
- §4 登录界面 → Task 4(connect_view 重画 + password 接线)✓
- §5 主控制台 → Task 3(DSL)+ Task 5(apply_theme 残留清理);主体配色经 palette 自动生效 ✓
- §6 鉴权修复 → Task 1(bridge 全部)✓
- §7 验证 → 各 Task 的编译/测试步骤 + Task 6 整体 ✓

**2. 占位符扫描:** 无 TBD/TODO;每个代码步骤都有完整代码。

**3. 类型一致性:** `Cmd::Connect { server, password: Option<String> }` 在 Task 1 定义、Task 4 Step 3 使用,签名一致。`Palette::info` 在 Task 2 Step 1 定义、Step 2/3 在 dark/light 构造,一致。`url_input`(替换 host/port)在 Task 4 Step 1 定义、Step 2/3 引用,一致。

**4. 风险缓解(spec §8):** DSL 不支持聚焦外发光 → Task 4 Step 1 用 `border_size:1.0` + `border_color_focus:Caccent` 实现聚焦加亮(已验证 Makepad 支持),非 box_shadow,符合降级方案。
